#![cfg_attr(not(any(feature = "blocking", feature = "tokio")), allow(dead_code))]

use std::cmp;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};
use crate::v3::proto::{
    CookieVerf, FileAttr, FileHandle, MAX_IO_BYTES, MAX_NAME_BYTES, ReadDirResult,
};

/// Parsed NFSv3 target in `host:/export` form.
///
/// IPv6 literals are accepted in bracketed form, for example
/// `[::1]:/export`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteTarget {
    /// Server hostname or IP address.
    pub host: String,
    /// Export path passed to the NFSv3 MOUNT service.
    pub export: String,
}

impl RemoteTarget {
    /// Parses a target string such as `127.0.0.1:/export`.
    pub fn parse(target: &str) -> Result<Self> {
        let (host, export) = if let Some(rest) = target.strip_prefix('[') {
            let (host, rest) = rest
                .split_once(']')
                .ok_or_else(|| Error::InvalidTarget(target.to_owned()))?;
            let export = rest
                .strip_prefix(':')
                .ok_or_else(|| Error::InvalidTarget(target.to_owned()))?;
            (host, export)
        } else {
            target
                .split_once(':')
                .ok_or_else(|| Error::InvalidTarget(target.to_owned()))?
        };
        let parsed = Self {
            host: host.to_owned(),
            export: export.to_owned(),
        };
        validate_remote_target(&parsed).map_err(|_| Error::InvalidTarget(target.to_owned()))?;
        Ok(parsed)
    }
}

pub(crate) fn validate_remote_target(target: &RemoteTarget) -> Result<()> {
    if target.host.trim().is_empty() || target.export.is_empty() || !target.export.starts_with('/')
    {
        return Err(Error::InvalidTarget(format!(
            "{}:{}",
            target.host, target.export
        )));
    }
    Ok(())
}

pub(crate) fn validate_host(host: &str) -> Result<()> {
    if host.trim().is_empty() {
        return Err(Error::InvalidTarget(host.to_owned()));
    }
    Ok(())
}

pub(crate) fn validate_port(name: &'static str, port: u16) -> Result<()> {
    if port == 0 {
        return Err(Error::Protocol(format!("{name} must be non-zero")));
    }
    Ok(())
}

/// Directory entry returned by NFSv3 directory reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// Entry name.
    pub name: String,
    /// Server-provided file identifier.
    pub fileid: u64,
    /// Attributes returned by `READDIRPLUS`, when available.
    pub attributes: Option<FileAttr>,
}

/// Cursor for paged NFSv3 directory reads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirPageCursor {
    /// Cookie of the last entry returned by the previous page.
    pub cookie: u64,
    /// Cookie verifier returned by the server.
    pub cookieverf: CookieVerf,
}

/// A single page of directory entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirPage {
    /// Entries returned in this page.
    pub entries: Vec<DirEntry>,
    /// Cursor for the next page, or `None` when the server reported EOF.
    pub next_cursor: Option<DirPageCursor>,
}

impl DirPage {
    /// Returns true when there are no further pages to request.
    pub fn is_eof(&self) -> bool {
        self.next_cursor.is_none()
    }
}

pub(crate) fn advance_offset(
    offset: &mut u64,
    amount: usize,
    operation: &'static str,
) -> Result<()> {
    let amount = u64::try_from(amount).map_err(|_| Error::LengthOutOfRange { len: amount })?;
    *offset = offset
        .checked_add(amount)
        .ok_or_else(|| Error::Protocol(format!("{operation} offset overflow")))?;
    Ok(())
}

pub(crate) fn normalize_path(path: &str) -> Result<Vec<&str>> {
    if path.is_empty() {
        return Err(Error::InvalidPath(path.to_owned()));
    }

    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => return Err(Error::InvalidPath(path.to_owned())),
            name if name.len() > MAX_NAME_BYTES => {
                return Err(Error::NameTooLong {
                    name: name.to_owned(),
                    max: MAX_NAME_BYTES,
                });
            }
            name => components.push(name),
        }
    }
    Ok(components)
}

pub(crate) fn join_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{}/{name}", parent.trim_end_matches('/'))
    }
}

pub(crate) fn temporary_sibling_path(path: &str) -> Result<String> {
    let mut components = normalize_path(path)?;
    components
        .pop()
        .ok_or_else(|| Error::InvalidPath(path.to_owned()))?;

    let mut parent = String::from("/");
    for component in components {
        parent = join_path(&parent, component);
    }

    Ok(join_path(&parent, &temporary_name()))
}

fn temporary_name() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".nfs-rs-tmp-{}-{nanos}-{counter}", std::process::id())
}

pub(crate) fn append_dir_entries(
    out: &mut Vec<DirEntry>,
    batch: &ReadDirResult,
    max_dir_entries: usize,
) -> Result<()> {
    if out.len().saturating_add(batch.entries.len()) > max_dir_entries {
        return Err(Error::Protocol(format!(
            "READDIR exceeded configured limit of {max_dir_entries} entries"
        )));
    }
    out.extend(batch.entries.iter().map(|entry| DirEntry {
        name: entry.name.clone(),
        fileid: entry.fileid,
        attributes: entry.attributes.clone(),
    }));
    Ok(())
}

pub(crate) fn dir_page_from_batch(
    batch: &ReadDirResult,
    previous_cookie: u64,
    max_entries: usize,
) -> Result<DirPage> {
    let mut entries = Vec::new();
    append_dir_entries(&mut entries, batch, max_entries)?;
    let next_cursor = next_dir_cursor(batch, previous_cookie)?;
    Ok(DirPage {
        entries,
        next_cursor,
    })
}

pub(crate) fn next_dir_cursor(
    batch: &ReadDirResult,
    previous_cookie: u64,
) -> Result<Option<DirPageCursor>> {
    if batch.eof {
        return Ok(None);
    }

    let last = batch
        .entries
        .last()
        .ok_or_else(|| Error::Protocol("READDIR returned no entries before EOF".to_owned()))?;
    if last.cookie == previous_cookie {
        return Err(Error::Protocol(format!(
            "READDIR did not advance directory cookie {previous_cookie}"
        )));
    }
    Ok(Some(DirPageCursor {
        cookie: last.cookie,
        cookieverf: batch.cookieverf,
    }))
}

pub(crate) fn validate_transfer_size(name: &'static str, size: u32) -> Result<u32> {
    if size == 0 || size as usize > MAX_IO_BYTES {
        return Err(Error::Protocol(format!(
            "{name} must be in 1..={MAX_IO_BYTES} bytes"
        )));
    }
    Ok(size)
}

pub(crate) fn validate_max_dir_entries(max_dir_entries: usize) -> Result<()> {
    if max_dir_entries == 0 {
        return Err(Error::Protocol(
            "max_dir_entries must be greater than zero".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn clamp_io_size(preferred: u32, max: u32, limit: u32) -> u32 {
    let size = if preferred == 0 { max } else { preferred };
    let size = if max == 0 { size } else { cmp::min(size, max) };
    size.clamp(1, limit)
}

pub(crate) fn clamp_dir_size(preferred: u32, limit: u32) -> u32 {
    if preferred == 0 {
        limit
    } else {
        preferred.clamp(1, limit)
    }
}

pub(crate) fn ensure_distinct_copy_handles(source: &FileHandle, target: &FileHandle) -> Result<()> {
    if source == target {
        return Err(Error::Protocol(
            "copy source and destination refer to the same file handle".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn cleanup_error(
    error: Error,
    cleanup_context: &'static str,
    cleanup_result: Result<()>,
) -> Error {
    match cleanup_result {
        Ok(()) => error,
        Err(cleanup_error) => Error::cleanup(cleanup_context, error, cleanup_error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_path_rejects_parent_components() {
        assert!(matches!(normalize_path("../x"), Err(Error::InvalidPath(_))));
        assert!(matches!(
            normalize_path("/safe/../x"),
            Err(Error::InvalidPath(_))
        ));
    }

    #[test]
    fn validates_remote_targets_built_from_parts() {
        assert!(
            validate_remote_target(&RemoteTarget {
                host: "127.0.0.1".to_owned(),
                export: "/export".to_owned(),
            })
            .is_ok()
        );
        assert!(matches!(
            validate_remote_target(&RemoteTarget {
                host: " ".to_owned(),
                export: "/export".to_owned(),
            }),
            Err(Error::InvalidTarget(_))
        ));
        assert!(matches!(
            validate_remote_target(&RemoteTarget {
                host: "127.0.0.1".to_owned(),
                export: "relative".to_owned(),
            }),
            Err(Error::InvalidTarget(_))
        ));
    }

    #[test]
    fn validates_remote_ports() {
        assert!(validate_port("nfs_port", 2049).is_ok());
        assert!(matches!(
            validate_port("nfs_port", 0),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn normalize_path_ignores_root_empty_and_dot_components() {
        assert_eq!(normalize_path("/").unwrap(), Vec::<&str>::new());
        assert_eq!(normalize_path("/a/./b//").unwrap(), vec!["a", "b"]);
    }

    #[test]
    fn joins_remote_paths_without_duplicate_slashes() {
        assert_eq!(join_path("/", "a"), "/a");
        assert_eq!(join_path("/a/", "b"), "/a/b");
        assert_eq!(join_path("a", "b"), "a/b");
    }

    #[test]
    fn builds_temporary_sibling_paths() {
        let path = temporary_sibling_path("/a/b/file.txt").unwrap();
        assert!(path.starts_with("/a/b/.nfs-rs-tmp-"));
        assert!(temporary_sibling_path("/").is_err());
    }

    #[test]
    fn builds_directory_pages_from_batches() {
        let batch = ReadDirResult {
            directory_attributes: None,
            cookieverf: [7; 8],
            entries: vec![crate::v3::proto::DirectoryEntry {
                fileid: 1,
                name: "file".to_owned(),
                cookie: 9,
                attributes: None,
                handle: None,
            }],
            eof: false,
        };

        let page = dir_page_from_batch(&batch, 0, 16).unwrap();
        assert_eq!(page.entries.len(), 1);
        assert_eq!(
            page.next_cursor,
            Some(DirPageCursor {
                cookie: 9,
                cookieverf: [7; 8],
            })
        );
    }

    #[test]
    fn rejects_non_advancing_directory_cookies() {
        let batch = ReadDirResult {
            directory_attributes: None,
            cookieverf: [7; 8],
            entries: vec![crate::v3::proto::DirectoryEntry {
                fileid: 1,
                name: "file".to_owned(),
                cookie: 9,
                attributes: None,
                handle: None,
            }],
            eof: false,
        };

        assert!(matches!(
            dir_page_from_batch(&batch, 9, 16),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn validates_configured_transfer_sizes() {
        assert!(matches!(
            validate_transfer_size("read_size", 0),
            Err(Error::Protocol(_))
        ));
        assert!(matches!(
            validate_transfer_size("read_size", MAX_IO_BYTES as u32 + 1),
            Err(Error::Protocol(_))
        ));
        assert_eq!(
            clamp_io_size(1024 * 1024, 2 * 1024 * 1024, 128 * 1024),
            128 * 1024
        );
        assert_eq!(clamp_dir_size(0, 64 * 1024), 64 * 1024);
        assert_eq!(clamp_dir_size(256 * 1024, 64 * 1024), 64 * 1024);
    }

    #[test]
    fn validates_max_dir_entries() {
        assert!(matches!(
            validate_max_dir_entries(0),
            Err(Error::Protocol(_))
        ));
        assert!(validate_max_dir_entries(1).is_ok());
    }

    #[test]
    fn rejects_copy_between_equal_file_handles() {
        let handle = FileHandle::new(vec![1, 2, 3]).unwrap();
        assert!(matches!(
            ensure_distinct_copy_handles(&handle, &handle),
            Err(Error::Protocol(_))
        ));

        let other = FileHandle::new(vec![1, 2, 4]).unwrap();
        assert!(ensure_distinct_copy_handles(&handle, &other).is_ok());
    }

    #[test]
    fn cleanup_error_preserves_cleanup_failures() {
        let err = cleanup_error(
            Error::Protocol("primary failure".to_owned()),
            "cleanup REMOVE",
            Err(Error::Protocol("remove failure".to_owned())),
        );

        let message = err.to_string();
        assert!(message.contains("primary failure"));
        assert!(message.contains("remove failure"));
    }

    #[test]
    fn advance_offset_rejects_overflow() {
        let mut offset = u64::MAX;
        assert!(matches!(
            advance_offset(&mut offset, 1, "READ"),
            Err(Error::Protocol(_))
        ));
        assert_eq!(offset, u64::MAX);
    }
}
