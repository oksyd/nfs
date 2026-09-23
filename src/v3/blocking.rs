//! Blocking NFSv3 client.
//!
//! The client connects to the MOUNT service, resolves the export root, then
//! performs NFSv3 operations over TCP. Paths are interpreted relative to the
//! export root.
//!
//! ```no_run
//! let mut client = nfs::v3::blocking::Client::connect("127.0.0.1:/export")?;
//! client.write("/object.txt", b"payload")?;
//! assert_eq!(client.read("/object.txt")?, b"payload");
//! # Ok::<(), nfs::Error>(())
//! ```

use std::cmp;
use std::io::{Read, Write};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::retry::RetryPolicy;
use crate::rpc::{AuthSys, max_record_size_for_payloads};
use crate::v3::client::{
    advance_offset, append_dir_entries, clamp_dir_size, clamp_io_size, cleanup_error,
    dir_page_from_batch, ensure_distinct_copy_handles, join_path, next_dir_cursor, normalize_path,
    temporary_sibling_path, validate_host, validate_max_dir_entries, validate_port,
    validate_remote_target, validate_transfer_size,
};
use crate::v3::mount::{Export, MOUNT_PROGRAM, MOUNT_VERSION, MountClient, MountEntry};
use crate::v3::portmap;
use crate::v3::proto::{
    AccessResult, CommitResult, CreateHow, CreateResult, FileAttr, FileHandle, FileType, FsInfo,
    FsStat, MAX_DIR_ENTRIES, MknodData, NFS_PORT, NFS_PROGRAM, NFS_VERSION, Nfs3Client, NfsStatus,
    NfsTime, PathConf, SetAttr, SpecData, StableHow,
};

pub use crate::v3::client::{DirEntry, DirPage, DirPageCursor, RemoteTarget};

const DEFAULT_IO_SIZE: u32 = 128 * 1024;
const DEFAULT_DIR_SIZE: u32 = 128 * 1024;

/// Lists exports advertised by an NFSv3 server's MOUNT service.
///
/// This queries `MOUNTPROC3_EXPORT` using the default 30 second socket timeout
/// and discovers the MOUNT service port through portmapper.
pub fn list_exports(host: &str) -> Result<Vec<Export>> {
    list_exports_with_timeout(host, Some(Duration::from_secs(30)))
}

/// Lists exports advertised by an NFSv3 server's MOUNT service.
///
/// `None` disables socket timeouts. The MOUNT service port is discovered
/// through portmapper.
pub fn list_exports_with_timeout(host: &str, timeout: Option<Duration>) -> Result<Vec<Export>> {
    list_exports_with_optional_mount_port(host, None, timeout)
}

/// Lists exports using an explicit MOUNT service port.
pub fn list_exports_with_mount_port(
    host: &str,
    mount_port: u16,
    timeout: Option<Duration>,
) -> Result<Vec<Export>> {
    let mut mount = connect_mount_client(host, Some(mount_port), timeout)?;
    mount.exports()
}

/// Lists current MOUNT records advertised by an NFSv3 server.
///
/// This queries `MOUNTPROC3_DUMP` using the default 30 second socket timeout.
pub fn list_mounts(host: &str) -> Result<Vec<MountEntry>> {
    list_mounts_with_timeout(host, Some(Duration::from_secs(30)))
}

/// Lists current MOUNT records advertised by an NFSv3 server.
///
/// `None` disables socket timeouts. The MOUNT service port is discovered
/// through portmapper.
pub fn list_mounts_with_timeout(host: &str, timeout: Option<Duration>) -> Result<Vec<MountEntry>> {
    list_mounts_with_optional_mount_port(host, None, timeout)
}

/// Lists current MOUNT records using an explicit MOUNT service port.
pub fn list_mounts_with_mount_port(
    host: &str,
    mount_port: u16,
    timeout: Option<Duration>,
) -> Result<Vec<MountEntry>> {
    let mut mount = connect_mount_client(host, Some(mount_port), timeout)?;
    mount.dump()
}

/// Sends `MOUNTPROC3_UMNT` for a `host:/export` target.
pub fn unmount(target: &str) -> Result<()> {
    unmount_with_timeout(target, Some(Duration::from_secs(30)))
}

/// Sends `MOUNTPROC3_UMNT` for a `host:/export` target.
///
/// `None` disables socket timeouts. The MOUNT service port is discovered
/// through portmapper.
pub fn unmount_with_timeout(target: &str, timeout: Option<Duration>) -> Result<()> {
    unmount_with_optional_mount_port(target, None, timeout)
}

/// Sends `MOUNTPROC3_UMNT` using an explicit MOUNT service port.
pub fn unmount_with_mount_port(
    target: &str,
    mount_port: u16,
    timeout: Option<Duration>,
) -> Result<()> {
    unmount_with_optional_mount_port(target, Some(mount_port), timeout)
}

/// Sends `MOUNTPROC3_UMNTALL` to a server's MOUNT service.
pub fn unmount_all(host: &str) -> Result<()> {
    unmount_all_with_timeout(host, Some(Duration::from_secs(30)))
}

/// Sends `MOUNTPROC3_UMNTALL` to a server's MOUNT service.
///
/// `None` disables socket timeouts. The MOUNT service port is discovered
/// through portmapper.
pub fn unmount_all_with_timeout(host: &str, timeout: Option<Duration>) -> Result<()> {
    unmount_all_with_optional_mount_port(host, None, timeout)
}

/// Sends `MOUNTPROC3_UMNTALL` using an explicit MOUNT service port.
pub fn unmount_all_with_mount_port(
    host: &str,
    mount_port: u16,
    timeout: Option<Duration>,
) -> Result<()> {
    unmount_all_with_optional_mount_port(host, Some(mount_port), timeout)
}

fn list_exports_with_optional_mount_port(
    host: &str,
    mount_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<Vec<Export>> {
    let mut mount = connect_mount_client(host, mount_port, timeout)?;
    mount.exports()
}

fn list_mounts_with_optional_mount_port(
    host: &str,
    mount_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<Vec<MountEntry>> {
    let mut mount = connect_mount_client(host, mount_port, timeout)?;
    mount.dump()
}

fn unmount_with_optional_mount_port(
    target: &str,
    mount_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<()> {
    let target = RemoteTarget::parse(target)?;
    let mut mount = connect_mount_client(&target.host, mount_port, timeout)?;
    mount.unmount(&target.export)
}

fn unmount_all_with_optional_mount_port(
    host: &str,
    mount_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<()> {
    let mut mount = connect_mount_client(host, mount_port, timeout)?;
    mount.unmount_all()
}

fn connect_mount_client(
    host: &str,
    mount_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<MountClient> {
    validate_host(host)?;
    let mount_port = match mount_port {
        Some(port) => {
            validate_port("mount_port", port)?;
            port
        }
        None => portmap::get_tcp_port_with_timeout(host, MOUNT_PROGRAM, MOUNT_VERSION, timeout)?,
    };
    let mount = MountClient::connect_with_timeout((host, mount_port), AuthSys::current(), timeout)?;
    mount.set_timeout(timeout)?;
    Ok(mount)
}

/// Builder for a blocking NFSv3 [`Client`].
///
/// Defaults are conservative: AUTH_SYS credentials from the current process, a
/// 30 second timeout, TCP port discovery through portmapper, 128 KiB transfer
/// limits, and the default [`RetryPolicy`].
#[derive(Debug, Clone)]
pub struct ClientBuilder {
    target: RemoteTarget,
    auth: AuthSys,
    timeout: Option<Duration>,
    mount_port: Option<u16>,
    nfs_port: Option<u16>,
    read_size_limit: u32,
    write_size_limit: u32,
    dir_size_limit: u32,
    max_dir_entries: usize,
    retry_policy: RetryPolicy,
}

impl ClientBuilder {
    /// Creates a builder from a host and export path.
    ///
    /// The export must be an absolute path as seen by the server's MOUNT
    /// service, for example `/export`.
    pub fn new(host: impl Into<String>, export: impl Into<String>) -> Self {
        Self {
            target: RemoteTarget {
                host: host.into(),
                export: export.into(),
            },
            auth: AuthSys::current(),
            timeout: Some(Duration::from_secs(30)),
            mount_port: None,
            nfs_port: None,
            read_size_limit: DEFAULT_IO_SIZE,
            write_size_limit: DEFAULT_IO_SIZE,
            dir_size_limit: DEFAULT_DIR_SIZE,
            max_dir_entries: MAX_DIR_ENTRIES,
            retry_policy: RetryPolicy::default(),
        }
    }

    /// Creates a builder from `host:/export` target syntax.
    ///
    /// IPv6 hosts may be written as `[::1]:/export`.
    pub fn from_target(target: &str) -> Result<Self> {
        Ok(Self {
            target: RemoteTarget::parse(target)?,
            auth: AuthSys::current(),
            timeout: Some(Duration::from_secs(30)),
            mount_port: None,
            nfs_port: None,
            read_size_limit: DEFAULT_IO_SIZE,
            write_size_limit: DEFAULT_IO_SIZE,
            dir_size_limit: DEFAULT_DIR_SIZE,
            max_dir_entries: MAX_DIR_ENTRIES,
            retry_policy: RetryPolicy::default(),
        })
    }

    /// Sets AUTH_SYS credentials for RPC calls.
    pub fn auth_sys(mut self, auth: AuthSys) -> Self {
        self.auth = auth;
        self
    }

    /// Sets socket connect/read/write timeout.
    ///
    /// `None` disables socket timeouts.
    pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the MOUNT service port explicitly.
    ///
    /// When omitted, the portmapper is queried.
    pub fn mount_port(mut self, port: u16) -> Self {
        self.mount_port = Some(port);
        self
    }

    /// Sets the NFS service port explicitly.
    ///
    /// When omitted, the portmapper is queried.
    pub fn nfs_port(mut self, port: u16) -> Self {
        self.nfs_port = Some(port);
        self
    }

    /// Sets both read and write transfer limits.
    pub fn io_size(mut self, size: u32) -> Self {
        self.read_size_limit = size;
        self.write_size_limit = size;
        self
    }

    /// Sets the read transfer limit.
    pub fn read_size(mut self, size: u32) -> Self {
        self.read_size_limit = size;
        self
    }

    /// Sets the write transfer limit.
    pub fn write_size(mut self, size: u32) -> Self {
        self.write_size_limit = size;
        self
    }

    /// Sets the maximum READDIR/READDIRPLUS response size requested.
    pub fn dir_size(mut self, size: u32) -> Self {
        self.dir_size_limit = size;
        self
    }

    /// Sets the maximum number of directory entries a single high-level call may collect.
    pub fn max_dir_entries(mut self, max_dir_entries: usize) -> Self {
        self.max_dir_entries = max_dir_entries;
        self
    }

    /// Sets retry behavior for retryable transport and protocol responses.
    pub fn retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    /// Connects to the server and returns a ready client.
    pub fn connect(self) -> Result<Client> {
        Client::connect_with_builder(self)
    }
}

/// Blocking, path-oriented NFSv3 client.
///
/// `Client` owns one MOUNT/NFS connection pair and exposes storage-oriented
/// operations such as whole-file reads, offset reads, atomic writes, copy,
/// directory pagination, metadata updates, and recursive removal.
///
/// Methods take paths relative to the mounted export. The root of the export is
/// `/`.
#[derive(Debug)]
pub struct Client {
    builder: ClientBuilder,
    target: RemoteTarget,
    auth: AuthSys,
    mount_port: u16,
    root: FileHandle,
    nfs: Nfs3Client,
    fsinfo: Option<FsInfo>,
    read_size: u32,
    write_size: u32,
    dir_size: u32,
    max_dir_entries: usize,
}

impl Client {
    /// Connects to a target in `host:/export` form.
    pub fn connect(target: &str) -> Result<Self> {
        ClientBuilder::from_target(target)?.connect()
    }

    /// Creates a builder from host and export components.
    pub fn builder(host: impl Into<String>, export: impl Into<String>) -> ClientBuilder {
        ClientBuilder::new(host, export)
    }

    /// Returns filesystem information discovered at connect time, if available.
    pub fn fsinfo(&self) -> Option<&FsInfo> {
        self.fsinfo.as_ref()
    }

    /// Alias for [`Client::fsinfo`].
    pub fn root_fsinfo(&self) -> Option<&FsInfo> {
        self.fsinfo()
    }

    /// Reconnects using the original builder configuration.
    pub fn reconnect(&mut self) -> Result<()> {
        *self = Self::connect_with_builder(self.builder.clone())?;
        Ok(())
    }

    /// Reads filesystem capability information for a path.
    pub fn path_fsinfo(&mut self, path: &str) -> Result<FsInfo> {
        let handle = self.resolve(path)?;
        self.nfs.fsinfo(&handle)
    }

    /// Reads filesystem capacity information for a path.
    pub fn fsstat(&mut self, path: &str) -> Result<FsStat> {
        let handle = self.resolve(path)?;
        self.nfs.fsstat(&handle)
    }

    /// Reads path configuration limits for a path.
    pub fn pathconf(&mut self, path: &str) -> Result<PathConf> {
        let handle = self.resolve(path)?;
        self.nfs.pathconf(&handle)
    }

    /// Resolves a path and returns its NFSv3 file handle.
    pub fn file_handle(&mut self, path: &str) -> Result<FileHandle> {
        self.resolve(path)
    }

    /// Resolves `path` and returns the file handle for its parent directory.
    pub fn parent_file_handle(&mut self, path: &str) -> Result<FileHandle> {
        let (handle, _) = self.resolve_parent(path)?;
        Ok(handle)
    }

    /// Reads NFSv3 attributes for a path.
    pub fn getattr(&mut self, path: &str) -> Result<FileAttr> {
        let handle = self.resolve(path)?;
        self.nfs.getattr(&handle)
    }

    /// Alias for [`Client::getattr`].
    pub fn metadata(&mut self, path: &str) -> Result<FileAttr> {
        self.getattr(path)
    }

    /// Reads NFSv3 attributes for the parent directory of `path`.
    pub fn parent_getattr(&mut self, path: &str) -> Result<FileAttr> {
        let handle = self.parent_file_handle(path)?;
        self.nfs.getattr(&handle)
    }

    /// Alias for [`Client::parent_getattr`].
    pub fn parent_metadata(&mut self, path: &str) -> Result<FileAttr> {
        self.parent_getattr(path)
    }

    /// Returns the remote file type for a path.
    pub fn file_type(&mut self, path: &str) -> Result<FileType> {
        Ok(self.metadata(path)?.file_type)
    }

    /// Returns true when the path is a regular file.
    pub fn is_file(&mut self, path: &str) -> Result<bool> {
        Ok(self.file_type(path)?.is_file())
    }

    /// Returns true when the path is a directory.
    pub fn is_dir(&mut self, path: &str) -> Result<bool> {
        Ok(self.file_type(path)?.is_dir())
    }

    /// Returns true when the path is a symbolic link.
    pub fn is_symlink(&mut self, path: &str) -> Result<bool> {
        Ok(self.file_type(path)?.is_symlink())
    }

    /// Checks server-granted access bits for a path.
    pub fn access(&mut self, path: &str, access: u32) -> Result<AccessResult> {
        let handle = self.resolve(path)?;
        self.nfs.access(&handle, access)
    }

    /// Resolves a path and returns success if it exists.
    pub fn lookup(&mut self, path: &str) -> Result<()> {
        self.resolve(path).map(|_| ())
    }

    /// Returns whether a path exists.
    pub fn exists(&mut self, path: &str) -> Result<bool> {
        match self.resolve(path) {
            Ok(_) => Ok(true),
            Err(Error::Nfs {
                status: NfsStatus::NoEnt,
                ..
            }) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Reads an entire file into memory.
    pub fn read(&mut self, path: &str) -> Result<Vec<u8>> {
        let handle = self.resolve(path)?;
        self.read_handle_to_end(&handle)
    }

    /// Streams an entire file into a local writer.
    pub fn read_to_writer<W: Write + ?Sized>(&mut self, path: &str, writer: &mut W) -> Result<u64> {
        let handle = self.resolve(path)?;
        self.read_handle_to_writer(&handle, writer)
    }

    /// Streams a byte range into a local writer.
    pub fn read_range_to_writer<W: Write + ?Sized>(
        &mut self,
        path: &str,
        offset: u64,
        count: u64,
        writer: &mut W,
    ) -> Result<u64> {
        let handle = self.resolve(path)?;
        self.read_handle_range_to_writer(&handle, offset, count, writer)
    }

    /// Reads a byte range into memory.
    pub fn read_range(&mut self, path: &str, offset: u64, count: u64) -> Result<Vec<u8>> {
        let handle = self.resolve(path)?;
        self.read_handle_range(&handle, offset, count)
    }

    /// Reads up to `count` bytes at `offset`.
    pub fn read_at(&mut self, path: &str, offset: u64, count: u32) -> Result<Vec<u8>> {
        let handle = self.resolve(path)?;
        self.read_handle_at(&handle, offset, count)
    }

    /// Reads exactly `count` bytes at `offset`, failing if EOF is reached first.
    pub fn read_exact_at(&mut self, path: &str, offset: u64, count: u32) -> Result<Vec<u8>> {
        let data = self.read_at(path, offset, count)?;
        if data.len() != count as usize {
            return Err(Error::Protocol(format!(
                "READ returned {} bytes before EOF; expected {count}",
                data.len()
            )));
        }
        Ok(data)
    }

    /// Reads the target of a symbolic link.
    pub fn read_link(&mut self, path: &str) -> Result<String> {
        let handle = self.resolve(path)?;
        self.nfs.readlink(&handle)
    }

    /// Replaces or creates a file with `data` using file-sync stability.
    pub fn write(&mut self, path: &str, data: &[u8]) -> Result<()> {
        self.write_with_stability(path, data, StableHow::FileSync)
    }

    /// Replaces or creates a file with an explicit NFS write stability level.
    pub fn write_with_stability(
        &mut self,
        path: &str,
        data: &[u8],
        stable: StableHow,
    ) -> Result<()> {
        let handle = match self.resolve(path) {
            Ok(handle) => handle,
            Err(Error::Nfs {
                status: NfsStatus::NoEnt,
                ..
            }) => self.create_handle_with_how(
                path,
                CreateHow::Unchecked(SetAttr {
                    mode: Some(0o644),
                    ..SetAttr::default()
                }),
            )?,
            Err(err) => return Err(err),
        };

        self.nfs.setattr(&handle, &SetAttr::size(0))?;
        self.write_handle_all(&handle, 0, data, stable)
    }

    /// Replaces or creates a file by streaming from a local reader.
    pub fn write_from_reader<R: Read + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
    ) -> Result<u64> {
        self.write_from_reader_with_stability(path, reader, StableHow::FileSync)
    }

    /// Replaces or creates a file from a reader with an explicit write stability level.
    pub fn write_from_reader_with_stability<R: Read + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
        stable: StableHow,
    ) -> Result<u64> {
        let handle = match self.resolve(path) {
            Ok(handle) => handle,
            Err(Error::Nfs {
                status: NfsStatus::NoEnt,
                ..
            }) => self.create_handle_with_how(
                path,
                CreateHow::Unchecked(SetAttr {
                    mode: Some(0o644),
                    ..SetAttr::default()
                }),
            )?,
            Err(err) => return Err(err),
        };

        self.nfs.setattr(&handle, &SetAttr::size(0))?;
        self.write_handle_from_reader(&handle, reader, stable)
    }

    /// Writes a file through a temporary sibling and renames it into place.
    pub fn write_atomic(&mut self, path: &str, data: &[u8]) -> Result<()> {
        self.write_atomic_with_mode_and_stability(path, data, 0o644, StableHow::FileSync)
    }

    /// Atomic write with an explicit mode for the temporary file.
    pub fn write_atomic_with_mode(&mut self, path: &str, data: &[u8], mode: u32) -> Result<()> {
        self.write_atomic_with_mode_and_stability(path, data, mode, StableHow::FileSync)
    }

    /// Atomic write with an explicit NFS write stability level.
    pub fn write_atomic_with_stability(
        &mut self,
        path: &str,
        data: &[u8],
        stable: StableHow,
    ) -> Result<()> {
        self.write_atomic_with_mode_and_stability(path, data, 0o644, stable)
    }

    /// Atomic write with explicit mode and write stability.
    pub fn write_atomic_with_mode_and_stability(
        &mut self,
        path: &str,
        data: &[u8],
        mode: u32,
        stable: StableHow,
    ) -> Result<()> {
        let temp = temporary_sibling_path(path)?;
        let mut created = false;
        let result = (|| {
            let handle = self.create_guarded_handle(&temp, mode, &mut created)?;
            self.write_handle_all(&handle, 0, data, stable)?;
            self.rename(&temp, path)
        })();
        self.finish_with_temp_cleanup(
            result,
            created,
            &temp,
            "cleanup REMOVE after failed atomic write",
        )
    }

    /// Atomic write by streaming from a local reader.
    pub fn write_atomic_from_reader<R: Read + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
    ) -> Result<u64> {
        self.write_atomic_from_reader_with_mode_and_stability(
            path,
            reader,
            0o644,
            StableHow::FileSync,
        )
    }

    /// Atomic reader-based write with an explicit mode for the temporary file.
    pub fn write_atomic_from_reader_with_mode<R: Read + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
        mode: u32,
    ) -> Result<u64> {
        self.write_atomic_from_reader_with_mode_and_stability(
            path,
            reader,
            mode,
            StableHow::FileSync,
        )
    }

    /// Atomic reader-based write with an explicit NFS write stability level.
    pub fn write_atomic_from_reader_with_stability<R: Read + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
        stable: StableHow,
    ) -> Result<u64> {
        self.write_atomic_from_reader_with_mode_and_stability(path, reader, 0o644, stable)
    }

    /// Atomic reader-based write with explicit mode and write stability.
    pub fn write_atomic_from_reader_with_mode_and_stability<R: Read + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
        mode: u32,
        stable: StableHow,
    ) -> Result<u64> {
        let temp = temporary_sibling_path(path)?;
        let mut created = false;
        let result = (|| {
            let handle = self.create_guarded_handle(&temp, mode, &mut created)?;
            let written = self.write_handle_from_reader(&handle, reader, stable)?;
            self.rename(&temp, path)?;
            Ok(written)
        })();
        self.finish_with_temp_cleanup(
            result,
            created,
            &temp,
            "cleanup REMOVE after failed atomic reader write",
        )
    }

    /// Appends bytes to an existing file and returns bytes written.
    pub fn append(&mut self, path: &str, data: &[u8]) -> Result<u64> {
        self.append_with_stability(path, data, StableHow::FileSync)
    }

    /// Appends bytes with an explicit NFS write stability level.
    pub fn append_with_stability(
        &mut self,
        path: &str,
        data: &[u8],
        stable: StableHow,
    ) -> Result<u64> {
        let handle = self.resolve(path)?;
        let attr = self.nfs.getattr(&handle)?;
        self.write_handle_all(&handle, attr.size, data, stable)?;
        let mut written = 0;
        advance_offset(&mut written, data.len(), "APPEND")?;
        Ok(written)
    }

    /// Appends bytes from a local reader and returns bytes written.
    pub fn append_from_reader<R: Read + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
    ) -> Result<u64> {
        self.append_from_reader_with_stability(path, reader, StableHow::FileSync)
    }

    /// Appends from a reader with an explicit NFS write stability level.
    pub fn append_from_reader_with_stability<R: Read + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
        stable: StableHow,
    ) -> Result<u64> {
        let handle = self.resolve(path)?;
        let attr = self.nfs.getattr(&handle)?;
        self.write_handle_from_reader_at(&handle, attr.size, reader, stable)
    }

    /// Truncates or extends a file to `size` bytes.
    pub fn truncate(&mut self, path: &str, size: u64) -> Result<()> {
        let handle = self.resolve(path)?;
        self.nfs.setattr(&handle, &SetAttr::size(size))?;
        Ok(())
    }

    /// Applies NFSv3 attributes to a path.
    pub fn setattr(&mut self, path: &str, attr: &SetAttr) -> Result<()> {
        let handle = self.resolve(path)?;
        self.nfs.setattr(&handle, attr)?;
        Ok(())
    }

    /// Sets POSIX mode bits.
    pub fn set_mode(&mut self, path: &str, mode: u32) -> Result<()> {
        self.setattr(path, &SetAttr::mode(mode))
    }

    /// Sets numeric uid.
    pub fn set_uid(&mut self, path: &str, uid: u32) -> Result<()> {
        self.setattr(path, &SetAttr::uid(uid))
    }

    /// Sets numeric gid.
    pub fn set_gid(&mut self, path: &str, gid: u32) -> Result<()> {
        self.setattr(path, &SetAttr::gid(gid))
    }

    /// Sets numeric uid and gid.
    pub fn set_ownership(&mut self, path: &str, uid: u32, gid: u32) -> Result<()> {
        self.setattr(path, &SetAttr::ownership(uid, gid))
    }

    /// Sets access and modification times.
    pub fn set_times(
        &mut self,
        path: &str,
        atime: Option<NfsTime>,
        mtime: Option<NfsTime>,
    ) -> Result<()> {
        self.setattr(path, &SetAttr::times(atime, mtime))
    }

    /// Updates access and modification times to the server time.
    pub fn touch(&mut self, path: &str) -> Result<()> {
        self.setattr(path, &SetAttr::touch())
    }

    /// Writes bytes at `offset` using file-sync stability.
    pub fn write_at(&mut self, path: &str, offset: u64, data: &[u8]) -> Result<()> {
        self.write_at_with_stability(path, offset, data, StableHow::FileSync)
    }

    /// Writes bytes at `offset` with an explicit NFS write stability level.
    pub fn write_at_with_stability(
        &mut self,
        path: &str,
        offset: u64,
        data: &[u8],
        stable: StableHow,
    ) -> Result<()> {
        let handle = self.resolve(path)?;
        self.write_handle_all(&handle, offset, data, stable)
    }

    /// Copies a file, replacing or creating the destination.
    pub fn copy(&mut self, from: &str, to: &str) -> Result<u64> {
        self.copy_with_stability(from, to, StableHow::FileSync)
    }

    /// Copies a file with an explicit NFS write stability level.
    pub fn copy_with_stability(&mut self, from: &str, to: &str, stable: StableHow) -> Result<u64> {
        if normalize_path(from)? == normalize_path(to)? {
            return Err(Error::Protocol(
                "copy source and destination must differ".to_owned(),
            ));
        }
        let source = self.resolve(from)?;
        let source_attr = self.nfs.getattr(&source)?;
        let target = match self.resolve(to) {
            Ok(handle) => handle,
            Err(Error::Nfs {
                status: NfsStatus::NoEnt,
                ..
            }) => self.create_handle_with_how(
                to,
                CreateHow::Unchecked(SetAttr {
                    mode: Some(source_attr.mode & 0o7777),
                    ..SetAttr::default()
                }),
            )?,
            Err(err) => return Err(err),
        };
        ensure_distinct_copy_handles(&source, &target)?;

        self.nfs.setattr(&target, &SetAttr::size(0))?;
        self.copy_handles(&source, &target, stable)
    }

    /// Copies through a temporary sibling and renames it into place.
    pub fn copy_atomic(&mut self, from: &str, to: &str) -> Result<u64> {
        self.copy_atomic_with_stability(from, to, StableHow::FileSync)
    }

    /// Atomic copy with an explicit NFS write stability level.
    pub fn copy_atomic_with_stability(
        &mut self,
        from: &str,
        to: &str,
        stable: StableHow,
    ) -> Result<u64> {
        if normalize_path(from)? == normalize_path(to)? {
            return Err(Error::Protocol(
                "copy source and destination must differ".to_owned(),
            ));
        }
        let source = self.resolve(from)?;
        let source_attr = self.nfs.getattr(&source)?;
        let temp = temporary_sibling_path(to)?;
        let mut created = false;

        let result = (|| {
            let target =
                self.create_guarded_handle(&temp, source_attr.mode & 0o7777, &mut created)?;
            let copied = self.copy_handles(&source, &target, stable)?;
            self.rename(&temp, to)?;
            Ok(copied)
        })();

        self.finish_with_temp_cleanup(
            result,
            created,
            &temp,
            "cleanup REMOVE after failed atomic copy",
        )
    }

    /// Commits previously unstable writes for a byte range.
    pub fn commit(&mut self, path: &str, offset: u64, count: u32) -> Result<CommitResult> {
        let handle = self.resolve(path)?;
        self.nfs.commit(&handle, offset, count)
    }

    /// Creates a new file using guarded create semantics.
    pub fn create(&mut self, path: &str, mode: u32) -> Result<()> {
        self.create_new(path, mode)
    }

    /// Creates a new file and fails if it already exists.
    pub fn create_new(&mut self, path: &str, mode: u32) -> Result<()> {
        self.create_handle_new(path, mode).map(|_| ())
    }

    /// Creates or replaces a file using unchecked create semantics.
    pub fn create_unchecked(&mut self, path: &str, mode: u32) -> Result<()> {
        self.create_handle_with_how(
            path,
            CreateHow::Unchecked(SetAttr {
                mode: Some(mode),
                ..SetAttr::default()
            }),
        )
        .map(|_| ())
    }

    fn create_handle_new(&mut self, path: &str, mode: u32) -> Result<FileHandle> {
        let mut created = false;
        self.create_guarded_handle(path, mode, &mut created)
    }

    fn create_handle_with_how(&mut self, path: &str, how: CreateHow) -> Result<FileHandle> {
        let (parent, name) = self.resolve_parent(path)?;
        let result = self.nfs.create(&parent, &name, &how)?;
        self.handle_from_create_result(&parent, &name, result)
    }

    fn create_guarded_handle(
        &mut self,
        path: &str,
        mode: u32,
        created: &mut bool,
    ) -> Result<FileHandle> {
        let (parent, name) = self.resolve_parent(path)?;
        let result = self
            .nfs
            .create(&parent, &name, &CreateHow::Guarded(SetAttr::mode(mode)))?;
        *created = true;
        self.handle_from_create_result(&parent, &name, result)
    }

    fn handle_from_create_result(
        &mut self,
        parent: &FileHandle,
        name: &str,
        result: CreateResult,
    ) -> Result<FileHandle> {
        match result.object {
            Some(handle) => Ok(handle),
            None => Ok(self.nfs.lookup(parent, name)?.object),
        }
    }

    fn finish_with_temp_cleanup<T>(
        &mut self,
        result: Result<T>,
        created: bool,
        temp: &str,
        cleanup_context: &'static str,
    ) -> Result<T> {
        match result {
            Ok(value) => Ok(value),
            Err(err) if created => Err(cleanup_error(err, cleanup_context, self.remove(temp))),
            Err(err) => Err(err),
        }
    }

    /// Creates a directory.
    pub fn mkdir(&mut self, path: &str, mode: u32) -> Result<()> {
        let (parent, name) = self.resolve_parent(path)?;
        self.nfs.mkdir(&parent, &name, &SetAttr::mode(mode))?;
        Ok(())
    }

    /// Creates a directory and missing parents, like `mkdir -p`.
    pub fn create_dir_all(&mut self, path: &str, mode: u32) -> Result<()> {
        let components = normalize_path(path)?;
        let mut current = self.root.clone();
        let mut current_path = String::from("/");

        for component in components {
            current_path = join_path(&current_path, component);
            match self.nfs.lookup(&current, component) {
                Ok(lookup) => {
                    self.ensure_directory(&current_path, &lookup.object, lookup.object_attributes)?;
                    current = lookup.object;
                }
                Err(Error::Nfs {
                    status: NfsStatus::NoEnt,
                    ..
                }) => match self.nfs.mkdir(&current, component, &SetAttr::mode(mode)) {
                    Ok(created) => {
                        current = match created.object {
                            Some(handle) => handle,
                            None => self.nfs.lookup(&current, component)?.object,
                        };
                    }
                    Err(Error::Nfs {
                        status: NfsStatus::Exist,
                        ..
                    }) => {
                        let lookup = self.nfs.lookup(&current, component)?;
                        self.ensure_directory(
                            &current_path,
                            &lookup.object,
                            lookup.object_attributes,
                        )?;
                        current = lookup.object;
                    }
                    Err(err) => return Err(err),
                },
                Err(err) => return Err(err),
            }
        }

        Ok(())
    }

    /// Creates a symbolic link at `path` pointing to `target`.
    pub fn symlink(&mut self, path: &str, target: &str) -> Result<()> {
        let (parent, name) = self.resolve_parent(path)?;
        self.nfs
            .symlink(&parent, &name, target, &SetAttr::default())?;
        Ok(())
    }

    /// Creates a FIFO special file.
    pub fn create_fifo(&mut self, path: &str, mode: u32) -> Result<()> {
        self.mknod(
            path,
            MknodData::Fifo {
                attributes: SetAttr::mode(mode),
            },
        )
    }

    /// Creates a socket special file.
    pub fn create_socket(&mut self, path: &str, mode: u32) -> Result<()> {
        self.mknod(
            path,
            MknodData::Socket {
                attributes: SetAttr::mode(mode),
            },
        )
    }

    /// Creates a block device special file.
    pub fn create_block_device(
        &mut self,
        path: &str,
        major: u32,
        minor: u32,
        mode: u32,
    ) -> Result<()> {
        self.mknod(
            path,
            MknodData::BlockDevice {
                attributes: SetAttr::mode(mode),
                spec: SpecData {
                    specdata1: major,
                    specdata2: minor,
                },
            },
        )
    }

    /// Creates a character device special file.
    pub fn create_character_device(
        &mut self,
        path: &str,
        major: u32,
        minor: u32,
        mode: u32,
    ) -> Result<()> {
        self.mknod(
            path,
            MknodData::CharacterDevice {
                attributes: SetAttr::mode(mode),
                spec: SpecData {
                    specdata1: major,
                    specdata2: minor,
                },
            },
        )
    }

    fn mknod(&mut self, path: &str, what: MknodData) -> Result<()> {
        let (parent, name) = self.resolve_parent(path)?;
        self.nfs.mknod(&parent, &name, &what)?;
        Ok(())
    }

    /// Creates a hard link.
    pub fn hard_link(&mut self, existing: &str, link: &str) -> Result<()> {
        let file = self.resolve(existing)?;
        let (link_dir, link_name) = self.resolve_parent(link)?;
        self.nfs.link(&file, &link_dir, &link_name)?;
        Ok(())
    }

    /// Removes a non-directory entry.
    pub fn remove(&mut self, path: &str) -> Result<()> {
        let (parent, name) = self.resolve_parent(path)?;
        self.nfs.remove(&parent, &name)?;
        Ok(())
    }

    /// Removes a non-directory entry if it exists.
    pub fn remove_if_exists(&mut self, path: &str) -> Result<bool> {
        match self.remove(path) {
            Ok(()) => Ok(true),
            Err(err) if err.is_not_found() => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Removes an empty directory.
    pub fn rmdir(&mut self, path: &str) -> Result<()> {
        let (parent, name) = self.resolve_parent(path)?;
        self.nfs.rmdir(&parent, &name)?;
        Ok(())
    }

    /// Removes an empty directory if it exists.
    pub fn rmdir_if_exists(&mut self, path: &str) -> Result<bool> {
        match self.rmdir(path) {
            Ok(()) => Ok(true),
            Err(err) if err.is_not_found() => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Recursively removes a file tree.
    ///
    /// The export root itself cannot be removed through this method.
    pub fn remove_all(&mut self, path: &str) -> Result<()> {
        if normalize_path(path)?.is_empty() {
            return Err(Error::InvalidPath(path.to_owned()));
        }

        enum RemoveTask {
            Visit(String, Option<FileType>),
            RemoveDir(String),
        }

        let file_type = self.metadata(path)?.file_type;
        let mut stack = vec![RemoveTask::Visit(path.to_owned(), Some(file_type))];
        while let Some(task) = stack.pop() {
            match task {
                RemoveTask::Visit(path, file_type) => {
                    let file_type = match file_type {
                        Some(file_type) => file_type,
                        None => self.metadata(&path)?.file_type,
                    };
                    if file_type == FileType::Directory {
                        stack.push(RemoveTask::RemoveDir(path.clone()));
                        let entries = self.read_dir(&path)?;
                        for entry in entries.into_iter().rev() {
                            if entry.name == "." || entry.name == ".." {
                                continue;
                            }
                            let child = join_path(&path, &entry.name);
                            let child_type = entry.attributes.map(|attr| attr.file_type);
                            stack.push(RemoveTask::Visit(child, child_type));
                        }
                    } else {
                        self.remove(&path)?;
                    }
                }
                RemoveTask::RemoveDir(path) => self.rmdir(&path)?,
            }
        }

        Ok(())
    }

    /// Recursively removes a file tree if it exists.
    pub fn remove_all_if_exists(&mut self, path: &str) -> Result<bool> {
        match self.remove_all(path) {
            Ok(()) => Ok(true),
            Err(err) if err.is_not_found() => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Renames or moves a path.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        let (from_parent, from_name) = self.resolve_parent(from)?;
        let (to_parent, to_name) = self.resolve_parent(to)?;
        self.nfs
            .rename(&from_parent, &from_name, &to_parent, &to_name)?;
        Ok(())
    }

    /// Reads all entries in a directory, subject to the client's entry limit.
    pub fn read_dir(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        self.read_dir_with_limit(path, self.max_dir_entries)
    }

    /// Reads all entries in a directory with a per-call entry limit.
    pub fn read_dir_limited(&mut self, path: &str, max_entries: usize) -> Result<Vec<DirEntry>> {
        validate_max_dir_entries(max_entries)?;
        self.read_dir_with_limit(path, max_entries.min(self.max_dir_entries))
    }

    /// Reads one page of directory entries.
    pub fn read_dir_page(&mut self, path: &str, cursor: Option<DirPageCursor>) -> Result<DirPage> {
        self.read_dir_page_limited(path, cursor, self.max_dir_entries)
    }

    /// Reads one page of directory entries with a per-page entry limit.
    pub fn read_dir_page_limited(
        &mut self,
        path: &str,
        cursor: Option<DirPageCursor>,
        max_entries: usize,
    ) -> Result<DirPage> {
        validate_max_dir_entries(max_entries)?;
        let max_entries = max_entries.min(self.max_dir_entries);
        let dir = self.resolve(path)?;
        let cursor = cursor.unwrap_or_default();
        let batch = match self.nfs.readdirplus(
            &dir,
            cursor.cookie,
            cursor.cookieverf,
            self.dir_size,
            self.dir_size,
        ) {
            Ok(batch) => batch,
            Err(Error::Nfs {
                status: NfsStatus::NotSupported,
                ..
            }) => self
                .nfs
                .readdir(&dir, cursor.cookie, cursor.cookieverf, self.dir_size)?,
            Err(err) => return Err(err),
        };
        dir_page_from_batch(&batch, cursor.cookie, max_entries)
    }

    fn read_dir_with_limit(&mut self, path: &str, max_entries: usize) -> Result<Vec<DirEntry>> {
        let dir = self.resolve(path)?;
        let mut entries = Vec::new();
        let mut cookie = 0;
        let mut cookieverf = [0; 8];

        loop {
            let batch =
                match self
                    .nfs
                    .readdirplus(&dir, cookie, cookieverf, self.dir_size, self.dir_size)
                {
                    Ok(batch) => batch,
                    Err(Error::Nfs {
                        status: NfsStatus::NotSupported,
                        ..
                    }) => self.nfs.readdir(&dir, cookie, cookieverf, self.dir_size)?,
                    Err(err) => return Err(err),
                };

            append_dir_entries(&mut entries, &batch, max_entries)?;
            match next_dir_cursor(&batch, cookie)? {
                Some(next) => {
                    cookie = next.cookie;
                    cookieverf = next.cookieverf;
                }
                None => break,
            }
        }

        Ok(entries)
    }

    /// Sends an NFSv3 unmount request for the export.
    pub fn unmount(self) -> Result<()> {
        let mut mount = MountClient::connect_with_timeout(
            (self.target.host.as_str(), self.mount_port),
            self.auth.clone(),
            self.builder.timeout,
        )?;
        mount.set_timeout(self.builder.timeout)?;
        mount.unmount(&self.target.export)
    }

    fn connect_with_builder(builder: ClientBuilder) -> Result<Self> {
        validate_remote_target(&builder.target)?;
        let read_size_limit = validate_transfer_size("read_size", builder.read_size_limit)?;
        let write_size_limit = validate_transfer_size("write_size", builder.write_size_limit)?;
        let dir_size_limit = validate_transfer_size("dir_size", builder.dir_size_limit)?;
        validate_max_dir_entries(builder.max_dir_entries)?;

        let stored_builder = builder.clone();
        let mount_port = match builder.mount_port {
            Some(port) => {
                validate_port("mount_port", port)?;
                port
            }
            None => portmap::get_tcp_port_with_timeout(
                &builder.target.host,
                MOUNT_PROGRAM,
                MOUNT_VERSION,
                builder.timeout,
            )?,
        };

        let mut mount = MountClient::connect_with_timeout(
            (builder.target.host.as_str(), mount_port),
            builder.auth.clone(),
            builder.timeout,
        )?;
        mount.set_timeout(builder.timeout)?;
        let mount_info = mount.mount(&builder.target.export)?;
        let cleanup_mount_context = "cleanup UMOUNT after failed NFSv3 connect";

        let nfs_port = match builder.nfs_port {
            Some(port) => {
                if let Err(err) = validate_port("nfs_port", port) {
                    return Err(cleanup_error(
                        err,
                        cleanup_mount_context,
                        mount.unmount(&builder.target.export),
                    ));
                }
                port
            }
            None => portmap::get_tcp_port_with_timeout(
                &builder.target.host,
                NFS_PROGRAM,
                NFS_VERSION,
                builder.timeout,
            )
            .unwrap_or(NFS_PORT),
        };

        let mut nfs = match Nfs3Client::connect_with_timeout(
            (builder.target.host.as_str(), nfs_port),
            builder.auth.clone(),
            builder.timeout,
        ) {
            Ok(nfs) => nfs,
            Err(err) => {
                return Err(cleanup_error(
                    err,
                    cleanup_mount_context,
                    mount.unmount(&builder.target.export),
                ));
            }
        };
        if let Err(err) = nfs.set_timeout(builder.timeout) {
            return Err(cleanup_error(
                err,
                cleanup_mount_context,
                mount.unmount(&builder.target.export),
            ));
        }
        nfs.set_retry_policy(builder.retry_policy);

        let fsinfo = match nfs.fsinfo(&mount_info.file_handle) {
            Ok(fsinfo) => fsinfo,
            Err(err) => {
                return Err(cleanup_error(
                    err,
                    cleanup_mount_context,
                    mount.unmount(&builder.target.export),
                ));
            }
        };
        let read_size = clamp_io_size(fsinfo.read_preferred, fsinfo.read_max, read_size_limit);
        let write_size = clamp_io_size(fsinfo.write_preferred, fsinfo.write_max, write_size_limit);
        let dir_size = clamp_dir_size(fsinfo.dir_preferred, dir_size_limit);
        if let Err(err) = nfs.set_max_record_size(max_record_size_for_payloads(&[
            read_size, write_size, dir_size,
        ])) {
            return Err(cleanup_error(
                err,
                cleanup_mount_context,
                mount.unmount(&builder.target.export),
            ));
        }

        Ok(Self {
            builder: stored_builder,
            target: builder.target,
            auth: builder.auth,
            mount_port,
            root: mount_info.file_handle,
            nfs,
            fsinfo: Some(fsinfo),
            read_size,
            write_size,
            dir_size,
            max_dir_entries: builder.max_dir_entries,
        })
    }

    fn resolve(&mut self, path: &str) -> Result<FileHandle> {
        let components = normalize_path(path)?;
        let mut current = self.root.clone();
        for component in components {
            current = self.nfs.lookup(&current, component)?.object;
        }
        Ok(current)
    }

    fn resolve_parent(&mut self, path: &str) -> Result<(FileHandle, String)> {
        let mut components = normalize_path(path)?;
        let name = components
            .pop()
            .ok_or_else(|| Error::InvalidPath(path.to_owned()))?
            .to_owned();
        let mut current = self.root.clone();
        for component in components {
            current = self.nfs.lookup(&current, component)?.object;
        }
        Ok((current, name))
    }

    fn ensure_directory(
        &mut self,
        path: &str,
        handle: &FileHandle,
        attr: Option<FileAttr>,
    ) -> Result<()> {
        let attr = match attr {
            Some(attr) => attr,
            None => self.nfs.getattr(handle)?,
        };
        if attr.file_type == FileType::Directory {
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "{path:?} exists but is not a directory"
            )))
        }
    }

    fn read_handle_to_end(&mut self, handle: &FileHandle) -> Result<Vec<u8>> {
        let mut offset = 0;
        let mut out = Vec::new();
        loop {
            let chunk = self.nfs.read(handle, offset, self.read_size)?;
            if chunk.data.len() > self.read_size as usize {
                return Err(Error::Protocol(format!(
                    "READ returned {} bytes for a {} byte request",
                    chunk.data.len(),
                    self.read_size
                )));
            }
            if chunk.data.is_empty() {
                if chunk.eof {
                    return Ok(out);
                }
                return Err(Error::Protocol(
                    "READ returned no data before EOF".to_owned(),
                ));
            }
            advance_offset(&mut offset, chunk.data.len(), "READ")?;
            out.extend_from_slice(&chunk.data);
            if chunk.eof {
                return Ok(out);
            }
        }
    }

    fn read_handle_to_writer<W: Write + ?Sized>(
        &mut self,
        handle: &FileHandle,
        writer: &mut W,
    ) -> Result<u64> {
        let mut offset = 0;
        let mut total = 0;
        loop {
            let chunk = self.nfs.read(handle, offset, self.read_size)?;
            if chunk.data.len() > self.read_size as usize {
                return Err(Error::Protocol(format!(
                    "READ returned {} bytes for a {} byte request",
                    chunk.data.len(),
                    self.read_size
                )));
            }
            if chunk.data.is_empty() {
                if chunk.eof {
                    return Ok(total);
                }
                return Err(Error::Protocol(
                    "READ returned no data before EOF".to_owned(),
                ));
            }
            writer.write_all(&chunk.data)?;
            advance_offset(&mut offset, chunk.data.len(), "READ")?;
            advance_offset(&mut total, chunk.data.len(), "READ total")?;
            if chunk.eof {
                return Ok(total);
            }
        }
    }

    fn read_handle_at(&mut self, handle: &FileHandle, offset: u64, count: u32) -> Result<Vec<u8>> {
        self.read_handle_range(handle, offset, u64::from(count))
    }

    fn read_handle_range(
        &mut self,
        handle: &FileHandle,
        offset: u64,
        count: u64,
    ) -> Result<Vec<u8>> {
        let capacity = usize::try_from(count).unwrap_or(usize::MAX);
        let mut out = Vec::with_capacity(capacity.min(self.read_size as usize));
        self.read_handle_range_to_writer(handle, offset, count, &mut out)?;
        Ok(out)
    }

    fn read_handle_range_to_writer<W: Write + ?Sized>(
        &mut self,
        handle: &FileHandle,
        mut offset: u64,
        mut remaining: u64,
        writer: &mut W,
    ) -> Result<u64> {
        let mut total = 0;
        while remaining > 0 {
            let request = cmp::min(u64::from(self.read_size), remaining) as u32;
            let chunk = self.nfs.read(handle, offset, request)?;
            if chunk.data.len() > request as usize {
                return Err(Error::Protocol(format!(
                    "READ returned {} bytes for a {request} byte request",
                    chunk.data.len()
                )));
            }
            if chunk.data.is_empty() {
                if chunk.eof {
                    return Ok(total);
                }
                return Err(Error::Protocol(
                    "READ returned no data before EOF".to_owned(),
                ));
            }
            writer.write_all(&chunk.data)?;
            advance_offset(&mut offset, chunk.data.len(), "READ")?;
            advance_offset(&mut total, chunk.data.len(), "READ total")?;
            remaining -= chunk.data.len() as u64;
            if chunk.eof {
                return Ok(total);
            }
        }
        Ok(total)
    }

    fn write_handle_all(
        &mut self,
        handle: &FileHandle,
        mut offset: u64,
        mut data: &[u8],
        stable: StableHow,
    ) -> Result<()> {
        while !data.is_empty() {
            let chunk_offset = offset;
            let chunk_len = cmp::min(data.len(), self.write_size as usize);
            let result = self
                .nfs
                .write(handle, chunk_offset, stable, &data[..chunk_len])?;
            let written = result.count;
            if written == 0 {
                return Err(Error::Protocol("WRITE accepted zero bytes".to_owned()));
            }
            let written = written as usize;
            if written > chunk_len {
                return Err(Error::Protocol(format!(
                    "WRITE reported {written} bytes for a {chunk_len} byte request"
                )));
            }
            if !result.committed.satisfies(stable) {
                let commit = self.nfs.commit(handle, chunk_offset, result.count)?;
                if commit.verifier != result.verifier {
                    return Err(Error::Protocol(
                        "COMMIT verifier changed after unstable WRITE".to_owned(),
                    ));
                }
            }
            advance_offset(&mut offset, written, "WRITE")?;
            data = &data[written..];
        }
        Ok(())
    }

    fn write_handle_from_reader<R: Read + ?Sized>(
        &mut self,
        handle: &FileHandle,
        reader: &mut R,
        stable: StableHow,
    ) -> Result<u64> {
        self.write_handle_from_reader_at(handle, 0, reader, stable)
    }

    fn write_handle_from_reader_at<R: Read + ?Sized>(
        &mut self,
        handle: &FileHandle,
        mut offset: u64,
        reader: &mut R,
        stable: StableHow,
    ) -> Result<u64> {
        let mut written = 0;
        let mut buffer = vec![0; self.write_size as usize];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                return Ok(written);
            }
            self.write_handle_all(handle, offset, &buffer[..read], stable)?;
            advance_offset(&mut offset, read, "WRITE reader")?;
            advance_offset(&mut written, read, "WRITE reader total")?;
        }
    }

    fn copy_handles(
        &mut self,
        source: &FileHandle,
        target: &FileHandle,
        stable: StableHow,
    ) -> Result<u64> {
        let mut offset = 0;
        loop {
            let chunk = self.nfs.read(source, offset, self.read_size)?;
            if chunk.data.len() > self.read_size as usize {
                return Err(Error::Protocol(format!(
                    "READ returned {} bytes for a {} byte request",
                    chunk.data.len(),
                    self.read_size
                )));
            }
            if chunk.data.is_empty() {
                if chunk.eof {
                    return Ok(offset);
                }
                return Err(Error::Protocol(
                    "READ returned no data before EOF".to_owned(),
                ));
            }
            self.write_handle_all(target, offset, &chunk.data, stable)?;
            advance_offset(&mut offset, chunk.data.len(), "COPY")?;
            if chunk.eof {
                return Ok(offset);
            }
        }
    }
}
