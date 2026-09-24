//! NFSv4 client support.
//!
//! NFSv4 is session-based and uses the server's v4 pseudo-filesystem rather
//! than the NFSv3 MOUNT service. Paths passed to this module are absolute paths
//! in that pseudo-filesystem, for example `/export/file.txt`.
//! The high-level clients negotiate NFSv4.2 and fall back to NFSv4.1 when the
//! server does not accept the newer minor version.
//!
//! Use [`blocking::Client`] with the default `blocking` feature, or
//! [`tokio::Client`] with the `tokio` feature.

#![cfg_attr(not(any(feature = "blocking", feature = "tokio")), allow(dead_code))]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};

#[cfg(feature = "blocking")]
pub mod blocking;
mod client;
#[cfg(any(feature = "blocking", feature = "tokio"))]
mod lease;
mod proto;
#[cfg(all(test, any(feature = "blocking", feature = "tokio")))]
mod recovery_tests;

#[cfg(feature = "tokio")]
pub mod tokio;

/// Low-level NFSv4 wire types and COMPOUND operation structures.
///
/// This module is available with the `protocol` feature. It exposes the
/// protocol representation used by the clients, but the stable application API
/// is the path-oriented client layer.
#[cfg(feature = "protocol")]
pub mod protocol {
    pub use super::proto::*;
}

pub use client::{
    ByteRangeLock, DeviceListCursor, DeviceListPage, DirEntry, DirPage, DirPageCursor,
};
pub use proto::{
    ACCESS4_DELETE, ACCESS4_EXECUTE, ACCESS4_EXTEND, ACCESS4_LOOKUP, ACCESS4_MODIFY, ACCESS4_READ,
    AccessResult, AppDataBlock, BasicAttributes, BindConnToSessionResult, Bitmap, CallbackSecParms,
    ChannelDirFromClient, ChannelDirFromServer, CommitResult, CopyNotifyResult, CopyRequirements,
    CopyResult, DelegationClaim, DeviceAddr, DeviceError, DeviceId, FATTR4_ACL, FATTR4_ACLSUPPORT,
    FATTR4_ARCHIVE, FATTR4_CANSETTIME, FATTR4_CASE_INSENSITIVE, FATTR4_CASE_PRESERVING,
    FATTR4_CHANGE, FATTR4_CHANGE_ATTR_TYPE, FATTR4_CHANGE_POLICY, FATTR4_CHOWN_RESTRICTED,
    FATTR4_CLONE_BLKSIZE, FATTR4_DACL, FATTR4_DIR_NOTIF_DELAY, FATTR4_DIRENT_NOTIF_DELAY,
    FATTR4_FH_EXPIRE_TYPE, FATTR4_FILEHANDLE, FATTR4_FILEID, FATTR4_FILES_AVAIL, FATTR4_FILES_FREE,
    FATTR4_FILES_TOTAL, FATTR4_FS_CHARSET_CAP, FATTR4_FS_LAYOUT_TYPE, FATTR4_FS_LOCATIONS,
    FATTR4_FS_LOCATIONS_INFO, FATTR4_FS_STATUS, FATTR4_FSID, FATTR4_HIDDEN, FATTR4_HOMOGENEOUS,
    FATTR4_LAYOUT_ALIGNMENT, FATTR4_LAYOUT_BLKSIZE, FATTR4_LAYOUT_HINT, FATTR4_LAYOUT_TYPE,
    FATTR4_LEASE_TIME, FATTR4_LINK_SUPPORT, FATTR4_MAXFILESIZE, FATTR4_MAXLINK, FATTR4_MAXNAME,
    FATTR4_MAXREAD, FATTR4_MAXWRITE, FATTR4_MDSTHRESHOLD, FATTR4_MIMETYPE, FATTR4_MODE,
    FATTR4_MODE_SET_MASKED, FATTR4_MOUNTED_ON_FILEID, FATTR4_NAMED_ATTR, FATTR4_NO_TRUNC,
    FATTR4_NUMLINKS, FATTR4_OWNER, FATTR4_OWNER_GROUP, FATTR4_QUOTA_AVAIL_HARD,
    FATTR4_QUOTA_AVAIL_SOFT, FATTR4_QUOTA_USED, FATTR4_RAWDEV, FATTR4_RDATTR_ERROR,
    FATTR4_RETENTEVT_GET, FATTR4_RETENTEVT_SET, FATTR4_RETENTION_GET, FATTR4_RETENTION_HOLD,
    FATTR4_RETENTION_SET, FATTR4_SACL, FATTR4_SEC_LABEL, FATTR4_SIZE, FATTR4_SPACE_AVAIL,
    FATTR4_SPACE_FREE, FATTR4_SPACE_FREED, FATTR4_SPACE_TOTAL, FATTR4_SPACE_USED,
    FATTR4_SUPPATTR_EXCLCREAT, FATTR4_SUPPORTED_ATTRS, FATTR4_SYMLINK_SUPPORT, FATTR4_SYSTEM,
    FATTR4_TIME_ACCESS, FATTR4_TIME_ACCESS_SET, FATTR4_TIME_BACKUP, FATTR4_TIME_CREATE,
    FATTR4_TIME_DELTA, FATTR4_TIME_METADATA, FATTR4_TIME_MODIFY, FATTR4_TIME_MODIFY_SET,
    FATTR4_UNIQUE_HANDLES, Fattr, FileHandle, FileType, FsInfo, FsStat, GetDeviceInfoResult,
    GetDeviceListResult, GetDirDelegationArgs, GetDirDelegationResult, IoAdviceType,
    IoAdviseResult, IoInfo, Layout, LayoutCommitResult, LayoutContent, LayoutGetResult,
    LayoutIomode, LayoutReturnResult, LayoutType, LayoutUpdate, LockDenied, LockType, NFS4_FHSIZE,
    NFS4_MINOR_VERSION_LATEST, NFS4_MINOR_VERSION_SESSION_MIN, NFS4_MINOR_VERSION_V42,
    NFS4_NSECONDS_PER_SECOND, NFS4_OPAQUE_LIMIT, NFS4_PORT, NFS4_PROGRAM, NFS4_SESSIONID_SIZE,
    NFS4_VERIFIER_SIZE, NFS4_VERSION, NetLoc, NfsAce, NfsSpaceLimit, NfsTime,
    OPEN4_SHARE_ACCESS_WANT_ANY_DELEG, OPEN4_SHARE_ACCESS_WANT_CANCEL,
    OPEN4_SHARE_ACCESS_WANT_DELEG_MASK, OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
    OPEN4_SHARE_ACCESS_WANT_NO_PREFERENCE, OPEN4_SHARE_ACCESS_WANT_PUSH_DELEG_WHEN_UNCONTENDED,
    OPEN4_SHARE_ACCESS_WANT_READ_DELEG, OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL,
    OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG, OffloadStatusResult, OpCode, OpenDelegation,
    OpenDelegationType, OpenNoneDelegation, OpenReadDelegation, OpenWriteDelegation, PathConf,
    ReadPlusContent, ReadPlusResult, RpcGssService, SecInfo, SecInfoStyle, SeekContent, SeekResult,
    SetAttrs, SetSsvResult, SetTime, StableHow, StateId, Status, Verifier, WhyNoDelegation,
    WriteResponse,
};

pub(crate) fn validate_owner_id(owner_id: &[u8]) -> Result<()> {
    validate_opaque_id("owner_id", owner_id)
}

pub(crate) fn validate_open_owner(open_owner: &[u8]) -> Result<()> {
    validate_opaque_id("open_owner", open_owner)
}

pub(crate) fn validate_lock_owner(lock_owner: &[u8]) -> Result<()> {
    validate_opaque_id("lock_owner", lock_owner)
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

fn validate_opaque_id(name: &'static str, value: &[u8]) -> Result<()> {
    if value.len() > proto::NFS4_OPAQUE_LIMIT {
        return Err(Error::Protocol(format!(
            "NFSv4 {name} length {} exceeds opaque limit {}",
            value.len(),
            proto::NFS4_OPAQUE_LIMIT
        )));
    }
    Ok(())
}

pub(crate) fn validate_transfer_size(name: &'static str, size: u32) -> Result<()> {
    if size == 0 || size as usize > proto::NFS4_MAX_IO {
        return Err(Error::Protocol(format!(
            "{name} must be in 1..={} bytes",
            proto::NFS4_MAX_IO
        )));
    }
    Ok(())
}

pub(crate) fn validate_max_dir_entries(max_dir_entries: usize) -> Result<()> {
    if max_dir_entries == 0 {
        return Err(Error::Protocol(
            "max_dir_entries must be greater than zero".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_minor_version(name: &'static str, minor_version: u32) -> Result<()> {
    if !(proto::NFS4_MINOR_VERSION_SESSION_MIN..=proto::NFS4_MINOR_VERSION_LATEST)
        .contains(&minor_version)
    {
        return Err(Error::Protocol(format!(
            "{name} must be in {}..={}",
            proto::NFS4_MINOR_VERSION_SESSION_MIN,
            proto::NFS4_MINOR_VERSION_LATEST
        )));
    }
    Ok(())
}

pub(crate) fn negotiated_minor_versions(max_minor_version: u32) -> impl Iterator<Item = u32> {
    (proto::NFS4_MINOR_VERSION_SESSION_MIN..=max_minor_version).rev()
}

pub(crate) fn require_minor_version(
    operation: &'static str,
    negotiated: u32,
    required: u32,
) -> Result<()> {
    if negotiated >= required {
        Ok(())
    } else {
        Err(Error::Protocol(format!(
            "NFSv4 operation {operation} requires minor version {required}, negotiated {negotiated}"
        )))
    }
}

pub(crate) fn clamp_io_size(server_max: Option<u64>, configured_limit: u32) -> u32 {
    match server_max {
        Some(0) | None => configured_limit,
        Some(max) => u64::from(configured_limit).min(max).max(1) as u32,
    }
}

pub(crate) fn default_owner_id(host: &str) -> Vec<u8> {
    default_opaque_id("client", host)
}

pub(crate) fn default_open_owner(host: &str) -> Vec<u8> {
    default_opaque_id("open", host)
}

pub(crate) fn default_lock_owner(host: &str) -> Vec<u8> {
    default_opaque_id("lock", host)
}

fn default_opaque_id(kind: &str, host: &str) -> Vec<u8> {
    static NEXT_OWNER_ID: AtomicU64 = AtomicU64::new(1);

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!(
        "nfs-rs:{kind}:{:016x}:{}:{}:{}",
        fnv1a64(host.as_bytes()),
        std::process::id(),
        duration.as_nanos(),
        NEXT_OWNER_ID.fetch_add(1, Ordering::Relaxed)
    )
    .into_bytes()
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    bytes.iter().fold(OFFSET, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(PRIME)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_owner_id_is_unique_and_bounded() {
        let first = default_owner_id(&"host".repeat(2_000));
        let second = default_owner_id(&"host".repeat(2_000));
        let lock_owner = default_lock_owner(&"host".repeat(2_000));

        assert_ne!(first, second);
        assert!(first.len() <= NFS4_OPAQUE_LIMIT);
        assert!(second.len() <= NFS4_OPAQUE_LIMIT);
        assert!(lock_owner.len() <= NFS4_OPAQUE_LIMIT);
    }

    #[test]
    fn validate_owner_id_rejects_oversized_values() {
        let owner_id = vec![0; NFS4_OPAQUE_LIMIT + 1];
        assert!(matches!(
            validate_owner_id(&owner_id),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn validate_open_owner_rejects_oversized_values() {
        let open_owner = vec![0; NFS4_OPAQUE_LIMIT + 1];
        assert!(matches!(
            validate_open_owner(&open_owner),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn validate_lock_owner_rejects_oversized_values() {
        let lock_owner = vec![0; NFS4_OPAQUE_LIMIT + 1];
        assert!(matches!(
            validate_lock_owner(&lock_owner),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn validate_transfer_size_rejects_invalid_values() {
        assert!(matches!(
            validate_transfer_size("read_size", 0),
            Err(Error::Protocol(_))
        ));
        assert!(matches!(
            validate_transfer_size("read_size", proto::NFS4_MAX_IO as u32 + 1),
            Err(Error::Protocol(_))
        ));
        assert!(validate_transfer_size("read_size", proto::NFS4_MAX_IO as u32).is_ok());
    }

    #[test]
    fn validates_supported_session_minor_versions() {
        assert!(matches!(
            validate_minor_version("max_minor_version", 0),
            Err(Error::Protocol(_))
        ));
        assert!(validate_minor_version("max_minor_version", 1).is_ok());
        assert!(validate_minor_version("max_minor_version", 2).is_ok());
        assert!(matches!(
            validate_minor_version("max_minor_version", 3),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn validates_v4_host_before_network() {
        assert!(validate_host("127.0.0.1").is_ok());
        assert!(matches!(validate_host(""), Err(Error::InvalidTarget(_))));
        assert!(matches!(validate_host(" "), Err(Error::InvalidTarget(_))));
    }

    #[test]
    fn validates_v4_port_before_network() {
        assert!(validate_port("port", 2049).is_ok());
        assert!(matches!(validate_port("port", 0), Err(Error::Protocol(_))));
    }

    #[test]
    fn negotiates_minor_versions_from_high_to_low() {
        assert_eq!(negotiated_minor_versions(2).collect::<Vec<_>>(), vec![2, 1]);
        assert_eq!(negotiated_minor_versions(1).collect::<Vec<_>>(), vec![1]);
    }

    #[test]
    fn rejects_operations_above_negotiated_minor_version() {
        assert!(require_minor_version("SEEK", 2, 2).is_ok());
        assert!(matches!(
            require_minor_version("SEEK", 1, 2),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn clamps_io_size_to_server_advertised_limits() {
        assert_eq!(clamp_io_size(None, 128 * 1024), 128 * 1024);
        assert_eq!(clamp_io_size(Some(0), 128 * 1024), 128 * 1024);
        assert_eq!(clamp_io_size(Some(64 * 1024), 128 * 1024), 64 * 1024);
        assert_eq!(clamp_io_size(Some(1024 * 1024), 128 * 1024), 128 * 1024);
    }

    #[test]
    fn validate_max_dir_entries_rejects_zero() {
        assert!(matches!(
            validate_max_dir_entries(0),
            Err(Error::Protocol(_))
        ));
        assert!(validate_max_dir_entries(1).is_ok());
    }
}
