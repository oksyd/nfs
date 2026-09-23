//! NFSv3 client support.
//!
//! NFSv3 uses a separate MOUNT service to resolve an export such as
//! `host:/export` into a server file handle. The high-level clients hide that
//! setup and operate on paths inside the mounted export.
//!
//! Use [`blocking::Client`] with the default `blocking` feature, or
//! [`tokio::Client`] with the `tokio` feature.

#[cfg(feature = "blocking")]
pub mod blocking;
mod client;
mod mount;
mod portmap;
mod proto;

#[cfg(feature = "tokio")]
pub mod tokio;

/// Low-level NFSv3, MOUNT, and portmapper wire types.
///
/// This module is available with the `protocol` feature. It is intended for
/// protocol tests and advanced integrations. Regular applications should use
/// the high-level clients instead.
#[cfg(feature = "protocol")]
pub mod protocol {
    pub use super::mount::*;
    pub use super::portmap::*;
    pub use super::proto::*;
}

pub use client::{DirEntry, DirPage, DirPageCursor, RemoteTarget};
pub use mount::{Export, MountEntry, MountStatus};
pub use proto::{
    ACCESS3_DELETE, ACCESS3_EXECUTE, ACCESS3_EXTEND, ACCESS3_LOOKUP, ACCESS3_MODIFY, ACCESS3_READ,
    AccessResult, CommitResult, FSF3_CANSETTIME, FSF3_HOMOGENEOUS, FSF3_LINK, FSF3_SYMLINK,
    FileAttr, FileHandle, FileType, FsInfo, FsStat, NFS_PORT, NFS_PROGRAM, NFS_VERSION,
    NFS3_COOKIEVERFSIZE, NFS3_CREATEVERFSIZE, NFS3_FHSIZE, NFS3_NSECONDS_PER_SECOND,
    NFS3_WRITEVERFSIZE, NfsStatus, NfsTime, PathConf, SetAttr, SetTime, StableHow,
};
