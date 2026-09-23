use std::fmt;

/// Result type used by this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for transport, XDR, RPC, and NFS protocol failures.
///
/// The variants keep the original protocol status where possible. Convenience
/// methods such as [`Error::is_not_found`], [`Error::is_retryable`], and
/// [`Error::is_permission_denied`] are usually the best way to branch on common
/// operational conditions across NFS versions.
#[derive(Debug)]
pub enum Error {
    /// Local I/O error while connecting or reading/writing an RPC stream.
    Io(std::io::Error),
    /// XDR encoding or decoding failed.
    Xdr(crate::xdr::Error),
    /// Invalid NFS target string, such as a malformed `host:/export`.
    InvalidTarget(String),
    /// Invalid remote path.
    InvalidPath(String),
    /// A path component exceeds the protocol limit.
    NameTooLong {
        /// The offending path component.
        name: String,
        /// The maximum allowed byte length.
        max: usize,
    },
    /// A length cannot be represented safely on the wire.
    LengthOutOfRange {
        /// The offending length.
        len: usize,
    },
    /// Protocol-level invariant violation detected by the client.
    Protocol(String),
    /// Primary operation failed and a best-effort cleanup operation also failed.
    Cleanup {
        /// Cleanup step that failed.
        context: &'static str,
        /// Primary operation error.
        primary: Box<Error>,
        /// Cleanup operation error.
        cleanup: Box<Error>,
    },
    /// RPC reply XID did not match the request XID.
    RpcMismatch {
        /// Request XID.
        expected: u32,
        /// Reply XID.
        actual: u32,
    },
    /// RPC reply had an unexpected message type.
    RpcUnexpectedMessageType(u32),
    /// RPC request was denied by the server.
    RpcDenied {
        /// RPC reject status.
        reject_stat: u32,
        /// Additional reject detail.
        detail: u32,
    },
    /// RPC request was accepted but the procedure failed before NFS decoding.
    RpcAcceptedError {
        /// RPC accept status.
        accept_stat: u32,
    },
    /// RPC program version mismatch.
    RpcProgramMismatch {
        /// Lowest supported version reported by the server.
        low: u32,
        /// Highest supported version reported by the server.
        high: u32,
    },
    /// RPC record exceeded the configured maximum frame size.
    RpcRecordTooLarge {
        /// Record length.
        len: usize,
        /// Maximum configured length.
        max: usize,
    },
    /// Portmapper did not return a TCP port for the requested program.
    PortUnavailable {
        /// RPC program number.
        program: u32,
        /// RPC program version.
        version: u32,
    },
    /// NFSv3 MOUNT service returned an error status.
    Mount {
        /// MOUNT protocol status.
        status: crate::v3::MountStatus,
    },
    /// NFSv3 operation returned an error status.
    Nfs {
        /// NFSv3 procedure name.
        procedure: &'static str,
        /// NFSv3 status.
        status: crate::v3::NfsStatus,
    },
    /// NFSv4 operation returned an error status.
    NfsV4 {
        /// NFSv4 operation name.
        operation: &'static str,
        /// NFSv4 status.
        status: crate::v4::Status,
    },
}

impl Error {
    pub(crate) fn nfs(procedure: &'static str, status: crate::v3::NfsStatus) -> Self {
        Self::Nfs { procedure, status }
    }

    pub(crate) fn nfsv4(operation: &'static str, status: crate::v4::Status) -> Self {
        Self::NfsV4 { operation, status }
    }

    pub(crate) fn cleanup(context: &'static str, primary: Error, cleanup: Error) -> Self {
        Self::Cleanup {
            context,
            primary: Box::new(primary),
            cleanup: Box::new(cleanup),
        }
    }

    /// Returns true for missing paths across local I/O, NFSv3, and NFSv4.
    pub fn is_not_found(&self) -> bool {
        match self {
            Self::Cleanup { primary, .. } => primary.is_not_found(),
            Self::Io(err) => err.kind() == std::io::ErrorKind::NotFound,
            Self::Mount {
                status: crate::v3::MountStatus::NoEnt,
            }
            | Self::Nfs {
                status: crate::v3::NfsStatus::NoEnt,
                ..
            }
            | Self::NfsV4 {
                status: crate::v4::Status::NoEnt,
                ..
            } => true,
            _ => false,
        }
    }

    /// Returns true for permission errors across MOUNT, NFSv3, and NFSv4.
    pub fn is_permission_denied(&self) -> bool {
        match self {
            Self::Cleanup { primary, .. } => primary.is_permission_denied(),
            Self::Io(err) => err.kind() == std::io::ErrorKind::PermissionDenied,
            Self::Mount {
                status: crate::v3::MountStatus::Perm | crate::v3::MountStatus::Access,
            }
            | Self::Nfs {
                status: crate::v3::NfsStatus::Perm | crate::v3::NfsStatus::Access,
                ..
            }
            | Self::NfsV4 {
                status:
                    crate::v4::Status::Perm
                    | crate::v4::Status::Access
                    | crate::v4::Status::PartnerNoAuth
                    | crate::v4::Status::WrongCred
                    | crate::v4::Status::WrongSec,
                ..
            } => true,
            _ => false,
        }
    }

    /// Returns true when retrying the operation may succeed.
    ///
    /// This covers transient I/O failures, NFSv3 `Jukebox`, and NFSv4
    /// `Delay` or `Grace`. Session recovery statuses are handled internally by
    /// NFSv4 clients only when the operation is safe to replay.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Cleanup { primary, .. } => primary.is_retryable(),
            Self::Io(err) => is_retryable_io_error(err.kind()),
            Self::Nfs {
                status: crate::v3::NfsStatus::Jukebox,
                ..
            } => true,
            Self::NfsV4 { status, .. } => status.is_retryable(),
            _ => false,
        }
    }

    /// Returns true when an NFSv4 status indicates that the session is no
    /// longer usable.
    ///
    /// This is primarily useful for low-level protocol integrations. The
    /// high-level NFSv4 clients recreate sessions internally and only replay
    /// operations that are safe to send again.
    pub fn requires_session_recovery(&self) -> bool {
        match self {
            Self::Cleanup {
                primary, cleanup, ..
            } => primary.requires_session_recovery() || cleanup.requires_session_recovery(),
            Self::NfsV4 { status, .. } => status.requires_session_recovery(),
            _ => false,
        }
    }

    /// Returns true for quota or no-space conditions.
    pub fn is_no_space(&self) -> bool {
        match self {
            Self::Cleanup { primary, .. } => primary.is_no_space(),
            Self::Nfs {
                status: crate::v3::NfsStatus::NoSpc | crate::v3::NfsStatus::Dquot,
                ..
            }
            | Self::NfsV4 {
                status: crate::v4::Status::NoSpc | crate::v4::Status::Dquot,
                ..
            } => true,
            _ => false,
        }
    }

    /// Returns true when the server reported a read-only filesystem.
    pub fn is_read_only(&self) -> bool {
        match self {
            Self::Cleanup { primary, .. } => primary.is_read_only(),
            Self::Nfs {
                status: crate::v3::NfsStatus::ReadOnlyFs,
                ..
            }
            | Self::NfsV4 {
                status: crate::v4::Status::ReadOnlyFs,
                ..
            } => true,
            _ => false,
        }
    }

    /// Returns true when a server-side file handle is stale or invalid.
    pub fn is_stale_handle(&self) -> bool {
        match self {
            Self::Cleanup { primary, .. } => primary.is_stale_handle(),
            Self::Nfs {
                status: crate::v3::NfsStatus::Stale | crate::v3::NfsStatus::BadHandle,
                ..
            }
            | Self::NfsV4 {
                status:
                    crate::v4::Status::Stale
                    | crate::v4::Status::BadHandle
                    | crate::v4::Status::FhExpired,
                ..
            } => true,
            _ => false,
        }
    }

    /// Returns true for NFSv4 statuses indicating lost open or lock state.
    pub fn is_lost_state(&self) -> bool {
        match self {
            Self::Cleanup { primary, .. } => primary.is_lost_state(),
            Self::NfsV4 { status, .. } => status.indicates_lost_state(),
            _ => false,
        }
    }

    /// Returns true for NFSv4 session errors that can be recovered by reconnecting.
    pub fn is_session_recoverable(&self) -> bool {
        match self {
            Self::Cleanup {
                primary, cleanup, ..
            } => primary.is_session_recoverable() || cleanup.is_session_recoverable(),
            Self::NfsV4 { status, .. } => status.requires_session_recovery(),
            _ => false,
        }
    }

    /// Returns true when create or rename encountered an existing object.
    pub fn is_already_exists(&self) -> bool {
        match self {
            Self::Cleanup { primary, .. } => primary.is_already_exists(),
            Self::Io(err) => err.kind() == std::io::ErrorKind::AlreadyExists,
            Self::Nfs {
                status: crate::v3::NfsStatus::Exist,
                ..
            }
            | Self::NfsV4 {
                status: crate::v4::Status::Exist,
                ..
            } => true,
            _ => false,
        }
    }
}

fn is_retryable_io_error(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::NotConnected
    )
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Xdr(err) => write!(f, "XDR error: {err}"),
            Self::InvalidTarget(target) => write!(f, "invalid NFS target {target:?}"),
            Self::InvalidPath(path) => write!(f, "invalid NFS path {path:?}"),
            Self::NameTooLong { name, max } => {
                write!(f, "path component {name:?} exceeds {max} bytes")
            }
            Self::LengthOutOfRange { len } => {
                write!(f, "length {len} cannot be represented on the wire")
            }
            Self::Protocol(message) => write!(f, "protocol error: {message}"),
            Self::Cleanup {
                context,
                primary,
                cleanup,
            } => {
                write!(f, "{primary}; {context} also failed: {cleanup}")
            }
            Self::RpcMismatch { expected, actual } => {
                write!(f, "RPC xid mismatch: expected {expected}, got {actual}")
            }
            Self::RpcUnexpectedMessageType(value) => {
                write!(f, "unexpected RPC message type {value}")
            }
            Self::RpcDenied {
                reject_stat,
                detail,
            } => {
                write!(
                    f,
                    "RPC message denied: reject_stat={reject_stat}, detail={detail}"
                )
            }
            Self::RpcAcceptedError { accept_stat } => {
                write!(f, "RPC call accepted but failed: accept_stat={accept_stat}")
            }
            Self::RpcProgramMismatch { low, high } => {
                write!(
                    f,
                    "RPC program version mismatch: supported range {low}..={high}"
                )
            }
            Self::RpcRecordTooLarge { len, max } => {
                write!(f, "RPC record length {len} exceeds limit {max}")
            }
            Self::PortUnavailable { program, version } => {
                write!(
                    f,
                    "RPC program {program} version {version} is not registered for TCP"
                )
            }
            Self::Mount { status } => write!(f, "mount failed with status {status:?}"),
            Self::Nfs { procedure, status } => {
                write!(f, "NFS procedure {procedure} failed with status {status:?}")
            }
            Self::NfsV4 { operation, status } => {
                write!(
                    f,
                    "NFSv4 operation {operation} failed with status {status:?}"
                )
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Xdr(err) => Some(err),
            Self::Cleanup { primary, .. } => Some(primary),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<crate::xdr::Error> for Error {
    fn from(value: crate::xdr::Error) -> Self {
        Self::Xdr(value)
    }
}
