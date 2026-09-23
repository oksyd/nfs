#![cfg_attr(not(feature = "protocol"), allow(dead_code))]

use crate::AuthSys;
use crate::error::{Error, Result};
use crate::xdr::{Decode, Decoder, Encode, Encoder};

pub const NFS4_PROGRAM: u32 = 100003;
pub const NFS4_VERSION: u32 = 4;
pub const NFS4_PORT: u16 = 2049;
pub const NFS4_MINOR_VERSION_SESSION_MIN: u32 = 1;
pub const NFS4_MINOR_VERSION_V42: u32 = 2;
pub const NFS4_MINOR_VERSION_LATEST: u32 = 2;

pub const NFS4_FHSIZE: usize = 128;
pub const NFS4_VERIFIER_SIZE: usize = 8;
pub const NFS4_OPAQUE_LIMIT: usize = 1024;
pub const NFS4_SESSIONID_SIZE: usize = 16;
pub const NFS4_DEVICEID_SIZE: usize = 16;
pub const NFS4_MAX_OPS: usize = 128;
pub const NFS4_MAX_IO: usize = 64 * 1024 * 1024;
pub const NFS4_MAX_DIR_ENTRIES: usize = 1_000_000;
pub const NFS4_MAX_READ_PLUS_SEGMENTS: usize = 1_000_000;
pub const NFS4_MAX_SECINFO_FLAVORS: usize = 128;
pub const NFS4_MAX_NETLOCATIONS: usize = 128;
pub const NFS4_MAX_CALLBACK_SEC_PARMS: usize = 16;
pub const NFS4_MAX_DEVICEIDS: usize = 1_000_000;
pub const NFS4_MAX_LAYOUTS: usize = 1_000_000;
pub const NFS4_MAX_LAYOUT_ERRORS: usize = 1_000_000;
pub const NFS4_INT64_MAX: i64 = 0x7fff_ffff_ffff_ffff;
pub const NFS4_UINT64_MAX: u64 = 0xffff_ffff_ffff_ffff;
pub const NFS4_INT32_MAX: i32 = 0x7fff_ffff;
pub const NFS4_UINT32_MAX: u32 = 0xffff_ffff;
pub const NFS4_MAXFILELEN: u64 = 0xffff_ffff_ffff_ffff;
pub const NFS4_MAXFILEOFF: u64 = 0xffff_ffff_ffff_fffe;
pub const NFS4_NSECONDS_PER_SECOND: u32 = 1_000_000_000;

const DEFAULT_SESSION_CHANNEL_SIZE: u32 = 1024 * 1024;
const NFS4_MAX_BITMAP_WORDS: usize = 128;
const NFS4_MAX_STATE_PROTECT_HANDLES: usize = 1024;

pub const FATTR4_SUPPORTED_ATTRS: u32 = 0;
pub const FATTR4_TYPE: u32 = 1;
pub const FATTR4_FH_EXPIRE_TYPE: u32 = 2;
pub const FATTR4_CHANGE: u32 = 3;
pub const FATTR4_SIZE: u32 = 4;
pub const FATTR4_LINK_SUPPORT: u32 = 5;
pub const FATTR4_SYMLINK_SUPPORT: u32 = 6;
pub const FATTR4_NAMED_ATTR: u32 = 7;
pub const FATTR4_FSID: u32 = 8;
pub const FATTR4_UNIQUE_HANDLES: u32 = 9;
pub const FATTR4_LEASE_TIME: u32 = 10;
pub const FATTR4_RDATTR_ERROR: u32 = 11;
pub const FATTR4_ACL: u32 = 12;
pub const FATTR4_ACLSUPPORT: u32 = 13;
pub const FATTR4_ARCHIVE: u32 = 14;
pub const FATTR4_CANSETTIME: u32 = 15;
pub const FATTR4_CASE_INSENSITIVE: u32 = 16;
pub const FATTR4_CASE_PRESERVING: u32 = 17;
pub const FATTR4_CHOWN_RESTRICTED: u32 = 18;
pub const FATTR4_FILEHANDLE: u32 = 19;
pub const FATTR4_FILEID: u32 = 20;
pub const FATTR4_FILES_AVAIL: u32 = 21;
pub const FATTR4_FILES_FREE: u32 = 22;
pub const FATTR4_FILES_TOTAL: u32 = 23;
pub const FATTR4_FS_LOCATIONS: u32 = 24;
pub const FATTR4_HIDDEN: u32 = 25;
pub const FATTR4_HOMOGENEOUS: u32 = 26;
pub const FATTR4_MAXFILESIZE: u32 = 27;
pub const FATTR4_MAXLINK: u32 = 28;
pub const FATTR4_MAXNAME: u32 = 29;
pub const FATTR4_MAXREAD: u32 = 30;
pub const FATTR4_MAXWRITE: u32 = 31;
pub const FATTR4_MIMETYPE: u32 = 32;
pub const FATTR4_MODE: u32 = 33;
pub const FATTR4_NO_TRUNC: u32 = 34;
pub const FATTR4_NUMLINKS: u32 = 35;
pub const FATTR4_OWNER: u32 = 36;
pub const FATTR4_OWNER_GROUP: u32 = 37;
pub const FATTR4_QUOTA_AVAIL_HARD: u32 = 38;
pub const FATTR4_QUOTA_AVAIL_SOFT: u32 = 39;
pub const FATTR4_QUOTA_USED: u32 = 40;
pub const FATTR4_RAWDEV: u32 = 41;
pub const FATTR4_SPACE_AVAIL: u32 = 42;
pub const FATTR4_SPACE_FREE: u32 = 43;
pub const FATTR4_SPACE_TOTAL: u32 = 44;
pub const FATTR4_SPACE_USED: u32 = 45;
pub const FATTR4_SYSTEM: u32 = 46;
pub const FATTR4_TIME_ACCESS: u32 = 47;
pub const FATTR4_TIME_ACCESS_SET: u32 = 48;
pub const FATTR4_TIME_BACKUP: u32 = 49;
pub const FATTR4_TIME_CREATE: u32 = 50;
pub const FATTR4_TIME_DELTA: u32 = 51;
pub const FATTR4_TIME_METADATA: u32 = 52;
pub const FATTR4_TIME_MODIFY: u32 = 53;
pub const FATTR4_TIME_MODIFY_SET: u32 = 54;
pub const FATTR4_MOUNTED_ON_FILEID: u32 = 55;
pub const FATTR4_DIR_NOTIF_DELAY: u32 = 56;
pub const FATTR4_DIRENT_NOTIF_DELAY: u32 = 57;
pub const FATTR4_DACL: u32 = 58;
pub const FATTR4_SACL: u32 = 59;
pub const FATTR4_CHANGE_POLICY: u32 = 60;
pub const FATTR4_FS_STATUS: u32 = 61;
pub const FATTR4_FS_LAYOUT_TYPE: u32 = 62;
pub const FATTR4_LAYOUT_HINT: u32 = 63;
pub const FATTR4_LAYOUT_TYPE: u32 = 64;
pub const FATTR4_LAYOUT_BLKSIZE: u32 = 65;
pub const FATTR4_LAYOUT_ALIGNMENT: u32 = 66;
pub const FATTR4_FS_LOCATIONS_INFO: u32 = 67;
pub const FATTR4_MDSTHRESHOLD: u32 = 68;
pub const FATTR4_RETENTION_GET: u32 = 69;
pub const FATTR4_RETENTION_SET: u32 = 70;
pub const FATTR4_RETENTEVT_GET: u32 = 71;
pub const FATTR4_RETENTEVT_SET: u32 = 72;
pub const FATTR4_RETENTION_HOLD: u32 = 73;
pub const FATTR4_MODE_SET_MASKED: u32 = 74;
pub const FATTR4_SUPPATTR_EXCLCREAT: u32 = 75;
pub const FATTR4_FS_CHARSET_CAP: u32 = 76;
pub const FATTR4_CLONE_BLKSIZE: u32 = 77;
pub const FATTR4_SPACE_FREED: u32 = 78;
pub const FATTR4_CHANGE_ATTR_TYPE: u32 = 79;
pub const FATTR4_SEC_LABEL: u32 = 80;
pub const FATTR4_BASIC_ATTRS: &[u32] = &[
    FATTR4_TYPE,
    FATTR4_CHANGE,
    FATTR4_SIZE,
    FATTR4_FILEID,
    FATTR4_MODE,
    FATTR4_NUMLINKS,
    FATTR4_OWNER,
    FATTR4_OWNER_GROUP,
    FATTR4_SPACE_USED,
    FATTR4_TIME_ACCESS,
    FATTR4_TIME_METADATA,
    FATTR4_TIME_MODIFY,
];
pub const FATTR4_FSSTAT_ATTRS: &[u32] = &[
    FATTR4_FILES_AVAIL,
    FATTR4_FILES_FREE,
    FATTR4_FILES_TOTAL,
    FATTR4_SPACE_AVAIL,
    FATTR4_SPACE_FREE,
    FATTR4_SPACE_TOTAL,
];
pub const FATTR4_FSINFO_ATTRS: &[u32] = &[
    FATTR4_FH_EXPIRE_TYPE,
    FATTR4_LINK_SUPPORT,
    FATTR4_SYMLINK_SUPPORT,
    FATTR4_UNIQUE_HANDLES,
    FATTR4_LEASE_TIME,
    FATTR4_CANSETTIME,
    FATTR4_HOMOGENEOUS,
    FATTR4_MAXFILESIZE,
    FATTR4_MAXREAD,
    FATTR4_MAXWRITE,
    FATTR4_TIME_DELTA,
];
pub const FATTR4_PATHCONF_ATTRS: &[u32] = &[
    FATTR4_CASE_INSENSITIVE,
    FATTR4_CASE_PRESERVING,
    FATTR4_CHOWN_RESTRICTED,
    FATTR4_MAXLINK,
    FATTR4_MAXNAME,
    FATTR4_NO_TRUNC,
];
pub const NF4REG: u32 = 1;
pub const NF4DIR: u32 = 2;
pub const NF4BLK: u32 = 3;
pub const NF4CHR: u32 = 4;
pub const NF4LNK: u32 = 5;
pub const NF4SOCK: u32 = 6;
pub const NF4FIFO: u32 = 7;
pub const EXCHGID4_FLAG_SUPP_MOVED_REFER: u32 = 0x0000_0001;
pub const EXCHGID4_FLAG_SUPP_MOVED_MIGR: u32 = 0x0000_0002;
pub const EXCHGID4_FLAG_BIND_PRINC_STATEID: u32 = 0x0000_0100;
pub const EXCHGID4_FLAG_USE_NON_PNFS: u32 = 0x0001_0000;
pub const EXCHGID4_FLAG_USE_PNFS_MDS: u32 = 0x0002_0000;
pub const EXCHGID4_FLAG_USE_PNFS_DS: u32 = 0x0004_0000;
pub const EXCHGID4_FLAG_MASK_PNFS: u32 = 0x0007_0000;
pub const EXCHGID4_FLAG_UPD_CONFIRMED_REC_A: u32 = 0x4000_0000;
pub const EXCHGID4_FLAG_CONFIRMED_R: u32 = 0x8000_0000;
pub const CREATE_SESSION4_FLAG_PERSIST: u32 = 0x0000_0001;
pub const CREATE_SESSION4_FLAG_CONN_BACK_CHAN: u32 = 0x0000_0002;
pub const CREATE_SESSION4_FLAG_CONN_RDMA: u32 = 0x0000_0004;
pub const SEQ4_STATUS_CB_PATH_DOWN: u32 = 0x0000_0001;
pub const SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRING: u32 = 0x0000_0002;
pub const SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRED: u32 = 0x0000_0004;
pub const SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED: u32 = 0x0000_0008;
pub const SEQ4_STATUS_EXPIRED_SOME_STATE_REVOKED: u32 = 0x0000_0010;
pub const SEQ4_STATUS_ADMIN_STATE_REVOKED: u32 = 0x0000_0020;
pub const SEQ4_STATUS_RECALLABLE_STATE_REVOKED: u32 = 0x0000_0040;
pub const SEQ4_STATUS_LEASE_MOVED: u32 = 0x0000_0080;
pub const SEQ4_STATUS_RESTART_RECLAIM_NEEDED: u32 = 0x0000_0100;
pub const SEQ4_STATUS_CB_PATH_DOWN_SESSION: u32 = 0x0000_0200;
pub const SEQ4_STATUS_BACKCHANNEL_FAULT: u32 = 0x0000_0400;
pub const SEQ4_STATUS_DEVID_CHANGED: u32 = 0x0000_0800;
pub const SEQ4_STATUS_DEVID_DELETED: u32 = 0x0000_1000;
pub const OPEN4_SHARE_ACCESS_READ: u32 = 0x0000_0001;
pub const OPEN4_SHARE_ACCESS_WRITE: u32 = 0x0000_0002;
pub const OPEN4_SHARE_ACCESS_BOTH: u32 = 0x0000_0003;
pub const OPEN4_SHARE_ACCESS_WANT_DELEG_MASK: u32 = 0x0000_ff00;
pub const OPEN4_SHARE_ACCESS_WANT_NO_PREFERENCE: u32 = 0x0000_0000;
pub const OPEN4_SHARE_ACCESS_WANT_READ_DELEG: u32 = 0x0000_0100;
pub const OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG: u32 = 0x0000_0200;
pub const OPEN4_SHARE_ACCESS_WANT_ANY_DELEG: u32 = 0x0000_0300;
pub const OPEN4_SHARE_ACCESS_WANT_NO_DELEG: u32 = 0x0000_0400;
pub const OPEN4_SHARE_ACCESS_WANT_CANCEL: u32 = 0x0000_0500;
pub const OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL: u32 = 0x0001_0000;
pub const OPEN4_SHARE_ACCESS_WANT_PUSH_DELEG_WHEN_UNCONTENDED: u32 = 0x0002_0000;
pub const OPEN4_SHARE_DENY_NONE: u32 = 0x0000_0000;
pub const OPEN4_SHARE_DENY_READ: u32 = 0x0000_0001;
pub const OPEN4_SHARE_DENY_WRITE: u32 = 0x0000_0002;
pub const OPEN4_SHARE_DENY_BOTH: u32 = 0x0000_0003;
pub const OPEN4_RESULT_CONFIRM: u32 = 0x0000_0002;
pub const OPEN4_RESULT_LOCKTYPE_POSIX: u32 = 0x0000_0004;
pub const OPEN4_RESULT_PRESERVE_UNLINKED: u32 = 0x0000_0008;
pub const OPEN4_RESULT_MAY_NOTIFY_LOCK: u32 = 0x0000_0020;
pub const ACCESS4_READ: u32 = 0x0001;
pub const ACCESS4_LOOKUP: u32 = 0x0002;
pub const ACCESS4_MODIFY: u32 = 0x0004;
pub const ACCESS4_EXTEND: u32 = 0x0008;
pub const ACCESS4_DELETE: u32 = 0x0010;
pub const ACCESS4_EXECUTE: u32 = 0x0020;
pub const NFS4_CONTENT_DATA: u32 = 0;
pub const NFS4_CONTENT_HOLE: u32 = 1;
pub const AUTH_NONE: u32 = 0;
pub const AUTH_SYS: u32 = 1;
pub const RPCSEC_GSS: u32 = 6;
pub const RPC_GSS_SVC_NONE: u32 = 1;
pub const RPC_GSS_SVC_INTEGRITY: u32 = 2;
pub const RPC_GSS_SVC_PRIVACY: u32 = 3;
pub const LAYOUT4_NFSV4_1_FILES: u32 = 1;
pub const LAYOUT4_OSD2_OBJECTS: u32 = 2;
pub const LAYOUT4_BLOCK_VOLUME: u32 = 3;
pub const LAYOUTIOMODE4_READ: u32 = 1;
pub const LAYOUTIOMODE4_RW: u32 = 2;
pub const LAYOUTIOMODE4_ANY: u32 = 3;
pub const LAYOUTRETURN4_FILE: u32 = 1;
pub const LAYOUTRETURN4_FSID: u32 = 2;
pub const LAYOUTRETURN4_ALL: u32 = 3;
pub const GDD4_OK: u32 = 0;
pub const GDD4_UNAVAIL: u32 = 1;

/// NFSv4 verifier value.
pub type Verifier = [u8; NFS4_VERIFIER_SIZE];
/// NFSv4 session id.
pub type SessionId = [u8; NFS4_SESSIONID_SIZE];
/// NFSv4 pNFS device id.
pub type DeviceId = [u8; NFS4_DEVICEID_SIZE];

/// NFSv4 status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Perm,
    NoEnt,
    Io,
    Nxio,
    Access,
    Exist,
    Xdev,
    NotDir,
    IsDir,
    Inval,
    Fbig,
    NoSpc,
    ReadOnlyFs,
    Mlink,
    NameTooLong,
    NotEmpty,
    Dquot,
    Stale,
    Same,
    Denied,
    Expired,
    Locked,
    Grace,
    FhExpired,
    ShareDenied,
    BadHandle,
    BadCookie,
    NotSupported,
    TooSmall,
    ServerFault,
    BadType,
    Delay,
    ClidInUse,
    Resource,
    Moved,
    StaleClientId,
    StaleStateId,
    OldStateId,
    BadStateId,
    BadSeqId,
    NotSame,
    LockRange,
    Symlink,
    RestoreFh,
    LeaseMoved,
    AttrNotSupp,
    NoGrace,
    ReclaimBad,
    ReclaimConflict,
    BadXdr,
    LocksHeld,
    OpenMode,
    BadOwner,
    BadChar,
    BadName,
    BadRange,
    LockNotSupp,
    OpIllegal,
    Deadlock,
    FileOpen,
    WrongSec,
    NoFileHandle,
    MinorVersionMismatch,
    AdminRevoked,
    CbPathDown,
    BadIoMode,
    BadLayout,
    BadSessionDigest,
    BadSession,
    BadSlot,
    CompleteAlready,
    ConnNotBoundToSession,
    DelegAlreadyWanted,
    BackChanBusy,
    LayoutTryLater,
    LayoutUnavailable,
    NoMatchingLayout,
    RecallConflict,
    UnknownLayoutType,
    SeqMisordered,
    SequencePos,
    ReqTooBig,
    RepTooBig,
    RepTooBigToCache,
    RetryUncachedRep,
    UnsafeCompound,
    TooManyOps,
    SeqFalseRetry,
    OpNotInSession,
    HashAlgUnsupported,
    ClientIdBusy,
    BadHighSlot,
    DeadSession,
    EncrAlgUnsupported,
    PnfsIoHole,
    PnfsNoLayout,
    NotOnlyOp,
    WrongCred,
    WrongType,
    DirDelegUnavailable,
    RejectDeleg,
    ReturnConflict,
    DelegRevoked,
    PartnerNotSupp,
    PartnerNoAuth,
    UnionNotSupported,
    OffloadDenied,
    WrongLfs,
    BadLabel,
    OffloadNoReqs,
    Unknown(u32),
}

impl Status {
    /// Converts a raw NFSv4 status code into [`Status`].
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::Ok,
            1 => Self::Perm,
            2 => Self::NoEnt,
            5 => Self::Io,
            6 => Self::Nxio,
            13 => Self::Access,
            17 => Self::Exist,
            18 => Self::Xdev,
            20 => Self::NotDir,
            21 => Self::IsDir,
            22 => Self::Inval,
            27 => Self::Fbig,
            28 => Self::NoSpc,
            30 => Self::ReadOnlyFs,
            31 => Self::Mlink,
            63 => Self::NameTooLong,
            66 => Self::NotEmpty,
            69 => Self::Dquot,
            70 => Self::Stale,
            10009 => Self::Same,
            10010 => Self::Denied,
            10011 => Self::Expired,
            10012 => Self::Locked,
            10013 => Self::Grace,
            10014 => Self::FhExpired,
            10015 => Self::ShareDenied,
            10001 => Self::BadHandle,
            10003 => Self::BadCookie,
            10004 => Self::NotSupported,
            10005 => Self::TooSmall,
            10006 => Self::ServerFault,
            10007 => Self::BadType,
            10008 => Self::Delay,
            10017 => Self::ClidInUse,
            10018 => Self::Resource,
            10019 => Self::Moved,
            10022 => Self::StaleClientId,
            10023 => Self::StaleStateId,
            10024 => Self::OldStateId,
            10025 => Self::BadStateId,
            10026 => Self::BadSeqId,
            10027 => Self::NotSame,
            10028 => Self::LockRange,
            10029 => Self::Symlink,
            10030 => Self::RestoreFh,
            10031 => Self::LeaseMoved,
            10032 => Self::AttrNotSupp,
            10033 => Self::NoGrace,
            10034 => Self::ReclaimBad,
            10035 => Self::ReclaimConflict,
            10036 => Self::BadXdr,
            10037 => Self::LocksHeld,
            10038 => Self::OpenMode,
            10039 => Self::BadOwner,
            10040 => Self::BadChar,
            10041 => Self::BadName,
            10042 => Self::BadRange,
            10043 => Self::LockNotSupp,
            10044 => Self::OpIllegal,
            10045 => Self::Deadlock,
            10046 => Self::FileOpen,
            10016 => Self::WrongSec,
            10020 => Self::NoFileHandle,
            10021 => Self::MinorVersionMismatch,
            10047 => Self::AdminRevoked,
            10048 => Self::CbPathDown,
            10049 => Self::BadIoMode,
            10050 => Self::BadLayout,
            10051 => Self::BadSessionDigest,
            10052 => Self::BadSession,
            10053 => Self::BadSlot,
            10054 => Self::CompleteAlready,
            10055 => Self::ConnNotBoundToSession,
            10056 => Self::DelegAlreadyWanted,
            10057 => Self::BackChanBusy,
            10058 => Self::LayoutTryLater,
            10059 => Self::LayoutUnavailable,
            10060 => Self::NoMatchingLayout,
            10061 => Self::RecallConflict,
            10062 => Self::UnknownLayoutType,
            10063 => Self::SeqMisordered,
            10064 => Self::SequencePos,
            10065 => Self::ReqTooBig,
            10066 => Self::RepTooBig,
            10067 => Self::RepTooBigToCache,
            10068 => Self::RetryUncachedRep,
            10069 => Self::UnsafeCompound,
            10070 => Self::TooManyOps,
            10076 => Self::SeqFalseRetry,
            10071 => Self::OpNotInSession,
            10072 => Self::HashAlgUnsupported,
            10074 => Self::ClientIdBusy,
            10077 => Self::BadHighSlot,
            10078 => Self::DeadSession,
            10079 => Self::EncrAlgUnsupported,
            10075 => Self::PnfsIoHole,
            10080 => Self::PnfsNoLayout,
            10081 => Self::NotOnlyOp,
            10082 => Self::WrongCred,
            10083 => Self::WrongType,
            10084 => Self::DirDelegUnavailable,
            10085 => Self::RejectDeleg,
            10086 => Self::ReturnConflict,
            10087 => Self::DelegRevoked,
            10088 => Self::PartnerNotSupp,
            10089 => Self::PartnerNoAuth,
            10090 => Self::UnionNotSupported,
            10091 => Self::OffloadDenied,
            10092 => Self::WrongLfs,
            10093 => Self::BadLabel,
            10094 => Self::OffloadNoReqs,
            value => Self::Unknown(value),
        }
    }

    /// Returns the raw NFSv4 status code.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Ok => 0,
            Self::Perm => 1,
            Self::NoEnt => 2,
            Self::Io => 5,
            Self::Nxio => 6,
            Self::Access => 13,
            Self::Exist => 17,
            Self::Xdev => 18,
            Self::NotDir => 20,
            Self::IsDir => 21,
            Self::Inval => 22,
            Self::Fbig => 27,
            Self::NoSpc => 28,
            Self::ReadOnlyFs => 30,
            Self::Mlink => 31,
            Self::NameTooLong => 63,
            Self::NotEmpty => 66,
            Self::Dquot => 69,
            Self::Stale => 70,
            Self::Same => 10009,
            Self::Denied => 10010,
            Self::Expired => 10011,
            Self::Locked => 10012,
            Self::Grace => 10013,
            Self::FhExpired => 10014,
            Self::ShareDenied => 10015,
            Self::BadHandle => 10001,
            Self::BadCookie => 10003,
            Self::NotSupported => 10004,
            Self::TooSmall => 10005,
            Self::ServerFault => 10006,
            Self::BadType => 10007,
            Self::Delay => 10008,
            Self::ClidInUse => 10017,
            Self::Resource => 10018,
            Self::Moved => 10019,
            Self::StaleClientId => 10022,
            Self::StaleStateId => 10023,
            Self::OldStateId => 10024,
            Self::BadStateId => 10025,
            Self::BadSeqId => 10026,
            Self::NotSame => 10027,
            Self::LockRange => 10028,
            Self::Symlink => 10029,
            Self::RestoreFh => 10030,
            Self::LeaseMoved => 10031,
            Self::AttrNotSupp => 10032,
            Self::NoGrace => 10033,
            Self::ReclaimBad => 10034,
            Self::ReclaimConflict => 10035,
            Self::BadXdr => 10036,
            Self::LocksHeld => 10037,
            Self::OpenMode => 10038,
            Self::BadOwner => 10039,
            Self::BadChar => 10040,
            Self::BadName => 10041,
            Self::BadRange => 10042,
            Self::LockNotSupp => 10043,
            Self::OpIllegal => 10044,
            Self::Deadlock => 10045,
            Self::FileOpen => 10046,
            Self::WrongSec => 10016,
            Self::NoFileHandle => 10020,
            Self::MinorVersionMismatch => 10021,
            Self::AdminRevoked => 10047,
            Self::CbPathDown => 10048,
            Self::BadIoMode => 10049,
            Self::BadLayout => 10050,
            Self::BadSessionDigest => 10051,
            Self::BadSession => 10052,
            Self::BadSlot => 10053,
            Self::CompleteAlready => 10054,
            Self::ConnNotBoundToSession => 10055,
            Self::DelegAlreadyWanted => 10056,
            Self::BackChanBusy => 10057,
            Self::LayoutTryLater => 10058,
            Self::LayoutUnavailable => 10059,
            Self::NoMatchingLayout => 10060,
            Self::RecallConflict => 10061,
            Self::UnknownLayoutType => 10062,
            Self::SeqMisordered => 10063,
            Self::SequencePos => 10064,
            Self::ReqTooBig => 10065,
            Self::RepTooBig => 10066,
            Self::RepTooBigToCache => 10067,
            Self::RetryUncachedRep => 10068,
            Self::UnsafeCompound => 10069,
            Self::TooManyOps => 10070,
            Self::SeqFalseRetry => 10076,
            Self::OpNotInSession => 10071,
            Self::HashAlgUnsupported => 10072,
            Self::ClientIdBusy => 10074,
            Self::BadHighSlot => 10077,
            Self::DeadSession => 10078,
            Self::EncrAlgUnsupported => 10079,
            Self::PnfsIoHole => 10075,
            Self::PnfsNoLayout => 10080,
            Self::NotOnlyOp => 10081,
            Self::WrongCred => 10082,
            Self::WrongType => 10083,
            Self::DirDelegUnavailable => 10084,
            Self::RejectDeleg => 10085,
            Self::ReturnConflict => 10086,
            Self::DelegRevoked => 10087,
            Self::PartnerNotSupp => 10088,
            Self::PartnerNoAuth => 10089,
            Self::UnionNotSupported => 10090,
            Self::OffloadDenied => 10091,
            Self::WrongLfs => 10092,
            Self::BadLabel => 10093,
            Self::OffloadNoReqs => 10094,
            Self::Unknown(value) => value,
        }
    }

    /// Returns true for `NFS4_OK`.
    pub fn is_ok(self) -> bool {
        self == Self::Ok
    }

    /// Returns true when the same operation can be retried after a delay.
    ///
    /// Session recovery statuses are intentionally excluded here because safe
    /// replay depends on the operation and client state. Use
    /// [`Status::requires_session_recovery`] for those statuses.
    pub fn is_retryable(self) -> bool {
        matches!(self, Self::Delay | Self::Grace)
    }

    /// Returns true when the client should create a new session and retry.
    pub fn requires_session_recovery(self) -> bool {
        matches!(
            self,
            Self::BadSession
                | Self::ConnNotBoundToSession
                | Self::DeadSession
                | Self::StaleClientId
        )
    }

    /// Returns true when the status indicates lost NFSv4 state.
    pub fn indicates_lost_state(self) -> bool {
        matches!(
            self,
            Self::AdminRevoked
                | Self::BadStateId
                | Self::DelegRevoked
                | Self::Expired
                | Self::LeaseMoved
                | Self::NoGrace
                | Self::OldStateId
                | Self::ReclaimBad
                | Self::ReclaimConflict
                | Self::StaleClientId
                | Self::StaleStateId
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum OpCode {
    Access = 3,
    Close = 4,
    Commit = 5,
    Create = 6,
    DelegPurge = 7,
    DelegReturn = 8,
    GetAttr = 9,
    GetFh = 10,
    Link = 11,
    Lock = 12,
    Lockt = 13,
    Locku = 14,
    Lookup = 15,
    Lookupp = 16,
    NVerify = 17,
    Open = 18,
    OpenAttr = 19,
    OpenConfirm = 20,
    OpenDowngrade = 21,
    PutFh = 22,
    PutPubFh = 23,
    PutRootFh = 24,
    Read = 25,
    ReadDir = 26,
    ReadLink = 27,
    Remove = 28,
    Rename = 29,
    Renew = 30,
    RestoreFh = 31,
    SaveFh = 32,
    SecInfo = 33,
    SetAttr = 34,
    SetClientId = 35,
    SetClientIdConfirm = 36,
    Verify = 37,
    Write = 38,
    ReleaseLockOwner = 39,
    BackchannelCtl = 40,
    BindConnToSession = 41,
    ExchangeId = 42,
    CreateSession = 43,
    DestroySession = 44,
    FreeStateId = 45,
    GetDirDelegation = 46,
    GetDeviceInfo = 47,
    GetDeviceList = 48,
    LayoutCommit = 49,
    LayoutGet = 50,
    LayoutReturn = 51,
    SecInfoNoName = 52,
    Sequence = 53,
    SetSsv = 54,
    TestStateId = 55,
    WantDelegation = 56,
    DestroyClientId = 57,
    ReclaimComplete = 58,
    Allocate = 59,
    Copy = 60,
    CopyNotify = 61,
    Deallocate = 62,
    IoAdvise = 63,
    LayoutError = 64,
    LayoutStats = 65,
    OffloadCancel = 66,
    OffloadStatus = 67,
    ReadPlus = 68,
    Seek = 69,
    WriteSame = 70,
    Clone = 71,
    Illegal = 10044,
}

impl OpCode {
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            3 => Self::Access,
            4 => Self::Close,
            5 => Self::Commit,
            6 => Self::Create,
            7 => Self::DelegPurge,
            8 => Self::DelegReturn,
            9 => Self::GetAttr,
            10 => Self::GetFh,
            11 => Self::Link,
            12 => Self::Lock,
            13 => Self::Lockt,
            14 => Self::Locku,
            15 => Self::Lookup,
            16 => Self::Lookupp,
            17 => Self::NVerify,
            18 => Self::Open,
            19 => Self::OpenAttr,
            20 => Self::OpenConfirm,
            21 => Self::OpenDowngrade,
            22 => Self::PutFh,
            23 => Self::PutPubFh,
            24 => Self::PutRootFh,
            25 => Self::Read,
            26 => Self::ReadDir,
            27 => Self::ReadLink,
            28 => Self::Remove,
            29 => Self::Rename,
            30 => Self::Renew,
            31 => Self::RestoreFh,
            32 => Self::SaveFh,
            33 => Self::SecInfo,
            34 => Self::SetAttr,
            35 => Self::SetClientId,
            36 => Self::SetClientIdConfirm,
            37 => Self::Verify,
            38 => Self::Write,
            39 => Self::ReleaseLockOwner,
            40 => Self::BackchannelCtl,
            41 => Self::BindConnToSession,
            42 => Self::ExchangeId,
            43 => Self::CreateSession,
            44 => Self::DestroySession,
            45 => Self::FreeStateId,
            46 => Self::GetDirDelegation,
            47 => Self::GetDeviceInfo,
            48 => Self::GetDeviceList,
            49 => Self::LayoutCommit,
            50 => Self::LayoutGet,
            51 => Self::LayoutReturn,
            52 => Self::SecInfoNoName,
            53 => Self::Sequence,
            54 => Self::SetSsv,
            55 => Self::TestStateId,
            56 => Self::WantDelegation,
            57 => Self::DestroyClientId,
            58 => Self::ReclaimComplete,
            59 => Self::Allocate,
            60 => Self::Copy,
            61 => Self::CopyNotify,
            62 => Self::Deallocate,
            63 => Self::IoAdvise,
            64 => Self::LayoutError,
            65 => Self::LayoutStats,
            66 => Self::OffloadCancel,
            67 => Self::OffloadStatus,
            68 => Self::ReadPlus,
            69 => Self::Seek,
            70 => Self::WriteSame,
            71 => Self::Clone,
            10044 => Self::Illegal,
            _ => return None,
        })
    }

    pub fn as_u32(self) -> u32 {
        self as u32
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Access => "ACCESS",
            Self::Close => "CLOSE",
            Self::Commit => "COMMIT",
            Self::Create => "CREATE",
            Self::DelegPurge => "DELEGPURGE",
            Self::DelegReturn => "DELEGRETURN",
            Self::GetAttr => "GETATTR",
            Self::GetFh => "GETFH",
            Self::Link => "LINK",
            Self::Lock => "LOCK",
            Self::Lockt => "LOCKT",
            Self::Locku => "LOCKU",
            Self::Lookup => "LOOKUP",
            Self::Lookupp => "LOOKUPP",
            Self::NVerify => "NVERIFY",
            Self::Open => "OPEN",
            Self::OpenAttr => "OPENATTR",
            Self::OpenConfirm => "OPEN_CONFIRM",
            Self::OpenDowngrade => "OPEN_DOWNGRADE",
            Self::PutFh => "PUTFH",
            Self::PutPubFh => "PUTPUBFH",
            Self::PutRootFh => "PUTROOTFH",
            Self::Read => "READ",
            Self::ReadDir => "READDIR",
            Self::ReadLink => "READLINK",
            Self::Remove => "REMOVE",
            Self::Rename => "RENAME",
            Self::Renew => "RENEW",
            Self::RestoreFh => "RESTOREFH",
            Self::SaveFh => "SAVEFH",
            Self::SecInfo => "SECINFO",
            Self::SetAttr => "SETATTR",
            Self::SetClientId => "SETCLIENTID",
            Self::SetClientIdConfirm => "SETCLIENTID_CONFIRM",
            Self::Verify => "VERIFY",
            Self::Write => "WRITE",
            Self::ReleaseLockOwner => "RELEASE_LOCKOWNER",
            Self::BackchannelCtl => "BACKCHANNEL_CTL",
            Self::BindConnToSession => "BIND_CONN_TO_SESSION",
            Self::ExchangeId => "EXCHANGE_ID",
            Self::CreateSession => "CREATE_SESSION",
            Self::DestroySession => "DESTROY_SESSION",
            Self::FreeStateId => "FREE_STATEID",
            Self::GetDirDelegation => "GET_DIR_DELEGATION",
            Self::GetDeviceInfo => "GETDEVICEINFO",
            Self::GetDeviceList => "GETDEVICELIST",
            Self::LayoutCommit => "LAYOUTCOMMIT",
            Self::LayoutGet => "LAYOUTGET",
            Self::LayoutReturn => "LAYOUTRETURN",
            Self::SecInfoNoName => "SECINFO_NO_NAME",
            Self::Sequence => "SEQUENCE",
            Self::SetSsv => "SET_SSV",
            Self::TestStateId => "TEST_STATEID",
            Self::WantDelegation => "WANT_DELEGATION",
            Self::DestroyClientId => "DESTROY_CLIENTID",
            Self::ReclaimComplete => "RECLAIM_COMPLETE",
            Self::Allocate => "ALLOCATE",
            Self::Copy => "COPY",
            Self::CopyNotify => "COPY_NOTIFY",
            Self::Deallocate => "DEALLOCATE",
            Self::IoAdvise => "IO_ADVISE",
            Self::LayoutError => "LAYOUTERROR",
            Self::LayoutStats => "LAYOUTSTATS",
            Self::OffloadCancel => "OFFLOAD_CANCEL",
            Self::OffloadStatus => "OFFLOAD_STATUS",
            Self::ReadPlus => "READ_PLUS",
            Self::Seek => "SEEK",
            Self::WriteSame => "WRITE_SAME",
            Self::Clone => "CLONE",
            Self::Illegal => "ILLEGAL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileHandle {
    data: Vec<u8>,
}

impl FileHandle {
    pub fn new(data: Vec<u8>) -> Result<Self> {
        if data.len() > NFS4_FHSIZE {
            return Err(Error::Protocol(format!(
                "NFSv4 file handle is {} bytes, maximum is {NFS4_FHSIZE}",
                data.len()
            )));
        }
        Ok(Self { data })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl Encode for FileHandle {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_opaque(&self.data, NFS4_FHSIZE)
    }
}

impl Decode for FileHandle {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            data: decoder.read_opaque_vec(NFS4_FHSIZE)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateId {
    pub seqid: u32,
    pub other: [u8; 12],
}

impl StateId {
    pub fn anonymous() -> Self {
        Self {
            seqid: 0,
            other: [0; 12],
        }
    }

    pub fn is_anonymous(self) -> bool {
        self == Self::anonymous()
    }
}

impl Encode for StateId {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u32(self.seqid);
        encoder.write_fixed_opaque(&self.other);
        Ok(())
    }
}

impl Decode for StateId {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        let seqid = decoder.read_u32()?;
        let bytes = decoder.read_fixed_opaque(12)?;
        let other: [u8; 12] = bytes
            .try_into()
            .map_err(|_| crate::xdr::Error::UnexpectedEof {
                needed: 12,
                remaining: bytes.len(),
            })?;
        Ok(Self { seqid, other })
    }
}

impl Encode for DeviceId {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_fixed_opaque(self);
        Ok(())
    }
}

impl Decode for DeviceId {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        let bytes = decoder.read_fixed_opaque(NFS4_DEVICEID_SIZE)?;
        let device_id: DeviceId =
            bytes
                .try_into()
                .map_err(|_| crate::xdr::Error::UnexpectedEof {
                    needed: NFS4_DEVICEID_SIZE,
                    remaining: bytes.len(),
                })?;
        Ok(device_id)
    }
}

/// NFSv4 file type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    BlockDevice,
    CharacterDevice,
    Symlink,
    Socket,
    Fifo,
    AttrDir,
    NamedAttr,
    Unknown(u32),
}

impl FileType {
    /// Returns true for regular files.
    pub fn is_file(self) -> bool {
        self == Self::Regular
    }

    /// Returns true for directories.
    pub fn is_dir(self) -> bool {
        self == Self::Directory
    }

    /// Returns true for symbolic links.
    pub fn is_symlink(self) -> bool {
        self == Self::Symlink
    }

    /// Converts a raw `type` attribute value into [`FileType`].
    pub fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::Regular,
            2 => Self::Directory,
            3 => Self::BlockDevice,
            4 => Self::CharacterDevice,
            5 => Self::Symlink,
            6 => Self::Socket,
            7 => Self::Fifo,
            8 => Self::AttrDir,
            9 => Self::NamedAttr,
            value => Self::Unknown(value),
        }
    }
}

/// NFSv4 attribute bitmap.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Bitmap {
    words: Vec<u32>,
}

impl Bitmap {
    /// Creates an empty bitmap.
    pub fn empty() -> Self {
        Self { words: Vec::new() }
    }

    /// Builds a bitmap containing the given attribute numbers.
    ///
    /// The client caps bitmap construction to the same word count accepted by
    /// the decoder, preventing accidental huge allocations from untrusted attr
    /// ids.
    pub fn from_attrs(attrs: &[u32]) -> Result<Self> {
        validate_bitmap_attrs(attrs)?;
        Ok(Self::from_valid_attrs(attrs))
    }

    pub(crate) fn from_known_attrs(attrs: &[u32]) -> Self {
        debug_assert!(validate_bitmap_attrs(attrs).is_ok());
        Self::from_valid_attrs(attrs)
    }

    fn from_valid_attrs(attrs: &[u32]) -> Self {
        let max = attrs.iter().copied().max();
        let mut words = max
            .map(|attr| vec![0; attr as usize / 32 + 1])
            .unwrap_or_default();
        for attr in attrs {
            let word = (*attr / 32) as usize;
            let bit = *attr % 32;
            words[word] |= 1 << bit;
        }
        Self { words }
    }

    /// Builds a bitmap containing requested attributes that are supported.
    pub fn from_supported_attrs(supported: &Self, attrs: &[u32]) -> Result<Self> {
        validate_bitmap_attrs(attrs)?;
        let attrs = attrs
            .iter()
            .copied()
            .filter(|attr| supported.contains(*attr))
            .collect::<Vec<_>>();
        Self::from_attrs(&attrs)
    }

    /// Returns the raw bitmap words.
    pub fn words(&self) -> &[u32] {
        &self.words
    }

    /// Returns true when no attribute bits are set.
    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    /// Returns true when `attr` is present in the bitmap.
    pub fn contains(&self, attr: u32) -> bool {
        let word = attr as usize / 32;
        let bit = attr % 32;
        self.words
            .get(word)
            .map(|word| (word & (1 << bit)) != 0)
            .unwrap_or(false)
    }

    fn attrs(&self) -> impl Iterator<Item = u32> + '_ {
        self.words
            .iter()
            .enumerate()
            .flat_map(|(word_index, word)| {
                (0..32).filter_map(move |bit| {
                    if (word & (1 << bit)) != 0 {
                        Some((word_index as u32) * 32 + bit)
                    } else {
                        None
                    }
                })
            })
    }
}

impl Encode for Bitmap {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_array(&self.words, NFS4_MAX_BITMAP_WORDS)
    }
}

impl Decode for Bitmap {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            words: decoder.read_array::<u32>(NFS4_MAX_BITMAP_WORDS)?,
        })
    }
}

fn validate_bitmap_attrs(attrs: &[u32]) -> Result<()> {
    let Some(attr) = attrs
        .iter()
        .copied()
        .find(|attr| (*attr as usize / 32) >= NFS4_MAX_BITMAP_WORDS)
    else {
        return Ok(());
    };

    Err(Error::Protocol(format!(
        "NFSv4 bitmap attribute {attr} exceeds supported bitmap word limit {NFS4_MAX_BITMAP_WORDS}"
    )))
}

/// Raw NFSv4 attribute payload.
///
/// High-level APIs usually return parsed structures such as
/// [`BasicAttributes`], [`FsInfo`], [`FsStat`], and [`PathConf`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fattr {
    /// Attribute bitmap describing the encoded values.
    pub attrmask: Bitmap,
    /// XDR-encoded attribute values in bitmap order.
    pub attr_vals: Vec<u8>,
}

impl Fattr {
    /// Creates an empty attribute payload.
    pub fn empty() -> Self {
        Self {
            attrmask: Bitmap::empty(),
            attr_vals: Vec::new(),
        }
    }

    /// Creates an attribute payload that sets file size.
    pub fn size(size: u64) -> Self {
        let mut encoder = Encoder::new();
        encoder.write_u64(size);
        Self {
            attrmask: Bitmap::from_known_attrs(&[FATTR4_SIZE]),
            attr_vals: encoder.into_bytes(),
        }
    }

    /// Creates an attribute payload that sets mode bits.
    pub fn mode(mode: u32) -> Self {
        let mut encoder = Encoder::new();
        encoder.write_u32(mode);
        Self {
            attrmask: Bitmap::from_known_attrs(&[FATTR4_MODE]),
            attr_vals: encoder.into_bytes(),
        }
    }

    /// Encodes high-level settable attributes.
    pub fn from_set_attrs(attrs: &SetAttrs) -> Result<Self> {
        let mut attr_ids = Vec::new();
        let mut encoder = Encoder::new();

        if let Some(size) = attrs.size {
            attr_ids.push(FATTR4_SIZE);
            encoder.write_u64(size);
        }
        if let Some(mode) = attrs.mode {
            attr_ids.push(FATTR4_MODE);
            encoder.write_u32(mode);
        }
        if let Some(owner) = &attrs.owner {
            attr_ids.push(FATTR4_OWNER);
            encoder.write_string(owner, NFS4_OPAQUE_LIMIT)?;
        }
        if let Some(owner_group) = &attrs.owner_group {
            attr_ids.push(FATTR4_OWNER_GROUP);
            encoder.write_string(owner_group, NFS4_OPAQUE_LIMIT)?;
        }
        if attrs.access_time != SetTime::DontChange {
            attr_ids.push(FATTR4_TIME_ACCESS_SET);
            encode_set_time(&mut encoder, attrs.access_time)?;
        }
        if attrs.modify_time != SetTime::DontChange {
            attr_ids.push(FATTR4_TIME_MODIFY_SET);
            encode_set_time(&mut encoder, attrs.modify_time)?;
        }

        Ok(Self {
            attrmask: Bitmap::from_known_attrs(&attr_ids),
            attr_vals: encoder.into_bytes(),
        })
    }

    /// Parses a `supported_attrs` response.
    pub fn parse_supported_attrs(&self) -> Result<Bitmap> {
        let mut decoder = Decoder::new(&self.attr_vals);
        let mut supported = None;

        for attr in self.attrmask.attrs() {
            match attr {
                FATTR4_SUPPORTED_ATTRS => supported = Some(Bitmap::decode(&mut decoder)?),
                _ => {
                    return Err(Error::Protocol(format!(
                        "cannot parse unsupported NFSv4 supported_attrs attribute {attr}"
                    )));
                }
            }
        }

        decoder.finish()?;
        supported.ok_or_else(|| {
            Error::Protocol("NFSv4 supported_attrs response did not include attr 0".into())
        })
    }

    /// Parses the basic attribute set used by the high-level client.
    pub fn parse_basic(&self) -> Result<BasicAttributes> {
        let mut decoder = Decoder::new(&self.attr_vals);
        let mut parsed = BasicAttributes {
            file_type: None,
            change: None,
            size: None,
            fileid: None,
            mode: None,
            numlinks: None,
            owner: None,
            owner_group: None,
            space_used: None,
            access_time: None,
            metadata_time: None,
            modify_time: None,
            raw: self.clone(),
        };

        for attr in self.attrmask.attrs() {
            match attr {
                FATTR4_TYPE => parsed.file_type = Some(FileType::from_u32(decoder.read_u32()?)),
                FATTR4_CHANGE => parsed.change = Some(decoder.read_u64()?),
                FATTR4_SIZE => parsed.size = Some(decoder.read_u64()?),
                FATTR4_FILEID => parsed.fileid = Some(decoder.read_u64()?),
                FATTR4_MODE => parsed.mode = Some(decoder.read_u32()?),
                FATTR4_NUMLINKS => parsed.numlinks = Some(decoder.read_u32()?),
                FATTR4_OWNER => parsed.owner = Some(decoder.read_string(NFS4_OPAQUE_LIMIT)?),
                FATTR4_OWNER_GROUP => {
                    parsed.owner_group = Some(decoder.read_string(NFS4_OPAQUE_LIMIT)?);
                }
                FATTR4_SPACE_USED => parsed.space_used = Some(decoder.read_u64()?),
                FATTR4_TIME_ACCESS => parsed.access_time = Some(NfsTime::decode(&mut decoder)?),
                FATTR4_TIME_METADATA => {
                    parsed.metadata_time = Some(NfsTime::decode(&mut decoder)?);
                }
                FATTR4_TIME_MODIFY => parsed.modify_time = Some(NfsTime::decode(&mut decoder)?),
                _ => {
                    return Err(Error::Protocol(format!(
                        "cannot parse unsupported NFSv4 basic attribute {attr}"
                    )));
                }
            }
        }

        decoder.finish()?;
        Ok(parsed)
    }

    pub fn parse_fsstat(&self) -> Result<FsStat> {
        let mut decoder = Decoder::new(&self.attr_vals);
        let mut parsed = FsStat {
            total_bytes: None,
            free_bytes: None,
            available_bytes: None,
            total_files: None,
            free_files: None,
            available_files: None,
            raw: self.clone(),
        };

        for attr in self.attrmask.attrs() {
            match attr {
                FATTR4_FILES_AVAIL => parsed.available_files = Some(decoder.read_u64()?),
                FATTR4_FILES_FREE => parsed.free_files = Some(decoder.read_u64()?),
                FATTR4_FILES_TOTAL => parsed.total_files = Some(decoder.read_u64()?),
                FATTR4_SPACE_AVAIL => parsed.available_bytes = Some(decoder.read_u64()?),
                FATTR4_SPACE_FREE => parsed.free_bytes = Some(decoder.read_u64()?),
                FATTR4_SPACE_TOTAL => parsed.total_bytes = Some(decoder.read_u64()?),
                _ => {
                    return Err(Error::Protocol(format!(
                        "cannot parse unsupported NFSv4 fsstat attribute {attr}"
                    )));
                }
            }
        }

        decoder.finish()?;
        Ok(parsed)
    }

    pub fn parse_fsinfo(&self) -> Result<FsInfo> {
        let mut decoder = Decoder::new(&self.attr_vals);
        let mut parsed = FsInfo {
            fh_expire_type: None,
            link_support: None,
            symlink_support: None,
            unique_handles: None,
            lease_time_seconds: None,
            can_set_time: None,
            homogeneous: None,
            max_file_size: None,
            max_read: None,
            max_write: None,
            time_delta: None,
            raw: self.clone(),
        };

        for attr in self.attrmask.attrs() {
            match attr {
                FATTR4_FH_EXPIRE_TYPE => parsed.fh_expire_type = Some(decoder.read_u32()?),
                FATTR4_LINK_SUPPORT => parsed.link_support = Some(decoder.read_bool()?),
                FATTR4_SYMLINK_SUPPORT => parsed.symlink_support = Some(decoder.read_bool()?),
                FATTR4_UNIQUE_HANDLES => parsed.unique_handles = Some(decoder.read_bool()?),
                FATTR4_LEASE_TIME => parsed.lease_time_seconds = Some(decoder.read_u32()?),
                FATTR4_CANSETTIME => parsed.can_set_time = Some(decoder.read_bool()?),
                FATTR4_HOMOGENEOUS => parsed.homogeneous = Some(decoder.read_bool()?),
                FATTR4_MAXFILESIZE => parsed.max_file_size = Some(decoder.read_u64()?),
                FATTR4_MAXREAD => parsed.max_read = Some(decoder.read_u64()?),
                FATTR4_MAXWRITE => parsed.max_write = Some(decoder.read_u64()?),
                FATTR4_TIME_DELTA => parsed.time_delta = Some(NfsTime::decode(&mut decoder)?),
                _ => {
                    return Err(Error::Protocol(format!(
                        "cannot parse unsupported NFSv4 fsinfo attribute {attr}"
                    )));
                }
            }
        }

        decoder.finish()?;
        Ok(parsed)
    }

    pub fn parse_pathconf(&self) -> Result<PathConf> {
        let mut decoder = Decoder::new(&self.attr_vals);
        let mut parsed = PathConf {
            link_max: None,
            name_max: None,
            no_trunc: None,
            chown_restricted: None,
            case_insensitive: None,
            case_preserving: None,
            raw: self.clone(),
        };

        for attr in self.attrmask.attrs() {
            match attr {
                FATTR4_CASE_INSENSITIVE => parsed.case_insensitive = Some(decoder.read_bool()?),
                FATTR4_CASE_PRESERVING => parsed.case_preserving = Some(decoder.read_bool()?),
                FATTR4_CHOWN_RESTRICTED => {
                    parsed.chown_restricted = Some(decoder.read_bool()?);
                }
                FATTR4_MAXLINK => parsed.link_max = Some(decoder.read_u32()?),
                FATTR4_MAXNAME => parsed.name_max = Some(decoder.read_u32()?),
                FATTR4_NO_TRUNC => parsed.no_trunc = Some(decoder.read_bool()?),
                _ => {
                    return Err(Error::Protocol(format!(
                        "cannot parse unsupported NFSv4 pathconf attribute {attr}"
                    )));
                }
            }
        }

        decoder.finish()?;
        Ok(parsed)
    }
}

impl Decode for Fattr {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            attrmask: Bitmap::decode(decoder)?,
            attr_vals: decoder.read_opaque_vec(NFS4_MAX_IO)?,
        })
    }
}

impl Encode for Fattr {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.attrmask.encode(encoder)?;
        encoder.write_opaque(&self.attr_vals, NFS4_MAX_IO)
    }
}

/// Parsed basic NFSv4 attributes.
///
/// NFSv4 servers may omit attributes. Optional fields reflect exactly what was
/// returned by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicAttributes {
    pub file_type: Option<FileType>,
    pub change: Option<u64>,
    pub size: Option<u64>,
    pub fileid: Option<u64>,
    pub mode: Option<u32>,
    pub numlinks: Option<u32>,
    pub owner: Option<String>,
    pub owner_group: Option<String>,
    pub space_used: Option<u64>,
    pub access_time: Option<NfsTime>,
    pub metadata_time: Option<NfsTime>,
    pub modify_time: Option<NfsTime>,
    pub raw: Fattr,
}

impl BasicAttributes {
    /// Returns the file type or an error if the server omitted it.
    pub fn required_file_type(&self) -> Result<FileType> {
        self.file_type.ok_or_else(|| {
            Error::Protocol("NFSv4 file type attribute was not returned by the server".to_owned())
        })
    }

    /// Returns true when the object is a regular file.
    pub fn is_file(&self) -> Result<bool> {
        Ok(self.required_file_type()?.is_file())
    }

    /// Returns true when the object is a directory.
    pub fn is_dir(&self) -> Result<bool> {
        Ok(self.required_file_type()?.is_dir())
    }

    /// Returns true when the object is a symbolic link.
    pub fn is_symlink(&self) -> Result<bool> {
        Ok(self.required_file_type()?.is_symlink())
    }
}

/// Parsed NFSv4 filesystem capacity attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsStat {
    pub total_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub total_files: Option<u64>,
    pub free_files: Option<u64>,
    pub available_files: Option<u64>,
    pub raw: Fattr,
}

/// Parsed NFSv4 filesystem capability attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsInfo {
    pub fh_expire_type: Option<u32>,
    pub link_support: Option<bool>,
    pub symlink_support: Option<bool>,
    pub unique_handles: Option<bool>,
    pub lease_time_seconds: Option<u32>,
    pub can_set_time: Option<bool>,
    pub homogeneous: Option<bool>,
    pub max_file_size: Option<u64>,
    pub max_read: Option<u64>,
    pub max_write: Option<u64>,
    pub time_delta: Option<NfsTime>,
    pub raw: Fattr,
}

/// Time-setting mode used by [`SetAttrs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SetTime {
    /// Leave the timestamp unchanged.
    #[default]
    DontChange,
    /// Ask the server to set the timestamp to its current time.
    ServerTime,
    /// Set the timestamp to a client-provided value.
    ClientTime(NfsTime),
}

/// NFSv4 attribute update.
///
/// Fields left empty are not sent to the server. Use constructors such as
/// [`SetAttrs::mode`], [`SetAttrs::size`], and [`SetAttrs::touch`] for common
/// updates.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SetAttrs {
    pub size: Option<u64>,
    pub mode: Option<u32>,
    pub owner: Option<String>,
    pub owner_group: Option<String>,
    pub access_time: SetTime,
    pub modify_time: SetTime,
}

impl SetAttrs {
    /// Builds an attribute update that sets file size.
    pub fn size(size: u64) -> Self {
        Self {
            size: Some(size),
            ..Self::default()
        }
    }

    /// Builds an attribute update that sets POSIX mode bits.
    pub fn mode(mode: u32) -> Self {
        Self {
            mode: Some(mode),
            ..Self::default()
        }
    }

    /// Builds an attribute update that sets owner.
    pub fn owner(owner: impl Into<String>) -> Self {
        Self {
            owner: Some(owner.into()),
            ..Self::default()
        }
    }

    /// Builds an attribute update that sets owner group.
    pub fn owner_group(owner_group: impl Into<String>) -> Self {
        Self {
            owner_group: Some(owner_group.into()),
            ..Self::default()
        }
    }

    /// Builds an attribute update that sets owner and owner group.
    pub fn ownership(owner: impl Into<String>, owner_group: impl Into<String>) -> Self {
        Self {
            owner: Some(owner.into()),
            owner_group: Some(owner_group.into()),
            ..Self::default()
        }
    }

    /// Builds an attribute update that sets access and modification times.
    pub fn times(access_time: Option<NfsTime>, modify_time: Option<NfsTime>) -> Self {
        Self {
            access_time: access_time.map_or(SetTime::DontChange, SetTime::ClientTime),
            modify_time: modify_time.map_or(SetTime::DontChange, SetTime::ClientTime),
            ..Self::default()
        }
    }

    /// Builds an attribute update that asks the server to update both times.
    pub fn touch() -> Self {
        Self {
            access_time: SetTime::ServerTime,
            modify_time: SetTime::ServerTime,
            ..Self::default()
        }
    }
}

/// Parsed NFSv4 path configuration attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathConf {
    pub link_max: Option<u32>,
    pub name_max: Option<u32>,
    pub no_trunc: Option<bool>,
    pub chown_restricted: Option<bool>,
    pub case_insensitive: Option<bool>,
    pub case_preserving: Option<bool>,
    pub raw: Fattr,
}

/// NFSv4 timestamp with second and nanosecond components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NfsTime {
    /// Seconds since the Unix epoch.
    pub seconds: i64,
    /// Nanoseconds within the second. Must be less than
    /// [`NFS4_NSECONDS_PER_SECOND`] when encoded.
    pub nseconds: u32,
}

impl Decode for NfsTime {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        let time = Self {
            seconds: decoder.read_i64()?,
            nseconds: decoder.read_u32()?,
        };
        time.validate()?;
        Ok(time)
    }
}

impl Encode for NfsTime {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.validate()?;
        encoder.write_i64(self.seconds);
        encoder.write_u32(self.nseconds);
        Ok(())
    }
}

impl NfsTime {
    pub(crate) fn validate(self) -> crate::xdr::Result<()> {
        validate_nseconds(self.nseconds)
    }
}

fn encode_set_time(encoder: &mut Encoder, value: SetTime) -> crate::xdr::Result<()> {
    match value {
        SetTime::DontChange | SetTime::ServerTime => encoder.write_u32(0),
        SetTime::ClientTime(time) => {
            time.validate()?;
            encoder.write_u32(1);
            time.encode(encoder)?;
        }
    }
    Ok(())
}

fn validate_nseconds(nseconds: u32) -> crate::xdr::Result<()> {
    if nseconds >= NFS4_NSECONDS_PER_SECOND {
        return Err(crate::xdr::Error::LengthLimitExceeded {
            len: nseconds as usize,
            max: (NFS4_NSECONDS_PER_SECOND - 1) as usize,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessResult {
    pub supported: u32,
    pub access: u32,
}

/// RPCSEC_GSS service advertised by `SECINFO`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcGssService {
    None,
    Integrity,
    Privacy,
    Unknown(u32),
}

impl RpcGssService {
    /// Converts a protocol discriminant into [`RpcGssService`].
    pub fn from_u32(value: u32) -> Self {
        match value {
            RPC_GSS_SVC_NONE => Self::None,
            RPC_GSS_SVC_INTEGRITY => Self::Integrity,
            RPC_GSS_SVC_PRIVACY => Self::Privacy,
            value => Self::Unknown(value),
        }
    }

    /// Returns the protocol discriminant.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::None => RPC_GSS_SVC_NONE,
            Self::Integrity => RPC_GSS_SVC_INTEGRITY,
            Self::Privacy => RPC_GSS_SVC_PRIVACY,
            Self::Unknown(value) => value,
        }
    }
}

/// Security flavor advertised by `SECINFO` and `SECINFO_NO_NAME`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecInfo {
    AuthNone,
    AuthSys,
    RpcSecGss {
        oid: Vec<u8>,
        qop: u32,
        service: RpcGssService,
    },
    Unknown(u32),
}

impl Decode for SecInfo {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        match decoder.read_u32()? {
            AUTH_NONE => Ok(Self::AuthNone),
            AUTH_SYS => Ok(Self::AuthSys),
            RPCSEC_GSS => Ok(Self::RpcSecGss {
                oid: decoder.read_opaque_vec(NFS4_OPAQUE_LIMIT)?,
                qop: decoder.read_u32()?,
                service: RpcGssService::from_u32(decoder.read_u32()?),
            }),
            flavor => Ok(Self::Unknown(flavor)),
        }
    }
}

/// RPC universal network address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetAddr {
    pub netid: String,
    pub addr: String,
}

impl Encode for NetAddr {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_string(&self.netid, NFS4_OPAQUE_LIMIT)?;
        encoder.write_string(&self.addr, NFS4_OPAQUE_LIMIT)
    }
}

impl Decode for NetAddr {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            netid: decoder.read_string(NFS4_OPAQUE_LIMIT)?,
            addr: decoder.read_string(NFS4_OPAQUE_LIMIT)?,
        })
    }
}

/// Callback security parameter used by `CREATE_SESSION` and `BACKCHANNEL_CTL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallbackSecParms {
    AuthNone,
    AuthSys(AuthSys),
    RpcSecGss {
        service: RpcGssService,
        handle_from_server: Vec<u8>,
        handle_from_client: Vec<u8>,
    },
}

impl Encode for CallbackSecParms {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        match self {
            Self::AuthNone => {
                encoder.write_u32(AUTH_NONE);
                Ok(())
            }
            Self::AuthSys(auth) => {
                encoder.write_u32(AUTH_SYS);
                auth.encode(encoder)
            }
            Self::RpcSecGss {
                service,
                handle_from_server,
                handle_from_client,
            } => {
                encoder.write_u32(RPCSEC_GSS);
                encoder.write_u32(service.as_u32());
                encoder.write_opaque(handle_from_server, NFS4_OPAQUE_LIMIT)?;
                encoder.write_opaque(handle_from_client, NFS4_OPAQUE_LIMIT)
            }
        }
    }
}

/// `SECINFO_NO_NAME` selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecInfoStyle {
    CurrentFileHandle,
    Parent,
}

impl SecInfoStyle {
    /// Returns the protocol discriminant.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::CurrentFileHandle => 0,
            Self::Parent => 1,
        }
    }

    /// Converts a protocol discriminant into [`SecInfoStyle`].
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::CurrentFileHandle,
            1 => Self::Parent,
            _ => return None,
        })
    }
}

/// NFSv4.1 state protection selector used by `EXCHANGE_ID`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateProtectHow {
    /// No state protection is requested.
    None,
    /// Machine credentials protect state-changing operations.
    MachineCredentials,
    /// Secret state verifier protection.
    SecretStateVerifier,
}

impl StateProtectHow {
    /// Returns the protocol discriminant.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::None => 0,
            Self::MachineCredentials => 1,
            Self::SecretStateVerifier => 2,
        }
    }

    /// Converts a protocol discriminant into [`StateProtectHow`].
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::None,
            1 => Self::MachineCredentials,
            2 => Self::SecretStateVerifier,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientOwner {
    pub verifier: Verifier,
    pub owner_id: Vec<u8>,
}

impl Encode for ClientOwner {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_fixed_opaque(&self.verifier);
        encoder.write_opaque(&self.owner_id, NFS4_OPAQUE_LIMIT)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackClient {
    pub program: u32,
    pub location: NetAddr,
}

impl Encode for CallbackClient {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u32(self.program);
        self.location.encode(encoder)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetClientIdArgs {
    pub client: ClientOwner,
    pub callback: CallbackClient,
    pub callback_ident: u32,
}

impl Encode for SetClientIdArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.client.encode(encoder)?;
        self.callback.encode(encoder)?;
        encoder.write_u32(self.callback_ident);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetClientIdConfirmArgs {
    pub client_id: u64,
    pub verifier: Verifier,
}

impl Encode for SetClientIdConfirmArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u64(self.client_id);
        encoder.write_fixed_opaque(&self.verifier);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetClientIdResult {
    pub client_id: u64,
    pub verifier: Verifier,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeIdArgs {
    pub client_owner: ClientOwner,
    pub flags: u32,
}

impl Encode for ExchangeIdArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.client_owner.encode(encoder)?;
        encoder.write_u32(self.flags);
        encoder.write_u32(StateProtectHow::None.as_u32());
        encoder.write_u32(0); // eia_client_impl_id<1>
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeIdResult {
    pub client_id: u64,
    pub sequence_id: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelAttrs {
    pub header_pad_size: u32,
    pub max_request_size: u32,
    pub max_response_size: u32,
    pub max_response_size_cached: u32,
    pub max_operations: u32,
    pub max_requests: u32,
    pub rdma_ird: Vec<u32>,
}

impl ChannelAttrs {
    pub fn fore_channel_default() -> Self {
        Self {
            header_pad_size: 0,
            max_request_size: DEFAULT_SESSION_CHANNEL_SIZE,
            max_response_size: DEFAULT_SESSION_CHANNEL_SIZE,
            max_response_size_cached: DEFAULT_SESSION_CHANNEL_SIZE,
            max_operations: 64,
            max_requests: 1,
            rdma_ird: Vec::new(),
        }
    }

    pub fn back_channel_disabled() -> Self {
        Self {
            header_pad_size: 0,
            max_request_size: DEFAULT_SESSION_CHANNEL_SIZE,
            max_response_size: DEFAULT_SESSION_CHANNEL_SIZE,
            max_response_size_cached: DEFAULT_SESSION_CHANNEL_SIZE,
            max_operations: 8,
            max_requests: 1,
            rdma_ird: Vec::new(),
        }
    }
}

impl Encode for ChannelAttrs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u32(self.header_pad_size);
        encoder.write_u32(self.max_request_size);
        encoder.write_u32(self.max_response_size);
        encoder.write_u32(self.max_response_size_cached);
        encoder.write_u32(self.max_operations);
        encoder.write_u32(self.max_requests);
        encoder.write_array(&self.rdma_ird, 1)?;
        Ok(())
    }
}

impl Decode for ChannelAttrs {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            header_pad_size: decoder.read_u32()?,
            max_request_size: decoder.read_u32()?,
            max_response_size: decoder.read_u32()?,
            max_response_size_cached: decoder.read_u32()?,
            max_operations: decoder.read_u32()?,
            max_requests: decoder.read_u32()?,
            rdma_ird: decoder.read_array::<u32>(1)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSessionArgs {
    pub client_id: u64,
    pub sequence_id: u32,
    pub flags: u32,
    pub fore_channel_attrs: ChannelAttrs,
    pub back_channel_attrs: ChannelAttrs,
    pub callback_program: u32,
    pub callback_sec_parms: Vec<CallbackSecParms>,
}

impl Encode for CreateSessionArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u64(self.client_id);
        encoder.write_u32(self.sequence_id);
        encoder.write_u32(self.flags);
        self.fore_channel_attrs.encode(encoder)?;
        self.back_channel_attrs.encode(encoder)?;
        encoder.write_u32(self.callback_program);
        encoder.write_array(&self.callback_sec_parms, NFS4_MAX_CALLBACK_SEC_PARMS)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSessionResult {
    pub session_id: SessionId,
    pub sequence_id: u32,
    pub flags: u32,
    pub fore_channel_attrs: ChannelAttrs,
    pub back_channel_attrs: ChannelAttrs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackchannelCtlArgs {
    pub callback_program: u32,
    pub callback_sec_parms: Vec<CallbackSecParms>,
}

impl Encode for BackchannelCtlArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u32(self.callback_program);
        encoder.write_array(&self.callback_sec_parms, NFS4_MAX_CALLBACK_SEC_PARMS)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceArgs {
    pub session_id: SessionId,
    pub sequence_id: u32,
    pub slot_id: u32,
    pub highest_slot_id: u32,
    pub cache_this: bool,
}

impl Encode for SequenceArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_fixed_opaque(&self.session_id);
        encoder.write_u32(self.sequence_id);
        encoder.write_u32(self.slot_id);
        encoder.write_u32(self.highest_slot_id);
        encoder.write_bool(self.cache_this);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceResult {
    pub session_id: SessionId,
    pub sequence_id: u32,
    pub slot_id: u32,
    pub highest_slot_id: u32,
    pub target_highest_slot_id: u32,
    pub status_flags: u32,
}

/// Direction requested by `BIND_CONN_TO_SESSION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelDirFromClient {
    Fore,
    Back,
    ForeOrBoth,
    BackOrBoth,
}

impl ChannelDirFromClient {
    /// Returns the protocol discriminant.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Fore => 0x1,
            Self::Back => 0x2,
            Self::ForeOrBoth => 0x3,
            Self::BackOrBoth => 0x7,
        }
    }

    /// Converts a protocol discriminant into [`ChannelDirFromClient`].
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0x1 => Self::Fore,
            0x2 => Self::Back,
            0x3 => Self::ForeOrBoth,
            0x7 => Self::BackOrBoth,
            _ => return None,
        })
    }
}

/// Direction accepted by `BIND_CONN_TO_SESSION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelDirFromServer {
    Fore,
    Back,
    Both,
}

impl ChannelDirFromServer {
    /// Returns the protocol discriminant.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Fore => 0x1,
            Self::Back => 0x2,
            Self::Both => 0x3,
        }
    }

    /// Converts a protocol discriminant into [`ChannelDirFromServer`].
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0x1 => Self::Fore,
            0x2 => Self::Back,
            0x3 => Self::Both,
            _ => return None,
        })
    }
}

/// Arguments for `BIND_CONN_TO_SESSION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindConnToSessionArgs {
    pub session_id: SessionId,
    pub direction: ChannelDirFromClient,
    pub use_conn_in_rdma_mode: bool,
}

impl Encode for BindConnToSessionArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_fixed_opaque(&self.session_id);
        encoder.write_u32(self.direction.as_u32());
        encoder.write_bool(self.use_conn_in_rdma_mode);
        Ok(())
    }
}

/// Result of `BIND_CONN_TO_SESSION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindConnToSessionResult {
    pub session_id: SessionId,
    pub direction: ChannelDirFromServer,
    pub use_conn_in_rdma_mode: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOwner {
    pub client_id: u64,
    pub owner: Vec<u8>,
}

impl Encode for OpenOwner {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u64(self.client_id);
        encoder.write_opaque(&self.owner, NFS4_OPAQUE_LIMIT)
    }
}

/// NFSv4 OPEN create mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateMode {
    /// Create if needed and do not fail when the object already exists.
    Unchecked,
    /// Fail with `NFS4ERR_EXIST` when the object already exists.
    Guarded,
    /// Deprecated v4.0-style exclusive create verifier.
    Exclusive,
    /// v4.1 exclusive create verifier with attributes.
    Exclusive4_1,
}

impl CreateMode {
    /// Returns the protocol discriminant.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Unchecked => 0,
            Self::Guarded => 1,
            Self::Exclusive => 2,
            Self::Exclusive4_1 => 3,
        }
    }

    /// Converts a protocol discriminant into [`CreateMode`].
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::Unchecked,
            1 => Self::Guarded,
            2 => Self::Exclusive,
            3 => Self::Exclusive4_1,
            _ => return None,
        })
    }
}

/// NFSv4 OPEN `openflag4` selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenType {
    /// Open an existing object.
    NoCreate,
    /// Create the object when needed.
    Create,
}

impl OpenType {
    /// Returns the protocol discriminant.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::NoCreate => 0,
            Self::Create => 1,
        }
    }

    /// Converts a protocol discriminant into [`OpenType`].
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::NoCreate,
            1 => Self::Create,
            _ => return None,
        })
    }
}

/// NFSv4 OPEN delegation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenDelegationType {
    /// No delegation was granted.
    None,
    /// A read delegation was granted.
    Read,
    /// A write delegation was granted.
    Write,
    /// No delegation was granted, with v4.1 reason details.
    NoneExt,
}

impl OpenDelegationType {
    /// Returns the protocol discriminant.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::None => 0,
            Self::Read => 1,
            Self::Write => 2,
            Self::NoneExt => 3,
        }
    }

    /// Converts a protocol discriminant into [`OpenDelegationType`].
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::None,
            1 => Self::Read,
            2 => Self::Write,
            3 => Self::NoneExt,
            _ => return None,
        })
    }
}

/// NFSv4 ACE used in delegation permissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfsAce {
    pub ace_type: u32,
    pub flag: u32,
    pub access_mask: u32,
    pub who: String,
}

impl Decode for NfsAce {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            ace_type: decoder.read_u32()?,
            flag: decoder.read_u32()?,
            access_mask: decoder.read_u32()?,
            who: decoder.read_string(NFS4_OPAQUE_LIMIT)?,
        })
    }
}

/// Space limit returned with write delegations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfsSpaceLimit {
    Size(u64),
    Blocks {
        num_blocks: u32,
        bytes_per_block: u32,
    },
}

impl Decode for NfsSpaceLimit {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        match decoder.read_u32()? {
            1 => Ok(Self::Size(decoder.read_u64()?)),
            2 => Ok(Self::Blocks {
                num_blocks: decoder.read_u32()?,
                bytes_per_block: decoder.read_u32()?,
            }),
            value => Err(crate::xdr::Error::InvalidDiscriminant {
                type_name: "limit_by4",
                value: value as i32,
            }),
        }
    }
}

/// Read delegation payload returned by OPEN or WANT_DELEGATION.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenReadDelegation {
    pub stateid: StateId,
    pub recall: bool,
    pub permissions: NfsAce,
}

/// Write delegation payload returned by OPEN or WANT_DELEGATION.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenWriteDelegation {
    pub stateid: StateId,
    pub recall: bool,
    pub space_limit: NfsSpaceLimit,
    pub permissions: NfsAce,
}

/// Reason why the server did not grant an OPEN delegation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhyNoDelegation {
    NotWanted,
    Contention,
    Resource,
    NotSupportedFileType,
    WriteDelegationNotSupportedFileType,
    NotSupportedUpgrade,
    NotSupportedDowngrade,
    Cancelled,
    IsDirectory,
    Unknown(u32),
}

impl WhyNoDelegation {
    /// Converts a protocol discriminant into [`WhyNoDelegation`].
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::NotWanted,
            1 => Self::Contention,
            2 => Self::Resource,
            3 => Self::NotSupportedFileType,
            4 => Self::WriteDelegationNotSupportedFileType,
            5 => Self::NotSupportedUpgrade,
            6 => Self::NotSupportedDowngrade,
            7 => Self::Cancelled,
            8 => Self::IsDirectory,
            value => Self::Unknown(value),
        }
    }
}

/// Extended no-delegation payload returned by NFSv4.1+ servers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenNoneDelegation {
    pub why: WhyNoDelegation,
    pub server_will_push_deleg: Option<bool>,
    pub server_will_signal_avail: Option<bool>,
}

/// Delegation returned by OPEN or WANT_DELEGATION.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenDelegation {
    None,
    Read(OpenReadDelegation),
    Write(OpenWriteDelegation),
    NoneExt(OpenNoneDelegation),
}

impl Decode for OpenDelegation {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        match decoder.read_u32()? {
            0 => Ok(Self::None),
            1 => Ok(Self::Read(OpenReadDelegation {
                stateid: StateId::decode(decoder)?,
                recall: bool::decode(decoder)?,
                permissions: NfsAce::decode(decoder)?,
            })),
            2 => Ok(Self::Write(OpenWriteDelegation {
                stateid: StateId::decode(decoder)?,
                recall: bool::decode(decoder)?,
                space_limit: NfsSpaceLimit::decode(decoder)?,
                permissions: NfsAce::decode(decoder)?,
            })),
            3 => {
                let why = WhyNoDelegation::from_u32(decoder.read_u32()?);
                let (server_will_push_deleg, server_will_signal_avail) = match why {
                    WhyNoDelegation::Contention => (Some(bool::decode(decoder)?), None),
                    WhyNoDelegation::Resource => (None, Some(bool::decode(decoder)?)),
                    _ => (None, None),
                };
                Ok(Self::NoneExt(OpenNoneDelegation {
                    why,
                    server_will_push_deleg,
                    server_will_signal_avail,
                }))
            }
            value => Err(crate::xdr::Error::InvalidDiscriminant {
                type_name: "open_delegation_type4",
                value: value as i32,
            }),
        }
    }
}

/// NFSv4 OPEN claim selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenClaimType {
    /// Ordinary OPEN by file name.
    Null,
    /// Reclaim previous open state after server restart.
    Previous,
    /// OPEN by current delegation and file name.
    DelegateCurrent,
    /// Reclaim previous delegation by file name.
    DelegatePrevious,
    /// Ordinary OPEN by current filehandle.
    FileHandle,
    /// OPEN by current delegation and current filehandle.
    DelegateCurrentFileHandle,
    /// Reclaim previous delegation by current filehandle.
    DelegatePreviousFileHandle,
}

impl OpenClaimType {
    /// Returns the protocol discriminant.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Null => 0,
            Self::Previous => 1,
            Self::DelegateCurrent => 2,
            Self::DelegatePrevious => 3,
            Self::FileHandle => 4,
            Self::DelegateCurrentFileHandle => 5,
            Self::DelegatePreviousFileHandle => 6,
        }
    }

    /// Converts a protocol discriminant into [`OpenClaimType`].
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::Null,
            1 => Self::Previous,
            2 => Self::DelegateCurrent,
            3 => Self::DelegatePrevious,
            4 => Self::FileHandle,
            5 => Self::DelegateCurrentFileHandle,
            6 => Self::DelegatePreviousFileHandle,
            _ => return None,
        })
    }
}

/// NFSv4 byte-range lock type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockType {
    /// Shared read lock.
    Read,
    /// Exclusive write lock.
    Write,
    /// Blocking shared read lock.
    ReadBlocking,
    /// Blocking exclusive write lock.
    WriteBlocking,
}

impl LockType {
    /// Returns the protocol discriminant.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Read => 1,
            Self::Write => 2,
            Self::ReadBlocking => 3,
            Self::WriteBlocking => 4,
        }
    }

    /// Converts a protocol discriminant into [`LockType`].
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            1 => Self::Read,
            2 => Self::Write,
            3 => Self::ReadBlocking,
            4 => Self::WriteBlocking,
            _ => return None,
        })
    }
}

/// NFSv4 byte-range lock owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockOwner {
    pub client_id: u64,
    pub owner: Vec<u8>,
}

impl Encode for LockOwner {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u64(self.client_id);
        encoder.write_opaque(&self.owner, NFS4_OPAQUE_LIMIT)
    }
}

impl Decode for LockOwner {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            client_id: decoder.read_u64()?,
            owner: decoder.read_opaque_vec(NFS4_OPAQUE_LIMIT)?,
        })
    }
}

/// NFSv4 `LOCK` owner selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Locker {
    /// First lock for this lock owner, transitioning from an OPEN stateid.
    New {
        open_seqid: u32,
        open_stateid: StateId,
        lock_seqid: u32,
        lock_owner: LockOwner,
    },
    /// Existing lock owner identified by its lock stateid.
    Existing {
        lock_stateid: StateId,
        lock_seqid: u32,
    },
}

impl Encode for Locker {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        match self {
            Self::New {
                open_seqid,
                open_stateid,
                lock_seqid,
                lock_owner,
            } => {
                encoder.write_bool(true);
                encoder.write_u32(*open_seqid);
                open_stateid.encode(encoder)?;
                encoder.write_u32(*lock_seqid);
                lock_owner.encode(encoder)
            }
            Self::Existing {
                lock_stateid,
                lock_seqid,
            } => {
                encoder.write_bool(false);
                lock_stateid.encode(encoder)?;
                encoder.write_u32(*lock_seqid);
                Ok(())
            }
        }
    }
}

/// Arguments for the NFSv4 `LOCK` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockArgs {
    pub lock_type: LockType,
    pub reclaim: bool,
    pub offset: u64,
    pub length: u64,
    pub locker: Locker,
}

impl Encode for LockArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u32(self.lock_type.as_u32());
        encoder.write_bool(self.reclaim);
        encoder.write_u64(self.offset);
        encoder.write_u64(self.length);
        self.locker.encode(encoder)
    }
}

/// Arguments for the NFSv4 `LOCKT` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockTestArgs {
    pub lock_type: LockType,
    pub offset: u64,
    pub length: u64,
    pub owner: LockOwner,
}

impl Encode for LockTestArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u32(self.lock_type.as_u32());
        encoder.write_u64(self.offset);
        encoder.write_u64(self.length);
        self.owner.encode(encoder)
    }
}

/// Arguments for the NFSv4 `LOCKU` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockUnlockArgs {
    pub lock_type: LockType,
    pub seqid: u32,
    pub lock_stateid: StateId,
    pub offset: u64,
    pub length: u64,
}

impl Encode for LockUnlockArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u32(self.lock_type.as_u32());
        encoder.write_u32(self.seqid);
        self.lock_stateid.encode(encoder)?;
        encoder.write_u64(self.offset);
        encoder.write_u64(self.length);
        Ok(())
    }
}

/// Conflicting lock returned by `LOCK` or `LOCKT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockDenied {
    pub offset: u64,
    pub length: u64,
    pub lock_type: LockType,
    pub owner: LockOwner,
}

impl Decode for LockDenied {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        let offset = decoder.read_u64()?;
        let length = decoder.read_u64()?;
        let raw_lock_type = decoder.read_u32()?;
        let lock_type =
            LockType::from_u32(raw_lock_type).ok_or(crate::xdr::Error::InvalidDiscriminant {
                type_name: "nfs_lock_type4",
                value: raw_lock_type as i32,
            })?;
        Ok(Self {
            offset,
            length,
            lock_type,
            owner: LockOwner::decode(decoder)?,
        })
    }
}

/// NFSv4.2 IO_ADVISE hint type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoAdviceType {
    /// Default access behavior.
    Normal,
    /// Sequential access from lower to higher offsets.
    Sequential,
    /// Sequential access from higher to lower offsets.
    SequentialBackwards,
    /// Random access.
    Random,
    /// Data will likely be needed.
    WillNeed,
    /// Data may be needed speculatively.
    WillNeedOpportunistic,
    /// Data will likely not be needed.
    DontNeed,
    /// Data will be used once.
    NoReuse,
    /// Data will likely be read.
    Read,
    /// Data will likely be written.
    Write,
    /// Data recently accessed locally remains important.
    InitProximity,
}

impl IoAdviceType {
    /// Returns the protocol discriminant.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Normal => 0,
            Self::Sequential => 1,
            Self::SequentialBackwards => 2,
            Self::Random => 3,
            Self::WillNeed => 4,
            Self::WillNeedOpportunistic => 5,
            Self::DontNeed => 6,
            Self::NoReuse => 7,
            Self::Read => 8,
            Self::Write => 9,
            Self::InitProximity => 10,
        }
    }

    /// Converts a protocol discriminant into [`IoAdviceType`].
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::Normal,
            1 => Self::Sequential,
            2 => Self::SequentialBackwards,
            3 => Self::Random,
            4 => Self::WillNeed,
            5 => Self::WillNeedOpportunistic,
            6 => Self::DontNeed,
            7 => Self::NoReuse,
            8 => Self::Read,
            9 => Self::Write,
            10 => Self::InitProximity,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenHow {
    NoCreate,
    Unchecked(Fattr),
    Guarded(Fattr),
    Exclusive(Verifier),
    ExclusiveWithAttrs { verifier: Verifier, attrs: Fattr },
}

impl Encode for OpenHow {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        match self {
            Self::NoCreate => {
                encoder.write_u32(OpenType::NoCreate.as_u32());
            }
            Self::Unchecked(attrs) => {
                encoder.write_u32(OpenType::Create.as_u32());
                encoder.write_u32(CreateMode::Unchecked.as_u32());
                attrs.encode(encoder)?;
            }
            Self::Guarded(attrs) => {
                encoder.write_u32(OpenType::Create.as_u32());
                encoder.write_u32(CreateMode::Guarded.as_u32());
                attrs.encode(encoder)?;
            }
            Self::Exclusive(verifier) => {
                encoder.write_u32(OpenType::Create.as_u32());
                encoder.write_u32(CreateMode::Exclusive.as_u32());
                encoder.write_fixed_opaque(verifier);
            }
            Self::ExclusiveWithAttrs { verifier, attrs } => {
                encoder.write_u32(OpenType::Create.as_u32());
                encoder.write_u32(CreateMode::Exclusive4_1.as_u32());
                encoder.write_fixed_opaque(verifier);
                attrs.encode(encoder)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenClaim {
    Null(String),
    Previous(OpenDelegationType),
    DelegateCurrent {
        delegate_stateid: StateId,
        file: String,
    },
    DelegatePrevious(String),
    CurrentFileHandle,
    DelegateCurrentFileHandle(StateId),
    DelegatePreviousFileHandle,
}

impl Encode for OpenClaim {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        match self {
            Self::Null(name) => {
                encoder.write_u32(OpenClaimType::Null.as_u32());
                encoder.write_string(name, NFS4_OPAQUE_LIMIT)?;
            }
            Self::Previous(delegation_type) => {
                encoder.write_u32(OpenClaimType::Previous.as_u32());
                encoder.write_u32(delegation_type.as_u32());
            }
            Self::DelegateCurrent {
                delegate_stateid,
                file,
            } => {
                encoder.write_u32(OpenClaimType::DelegateCurrent.as_u32());
                delegate_stateid.encode(encoder)?;
                encoder.write_string(file, NFS4_OPAQUE_LIMIT)?;
            }
            Self::DelegatePrevious(file) => {
                encoder.write_u32(OpenClaimType::DelegatePrevious.as_u32());
                encoder.write_string(file, NFS4_OPAQUE_LIMIT)?;
            }
            Self::CurrentFileHandle => {
                encoder.write_u32(OpenClaimType::FileHandle.as_u32());
            }
            Self::DelegateCurrentFileHandle(delegate_stateid) => {
                encoder.write_u32(OpenClaimType::DelegateCurrentFileHandle.as_u32());
                delegate_stateid.encode(encoder)?;
            }
            Self::DelegatePreviousFileHandle => {
                encoder.write_u32(OpenClaimType::DelegatePreviousFileHandle.as_u32());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenArgs {
    pub seqid: u32,
    pub share_access: u32,
    pub share_deny: u32,
    pub owner: OpenOwner,
    pub openhow: OpenHow,
    pub claim: OpenClaim,
}

impl Encode for OpenArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u32(self.seqid);
        encoder.write_u32(self.share_access);
        encoder.write_u32(self.share_deny);
        self.owner.encode(encoder)?;
        self.openhow.encode(encoder)?;
        self.claim.encode(encoder)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenResult {
    pub stateid: StateId,
    pub result_flags: u32,
    pub attrset: Bitmap,
    pub delegation: OpenDelegation,
}

/// NFSv4 write stability requested or reported by the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StableHow {
    /// Server may cache data without committing it to stable storage.
    Unstable,
    /// Server commits file data, but not necessarily metadata.
    DataSync,
    /// Server commits file data and metadata.
    FileSync,
}

impl StableHow {
    /// Returns the protocol discriminant.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Unstable => 0,
            Self::DataSync => 1,
            Self::FileSync => 2,
        }
    }

    /// Converts a protocol discriminant into [`StableHow`].
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::Unstable,
            1 => Self::DataSync,
            2 => Self::FileSync,
            _ => return None,
        })
    }

    #[cfg(any(test, feature = "blocking", feature = "tokio"))]
    pub(crate) fn satisfies(self, requested: Self) -> bool {
        self >= requested
    }
}

/// Result of an NFSv4 WRITE operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteResult {
    /// Number of bytes written.
    pub count: u32,
    /// Stability level committed by the server.
    pub committed: StableHow,
    /// Server write verifier.
    pub verifier: Verifier,
}

/// Result of an NFSv4 COMMIT operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitResult {
    /// Server write verifier.
    pub verifier: Verifier,
}

/// NFSv4.2 SEEK content selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeekContent {
    /// Find data.
    Data,
    /// Find a hole.
    Hole,
}

impl SeekContent {
    /// Returns the protocol discriminant.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Data => NFS4_CONTENT_DATA,
            Self::Hole => NFS4_CONTENT_HOLE,
        }
    }

    /// Converts a protocol discriminant into [`SeekContent`].
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            NFS4_CONTENT_DATA => Self::Data,
            NFS4_CONTENT_HOLE => Self::Hole,
            _ => return None,
        })
    }
}

/// NFSv4.2 change attribute evolution classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeAttrType {
    /// Change values monotonically increase.
    MonotonicIncr,
    /// Change values are version counters.
    VersionCounter,
    /// Change values are version counters, without pNFS write preservation.
    VersionCounterNoPnfs,
    /// Change values are derived from `time_metadata`.
    TimeMetadata,
    /// The server does not define the evolution model.
    Undefined,
}

impl ChangeAttrType {
    /// Returns the protocol discriminant.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::MonotonicIncr => 0,
            Self::VersionCounter => 1,
            Self::VersionCounterNoPnfs => 2,
            Self::TimeMetadata => 3,
            Self::Undefined => 4,
        }
    }

    /// Converts a protocol discriminant into [`ChangeAttrType`].
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::MonotonicIncr,
            1 => Self::VersionCounter,
            2 => Self::VersionCounterNoPnfs,
            3 => Self::TimeMetadata,
            4 => Self::Undefined,
            _ => return None,
        })
    }
}

/// Result of an NFSv4.2 SEEK operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeekResult {
    /// Whether the server reached EOF before finding the requested content.
    pub eof: bool,
    /// Found offset, or EOF offset when `eof` is true.
    pub offset: u64,
}

impl SeekResult {
    /// Returns the found offset, or `None` when EOF was reached.
    pub fn found_offset(self) -> Option<u64> {
        (!self.eof).then_some(self.offset)
    }
}

/// Arguments for the NFSv4.2 `READ_PLUS` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadPlusArgs {
    pub stateid: StateId,
    pub offset: u64,
    pub count: u32,
}

impl Encode for ReadPlusArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.stateid.encode(encoder)?;
        encoder.write_u64(self.offset);
        encoder.write_u32(self.count);
        Ok(())
    }
}

/// One content segment returned by `READ_PLUS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadPlusContent {
    /// A data segment with its file offset and payload.
    Data { offset: u64, data: Vec<u8> },
    /// A hole segment with its file offset and length.
    Hole { offset: u64, length: u64 },
}

impl Decode for ReadPlusContent {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        match decoder.read_u32()? {
            NFS4_CONTENT_DATA => Ok(Self::Data {
                offset: decoder.read_u64()?,
                data: decoder.read_opaque_vec(NFS4_MAX_IO)?,
            }),
            NFS4_CONTENT_HOLE => Ok(Self::Hole {
                offset: decoder.read_u64()?,
                length: decoder.read_u64()?,
            }),
            value => Err(crate::xdr::Error::InvalidDiscriminant {
                type_name: "data_content4",
                value: value as i32,
            }),
        }
    }
}

/// Result of an NFSv4.2 `READ_PLUS` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadPlusResult {
    pub eof: bool,
    pub contents: Vec<ReadPlusContent>,
}

/// Arguments for the NFSv4.2 `IO_ADVISE` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoAdviseArgs {
    pub stateid: StateId,
    pub offset: u64,
    pub count: u64,
    pub hints: Bitmap,
}

impl Encode for IoAdviseArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.stateid.encode(encoder)?;
        encoder.write_u64(self.offset);
        encoder.write_u64(self.count);
        self.hints.encode(encoder)
    }
}

/// Result of an NFSv4.2 `IO_ADVISE` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoAdviseResult {
    pub hints: Bitmap,
}

/// Result of an NFSv4.2 `OFFLOAD_STATUS` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OffloadStatusResult {
    pub count: u64,
    pub complete: Option<Status>,
}

/// pNFS layout type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutType {
    NfsV4_1Files,
    Osd2Objects,
    BlockVolume,
    Unknown(u32),
}

impl LayoutType {
    /// Returns the protocol discriminant.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::NfsV4_1Files => LAYOUT4_NFSV4_1_FILES,
            Self::Osd2Objects => LAYOUT4_OSD2_OBJECTS,
            Self::BlockVolume => LAYOUT4_BLOCK_VOLUME,
            Self::Unknown(value) => value,
        }
    }

    /// Converts a protocol discriminant into [`LayoutType`].
    pub fn from_u32(value: u32) -> Self {
        match value {
            LAYOUT4_NFSV4_1_FILES => Self::NfsV4_1Files,
            LAYOUT4_OSD2_OBJECTS => Self::Osd2Objects,
            LAYOUT4_BLOCK_VOLUME => Self::BlockVolume,
            value => Self::Unknown(value),
        }
    }
}

impl Encode for LayoutType {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u32(self.as_u32());
        Ok(())
    }
}

impl Decode for LayoutType {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self::from_u32(decoder.read_u32()?))
    }
}

/// pNFS layout I/O mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutIomode {
    Read,
    ReadWrite,
    Any,
    Unknown(u32),
}

impl LayoutIomode {
    /// Returns the protocol discriminant.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Read => LAYOUTIOMODE4_READ,
            Self::ReadWrite => LAYOUTIOMODE4_RW,
            Self::Any => LAYOUTIOMODE4_ANY,
            Self::Unknown(value) => value,
        }
    }

    /// Converts a protocol discriminant into [`LayoutIomode`].
    pub fn from_u32(value: u32) -> Self {
        match value {
            LAYOUTIOMODE4_READ => Self::Read,
            LAYOUTIOMODE4_RW => Self::ReadWrite,
            LAYOUTIOMODE4_ANY => Self::Any,
            value => Self::Unknown(value),
        }
    }
}

impl Encode for LayoutIomode {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u32(self.as_u32());
        Ok(())
    }
}

impl Decode for LayoutIomode {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self::from_u32(decoder.read_u32()?))
    }
}

/// Opaque layout-type-specific content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutContent {
    pub layout_type: LayoutType,
    pub body: Vec<u8>,
}

impl Encode for LayoutContent {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.layout_type.encode(encoder)?;
        encoder.write_opaque(&self.body, NFS4_MAX_IO)
    }
}

impl Decode for LayoutContent {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            layout_type: LayoutType::decode(decoder)?,
            body: decoder.read_opaque_vec(NFS4_MAX_IO)?,
        })
    }
}

/// pNFS layout extent returned by `LAYOUTGET`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub offset: u64,
    pub length: u64,
    pub iomode: LayoutIomode,
    pub content: LayoutContent,
}

impl Encode for Layout {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u64(self.offset);
        encoder.write_u64(self.length);
        self.iomode.encode(encoder)?;
        self.content.encode(encoder)
    }
}

impl Decode for Layout {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            offset: decoder.read_u64()?,
            length: decoder.read_u64()?,
            iomode: LayoutIomode::decode(decoder)?,
            content: LayoutContent::decode(decoder)?,
        })
    }
}

/// pNFS device address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAddr {
    pub layout_type: LayoutType,
    pub body: Vec<u8>,
}

impl Decode for DeviceAddr {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            layout_type: LayoutType::decode(decoder)?,
            body: decoder.read_opaque_vec(NFS4_MAX_IO)?,
        })
    }
}

/// Opaque layout update sent by `LAYOUTCOMMIT` and `LAYOUTSTATS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutUpdate {
    pub layout_type: LayoutType,
    pub body: Vec<u8>,
}

impl Encode for LayoutUpdate {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.layout_type.encode(encoder)?;
        encoder.write_opaque(&self.body, NFS4_MAX_IO)
    }
}

/// `GET_DIR_DELEGATION` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetDirDelegationArgs {
    pub signal_deleg_avail: bool,
    pub notification_types: Bitmap,
    pub child_attr_delay: NfsTime,
    pub dir_attr_delay: NfsTime,
    pub child_attributes: Bitmap,
    pub dir_attributes: Bitmap,
}

impl Encode for GetDirDelegationArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_bool(self.signal_deleg_avail);
        self.notification_types.encode(encoder)?;
        self.child_attr_delay.encode(encoder)?;
        self.dir_attr_delay.encode(encoder)?;
        self.child_attributes.encode(encoder)?;
        self.dir_attributes.encode(encoder)
    }
}

/// `GET_DIR_DELEGATION` successful or non-fatal result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetDirDelegationResult {
    Granted {
        cookieverf: Verifier,
        stateid: StateId,
        notification: Bitmap,
        child_attributes: Bitmap,
        dir_attributes: Bitmap,
    },
    Unavailable {
        will_signal_deleg_avail: bool,
    },
}

/// `GETDEVICEINFO` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetDeviceInfoArgs {
    pub device_id: DeviceId,
    pub layout_type: LayoutType,
    pub max_count: u32,
    pub notify_types: Bitmap,
}

impl Encode for GetDeviceInfoArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.device_id.encode(encoder)?;
        self.layout_type.encode(encoder)?;
        encoder.write_u32(self.max_count);
        self.notify_types.encode(encoder)
    }
}

/// `GETDEVICEINFO` successful result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetDeviceInfoResult {
    pub device_addr: DeviceAddr,
    pub notification: Bitmap,
}

/// `GETDEVICELIST` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetDeviceListArgs {
    pub layout_type: LayoutType,
    pub max_devices: u32,
    pub cookie: u64,
    pub cookieverf: Verifier,
}

impl Encode for GetDeviceListArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.layout_type.encode(encoder)?;
        encoder.write_u32(self.max_devices);
        encoder.write_u64(self.cookie);
        encoder.write_fixed_opaque(&self.cookieverf);
        Ok(())
    }
}

/// `GETDEVICELIST` successful result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetDeviceListResult {
    pub cookie: u64,
    pub cookieverf: Verifier,
    pub device_ids: Vec<DeviceId>,
    pub eof: bool,
}

/// `LAYOUTCOMMIT` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutCommitArgs {
    pub offset: u64,
    pub length: u64,
    pub reclaim: bool,
    pub stateid: StateId,
    pub last_write_offset: Option<u64>,
    pub time_modify: Option<NfsTime>,
    pub layout_update: LayoutUpdate,
}

impl Encode for LayoutCommitArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u64(self.offset);
        encoder.write_u64(self.length);
        encoder.write_bool(self.reclaim);
        self.stateid.encode(encoder)?;
        encoder.write_optional(self.last_write_offset.as_ref())?;
        encoder.write_optional(self.time_modify.as_ref())?;
        self.layout_update.encode(encoder)
    }
}

/// `LAYOUTCOMMIT` successful result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutCommitResult {
    pub new_size: Option<u64>,
}

/// `LAYOUTGET` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutGetArgs {
    pub signal_layout_avail: bool,
    pub layout_type: LayoutType,
    pub iomode: LayoutIomode,
    pub offset: u64,
    pub length: u64,
    pub min_length: u64,
    pub stateid: StateId,
    pub max_count: u32,
}

impl Encode for LayoutGetArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_bool(self.signal_layout_avail);
        self.layout_type.encode(encoder)?;
        self.iomode.encode(encoder)?;
        encoder.write_u64(self.offset);
        encoder.write_u64(self.length);
        encoder.write_u64(self.min_length);
        self.stateid.encode(encoder)?;
        encoder.write_u32(self.max_count);
        Ok(())
    }
}

/// `LAYOUTGET` successful result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutGetResult {
    pub return_on_close: bool,
    pub stateid: StateId,
    pub layouts: Vec<Layout>,
}

/// File-specific `LAYOUTRETURN` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutReturnFile {
    pub offset: u64,
    pub length: u64,
    pub stateid: StateId,
    pub body: Vec<u8>,
}

impl Encode for LayoutReturnFile {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u64(self.offset);
        encoder.write_u64(self.length);
        self.stateid.encode(encoder)?;
        encoder.write_opaque(&self.body, NFS4_MAX_IO)
    }
}

/// `LAYOUTRETURN` selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutReturn {
    File(LayoutReturnFile),
    Fsid,
    All,
}

impl Encode for LayoutReturn {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        match self {
            Self::File(file) => {
                encoder.write_u32(LAYOUTRETURN4_FILE);
                file.encode(encoder)
            }
            Self::Fsid => {
                encoder.write_u32(LAYOUTRETURN4_FSID);
                Ok(())
            }
            Self::All => {
                encoder.write_u32(LAYOUTRETURN4_ALL);
                Ok(())
            }
        }
    }
}

/// `LAYOUTRETURN` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutReturnArgs {
    pub reclaim: bool,
    pub layout_type: LayoutType,
    pub iomode: LayoutIomode,
    pub layout_return: LayoutReturn,
}

impl Encode for LayoutReturnArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_bool(self.reclaim);
        self.layout_type.encode(encoder)?;
        self.iomode.encode(encoder)?;
        self.layout_return.encode(encoder)
    }
}

/// `LAYOUTRETURN` successful result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutReturnResult {
    pub stateid: Option<StateId>,
}

/// `SET_SSV` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetSsvArgs {
    pub ssv: Vec<u8>,
    pub digest: Vec<u8>,
}

impl Encode for SetSsvArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_opaque(&self.ssv, NFS4_OPAQUE_LIMIT)?;
        encoder.write_opaque(&self.digest, NFS4_OPAQUE_LIMIT)
    }
}

/// `SET_SSV` successful result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetSsvResult {
    pub digest: Vec<u8>,
}

/// `WANT_DELEGATION` claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationClaim {
    FileHandle,
    Previous(OpenDelegationType),
    DelegPrevFileHandle,
}

impl Encode for DelegationClaim {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        match self {
            Self::FileHandle => {
                encoder.write_u32(OpenClaimType::FileHandle.as_u32());
            }
            Self::Previous(delegation_type) => {
                encoder.write_u32(OpenClaimType::Previous.as_u32());
                encoder.write_u32(delegation_type.as_u32());
            }
            Self::DelegPrevFileHandle => {
                encoder.write_u32(OpenClaimType::DelegatePreviousFileHandle.as_u32());
            }
        }
        Ok(())
    }
}

/// `WANT_DELEGATION` arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WantDelegationArgs {
    pub want: u32,
    pub claim: DelegationClaim,
}

impl Encode for WantDelegationArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u32(self.want);
        self.claim.encode(encoder)
    }
}

/// pNFS device error entry used by `LAYOUTERROR`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceError {
    pub device_id: DeviceId,
    pub status: Status,
    pub opnum: OpCode,
}

impl Encode for DeviceError {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.device_id.encode(encoder)?;
        encoder.write_u32(self.status.as_u32());
        encoder.write_u32(self.opnum.as_u32());
        Ok(())
    }
}

/// `LAYOUTERROR` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutErrorArgs {
    pub offset: u64,
    pub length: u64,
    pub stateid: StateId,
    pub errors: Vec<DeviceError>,
}

impl Encode for LayoutErrorArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u64(self.offset);
        encoder.write_u64(self.length);
        self.stateid.encode(encoder)?;
        encoder.write_array(&self.errors, NFS4_MAX_LAYOUT_ERRORS)
    }
}

/// I/O counters reported by `LAYOUTSTATS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoInfo {
    pub count: u64,
    pub bytes: u64,
}

impl Encode for IoInfo {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u64(self.count);
        encoder.write_u64(self.bytes);
        Ok(())
    }
}

/// `LAYOUTSTATS` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutStatsArgs {
    pub offset: u64,
    pub length: u64,
    pub stateid: StateId,
    pub read: IoInfo,
    pub write: IoInfo,
    pub device_id: DeviceId,
    pub layout_update: LayoutUpdate,
}

impl Encode for LayoutStatsArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u64(self.offset);
        encoder.write_u64(self.length);
        self.stateid.encode(encoder)?;
        self.read.encode(encoder)?;
        self.write.encode(encoder)?;
        self.device_id.encode(encoder)?;
        self.layout_update.encode(encoder)
    }
}

/// Server location used by NFSv4.2 copy offload operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetLoc {
    Name(String),
    Url(String),
    NetAddr { netid: String, addr: String },
}

impl Encode for NetLoc {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        match self {
            Self::Name(name) => {
                encoder.write_u32(1);
                encoder.write_string(name, NFS4_OPAQUE_LIMIT)
            }
            Self::Url(url) => {
                encoder.write_u32(2);
                encoder.write_string(url, NFS4_OPAQUE_LIMIT)
            }
            Self::NetAddr { netid, addr } => {
                encoder.write_u32(3);
                encoder.write_string(netid, NFS4_OPAQUE_LIMIT)?;
                encoder.write_string(addr, NFS4_OPAQUE_LIMIT)
            }
        }
    }
}

impl Decode for NetLoc {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        match decoder.read_u32()? {
            1 => Ok(Self::Name(decoder.read_string(NFS4_OPAQUE_LIMIT)?)),
            2 => Ok(Self::Url(decoder.read_string(NFS4_OPAQUE_LIMIT)?)),
            3 => Ok(Self::NetAddr {
                netid: decoder.read_string(NFS4_OPAQUE_LIMIT)?,
                addr: decoder.read_string(NFS4_OPAQUE_LIMIT)?,
            }),
            value => Err(crate::xdr::Error::InvalidDiscriminant {
                type_name: "netloc_type4",
                value: value as i32,
            }),
        }
    }
}

/// Application data block used by `WRITE_SAME`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppDataBlock {
    pub offset: u64,
    pub block_size: u64,
    pub block_count: u64,
    pub block_number_offset: u64,
    pub block_number: u32,
    pub pattern_offset: u64,
    pub pattern: Vec<u8>,
}

impl Encode for AppDataBlock {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u64(self.offset);
        encoder.write_u64(self.block_size);
        encoder.write_u64(self.block_count);
        encoder.write_u64(self.block_number_offset);
        encoder.write_u32(self.block_number);
        encoder.write_u64(self.pattern_offset);
        encoder.write_opaque(&self.pattern, NFS4_MAX_IO)
    }
}

/// Shared write response used by `COPY` and `WRITE_SAME`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteResponse {
    pub callback_id: Option<StateId>,
    pub count: u64,
    pub committed: StableHow,
    pub verifier: Verifier,
}

impl Decode for WriteResponse {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        let callback_ids = decoder.read_array::<StateId>(1)?;
        let count = decoder.read_u64()?;
        let raw_committed = decoder.read_u32()?;
        let committed =
            StableHow::from_u32(raw_committed).ok_or(crate::xdr::Error::InvalidDiscriminant {
                type_name: "stable_how4",
                value: raw_committed as i32,
            })?;
        Ok(Self {
            callback_id: callback_ids.into_iter().next(),
            count,
            committed,
            verifier: decode_verifier(decoder)?,
        })
    }
}

/// COPY requirements returned by the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyRequirements {
    pub consecutive: bool,
    pub synchronous: bool,
}

impl Decode for CopyRequirements {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            consecutive: bool::decode(decoder)?,
            synchronous: bool::decode(decoder)?,
        })
    }
}

/// Arguments for the NFSv4.2 `COPY` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyArgs {
    pub src_stateid: StateId,
    pub dst_stateid: StateId,
    pub src_offset: u64,
    pub dst_offset: u64,
    pub count: u64,
    pub consecutive: bool,
    pub synchronous: bool,
    pub source_servers: Vec<NetLoc>,
}

impl Encode for CopyArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.src_stateid.encode(encoder)?;
        self.dst_stateid.encode(encoder)?;
        encoder.write_u64(self.src_offset);
        encoder.write_u64(self.dst_offset);
        encoder.write_u64(self.count);
        encoder.write_bool(self.consecutive);
        encoder.write_bool(self.synchronous);
        encoder.write_array(&self.source_servers, NFS4_MAX_NETLOCATIONS)
    }
}

/// Result of the NFSv4.2 `COPY` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyResult {
    pub response: Option<WriteResponse>,
    pub requirements: Option<CopyRequirements>,
}

/// Arguments for the NFSv4.2 `COPY_NOTIFY` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyNotifyArgs {
    pub src_stateid: StateId,
    pub destination_server: NetLoc,
}

impl Encode for CopyNotifyArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.src_stateid.encode(encoder)?;
        self.destination_server.encode(encoder)
    }
}

/// Result of the NFSv4.2 `COPY_NOTIFY` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyNotifyResult {
    pub lease_time: NfsTime,
    pub stateid: StateId,
    pub source_servers: Vec<NetLoc>,
}

/// Arguments for the NFSv4.2 `WRITE_SAME` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteSameArgs {
    pub stateid: StateId,
    pub stable: StableHow,
    pub block: AppDataBlock,
}

impl Encode for WriteSameArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.stateid.encode(encoder)?;
        encoder.write_u32(self.stable.as_u32());
        self.block.encode(encoder)
    }
}

/// Arguments for the NFSv4.2 `CLONE` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloneArgs {
    pub src_stateid: StateId,
    pub dst_stateid: StateId,
    pub src_offset: u64,
    pub dst_offset: u64,
    pub count: u64,
}

impl Encode for CloneArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.src_stateid.encode(encoder)?;
        self.dst_stateid.encode(encoder)?;
        encoder.write_u64(self.src_offset);
        encoder.write_u64(self.dst_offset);
        encoder.write_u64(self.count);
        Ok(())
    }
}

/// Object type for raw NFSv4 CREATE operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateKind {
    Directory,
    Symlink(String),
    BlockDevice { major: u32, minor: u32 },
    CharacterDevice { major: u32, minor: u32 },
    Socket,
    Fifo,
}

impl Encode for CreateKind {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        match self {
            Self::Directory => {
                encoder.write_u32(NF4DIR);
            }
            Self::Symlink(target) => {
                encoder.write_u32(NF4LNK);
                encoder.write_string(target, NFS4_OPAQUE_LIMIT)?;
            }
            Self::BlockDevice { major, minor } => {
                encoder.write_u32(NF4BLK);
                encoder.write_u32(*major);
                encoder.write_u32(*minor);
            }
            Self::CharacterDevice { major, minor } => {
                encoder.write_u32(NF4CHR);
                encoder.write_u32(*major);
                encoder.write_u32(*minor);
            }
            Self::Socket => {
                encoder.write_u32(NF4SOCK);
            }
            Self::Fifo => {
                encoder.write_u32(NF4FIFO);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateArgs {
    pub kind: CreateKind,
    pub name: String,
    pub attrs: Fattr,
}

impl Encode for CreateArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.kind.encode(encoder)?;
        encoder.write_string(&self.name, NFS4_OPAQUE_LIMIT)?;
        self.attrs.encode(encoder)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    SetClientId(SetClientIdArgs),
    SetClientIdConfirm(SetClientIdConfirmArgs),
    ExchangeId(ExchangeIdArgs),
    CreateSession(CreateSessionArgs),
    BackchannelCtl(BackchannelCtlArgs),
    BindConnToSession(BindConnToSessionArgs),
    DestroySession(SessionId),
    DestroyClientId(u64),
    ReclaimComplete {
        one_fs: bool,
    },
    Sequence(SequenceArgs),
    PutRootFh,
    PutPubFh,
    PutFh(FileHandle),
    Lookup(String),
    Lookupp,
    Access(u32),
    SecInfo(String),
    SecInfoNoName(SecInfoStyle),
    DelegPurge(u64),
    DelegReturn(StateId),
    NVerify(Fattr),
    Open(OpenArgs),
    OpenAttr {
        create_dir: bool,
    },
    OpenConfirm {
        stateid: StateId,
        seqid: u32,
    },
    Close {
        seqid: u32,
        stateid: StateId,
    },
    Lock(LockArgs),
    LockTest(LockTestArgs),
    LockUnlock(LockUnlockArgs),
    OpenDowngrade {
        seqid: u32,
        stateid: StateId,
        share_access: u32,
        share_deny: u32,
    },
    FreeStateId(StateId),
    TestStateIds(Vec<StateId>),
    GetDirDelegation(GetDirDelegationArgs),
    GetDeviceInfo(GetDeviceInfoArgs),
    GetDeviceList(GetDeviceListArgs),
    LayoutCommit(LayoutCommitArgs),
    LayoutGet(LayoutGetArgs),
    LayoutReturn(LayoutReturnArgs),
    SetSsv(SetSsvArgs),
    WantDelegation(WantDelegationArgs),
    GetFh,
    GetAttr(Bitmap),
    SetAttr {
        stateid: StateId,
        attrs: Fattr,
    },
    Read {
        stateid: StateId,
        offset: u64,
        count: u32,
    },
    Write {
        stateid: StateId,
        offset: u64,
        stable: StableHow,
        data: Vec<u8>,
    },
    Allocate {
        stateid: StateId,
        offset: u64,
        length: u64,
    },
    Deallocate {
        stateid: StateId,
        offset: u64,
        length: u64,
    },
    IoAdvise(IoAdviseArgs),
    Copy(CopyArgs),
    CopyNotify(CopyNotifyArgs),
    LayoutError(LayoutErrorArgs),
    LayoutStats(LayoutStatsArgs),
    OffloadCancel(StateId),
    OffloadStatus(StateId),
    ReadPlus(ReadPlusArgs),
    Seek {
        stateid: StateId,
        offset: u64,
        what: SeekContent,
    },
    Clone(CloneArgs),
    WriteSame(WriteSameArgs),
    Commit {
        offset: u64,
        count: u32,
    },
    Renew(u64),
    ReadDir {
        cookie: u64,
        cookieverf: Verifier,
        dircount: u32,
        maxcount: u32,
        attr_request: Bitmap,
    },
    ReadLink,
    Remove(String),
    Link(String),
    Rename {
        oldname: String,
        newname: String,
    },
    Verify(Fattr),
    ReleaseLockOwner(LockOwner),
    Create(CreateArgs),
    SaveFh,
    RestoreFh,
}

impl Operation {
    pub fn op_code(&self) -> OpCode {
        match self {
            Self::SetClientId(_) => OpCode::SetClientId,
            Self::SetClientIdConfirm(_) => OpCode::SetClientIdConfirm,
            Self::ExchangeId(_) => OpCode::ExchangeId,
            Self::CreateSession(_) => OpCode::CreateSession,
            Self::BackchannelCtl(_) => OpCode::BackchannelCtl,
            Self::BindConnToSession(_) => OpCode::BindConnToSession,
            Self::DestroySession(_) => OpCode::DestroySession,
            Self::DestroyClientId(_) => OpCode::DestroyClientId,
            Self::ReclaimComplete { .. } => OpCode::ReclaimComplete,
            Self::Sequence(_) => OpCode::Sequence,
            Self::PutRootFh => OpCode::PutRootFh,
            Self::PutPubFh => OpCode::PutPubFh,
            Self::PutFh(_) => OpCode::PutFh,
            Self::Lookup(_) => OpCode::Lookup,
            Self::Lookupp => OpCode::Lookupp,
            Self::Access(_) => OpCode::Access,
            Self::SecInfo(_) => OpCode::SecInfo,
            Self::SecInfoNoName(_) => OpCode::SecInfoNoName,
            Self::DelegPurge(_) => OpCode::DelegPurge,
            Self::DelegReturn(_) => OpCode::DelegReturn,
            Self::NVerify(_) => OpCode::NVerify,
            Self::Open(_) => OpCode::Open,
            Self::OpenAttr { .. } => OpCode::OpenAttr,
            Self::OpenConfirm { .. } => OpCode::OpenConfirm,
            Self::Close { .. } => OpCode::Close,
            Self::Lock(_) => OpCode::Lock,
            Self::LockTest(_) => OpCode::Lockt,
            Self::LockUnlock(_) => OpCode::Locku,
            Self::OpenDowngrade { .. } => OpCode::OpenDowngrade,
            Self::FreeStateId(_) => OpCode::FreeStateId,
            Self::TestStateIds(_) => OpCode::TestStateId,
            Self::GetDirDelegation(_) => OpCode::GetDirDelegation,
            Self::GetDeviceInfo(_) => OpCode::GetDeviceInfo,
            Self::GetDeviceList(_) => OpCode::GetDeviceList,
            Self::LayoutCommit(_) => OpCode::LayoutCommit,
            Self::LayoutGet(_) => OpCode::LayoutGet,
            Self::LayoutReturn(_) => OpCode::LayoutReturn,
            Self::SetSsv(_) => OpCode::SetSsv,
            Self::WantDelegation(_) => OpCode::WantDelegation,
            Self::GetFh => OpCode::GetFh,
            Self::GetAttr(_) => OpCode::GetAttr,
            Self::SetAttr { .. } => OpCode::SetAttr,
            Self::Read { .. } => OpCode::Read,
            Self::Write { .. } => OpCode::Write,
            Self::Allocate { .. } => OpCode::Allocate,
            Self::Deallocate { .. } => OpCode::Deallocate,
            Self::IoAdvise(_) => OpCode::IoAdvise,
            Self::Copy(_) => OpCode::Copy,
            Self::CopyNotify(_) => OpCode::CopyNotify,
            Self::LayoutError(_) => OpCode::LayoutError,
            Self::LayoutStats(_) => OpCode::LayoutStats,
            Self::OffloadCancel(_) => OpCode::OffloadCancel,
            Self::OffloadStatus(_) => OpCode::OffloadStatus,
            Self::ReadPlus(_) => OpCode::ReadPlus,
            Self::Seek { .. } => OpCode::Seek,
            Self::Clone(_) => OpCode::Clone,
            Self::WriteSame(_) => OpCode::WriteSame,
            Self::Commit { .. } => OpCode::Commit,
            Self::Renew(_) => OpCode::Renew,
            Self::ReadDir { .. } => OpCode::ReadDir,
            Self::ReadLink => OpCode::ReadLink,
            Self::Remove(_) => OpCode::Remove,
            Self::Link(_) => OpCode::Link,
            Self::Rename { .. } => OpCode::Rename,
            Self::Verify(_) => OpCode::Verify,
            Self::ReleaseLockOwner(_) => OpCode::ReleaseLockOwner,
            Self::Create(_) => OpCode::Create,
            Self::SaveFh => OpCode::SaveFh,
            Self::RestoreFh => OpCode::RestoreFh,
        }
    }
}

impl Encode for Operation {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u32(self.op_code().as_u32());
        match self {
            Self::SetClientId(args) => args.encode(encoder),
            Self::SetClientIdConfirm(args) => args.encode(encoder),
            Self::ExchangeId(args) => args.encode(encoder),
            Self::CreateSession(args) => args.encode(encoder),
            Self::BackchannelCtl(args) => args.encode(encoder),
            Self::BindConnToSession(args) => args.encode(encoder),
            Self::DestroySession(session_id) => {
                encoder.write_fixed_opaque(session_id);
                Ok(())
            }
            Self::DestroyClientId(client_id) => {
                encoder.write_u64(*client_id);
                Ok(())
            }
            Self::ReclaimComplete { one_fs } => {
                encoder.write_bool(*one_fs);
                Ok(())
            }
            Self::Sequence(args) => args.encode(encoder),
            Self::PutRootFh
            | Self::PutPubFh
            | Self::Lookupp
            | Self::GetFh
            | Self::ReadLink
            | Self::SaveFh
            | Self::RestoreFh => Ok(()),
            Self::PutFh(handle) => handle.encode(encoder),
            Self::Lookup(component) => encoder.write_string(component, NFS4_OPAQUE_LIMIT),
            Self::Access(access) => {
                encoder.write_u32(*access);
                Ok(())
            }
            Self::SecInfo(name) => encoder.write_string(name, NFS4_OPAQUE_LIMIT),
            Self::SecInfoNoName(style) => {
                encoder.write_u32(style.as_u32());
                Ok(())
            }
            Self::DelegPurge(client_id) => {
                encoder.write_u64(*client_id);
                Ok(())
            }
            Self::DelegReturn(stateid) => stateid.encode(encoder),
            Self::NVerify(attrs) => attrs.encode(encoder),
            Self::Open(args) => args.encode(encoder),
            Self::OpenAttr { create_dir } => {
                encoder.write_bool(*create_dir);
                Ok(())
            }
            Self::OpenConfirm { stateid, seqid } => {
                stateid.encode(encoder)?;
                encoder.write_u32(*seqid);
                Ok(())
            }
            Self::Close { seqid, stateid } => {
                encoder.write_u32(*seqid);
                stateid.encode(encoder)
            }
            Self::Lock(args) => args.encode(encoder),
            Self::LockTest(args) => args.encode(encoder),
            Self::LockUnlock(args) => args.encode(encoder),
            Self::OpenDowngrade {
                seqid,
                stateid,
                share_access,
                share_deny,
            } => {
                stateid.encode(encoder)?;
                encoder.write_u32(*seqid);
                encoder.write_u32(*share_access);
                encoder.write_u32(*share_deny);
                Ok(())
            }
            Self::FreeStateId(stateid) => stateid.encode(encoder),
            Self::TestStateIds(stateids) => encoder.write_array(stateids, NFS4_MAX_OPS),
            Self::GetDirDelegation(args) => args.encode(encoder),
            Self::GetDeviceInfo(args) => args.encode(encoder),
            Self::GetDeviceList(args) => args.encode(encoder),
            Self::LayoutCommit(args) => args.encode(encoder),
            Self::LayoutGet(args) => args.encode(encoder),
            Self::LayoutReturn(args) => args.encode(encoder),
            Self::SetSsv(args) => args.encode(encoder),
            Self::WantDelegation(args) => args.encode(encoder),
            Self::GetAttr(bitmap) => bitmap.encode(encoder),
            Self::SetAttr { stateid, attrs } => {
                stateid.encode(encoder)?;
                attrs.encode(encoder)
            }
            Self::Read {
                stateid,
                offset,
                count,
            } => {
                stateid.encode(encoder)?;
                encoder.write_u64(*offset);
                encoder.write_u32(*count);
                Ok(())
            }
            Self::Write {
                stateid,
                offset,
                stable,
                data,
            } => {
                stateid.encode(encoder)?;
                encoder.write_u64(*offset);
                encoder.write_u32(stable.as_u32());
                encoder.write_opaque(data, NFS4_MAX_IO)
            }
            Self::Allocate {
                stateid,
                offset,
                length,
            }
            | Self::Deallocate {
                stateid,
                offset,
                length,
            } => {
                stateid.encode(encoder)?;
                encoder.write_u64(*offset);
                encoder.write_u64(*length);
                Ok(())
            }
            Self::IoAdvise(args) => args.encode(encoder),
            Self::Copy(args) => args.encode(encoder),
            Self::CopyNotify(args) => args.encode(encoder),
            Self::LayoutError(args) => args.encode(encoder),
            Self::LayoutStats(args) => args.encode(encoder),
            Self::OffloadCancel(stateid) | Self::OffloadStatus(stateid) => stateid.encode(encoder),
            Self::ReadPlus(args) => args.encode(encoder),
            Self::Seek {
                stateid,
                offset,
                what,
            } => {
                stateid.encode(encoder)?;
                encoder.write_u64(*offset);
                encoder.write_u32(what.as_u32());
                Ok(())
            }
            Self::Clone(args) => args.encode(encoder),
            Self::WriteSame(args) => args.encode(encoder),
            Self::Commit { offset, count } => {
                encoder.write_u64(*offset);
                encoder.write_u32(*count);
                Ok(())
            }
            Self::Renew(client_id) => {
                encoder.write_u64(*client_id);
                Ok(())
            }
            Self::ReadDir {
                cookie,
                cookieverf,
                dircount,
                maxcount,
                attr_request,
            } => {
                encoder.write_u64(*cookie);
                encoder.write_fixed_opaque(cookieverf);
                encoder.write_u32(*dircount);
                encoder.write_u32(*maxcount);
                attr_request.encode(encoder)
            }
            Self::Remove(target) => encoder.write_string(target, NFS4_OPAQUE_LIMIT),
            Self::Link(target) => encoder.write_string(target, NFS4_OPAQUE_LIMIT),
            Self::Rename { oldname, newname } => {
                encoder.write_string(oldname, NFS4_OPAQUE_LIMIT)?;
                encoder.write_string(newname, NFS4_OPAQUE_LIMIT)
            }
            Self::Verify(attrs) => attrs.encode(encoder),
            Self::ReleaseLockOwner(owner) => owner.encode(encoder),
            Self::Create(args) => args.encode(encoder),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompoundArgs {
    pub tag: String,
    pub minor_version: u32,
    pub operations: Vec<Operation>,
}

impl Encode for CompoundArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_string(&self.tag, NFS4_OPAQUE_LIMIT)?;
        encoder.write_u32(self.minor_version);
        encoder.write_array(&self.operations, NFS4_MAX_OPS)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompoundResponse {
    pub status: Status,
    pub tag: String,
    pub results: Vec<OperationResult>,
}

impl Decode for CompoundResponse {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            status: Status::from_u32(decoder.read_u32()?),
            tag: decoder.read_string(NFS4_OPAQUE_LIMIT)?,
            results: decoder.read_array::<OperationResult>(NFS4_MAX_OPS)?,
        })
    }
}

impl CompoundResponse {
    pub fn ensure_ok(&self) -> Result<()> {
        if self.status.is_ok() {
            Ok(())
        } else if let Some(result) = self.results.last() {
            Err(Error::nfsv4(result.op_name(), result.status()))
        } else {
            Err(Error::nfsv4("COMPOUND", self.status))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationResult {
    SetClientId {
        status: Status,
        result: Option<SetClientIdResult>,
        client_using: Option<NetAddr>,
    },
    ExchangeId {
        status: Status,
        result: Option<ExchangeIdResult>,
    },
    CreateSession {
        status: Status,
        result: Option<CreateSessionResult>,
    },
    BindConnToSession {
        status: Status,
        result: Option<BindConnToSessionResult>,
    },
    Sequence {
        status: Status,
        result: Option<SequenceResult>,
    },
    StatusOnly {
        op: OpCode,
        status: Status,
    },
    Open {
        status: Status,
        result: Option<OpenResult>,
    },
    OpenConfirm {
        status: Status,
        stateid: Option<StateId>,
    },
    Close {
        status: Status,
        stateid: Option<StateId>,
    },
    Lock {
        status: Status,
        stateid: Option<StateId>,
        denied: Option<LockDenied>,
    },
    LockTest {
        status: Status,
        denied: Option<LockDenied>,
    },
    LockUnlock {
        status: Status,
        stateid: Option<StateId>,
    },
    OpenDowngrade {
        status: Status,
        stateid: Option<StateId>,
    },
    TestStateIds {
        status: Status,
        statuses: Vec<Status>,
    },
    GetDirDelegation {
        status: Status,
        result: Option<GetDirDelegationResult>,
    },
    GetDeviceInfo {
        status: Status,
        result: Option<GetDeviceInfoResult>,
        min_count: Option<u32>,
    },
    GetDeviceList {
        status: Status,
        result: Option<GetDeviceListResult>,
    },
    LayoutCommit {
        status: Status,
        result: Option<LayoutCommitResult>,
    },
    LayoutGet {
        status: Status,
        result: Option<LayoutGetResult>,
        will_signal_layout_avail: Option<bool>,
    },
    LayoutReturn {
        status: Status,
        result: Option<LayoutReturnResult>,
    },
    SetSsv {
        status: Status,
        result: Option<SetSsvResult>,
    },
    WantDelegation {
        status: Status,
        delegation: Option<OpenDelegation>,
    },
    GetFh {
        status: Status,
        handle: Option<FileHandle>,
    },
    GetAttr {
        status: Status,
        attrs: Option<Fattr>,
    },
    Access {
        status: Status,
        result: Option<AccessResult>,
    },
    SecInfo {
        op: OpCode,
        status: Status,
        flavors: Vec<SecInfo>,
    },
    Read {
        status: Status,
        eof: bool,
        data: Vec<u8>,
    },
    Write {
        status: Status,
        result: Option<WriteResult>,
    },
    Commit {
        status: Status,
        result: Option<CommitResult>,
    },
    IoAdvise {
        status: Status,
        result: Option<IoAdviseResult>,
    },
    Copy {
        status: Status,
        result: Option<CopyResult>,
    },
    CopyNotify {
        status: Status,
        result: Option<CopyNotifyResult>,
    },
    OffloadStatus {
        status: Status,
        result: Option<OffloadStatusResult>,
    },
    ReadPlus {
        status: Status,
        result: Option<ReadPlusResult>,
    },
    Seek {
        status: Status,
        result: Option<SeekResult>,
    },
    WriteSame {
        status: Status,
        result: Option<WriteResponse>,
    },
    ReadDir {
        status: Status,
        cookieverf: Verifier,
        entries: Vec<DirEntry>,
        eof: bool,
    },
    ReadLink {
        status: Status,
        data: Option<String>,
    },
}

impl OperationResult {
    pub fn op_code(&self) -> OpCode {
        match self {
            Self::SetClientId { .. } => OpCode::SetClientId,
            Self::ExchangeId { .. } => OpCode::ExchangeId,
            Self::CreateSession { .. } => OpCode::CreateSession,
            Self::BindConnToSession { .. } => OpCode::BindConnToSession,
            Self::Sequence { .. } => OpCode::Sequence,
            Self::StatusOnly { op, .. } => *op,
            Self::Open { .. } => OpCode::Open,
            Self::OpenConfirm { .. } => OpCode::OpenConfirm,
            Self::Close { .. } => OpCode::Close,
            Self::Lock { .. } => OpCode::Lock,
            Self::LockTest { .. } => OpCode::Lockt,
            Self::LockUnlock { .. } => OpCode::Locku,
            Self::OpenDowngrade { .. } => OpCode::OpenDowngrade,
            Self::TestStateIds { .. } => OpCode::TestStateId,
            Self::GetDirDelegation { .. } => OpCode::GetDirDelegation,
            Self::GetDeviceInfo { .. } => OpCode::GetDeviceInfo,
            Self::GetDeviceList { .. } => OpCode::GetDeviceList,
            Self::LayoutCommit { .. } => OpCode::LayoutCommit,
            Self::LayoutGet { .. } => OpCode::LayoutGet,
            Self::LayoutReturn { .. } => OpCode::LayoutReturn,
            Self::SetSsv { .. } => OpCode::SetSsv,
            Self::WantDelegation { .. } => OpCode::WantDelegation,
            Self::GetFh { .. } => OpCode::GetFh,
            Self::GetAttr { .. } => OpCode::GetAttr,
            Self::Access { .. } => OpCode::Access,
            Self::SecInfo { op, .. } => *op,
            Self::Read { .. } => OpCode::Read,
            Self::Write { .. } => OpCode::Write,
            Self::Commit { .. } => OpCode::Commit,
            Self::IoAdvise { .. } => OpCode::IoAdvise,
            Self::Copy { .. } => OpCode::Copy,
            Self::CopyNotify { .. } => OpCode::CopyNotify,
            Self::OffloadStatus { .. } => OpCode::OffloadStatus,
            Self::ReadPlus { .. } => OpCode::ReadPlus,
            Self::Seek { .. } => OpCode::Seek,
            Self::WriteSame { .. } => OpCode::WriteSame,
            Self::ReadDir { .. } => OpCode::ReadDir,
            Self::ReadLink { .. } => OpCode::ReadLink,
        }
    }

    pub fn op_name(&self) -> &'static str {
        self.op_code().name()
    }

    pub fn status(&self) -> Status {
        match self {
            Self::SetClientId { status, .. }
            | Self::ExchangeId { status, .. }
            | Self::CreateSession { status, .. }
            | Self::BindConnToSession { status, .. }
            | Self::Sequence { status, .. }
            | Self::StatusOnly { status, .. }
            | Self::Open { status, .. }
            | Self::OpenConfirm { status, .. }
            | Self::Close { status, .. }
            | Self::Lock { status, .. }
            | Self::LockTest { status, .. }
            | Self::LockUnlock { status, .. }
            | Self::OpenDowngrade { status, .. }
            | Self::TestStateIds { status, .. }
            | Self::GetDirDelegation { status, .. }
            | Self::GetDeviceInfo { status, .. }
            | Self::GetDeviceList { status, .. }
            | Self::LayoutCommit { status, .. }
            | Self::LayoutGet { status, .. }
            | Self::LayoutReturn { status, .. }
            | Self::SetSsv { status, .. }
            | Self::WantDelegation { status, .. }
            | Self::GetFh { status, .. }
            | Self::GetAttr { status, .. }
            | Self::Access { status, .. }
            | Self::SecInfo { status, .. }
            | Self::Read { status, .. }
            | Self::Write { status, .. }
            | Self::Commit { status, .. }
            | Self::IoAdvise { status, .. }
            | Self::Copy { status, .. }
            | Self::CopyNotify { status, .. }
            | Self::OffloadStatus { status, .. }
            | Self::ReadPlus { status, .. }
            | Self::Seek { status, .. }
            | Self::WriteSame { status, .. }
            | Self::ReadDir { status, .. }
            | Self::ReadLink { status, .. } => *status,
        }
    }
}

impl Decode for OperationResult {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        let raw_op = decoder.read_u32()?;
        let op = OpCode::from_u32(raw_op).unwrap_or(OpCode::Illegal);
        let status = Status::from_u32(decoder.read_u32()?);

        match op {
            OpCode::SetClientId => decode_set_client_id_result(decoder, status),
            OpCode::ExchangeId => decode_exchange_id_result(decoder, status),
            OpCode::CreateSession => decode_create_session_result(decoder, status),
            OpCode::BindConnToSession => decode_bind_conn_to_session_result(decoder, status),
            OpCode::Sequence => decode_sequence_result(decoder, status),
            OpCode::Open => decode_open_result(decoder, status),
            OpCode::OpenConfirm => {
                let stateid = if status.is_ok() {
                    Some(StateId::decode(decoder)?)
                } else {
                    None
                };
                Ok(Self::OpenConfirm { status, stateid })
            }
            OpCode::Close => {
                let stateid = if status.is_ok() {
                    Some(StateId::decode(decoder)?)
                } else {
                    None
                };
                Ok(Self::Close { status, stateid })
            }
            OpCode::Lock => {
                let (stateid, denied) = match status {
                    Status::Ok => (Some(StateId::decode(decoder)?), None),
                    Status::Denied => (None, Some(LockDenied::decode(decoder)?)),
                    _ => (None, None),
                };
                Ok(Self::Lock {
                    status,
                    stateid,
                    denied,
                })
            }
            OpCode::Lockt => {
                let denied = if status == Status::Denied {
                    Some(LockDenied::decode(decoder)?)
                } else {
                    None
                };
                Ok(Self::LockTest { status, denied })
            }
            OpCode::Locku => {
                let stateid = if status.is_ok() {
                    Some(StateId::decode(decoder)?)
                } else {
                    None
                };
                Ok(Self::LockUnlock { status, stateid })
            }
            OpCode::OpenDowngrade => {
                let stateid = if status.is_ok() {
                    Some(StateId::decode(decoder)?)
                } else {
                    None
                };
                Ok(Self::OpenDowngrade { status, stateid })
            }
            OpCode::TestStateId => {
                let statuses = if status.is_ok() {
                    decoder
                        .read_array::<u32>(NFS4_MAX_OPS)?
                        .into_iter()
                        .map(Status::from_u32)
                        .collect()
                } else {
                    Vec::new()
                };
                Ok(Self::TestStateIds { status, statuses })
            }
            OpCode::GetDirDelegation => decode_get_dir_delegation_result(decoder, status),
            OpCode::GetDeviceInfo => decode_get_device_info_result(decoder, status),
            OpCode::GetDeviceList => decode_get_device_list_result(decoder, status),
            OpCode::LayoutCommit => decode_layout_commit_result(decoder, status),
            OpCode::LayoutGet => decode_layout_get_result(decoder, status),
            OpCode::LayoutReturn => decode_layout_return_result(decoder, status),
            OpCode::SetSsv => {
                let result = if status.is_ok() {
                    Some(SetSsvResult {
                        digest: decoder.read_opaque_vec(NFS4_OPAQUE_LIMIT)?,
                    })
                } else {
                    None
                };
                Ok(Self::SetSsv { status, result })
            }
            OpCode::WantDelegation => {
                let delegation = if status.is_ok() {
                    Some(OpenDelegation::decode(decoder)?)
                } else {
                    None
                };
                Ok(Self::WantDelegation { status, delegation })
            }
            OpCode::GetFh => {
                let handle = if status.is_ok() {
                    Some(FileHandle::decode(decoder)?)
                } else {
                    None
                };
                Ok(Self::GetFh { status, handle })
            }
            OpCode::GetAttr => {
                let attrs = if status.is_ok() {
                    Some(Fattr::decode(decoder)?)
                } else {
                    None
                };
                Ok(Self::GetAttr { status, attrs })
            }
            OpCode::Access => {
                let result = if status.is_ok() {
                    Some(AccessResult {
                        supported: decoder.read_u32()?,
                        access: decoder.read_u32()?,
                    })
                } else {
                    None
                };
                Ok(Self::Access { status, result })
            }
            OpCode::SecInfo | OpCode::SecInfoNoName => {
                let flavors = if status.is_ok() {
                    decoder.read_array::<SecInfo>(NFS4_MAX_SECINFO_FLAVORS)?
                } else {
                    Vec::new()
                };
                Ok(Self::SecInfo {
                    op,
                    status,
                    flavors,
                })
            }
            OpCode::Read => {
                if status.is_ok() {
                    Ok(Self::Read {
                        status,
                        eof: bool::decode(decoder)?,
                        data: decoder.read_opaque_vec(NFS4_MAX_IO)?,
                    })
                } else {
                    Ok(Self::Read {
                        status,
                        eof: false,
                        data: Vec::new(),
                    })
                }
            }
            OpCode::Write => {
                let result = if status.is_ok() {
                    let count = decoder.read_u32()?;
                    let raw_committed = decoder.read_u32()?;
                    let committed = StableHow::from_u32(raw_committed).ok_or(
                        crate::xdr::Error::InvalidDiscriminant {
                            type_name: "stable_how4",
                            value: raw_committed as i32,
                        },
                    )?;
                    Some(WriteResult {
                        count,
                        committed,
                        verifier: decode_verifier(decoder)?,
                    })
                } else {
                    None
                };
                Ok(Self::Write { status, result })
            }
            OpCode::Commit => {
                let result = if status.is_ok() {
                    Some(CommitResult {
                        verifier: decode_verifier(decoder)?,
                    })
                } else {
                    None
                };
                Ok(Self::Commit { status, result })
            }
            OpCode::IoAdvise => {
                let result = if status.is_ok() {
                    Some(IoAdviseResult {
                        hints: Bitmap::decode(decoder)?,
                    })
                } else {
                    None
                };
                Ok(Self::IoAdvise { status, result })
            }
            OpCode::Copy => {
                let result = match status {
                    Status::Ok => Some(CopyResult {
                        response: Some(WriteResponse::decode(decoder)?),
                        requirements: Some(CopyRequirements::decode(decoder)?),
                    }),
                    Status::OffloadNoReqs => Some(CopyResult {
                        response: None,
                        requirements: Some(CopyRequirements::decode(decoder)?),
                    }),
                    _ => None,
                };
                Ok(Self::Copy { status, result })
            }
            OpCode::CopyNotify => {
                let result = if status.is_ok() {
                    Some(CopyNotifyResult {
                        lease_time: NfsTime::decode(decoder)?,
                        stateid: StateId::decode(decoder)?,
                        source_servers: decoder.read_array::<NetLoc>(NFS4_MAX_NETLOCATIONS)?,
                    })
                } else {
                    None
                };
                Ok(Self::CopyNotify { status, result })
            }
            OpCode::OffloadStatus => {
                let result = if status.is_ok() {
                    let count = decoder.read_u64()?;
                    let complete = decoder
                        .read_array::<u32>(1)?
                        .into_iter()
                        .next()
                        .map(Status::from_u32);
                    Some(OffloadStatusResult { count, complete })
                } else {
                    None
                };
                Ok(Self::OffloadStatus { status, result })
            }
            OpCode::ReadPlus => {
                let result = if status.is_ok() {
                    Some(ReadPlusResult {
                        eof: bool::decode(decoder)?,
                        contents: decoder
                            .read_array::<ReadPlusContent>(NFS4_MAX_READ_PLUS_SEGMENTS)?,
                    })
                } else {
                    None
                };
                Ok(Self::ReadPlus { status, result })
            }
            OpCode::Seek => {
                let result = if status.is_ok() {
                    Some(SeekResult {
                        eof: bool::decode(decoder)?,
                        offset: decoder.read_u64()?,
                    })
                } else {
                    None
                };
                Ok(Self::Seek { status, result })
            }
            OpCode::WriteSame => {
                let result = if status.is_ok() {
                    Some(WriteResponse::decode(decoder)?)
                } else {
                    None
                };
                Ok(Self::WriteSame { status, result })
            }
            OpCode::SetAttr => {
                if status.is_ok() {
                    Bitmap::decode(decoder)?;
                }
                Ok(Self::StatusOnly { op, status })
            }
            OpCode::Remove => {
                if status.is_ok() {
                    skip_change_info(decoder)?;
                }
                Ok(Self::StatusOnly { op, status })
            }
            OpCode::Link => {
                if status.is_ok() {
                    skip_change_info(decoder)?;
                }
                Ok(Self::StatusOnly { op, status })
            }
            OpCode::Rename => {
                if status.is_ok() {
                    skip_change_info(decoder)?;
                    skip_change_info(decoder)?;
                }
                Ok(Self::StatusOnly { op, status })
            }
            OpCode::Create => {
                if status.is_ok() {
                    skip_change_info(decoder)?;
                    Bitmap::decode(decoder)?;
                }
                Ok(Self::StatusOnly { op, status })
            }
            OpCode::ReadDir => decode_readdir_result(decoder, status),
            OpCode::ReadLink => {
                let data = if status.is_ok() {
                    Some(decoder.read_string(NFS4_OPAQUE_LIMIT)?)
                } else {
                    None
                };
                Ok(Self::ReadLink { status, data })
            }
            _ => Ok(Self::StatusOnly { op, status }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub cookie: u64,
    pub name: String,
    pub attrs: Fattr,
}

impl DirEntry {
    pub fn basic_attributes(&self) -> Result<BasicAttributes> {
        self.attrs.parse_basic()
    }
}

fn decode_set_client_id_result(
    decoder: &mut Decoder<'_>,
    status: Status,
) -> crate::xdr::Result<OperationResult> {
    match status {
        Status::Ok => Ok(OperationResult::SetClientId {
            status,
            result: Some(SetClientIdResult {
                client_id: decoder.read_u64()?,
                verifier: decode_verifier(decoder)?,
            }),
            client_using: None,
        }),
        Status::ClidInUse => Ok(OperationResult::SetClientId {
            status,
            result: None,
            client_using: Some(NetAddr::decode(decoder)?),
        }),
        _ => Ok(OperationResult::SetClientId {
            status,
            result: None,
            client_using: None,
        }),
    }
}

fn decode_exchange_id_result(
    decoder: &mut Decoder<'_>,
    status: Status,
) -> crate::xdr::Result<OperationResult> {
    if !status.is_ok() {
        return Ok(OperationResult::ExchangeId {
            status,
            result: None,
        });
    }

    let result = ExchangeIdResult {
        client_id: decoder.read_u64()?,
        sequence_id: decoder.read_u32()?,
        flags: decoder.read_u32()?,
    };
    skip_state_protect_reply(decoder)?;
    skip_server_owner(decoder)?;
    decoder.read_opaque(NFS4_OPAQUE_LIMIT)?;
    skip_impl_ids(decoder)?;
    Ok(OperationResult::ExchangeId {
        status,
        result: Some(result),
    })
}

fn decode_create_session_result(
    decoder: &mut Decoder<'_>,
    status: Status,
) -> crate::xdr::Result<OperationResult> {
    if !status.is_ok() {
        return Ok(OperationResult::CreateSession {
            status,
            result: None,
        });
    }

    let result = CreateSessionResult {
        session_id: decode_session_id(decoder)?,
        sequence_id: decoder.read_u32()?,
        flags: decoder.read_u32()?,
        fore_channel_attrs: ChannelAttrs::decode(decoder)?,
        back_channel_attrs: ChannelAttrs::decode(decoder)?,
    };
    Ok(OperationResult::CreateSession {
        status,
        result: Some(result),
    })
}

fn decode_bind_conn_to_session_result(
    decoder: &mut Decoder<'_>,
    status: Status,
) -> crate::xdr::Result<OperationResult> {
    if !status.is_ok() {
        return Ok(OperationResult::BindConnToSession {
            status,
            result: None,
        });
    }

    let session_id = decode_session_id(decoder)?;
    let raw_direction = decoder.read_u32()?;
    let direction = ChannelDirFromServer::from_u32(raw_direction).ok_or(
        crate::xdr::Error::InvalidDiscriminant {
            type_name: "channel_dir_from_server4",
            value: raw_direction as i32,
        },
    )?;
    let result = BindConnToSessionResult {
        session_id,
        direction,
        use_conn_in_rdma_mode: bool::decode(decoder)?,
    };
    Ok(OperationResult::BindConnToSession {
        status,
        result: Some(result),
    })
}

fn decode_sequence_result(
    decoder: &mut Decoder<'_>,
    status: Status,
) -> crate::xdr::Result<OperationResult> {
    let result = if status.is_ok() {
        Some(SequenceResult {
            session_id: decode_session_id(decoder)?,
            sequence_id: decoder.read_u32()?,
            slot_id: decoder.read_u32()?,
            highest_slot_id: decoder.read_u32()?,
            target_highest_slot_id: decoder.read_u32()?,
            status_flags: decoder.read_u32()?,
        })
    } else {
        None
    };
    Ok(OperationResult::Sequence { status, result })
}

fn decode_get_dir_delegation_result(
    decoder: &mut Decoder<'_>,
    status: Status,
) -> crate::xdr::Result<OperationResult> {
    let result = if status.is_ok() {
        match decoder.read_u32()? {
            GDD4_OK => Some(GetDirDelegationResult::Granted {
                cookieverf: decode_verifier(decoder)?,
                stateid: StateId::decode(decoder)?,
                notification: Bitmap::decode(decoder)?,
                child_attributes: Bitmap::decode(decoder)?,
                dir_attributes: Bitmap::decode(decoder)?,
            }),
            GDD4_UNAVAIL => Some(GetDirDelegationResult::Unavailable {
                will_signal_deleg_avail: bool::decode(decoder)?,
            }),
            value => {
                return Err(crate::xdr::Error::InvalidDiscriminant {
                    type_name: "gddrnf4_status",
                    value: value as i32,
                });
            }
        }
    } else {
        None
    };
    Ok(OperationResult::GetDirDelegation { status, result })
}

fn decode_get_device_info_result(
    decoder: &mut Decoder<'_>,
    status: Status,
) -> crate::xdr::Result<OperationResult> {
    match status {
        Status::Ok => Ok(OperationResult::GetDeviceInfo {
            status,
            result: Some(GetDeviceInfoResult {
                device_addr: DeviceAddr::decode(decoder)?,
                notification: Bitmap::decode(decoder)?,
            }),
            min_count: None,
        }),
        Status::TooSmall => Ok(OperationResult::GetDeviceInfo {
            status,
            result: None,
            min_count: Some(decoder.read_u32()?),
        }),
        _ => Ok(OperationResult::GetDeviceInfo {
            status,
            result: None,
            min_count: None,
        }),
    }
}

fn decode_get_device_list_result(
    decoder: &mut Decoder<'_>,
    status: Status,
) -> crate::xdr::Result<OperationResult> {
    let result = if status.is_ok() {
        Some(GetDeviceListResult {
            cookie: decoder.read_u64()?,
            cookieverf: decode_verifier(decoder)?,
            device_ids: decoder.read_array::<DeviceId>(NFS4_MAX_DEVICEIDS)?,
            eof: bool::decode(decoder)?,
        })
    } else {
        None
    };
    Ok(OperationResult::GetDeviceList { status, result })
}

fn decode_layout_commit_result(
    decoder: &mut Decoder<'_>,
    status: Status,
) -> crate::xdr::Result<OperationResult> {
    let result = if status.is_ok() {
        Some(LayoutCommitResult {
            new_size: decoder.read_optional::<u64>()?,
        })
    } else {
        None
    };
    Ok(OperationResult::LayoutCommit { status, result })
}

fn decode_layout_get_result(
    decoder: &mut Decoder<'_>,
    status: Status,
) -> crate::xdr::Result<OperationResult> {
    match status {
        Status::Ok => Ok(OperationResult::LayoutGet {
            status,
            result: Some(LayoutGetResult {
                return_on_close: bool::decode(decoder)?,
                stateid: StateId::decode(decoder)?,
                layouts: decoder.read_array::<Layout>(NFS4_MAX_LAYOUTS)?,
            }),
            will_signal_layout_avail: None,
        }),
        Status::LayoutTryLater => Ok(OperationResult::LayoutGet {
            status,
            result: None,
            will_signal_layout_avail: Some(bool::decode(decoder)?),
        }),
        _ => Ok(OperationResult::LayoutGet {
            status,
            result: None,
            will_signal_layout_avail: None,
        }),
    }
}

fn decode_layout_return_result(
    decoder: &mut Decoder<'_>,
    status: Status,
) -> crate::xdr::Result<OperationResult> {
    let result = if status.is_ok() {
        Some(LayoutReturnResult {
            stateid: decoder.read_optional::<StateId>()?,
        })
    } else {
        None
    };
    Ok(OperationResult::LayoutReturn { status, result })
}

fn decode_open_result(
    decoder: &mut Decoder<'_>,
    status: Status,
) -> crate::xdr::Result<OperationResult> {
    if !status.is_ok() {
        return Ok(OperationResult::Open {
            status,
            result: None,
        });
    }

    let stateid = StateId::decode(decoder)?;
    skip_change_info(decoder)?;
    let result_flags = decoder.read_u32()?;
    let attrset = Bitmap::decode(decoder)?;
    let delegation = OpenDelegation::decode(decoder)?;
    Ok(OperationResult::Open {
        status,
        result: Some(OpenResult {
            stateid,
            result_flags,
            attrset,
            delegation,
        }),
    })
}

fn skip_change_info(decoder: &mut Decoder<'_>) -> crate::xdr::Result<()> {
    decoder.read_bool()?;
    decoder.read_u64()?;
    decoder.read_u64()?;
    Ok(())
}

fn decode_readdir_result(
    decoder: &mut Decoder<'_>,
    status: Status,
) -> crate::xdr::Result<OperationResult> {
    if !status.is_ok() {
        return Ok(OperationResult::ReadDir {
            status,
            cookieverf: [0; NFS4_VERIFIER_SIZE],
            entries: Vec::new(),
            eof: false,
        });
    }

    let cookieverf = decode_verifier(decoder)?;
    let mut entries = Vec::new();
    while bool::decode(decoder)? {
        if entries.len() >= NFS4_MAX_DIR_ENTRIES {
            return Err(crate::xdr::Error::LengthLimitExceeded {
                len: entries.len() + 1,
                max: NFS4_MAX_DIR_ENTRIES,
            });
        }
        entries.push(DirEntry {
            cookie: decoder.read_u64()?,
            name: decoder.read_string(NFS4_OPAQUE_LIMIT)?,
            attrs: Fattr::decode(decoder)?,
        });
    }
    let eof = bool::decode(decoder)?;
    Ok(OperationResult::ReadDir {
        status,
        cookieverf,
        entries,
        eof,
    })
}

fn skip_state_protect_reply(decoder: &mut Decoder<'_>) -> crate::xdr::Result<()> {
    match decoder.read_u32()? {
        0 => Ok(()),
        1 => {
            Bitmap::decode(decoder)?;
            Bitmap::decode(decoder)?;
            Ok(())
        }
        2 => {
            Bitmap::decode(decoder)?;
            Bitmap::decode(decoder)?;
            decoder.read_u32()?;
            decoder.read_u32()?;
            decoder.read_u32()?;
            decoder.read_u32()?;
            let handle_count = decoder.read_u32()? as usize;
            if handle_count > NFS4_MAX_STATE_PROTECT_HANDLES {
                return Err(crate::xdr::Error::LengthLimitExceeded {
                    len: handle_count,
                    max: NFS4_MAX_STATE_PROTECT_HANDLES,
                });
            }
            for _ in 0..handle_count {
                decoder.read_opaque(NFS4_OPAQUE_LIMIT)?;
            }
            Ok(())
        }
        value => Err(crate::xdr::Error::InvalidDiscriminant {
            type_name: "state_protect_how4",
            value: value as i32,
        }),
    }
}

fn skip_server_owner(decoder: &mut Decoder<'_>) -> crate::xdr::Result<()> {
    decoder.read_u64()?;
    decoder.read_opaque(NFS4_OPAQUE_LIMIT)?;
    Ok(())
}

fn skip_impl_ids(decoder: &mut Decoder<'_>) -> crate::xdr::Result<()> {
    let count = decoder.read_u32()? as usize;
    if count > 1 {
        return Err(crate::xdr::Error::LengthLimitExceeded { len: count, max: 1 });
    }
    for _ in 0..count {
        decoder.read_opaque(NFS4_OPAQUE_LIMIT)?;
        decoder.read_opaque(NFS4_OPAQUE_LIMIT)?;
        decoder.read_i64()?;
        decoder.read_u32()?;
    }
    Ok(())
}

pub(crate) fn decode_verifier(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Verifier> {
    let bytes = decoder.read_fixed_opaque(NFS4_VERIFIER_SIZE)?;
    bytes
        .try_into()
        .map_err(|_| crate::xdr::Error::UnexpectedEof {
            needed: NFS4_VERIFIER_SIZE,
            remaining: bytes.len(),
        })
}

fn decode_session_id(decoder: &mut Decoder<'_>) -> crate::xdr::Result<SessionId> {
    let bytes = decoder.read_fixed_opaque(NFS4_SESSIONID_SIZE)?;
    bytes
        .try_into()
        .map_err(|_| crate::xdr::Error::UnexpectedEof {
            needed: NFS4_SESSIONID_SIZE,
            remaining: bytes.len(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fore_channel_default_advertises_cached_response_space() {
        let attrs = ChannelAttrs::fore_channel_default();

        assert_eq!(attrs.max_request_size, DEFAULT_SESSION_CHANNEL_SIZE);
        assert_eq!(attrs.max_response_size, DEFAULT_SESSION_CHANNEL_SIZE);
        assert_eq!(attrs.max_response_size_cached, DEFAULT_SESSION_CHANNEL_SIZE);
    }

    #[test]
    fn back_channel_default_satisfies_linux_session_minimums() {
        let attrs = ChannelAttrs::back_channel_disabled();

        assert_eq!(attrs.max_request_size, DEFAULT_SESSION_CHANNEL_SIZE);
        assert_eq!(attrs.max_response_size, DEFAULT_SESSION_CHANNEL_SIZE);
        assert_eq!(attrs.max_response_size_cached, DEFAULT_SESSION_CHANNEL_SIZE);
        assert!(attrs.max_operations > 0);
        assert!(attrs.max_requests > 0);
    }

    #[test]
    fn stable_how_reports_whether_server_commitment_satisfies_request() {
        assert!(StableHow::FileSync.satisfies(StableHow::Unstable));
        assert!(StableHow::FileSync.satisfies(StableHow::DataSync));
        assert!(StableHow::FileSync.satisfies(StableHow::FileSync));
        assert!(StableHow::DataSync.satisfies(StableHow::Unstable));
        assert!(StableHow::DataSync.satisfies(StableHow::DataSync));
        assert!(!StableHow::DataSync.satisfies(StableHow::FileSync));
        assert!(!StableHow::Unstable.satisfies(StableHow::DataSync));
    }
}
