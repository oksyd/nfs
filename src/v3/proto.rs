#![cfg_attr(not(feature = "protocol"), allow(dead_code))]

use std::net::ToSocketAddrs;
use std::thread;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::retry::RetryPolicy;
use crate::rpc::{Auth, AuthSys, RpcClient};
use crate::xdr::{Decode, Decoder, Encode, Encoder};

pub const NFS_PROGRAM: u32 = 100003;
pub const NFS_VERSION: u32 = 3;
pub const NFS_PORT: u16 = 2049;

pub const NFS3_FHSIZE: usize = 64;
pub const NFS3_COOKIEVERFSIZE: usize = 8;
pub const NFS3_CREATEVERFSIZE: usize = 8;
pub const NFS3_WRITEVERFSIZE: usize = 8;
pub const ACCESS3_READ: u32 = 0x0001;
pub const ACCESS3_LOOKUP: u32 = 0x0002;
pub const ACCESS3_MODIFY: u32 = 0x0004;
pub const ACCESS3_EXTEND: u32 = 0x0008;
pub const ACCESS3_DELETE: u32 = 0x0010;
pub const ACCESS3_EXECUTE: u32 = 0x0020;
pub const FSF3_LINK: u32 = 0x0001;
pub const FSF3_SYMLINK: u32 = 0x0002;
pub const FSF3_HOMOGENEOUS: u32 = 0x0008;
pub const FSF3_CANSETTIME: u32 = 0x0010;

pub(crate) const NFSPROC3_NULL: u32 = 0;
pub(crate) const NFSPROC3_GETATTR: u32 = 1;
pub(crate) const NFSPROC3_SETATTR: u32 = 2;
pub(crate) const NFSPROC3_LOOKUP: u32 = 3;
pub(crate) const NFSPROC3_ACCESS: u32 = 4;
pub(crate) const NFSPROC3_READLINK: u32 = 5;
pub(crate) const NFSPROC3_READ: u32 = 6;
pub(crate) const NFSPROC3_WRITE: u32 = 7;
pub(crate) const NFSPROC3_CREATE: u32 = 8;
pub(crate) const NFSPROC3_MKDIR: u32 = 9;
pub(crate) const NFSPROC3_SYMLINK: u32 = 10;
pub(crate) const NFSPROC3_MKNOD: u32 = 11;
pub(crate) const NFSPROC3_REMOVE: u32 = 12;
pub(crate) const NFSPROC3_RMDIR: u32 = 13;
pub(crate) const NFSPROC3_RENAME: u32 = 14;
pub(crate) const NFSPROC3_LINK: u32 = 15;
pub(crate) const NFSPROC3_READDIR: u32 = 16;
pub(crate) const NFSPROC3_READDIRPLUS: u32 = 17;
pub(crate) const NFSPROC3_FSSTAT: u32 = 18;
pub(crate) const NFSPROC3_FSINFO: u32 = 19;
pub(crate) const NFSPROC3_PATHCONF: u32 = 20;
pub(crate) const NFSPROC3_COMMIT: u32 = 21;

pub(crate) const MAX_NAME_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_PATH_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_IO_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_DIR_ENTRIES: usize = 1_000_000;
pub const NFS3_NSECONDS_PER_SECOND: u32 = 1_000_000_000;

/// NFSv3 directory cookie verifier.
pub type CookieVerf = [u8; NFS3_COOKIEVERFSIZE];
/// NFSv3 exclusive create verifier.
pub type CreateVerf = [u8; NFS3_CREATEVERFSIZE];
/// NFSv3 write verifier.
pub type WriteVerf = [u8; NFS3_WRITEVERFSIZE];

/// NFSv3 status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfsStatus {
    Ok,
    Perm,
    NoEnt,
    Io,
    Nxio,
    Access,
    Exist,
    Xdev,
    Nodev,
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
    Remote,
    BadHandle,
    NotSync,
    BadCookie,
    NotSupported,
    TooSmall,
    ServerFault,
    BadType,
    Jukebox,
    Unknown(u32),
}

impl NfsStatus {
    /// Converts a raw RFC 1813 status code into [`NfsStatus`].
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
            19 => Self::Nodev,
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
            71 => Self::Remote,
            10001 => Self::BadHandle,
            10002 => Self::NotSync,
            10003 => Self::BadCookie,
            10004 => Self::NotSupported,
            10005 => Self::TooSmall,
            10006 => Self::ServerFault,
            10007 => Self::BadType,
            10008 => Self::Jukebox,
            value => Self::Unknown(value),
        }
    }

    /// Returns the raw RFC 1813 status code.
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
            Self::Nodev => 19,
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
            Self::Remote => 71,
            Self::BadHandle => 10001,
            Self::NotSync => 10002,
            Self::BadCookie => 10003,
            Self::NotSupported => 10004,
            Self::TooSmall => 10005,
            Self::ServerFault => 10006,
            Self::BadType => 10007,
            Self::Jukebox => 10008,
            Self::Unknown(value) => value,
        }
    }
}

/// NFSv3 file type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    BlockDevice,
    CharacterDevice,
    Symlink,
    Socket,
    Fifo,
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

    fn from_i32(value: i32) -> crate::xdr::Result<Self> {
        match value {
            1 => Ok(Self::Regular),
            2 => Ok(Self::Directory),
            3 => Ok(Self::BlockDevice),
            4 => Ok(Self::CharacterDevice),
            5 => Ok(Self::Symlink),
            6 => Ok(Self::Socket),
            7 => Ok(Self::Fifo),
            value => Err(crate::xdr::Error::InvalidDiscriminant {
                type_name: "ftype3",
                value,
            }),
        }
    }

    fn as_i32(self) -> i32 {
        match self {
            Self::Regular => 1,
            Self::Directory => 2,
            Self::BlockDevice => 3,
            Self::CharacterDevice => 4,
            Self::Symlink => 5,
            Self::Socket => 6,
            Self::Fifo => 7,
        }
    }
}

impl Encode for FileType {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_discriminant(self.as_i32());
        Ok(())
    }
}

impl Decode for FileType {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Self::from_i32(decoder.read_discriminant()?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileHandle {
    data: Vec<u8>,
}

impl FileHandle {
    pub fn new(data: Vec<u8>) -> Result<Self> {
        if data.len() > NFS3_FHSIZE {
            return Err(Error::Protocol(format!(
                "NFS file handle is {} bytes, maximum is {NFS3_FHSIZE}",
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
        encoder.write_opaque(&self.data, NFS3_FHSIZE)
    }
}

impl Decode for FileHandle {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            data: decoder.read_opaque_vec(NFS3_FHSIZE)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpecData {
    pub specdata1: u32,
    pub specdata2: u32,
}

impl Decode for SpecData {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            specdata1: u32::decode(decoder)?,
            specdata2: u32::decode(decoder)?,
        })
    }
}

impl Encode for SpecData {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.specdata1.encode(encoder)?;
        self.specdata2.encode(encoder)
    }
}

/// NFS timestamp with second and nanosecond components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NfsTime {
    /// Seconds since the Unix epoch.
    pub seconds: u32,
    /// Nanoseconds within the second. Must be less than
    /// [`NFS3_NSECONDS_PER_SECOND`] when encoded.
    pub nseconds: u32,
}

impl Decode for NfsTime {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        let time = Self {
            seconds: u32::decode(decoder)?,
            nseconds: u32::decode(decoder)?,
        };
        time.validate()?;
        Ok(time)
    }
}

impl Encode for NfsTime {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.validate()?;
        self.seconds.encode(encoder)?;
        self.nseconds.encode(encoder)
    }
}

impl NfsTime {
    pub(crate) fn validate(self) -> crate::xdr::Result<()> {
        validate_nseconds(self.nseconds)
    }
}

/// NFSv3 post-operation file attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAttr {
    /// File type.
    pub file_type: FileType,
    /// POSIX mode bits.
    pub mode: u32,
    /// Link count.
    pub nlink: u32,
    /// Numeric owner uid.
    pub uid: u32,
    /// Numeric owner gid.
    pub gid: u32,
    /// File size in bytes.
    pub size: u64,
    /// Disk bytes used.
    pub used: u64,
    /// Device numbers for special files.
    pub rdev: SpecData,
    /// Filesystem id.
    pub fsid: u64,
    /// File id.
    pub fileid: u64,
    /// Last access time.
    pub atime: NfsTime,
    /// Last modification time.
    pub mtime: NfsTime,
    /// Last metadata change time.
    pub ctime: NfsTime,
}

impl FileAttr {
    /// Returns true when this is a regular file.
    pub fn is_file(&self) -> bool {
        self.file_type.is_file()
    }

    /// Returns true when this is a directory.
    pub fn is_dir(&self) -> bool {
        self.file_type.is_dir()
    }

    /// Returns true when this is a symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.file_type.is_symlink()
    }
}

impl Decode for FileAttr {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            file_type: FileType::decode(decoder)?,
            mode: u32::decode(decoder)?,
            nlink: u32::decode(decoder)?,
            uid: u32::decode(decoder)?,
            gid: u32::decode(decoder)?,
            size: u64::decode(decoder)?,
            used: u64::decode(decoder)?,
            rdev: SpecData::decode(decoder)?,
            fsid: u64::decode(decoder)?,
            fileid: u64::decode(decoder)?,
            atime: NfsTime::decode(decoder)?,
            mtime: NfsTime::decode(decoder)?,
            ctime: NfsTime::decode(decoder)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WccAttr {
    pub size: u64,
    pub mtime: NfsTime,
    pub ctime: NfsTime,
}

impl Decode for WccAttr {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            size: u64::decode(decoder)?,
            mtime: NfsTime::decode(decoder)?,
            ctime: NfsTime::decode(decoder)?,
        })
    }
}

pub type PostOpAttr = Option<FileAttr>;
pub type PreOpAttr = Option<WccAttr>;
pub type PostOpFileHandle = Option<FileHandle>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WccData {
    pub before: PreOpAttr,
    pub after: PostOpAttr,
}

impl Decode for WccData {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            before: decode_pre_op_attr(decoder)?,
            after: decode_post_op_attr(decoder)?,
        })
    }
}

/// Time-setting mode used by [`SetAttr`].
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

/// NFSv3 attribute update.
///
/// Fields set to `None` are left unchanged. Use constructors such as
/// [`SetAttr::mode`], [`SetAttr::size`], or [`SetAttr::touch`] for common
/// updates.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SetAttr {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: SetTime,
    pub mtime: SetTime,
}

impl SetAttr {
    /// Builds an attribute update that sets POSIX mode bits.
    pub fn mode(mode: u32) -> Self {
        Self {
            mode: Some(mode),
            ..Self::default()
        }
    }

    /// Builds an attribute update that sets numeric uid.
    pub fn uid(uid: u32) -> Self {
        Self {
            uid: Some(uid),
            ..Self::default()
        }
    }

    /// Builds an attribute update that sets numeric gid.
    pub fn gid(gid: u32) -> Self {
        Self {
            gid: Some(gid),
            ..Self::default()
        }
    }

    /// Builds an attribute update that sets numeric uid and gid.
    pub fn ownership(uid: u32, gid: u32) -> Self {
        Self {
            uid: Some(uid),
            gid: Some(gid),
            ..Self::default()
        }
    }

    /// Builds an attribute update that sets file size.
    pub fn size(size: u64) -> Self {
        Self {
            size: Some(size),
            ..Self::default()
        }
    }

    /// Builds an attribute update that sets access and modification times.
    pub fn times(atime: Option<NfsTime>, mtime: Option<NfsTime>) -> Self {
        Self {
            atime: atime.map_or(SetTime::DontChange, SetTime::ClientTime),
            mtime: mtime.map_or(SetTime::DontChange, SetTime::ClientTime),
            ..Self::default()
        }
    }

    /// Builds an attribute update that asks the server to update both times.
    pub fn touch() -> Self {
        Self {
            atime: SetTime::ServerTime,
            mtime: SetTime::ServerTime,
            ..Self::default()
        }
    }
}

impl Encode for SetAttr {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encode_optional_u32(encoder, self.mode)?;
        encode_optional_u32(encoder, self.uid)?;
        encode_optional_u32(encoder, self.gid)?;
        encode_optional_u64(encoder, self.size)?;
        encode_set_time(encoder, self.atime)?;
        encode_set_time(encoder, self.mtime)?;
        Ok(())
    }
}

/// NFSv3 write stability requested or reported by the server.
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
    fn from_i32(value: i32) -> crate::xdr::Result<Self> {
        match value {
            0 => Ok(Self::Unstable),
            1 => Ok(Self::DataSync),
            2 => Ok(Self::FileSync),
            value => Err(crate::xdr::Error::InvalidDiscriminant {
                type_name: "stable_how",
                value,
            }),
        }
    }

    fn as_i32(self) -> i32 {
        match self {
            Self::Unstable => 0,
            Self::DataSync => 1,
            Self::FileSync => 2,
        }
    }

    #[cfg(any(test, feature = "blocking", feature = "tokio"))]
    pub(crate) fn satisfies(self, requested: Self) -> bool {
        self >= requested
    }
}

impl Encode for StableHow {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_discriminant(self.as_i32());
        Ok(())
    }
}

impl Decode for StableHow {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Self::from_i32(decoder.read_discriminant()?)
    }
}

/// NFSv3 create mode used by raw protocol calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateHow {
    Unchecked(SetAttr),
    Guarded(SetAttr),
    Exclusive(CreateVerf),
}

impl Encode for CreateHow {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        match self {
            Self::Unchecked(attr) => {
                encoder.write_discriminant(0);
                attr.encode(encoder)
            }
            Self::Guarded(attr) => {
                encoder.write_discriminant(1);
                attr.encode(encoder)
            }
            Self::Exclusive(verf) => {
                encoder.write_discriminant(2);
                encoder.write_fixed_opaque(verf);
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MknodData {
    CharacterDevice { attributes: SetAttr, spec: SpecData },
    BlockDevice { attributes: SetAttr, spec: SpecData },
    Socket { attributes: SetAttr },
    Fifo { attributes: SetAttr },
}

impl Encode for MknodData {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        match self {
            Self::CharacterDevice { attributes, spec } => {
                FileType::CharacterDevice.encode(encoder)?;
                attributes.encode(encoder)?;
                spec.encode(encoder)
            }
            Self::BlockDevice { attributes, spec } => {
                FileType::BlockDevice.encode(encoder)?;
                attributes.encode(encoder)?;
                spec.encode(encoder)
            }
            Self::Socket { attributes } => {
                FileType::Socket.encode(encoder)?;
                attributes.encode(encoder)
            }
            Self::Fifo { attributes } => {
                FileType::Fifo.encode(encoder)?;
                attributes.encode(encoder)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupResult {
    pub object: FileHandle,
    pub object_attributes: PostOpAttr,
    pub directory_attributes: PostOpAttr,
}

/// Result of an NFSv3 ACCESS call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessResult {
    /// Attributes for the object, when returned by the server.
    pub object_attributes: PostOpAttr,
    /// Access bits granted by the server.
    pub access: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadResult {
    pub file_attributes: PostOpAttr,
    pub count: u32,
    pub eof: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteResult {
    pub file_wcc: WccData,
    pub count: u32,
    pub committed: StableHow,
    pub verifier: WriteVerf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateResult {
    pub object: PostOpFileHandle,
    pub object_attributes: PostOpAttr,
    pub directory_wcc: WccData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameResult {
    pub fromdir_wcc: WccData,
    pub todir_wcc: WccData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkResult {
    pub file_attributes: PostOpAttr,
    pub linkdir_wcc: WccData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    pub fileid: u64,
    pub name: String,
    pub cookie: u64,
    pub attributes: PostOpAttr,
    pub handle: PostOpFileHandle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadDirResult {
    pub directory_attributes: PostOpAttr,
    pub cookieverf: CookieVerf,
    pub entries: Vec<DirectoryEntry>,
    pub eof: bool,
}

/// Result of an NFSv3 FSSTAT call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsStat {
    pub object_attributes: PostOpAttr,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub available_bytes: u64,
    pub total_files: u64,
    pub free_files: u64,
    pub available_files: u64,
    pub invariant_seconds: u32,
}

/// Result of an NFSv3 FSINFO call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsInfo {
    pub object_attributes: PostOpAttr,
    pub read_max: u32,
    pub read_preferred: u32,
    pub read_multiple: u32,
    pub write_max: u32,
    pub write_preferred: u32,
    pub write_multiple: u32,
    pub dir_preferred: u32,
    pub max_file_size: u64,
    pub time_delta: NfsTime,
    pub properties: u32,
}

/// Result of an NFSv3 PATHCONF call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathConf {
    pub object_attributes: PostOpAttr,
    pub link_max: u32,
    pub name_max: u32,
    pub no_trunc: bool,
    pub chown_restricted: bool,
    pub case_insensitive: bool,
    pub case_preserving: bool,
}

/// Result of an NFSv3 COMMIT call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitResult {
    pub file_wcc: WccData,
    pub verifier: WriteVerf,
}

#[derive(Debug)]
pub struct Nfs3Client {
    rpc: RpcClient,
    retry_policy: RetryPolicy,
}

impl Nfs3Client {
    pub fn connect<A: ToSocketAddrs>(addr: A, auth: AuthSys) -> Result<Self> {
        Self::connect_with_timeout(addr, auth, None)
    }

    pub fn connect_with_timeout<A: ToSocketAddrs>(
        addr: A,
        auth: AuthSys,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        Ok(Self {
            rpc: RpcClient::connect_with_timeout(addr, Auth::sys(auth), timeout)?,
            retry_policy: RetryPolicy::default(),
        })
    }

    pub fn set_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.rpc.set_timeout(timeout)
    }

    pub fn set_max_record_size(&mut self, max_record_size: usize) -> Result<()> {
        self.rpc.set_max_record_size(max_record_size)
    }

    pub fn set_retry_policy(&mut self, retry_policy: RetryPolicy) {
        self.retry_policy = retry_policy;
    }

    pub fn null(&mut self) -> Result<()> {
        let payload = self
            .rpc
            .call(NFS_PROGRAM, NFS_VERSION, NFSPROC3_NULL, &())?;
        let decoder = Decoder::new(&payload);
        decoder.finish()?;
        Ok(())
    }

    pub fn getattr(&mut self, object: &FileHandle) -> Result<FileAttr> {
        let payload = self.call(NFSPROC3_GETATTR, object)?;
        let mut decoder = Decoder::new(&payload);
        require_ok(&mut decoder, "GETATTR")?;
        let attr = FileAttr::decode(&mut decoder)?;
        decoder.finish()?;
        Ok(attr)
    }

    pub fn setattr(&mut self, object: &FileHandle, attr: &SetAttr) -> Result<WccData> {
        let payload = self.call(
            NFSPROC3_SETATTR,
            &SetattrArgs {
                object,
                attr,
                guard: None,
            },
        )?;
        let mut decoder = Decoder::new(&payload);
        let status = decode_status(&mut decoder)?;
        let wcc = WccData::decode(&mut decoder)?;
        decoder.finish()?;
        if status == NfsStatus::Ok {
            Ok(wcc)
        } else {
            Err(Error::nfs("SETATTR", status))
        }
    }

    pub fn lookup(&mut self, dir: &FileHandle, name: &str) -> Result<LookupResult> {
        let payload = self.call(NFSPROC3_LOOKUP, &Diropargs { dir, name })?;
        let mut decoder = Decoder::new(&payload);
        let status = decode_status(&mut decoder)?;
        if status == NfsStatus::Ok {
            let result = LookupResult {
                object: FileHandle::decode(&mut decoder)?,
                object_attributes: decode_post_op_attr(&mut decoder)?,
                directory_attributes: decode_post_op_attr(&mut decoder)?,
            };
            decoder.finish()?;
            Ok(result)
        } else {
            let _directory_attributes = decode_post_op_attr(&mut decoder)?;
            decoder.finish()?;
            Err(Error::nfs("LOOKUP", status))
        }
    }

    pub fn access(&mut self, object: &FileHandle, access: u32) -> Result<AccessResult> {
        let payload = self.call(NFSPROC3_ACCESS, &AccessArgs { object, access })?;
        let mut decoder = Decoder::new(&payload);
        let status = decode_status(&mut decoder)?;
        let object_attributes = decode_post_op_attr(&mut decoder)?;
        if status == NfsStatus::Ok {
            let access = u32::decode(&mut decoder)?;
            decoder.finish()?;
            Ok(AccessResult {
                object_attributes,
                access,
            })
        } else {
            decoder.finish()?;
            Err(Error::nfs("ACCESS", status))
        }
    }

    pub fn readlink(&mut self, symlink: &FileHandle) -> Result<String> {
        let payload = self.call(NFSPROC3_READLINK, symlink)?;
        let mut decoder = Decoder::new(&payload);
        let status = decode_status(&mut decoder)?;
        let _symlink_attributes = decode_post_op_attr(&mut decoder)?;
        if status == NfsStatus::Ok {
            let data = decoder.read_string(MAX_PATH_BYTES)?;
            decoder.finish()?;
            Ok(data)
        } else {
            decoder.finish()?;
            Err(Error::nfs("READLINK", status))
        }
    }

    pub fn read(&mut self, file: &FileHandle, offset: u64, count: u32) -> Result<ReadResult> {
        let requested_count = count;
        let payload = self.call(
            NFSPROC3_READ,
            &ReadArgs {
                file,
                offset,
                count,
            },
        )?;
        let mut decoder = Decoder::new(&payload);
        let status = decode_status(&mut decoder)?;
        let file_attributes = decode_post_op_attr(&mut decoder)?;
        if status == NfsStatus::Ok {
            let returned_count = u32::decode(&mut decoder)?;
            let eof = bool::decode(&mut decoder)?;
            let data = decoder.read_opaque_vec(MAX_IO_BYTES)?;
            decoder.finish()?;
            validate_read_result_size(requested_count, returned_count, data.len(), eof)?;
            Ok(ReadResult {
                file_attributes,
                count: returned_count,
                eof,
                data,
            })
        } else {
            decoder.finish()?;
            Err(Error::nfs("READ", status))
        }
    }

    pub fn write(
        &mut self,
        file: &FileHandle,
        offset: u64,
        stable: StableHow,
        data: &[u8],
    ) -> Result<WriteResult> {
        let requested_count =
            u32::try_from(data.len()).map_err(|_| Error::LengthOutOfRange { len: data.len() })?;
        let payload = self.call(
            NFSPROC3_WRITE,
            &WriteArgs {
                file,
                offset,
                count: requested_count,
                stable,
                data,
            },
        )?;
        let mut decoder = Decoder::new(&payload);
        let status = decode_status(&mut decoder)?;
        let file_wcc = WccData::decode(&mut decoder)?;
        if status == NfsStatus::Ok {
            let returned_count = u32::decode(&mut decoder)?;
            let committed = StableHow::decode(&mut decoder)?;
            let verifier = decode_writeverf(&mut decoder)?;
            decoder.finish()?;
            validate_write_result_count(requested_count, returned_count)?;
            Ok(WriteResult {
                file_wcc,
                count: returned_count,
                committed,
                verifier,
            })
        } else {
            decoder.finish()?;
            Err(Error::nfs("WRITE", status))
        }
    }

    pub fn create(
        &mut self,
        dir: &FileHandle,
        name: &str,
        how: &CreateHow,
    ) -> Result<CreateResult> {
        self.create_like(
            NFSPROC3_CREATE,
            "CREATE",
            &CreateArgs {
                where_: Diropargs { dir, name },
                how,
            },
        )
    }

    pub fn mkdir(
        &mut self,
        dir: &FileHandle,
        name: &str,
        attributes: &SetAttr,
    ) -> Result<CreateResult> {
        self.create_like(
            NFSPROC3_MKDIR,
            "MKDIR",
            &MkdirArgs {
                where_: Diropargs { dir, name },
                attributes,
            },
        )
    }

    pub fn symlink(
        &mut self,
        dir: &FileHandle,
        name: &str,
        target: &str,
        attributes: &SetAttr,
    ) -> Result<CreateResult> {
        self.create_like(
            NFSPROC3_SYMLINK,
            "SYMLINK",
            &SymlinkArgs {
                where_: Diropargs { dir, name },
                target,
                attributes,
            },
        )
    }

    pub fn mknod(
        &mut self,
        dir: &FileHandle,
        name: &str,
        what: &MknodData,
    ) -> Result<CreateResult> {
        self.create_like(
            NFSPROC3_MKNOD,
            "MKNOD",
            &MknodArgs {
                where_: Diropargs { dir, name },
                what,
            },
        )
    }

    pub fn remove(&mut self, dir: &FileHandle, name: &str) -> Result<WccData> {
        self.wcc_only(NFSPROC3_REMOVE, "REMOVE", &Diropargs { dir, name })
    }

    pub fn rmdir(&mut self, dir: &FileHandle, name: &str) -> Result<WccData> {
        self.wcc_only(NFSPROC3_RMDIR, "RMDIR", &Diropargs { dir, name })
    }

    pub fn rename(
        &mut self,
        from_dir: &FileHandle,
        from_name: &str,
        to_dir: &FileHandle,
        to_name: &str,
    ) -> Result<RenameResult> {
        let payload = self.call(
            NFSPROC3_RENAME,
            &RenameArgs {
                from: Diropargs {
                    dir: from_dir,
                    name: from_name,
                },
                to: Diropargs {
                    dir: to_dir,
                    name: to_name,
                },
            },
        )?;
        let mut decoder = Decoder::new(&payload);
        let status = decode_status(&mut decoder)?;
        let result = RenameResult {
            fromdir_wcc: WccData::decode(&mut decoder)?,
            todir_wcc: WccData::decode(&mut decoder)?,
        };
        decoder.finish()?;
        if status == NfsStatus::Ok {
            Ok(result)
        } else {
            Err(Error::nfs("RENAME", status))
        }
    }

    pub fn link(
        &mut self,
        file: &FileHandle,
        link_dir: &FileHandle,
        link_name: &str,
    ) -> Result<LinkResult> {
        let payload = self.call(
            NFSPROC3_LINK,
            &LinkArgs {
                file,
                link: Diropargs {
                    dir: link_dir,
                    name: link_name,
                },
            },
        )?;
        let mut decoder = Decoder::new(&payload);
        let status = decode_status(&mut decoder)?;
        let result = LinkResult {
            file_attributes: decode_post_op_attr(&mut decoder)?,
            linkdir_wcc: WccData::decode(&mut decoder)?,
        };
        decoder.finish()?;
        if status == NfsStatus::Ok {
            Ok(result)
        } else {
            Err(Error::nfs("LINK", status))
        }
    }

    pub fn readdir(
        &mut self,
        dir: &FileHandle,
        cookie: u64,
        cookieverf: CookieVerf,
        count: u32,
    ) -> Result<ReadDirResult> {
        let payload = self.call(
            NFSPROC3_READDIR,
            &ReadDirArgs {
                dir,
                cookie,
                cookieverf,
                count,
            },
        )?;
        let mut decoder = Decoder::new(&payload);
        let status = decode_status(&mut decoder)?;
        let directory_attributes = decode_post_op_attr(&mut decoder)?;
        if status != NfsStatus::Ok {
            decoder.finish()?;
            return Err(Error::nfs("READDIR", status));
        }

        let cookieverf = decode_cookieverf(&mut decoder)?;
        let entries = decode_dir_entries(&mut decoder, false)?;
        let eof = bool::decode(&mut decoder)?;
        decoder.finish()?;
        Ok(ReadDirResult {
            directory_attributes,
            cookieverf,
            entries,
            eof,
        })
    }

    pub fn readdirplus(
        &mut self,
        dir: &FileHandle,
        cookie: u64,
        cookieverf: CookieVerf,
        dircount: u32,
        maxcount: u32,
    ) -> Result<ReadDirResult> {
        let payload = self.call(
            NFSPROC3_READDIRPLUS,
            &ReadDirPlusArgs {
                dir,
                cookie,
                cookieverf,
                dircount,
                maxcount,
            },
        )?;
        let mut decoder = Decoder::new(&payload);
        let status = decode_status(&mut decoder)?;
        let directory_attributes = decode_post_op_attr(&mut decoder)?;
        if status != NfsStatus::Ok {
            decoder.finish()?;
            return Err(Error::nfs("READDIRPLUS", status));
        }

        let cookieverf = decode_cookieverf(&mut decoder)?;
        let entries = decode_dir_entries(&mut decoder, true)?;
        let eof = bool::decode(&mut decoder)?;
        decoder.finish()?;
        Ok(ReadDirResult {
            directory_attributes,
            cookieverf,
            entries,
            eof,
        })
    }

    pub fn fsstat(&mut self, fsroot: &FileHandle) -> Result<FsStat> {
        let payload = self.call(NFSPROC3_FSSTAT, fsroot)?;
        let mut decoder = Decoder::new(&payload);
        let status = decode_status(&mut decoder)?;
        let object_attributes = decode_post_op_attr(&mut decoder)?;
        if status == NfsStatus::Ok {
            let result = FsStat {
                object_attributes,
                total_bytes: u64::decode(&mut decoder)?,
                free_bytes: u64::decode(&mut decoder)?,
                available_bytes: u64::decode(&mut decoder)?,
                total_files: u64::decode(&mut decoder)?,
                free_files: u64::decode(&mut decoder)?,
                available_files: u64::decode(&mut decoder)?,
                invariant_seconds: u32::decode(&mut decoder)?,
            };
            decoder.finish()?;
            Ok(result)
        } else {
            decoder.finish()?;
            Err(Error::nfs("FSSTAT", status))
        }
    }

    pub fn fsinfo(&mut self, fsroot: &FileHandle) -> Result<FsInfo> {
        let payload = self.call(NFSPROC3_FSINFO, fsroot)?;
        let mut decoder = Decoder::new(&payload);
        let status = decode_status(&mut decoder)?;
        let object_attributes = decode_post_op_attr(&mut decoder)?;
        if status == NfsStatus::Ok {
            let result = FsInfo {
                object_attributes,
                read_max: u32::decode(&mut decoder)?,
                read_preferred: u32::decode(&mut decoder)?,
                read_multiple: u32::decode(&mut decoder)?,
                write_max: u32::decode(&mut decoder)?,
                write_preferred: u32::decode(&mut decoder)?,
                write_multiple: u32::decode(&mut decoder)?,
                dir_preferred: u32::decode(&mut decoder)?,
                max_file_size: u64::decode(&mut decoder)?,
                time_delta: NfsTime::decode(&mut decoder)?,
                properties: u32::decode(&mut decoder)?,
            };
            decoder.finish()?;
            Ok(result)
        } else {
            decoder.finish()?;
            Err(Error::nfs("FSINFO", status))
        }
    }

    pub fn pathconf(&mut self, object: &FileHandle) -> Result<PathConf> {
        let payload = self.call(NFSPROC3_PATHCONF, object)?;
        let mut decoder = Decoder::new(&payload);
        let status = decode_status(&mut decoder)?;
        let object_attributes = decode_post_op_attr(&mut decoder)?;
        if status == NfsStatus::Ok {
            let result = PathConf {
                object_attributes,
                link_max: u32::decode(&mut decoder)?,
                name_max: u32::decode(&mut decoder)?,
                no_trunc: bool::decode(&mut decoder)?,
                chown_restricted: bool::decode(&mut decoder)?,
                case_insensitive: bool::decode(&mut decoder)?,
                case_preserving: bool::decode(&mut decoder)?,
            };
            decoder.finish()?;
            Ok(result)
        } else {
            decoder.finish()?;
            Err(Error::nfs("PATHCONF", status))
        }
    }

    pub fn commit(&mut self, file: &FileHandle, offset: u64, count: u32) -> Result<CommitResult> {
        let payload = self.call(
            NFSPROC3_COMMIT,
            &CommitArgs {
                file,
                offset,
                count,
            },
        )?;
        let mut decoder = Decoder::new(&payload);
        let status = decode_status(&mut decoder)?;
        let result = CommitResult {
            file_wcc: WccData::decode(&mut decoder)?,
            verifier: if status == NfsStatus::Ok {
                decode_writeverf(&mut decoder)?
            } else {
                [0; NFS3_WRITEVERFSIZE]
            },
        };
        decoder.finish()?;
        if status == NfsStatus::Ok {
            Ok(result)
        } else {
            Err(Error::nfs("COMMIT", status))
        }
    }

    fn create_like<T: Encode + ?Sized>(
        &mut self,
        procedure_id: u32,
        procedure_name: &'static str,
        args: &T,
    ) -> Result<CreateResult> {
        let payload = self.call(procedure_id, args)?;
        let mut decoder = Decoder::new(&payload);
        let status = decode_status(&mut decoder)?;
        if status == NfsStatus::Ok {
            let result = CreateResult {
                object: decode_post_op_fh(&mut decoder)?,
                object_attributes: decode_post_op_attr(&mut decoder)?,
                directory_wcc: WccData::decode(&mut decoder)?,
            };
            decoder.finish()?;
            Ok(result)
        } else {
            let _directory_wcc = WccData::decode(&mut decoder)?;
            decoder.finish()?;
            Err(Error::nfs(procedure_name, status))
        }
    }

    fn wcc_only<T: Encode + ?Sized>(
        &mut self,
        procedure_id: u32,
        procedure_name: &'static str,
        args: &T,
    ) -> Result<WccData> {
        let payload = self.call(procedure_id, args)?;
        let mut decoder = Decoder::new(&payload);
        let status = decode_status(&mut decoder)?;
        let wcc = WccData::decode(&mut decoder)?;
        decoder.finish()?;
        if status == NfsStatus::Ok {
            Ok(wcc)
        } else {
            Err(Error::nfs(procedure_name, status))
        }
    }

    fn call<T: Encode + ?Sized>(&mut self, procedure: u32, args: &T) -> Result<Vec<u8>> {
        let mut retry = 0;
        loop {
            let payload = self.rpc.call(NFS_PROGRAM, NFS_VERSION, procedure, args)?;
            if procedure != NFSPROC3_NULL
                && payload_has_status(&payload, NfsStatus::Jukebox)
                && let Some(delay) = self.retry_policy.delay_for_retry(retry)
            {
                retry += 1;
                thread::sleep(delay);
                continue;
            }
            return Ok(payload);
        }
    }
}

pub(crate) fn payload_has_status(payload: &[u8], expected: NfsStatus) -> bool {
    payload
        .get(..4)
        .map(|bytes| {
            let status = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            NfsStatus::from_u32(status) == expected
        })
        .unwrap_or(false)
}

pub(crate) fn decode_status(decoder: &mut Decoder<'_>) -> crate::xdr::Result<NfsStatus> {
    Ok(NfsStatus::from_u32(u32::decode(decoder)?))
}

pub(crate) fn require_ok(decoder: &mut Decoder<'_>, procedure: &'static str) -> Result<()> {
    let status = decode_status(decoder)?;
    if status == NfsStatus::Ok {
        Ok(())
    } else {
        Err(Error::nfs(procedure, status))
    }
}

pub(crate) fn decode_post_op_attr(decoder: &mut Decoder<'_>) -> crate::xdr::Result<PostOpAttr> {
    if bool::decode(decoder)? {
        Ok(Some(FileAttr::decode(decoder)?))
    } else {
        Ok(None)
    }
}

pub(crate) fn decode_pre_op_attr(decoder: &mut Decoder<'_>) -> crate::xdr::Result<PreOpAttr> {
    if bool::decode(decoder)? {
        Ok(Some(WccAttr::decode(decoder)?))
    } else {
        Ok(None)
    }
}

pub(crate) fn decode_post_op_fh(decoder: &mut Decoder<'_>) -> crate::xdr::Result<PostOpFileHandle> {
    if bool::decode(decoder)? {
        Ok(Some(FileHandle::decode(decoder)?))
    } else {
        Ok(None)
    }
}

pub(crate) fn decode_cookieverf(decoder: &mut Decoder<'_>) -> crate::xdr::Result<CookieVerf> {
    let bytes = decoder.read_fixed_opaque(NFS3_COOKIEVERFSIZE)?;
    bytes
        .try_into()
        .map_err(|_| crate::xdr::Error::UnexpectedEof {
            needed: NFS3_COOKIEVERFSIZE,
            remaining: bytes.len(),
        })
}

pub(crate) fn decode_writeverf(decoder: &mut Decoder<'_>) -> crate::xdr::Result<WriteVerf> {
    let bytes = decoder.read_fixed_opaque(NFS3_WRITEVERFSIZE)?;
    bytes
        .try_into()
        .map_err(|_| crate::xdr::Error::UnexpectedEof {
            needed: NFS3_WRITEVERFSIZE,
            remaining: bytes.len(),
        })
}

pub(crate) fn validate_read_result_size(
    requested_count: u32,
    returned_count: u32,
    data_len: usize,
    eof: bool,
) -> Result<()> {
    if data_len != returned_count as usize {
        return Err(Error::Protocol(format!(
            "READ returned count {returned_count} but {data_len} data bytes"
        )));
    }
    if returned_count > requested_count {
        return Err(Error::Protocol(format!(
            "READ returned {returned_count} bytes for a {requested_count} byte request"
        )));
    }
    if requested_count > 0 && returned_count == 0 && !eof {
        return Err(Error::Protocol(
            "READ returned no data before EOF".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_write_result_count(requested_count: u32, returned_count: u32) -> Result<()> {
    if returned_count > requested_count {
        return Err(Error::Protocol(format!(
            "WRITE reported {returned_count} bytes for a {requested_count} byte request"
        )));
    }
    if requested_count > 0 && returned_count == 0 {
        return Err(Error::Protocol("WRITE accepted zero bytes".to_owned()));
    }
    Ok(())
}

pub(crate) fn decode_dir_entries(
    decoder: &mut Decoder<'_>,
    plus: bool,
) -> crate::xdr::Result<Vec<DirectoryEntry>> {
    let mut entries = Vec::new();
    while bool::decode(decoder)? {
        if entries.len() >= MAX_DIR_ENTRIES {
            return Err(crate::xdr::Error::LengthLimitExceeded {
                len: entries.len() + 1,
                max: MAX_DIR_ENTRIES,
            });
        }

        let fileid = u64::decode(decoder)?;
        let name = decoder.read_string(MAX_NAME_BYTES)?;
        let cookie = u64::decode(decoder)?;
        let (attributes, handle) = if plus {
            (decode_post_op_attr(decoder)?, decode_post_op_fh(decoder)?)
        } else {
            (None, None)
        };
        entries.push(DirectoryEntry {
            fileid,
            name,
            cookie,
            attributes,
            handle,
        });
    }
    Ok(entries)
}

fn encode_optional_u32(encoder: &mut Encoder, value: Option<u32>) -> crate::xdr::Result<()> {
    encoder.write_bool(value.is_some());
    if let Some(value) = value {
        encoder.write_u32(value);
    }
    Ok(())
}

fn encode_optional_u64(encoder: &mut Encoder, value: Option<u64>) -> crate::xdr::Result<()> {
    encoder.write_bool(value.is_some());
    if let Some(value) = value {
        encoder.write_u64(value);
    }
    Ok(())
}

fn encode_set_time(encoder: &mut Encoder, value: SetTime) -> crate::xdr::Result<()> {
    match value {
        SetTime::DontChange => encoder.write_discriminant(0),
        SetTime::ServerTime => encoder.write_discriminant(1),
        SetTime::ClientTime(time) => {
            time.validate()?;
            encoder.write_discriminant(2);
            time.encode(encoder)?;
        }
    }
    Ok(())
}

fn validate_nseconds(nseconds: u32) -> crate::xdr::Result<()> {
    if nseconds >= NFS3_NSECONDS_PER_SECOND {
        return Err(crate::xdr::Error::LengthLimitExceeded {
            len: nseconds as usize,
            max: (NFS3_NSECONDS_PER_SECOND - 1) as usize,
        });
    }
    Ok(())
}

pub(crate) struct Diropargs<'a> {
    pub(crate) dir: &'a FileHandle,
    pub(crate) name: &'a str,
}

impl Encode for Diropargs<'_> {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.dir.encode(encoder)?;
        encoder.write_string(self.name, MAX_NAME_BYTES)
    }
}

pub(crate) struct SetattrArgs<'a> {
    pub(crate) object: &'a FileHandle,
    pub(crate) attr: &'a SetAttr,
    pub(crate) guard: Option<NfsTime>,
}

impl Encode for SetattrArgs<'_> {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.object.encode(encoder)?;
        self.attr.encode(encoder)?;
        encoder.write_bool(self.guard.is_some());
        if let Some(guard) = self.guard {
            guard.encode(encoder)?;
        }
        Ok(())
    }
}

pub(crate) struct AccessArgs<'a> {
    pub(crate) object: &'a FileHandle,
    pub(crate) access: u32,
}

impl Encode for AccessArgs<'_> {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.object.encode(encoder)?;
        encoder.write_u32(self.access);
        Ok(())
    }
}

pub(crate) struct ReadArgs<'a> {
    pub(crate) file: &'a FileHandle,
    pub(crate) offset: u64,
    pub(crate) count: u32,
}

impl Encode for ReadArgs<'_> {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.file.encode(encoder)?;
        encoder.write_u64(self.offset);
        encoder.write_u32(self.count);
        Ok(())
    }
}

pub(crate) struct WriteArgs<'a> {
    pub(crate) file: &'a FileHandle,
    pub(crate) offset: u64,
    pub(crate) count: u32,
    pub(crate) stable: StableHow,
    pub(crate) data: &'a [u8],
}

impl Encode for WriteArgs<'_> {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.file.encode(encoder)?;
        encoder.write_u64(self.offset);
        encoder.write_u32(self.count);
        self.stable.encode(encoder)?;
        encoder.write_opaque(self.data, MAX_IO_BYTES)
    }
}

pub(crate) struct CreateArgs<'a> {
    pub(crate) where_: Diropargs<'a>,
    pub(crate) how: &'a CreateHow,
}

impl Encode for CreateArgs<'_> {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.where_.encode(encoder)?;
        self.how.encode(encoder)
    }
}

pub(crate) struct MkdirArgs<'a> {
    pub(crate) where_: Diropargs<'a>,
    pub(crate) attributes: &'a SetAttr,
}

impl Encode for MkdirArgs<'_> {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.where_.encode(encoder)?;
        self.attributes.encode(encoder)
    }
}

pub(crate) struct SymlinkArgs<'a> {
    pub(crate) where_: Diropargs<'a>,
    pub(crate) target: &'a str,
    pub(crate) attributes: &'a SetAttr,
}

impl Encode for SymlinkArgs<'_> {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.where_.encode(encoder)?;
        self.attributes.encode(encoder)?;
        encoder.write_string(self.target, MAX_PATH_BYTES)
    }
}

pub(crate) struct MknodArgs<'a> {
    pub(crate) where_: Diropargs<'a>,
    pub(crate) what: &'a MknodData,
}

impl Encode for MknodArgs<'_> {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.where_.encode(encoder)?;
        self.what.encode(encoder)
    }
}

pub(crate) struct RenameArgs<'a> {
    pub(crate) from: Diropargs<'a>,
    pub(crate) to: Diropargs<'a>,
}

impl Encode for RenameArgs<'_> {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.from.encode(encoder)?;
        self.to.encode(encoder)
    }
}

pub(crate) struct LinkArgs<'a> {
    pub(crate) file: &'a FileHandle,
    pub(crate) link: Diropargs<'a>,
}

impl Encode for LinkArgs<'_> {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.file.encode(encoder)?;
        self.link.encode(encoder)
    }
}

pub(crate) struct ReadDirArgs<'a> {
    pub(crate) dir: &'a FileHandle,
    pub(crate) cookie: u64,
    pub(crate) cookieverf: CookieVerf,
    pub(crate) count: u32,
}

impl Encode for ReadDirArgs<'_> {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.dir.encode(encoder)?;
        encoder.write_u64(self.cookie);
        encoder.write_fixed_opaque(&self.cookieverf);
        encoder.write_u32(self.count);
        Ok(())
    }
}

pub(crate) struct ReadDirPlusArgs<'a> {
    pub(crate) dir: &'a FileHandle,
    pub(crate) cookie: u64,
    pub(crate) cookieverf: CookieVerf,
    pub(crate) dircount: u32,
    pub(crate) maxcount: u32,
}

impl Encode for ReadDirPlusArgs<'_> {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.dir.encode(encoder)?;
        encoder.write_u64(self.cookie);
        encoder.write_fixed_opaque(&self.cookieverf);
        encoder.write_u32(self.dircount);
        encoder.write_u32(self.maxcount);
        Ok(())
    }
}

pub(crate) struct CommitArgs<'a> {
    pub(crate) file: &'a FileHandle,
    pub(crate) offset: u64,
    pub(crate) count: u32,
}

impl Encode for CommitArgs<'_> {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.file.encode(encoder)?;
        encoder.write_u64(self.offset);
        encoder.write_u32(self.count);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdr::to_bytes;

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

    #[test]
    fn detects_retryable_v3_status_payloads() {
        assert!(payload_has_status(
            &NfsStatus::Jukebox.as_u32().to_be_bytes(),
            NfsStatus::Jukebox
        ));
        assert!(!payload_has_status(
            &NfsStatus::Ok.as_u32().to_be_bytes(),
            NfsStatus::Jukebox
        ));
        assert!(!payload_has_status(&[0, 0, 0], NfsStatus::Jukebox));
    }

    #[test]
    fn decodes_optional_post_op_file_handles() {
        let mut decoder = Decoder::new(&[0, 0, 0, 0]);
        assert_eq!(decode_post_op_fh(&mut decoder).unwrap(), None);
        decoder.finish().unwrap();

        let mut decoder = Decoder::new(&[
            0, 0, 0, 1, // present
            0, 0, 0, 3, // opaque length
            1, 2, 3, 0, // opaque data and padding
        ]);
        assert_eq!(
            decode_post_op_fh(&mut decoder).unwrap(),
            Some(FileHandle::new(vec![1, 2, 3]).unwrap())
        );
        decoder.finish().unwrap();
    }

    #[test]
    fn validates_read_result_size_against_request() {
        assert!(validate_read_result_size(8, 4, 4, false).is_ok());
        assert!(matches!(
            validate_read_result_size(8, 4, 3, false),
            Err(Error::Protocol(_))
        ));
        assert!(matches!(
            validate_read_result_size(4, 8, 8, false),
            Err(Error::Protocol(_))
        ));
        assert!(matches!(
            validate_read_result_size(8, 0, 0, false),
            Err(Error::Protocol(_))
        ));
        assert!(validate_read_result_size(8, 0, 0, true).is_ok());
    }

    #[test]
    fn validates_write_result_count_against_request() {
        assert!(validate_write_result_count(8, 4).is_ok());
        assert!(validate_write_result_count(8, 8).is_ok());
        assert!(validate_write_result_count(0, 0).is_ok());
        assert!(matches!(
            validate_write_result_count(4, 8),
            Err(Error::Protocol(_))
        ));
        assert!(matches!(
            validate_write_result_count(4, 0),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn rfc1813_procedure_numbers_match_spec() {
        let procedures = [
            (NFSPROC3_NULL, 0),
            (NFSPROC3_GETATTR, 1),
            (NFSPROC3_SETATTR, 2),
            (NFSPROC3_LOOKUP, 3),
            (NFSPROC3_ACCESS, 4),
            (NFSPROC3_READLINK, 5),
            (NFSPROC3_READ, 6),
            (NFSPROC3_WRITE, 7),
            (NFSPROC3_CREATE, 8),
            (NFSPROC3_MKDIR, 9),
            (NFSPROC3_SYMLINK, 10),
            (NFSPROC3_MKNOD, 11),
            (NFSPROC3_REMOVE, 12),
            (NFSPROC3_RMDIR, 13),
            (NFSPROC3_RENAME, 14),
            (NFSPROC3_LINK, 15),
            (NFSPROC3_READDIR, 16),
            (NFSPROC3_READDIRPLUS, 17),
            (NFSPROC3_FSSTAT, 18),
            (NFSPROC3_FSINFO, 19),
            (NFSPROC3_PATHCONF, 20),
            (NFSPROC3_COMMIT, 21),
        ];

        for (actual, expected) in procedures {
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn rfc1813_readdirplus_args_wire_format() {
        let handle = FileHandle::new(vec![1, 2]).unwrap();
        let args = ReadDirPlusArgs {
            dir: &handle,
            cookie: 3,
            cookieverf: [4; NFS3_COOKIEVERFSIZE],
            dircount: 5,
            maxcount: 6,
        };

        assert_eq!(
            to_bytes(&args).unwrap(),
            vec![
                0, 0, 0, 2, 1, 2, 0, 0, // file handle
                0, 0, 0, 0, 0, 0, 0, 3, // cookie
                4, 4, 4, 4, 4, 4, 4, 4, // cookie verifier
                0, 0, 0, 5, // dircount
                0, 0, 0, 6, // maxcount
            ]
        );
    }

    #[test]
    fn rfc1813_commit_args_wire_format() {
        let handle = FileHandle::new(vec![9]).unwrap();
        let args = CommitArgs {
            file: &handle,
            offset: 0x0102_0304_0506_0708,
            count: 4096,
        };

        assert_eq!(
            to_bytes(&args).unwrap(),
            vec![
                0, 0, 0, 1, 9, 0, 0, 0, // file handle
                1, 2, 3, 4, 5, 6, 7, 8, // offset
                0, 0, 0x10, 0, // count
            ]
        );
    }
}
