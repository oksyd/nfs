//! Tokio NFSv3 client.
//!
//! This module mirrors the blocking NFSv3 client with `async fn` methods and
//! Tokio I/O traits. Paths are interpreted relative to the mounted export.
//!
//! ```no_run
//! # async fn run() -> nfs::Result<()> {
//! let mut client = nfs::v3::tokio::Client::connect("127.0.0.1:/export").await?;
//! client.write("/object.txt", b"payload").await?;
//! let bytes = client.read("/object.txt").await?;
//! assert_eq!(bytes, b"payload");
//! # Ok(())
//! # }
//! ```

use std::cmp;
use std::time::Duration;

use ::tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use ::tokio::net::ToSocketAddrs;

use crate::error::{Error, Result};
use crate::retry::RetryPolicy;
use crate::rpc::{Auth, AuthSys, max_record_size_for_payloads};
use crate::tokio_rpc::RpcClient;
use crate::v3::client::{
    advance_offset, append_dir_entries, clamp_dir_size, clamp_io_size, cleanup_error,
    dir_page_from_batch, ensure_distinct_copy_handles, join_path, next_dir_cursor, normalize_path,
    temporary_sibling_path, validate_host, validate_max_dir_entries, validate_port,
    validate_remote_target, validate_transfer_size,
};
use crate::v3::mount::{
    Export, MNTPATHLEN, MOUNT_PROGRAM, MOUNT_VERSION, MountEntry, MountInfo, MountStatus,
    decode_export_list, decode_mount_list,
};
use crate::v3::portmap::{IPPROTO_TCP, PMAP_PORT, PMAP_PROGRAM, PMAP_VERSION};
use crate::v3::proto::{
    self as nfs3, AccessResult, CommitArgs, CommitResult, CookieVerf, CreateArgs, CreateHow,
    CreateResult, Diropargs, FileAttr, FileHandle, FileType, FsInfo, FsStat, LinkArgs, LinkResult,
    MAX_DIR_ENTRIES, MAX_IO_BYTES, MAX_PATH_BYTES, MkdirArgs, MknodArgs, MknodData, NFS_PORT,
    NFS_PROGRAM, NFS_VERSION, NFS3_WRITEVERFSIZE, NfsStatus, NfsTime, PathConf, ReadArgs,
    ReadDirArgs, ReadDirPlusArgs, ReadDirResult, ReadResult, RenameArgs, SetAttr, SetattrArgs,
    SpecData, StableHow, SymlinkArgs, WccData, WriteArgs, WriteResult,
};
use crate::xdr::{Decode, Decoder, Encode, Encoder};

pub use crate::v3::client::{DirEntry, DirPage, DirPageCursor, RemoteTarget};

const DEFAULT_IO_SIZE: u32 = 128 * 1024;
const DEFAULT_DIR_SIZE: u32 = 128 * 1024;

/// Lists exports advertised by an NFSv3 server's MOUNT service.
///
/// This queries `MOUNTPROC3_EXPORT` using the default 30 second socket timeout
/// and discovers the MOUNT service port through portmapper.
pub async fn list_exports(host: &str) -> Result<Vec<Export>> {
    list_exports_with_timeout(host, Some(Duration::from_secs(30))).await
}

/// Lists exports advertised by an NFSv3 server's MOUNT service.
///
/// `None` disables socket timeouts. The MOUNT service port is discovered
/// through portmapper.
pub async fn list_exports_with_timeout(
    host: &str,
    timeout: Option<Duration>,
) -> Result<Vec<Export>> {
    list_exports_with_optional_mount_port(host, None, timeout).await
}

/// Lists exports using an explicit MOUNT service port.
pub async fn list_exports_with_mount_port(
    host: &str,
    mount_port: u16,
    timeout: Option<Duration>,
) -> Result<Vec<Export>> {
    let mut mount = connect_mount_client(host, Some(mount_port), timeout).await?;
    mount.exports().await
}

/// Lists current MOUNT records advertised by an NFSv3 server.
///
/// This queries `MOUNTPROC3_DUMP` using the default 30 second socket timeout.
pub async fn list_mounts(host: &str) -> Result<Vec<MountEntry>> {
    list_mounts_with_timeout(host, Some(Duration::from_secs(30))).await
}

/// Lists current MOUNT records advertised by an NFSv3 server.
///
/// `None` disables socket timeouts. The MOUNT service port is discovered
/// through portmapper.
pub async fn list_mounts_with_timeout(
    host: &str,
    timeout: Option<Duration>,
) -> Result<Vec<MountEntry>> {
    list_mounts_with_optional_mount_port(host, None, timeout).await
}

/// Lists current MOUNT records using an explicit MOUNT service port.
pub async fn list_mounts_with_mount_port(
    host: &str,
    mount_port: u16,
    timeout: Option<Duration>,
) -> Result<Vec<MountEntry>> {
    let mut mount = connect_mount_client(host, Some(mount_port), timeout).await?;
    mount.dump().await
}

/// Sends `MOUNTPROC3_UMNT` for a `host:/export` target.
pub async fn unmount(target: &str) -> Result<()> {
    unmount_with_timeout(target, Some(Duration::from_secs(30))).await
}

/// Sends `MOUNTPROC3_UMNT` for a `host:/export` target.
///
/// `None` disables socket timeouts. The MOUNT service port is discovered
/// through portmapper.
pub async fn unmount_with_timeout(target: &str, timeout: Option<Duration>) -> Result<()> {
    unmount_with_optional_mount_port(target, None, timeout).await
}

/// Sends `MOUNTPROC3_UMNT` using an explicit MOUNT service port.
pub async fn unmount_with_mount_port(
    target: &str,
    mount_port: u16,
    timeout: Option<Duration>,
) -> Result<()> {
    unmount_with_optional_mount_port(target, Some(mount_port), timeout).await
}

/// Sends `MOUNTPROC3_UMNTALL` to a server's MOUNT service.
pub async fn unmount_all(host: &str) -> Result<()> {
    unmount_all_with_timeout(host, Some(Duration::from_secs(30))).await
}

/// Sends `MOUNTPROC3_UMNTALL` to a server's MOUNT service.
///
/// `None` disables socket timeouts. The MOUNT service port is discovered
/// through portmapper.
pub async fn unmount_all_with_timeout(host: &str, timeout: Option<Duration>) -> Result<()> {
    unmount_all_with_optional_mount_port(host, None, timeout).await
}

/// Sends `MOUNTPROC3_UMNTALL` using an explicit MOUNT service port.
pub async fn unmount_all_with_mount_port(
    host: &str,
    mount_port: u16,
    timeout: Option<Duration>,
) -> Result<()> {
    unmount_all_with_optional_mount_port(host, Some(mount_port), timeout).await
}

async fn list_exports_with_optional_mount_port(
    host: &str,
    mount_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<Vec<Export>> {
    let mut mount = connect_mount_client(host, mount_port, timeout).await?;
    mount.exports().await
}

async fn list_mounts_with_optional_mount_port(
    host: &str,
    mount_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<Vec<MountEntry>> {
    let mut mount = connect_mount_client(host, mount_port, timeout).await?;
    mount.dump().await
}

async fn unmount_with_optional_mount_port(
    target: &str,
    mount_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<()> {
    let target = RemoteTarget::parse(target)?;
    let mut mount = connect_mount_client(&target.host, mount_port, timeout).await?;
    mount.unmount(&target.export).await
}

async fn unmount_all_with_optional_mount_port(
    host: &str,
    mount_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<()> {
    let mut mount = connect_mount_client(host, mount_port, timeout).await?;
    mount.unmount_all().await
}

async fn connect_mount_client(
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
        None => get_tcp_port_with_timeout(host, MOUNT_PROGRAM, MOUNT_VERSION, timeout).await?,
    };
    let mut mount =
        MountClient::connect_with_timeout((host, mount_port), AuthSys::current(), timeout).await?;
    mount.set_timeout(timeout);
    Ok(mount)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Mapping {
    pub program: u32,
    pub version: u32,
    pub protocol: u32,
    pub port: u32,
}

impl Mapping {
    pub(crate) fn tcp(program: u32, version: u32) -> Self {
        Self {
            program,
            version,
            protocol: IPPROTO_TCP,
            port: 0,
        }
    }
}

impl Encode for Mapping {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u32(self.program);
        encoder.write_u32(self.version);
        encoder.write_u32(self.protocol);
        encoder.write_u32(self.port);
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct PortmapperClient {
    rpc: RpcClient,
}

impl PortmapperClient {
    pub(crate) async fn connect_with_timeout<A: ToSocketAddrs>(
        addr: A,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        Ok(Self {
            rpc: RpcClient::connect_with_timeout(addr, Auth::none(), timeout).await?,
        })
    }

    pub(crate) async fn get_port(&mut self, mapping: Mapping) -> Result<u16> {
        let payload = self
            .rpc
            .call(PMAP_PROGRAM, PMAP_VERSION, 3, &mapping)
            .await?;
        let mut decoder = Decoder::new(&payload);
        let port = u32::decode(&mut decoder)?;
        decoder.finish()?;
        u16::try_from(port).map_err(|_| {
            Error::Protocol(format!(
                "portmapper returned out-of-range port {port} for program {} version {}",
                mapping.program, mapping.version
            ))
        })
    }
}

pub(crate) async fn get_tcp_port_with_timeout(
    host: &str,
    program: u32,
    version: u32,
    timeout: Option<Duration>,
) -> Result<u16> {
    let mut client = PortmapperClient::connect_with_timeout((host, PMAP_PORT), timeout).await?;
    let port = client.get_port(Mapping::tcp(program, version)).await?;
    if port == 0 {
        return Err(Error::PortUnavailable { program, version });
    }
    Ok(port)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirPath<'a>(&'a str);

impl Encode for DirPath<'_> {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_string(self.0, MNTPATHLEN)
    }
}

#[derive(Debug)]
pub(crate) struct MountClient {
    rpc: RpcClient,
}

impl MountClient {
    pub(crate) async fn connect_with_timeout<A: ToSocketAddrs>(
        addr: A,
        auth: AuthSys,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        Ok(Self {
            rpc: RpcClient::connect_with_timeout(addr, Auth::sys(auth), timeout).await?,
        })
    }

    pub(crate) fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.rpc.set_timeout(timeout);
    }

    pub(crate) async fn mount(&mut self, export_path: &str) -> Result<MountInfo> {
        let payload = self
            .rpc
            .call(MOUNT_PROGRAM, MOUNT_VERSION, 1, &DirPath(export_path))
            .await?;
        let mut decoder = Decoder::new(&payload);
        let status = MountStatus::from_u32(u32::decode(&mut decoder)?);
        if status != MountStatus::Ok {
            decoder.finish()?;
            return Err(Error::Mount { status });
        }

        let file_handle = FileHandle::decode(&mut decoder)?;
        let auth_flavors = decoder.read_array::<u32>(128)?;
        decoder.finish()?;
        Ok(MountInfo {
            file_handle,
            auth_flavors,
        })
    }

    pub(crate) async fn dump(&mut self) -> Result<Vec<MountEntry>> {
        let payload = self.rpc.call(MOUNT_PROGRAM, MOUNT_VERSION, 2, &()).await?;
        let mut decoder = Decoder::new(&payload);
        let mounts = decode_mount_list(&mut decoder)?;
        decoder.finish()?;
        Ok(mounts)
    }

    pub(crate) async fn unmount(&mut self, export_path: &str) -> Result<()> {
        let payload = self
            .rpc
            .call(MOUNT_PROGRAM, MOUNT_VERSION, 3, &DirPath(export_path))
            .await?;
        let decoder = Decoder::new(&payload);
        decoder.finish()?;
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) async fn unmount_all(&mut self) -> Result<()> {
        let payload = self.rpc.call(MOUNT_PROGRAM, MOUNT_VERSION, 4, &()).await?;
        let decoder = Decoder::new(&payload);
        decoder.finish()?;
        Ok(())
    }

    pub(crate) async fn exports(&mut self) -> Result<Vec<Export>> {
        let payload = self.rpc.call(MOUNT_PROGRAM, MOUNT_VERSION, 5, &()).await?;
        let mut decoder = Decoder::new(&payload);
        let exports = decode_export_list(&mut decoder)?;
        decoder.finish()?;
        Ok(exports)
    }
}

#[derive(Debug)]
pub(crate) struct Nfs3Client {
    rpc: RpcClient,
    retry_policy: RetryPolicy,
}

impl Nfs3Client {
    pub(crate) async fn connect_with_timeout<A: ToSocketAddrs>(
        addr: A,
        auth: AuthSys,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        Ok(Self {
            rpc: RpcClient::connect_with_timeout(addr, Auth::sys(auth), timeout).await?,
            retry_policy: RetryPolicy::default(),
        })
    }

    pub(crate) fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.rpc.set_timeout(timeout);
    }

    pub(crate) fn set_max_record_size(&mut self, max_record_size: usize) -> Result<()> {
        self.rpc.set_max_record_size(max_record_size)
    }

    pub(crate) fn set_retry_policy(&mut self, retry_policy: RetryPolicy) {
        self.retry_policy = retry_policy;
    }

    #[allow(dead_code)]
    pub async fn null(&mut self) -> Result<()> {
        let payload = self
            .rpc
            .call(NFS_PROGRAM, NFS_VERSION, nfs3::NFSPROC3_NULL, &())
            .await?;
        let decoder = Decoder::new(&payload);
        decoder.finish()?;
        Ok(())
    }

    pub async fn getattr(&mut self, object: &FileHandle) -> Result<FileAttr> {
        let payload = self.call(nfs3::NFSPROC3_GETATTR, object).await?;
        let mut decoder = Decoder::new(&payload);
        nfs3::require_ok(&mut decoder, "GETATTR")?;
        let attr = FileAttr::decode(&mut decoder)?;
        decoder.finish()?;
        Ok(attr)
    }

    pub async fn setattr(&mut self, object: &FileHandle, attr: &SetAttr) -> Result<WccData> {
        let payload = self
            .call(
                nfs3::NFSPROC3_SETATTR,
                &SetattrArgs {
                    object,
                    attr,
                    guard: None,
                },
            )
            .await?;
        let mut decoder = Decoder::new(&payload);
        let status = nfs3::decode_status(&mut decoder)?;
        let wcc = WccData::decode(&mut decoder)?;
        decoder.finish()?;
        if status == NfsStatus::Ok {
            Ok(wcc)
        } else {
            Err(Error::nfs("SETATTR", status))
        }
    }

    pub async fn lookup(
        &mut self,
        dir: &FileHandle,
        name: &str,
    ) -> Result<crate::v3::proto::LookupResult> {
        let payload = self
            .call(nfs3::NFSPROC3_LOOKUP, &Diropargs { dir, name })
            .await?;
        let mut decoder = Decoder::new(&payload);
        let status = nfs3::decode_status(&mut decoder)?;
        if status == NfsStatus::Ok {
            let result = crate::v3::proto::LookupResult {
                object: FileHandle::decode(&mut decoder)?,
                object_attributes: nfs3::decode_post_op_attr(&mut decoder)?,
                directory_attributes: nfs3::decode_post_op_attr(&mut decoder)?,
            };
            decoder.finish()?;
            Ok(result)
        } else {
            let _directory_attributes = nfs3::decode_post_op_attr(&mut decoder)?;
            decoder.finish()?;
            Err(Error::nfs("LOOKUP", status))
        }
    }

    pub async fn access(&mut self, object: &FileHandle, access: u32) -> Result<AccessResult> {
        let payload = self
            .call(
                nfs3::NFSPROC3_ACCESS,
                &crate::v3::proto::AccessArgs { object, access },
            )
            .await?;
        let mut decoder = Decoder::new(&payload);
        let status = nfs3::decode_status(&mut decoder)?;
        let object_attributes = nfs3::decode_post_op_attr(&mut decoder)?;
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

    pub async fn readlink(&mut self, symlink: &FileHandle) -> Result<String> {
        let payload = self.call(nfs3::NFSPROC3_READLINK, symlink).await?;
        let mut decoder = Decoder::new(&payload);
        let status = nfs3::decode_status(&mut decoder)?;
        let _symlink_attributes = nfs3::decode_post_op_attr(&mut decoder)?;
        if status == NfsStatus::Ok {
            let data = decoder.read_string(MAX_PATH_BYTES)?;
            decoder.finish()?;
            Ok(data)
        } else {
            decoder.finish()?;
            Err(Error::nfs("READLINK", status))
        }
    }

    pub async fn read(&mut self, file: &FileHandle, offset: u64, count: u32) -> Result<ReadResult> {
        let requested_count = count;
        let payload = self
            .call(
                nfs3::NFSPROC3_READ,
                &ReadArgs {
                    file,
                    offset,
                    count,
                },
            )
            .await?;
        let mut decoder = Decoder::new(&payload);
        let status = nfs3::decode_status(&mut decoder)?;
        let file_attributes = nfs3::decode_post_op_attr(&mut decoder)?;
        if status == NfsStatus::Ok {
            let returned_count = u32::decode(&mut decoder)?;
            let eof = bool::decode(&mut decoder)?;
            let data = decoder.read_opaque_vec(MAX_IO_BYTES)?;
            decoder.finish()?;
            nfs3::validate_read_result_size(requested_count, returned_count, data.len(), eof)?;
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

    pub async fn write(
        &mut self,
        file: &FileHandle,
        offset: u64,
        stable: StableHow,
        data: &[u8],
    ) -> Result<WriteResult> {
        let requested_count =
            u32::try_from(data.len()).map_err(|_| Error::LengthOutOfRange { len: data.len() })?;
        let payload = self
            .call(
                nfs3::NFSPROC3_WRITE,
                &WriteArgs {
                    file,
                    offset,
                    count: requested_count,
                    stable,
                    data,
                },
            )
            .await?;
        let mut decoder = Decoder::new(&payload);
        let status = nfs3::decode_status(&mut decoder)?;
        let file_wcc = WccData::decode(&mut decoder)?;
        if status == NfsStatus::Ok {
            let returned_count = u32::decode(&mut decoder)?;
            let committed = StableHow::decode(&mut decoder)?;
            let verifier = nfs3::decode_writeverf(&mut decoder)?;
            decoder.finish()?;
            nfs3::validate_write_result_count(requested_count, returned_count)?;
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

    pub async fn create(
        &mut self,
        dir: &FileHandle,
        name: &str,
        how: &CreateHow,
    ) -> Result<CreateResult> {
        self.create_like(
            nfs3::NFSPROC3_CREATE,
            "CREATE",
            &CreateArgs {
                where_: Diropargs { dir, name },
                how,
            },
        )
        .await
    }

    pub async fn mkdir(
        &mut self,
        dir: &FileHandle,
        name: &str,
        attributes: &SetAttr,
    ) -> Result<CreateResult> {
        self.create_like(
            nfs3::NFSPROC3_MKDIR,
            "MKDIR",
            &MkdirArgs {
                where_: Diropargs { dir, name },
                attributes,
            },
        )
        .await
    }

    pub async fn symlink(
        &mut self,
        dir: &FileHandle,
        name: &str,
        target: &str,
        attributes: &SetAttr,
    ) -> Result<CreateResult> {
        self.create_like(
            nfs3::NFSPROC3_SYMLINK,
            "SYMLINK",
            &SymlinkArgs {
                where_: Diropargs { dir, name },
                target,
                attributes,
            },
        )
        .await
    }

    #[allow(dead_code)]
    pub async fn mknod(
        &mut self,
        dir: &FileHandle,
        name: &str,
        what: &MknodData,
    ) -> Result<CreateResult> {
        self.create_like(
            nfs3::NFSPROC3_MKNOD,
            "MKNOD",
            &MknodArgs {
                where_: Diropargs { dir, name },
                what,
            },
        )
        .await
    }

    pub async fn remove(&mut self, dir: &FileHandle, name: &str) -> Result<WccData> {
        self.wcc_only(nfs3::NFSPROC3_REMOVE, "REMOVE", &Diropargs { dir, name })
            .await
    }

    pub async fn rmdir(&mut self, dir: &FileHandle, name: &str) -> Result<WccData> {
        self.wcc_only(nfs3::NFSPROC3_RMDIR, "RMDIR", &Diropargs { dir, name })
            .await
    }

    pub async fn rename(
        &mut self,
        from_dir: &FileHandle,
        from_name: &str,
        to_dir: &FileHandle,
        to_name: &str,
    ) -> Result<crate::v3::proto::RenameResult> {
        let payload = self
            .call(
                nfs3::NFSPROC3_RENAME,
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
            )
            .await?;
        let mut decoder = Decoder::new(&payload);
        let status = nfs3::decode_status(&mut decoder)?;
        let result = crate::v3::proto::RenameResult {
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

    pub async fn link(
        &mut self,
        file: &FileHandle,
        link_dir: &FileHandle,
        link_name: &str,
    ) -> Result<LinkResult> {
        let payload = self
            .call(
                nfs3::NFSPROC3_LINK,
                &LinkArgs {
                    file,
                    link: Diropargs {
                        dir: link_dir,
                        name: link_name,
                    },
                },
            )
            .await?;
        let mut decoder = Decoder::new(&payload);
        let status = nfs3::decode_status(&mut decoder)?;
        let result = LinkResult {
            file_attributes: nfs3::decode_post_op_attr(&mut decoder)?,
            linkdir_wcc: WccData::decode(&mut decoder)?,
        };
        decoder.finish()?;
        if status == NfsStatus::Ok {
            Ok(result)
        } else {
            Err(Error::nfs("LINK", status))
        }
    }

    pub async fn readdir(
        &mut self,
        dir: &FileHandle,
        cookie: u64,
        cookieverf: CookieVerf,
        count: u32,
    ) -> Result<ReadDirResult> {
        let payload = self
            .call(
                nfs3::NFSPROC3_READDIR,
                &ReadDirArgs {
                    dir,
                    cookie,
                    cookieverf,
                    count,
                },
            )
            .await?;
        let mut decoder = Decoder::new(&payload);
        let status = nfs3::decode_status(&mut decoder)?;
        let directory_attributes = nfs3::decode_post_op_attr(&mut decoder)?;
        if status != NfsStatus::Ok {
            decoder.finish()?;
            return Err(Error::nfs("READDIR", status));
        }

        let cookieverf = nfs3::decode_cookieverf(&mut decoder)?;
        let entries = nfs3::decode_dir_entries(&mut decoder, false)?;
        let eof = bool::decode(&mut decoder)?;
        decoder.finish()?;
        Ok(ReadDirResult {
            directory_attributes,
            cookieverf,
            entries,
            eof,
        })
    }

    pub async fn readdirplus(
        &mut self,
        dir: &FileHandle,
        cookie: u64,
        cookieverf: CookieVerf,
        dircount: u32,
        maxcount: u32,
    ) -> Result<ReadDirResult> {
        let payload = self
            .call(
                nfs3::NFSPROC3_READDIRPLUS,
                &ReadDirPlusArgs {
                    dir,
                    cookie,
                    cookieverf,
                    dircount,
                    maxcount,
                },
            )
            .await?;
        let mut decoder = Decoder::new(&payload);
        let status = nfs3::decode_status(&mut decoder)?;
        let directory_attributes = nfs3::decode_post_op_attr(&mut decoder)?;
        if status != NfsStatus::Ok {
            decoder.finish()?;
            return Err(Error::nfs("READDIRPLUS", status));
        }

        let cookieverf = nfs3::decode_cookieverf(&mut decoder)?;
        let entries = nfs3::decode_dir_entries(&mut decoder, true)?;
        let eof = bool::decode(&mut decoder)?;
        decoder.finish()?;
        Ok(ReadDirResult {
            directory_attributes,
            cookieverf,
            entries,
            eof,
        })
    }

    pub async fn fsstat(&mut self, fsroot: &FileHandle) -> Result<FsStat> {
        let payload = self.call(nfs3::NFSPROC3_FSSTAT, fsroot).await?;
        let mut decoder = Decoder::new(&payload);
        let status = nfs3::decode_status(&mut decoder)?;
        let object_attributes = nfs3::decode_post_op_attr(&mut decoder)?;
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

    pub async fn fsinfo(&mut self, fsroot: &FileHandle) -> Result<FsInfo> {
        let payload = self.call(nfs3::NFSPROC3_FSINFO, fsroot).await?;
        let mut decoder = Decoder::new(&payload);
        let status = nfs3::decode_status(&mut decoder)?;
        let object_attributes = nfs3::decode_post_op_attr(&mut decoder)?;
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
                time_delta: crate::v3::proto::NfsTime::decode(&mut decoder)?,
                properties: u32::decode(&mut decoder)?,
            };
            decoder.finish()?;
            Ok(result)
        } else {
            decoder.finish()?;
            Err(Error::nfs("FSINFO", status))
        }
    }

    pub async fn pathconf(&mut self, object: &FileHandle) -> Result<PathConf> {
        let payload = self.call(nfs3::NFSPROC3_PATHCONF, object).await?;
        let mut decoder = Decoder::new(&payload);
        let status = nfs3::decode_status(&mut decoder)?;
        let object_attributes = nfs3::decode_post_op_attr(&mut decoder)?;
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

    pub async fn commit(
        &mut self,
        file: &FileHandle,
        offset: u64,
        count: u32,
    ) -> Result<CommitResult> {
        let payload = self
            .call(
                nfs3::NFSPROC3_COMMIT,
                &CommitArgs {
                    file,
                    offset,
                    count,
                },
            )
            .await?;
        let mut decoder = Decoder::new(&payload);
        let status = nfs3::decode_status(&mut decoder)?;
        let result = CommitResult {
            file_wcc: WccData::decode(&mut decoder)?,
            verifier: if status == NfsStatus::Ok {
                nfs3::decode_writeverf(&mut decoder)?
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

    async fn create_like<T: Encode + ?Sized>(
        &mut self,
        procedure_id: u32,
        procedure_name: &'static str,
        args: &T,
    ) -> Result<CreateResult> {
        let payload = self.call(procedure_id, args).await?;
        let mut decoder = Decoder::new(&payload);
        let status = nfs3::decode_status(&mut decoder)?;
        if status == NfsStatus::Ok {
            let result = CreateResult {
                object: nfs3::decode_post_op_fh(&mut decoder)?,
                object_attributes: nfs3::decode_post_op_attr(&mut decoder)?,
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

    async fn wcc_only<T: Encode + ?Sized>(
        &mut self,
        procedure_id: u32,
        procedure_name: &'static str,
        args: &T,
    ) -> Result<WccData> {
        let payload = self.call(procedure_id, args).await?;
        let mut decoder = Decoder::new(&payload);
        let status = nfs3::decode_status(&mut decoder)?;
        let wcc = WccData::decode(&mut decoder)?;
        decoder.finish()?;
        if status == NfsStatus::Ok {
            Ok(wcc)
        } else {
            Err(Error::nfs(procedure_name, status))
        }
    }

    async fn call<T: Encode + ?Sized>(&mut self, procedure: u32, args: &T) -> Result<Vec<u8>> {
        let mut retry = 0;
        loop {
            let payload = self
                .rpc
                .call(NFS_PROGRAM, NFS_VERSION, procedure, args)
                .await?;
            if procedure != nfs3::NFSPROC3_NULL
                && nfs3::payload_has_status(&payload, NfsStatus::Jukebox)
                && let Some(delay) = self.retry_policy.delay_for_retry(retry)
            {
                retry += 1;
                ::tokio::time::sleep(delay).await;
                continue;
            }
            return Ok(payload);
        }
    }
}

/// Builder for a Tokio NFSv3 [`Client`].
///
/// It has the same configuration model as
/// [`crate::v3::blocking::ClientBuilder`], but connects asynchronously.
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
    pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the MOUNT service port explicitly.
    pub fn mount_port(mut self, port: u16) -> Self {
        self.mount_port = Some(port);
        self
    }

    /// Sets the NFS service port explicitly.
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
    pub async fn connect(self) -> Result<Client> {
        Client::connect_with_builder(self).await
    }
}

/// Tokio, path-oriented NFSv3 client.
///
/// This client owns the asynchronous MOUNT and NFS connections. Its methods
/// mirror [`crate::v3::blocking::Client`] and use Tokio reader/writer traits
/// for streaming operations.
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
    pub async fn connect(target: &str) -> Result<Self> {
        ClientBuilder::from_target(target)?.connect().await
    }

    /// Creates a builder from host and export components.
    pub fn builder(host: impl Into<String>, export: impl Into<String>) -> ClientBuilder {
        ClientBuilder::new(host, export)
    }

    /// Returns filesystem information discovered at connect time, if available.
    pub fn fsinfo(&self) -> Option<&FsInfo> {
        self.fsinfo.as_ref()
    }

    pub fn root_fsinfo(&self) -> Option<&FsInfo> {
        self.fsinfo()
    }

    /// Reconnects using the original builder configuration.
    pub async fn reconnect(&mut self) -> Result<()> {
        *self = Self::connect_with_builder(self.builder.clone()).await?;
        Ok(())
    }

    pub async fn path_fsinfo(&mut self, path: &str) -> Result<FsInfo> {
        let handle = self.resolve(path).await?;
        self.nfs.fsinfo(&handle).await
    }

    pub async fn fsstat(&mut self, path: &str) -> Result<FsStat> {
        let handle = self.resolve(path).await?;
        self.nfs.fsstat(&handle).await
    }

    pub async fn pathconf(&mut self, path: &str) -> Result<PathConf> {
        let handle = self.resolve(path).await?;
        self.nfs.pathconf(&handle).await
    }

    pub async fn file_handle(&mut self, path: &str) -> Result<FileHandle> {
        self.resolve(path).await
    }

    pub async fn parent_file_handle(&mut self, path: &str) -> Result<FileHandle> {
        let (handle, _) = self.resolve_parent(path).await?;
        Ok(handle)
    }

    pub async fn getattr(&mut self, path: &str) -> Result<FileAttr> {
        let handle = self.resolve(path).await?;
        self.nfs.getattr(&handle).await
    }

    pub async fn metadata(&mut self, path: &str) -> Result<FileAttr> {
        self.getattr(path).await
    }

    pub async fn parent_getattr(&mut self, path: &str) -> Result<FileAttr> {
        let handle = self.parent_file_handle(path).await?;
        self.nfs.getattr(&handle).await
    }

    pub async fn parent_metadata(&mut self, path: &str) -> Result<FileAttr> {
        self.parent_getattr(path).await
    }

    pub async fn file_type(&mut self, path: &str) -> Result<FileType> {
        Ok(self.metadata(path).await?.file_type)
    }

    pub async fn is_file(&mut self, path: &str) -> Result<bool> {
        Ok(self.file_type(path).await?.is_file())
    }

    pub async fn is_dir(&mut self, path: &str) -> Result<bool> {
        Ok(self.file_type(path).await?.is_dir())
    }

    pub async fn is_symlink(&mut self, path: &str) -> Result<bool> {
        Ok(self.file_type(path).await?.is_symlink())
    }

    pub async fn access(&mut self, path: &str, access: u32) -> Result<AccessResult> {
        let handle = self.resolve(path).await?;
        self.nfs.access(&handle, access).await
    }

    pub async fn lookup(&mut self, path: &str) -> Result<()> {
        self.resolve(path).await.map(|_| ())
    }

    pub async fn exists(&mut self, path: &str) -> Result<bool> {
        match self.resolve(path).await {
            Ok(_) => Ok(true),
            Err(Error::Nfs {
                status: NfsStatus::NoEnt,
                ..
            }) => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub async fn read(&mut self, path: &str) -> Result<Vec<u8>> {
        let handle = self.resolve(path).await?;
        self.read_handle_to_end(&handle).await
    }

    pub async fn read_to_writer<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        path: &str,
        writer: &mut W,
    ) -> Result<u64> {
        let handle = self.resolve(path).await?;
        self.read_handle_to_writer(&handle, writer).await
    }

    pub async fn read_range_to_writer<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        path: &str,
        offset: u64,
        count: u64,
        writer: &mut W,
    ) -> Result<u64> {
        let handle = self.resolve(path).await?;
        self.read_handle_range_to_writer(&handle, offset, count, writer)
            .await
    }

    pub async fn read_range(&mut self, path: &str, offset: u64, count: u64) -> Result<Vec<u8>> {
        let handle = self.resolve(path).await?;
        self.read_handle_range(&handle, offset, count).await
    }

    pub async fn read_at(&mut self, path: &str, offset: u64, count: u32) -> Result<Vec<u8>> {
        let handle = self.resolve(path).await?;
        self.read_handle_at(&handle, offset, count).await
    }

    pub async fn read_exact_at(&mut self, path: &str, offset: u64, count: u32) -> Result<Vec<u8>> {
        let data = self.read_at(path, offset, count).await?;
        if data.len() != count as usize {
            return Err(Error::Protocol(format!(
                "READ returned {} bytes before EOF; expected {count}",
                data.len()
            )));
        }
        Ok(data)
    }

    pub async fn read_link(&mut self, path: &str) -> Result<String> {
        let handle = self.resolve(path).await?;
        self.nfs.readlink(&handle).await
    }

    pub async fn write(&mut self, path: &str, data: &[u8]) -> Result<()> {
        self.write_with_stability(path, data, StableHow::FileSync)
            .await
    }

    pub async fn write_with_stability(
        &mut self,
        path: &str,
        data: &[u8],
        stable: StableHow,
    ) -> Result<()> {
        let handle = match self.resolve(path).await {
            Ok(handle) => handle,
            Err(Error::Nfs {
                status: NfsStatus::NoEnt,
                ..
            }) => {
                self.create_handle_with_how(
                    path,
                    CreateHow::Unchecked(SetAttr {
                        mode: Some(0o644),
                        ..SetAttr::default()
                    }),
                )
                .await?
            }
            Err(err) => return Err(err),
        };

        self.nfs.setattr(&handle, &SetAttr::size(0)).await?;
        self.write_handle_all(&handle, 0, data, stable).await
    }

    pub async fn write_from_reader<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
    ) -> Result<u64> {
        self.write_from_reader_with_stability(path, reader, StableHow::FileSync)
            .await
    }

    pub async fn write_from_reader_with_stability<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
        stable: StableHow,
    ) -> Result<u64> {
        let handle = match self.resolve(path).await {
            Ok(handle) => handle,
            Err(Error::Nfs {
                status: NfsStatus::NoEnt,
                ..
            }) => {
                self.create_handle_with_how(
                    path,
                    CreateHow::Unchecked(SetAttr {
                        mode: Some(0o644),
                        ..SetAttr::default()
                    }),
                )
                .await?
            }
            Err(err) => return Err(err),
        };

        self.nfs.setattr(&handle, &SetAttr::size(0)).await?;
        self.write_handle_from_reader(&handle, reader, stable).await
    }

    pub async fn write_atomic(&mut self, path: &str, data: &[u8]) -> Result<()> {
        self.write_atomic_with_mode_and_stability(path, data, 0o644, StableHow::FileSync)
            .await
    }

    pub async fn write_atomic_with_mode(
        &mut self,
        path: &str,
        data: &[u8],
        mode: u32,
    ) -> Result<()> {
        self.write_atomic_with_mode_and_stability(path, data, mode, StableHow::FileSync)
            .await
    }

    pub async fn write_atomic_with_stability(
        &mut self,
        path: &str,
        data: &[u8],
        stable: StableHow,
    ) -> Result<()> {
        self.write_atomic_with_mode_and_stability(path, data, 0o644, stable)
            .await
    }

    pub async fn write_atomic_with_mode_and_stability(
        &mut self,
        path: &str,
        data: &[u8],
        mode: u32,
        stable: StableHow,
    ) -> Result<()> {
        let temp = temporary_sibling_path(path)?;
        let mut created = false;

        let result = match self.create_guarded_handle(&temp, mode, &mut created).await {
            Ok(handle) => match self.write_handle_all(&handle, 0, data, stable).await {
                Ok(()) => self.rename(&temp, path).await,
                Err(err) => Err(err),
            },
            Err(err) => Err(err),
        };

        self.finish_with_temp_cleanup(
            result,
            created,
            &temp,
            "cleanup REMOVE after failed atomic write",
        )
        .await
    }

    pub async fn write_atomic_from_reader<R: AsyncRead + Unpin + ?Sized>(
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
        .await
    }

    pub async fn write_atomic_from_reader_with_mode<R: AsyncRead + Unpin + ?Sized>(
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
        .await
    }

    pub async fn write_atomic_from_reader_with_stability<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
        stable: StableHow,
    ) -> Result<u64> {
        self.write_atomic_from_reader_with_mode_and_stability(path, reader, 0o644, stable)
            .await
    }

    pub async fn write_atomic_from_reader_with_mode_and_stability<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
        mode: u32,
        stable: StableHow,
    ) -> Result<u64> {
        let temp = temporary_sibling_path(path)?;
        let mut created = false;

        let result = match self.create_guarded_handle(&temp, mode, &mut created).await {
            Ok(handle) => match self.write_handle_from_reader(&handle, reader, stable).await {
                Ok(written) => match self.rename(&temp, path).await {
                    Ok(()) => Ok(written),
                    Err(err) => Err(err),
                },
                Err(err) => Err(err),
            },
            Err(err) => Err(err),
        };

        self.finish_with_temp_cleanup(
            result,
            created,
            &temp,
            "cleanup REMOVE after failed atomic reader write",
        )
        .await
    }

    pub async fn append(&mut self, path: &str, data: &[u8]) -> Result<u64> {
        self.append_with_stability(path, data, StableHow::FileSync)
            .await
    }

    pub async fn append_with_stability(
        &mut self,
        path: &str,
        data: &[u8],
        stable: StableHow,
    ) -> Result<u64> {
        let handle = self.resolve(path).await?;
        let attr = self.nfs.getattr(&handle).await?;
        self.write_handle_all(&handle, attr.size, data, stable)
            .await?;
        let mut written = 0;
        advance_offset(&mut written, data.len(), "APPEND")?;
        Ok(written)
    }

    pub async fn append_from_reader<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
    ) -> Result<u64> {
        self.append_from_reader_with_stability(path, reader, StableHow::FileSync)
            .await
    }

    pub async fn append_from_reader_with_stability<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
        stable: StableHow,
    ) -> Result<u64> {
        let handle = self.resolve(path).await?;
        let attr = self.nfs.getattr(&handle).await?;
        self.write_handle_from_reader_at(&handle, attr.size, reader, stable)
            .await
    }

    pub async fn truncate(&mut self, path: &str, size: u64) -> Result<()> {
        let handle = self.resolve(path).await?;
        self.nfs.setattr(&handle, &SetAttr::size(size)).await?;
        Ok(())
    }

    pub async fn setattr(&mut self, path: &str, attr: &SetAttr) -> Result<()> {
        let handle = self.resolve(path).await?;
        self.nfs.setattr(&handle, attr).await?;
        Ok(())
    }

    pub async fn set_mode(&mut self, path: &str, mode: u32) -> Result<()> {
        self.setattr(path, &SetAttr::mode(mode)).await
    }

    pub async fn set_uid(&mut self, path: &str, uid: u32) -> Result<()> {
        self.setattr(path, &SetAttr::uid(uid)).await
    }

    pub async fn set_gid(&mut self, path: &str, gid: u32) -> Result<()> {
        self.setattr(path, &SetAttr::gid(gid)).await
    }

    pub async fn set_ownership(&mut self, path: &str, uid: u32, gid: u32) -> Result<()> {
        self.setattr(path, &SetAttr::ownership(uid, gid)).await
    }

    pub async fn set_times(
        &mut self,
        path: &str,
        atime: Option<NfsTime>,
        mtime: Option<NfsTime>,
    ) -> Result<()> {
        self.setattr(path, &SetAttr::times(atime, mtime)).await
    }

    pub async fn touch(&mut self, path: &str) -> Result<()> {
        self.setattr(path, &SetAttr::touch()).await
    }

    pub async fn write_at(&mut self, path: &str, offset: u64, data: &[u8]) -> Result<()> {
        self.write_at_with_stability(path, offset, data, StableHow::FileSync)
            .await
    }

    pub async fn write_at_with_stability(
        &mut self,
        path: &str,
        offset: u64,
        data: &[u8],
        stable: StableHow,
    ) -> Result<()> {
        let handle = self.resolve(path).await?;
        self.write_handle_all(&handle, offset, data, stable).await
    }

    pub async fn copy(&mut self, from: &str, to: &str) -> Result<u64> {
        self.copy_with_stability(from, to, StableHow::FileSync)
            .await
    }

    pub async fn copy_with_stability(
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
        let source = self.resolve(from).await?;
        let source_attr = self.nfs.getattr(&source).await?;
        let target = match self.resolve(to).await {
            Ok(handle) => handle,
            Err(Error::Nfs {
                status: NfsStatus::NoEnt,
                ..
            }) => {
                self.create_handle_with_how(
                    to,
                    CreateHow::Unchecked(SetAttr {
                        mode: Some(source_attr.mode & 0o7777),
                        ..SetAttr::default()
                    }),
                )
                .await?
            }
            Err(err) => return Err(err),
        };
        ensure_distinct_copy_handles(&source, &target)?;

        self.nfs.setattr(&target, &SetAttr::size(0)).await?;
        self.copy_handles(&source, &target, stable).await
    }

    pub async fn copy_atomic(&mut self, from: &str, to: &str) -> Result<u64> {
        self.copy_atomic_with_stability(from, to, StableHow::FileSync)
            .await
    }

    pub async fn copy_atomic_with_stability(
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
        let source = self.resolve(from).await?;
        let source_attr = self.nfs.getattr(&source).await?;
        let temp = temporary_sibling_path(to)?;
        let mut created = false;

        let result = match self
            .create_guarded_handle(&temp, source_attr.mode & 0o7777, &mut created)
            .await
        {
            Ok(target) => match self.copy_handles(&source, &target, stable).await {
                Ok(copied) => match self.rename(&temp, to).await {
                    Ok(()) => Ok(copied),
                    Err(err) => Err(err),
                },
                Err(err) => Err(err),
            },
            Err(err) => Err(err),
        };

        self.finish_with_temp_cleanup(
            result,
            created,
            &temp,
            "cleanup REMOVE after failed atomic copy",
        )
        .await
    }

    pub async fn commit(&mut self, path: &str, offset: u64, count: u32) -> Result<CommitResult> {
        let handle = self.resolve(path).await?;
        self.nfs.commit(&handle, offset, count).await
    }

    pub async fn create(&mut self, path: &str, mode: u32) -> Result<()> {
        self.create_new(path, mode).await
    }

    pub async fn create_new(&mut self, path: &str, mode: u32) -> Result<()> {
        self.create_handle_new(path, mode).await.map(|_| ())
    }

    pub async fn create_unchecked(&mut self, path: &str, mode: u32) -> Result<()> {
        self.create_handle_with_how(
            path,
            CreateHow::Unchecked(SetAttr {
                mode: Some(mode),
                ..SetAttr::default()
            }),
        )
        .await
        .map(|_| ())
    }

    async fn create_handle_new(&mut self, path: &str, mode: u32) -> Result<FileHandle> {
        let mut created = false;
        self.create_guarded_handle(path, mode, &mut created).await
    }

    async fn create_handle_with_how(&mut self, path: &str, how: CreateHow) -> Result<FileHandle> {
        let (parent, name) = self.resolve_parent(path).await?;
        let result = self.nfs.create(&parent, &name, &how).await?;
        self.handle_from_create_result(&parent, &name, result).await
    }

    async fn create_guarded_handle(
        &mut self,
        path: &str,
        mode: u32,
        created: &mut bool,
    ) -> Result<FileHandle> {
        let (parent, name) = self.resolve_parent(path).await?;
        let result = self
            .nfs
            .create(&parent, &name, &CreateHow::Guarded(SetAttr::mode(mode)))
            .await?;
        *created = true;
        self.handle_from_create_result(&parent, &name, result).await
    }

    async fn handle_from_create_result(
        &mut self,
        parent: &FileHandle,
        name: &str,
        result: CreateResult,
    ) -> Result<FileHandle> {
        match result.object {
            Some(handle) => Ok(handle),
            None => Ok(self.nfs.lookup(parent, name).await?.object),
        }
    }

    async fn finish_with_temp_cleanup<T>(
        &mut self,
        result: Result<T>,
        created: bool,
        temp: &str,
        cleanup_context: &'static str,
    ) -> Result<T> {
        match result {
            Ok(value) => Ok(value),
            Err(err) if created => {
                Err(cleanup_error(err, cleanup_context, self.remove(temp).await))
            }
            Err(err) => Err(err),
        }
    }

    pub async fn mkdir(&mut self, path: &str, mode: u32) -> Result<()> {
        let (parent, name) = self.resolve_parent(path).await?;
        self.nfs.mkdir(&parent, &name, &SetAttr::mode(mode)).await?;
        Ok(())
    }

    pub async fn create_dir_all(&mut self, path: &str, mode: u32) -> Result<()> {
        let components = normalize_path(path)?;
        let mut current = self.root.clone();
        let mut current_path = String::from("/");

        for component in components {
            current_path = join_path(&current_path, component);
            match self.nfs.lookup(&current, component).await {
                Ok(lookup) => {
                    self.ensure_directory(&current_path, &lookup.object, lookup.object_attributes)
                        .await?;
                    current = lookup.object;
                }
                Err(Error::Nfs {
                    status: NfsStatus::NoEnt,
                    ..
                }) => match self
                    .nfs
                    .mkdir(&current, component, &SetAttr::mode(mode))
                    .await
                {
                    Ok(created) => {
                        current = match created.object {
                            Some(handle) => handle,
                            None => self.nfs.lookup(&current, component).await?.object,
                        };
                    }
                    Err(Error::Nfs {
                        status: NfsStatus::Exist,
                        ..
                    }) => {
                        let lookup = self.nfs.lookup(&current, component).await?;
                        self.ensure_directory(
                            &current_path,
                            &lookup.object,
                            lookup.object_attributes,
                        )
                        .await?;
                        current = lookup.object;
                    }
                    Err(err) => return Err(err),
                },
                Err(err) => return Err(err),
            }
        }

        Ok(())
    }

    pub async fn symlink(&mut self, path: &str, target: &str) -> Result<()> {
        let (parent, name) = self.resolve_parent(path).await?;
        self.nfs
            .symlink(&parent, &name, target, &SetAttr::default())
            .await?;
        Ok(())
    }

    pub async fn create_fifo(&mut self, path: &str, mode: u32) -> Result<()> {
        self.mknod(
            path,
            MknodData::Fifo {
                attributes: SetAttr::mode(mode),
            },
        )
        .await
    }

    pub async fn create_socket(&mut self, path: &str, mode: u32) -> Result<()> {
        self.mknod(
            path,
            MknodData::Socket {
                attributes: SetAttr::mode(mode),
            },
        )
        .await
    }

    pub async fn create_block_device(
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
        .await
    }

    pub async fn create_character_device(
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
        .await
    }

    async fn mknod(&mut self, path: &str, what: MknodData) -> Result<()> {
        let (parent, name) = self.resolve_parent(path).await?;
        self.nfs.mknod(&parent, &name, &what).await?;
        Ok(())
    }

    pub async fn hard_link(&mut self, existing: &str, link: &str) -> Result<()> {
        let file = self.resolve(existing).await?;
        let (link_dir, link_name) = self.resolve_parent(link).await?;
        self.nfs.link(&file, &link_dir, &link_name).await?;
        Ok(())
    }

    pub async fn remove(&mut self, path: &str) -> Result<()> {
        let (parent, name) = self.resolve_parent(path).await?;
        self.nfs.remove(&parent, &name).await?;
        Ok(())
    }

    pub async fn remove_if_exists(&mut self, path: &str) -> Result<bool> {
        match self.remove(path).await {
            Ok(()) => Ok(true),
            Err(err) if err.is_not_found() => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub async fn rmdir(&mut self, path: &str) -> Result<()> {
        let (parent, name) = self.resolve_parent(path).await?;
        self.nfs.rmdir(&parent, &name).await?;
        Ok(())
    }

    pub async fn rmdir_if_exists(&mut self, path: &str) -> Result<bool> {
        match self.rmdir(path).await {
            Ok(()) => Ok(true),
            Err(err) if err.is_not_found() => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub async fn remove_all(&mut self, path: &str) -> Result<()> {
        if normalize_path(path)?.is_empty() {
            return Err(Error::InvalidPath(path.to_owned()));
        }

        enum RemoveTask {
            Visit(String, Option<FileType>),
            RemoveDir(String),
        }

        let file_type = self.metadata(path).await?.file_type;
        let mut stack = vec![RemoveTask::Visit(path.to_owned(), Some(file_type))];
        while let Some(task) = stack.pop() {
            match task {
                RemoveTask::Visit(path, file_type) => {
                    let file_type = match file_type {
                        Some(file_type) => file_type,
                        None => self.metadata(&path).await?.file_type,
                    };
                    if file_type == FileType::Directory {
                        stack.push(RemoveTask::RemoveDir(path.clone()));
                        let entries = self.read_dir(&path).await?;
                        for entry in entries.into_iter().rev() {
                            if entry.name == "." || entry.name == ".." {
                                continue;
                            }
                            let child = join_path(&path, &entry.name);
                            let child_type = entry.attributes.map(|attr| attr.file_type);
                            stack.push(RemoveTask::Visit(child, child_type));
                        }
                    } else {
                        self.remove(&path).await?;
                    }
                }
                RemoveTask::RemoveDir(path) => self.rmdir(&path).await?,
            }
        }

        Ok(())
    }

    pub async fn remove_all_if_exists(&mut self, path: &str) -> Result<bool> {
        match self.remove_all(path).await {
            Ok(()) => Ok(true),
            Err(err) if err.is_not_found() => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub async fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        let (from_parent, from_name) = self.resolve_parent(from).await?;
        let (to_parent, to_name) = self.resolve_parent(to).await?;
        self.nfs
            .rename(&from_parent, &from_name, &to_parent, &to_name)
            .await?;
        Ok(())
    }

    pub async fn read_dir(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        self.read_dir_with_limit(path, self.max_dir_entries).await
    }

    pub async fn read_dir_limited(
        &mut self,
        path: &str,
        max_entries: usize,
    ) -> Result<Vec<DirEntry>> {
        validate_max_dir_entries(max_entries)?;
        self.read_dir_with_limit(path, max_entries.min(self.max_dir_entries))
            .await
    }

    pub async fn read_dir_page(
        &mut self,
        path: &str,
        cursor: Option<DirPageCursor>,
    ) -> Result<DirPage> {
        self.read_dir_page_limited(path, cursor, self.max_dir_entries)
            .await
    }

    pub async fn read_dir_page_limited(
        &mut self,
        path: &str,
        cursor: Option<DirPageCursor>,
        max_entries: usize,
    ) -> Result<DirPage> {
        validate_max_dir_entries(max_entries)?;
        let max_entries = max_entries.min(self.max_dir_entries);
        let dir = self.resolve(path).await?;
        let cursor = cursor.unwrap_or_default();
        let batch = match self
            .nfs
            .readdirplus(
                &dir,
                cursor.cookie,
                cursor.cookieverf,
                self.dir_size,
                self.dir_size,
            )
            .await
        {
            Ok(batch) => batch,
            Err(Error::Nfs {
                status: NfsStatus::NotSupported,
                ..
            }) => {
                self.nfs
                    .readdir(&dir, cursor.cookie, cursor.cookieverf, self.dir_size)
                    .await?
            }
            Err(err) => return Err(err),
        };
        dir_page_from_batch(&batch, cursor.cookie, max_entries)
    }

    async fn read_dir_with_limit(
        &mut self,
        path: &str,
        max_entries: usize,
    ) -> Result<Vec<DirEntry>> {
        let dir = self.resolve(path).await?;
        let mut entries = Vec::new();
        let mut cookie = 0;
        let mut cookieverf = [0; 8];

        loop {
            let batch = match self
                .nfs
                .readdirplus(&dir, cookie, cookieverf, self.dir_size, self.dir_size)
                .await
            {
                Ok(batch) => batch,
                Err(Error::Nfs {
                    status: NfsStatus::NotSupported,
                    ..
                }) => {
                    self.nfs
                        .readdir(&dir, cookie, cookieverf, self.dir_size)
                        .await?
                }
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

    pub async fn unmount(self) -> Result<()> {
        let mut mount = MountClient::connect_with_timeout(
            (self.target.host.as_str(), self.mount_port),
            self.auth.clone(),
            self.builder.timeout,
        )
        .await?;
        mount.set_timeout(self.builder.timeout);
        mount.unmount(&self.target.export).await
    }

    async fn connect_with_builder(builder: ClientBuilder) -> Result<Self> {
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
            None => {
                get_tcp_port_with_timeout(
                    &builder.target.host,
                    MOUNT_PROGRAM,
                    MOUNT_VERSION,
                    builder.timeout,
                )
                .await?
            }
        };

        let mut mount = MountClient::connect_with_timeout(
            (builder.target.host.as_str(), mount_port),
            builder.auth.clone(),
            builder.timeout,
        )
        .await?;
        mount.set_timeout(builder.timeout);
        let mount_info = mount.mount(&builder.target.export).await?;
        let cleanup_mount_context = "cleanup UMOUNT after failed NFSv3 connect";

        let nfs_port = match builder.nfs_port {
            Some(port) => {
                if let Err(err) = validate_port("nfs_port", port) {
                    return Err(cleanup_error(
                        err,
                        cleanup_mount_context,
                        mount.unmount(&builder.target.export).await,
                    ));
                }
                port
            }
            None => get_tcp_port_with_timeout(
                &builder.target.host,
                NFS_PROGRAM,
                NFS_VERSION,
                builder.timeout,
            )
            .await
            .unwrap_or(NFS_PORT),
        };

        let mut nfs = match Nfs3Client::connect_with_timeout(
            (builder.target.host.as_str(), nfs_port),
            builder.auth.clone(),
            builder.timeout,
        )
        .await
        {
            Ok(nfs) => nfs,
            Err(err) => {
                return Err(cleanup_error(
                    err,
                    cleanup_mount_context,
                    mount.unmount(&builder.target.export).await,
                ));
            }
        };
        nfs.set_timeout(builder.timeout);
        nfs.set_retry_policy(builder.retry_policy);

        let fsinfo = match nfs.fsinfo(&mount_info.file_handle).await {
            Ok(fsinfo) => fsinfo,
            Err(err) => {
                return Err(cleanup_error(
                    err,
                    cleanup_mount_context,
                    mount.unmount(&builder.target.export).await,
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
                mount.unmount(&builder.target.export).await,
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

    async fn resolve(&mut self, path: &str) -> Result<FileHandle> {
        let components = normalize_path(path)?;
        let mut current = self.root.clone();
        for component in components {
            current = self.nfs.lookup(&current, component).await?.object;
        }
        Ok(current)
    }

    async fn resolve_parent(&mut self, path: &str) -> Result<(FileHandle, String)> {
        let mut components = normalize_path(path)?;
        let name = components
            .pop()
            .ok_or_else(|| Error::InvalidPath(path.to_owned()))?
            .to_owned();
        let mut current = self.root.clone();
        for component in components {
            current = self.nfs.lookup(&current, component).await?.object;
        }
        Ok((current, name))
    }

    async fn ensure_directory(
        &mut self,
        path: &str,
        handle: &FileHandle,
        attr: Option<FileAttr>,
    ) -> Result<()> {
        let attr = match attr {
            Some(attr) => attr,
            None => self.nfs.getattr(handle).await?,
        };
        if attr.file_type == FileType::Directory {
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "{path:?} exists but is not a directory"
            )))
        }
    }

    async fn read_handle_to_end(&mut self, handle: &FileHandle) -> Result<Vec<u8>> {
        let mut offset = 0;
        let mut out = Vec::new();
        loop {
            let chunk = self.nfs.read(handle, offset, self.read_size).await?;
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

    async fn read_handle_to_writer<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        handle: &FileHandle,
        writer: &mut W,
    ) -> Result<u64> {
        let mut offset = 0;
        let mut total = 0;
        loop {
            let chunk = self.nfs.read(handle, offset, self.read_size).await?;
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
            writer.write_all(&chunk.data).await?;
            advance_offset(&mut offset, chunk.data.len(), "READ")?;
            advance_offset(&mut total, chunk.data.len(), "READ total")?;
            if chunk.eof {
                return Ok(total);
            }
        }
    }

    async fn read_handle_at(
        &mut self,
        handle: &FileHandle,
        offset: u64,
        count: u32,
    ) -> Result<Vec<u8>> {
        self.read_handle_range(handle, offset, u64::from(count))
            .await
    }

    async fn read_handle_range(
        &mut self,
        handle: &FileHandle,
        offset: u64,
        count: u64,
    ) -> Result<Vec<u8>> {
        let capacity = usize::try_from(count).unwrap_or(usize::MAX);
        let mut out = Vec::with_capacity(capacity.min(self.read_size as usize));
        self.read_handle_range_to_writer(handle, offset, count, &mut out)
            .await?;
        Ok(out)
    }

    async fn read_handle_range_to_writer<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        handle: &FileHandle,
        mut offset: u64,
        mut remaining: u64,
        writer: &mut W,
    ) -> Result<u64> {
        let mut total = 0;
        while remaining > 0 {
            let request = cmp::min(u64::from(self.read_size), remaining) as u32;
            let chunk = self.nfs.read(handle, offset, request).await?;
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
            writer.write_all(&chunk.data).await?;
            advance_offset(&mut offset, chunk.data.len(), "READ")?;
            advance_offset(&mut total, chunk.data.len(), "READ total")?;
            remaining -= chunk.data.len() as u64;
            if chunk.eof {
                return Ok(total);
            }
        }
        Ok(total)
    }

    async fn write_handle_all(
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
                .write(handle, chunk_offset, stable, &data[..chunk_len])
                .await?;
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
                let commit = self.nfs.commit(handle, chunk_offset, result.count).await?;
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

    async fn write_handle_from_reader<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        handle: &FileHandle,
        reader: &mut R,
        stable: StableHow,
    ) -> Result<u64> {
        self.write_handle_from_reader_at(handle, 0, reader, stable)
            .await
    }

    async fn write_handle_from_reader_at<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        handle: &FileHandle,
        mut offset: u64,
        reader: &mut R,
        stable: StableHow,
    ) -> Result<u64> {
        let mut written = 0;
        let mut buffer = vec![0; self.write_size as usize];
        loop {
            let read = reader.read(&mut buffer).await?;
            if read == 0 {
                return Ok(written);
            }
            self.write_handle_all(handle, offset, &buffer[..read], stable)
                .await?;
            advance_offset(&mut offset, read, "WRITE reader")?;
            advance_offset(&mut written, read, "WRITE reader total")?;
        }
    }

    async fn copy_handles(
        &mut self,
        source: &FileHandle,
        target: &FileHandle,
        stable: StableHow,
    ) -> Result<u64> {
        let mut offset = 0;
        loop {
            let chunk = self.nfs.read(source, offset, self.read_size).await?;
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
            self.write_handle_all(target, offset, &chunk.data, stable)
                .await?;
            advance_offset(&mut offset, chunk.data.len(), "COPY")?;
            if chunk.eof {
                return Ok(offset);
            }
        }
    }
}
