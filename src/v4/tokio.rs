//! Tokio NFSv4 client.
//!
//! This module mirrors the blocking NFSv4 client with `async fn` methods and
//! Tokio I/O traits. Paths are absolute paths in the server's v4
//! pseudo-filesystem.
//!
//! ```no_run
//! # async fn run() -> nfs::Result<()> {
//! let mut client = nfs::v4::tokio::Client::connect("127.0.0.1").await?;
//! client.write("/export/object.txt", b"payload").await?;
//! let bytes = client.read("/export/object.txt").await?;
//! assert_eq!(bytes, b"payload");
//! client.shutdown().await?;
//! # Ok(())
//! # }
//! ```

use std::time::Duration;

use ::tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};
use crate::retry::RetryPolicy;
use crate::rpc::{Auth, AuthSys, max_record_size_for_payloads};
use crate::tokio_rpc::RpcClient;
use crate::v4::client::{
    CopyOffloadOptions, SpaceOp, advance_offset, app_data_block_len, attrs_require_open_state,
    cleanup_error, device_list_page_from_result, dir_page_from_entries,
    ensure_distinct_copy_handles, ensure_last_status, ensure_reclaim_complete, finish_with_close,
    io_advice_bitmap, io_advice_share_access, join_path, layout_iomode_share_access,
    lock_share_access, named_attr_ops, next_dir_cursor, open_cleanup_error,
    operations_can_replay_after_session_recovery, parent_path_ops, path_components, path_ops,
    public_path_ops, response_access, response_allows_delayed_retry,
    response_allows_delayed_retry_without_sequence, response_bind_conn_to_session, response_commit,
    response_consumed_owner_seqid, response_copy, response_copy_notify, response_create_session,
    response_exchange_id, response_get_device_info, response_get_device_list,
    response_get_dir_delegation, response_getattr, response_getfh, response_io_advise,
    response_layout_commit, response_layout_get, response_layout_return, response_lock,
    response_lock_test, response_lock_unlock, response_offload_status, response_open,
    response_openattr_readdir, response_operation_has_delayed_status,
    response_operation_requires_session_recovery, response_read, response_read_plus,
    response_readdir, response_readlink, response_release_lock_owner,
    response_requires_session_recovery, response_secinfo, response_seek, response_set_ssv,
    response_test_stateids, response_verify, response_want_delegation, response_write,
    response_write_same, sequence_succeeded, session_max_operations, session_payload_limit,
    session_recovery_error, split_parent, temporary_named_attr_name, temporary_sibling_path,
    validate_compound_response_shape, validate_max_device_ids, validate_named_attr_name,
    validate_open_result, validate_session_channel_attrs,
    validate_session_compound_operation_count, validate_stateid_batch_len, verifier_from_time,
};
use crate::v4::proto::*;
use crate::v4::{
    clamp_io_size, default_lock_owner, default_open_owner, default_owner_id,
    negotiated_minor_versions, require_minor_version, validate_host, validate_lock_owner,
    validate_max_dir_entries, validate_minor_version, validate_open_owner, validate_owner_id,
    validate_port, validate_transfer_size,
};
use crate::xdr::{Decode, Decoder};

const DEFAULT_IO_SIZE: u32 = 128 * 1024;
const DEFAULT_DIR_SIZE: u32 = 128 * 1024;

pub use crate::v4::client::{
    ByteRangeLock, DeviceListCursor, DeviceListPage, DirEntry, DirPage, DirPageCursor,
};

/// Builder for a Tokio NFSv4 [`Client`].
///
/// It has the same configuration model as
/// [`crate::v4::blocking::ClientBuilder`], but connects asynchronously.
#[derive(Debug, Clone)]
pub struct ClientBuilder {
    host: String,
    auth: AuthSys,
    timeout: Option<Duration>,
    port: u16,
    owner_id: Vec<u8>,
    open_owner: Vec<u8>,
    client_owner_verifier: Verifier,
    read_size: u32,
    write_size: u32,
    dir_size: u32,
    max_dir_entries: usize,
    max_minor_version: u32,
    retry_policy: RetryPolicy,
}

impl ClientBuilder {
    /// Creates a builder for an NFSv4 server host.
    pub fn new(host: impl Into<String>) -> Self {
        let host = host.into();
        Self {
            owner_id: default_owner_id(&host),
            open_owner: default_open_owner(&host),
            client_owner_verifier: verifier_from_time(),
            host,
            auth: AuthSys::current(),
            timeout: Some(Duration::from_secs(30)),
            port: NFS4_PORT,
            read_size: DEFAULT_IO_SIZE,
            write_size: DEFAULT_IO_SIZE,
            dir_size: DEFAULT_DIR_SIZE,
            max_dir_entries: NFS4_MAX_DIR_ENTRIES,
            max_minor_version: NFS4_MINOR_VERSION_LATEST,
            retry_policy: RetryPolicy::default(),
        }
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

    /// Sets the NFSv4 TCP port.
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Sets the client owner id used during `EXCHANGE_ID`.
    pub fn owner_id(mut self, owner_id: impl Into<Vec<u8>>) -> Self {
        self.owner_id = owner_id.into();
        self
    }

    /// Sets the open owner id used for `OPEN` sequencing.
    pub fn open_owner(mut self, open_owner: impl Into<Vec<u8>>) -> Self {
        self.open_owner = open_owner.into();
        self
    }

    /// Sets the client owner verifier used during `EXCHANGE_ID`.
    pub fn client_owner_verifier(mut self, verifier: Verifier) -> Self {
        self.client_owner_verifier = verifier;
        self
    }

    /// Sets both read and write transfer limits.
    pub fn io_size(mut self, size: u32) -> Self {
        self.read_size = size;
        self.write_size = size;
        self
    }

    /// Sets the read transfer limit.
    pub fn read_size(mut self, size: u32) -> Self {
        self.read_size = size;
        self
    }

    /// Sets the write transfer limit.
    pub fn write_size(mut self, size: u32) -> Self {
        self.write_size = size;
        self
    }

    /// Sets the maximum READDIR response size requested.
    pub fn dir_size(mut self, size: u32) -> Self {
        self.dir_size = size;
        self
    }

    /// Sets the maximum number of directory entries a single high-level call may collect.
    pub fn max_dir_entries(mut self, max_dir_entries: usize) -> Self {
        self.max_dir_entries = max_dir_entries;
        self
    }

    /// Sets the highest NFSv4 minor version the client may negotiate.
    ///
    /// The session client supports NFSv4.1 and NFSv4.2. By default it tries
    /// NFSv4.2 first and falls back to NFSv4.1 when the server rejects the
    /// newer minor version.
    pub fn max_minor_version(mut self, minor_version: u32) -> Self {
        self.max_minor_version = minor_version;
        self
    }

    /// Sets retry behavior for retryable transport and protocol responses.
    pub fn retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    /// Connects, creates an NFSv4 session, and returns a ready client.
    pub async fn connect(self) -> Result<Client> {
        Client::connect_with_builder(self).await
    }
}

/// Tokio, path-oriented NFSv4 client.
///
/// This client owns an asynchronous NFSv4 session and mirrors the high-level
/// operations provided by [`crate::v4::blocking::Client`].
#[derive(Debug)]
pub struct Client {
    rpc: RpcClient,
    builder: ClientBuilder,
    client_id: u64,
    session_id: SessionId,
    sequence_id: u32,
    open_seqid: u32,
    open_owner: Vec<u8>,
    minor_version: u32,
    max_operations: usize,
    max_request_size: u32,
    max_response_size: u32,
    root_fsinfo: Option<FsInfo>,
    read_size: u32,
    write_size: u32,
    dir_size: u32,
    max_dir_entries: usize,
    retry_policy: RetryPolicy,
}

impl Client {
    /// Connects to an NFSv4 server using default builder options.
    pub async fn connect(host: impl Into<String>) -> Result<Self> {
        ClientBuilder::new(host).connect().await
    }

    /// Creates a builder for the given server host.
    pub fn builder(host: impl Into<String>) -> ClientBuilder {
        ClientBuilder::new(host)
    }

    /// Returns the negotiated NFSv4 minor version.
    pub fn minor_version(&self) -> u32 {
        self.minor_version
    }

    /// Resolves a path and returns success if it exists.
    pub async fn lookup(&mut self, path: &str) -> Result<()> {
        self.compound(path_ops(path, Vec::new())?).await.map(|_| ())
    }

    /// Resolves a path relative to the NFSv4 public filehandle.
    pub async fn lookup_public(&mut self, path: &str) -> Result<()> {
        self.compound(public_path_ops(path, Vec::new())?)
            .await
            .map(|_| ())
    }

    /// Returns whether a path exists relative to the NFSv4 public filehandle.
    pub async fn public_exists(&mut self, path: &str) -> Result<bool> {
        match self.lookup_public(path).await {
            Ok(_) => Ok(true),
            Err(Error::NfsV4 {
                status: Status::NoEnt,
                ..
            }) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Resolves a path and returns its NFSv4 file handle.
    pub async fn file_handle(&mut self, path: &str) -> Result<FileHandle> {
        let response = self
            .compound(path_ops(path, vec![Operation::GetFh])?)
            .await?;
        response_getfh(&response)
    }

    /// Resolves a path relative to the public filehandle and returns its file handle.
    pub async fn public_file_handle(&mut self, path: &str) -> Result<FileHandle> {
        let response = self
            .compound(public_path_ops(path, vec![Operation::GetFh])?)
            .await?;
        response_getfh(&response)
    }

    /// Resolves `path` and returns the file handle for its parent directory.
    pub async fn parent_file_handle(&mut self, path: &str) -> Result<FileHandle> {
        let response = self
            .compound(parent_path_ops(path, vec![Operation::GetFh])?)
            .await?;
        response_getfh(&response)
    }

    /// Returns whether a path exists.
    pub async fn exists(&mut self, path: &str) -> Result<bool> {
        match self.lookup(path).await {
            Ok(_) => Ok(true),
            Err(Error::NfsV4 {
                status: Status::NoEnt,
                ..
            }) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Reads basic attributes for a path relative to the NFSv4 public filehandle.
    pub async fn public_getattr(&mut self, path: &str) -> Result<BasicAttributes> {
        self.public_supported_attr_values(path, FATTR4_BASIC_ATTRS)
            .await?
            .parse_basic()
    }

    /// Returns the attribute bitmap supported for a public-filehandle path.
    pub async fn public_supported_attrs(&mut self, path: &str) -> Result<Bitmap> {
        let attrs = Bitmap::from_known_attrs(&[FATTR4_SUPPORTED_ATTRS]);
        let response = self
            .compound(public_path_ops(path, vec![Operation::GetAttr(attrs)])?)
            .await?;
        response_getattr(&response)?.parse_supported_attrs()
    }

    /// Reads raw NFSv4 attributes for a public-filehandle path.
    pub async fn public_getattr_values(
        &mut self,
        path: &str,
        attr_request: Bitmap,
    ) -> Result<Fattr> {
        if attr_request.is_empty() {
            return Ok(Fattr {
                attrmask: attr_request,
                attr_vals: Vec::new(),
            });
        }
        let response = self
            .compound(public_path_ops(
                path,
                vec![Operation::GetAttr(attr_request)],
            )?)
            .await?;
        response_getattr(&response)
    }

    /// Reads public-filehandle attributes after filtering the request by server support.
    pub async fn public_supported_attr_values(
        &mut self,
        path: &str,
        attrs: &[u32],
    ) -> Result<Fattr> {
        let supported = self.public_supported_attrs(path).await?;
        let attrs = Bitmap::from_supported_attrs(&supported, attrs)?;
        self.public_getattr_values(path, attrs).await
    }

    /// Reads all entries in a public-filehandle directory, subject to the client's entry limit.
    pub async fn public_read_dir(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        self.public_read_dir_with_limit(path, self.max_dir_entries)
            .await
    }

    /// Reads all entries in a public-filehandle directory with a per-call entry limit.
    pub async fn public_read_dir_limited(
        &mut self,
        path: &str,
        max_entries: usize,
    ) -> Result<Vec<DirEntry>> {
        validate_max_dir_entries(max_entries)?;
        self.public_read_dir_with_limit(path, max_entries.min(self.max_dir_entries))
            .await
    }

    /// Reads one page of public-filehandle directory entries.
    pub async fn public_read_dir_page(
        &mut self,
        path: &str,
        cursor: Option<DirPageCursor>,
    ) -> Result<DirPage> {
        self.public_read_dir_page_limited(path, cursor, self.max_dir_entries)
            .await
    }

    /// Reads one page of public-filehandle directory entries with a per-page entry limit.
    pub async fn public_read_dir_page_limited(
        &mut self,
        path: &str,
        cursor: Option<DirPageCursor>,
        max_entries: usize,
    ) -> Result<DirPage> {
        validate_max_dir_entries(max_entries)?;
        let max_entries = max_entries.min(self.max_dir_entries);
        let attr_request = self
            .public_supported_attr_request(path, FATTR4_BASIC_ATTRS)
            .await?;
        let cursor = cursor.unwrap_or_default();
        let response = self
            .compound(public_path_ops(
                path,
                vec![Operation::ReadDir {
                    cookie: cursor.cookie,
                    cookieverf: cursor.cookieverf,
                    dircount: (self.dir_size / 2).max(1),
                    maxcount: self.dir_size,
                    attr_request,
                }],
            )?)
            .await?;
        let (cookieverf, entries, eof) = response_readdir(&response)?;
        dir_page_from_entries(cookieverf, entries, eof, cursor.cookie, max_entries)
    }

    /// Reads filesystem capacity attributes for a public-filehandle path.
    pub async fn public_fsstat(&mut self, path: &str) -> Result<FsStat> {
        self.public_supported_attr_values(path, FATTR4_FSSTAT_ATTRS)
            .await?
            .parse_fsstat()
    }

    /// Reads filesystem capability attributes for a public-filehandle path.
    pub async fn public_fsinfo(&mut self, path: &str) -> Result<FsInfo> {
        self.public_supported_attr_values(path, FATTR4_FSINFO_ATTRS)
            .await?
            .parse_fsinfo()
    }

    /// Reads path configuration limits for a public-filehandle path.
    pub async fn public_pathconf(&mut self, path: &str) -> Result<PathConf> {
        self.public_supported_attr_values(path, FATTR4_PATHCONF_ATTRS)
            .await?
            .parse_pathconf()
    }

    /// Checks server-granted access bits for a public-filehandle path.
    pub async fn public_access(&mut self, path: &str, access: u32) -> Result<AccessResult> {
        let response = self
            .compound(public_path_ops(path, vec![Operation::Access(access)])?)
            .await?;
        response_access(&response)
    }

    /// Reads basic attributes for the parent filehandle of `path` using `LOOKUPP`.
    pub async fn parent_getattr(&mut self, path: &str) -> Result<BasicAttributes> {
        self.parent_supported_attr_values(path, FATTR4_BASIC_ATTRS)
            .await?
            .parse_basic()
    }

    /// Returns the attribute bitmap supported by the parent filehandle of `path`.
    pub async fn parent_supported_attrs(&mut self, path: &str) -> Result<Bitmap> {
        let attrs = Bitmap::from_known_attrs(&[FATTR4_SUPPORTED_ATTRS]);
        let response = self
            .compound(parent_path_ops(path, vec![Operation::GetAttr(attrs)])?)
            .await?;
        response_getattr(&response)?.parse_supported_attrs()
    }

    /// Reads raw attributes for the parent filehandle of `path`.
    pub async fn parent_getattr_values(
        &mut self,
        path: &str,
        attr_request: Bitmap,
    ) -> Result<Fattr> {
        if attr_request.is_empty() {
            return Ok(Fattr {
                attrmask: attr_request,
                attr_vals: Vec::new(),
            });
        }
        let response = self
            .compound(parent_path_ops(
                path,
                vec![Operation::GetAttr(attr_request)],
            )?)
            .await?;
        response_getattr(&response)
    }

    /// Reads parent filehandle attributes after filtering the request by server support.
    pub async fn parent_supported_attr_values(
        &mut self,
        path: &str,
        attrs: &[u32],
    ) -> Result<Fattr> {
        let supported = self.parent_supported_attrs(path).await?;
        let attrs = Bitmap::from_supported_attrs(&supported, attrs)?;
        self.parent_getattr_values(path, attrs).await
    }

    /// Reads all entries in the parent directory of `path`, subject to the client's entry limit.
    pub async fn parent_read_dir(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        self.parent_read_dir_with_limit(path, self.max_dir_entries)
            .await
    }

    /// Reads all entries in the parent directory of `path` with a per-call entry limit.
    pub async fn parent_read_dir_limited(
        &mut self,
        path: &str,
        max_entries: usize,
    ) -> Result<Vec<DirEntry>> {
        validate_max_dir_entries(max_entries)?;
        self.parent_read_dir_with_limit(path, max_entries.min(self.max_dir_entries))
            .await
    }

    /// Reads one page of entries from the parent directory of `path`.
    pub async fn parent_read_dir_page(
        &mut self,
        path: &str,
        cursor: Option<DirPageCursor>,
    ) -> Result<DirPage> {
        self.parent_read_dir_page_limited(path, cursor, self.max_dir_entries)
            .await
    }

    /// Reads one page of entries from the parent directory of `path` with a per-page entry limit.
    pub async fn parent_read_dir_page_limited(
        &mut self,
        path: &str,
        cursor: Option<DirPageCursor>,
        max_entries: usize,
    ) -> Result<DirPage> {
        validate_max_dir_entries(max_entries)?;
        let max_entries = max_entries.min(self.max_dir_entries);
        let attr_request = self
            .parent_supported_attr_request(path, FATTR4_BASIC_ATTRS)
            .await?;
        let cursor = cursor.unwrap_or_default();
        let response = self
            .compound(parent_path_ops(
                path,
                vec![Operation::ReadDir {
                    cookie: cursor.cookie,
                    cookieverf: cursor.cookieverf,
                    dircount: (self.dir_size / 2).max(1),
                    maxcount: self.dir_size,
                    attr_request,
                }],
            )?)
            .await?;
        let (cookieverf, entries, eof) = response_readdir(&response)?;
        dir_page_from_entries(cookieverf, entries, eof, cursor.cookie, max_entries)
    }

    /// Reads filesystem capacity attributes for the parent filehandle of `path`.
    pub async fn parent_fsstat(&mut self, path: &str) -> Result<FsStat> {
        self.parent_supported_attr_values(path, FATTR4_FSSTAT_ATTRS)
            .await?
            .parse_fsstat()
    }

    /// Reads filesystem capability attributes for the parent filehandle of `path`.
    pub async fn parent_fsinfo(&mut self, path: &str) -> Result<FsInfo> {
        self.parent_supported_attr_values(path, FATTR4_FSINFO_ATTRS)
            .await?
            .parse_fsinfo()
    }

    /// Reads path configuration limits for the parent filehandle of `path`.
    pub async fn parent_pathconf(&mut self, path: &str) -> Result<PathConf> {
        self.parent_supported_attr_values(path, FATTR4_PATHCONF_ATTRS)
            .await?
            .parse_pathconf()
    }

    /// Checks server-granted access bits for the parent filehandle of `path`.
    pub async fn parent_access(&mut self, path: &str, access: u32) -> Result<AccessResult> {
        let response = self
            .compound(parent_path_ops(path, vec![Operation::Access(access)])?)
            .await?;
        response_access(&response)
    }

    /// Reads basic attributes for a path.
    pub async fn getattr(&mut self, path: &str) -> Result<BasicAttributes> {
        self.get_supported_attr_values(path, FATTR4_BASIC_ATTRS)
            .await?
            .parse_basic()
    }

    /// Alias for [`Client::getattr`].
    pub async fn metadata(&mut self, path: &str) -> Result<BasicAttributes> {
        self.getattr(path).await
    }

    pub async fn file_type(&mut self, path: &str) -> Result<FileType> {
        self.metadata(path).await?.required_file_type()
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

    pub async fn supported_attrs(&mut self, path: &str) -> Result<Bitmap> {
        let attrs = Bitmap::from_known_attrs(&[FATTR4_SUPPORTED_ATTRS]);
        let response = self
            .compound(path_ops(path, vec![Operation::GetAttr(attrs)])?)
            .await?;
        response_getattr(&response)?.parse_supported_attrs()
    }

    pub async fn getattr_values(&mut self, path: &str, attr_request: Bitmap) -> Result<Fattr> {
        if attr_request.is_empty() {
            return Ok(Fattr {
                attrmask: attr_request,
                attr_vals: Vec::new(),
            });
        }
        let response = self
            .compound(path_ops(path, vec![Operation::GetAttr(attr_request)])?)
            .await?;
        response_getattr(&response)
    }

    pub async fn supported_attr_values(&mut self, path: &str, attrs: &[u32]) -> Result<Fattr> {
        self.get_supported_attr_values(path, attrs).await
    }

    pub async fn fsstat(&mut self, path: &str) -> Result<FsStat> {
        self.get_supported_attr_values(path, FATTR4_FSSTAT_ATTRS)
            .await?
            .parse_fsstat()
    }

    pub async fn fsinfo(&mut self, path: &str) -> Result<FsInfo> {
        self.get_supported_attr_values(path, FATTR4_FSINFO_ATTRS)
            .await?
            .parse_fsinfo()
    }

    pub async fn pathconf(&mut self, path: &str) -> Result<PathConf> {
        self.get_supported_attr_values(path, FATTR4_PATHCONF_ATTRS)
            .await?
            .parse_pathconf()
    }

    pub fn root_fsinfo(&self) -> Option<&FsInfo> {
        self.root_fsinfo.as_ref()
    }

    pub async fn reconnect(&mut self) -> Result<()> {
        self.recover_session().await?;
        self.refresh_root_fsinfo().await
    }

    /// Updates callback program and security parameters for the backchannel.
    pub async fn backchannel_ctl(
        &mut self,
        callback_program: u32,
        callback_sec_parms: Vec<CallbackSecParms>,
    ) -> Result<()> {
        let response = self
            .compound(vec![Operation::BackchannelCtl(BackchannelCtlArgs {
                callback_program,
                callback_sec_parms,
            })])
            .await?;
        self.ensure_status(response, "BACKCHANNEL_CTL")
    }

    /// Binds the current connection to the session for the requested direction.
    pub async fn bind_conn_to_session(
        &mut self,
        direction: ChannelDirFromClient,
    ) -> Result<BindConnToSessionResult> {
        self.bind_conn_to_session_with_options(direction, false)
            .await
    }

    /// Binds the current connection to the session with explicit RDMA mode.
    pub async fn bind_conn_to_session_with_options(
        &mut self,
        direction: ChannelDirFromClient,
        use_conn_in_rdma_mode: bool,
    ) -> Result<BindConnToSessionResult> {
        let response = self
            .raw_compound(
                "bind-conn-to-session",
                self.minor_version,
                vec![Operation::BindConnToSession(BindConnToSessionArgs {
                    session_id: self.session_id,
                    direction,
                    use_conn_in_rdma_mode,
                })],
            )
            .await?;
        response_bind_conn_to_session(&response)
    }

    /// Executes `SET_SSV` and returns the server digest.
    pub async fn set_ssv(&mut self, ssv: Vec<u8>, digest: Vec<u8>) -> Result<SetSsvResult> {
        let response = self
            .compound(vec![Operation::SetSsv(SetSsvArgs { ssv, digest })])
            .await?;
        response_set_ssv(&response)
    }

    async fn recover_session(&mut self) -> Result<()> {
        let previous_client_id = self.client_id;
        let previous_open_seqid = self.open_seqid;
        let previous_root_fsinfo = self.root_fsinfo.clone();

        let mut rebuilt = Self::connect_session(self.builder.clone()).await?;
        if rebuilt.client_id == previous_client_id {
            rebuilt.open_seqid = previous_open_seqid;
        }
        if let Some(fsinfo) = previous_root_fsinfo {
            rebuilt.apply_fsinfo_limits(&fsinfo)?;
            rebuilt.root_fsinfo = Some(fsinfo);
        }
        let old = std::mem::replace(self, rebuilt);
        let _ = old.shutdown().await;
        Ok(())
    }

    pub async fn access(&mut self, path: &str, access: u32) -> Result<AccessResult> {
        let response = self
            .compound(path_ops(path, vec![Operation::Access(access)])?)
            .await?;
        response_access(&response)
    }

    /// Returns security flavors accepted for `path` by querying its parent directory.
    pub async fn secinfo(&mut self, path: &str) -> Result<Vec<SecInfo>> {
        let (parent, name) = split_parent(path)?;
        let mut ops = vec![Operation::PutRootFh];
        for component in parent {
            ops.push(Operation::Lookup(component.to_owned()));
        }
        ops.push(Operation::SecInfo(name));
        let response = self.compound(ops).await?;
        response_secinfo(&response, OpCode::SecInfo)
    }

    /// Returns security flavors for the current or parent filehandle selected by `style`.
    pub async fn secinfo_no_name(
        &mut self,
        path: &str,
        style: SecInfoStyle,
    ) -> Result<Vec<SecInfo>> {
        let response = self
            .compound(path_ops(path, vec![Operation::SecInfoNoName(style)])?)
            .await?;
        response_secinfo(&response, OpCode::SecInfoNoName)
    }

    /// Returns security flavors accepted for `path` using `SECINFO_NO_NAME`.
    pub async fn secinfo_current(&mut self, path: &str) -> Result<Vec<SecInfo>> {
        self.secinfo_no_name(path, SecInfoStyle::CurrentFileHandle)
            .await
    }

    /// Returns security flavors accepted for the parent of `path` using `SECINFO_NO_NAME`.
    pub async fn secinfo_parent(&mut self, path: &str) -> Result<Vec<SecInfo>> {
        self.secinfo_no_name(path, SecInfoStyle::Parent).await
    }

    /// Verifies that the server attributes for `path` match `attrs`.
    ///
    /// Returns `Ok(true)` when the server returns `NFS4_OK`, `Ok(false)` when
    /// it returns `NFS4ERR_NOT_SAME`, and an error for other statuses.
    pub async fn verify_attrs(&mut self, path: &str, attrs: &Fattr) -> Result<bool> {
        let response = self
            .compound(path_ops(path, vec![Operation::Verify(attrs.clone())])?)
            .await?;
        response_verify(&response, OpCode::Verify, Status::NotSame)
    }

    /// Verifies that the server attributes for `path` do not match `attrs`.
    ///
    /// Returns `Ok(true)` when the server returns `NFS4_OK`, `Ok(false)` when
    /// it returns `NFS4ERR_SAME`, and an error for other statuses.
    pub async fn nverify_attrs(&mut self, path: &str, attrs: &Fattr) -> Result<bool> {
        let response = self
            .compound(path_ops(path, vec![Operation::NVerify(attrs.clone())])?)
            .await?;
        response_verify(&response, OpCode::NVerify, Status::Same)
    }

    /// Requests a read or write delegation for a path using the current filehandle claim.
    pub async fn want_delegation(&mut self, path: &str, want: u32) -> Result<OpenDelegation> {
        self.want_delegation_with_claim(path, want, DelegationClaim::FileHandle)
            .await
    }

    /// Requests a delegation for a path using an explicit delegation claim.
    pub async fn want_delegation_with_claim(
        &mut self,
        path: &str,
        want: u32,
        claim: DelegationClaim,
    ) -> Result<OpenDelegation> {
        require_minor_version(
            "WANT_DELEGATION",
            self.minor_version,
            NFS4_MINOR_VERSION_SESSION_MIN,
        )?;
        let response = self
            .compound(path_ops(
                path,
                vec![Operation::WantDelegation(WantDelegationArgs {
                    want,
                    claim,
                })],
            )?)
            .await?;
        response_want_delegation(&response)
    }

    /// Requests a directory delegation with explicit protocol arguments.
    pub async fn get_dir_delegation(
        &mut self,
        path: &str,
        args: GetDirDelegationArgs,
    ) -> Result<GetDirDelegationResult> {
        require_minor_version(
            "GET_DIR_DELEGATION",
            self.minor_version,
            NFS4_MINOR_VERSION_SESSION_MIN,
        )?;
        let response = self
            .compound(path_ops(path, vec![Operation::GetDirDelegation(args)])?)
            .await?;
        response_get_dir_delegation(&response)
    }

    /// Returns a delegation stateid for a path.
    pub async fn return_delegation(&mut self, path: &str, stateid: StateId) -> Result<()> {
        let response = self
            .compound(path_ops(path, vec![Operation::DelegReturn(stateid)])?)
            .await?;
        self.ensure_status(response, "DELEGRETURN")
    }

    /// Purges delegations for this client id.
    pub async fn purge_delegations(&mut self) -> Result<()> {
        let response = self
            .compound(vec![Operation::DelegPurge(self.client_id)])
            .await?;
        self.ensure_status(response, "DELEGPURGE")
    }

    /// Tests whether a byte-range lock would conflict with an existing lock.
    ///
    /// Returns `Ok(None)` when the server would grant the lock, or the
    /// conflicting lock details when the server returns `NFS4ERR_DENIED`.
    pub async fn test_lock(
        &mut self,
        path: &str,
        lock_type: LockType,
        offset: u64,
        length: u64,
    ) -> Result<Option<LockDenied>> {
        let owner = self.open_owner.clone();
        self.test_lock_with_owner(path, lock_type, offset, length, owner)
            .await
    }

    /// Tests a byte-range lock using an explicit lock owner id.
    pub async fn test_lock_with_owner(
        &mut self,
        path: &str,
        lock_type: LockType,
        offset: u64,
        length: u64,
        owner: impl Into<Vec<u8>>,
    ) -> Result<Option<LockDenied>> {
        let owner = owner.into();
        validate_lock_owner(&owner)?;
        let response = self
            .compound_status(path_ops(
                path,
                vec![Operation::LockTest(LockTestArgs {
                    lock_type,
                    offset,
                    length,
                    owner: LockOwner {
                        client_id: self.client_id,
                        owner,
                    },
                })],
            )?)
            .await?;
        response_lock_test(&response)
    }

    /// Acquires an NFSv4 byte-range lock using a generated lock owner.
    pub async fn lock(
        &mut self,
        path: &str,
        lock_type: LockType,
        offset: u64,
        length: u64,
    ) -> Result<ByteRangeLock> {
        let owner = default_lock_owner(&self.builder.host);
        self.lock_with_owner(path, lock_type, offset, length, owner)
            .await
    }

    /// Acquires a shared read byte-range lock.
    pub async fn read_lock(
        &mut self,
        path: &str,
        offset: u64,
        length: u64,
    ) -> Result<ByteRangeLock> {
        self.lock(path, LockType::Read, offset, length).await
    }

    /// Acquires an exclusive write byte-range lock.
    pub async fn write_lock(
        &mut self,
        path: &str,
        offset: u64,
        length: u64,
    ) -> Result<ByteRangeLock> {
        self.lock(path, LockType::Write, offset, length).await
    }

    /// Acquires an NFSv4 byte-range lock using an explicit lock owner id.
    pub async fn lock_with_owner(
        &mut self,
        path: &str,
        lock_type: LockType,
        offset: u64,
        length: u64,
        owner: impl Into<Vec<u8>>,
    ) -> Result<ByteRangeLock> {
        let owner = owner.into();
        validate_lock_owner(&owner)?;
        let open_owner = default_open_owner(&self.builder.host);
        let opened = self
            .open_with_owner(
                path,
                lock_share_access(lock_type),
                OpenHow::NoCreate,
                open_owner,
            )
            .await?;
        let result = self
            .lock_opened(&opened, lock_type, offset, length, owner.clone())
            .await;
        match result {
            Ok((lock_stateid, lock_seqid)) => Ok(ByteRangeLock {
                handle: opened.handle,
                open_stateid: opened.stateid,
                lock_stateid,
                lock_seqid,
                lock_type,
                offset,
                length,
                owner,
            }),
            Err(err) => Err(cleanup_error(
                err,
                "cleanup CLOSE after failed LOCK",
                self.close(opened).await,
            )),
        }
    }

    /// Releases an active NFSv4 byte-range lock.
    pub async fn unlock(&mut self, lock: ByteRangeLock) -> Result<()> {
        let owner = lock.owner.clone();
        let opened = OpenedFile {
            handle: lock.handle.clone(),
            stateid: lock.open_stateid,
        };
        let result = match self.unlock_opened(&lock).await {
            Ok(stateid) => match self.free_stateid(stateid).await {
                Ok(()) => self.release_lock_owner(owner).await.map(|_| ()),
                Err(err) => Err(err),
            },
            Err(err) => Err(err),
        };
        let close_result = self.close(opened).await;
        finish_with_close(result.map(|_| ()), close_result)
    }

    /// Releases server-side state associated with a stateid.
    pub async fn free_stateid(&mut self, stateid: StateId) -> Result<()> {
        let response = self.compound(vec![Operation::FreeStateId(stateid)]).await?;
        self.ensure_status(response, "FREE_STATEID")
    }

    /// Tests a single NFSv4 stateid and returns its server-reported status.
    pub async fn test_stateid(&mut self, stateid: StateId) -> Result<Status> {
        let mut statuses = self.test_stateids(&[stateid]).await?;
        statuses
            .pop()
            .ok_or_else(|| Error::Protocol("TEST_STATEID returned no status".into()))
    }

    /// Tests NFSv4 stateids and returns one status per requested stateid.
    pub async fn test_stateids(&mut self, stateids: &[StateId]) -> Result<Vec<Status>> {
        if stateids.is_empty() {
            return Ok(Vec::new());
        }
        validate_stateid_batch_len(stateids.len())?;
        let response = self
            .compound(vec![Operation::TestStateIds(stateids.to_vec())])
            .await?;
        response_test_stateids(&response, stateids.len())
    }

    /// Releases a lock owner when the server no longer tracks locks for it.
    ///
    /// Returns `Ok(false)` when the server reports `NFS4ERR_LOCKS_HELD`.
    pub async fn release_lock_owner(&mut self, owner: impl Into<Vec<u8>>) -> Result<bool> {
        let owner = owner.into();
        validate_lock_owner(&owner)?;
        let response = self
            .compound_status(vec![Operation::ReleaseLockOwner(LockOwner {
                client_id: self.client_id,
                owner,
            })])
            .await?;
        response_release_lock_owner(&response)
    }

    pub async fn io_advise(
        &mut self,
        path: &str,
        offset: u64,
        count: u64,
        hints: &[IoAdviceType],
    ) -> Result<IoAdviseResult> {
        require_minor_version("IO_ADVISE", self.minor_version, NFS4_MINOR_VERSION_V42)?;
        let opened = self
            .open(path, io_advice_share_access(hints), OpenHow::NoCreate)
            .await?;
        let result = self.io_advise_opened(&opened, offset, count, hints).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn read(&mut self, path: &str) -> Result<Vec<u8>> {
        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)
            .await?;
        let result = self.read_opened_to_end(&opened).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn read_to_writer<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        path: &str,
        writer: &mut W,
    ) -> Result<u64> {
        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)
            .await?;
        let result = self.read_opened_to_writer(&opened, writer).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn read_range_to_writer<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        path: &str,
        offset: u64,
        count: u64,
        writer: &mut W,
    ) -> Result<u64> {
        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)
            .await?;
        let result = self
            .read_opened_range_to_writer(&opened, offset, count, writer)
            .await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn read_range(&mut self, path: &str, offset: u64, count: u64) -> Result<Vec<u8>> {
        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)
            .await?;
        let result = self.read_opened_range_vec(&opened, offset, count).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn read_at(&mut self, path: &str, offset: u64, count: u32) -> Result<Vec<u8>> {
        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)
            .await?;
        let result = self.read_opened_range(&opened, offset, count).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn read_exact_at(&mut self, path: &str, offset: u64, count: u32) -> Result<Vec<u8>> {
        let data = self.read_at(path, offset, count).await?;
        if data.len() != count as usize {
            return Err(Error::Protocol(format!(
                "NFSv4 READ returned {} bytes before EOF; expected {count}",
                data.len()
            )));
        }
        Ok(data)
    }

    pub async fn read_plus(
        &mut self,
        path: &str,
        offset: u64,
        count: u32,
    ) -> Result<ReadPlusResult> {
        require_minor_version("READ_PLUS", self.minor_version, NFS4_MINOR_VERSION_V42)?;
        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)
            .await?;
        let result = self.read_plus_opened(&opened, offset, count).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn seek(&mut self, path: &str, offset: u64, what: SeekContent) -> Result<SeekResult> {
        require_minor_version("SEEK", self.minor_version, NFS4_MINOR_VERSION_V42)?;
        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)
            .await?;
        let result = self.seek_opened(&opened, offset, what).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn seek_data(&mut self, path: &str, offset: u64) -> Result<Option<u64>> {
        self.seek(path, offset, SeekContent::Data)
            .await
            .map(SeekResult::found_offset)
    }

    pub async fn seek_hole(&mut self, path: &str, offset: u64) -> Result<Option<u64>> {
        self.seek(path, offset, SeekContent::Hole)
            .await
            .map(SeekResult::found_offset)
    }

    pub async fn read_link(&mut self, path: &str) -> Result<String> {
        let response = self
            .compound(path_ops(path, vec![Operation::ReadLink])?)
            .await?;
        response_readlink(&response)
    }

    async fn read_opened_to_end(&mut self, opened: &OpenedFile) -> Result<Vec<u8>> {
        let mut offset = 0;
        let mut out = Vec::new();
        loop {
            let (eof, data) = self.read_opened_at(opened, offset, self.read_size).await?;
            if data.is_empty() {
                return Ok(out);
            }
            advance_offset(&mut offset, data.len(), "NFSv4 READ")?;
            out.extend_from_slice(&data);
            if eof {
                return Ok(out);
            }
        }
    }

    async fn read_opened_to_writer<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        opened: &OpenedFile,
        writer: &mut W,
    ) -> Result<u64> {
        let mut offset = 0;
        let mut total = 0;
        loop {
            let (eof, data) = self.read_opened_at(opened, offset, self.read_size).await?;
            if data.is_empty() {
                return Ok(total);
            }
            writer.write_all(&data).await?;
            advance_offset(&mut offset, data.len(), "NFSv4 READ")?;
            advance_offset(&mut total, data.len(), "NFSv4 READ total")?;
            if eof {
                return Ok(total);
            }
        }
    }

    async fn read_opened_range(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        count: u32,
    ) -> Result<Vec<u8>> {
        self.read_opened_range_vec(opened, offset, u64::from(count))
            .await
    }

    async fn read_opened_range_vec(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        count: u64,
    ) -> Result<Vec<u8>> {
        let capacity = usize::try_from(count).unwrap_or(usize::MAX);
        let mut out = Vec::with_capacity(capacity.min(self.read_size as usize));
        self.read_opened_range_to_writer(opened, offset, count, &mut out)
            .await?;
        Ok(out)
    }

    async fn read_opened_range_to_writer<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        opened: &OpenedFile,
        mut offset: u64,
        mut remaining: u64,
        writer: &mut W,
    ) -> Result<u64> {
        let mut total = 0;
        while remaining > 0 {
            let request = u64::from(self.read_size).min(remaining) as u32;
            let (eof, data) = self.read_opened_at(opened, offset, request).await?;
            if data.is_empty() {
                return Ok(total);
            }
            writer.write_all(&data).await?;
            advance_offset(&mut offset, data.len(), "NFSv4 READ")?;
            advance_offset(&mut total, data.len(), "NFSv4 READ total")?;
            remaining -= data.len() as u64;
            if eof {
                return Ok(total);
            }
        }
        Ok(total)
    }

    pub async fn write(&mut self, path: &str, data: &[u8]) -> Result<()> {
        self.write_with_mode(path, data, 0o644).await
    }

    pub async fn write_with_mode(&mut self, path: &str, data: &[u8], mode: u32) -> Result<()> {
        let opened = self
            .open(
                path,
                OPEN4_SHARE_ACCESS_BOTH,
                OpenHow::Unchecked(Fattr::mode(mode)),
            )
            .await?;
        let result = match self.set_opened_size(&opened, 0).await {
            Ok(()) => self.write_opened_at(&opened, 0, data).await,
            Err(err) => Err(err),
        };
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn write_from_reader<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
    ) -> Result<u64> {
        self.write_from_reader_with_mode(path, reader, 0o644).await
    }

    pub async fn write_from_reader_with_mode<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
        mode: u32,
    ) -> Result<u64> {
        let opened = self
            .open(
                path,
                OPEN4_SHARE_ACCESS_BOTH,
                OpenHow::Unchecked(Fattr::mode(mode)),
            )
            .await?;
        let result = match self.set_opened_size(&opened, 0).await {
            Ok(()) => self.write_opened_from_reader(&opened, reader).await,
            Err(err) => Err(err),
        };
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn write_atomic(&mut self, path: &str, data: &[u8]) -> Result<()> {
        self.write_atomic_with_mode(path, data, 0o644).await
    }

    pub async fn write_atomic_with_mode(
        &mut self,
        path: &str,
        data: &[u8],
        mode: u32,
    ) -> Result<()> {
        let temp = temporary_sibling_path(path)?;
        let mut created = false;

        let result = match self
            .open_temp(
                &temp,
                OPEN4_SHARE_ACCESS_BOTH,
                OpenHow::Guarded(Fattr::mode(mode)),
            )
            .await
        {
            Ok(opened) => {
                created = true;
                let write_result = self.write_opened_at(&opened, 0, data).await;
                let close_result = self.close(opened).await;
                match finish_with_close(write_result, close_result) {
                    Ok(()) => self.rename(&temp, path).await,
                    Err(err) => Err(err),
                }
            }
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
        self.write_atomic_from_reader_with_mode(path, reader, 0o644)
            .await
    }

    pub async fn write_atomic_from_reader_with_mode<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
        mode: u32,
    ) -> Result<u64> {
        let temp = temporary_sibling_path(path)?;
        let mut created = false;

        let result = match self
            .open_temp(
                &temp,
                OPEN4_SHARE_ACCESS_BOTH,
                OpenHow::Guarded(Fattr::mode(mode)),
            )
            .await
        {
            Ok(opened) => {
                created = true;
                let write_result = self.write_opened_from_reader(&opened, reader).await;
                let close_result = self.close(opened).await;
                match finish_with_close(write_result, close_result) {
                    Ok(written) => match self.rename(&temp, path).await {
                        Ok(()) => Ok(written),
                        Err(err) => Err(err),
                    },
                    Err(err) => Err(err),
                }
            }
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
        let offset = self.metadata(path).await?.size.ok_or_else(|| {
            Error::Protocol("NFSv4 size attribute is required for append".to_owned())
        })?;
        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)
            .await?;
        let result = match self.write_opened_at(&opened, offset, data).await {
            Ok(()) => {
                let mut written = 0;
                advance_offset(&mut written, data.len(), "NFSv4 APPEND").map(|()| written)
            }
            Err(err) => Err(err),
        };
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn append_from_reader<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
    ) -> Result<u64> {
        let offset = self.metadata(path).await?.size.ok_or_else(|| {
            Error::Protocol("NFSv4 size attribute is required for append".to_owned())
        })?;
        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)
            .await?;
        let result = self
            .write_opened_from_reader_at(&opened, offset, reader)
            .await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn truncate(&mut self, path: &str, size: u64) -> Result<()> {
        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)
            .await?;
        let result = self.set_opened_size(&opened, size).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn allocate(&mut self, path: &str, offset: u64, length: u64) -> Result<()> {
        self.update_allocation(path, offset, length, SpaceOp::Allocate)
            .await
    }

    pub async fn deallocate(&mut self, path: &str, offset: u64, length: u64) -> Result<()> {
        self.update_allocation(path, offset, length, SpaceOp::Deallocate)
            .await
    }

    pub async fn write_same(&mut self, path: &str, block: AppDataBlock) -> Result<WriteResponse> {
        self.write_same_with_stability(path, block, StableHow::FileSync)
            .await
    }

    pub async fn write_same_with_stability(
        &mut self,
        path: &str,
        block: AppDataBlock,
        stable: StableHow,
    ) -> Result<WriteResponse> {
        require_minor_version("WRITE_SAME", self.minor_version, NFS4_MINOR_VERSION_V42)?;
        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)
            .await?;
        let result = self.write_same_opened(&opened, block, stable).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn setattr(&mut self, path: &str, attrs: &SetAttrs) -> Result<()> {
        let attrs = Fattr::from_set_attrs(attrs)?;
        if attrs.attrmask.is_empty() {
            return Ok(());
        }
        if attrs_require_open_state(&attrs) {
            let opened = self
                .open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)
                .await?;
            let result = self.set_opened_attrs(&opened, attrs).await;
            let close_result = self.close(opened).await;
            return finish_with_close(result, close_result);
        }
        let response = self
            .compound(path_ops(
                path,
                vec![Operation::SetAttr {
                    stateid: StateId::anonymous(),
                    attrs,
                }],
            )?)
            .await?;
        self.ensure_status(response, "SETATTR")
    }

    pub async fn set_mode(&mut self, path: &str, mode: u32) -> Result<()> {
        self.setattr(path, &SetAttrs::mode(mode)).await
    }

    pub async fn set_owner(&mut self, path: &str, owner: impl Into<String>) -> Result<()> {
        self.setattr(path, &SetAttrs::owner(owner)).await
    }

    pub async fn set_owner_group(
        &mut self,
        path: &str,
        owner_group: impl Into<String>,
    ) -> Result<()> {
        self.setattr(path, &SetAttrs::owner_group(owner_group))
            .await
    }

    pub async fn set_ownership(
        &mut self,
        path: &str,
        owner: impl Into<String>,
        owner_group: impl Into<String>,
    ) -> Result<()> {
        self.setattr(path, &SetAttrs::ownership(owner, owner_group))
            .await
    }

    pub async fn set_times(
        &mut self,
        path: &str,
        access_time: Option<NfsTime>,
        modify_time: Option<NfsTime>,
    ) -> Result<()> {
        self.setattr(path, &SetAttrs::times(access_time, modify_time))
            .await
    }

    pub async fn touch(&mut self, path: &str) -> Result<()> {
        self.setattr(path, &SetAttrs::touch()).await
    }

    pub async fn write_at(&mut self, path: &str, offset: u64, data: &[u8]) -> Result<()> {
        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)
            .await?;
        let result = self.write_opened_at(&opened, offset, data).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn copy(&mut self, from: &str, to: &str) -> Result<u64> {
        if path_components(from)? == path_components(to)? {
            return Err(Error::Protocol(
                "copy source and destination must differ".to_owned(),
            ));
        }
        let mode = self.metadata(from).await?.mode.unwrap_or(0o644) & 0o7777;
        let source = self
            .open(from, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)
            .await?;
        let target = match self
            .open(
                to,
                OPEN4_SHARE_ACCESS_BOTH,
                OpenHow::Unchecked(Fattr::mode(mode)),
            )
            .await
        {
            Ok(target) => target,
            Err(err) => {
                return Err(cleanup_error(
                    err,
                    "cleanup CLOSE source after failed target OPEN",
                    self.close(source).await,
                ));
            }
        };

        if let Err(error) = ensure_distinct_copy_handles(&source.handle, &target.handle) {
            let target_close = self.close(target).await;
            let source_close = self.close(source).await;
            return Err(cleanup_error(
                error,
                "cleanup CLOSE after rejected same-file copy",
                target_close.and(source_close),
            ));
        }

        let result = match self.set_opened_size(&target, 0).await {
            Ok(()) => self.copy_opened(&source, &target).await,
            Err(err) => Err(err),
        };
        let target_close = self.close(target).await;
        let source_close = self.close(source).await;
        let close_result = target_close.and(source_close);
        match result {
            Ok(copied) => {
                close_result?;
                Ok(copied)
            }
            Err(err) => Err(cleanup_error(
                err,
                "cleanup CLOSE after failed COPY",
                close_result,
            )),
        }
    }

    pub async fn copy_atomic(&mut self, from: &str, to: &str) -> Result<u64> {
        if path_components(from)? == path_components(to)? {
            return Err(Error::Protocol(
                "copy source and destination must differ".to_owned(),
            ));
        }
        let mode = self.metadata(from).await?.mode.unwrap_or(0o644) & 0o7777;
        let temp = temporary_sibling_path(to)?;
        let source = self
            .open(from, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)
            .await?;
        let target = match self
            .open_temp(
                &temp,
                OPEN4_SHARE_ACCESS_BOTH,
                OpenHow::Guarded(Fattr::mode(mode)),
            )
            .await
        {
            Ok(target) => target,
            Err(err) => {
                return Err(cleanup_error(
                    err,
                    "cleanup CLOSE source after failed atomic target OPEN",
                    self.close(source).await,
                ));
            }
        };

        let copy_result = self.copy_opened(&source, &target).await;
        let target_close = self.close(target).await;
        let source_close = self.close(source).await;
        let close_result = target_close.and(source_close);
        let result = match copy_result {
            Ok(copied) => {
                close_result?;
                match self.rename(&temp, to).await {
                    Ok(()) => Ok(copied),
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(cleanup_error(
                err,
                "cleanup CLOSE after failed atomic COPY",
                close_result,
            )),
        };

        self.finish_with_temp_cleanup(
            result,
            true,
            &temp,
            "cleanup REMOVE after failed atomic copy",
        )
        .await
    }

    pub async fn copy_range_offload(
        &mut self,
        from: &str,
        to: &str,
        src_offset: u64,
        dst_offset: u64,
        count: u64,
    ) -> Result<CopyResult> {
        self.copy_range_offload_with_options(
            from,
            to,
            src_offset,
            dst_offset,
            count,
            false,
            true,
            Vec::new(),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn copy_range_offload_with_options(
        &mut self,
        from: &str,
        to: &str,
        src_offset: u64,
        dst_offset: u64,
        count: u64,
        consecutive: bool,
        synchronous: bool,
        source_servers: Vec<NetLoc>,
    ) -> Result<CopyResult> {
        require_minor_version("COPY", self.minor_version, NFS4_MINOR_VERSION_V42)?;
        if count == 0 {
            return Ok(CopyResult {
                response: None,
                requirements: None,
            });
        }
        if source_servers.len() > NFS4_MAX_NETLOCATIONS {
            return Err(Error::Protocol(format!(
                "NFSv4 COPY source server count {} exceeds maximum {NFS4_MAX_NETLOCATIONS}",
                source_servers.len()
            )));
        }

        let source = self
            .open(from, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)
            .await?;
        let target = match self
            .open(to, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)
            .await
        {
            Ok(target) => target,
            Err(err) => {
                return Err(cleanup_error(
                    err,
                    "cleanup CLOSE source after failed offload target OPEN",
                    self.close(source).await,
                ));
            }
        };

        if let Err(error) = ensure_distinct_copy_handles(&source.handle, &target.handle) {
            let target_close = self.close(target).await;
            let source_close = self.close(source).await;
            return Err(cleanup_error(
                error,
                "cleanup CLOSE after rejected same-file offload copy",
                target_close.and(source_close),
            ));
        }

        let result = self
            .copy_opened_range_offload(
                &source,
                &target,
                CopyOffloadOptions {
                    src_offset,
                    dst_offset,
                    count,
                    consecutive,
                    synchronous,
                    source_servers,
                },
            )
            .await;
        let target_close = self.close(target).await;
        let source_close = self.close(source).await;
        let close_result = target_close.and(source_close);
        match result {
            Ok(copy) => {
                close_result?;
                Ok(copy)
            }
            Err(err) => Err(cleanup_error(
                err,
                "cleanup CLOSE after failed offload COPY",
                close_result,
            )),
        }
    }

    pub async fn copy_notify(
        &mut self,
        source: &str,
        destination_server: NetLoc,
    ) -> Result<CopyNotifyResult> {
        require_minor_version("COPY_NOTIFY", self.minor_version, NFS4_MINOR_VERSION_V42)?;
        let opened = self
            .open(source, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)
            .await?;
        let result = self.copy_notify_opened(&opened, destination_server).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn copy_notify_with_stateid(
        &mut self,
        source: &str,
        stateid: StateId,
        destination_server: NetLoc,
    ) -> Result<CopyNotifyResult> {
        require_minor_version("COPY_NOTIFY", self.minor_version, NFS4_MINOR_VERSION_V42)?;
        let response = self
            .compound(path_ops(
                source,
                vec![Operation::CopyNotify(CopyNotifyArgs {
                    src_stateid: stateid,
                    destination_server,
                })],
            )?)
            .await?;
        response_copy_notify(&response)
    }

    pub async fn offload_status(&mut self, stateid: StateId) -> Result<OffloadStatusResult> {
        require_minor_version("OFFLOAD_STATUS", self.minor_version, NFS4_MINOR_VERSION_V42)?;
        let response = self
            .compound(vec![Operation::OffloadStatus(stateid)])
            .await?;
        response_offload_status(&response)
    }

    pub async fn offload_cancel(&mut self, stateid: StateId) -> Result<()> {
        require_minor_version("OFFLOAD_CANCEL", self.minor_version, NFS4_MINOR_VERSION_V42)?;
        let response = self
            .compound(vec![Operation::OffloadCancel(stateid)])
            .await?;
        self.ensure_status(response, "OFFLOAD_CANCEL")
    }

    pub async fn get_device_info(
        &mut self,
        device_id: DeviceId,
        layout_type: LayoutType,
    ) -> Result<GetDeviceInfoResult> {
        self.get_device_info_with_notify(
            device_id,
            layout_type,
            session_payload_limit(self.max_response_size).max(1),
            Bitmap::empty(),
        )
        .await
    }

    pub async fn get_device_info_with_notify(
        &mut self,
        device_id: DeviceId,
        layout_type: LayoutType,
        max_count: u32,
        notify_types: Bitmap,
    ) -> Result<GetDeviceInfoResult> {
        require_minor_version(
            "GETDEVICEINFO",
            self.minor_version,
            NFS4_MINOR_VERSION_SESSION_MIN,
        )?;
        if max_count == 0 {
            return Err(Error::Protocol(
                "GETDEVICEINFO max_count must be greater than zero".to_owned(),
            ));
        }
        let response = self
            .compound(vec![Operation::GetDeviceInfo(GetDeviceInfoArgs {
                device_id,
                layout_type,
                max_count,
                notify_types,
            })])
            .await?;
        response_get_device_info(&response)
    }

    pub async fn list_devices(&mut self, layout_type: LayoutType) -> Result<Vec<DeviceId>> {
        self.list_devices_limited(layout_type, self.max_dir_entries)
            .await
    }

    pub async fn list_devices_limited(
        &mut self,
        layout_type: LayoutType,
        max_device_ids: usize,
    ) -> Result<Vec<DeviceId>> {
        validate_max_device_ids(max_device_ids)?;
        let mut cursor = None;
        let mut device_ids = Vec::new();
        loop {
            let remaining = max_device_ids.saturating_sub(device_ids.len());
            if remaining == 0 {
                return Err(Error::Protocol(format!(
                    "NFSv4 GETDEVICELIST exceeded configured limit of {max_device_ids} device ids"
                )));
            }
            let page = self
                .list_device_page_limited(layout_type, cursor, remaining)
                .await?;
            device_ids.extend(page.device_ids);
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => return Ok(device_ids),
            }
        }
    }

    pub async fn list_device_page(
        &mut self,
        layout_type: LayoutType,
        cursor: Option<DeviceListCursor>,
    ) -> Result<DeviceListPage> {
        self.list_device_page_limited(layout_type, cursor, self.max_dir_entries)
            .await
    }

    pub async fn list_device_page_limited(
        &mut self,
        layout_type: LayoutType,
        cursor: Option<DeviceListCursor>,
        max_device_ids: usize,
    ) -> Result<DeviceListPage> {
        let max_devices = validate_max_device_ids(max_device_ids)?;
        require_minor_version(
            "GETDEVICELIST",
            self.minor_version,
            NFS4_MINOR_VERSION_SESSION_MIN,
        )?;
        let cursor = cursor.unwrap_or_default();
        let response = self
            .compound(vec![Operation::GetDeviceList(GetDeviceListArgs {
                layout_type,
                max_devices,
                cookie: cursor.cookie,
                cookieverf: cursor.cookieverf,
            })])
            .await?;
        let result = response_get_device_list(&response)?;
        device_list_page_from_result(result, cursor.cookie, max_device_ids)
    }

    pub async fn layout_get(
        &mut self,
        path: &str,
        layout_type: LayoutType,
        iomode: LayoutIomode,
        offset: u64,
        length: u64,
        min_length: u64,
    ) -> Result<LayoutGetResult> {
        self.layout_get_with_options(
            path,
            layout_type,
            iomode,
            offset,
            length,
            min_length,
            session_payload_limit(self.max_response_size).max(1),
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn layout_get_with_options(
        &mut self,
        path: &str,
        layout_type: LayoutType,
        iomode: LayoutIomode,
        offset: u64,
        length: u64,
        min_length: u64,
        max_count: u32,
        signal_layout_avail: bool,
    ) -> Result<LayoutGetResult> {
        require_minor_version(
            "LAYOUTGET",
            self.minor_version,
            NFS4_MINOR_VERSION_SESSION_MIN,
        )?;
        if max_count == 0 {
            return Err(Error::Protocol(
                "LAYOUTGET max_count must be greater than zero".to_owned(),
            ));
        }
        let opened = self
            .open(path, layout_iomode_share_access(iomode), OpenHow::NoCreate)
            .await?;
        let result = self
            .layout_get_opened(
                &opened,
                layout_type,
                iomode,
                offset,
                length,
                min_length,
                max_count,
                signal_layout_avail,
            )
            .await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn layout_commit(
        &mut self,
        path: &str,
        offset: u64,
        length: u64,
        stateid: StateId,
        layout_update: LayoutUpdate,
    ) -> Result<LayoutCommitResult> {
        self.layout_commit_with_options(
            path,
            offset,
            length,
            stateid,
            None,
            None,
            layout_update,
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn layout_commit_with_options(
        &mut self,
        path: &str,
        offset: u64,
        length: u64,
        stateid: StateId,
        last_write_offset: Option<u64>,
        time_modify: Option<NfsTime>,
        layout_update: LayoutUpdate,
        reclaim: bool,
    ) -> Result<LayoutCommitResult> {
        require_minor_version(
            "LAYOUTCOMMIT",
            self.minor_version,
            NFS4_MINOR_VERSION_SESSION_MIN,
        )?;
        let response = self
            .compound(path_ops(
                path,
                vec![Operation::LayoutCommit(LayoutCommitArgs {
                    offset,
                    length,
                    reclaim,
                    stateid,
                    last_write_offset,
                    time_modify,
                    layout_update,
                })],
            )?)
            .await?;
        response_layout_commit(&response)
    }

    pub async fn layout_error(
        &mut self,
        path: &str,
        offset: u64,
        length: u64,
        stateid: StateId,
        errors: Vec<DeviceError>,
    ) -> Result<()> {
        require_minor_version(
            "LAYOUTERROR",
            self.minor_version,
            NFS4_MINOR_VERSION_SESSION_MIN,
        )?;
        let response = self
            .compound(path_ops(
                path,
                vec![Operation::LayoutError(LayoutErrorArgs {
                    offset,
                    length,
                    stateid,
                    errors,
                })],
            )?)
            .await?;
        self.ensure_status(response, "LAYOUTERROR")
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn layout_stats(
        &mut self,
        path: &str,
        offset: u64,
        length: u64,
        stateid: StateId,
        read: IoInfo,
        write: IoInfo,
        device_id: DeviceId,
        layout_update: LayoutUpdate,
    ) -> Result<()> {
        require_minor_version(
            "LAYOUTSTATS",
            self.minor_version,
            NFS4_MINOR_VERSION_SESSION_MIN,
        )?;
        let response = self
            .compound(path_ops(
                path,
                vec![Operation::LayoutStats(LayoutStatsArgs {
                    offset,
                    length,
                    stateid,
                    read,
                    write,
                    device_id,
                    layout_update,
                })],
            )?)
            .await?;
        self.ensure_status(response, "LAYOUTSTATS")
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn layout_return_file(
        &mut self,
        path: &str,
        layout_type: LayoutType,
        iomode: LayoutIomode,
        offset: u64,
        length: u64,
        stateid: StateId,
        body: Vec<u8>,
    ) -> Result<LayoutReturnResult> {
        require_minor_version(
            "LAYOUTRETURN",
            self.minor_version,
            NFS4_MINOR_VERSION_SESSION_MIN,
        )?;
        let response = self
            .compound(path_ops(
                path,
                vec![Operation::LayoutReturn(LayoutReturnArgs {
                    reclaim: false,
                    layout_type,
                    iomode,
                    layout_return: LayoutReturn::File(LayoutReturnFile {
                        offset,
                        length,
                        stateid,
                        body,
                    }),
                })],
            )?)
            .await?;
        response_layout_return(&response)
    }

    pub async fn layout_return_fsid(
        &mut self,
        path: &str,
        layout_type: LayoutType,
        iomode: LayoutIomode,
    ) -> Result<LayoutReturnResult> {
        require_minor_version(
            "LAYOUTRETURN",
            self.minor_version,
            NFS4_MINOR_VERSION_SESSION_MIN,
        )?;
        let response = self
            .compound(path_ops(
                path,
                vec![Operation::LayoutReturn(LayoutReturnArgs {
                    reclaim: false,
                    layout_type,
                    iomode,
                    layout_return: LayoutReturn::Fsid,
                })],
            )?)
            .await?;
        response_layout_return(&response)
    }

    pub async fn layout_return_all(
        &mut self,
        layout_type: LayoutType,
        iomode: LayoutIomode,
    ) -> Result<LayoutReturnResult> {
        require_minor_version(
            "LAYOUTRETURN",
            self.minor_version,
            NFS4_MINOR_VERSION_SESSION_MIN,
        )?;
        let response = self
            .compound(vec![Operation::LayoutReturn(LayoutReturnArgs {
                reclaim: false,
                layout_type,
                iomode,
                layout_return: LayoutReturn::All,
            })])
            .await?;
        response_layout_return(&response)
    }

    pub async fn clone_range(
        &mut self,
        from: &str,
        to: &str,
        src_offset: u64,
        dst_offset: u64,
        count: u64,
    ) -> Result<()> {
        require_minor_version("CLONE", self.minor_version, NFS4_MINOR_VERSION_V42)?;
        if count == 0 {
            return Ok(());
        }

        let source = self
            .open(from, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)
            .await?;
        let target = match self
            .open(to, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)
            .await
        {
            Ok(target) => target,
            Err(err) => {
                return Err(cleanup_error(
                    err,
                    "cleanup CLOSE source after failed clone target OPEN",
                    self.close(source).await,
                ));
            }
        };

        let result = self
            .clone_opened_range(&source, &target, src_offset, dst_offset, count)
            .await;
        let target_close = self.close(target).await;
        let source_close = self.close(source).await;
        let close_result = target_close.and(source_close);
        match result {
            Ok(()) => {
                close_result?;
                Ok(())
            }
            Err(err) => Err(cleanup_error(
                err,
                "cleanup CLOSE after failed CLONE",
                close_result,
            )),
        }
    }

    pub async fn commit(&mut self, path: &str, offset: u64, count: u32) -> Result<CommitResult> {
        let response = self
            .compound(path_ops(path, vec![Operation::Commit { offset, count }])?)
            .await?;
        response_commit(&response)
    }

    pub async fn create(&mut self, path: &str) -> Result<()> {
        self.create_new(path).await
    }

    pub async fn create_new(&mut self, path: &str) -> Result<()> {
        self.create_new_with_mode(path, 0o644).await
    }

    pub async fn create_with_mode(&mut self, path: &str, mode: u32) -> Result<()> {
        self.create_new_with_mode(path, mode).await
    }

    pub async fn create_new_with_mode(&mut self, path: &str, mode: u32) -> Result<()> {
        let opened = self
            .open(
                path,
                OPEN4_SHARE_ACCESS_BOTH,
                OpenHow::Guarded(Fattr::mode(mode)),
            )
            .await?;
        self.close(opened).await
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

    async fn finish_with_named_attr_cleanup<T>(
        &mut self,
        result: Result<T>,
        created: bool,
        path: &str,
        temp_name: &str,
        cleanup_context: &'static str,
    ) -> Result<T> {
        match result {
            Ok(value) => Ok(value),
            Err(err) if created => Err(cleanup_error(
                err,
                cleanup_context,
                self.remove_named_attr(path, temp_name).await,
            )),
            Err(err) => Err(err),
        }
    }

    pub async fn mkdir(&mut self, path: &str, mode: u32) -> Result<()> {
        let (parent_components, name) = split_parent(path)?;
        let mut ops = vec![Operation::PutRootFh];
        for component in parent_components {
            ops.push(Operation::Lookup(component.to_owned()));
        }
        ops.push(Operation::Create(CreateArgs {
            kind: CreateKind::Directory,
            name,
            attrs: Fattr::mode(mode),
        }));

        let response = self.compound(ops).await?;
        self.ensure_status_for(&response, "CREATE")
    }

    pub async fn create_dir_all(&mut self, path: &str, mode: u32) -> Result<()> {
        let components = path_components(path)?;
        let mut current = String::from("/");
        for component in components {
            current = join_path(&current, component);
            match self.metadata(&current).await {
                Ok(attrs) => {
                    self.ensure_directory_type(&current, attrs.file_type)
                        .await?
                }
                Err(Error::NfsV4 {
                    status: Status::NoEnt,
                    ..
                }) => match self.mkdir(&current, mode).await {
                    Ok(_) => {}
                    Err(Error::NfsV4 {
                        status: Status::Exist,
                        ..
                    }) => {
                        let attrs = self.metadata(&current).await?;
                        self.ensure_directory_type(&current, attrs.file_type)
                            .await?;
                    }
                    Err(err) => return Err(err),
                },
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    pub async fn symlink(&mut self, path: &str, target: &str) -> Result<()> {
        let (parent_components, name) = split_parent(path)?;
        let mut ops = vec![Operation::PutRootFh];
        for component in parent_components {
            ops.push(Operation::Lookup(component.to_owned()));
        }
        ops.push(Operation::Create(CreateArgs {
            kind: CreateKind::Symlink(target.to_owned()),
            name,
            attrs: Fattr::empty(),
        }));

        let response = self.compound(ops).await?;
        self.ensure_status_for(&response, "CREATE")
    }

    pub async fn create_fifo(&mut self, path: &str, mode: u32) -> Result<()> {
        self.create_special(path, CreateKind::Fifo, mode).await
    }

    pub async fn create_socket(&mut self, path: &str, mode: u32) -> Result<()> {
        self.create_special(path, CreateKind::Socket, mode).await
    }

    pub async fn create_block_device(
        &mut self,
        path: &str,
        major: u32,
        minor: u32,
        mode: u32,
    ) -> Result<()> {
        self.create_special(path, CreateKind::BlockDevice { major, minor }, mode)
            .await
    }

    pub async fn create_character_device(
        &mut self,
        path: &str,
        major: u32,
        minor: u32,
        mode: u32,
    ) -> Result<()> {
        self.create_special(path, CreateKind::CharacterDevice { major, minor }, mode)
            .await
    }

    async fn create_special(&mut self, path: &str, kind: CreateKind, mode: u32) -> Result<()> {
        let (parent_components, name) = split_parent(path)?;
        let mut ops = vec![Operation::PutRootFh];
        for component in parent_components {
            ops.push(Operation::Lookup(component.to_owned()));
        }
        ops.push(Operation::Create(CreateArgs {
            kind,
            name,
            attrs: Fattr::mode(mode),
        }));

        let response = self.compound(ops).await?;
        self.ensure_status_for(&response, "CREATE")
    }

    pub async fn hard_link(&mut self, existing: &str, link: &str) -> Result<()> {
        let existing_components = path_components(existing)?;
        let (link_parent, link_name) = split_parent(link)?;
        let mut ops = vec![Operation::PutRootFh];
        for component in existing_components {
            ops.push(Operation::Lookup(component.to_owned()));
        }
        ops.push(Operation::SaveFh);
        ops.push(Operation::PutRootFh);
        for component in link_parent {
            ops.push(Operation::Lookup(component.to_owned()));
        }
        ops.push(Operation::Link(link_name));

        let response = self.compound(ops).await?;
        self.ensure_status(response, "LINK")
    }

    pub async fn remove(&mut self, path: &str) -> Result<()> {
        let (parent_components, name) = split_parent(path)?;
        let mut ops = vec![Operation::PutRootFh];
        for component in parent_components {
            ops.push(Operation::Lookup(component.to_owned()));
        }
        ops.push(Operation::Remove(name));

        let response = self.compound(ops).await?;
        self.ensure_status(response, "REMOVE")
    }

    pub async fn remove_if_exists(&mut self, path: &str) -> Result<bool> {
        match self.remove(path).await {
            Ok(()) => Ok(true),
            Err(err) if err.is_not_found() => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub async fn rmdir(&mut self, path: &str) -> Result<()> {
        self.remove(path).await
    }

    pub async fn rmdir_if_exists(&mut self, path: &str) -> Result<bool> {
        match self.rmdir(path).await {
            Ok(()) => Ok(true),
            Err(err) if err.is_not_found() => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub async fn remove_all(&mut self, path: &str) -> Result<()> {
        if path_components(path)?.is_empty() {
            return Err(Error::InvalidPath(path.to_owned()));
        }

        enum RemoveTask {
            Visit(String, Option<FileType>),
            RemoveDir(String),
        }

        let file_type = self.metadata(path).await?.file_type;
        let mut stack = vec![RemoveTask::Visit(path.to_owned(), file_type)];
        while let Some(task) = stack.pop() {
            match task {
                RemoveTask::Visit(path, file_type) => {
                    if self.path_is_directory(&path, file_type).await? {
                        stack.push(RemoveTask::RemoveDir(path.clone()));
                        let entries = self.read_dir(&path).await?;
                        for entry in entries.into_iter().rev() {
                            if entry.name == "." || entry.name == ".." {
                                continue;
                            }
                            let child = join_path(&path, &entry.name);
                            let child_type = entry.basic_attributes()?.file_type;
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
        let (from_parent, from_name) = split_parent(from)?;
        let (to_parent, to_name) = split_parent(to)?;
        let mut ops = vec![Operation::PutRootFh];
        for component in from_parent {
            ops.push(Operation::Lookup(component.to_owned()));
        }
        ops.push(Operation::SaveFh);
        ops.push(Operation::PutRootFh);
        for component in to_parent {
            ops.push(Operation::Lookup(component.to_owned()));
        }
        ops.push(Operation::Rename {
            oldname: from_name,
            newname: to_name,
        });

        let response = self.compound(ops).await?;
        self.ensure_status(response, "RENAME")
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
        let attr_request = self
            .supported_attr_request(path, FATTR4_BASIC_ATTRS)
            .await?;
        let cursor = cursor.unwrap_or_default();
        let response = self
            .compound(path_ops(
                path,
                vec![Operation::ReadDir {
                    cookie: cursor.cookie,
                    cookieverf: cursor.cookieverf,
                    dircount: (self.dir_size / 2).max(1),
                    maxcount: self.dir_size,
                    attr_request,
                }],
            )?)
            .await?;
        let (cookieverf, entries, eof) = response_readdir(&response)?;
        dir_page_from_entries(cookieverf, entries, eof, cursor.cookie, max_entries)
    }

    pub async fn read_named_attrs(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        self.read_named_attrs_with_limit(path, self.max_dir_entries)
            .await
    }

    pub async fn read_named_attrs_limited(
        &mut self,
        path: &str,
        max_entries: usize,
    ) -> Result<Vec<DirEntry>> {
        validate_max_dir_entries(max_entries)?;
        self.read_named_attrs_with_limit(path, max_entries.min(self.max_dir_entries))
            .await
    }

    pub async fn read_named_attr_page(
        &mut self,
        path: &str,
        cursor: Option<DirPageCursor>,
    ) -> Result<DirPage> {
        self.read_named_attr_page_limited(path, cursor, self.max_dir_entries)
            .await
    }

    pub async fn read_named_attr_page_limited(
        &mut self,
        path: &str,
        cursor: Option<DirPageCursor>,
        max_entries: usize,
    ) -> Result<DirPage> {
        validate_max_dir_entries(max_entries)?;
        let max_entries = max_entries.min(self.max_dir_entries);
        let attr_request = self
            .named_attr_supported_attr_request(path, FATTR4_BASIC_ATTRS)
            .await?;
        let cursor = cursor.unwrap_or_default();
        let response = self
            .compound(path_ops(
                path,
                vec![
                    Operation::OpenAttr { create_dir: false },
                    Operation::ReadDir {
                        cookie: cursor.cookie,
                        cookieverf: cursor.cookieverf,
                        dircount: (self.dir_size / 2).max(1),
                        maxcount: self.dir_size,
                        attr_request,
                    },
                ],
            )?)
            .await?;
        let (cookieverf, entries, eof) = response_openattr_readdir(&response)?;
        dir_page_from_entries(cookieverf, entries, eof, cursor.cookie, max_entries)
    }

    pub async fn named_attr_exists(&mut self, path: &str, name: &str) -> Result<bool> {
        match self.named_attr_metadata(path, name).await {
            Ok(_) => Ok(true),
            Err(err) if err.is_not_found() => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub async fn named_attr_metadata(&mut self, path: &str, name: &str) -> Result<BasicAttributes> {
        self.named_attr_supported_attr_values(path, name, FATTR4_BASIC_ATTRS)
            .await?
            .parse_basic()
    }

    pub async fn named_attr_supported_attrs(&mut self, path: &str, name: &str) -> Result<Bitmap> {
        let attrs = Bitmap::from_known_attrs(&[FATTR4_SUPPORTED_ATTRS]);
        let response = self
            .compound(named_attr_ops(path, name, vec![Operation::GetAttr(attrs)])?)
            .await?;
        response_getattr(&response)?.parse_supported_attrs()
    }

    pub async fn named_attr_getattr_values(
        &mut self,
        path: &str,
        name: &str,
        attr_request: Bitmap,
    ) -> Result<Fattr> {
        validate_named_attr_name(name)?;
        if attr_request.is_empty() {
            return Ok(Fattr {
                attrmask: attr_request,
                attr_vals: Vec::new(),
            });
        }
        let response = self
            .compound(named_attr_ops(
                path,
                name,
                vec![Operation::GetAttr(attr_request)],
            )?)
            .await?;
        response_getattr(&response)
    }

    pub async fn named_attr_supported_attr_values(
        &mut self,
        path: &str,
        name: &str,
        attrs: &[u32],
    ) -> Result<Fattr> {
        let supported = self.named_attr_supported_attrs(path, name).await?;
        let attrs = Bitmap::from_supported_attrs(&supported, attrs)?;
        self.named_attr_getattr_values(path, name, attrs).await
    }

    pub async fn read_named_attr(&mut self, path: &str, name: &str) -> Result<Vec<u8>> {
        let opened = self
            .open_named_attr(
                path,
                name,
                OPEN4_SHARE_ACCESS_READ,
                OpenHow::NoCreate,
                false,
            )
            .await?;
        let result = self.read_opened_to_end(&opened).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn read_named_attr_to_writer<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        path: &str,
        name: &str,
        writer: &mut W,
    ) -> Result<u64> {
        let opened = self
            .open_named_attr(
                path,
                name,
                OPEN4_SHARE_ACCESS_READ,
                OpenHow::NoCreate,
                false,
            )
            .await?;
        let result = self.read_opened_to_writer(&opened, writer).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn read_named_attr_range_to_writer<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        path: &str,
        name: &str,
        offset: u64,
        count: u64,
        writer: &mut W,
    ) -> Result<u64> {
        let opened = self
            .open_named_attr(
                path,
                name,
                OPEN4_SHARE_ACCESS_READ,
                OpenHow::NoCreate,
                false,
            )
            .await?;
        let result = self
            .read_opened_range_to_writer(&opened, offset, count, writer)
            .await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn read_named_attr_range(
        &mut self,
        path: &str,
        name: &str,
        offset: u64,
        count: u64,
    ) -> Result<Vec<u8>> {
        let opened = self
            .open_named_attr(
                path,
                name,
                OPEN4_SHARE_ACCESS_READ,
                OpenHow::NoCreate,
                false,
            )
            .await?;
        let result = self.read_opened_range_vec(&opened, offset, count).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn read_named_attr_at(
        &mut self,
        path: &str,
        name: &str,
        offset: u64,
        count: u32,
    ) -> Result<Vec<u8>> {
        let opened = self
            .open_named_attr(
                path,
                name,
                OPEN4_SHARE_ACCESS_READ,
                OpenHow::NoCreate,
                false,
            )
            .await?;
        let result = self.read_opened_range(&opened, offset, count).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn read_named_attr_exact_at(
        &mut self,
        path: &str,
        name: &str,
        offset: u64,
        count: u32,
    ) -> Result<Vec<u8>> {
        let data = self.read_named_attr_at(path, name, offset, count).await?;
        if data.len() != count as usize {
            return Err(Error::Protocol(format!(
                "NFSv4 named attribute READ returned {} bytes before EOF; expected {count}",
                data.len()
            )));
        }
        Ok(data)
    }

    pub async fn write_named_attr(&mut self, path: &str, name: &str, data: &[u8]) -> Result<()> {
        self.write_named_attr_with_mode(path, name, data, 0o644)
            .await
    }

    pub async fn write_named_attr_with_mode(
        &mut self,
        path: &str,
        name: &str,
        data: &[u8],
        mode: u32,
    ) -> Result<()> {
        let opened = self
            .open_named_attr(
                path,
                name,
                OPEN4_SHARE_ACCESS_BOTH,
                OpenHow::Unchecked(Fattr::mode(mode)),
                true,
            )
            .await?;
        let result = match self.set_opened_size(&opened, 0).await {
            Ok(()) => self.write_opened_at(&opened, 0, data).await,
            Err(err) => Err(err),
        };
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn write_named_attr_from_reader<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        path: &str,
        name: &str,
        reader: &mut R,
    ) -> Result<u64> {
        self.write_named_attr_from_reader_with_mode(path, name, reader, 0o644)
            .await
    }

    pub async fn write_named_attr_from_reader_with_mode<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        path: &str,
        name: &str,
        reader: &mut R,
        mode: u32,
    ) -> Result<u64> {
        let opened = self
            .open_named_attr(
                path,
                name,
                OPEN4_SHARE_ACCESS_BOTH,
                OpenHow::Unchecked(Fattr::mode(mode)),
                true,
            )
            .await?;
        let result = match self.set_opened_size(&opened, 0).await {
            Ok(()) => self.write_opened_from_reader(&opened, reader).await,
            Err(err) => Err(err),
        };
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn write_named_attr_atomic(
        &mut self,
        path: &str,
        name: &str,
        data: &[u8],
    ) -> Result<()> {
        self.write_named_attr_atomic_with_mode(path, name, data, 0o644)
            .await
    }

    pub async fn write_named_attr_atomic_with_mode(
        &mut self,
        path: &str,
        name: &str,
        data: &[u8],
        mode: u32,
    ) -> Result<()> {
        validate_named_attr_name(name)?;
        let temp_name = temporary_named_attr_name();
        let mut created = false;

        let result = match self
            .open_named_attr(
                path,
                &temp_name,
                OPEN4_SHARE_ACCESS_BOTH,
                OpenHow::Guarded(Fattr::mode(mode)),
                true,
            )
            .await
        {
            Ok(opened) => {
                created = true;
                let write_result = self.write_opened_at(&opened, 0, data).await;
                let close_result = self.close(opened).await;
                match finish_with_close(write_result, close_result) {
                    Ok(()) => self.rename_named_attr(path, &temp_name, name).await,
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        };

        self.finish_with_named_attr_cleanup(
            result,
            created,
            path,
            &temp_name,
            "cleanup REMOVE named attribute after failed atomic write",
        )
        .await
    }

    pub async fn write_named_attr_atomic_from_reader<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        path: &str,
        name: &str,
        reader: &mut R,
    ) -> Result<u64> {
        self.write_named_attr_atomic_from_reader_with_mode(path, name, reader, 0o644)
            .await
    }

    pub async fn write_named_attr_atomic_from_reader_with_mode<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        path: &str,
        name: &str,
        reader: &mut R,
        mode: u32,
    ) -> Result<u64> {
        validate_named_attr_name(name)?;
        let temp_name = temporary_named_attr_name();
        let mut created = false;

        let result = match self
            .open_named_attr(
                path,
                &temp_name,
                OPEN4_SHARE_ACCESS_BOTH,
                OpenHow::Guarded(Fattr::mode(mode)),
                true,
            )
            .await
        {
            Ok(opened) => {
                created = true;
                let write_result = self.write_opened_from_reader(&opened, reader).await;
                let close_result = self.close(opened).await;
                match finish_with_close(write_result, close_result) {
                    Ok(written) => match self.rename_named_attr(path, &temp_name, name).await {
                        Ok(()) => Ok(written),
                        Err(err) => Err(err),
                    },
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        };

        self.finish_with_named_attr_cleanup(
            result,
            created,
            path,
            &temp_name,
            "cleanup REMOVE named attribute after failed atomic reader write",
        )
        .await
    }

    pub async fn write_named_attr_at(
        &mut self,
        path: &str,
        name: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<()> {
        let opened = self
            .open_named_attr(
                path,
                name,
                OPEN4_SHARE_ACCESS_WRITE,
                OpenHow::NoCreate,
                false,
            )
            .await?;
        let result = self.write_opened_at(&opened, offset, data).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn append_named_attr(&mut self, path: &str, name: &str, data: &[u8]) -> Result<u64> {
        let offset = self
            .named_attr_metadata(path, name)
            .await?
            .size
            .ok_or_else(|| {
                Error::Protocol(
                    "NFSv4 named attribute size attribute is required for append".to_owned(),
                )
            })?;
        let opened = self
            .open_named_attr(
                path,
                name,
                OPEN4_SHARE_ACCESS_WRITE,
                OpenHow::NoCreate,
                false,
            )
            .await?;
        let result = match self.write_opened_at(&opened, offset, data).await {
            Ok(()) => {
                let mut written = 0;
                advance_offset(&mut written, data.len(), "NFSv4 named attribute APPEND")
                    .map(|()| written)
            }
            Err(err) => Err(err),
        };
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn append_named_attr_from_reader<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        path: &str,
        name: &str,
        reader: &mut R,
    ) -> Result<u64> {
        let offset = self
            .named_attr_metadata(path, name)
            .await?
            .size
            .ok_or_else(|| {
                Error::Protocol(
                    "NFSv4 named attribute size attribute is required for append".to_owned(),
                )
            })?;
        let opened = self
            .open_named_attr(
                path,
                name,
                OPEN4_SHARE_ACCESS_WRITE,
                OpenHow::NoCreate,
                false,
            )
            .await?;
        let result = self
            .write_opened_from_reader_at(&opened, offset, reader)
            .await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn copy_named_attr(
        &mut self,
        from_path: &str,
        from_name: &str,
        to_path: &str,
        to_name: &str,
    ) -> Result<u64> {
        let mode = self
            .named_attr_metadata(from_path, from_name)
            .await?
            .mode
            .unwrap_or(0o644)
            & 0o7777;
        let source = self
            .open_named_attr(
                from_path,
                from_name,
                OPEN4_SHARE_ACCESS_READ,
                OpenHow::NoCreate,
                false,
            )
            .await?;
        let target = match self
            .open_named_attr(
                to_path,
                to_name,
                OPEN4_SHARE_ACCESS_BOTH,
                OpenHow::Unchecked(Fattr::mode(mode)),
                true,
            )
            .await
        {
            Ok(target) => target,
            Err(err) => {
                return Err(cleanup_error(
                    err,
                    "cleanup CLOSE source after failed named attribute target OPEN",
                    self.close(source).await,
                ));
            }
        };

        if let Err(error) = ensure_distinct_copy_handles(&source.handle, &target.handle) {
            let target_close = self.close(target).await;
            let source_close = self.close(source).await;
            return Err(cleanup_error(
                error,
                "cleanup CLOSE after rejected same named attribute copy",
                target_close.and(source_close),
            ));
        }

        let result = match self.set_opened_size(&target, 0).await {
            Ok(()) => self.copy_opened(&source, &target).await,
            Err(err) => Err(err),
        };
        let target_close = self.close(target).await;
        let source_close = self.close(source).await;
        let close_result = target_close.and(source_close);
        match result {
            Ok(copied) => {
                close_result?;
                Ok(copied)
            }
            Err(err) => Err(cleanup_error(
                err,
                "cleanup CLOSE after failed named attribute COPY",
                close_result,
            )),
        }
    }

    pub async fn copy_named_attr_atomic(
        &mut self,
        from_path: &str,
        from_name: &str,
        to_path: &str,
        to_name: &str,
    ) -> Result<u64> {
        validate_named_attr_name(to_name)?;
        let mode = self
            .named_attr_metadata(from_path, from_name)
            .await?
            .mode
            .unwrap_or(0o644)
            & 0o7777;
        let temp_name = temporary_named_attr_name();

        let source = self
            .open_named_attr(
                from_path,
                from_name,
                OPEN4_SHARE_ACCESS_READ,
                OpenHow::NoCreate,
                false,
            )
            .await?;
        let target = match self
            .open_named_attr(
                to_path,
                &temp_name,
                OPEN4_SHARE_ACCESS_BOTH,
                OpenHow::Guarded(Fattr::mode(mode)),
                true,
            )
            .await
        {
            Ok(target) => target,
            Err(err) => {
                return Err(cleanup_error(
                    err,
                    "cleanup CLOSE source after failed atomic named attribute target OPEN",
                    self.close(source).await,
                ));
            }
        };

        let copy_result = match ensure_distinct_copy_handles(&source.handle, &target.handle) {
            Ok(()) => self.copy_opened(&source, &target).await,
            Err(err) => Err(err),
        };
        let target_close = self.close(target).await;
        let source_close = self.close(source).await;
        let close_result = target_close.and(source_close);
        let result = match copy_result {
            Ok(copied) => {
                close_result?;
                match self.rename_named_attr(to_path, &temp_name, to_name).await {
                    Ok(()) => Ok(copied),
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(cleanup_error(
                err,
                "cleanup CLOSE after failed atomic named attribute COPY",
                close_result,
            )),
        };

        self.finish_with_named_attr_cleanup(
            result,
            true,
            to_path,
            &temp_name,
            "cleanup REMOVE named attribute after failed atomic copy",
        )
        .await
    }

    pub async fn set_named_attr_attrs(
        &mut self,
        path: &str,
        name: &str,
        attrs: &SetAttrs,
    ) -> Result<()> {
        let attrs = Fattr::from_set_attrs(attrs)?;
        if attrs.attrmask.is_empty() {
            return Ok(());
        }
        let opened = self
            .open_named_attr(
                path,
                name,
                OPEN4_SHARE_ACCESS_WRITE,
                OpenHow::NoCreate,
                false,
            )
            .await?;
        let result = self.set_opened_attrs(&opened, attrs).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn set_named_attr_mode(&mut self, path: &str, name: &str, mode: u32) -> Result<()> {
        self.set_named_attr_attrs(path, name, &SetAttrs::mode(mode))
            .await
    }

    pub async fn set_named_attr_ownership(
        &mut self,
        path: &str,
        name: &str,
        owner: impl Into<String>,
        owner_group: impl Into<String>,
    ) -> Result<()> {
        self.set_named_attr_attrs(path, name, &SetAttrs::ownership(owner, owner_group))
            .await
    }

    pub async fn set_named_attr_times(
        &mut self,
        path: &str,
        name: &str,
        access_time: Option<NfsTime>,
        modify_time: Option<NfsTime>,
    ) -> Result<()> {
        self.set_named_attr_attrs(path, name, &SetAttrs::times(access_time, modify_time))
            .await
    }

    pub async fn truncate_named_attr(&mut self, path: &str, name: &str, size: u64) -> Result<()> {
        self.set_named_attr_attrs(path, name, &SetAttrs::size(size))
            .await
    }

    pub async fn rename_named_attr(
        &mut self,
        path: &str,
        from_name: &str,
        to_name: &str,
    ) -> Result<()> {
        validate_named_attr_name(from_name)?;
        validate_named_attr_name(to_name)?;
        let response = self
            .compound(path_ops(
                path,
                vec![
                    Operation::OpenAttr { create_dir: false },
                    Operation::SaveFh,
                    Operation::Rename {
                        oldname: from_name.to_owned(),
                        newname: to_name.to_owned(),
                    },
                ],
            )?)
            .await?;
        self.ensure_status(response, "RENAME")
    }

    pub async fn rename_named_attr_if_exists(
        &mut self,
        path: &str,
        from_name: &str,
        to_name: &str,
    ) -> Result<bool> {
        match self.rename_named_attr(path, from_name, to_name).await {
            Ok(()) => Ok(true),
            Err(err) if err.is_not_found() => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub async fn remove_named_attr(&mut self, path: &str, name: &str) -> Result<()> {
        validate_named_attr_name(name)?;
        let response = self
            .compound(path_ops(
                path,
                vec![
                    Operation::OpenAttr { create_dir: false },
                    Operation::Remove(name.to_owned()),
                ],
            )?)
            .await?;
        self.ensure_status(response, "REMOVE")
    }

    pub async fn remove_named_attr_if_exists(&mut self, path: &str, name: &str) -> Result<bool> {
        match self.remove_named_attr(path, name).await {
            Ok(()) => Ok(true),
            Err(err) if err.is_not_found() => Ok(false),
            Err(err) => Err(err),
        }
    }

    async fn read_dir_with_limit(
        &mut self,
        path: &str,
        max_entries: usize,
    ) -> Result<Vec<DirEntry>> {
        let attr_request = self
            .supported_attr_request(path, FATTR4_BASIC_ATTRS)
            .await?;
        let mut cookie = 0;
        let mut cookieverf = [0; NFS4_VERIFIER_SIZE];
        let mut entries = Vec::new();
        loop {
            let response = self
                .compound(path_ops(
                    path,
                    vec![Operation::ReadDir {
                        cookie,
                        cookieverf,
                        dircount: (self.dir_size / 2).max(1),
                        maxcount: self.dir_size,
                        attr_request: attr_request.clone(),
                    }],
                )?)
                .await?;
            let (next_cookieverf, batch, eof) = response_readdir(&response)?;
            let next = next_dir_cursor(next_cookieverf, &batch, eof, cookie)?;
            if entries.len().saturating_add(batch.len()) > max_entries {
                return Err(Error::Protocol(format!(
                    "NFSv4 READDIR exceeded configured limit of {max_entries} entries"
                )));
            }
            entries.extend(
                batch
                    .into_iter()
                    .map(DirEntry::from_wire)
                    .collect::<Result<Vec<_>>>()?,
            );
            match next {
                Some(next) => {
                    cookie = next.cookie;
                    cookieverf = next.cookieverf;
                }
                None => return Ok(entries),
            }
        }
    }

    async fn public_read_dir_with_limit(
        &mut self,
        path: &str,
        max_entries: usize,
    ) -> Result<Vec<DirEntry>> {
        let attr_request = self
            .public_supported_attr_request(path, FATTR4_BASIC_ATTRS)
            .await?;
        let mut cookie = 0;
        let mut cookieverf = [0; NFS4_VERIFIER_SIZE];
        let mut entries = Vec::new();
        loop {
            let response = self
                .compound(public_path_ops(
                    path,
                    vec![Operation::ReadDir {
                        cookie,
                        cookieverf,
                        dircount: (self.dir_size / 2).max(1),
                        maxcount: self.dir_size,
                        attr_request: attr_request.clone(),
                    }],
                )?)
                .await?;
            let (next_cookieverf, batch, eof) = response_readdir(&response)?;
            let next = next_dir_cursor(next_cookieverf, &batch, eof, cookie)?;
            if entries.len().saturating_add(batch.len()) > max_entries {
                return Err(Error::Protocol(format!(
                    "NFSv4 public-filehandle READDIR exceeded configured limit of {max_entries} entries"
                )));
            }
            entries.extend(
                batch
                    .into_iter()
                    .map(DirEntry::from_wire)
                    .collect::<Result<Vec<_>>>()?,
            );
            match next {
                Some(next) => {
                    cookie = next.cookie;
                    cookieverf = next.cookieverf;
                }
                None => return Ok(entries),
            }
        }
    }

    async fn parent_read_dir_with_limit(
        &mut self,
        path: &str,
        max_entries: usize,
    ) -> Result<Vec<DirEntry>> {
        let attr_request = self
            .parent_supported_attr_request(path, FATTR4_BASIC_ATTRS)
            .await?;
        let mut cookie = 0;
        let mut cookieverf = [0; NFS4_VERIFIER_SIZE];
        let mut entries = Vec::new();
        loop {
            let response = self
                .compound(parent_path_ops(
                    path,
                    vec![Operation::ReadDir {
                        cookie,
                        cookieverf,
                        dircount: (self.dir_size / 2).max(1),
                        maxcount: self.dir_size,
                        attr_request: attr_request.clone(),
                    }],
                )?)
                .await?;
            let (next_cookieverf, batch, eof) = response_readdir(&response)?;
            let next = next_dir_cursor(next_cookieverf, &batch, eof, cookie)?;
            if entries.len().saturating_add(batch.len()) > max_entries {
                return Err(Error::Protocol(format!(
                    "NFSv4 parent READDIR exceeded configured limit of {max_entries} entries"
                )));
            }
            entries.extend(
                batch
                    .into_iter()
                    .map(DirEntry::from_wire)
                    .collect::<Result<Vec<_>>>()?,
            );
            match next {
                Some(next) => {
                    cookie = next.cookie;
                    cookieverf = next.cookieverf;
                }
                None => return Ok(entries),
            }
        }
    }

    async fn read_named_attrs_with_limit(
        &mut self,
        path: &str,
        max_entries: usize,
    ) -> Result<Vec<DirEntry>> {
        let attr_request = self
            .named_attr_supported_attr_request(path, FATTR4_BASIC_ATTRS)
            .await?;
        let mut cookie = 0;
        let mut cookieverf = [0; NFS4_VERIFIER_SIZE];
        let mut entries = Vec::new();
        loop {
            let response = self
                .compound(path_ops(
                    path,
                    vec![
                        Operation::OpenAttr { create_dir: false },
                        Operation::ReadDir {
                            cookie,
                            cookieverf,
                            dircount: (self.dir_size / 2).max(1),
                            maxcount: self.dir_size,
                            attr_request: attr_request.clone(),
                        },
                    ],
                )?)
                .await?;
            let (next_cookieverf, batch, eof) = response_openattr_readdir(&response)?;
            let next = next_dir_cursor(next_cookieverf, &batch, eof, cookie)?;
            if entries.len().saturating_add(batch.len()) > max_entries {
                return Err(Error::Protocol(format!(
                    "NFSv4 OPENATTR READDIR exceeded configured limit of {max_entries} entries"
                )));
            }
            entries.extend(
                batch
                    .into_iter()
                    .map(DirEntry::from_wire)
                    .collect::<Result<Vec<_>>>()?,
            );
            match next {
                Some(next) => {
                    cookie = next.cookie;
                    cookieverf = next.cookieverf;
                }
                None => return Ok(entries),
            }
        }
    }

    pub async fn renew(&mut self) -> Result<()> {
        self.compound(Vec::new()).await.map(|_| ())
    }

    pub async fn shutdown(mut self) -> Result<()> {
        let session_id = self.session_id;
        let response = self
            .raw_compound(
                "destroy-session",
                self.minor_version,
                vec![Operation::DestroySession(session_id)],
            )
            .await?;
        response.ensure_ok()
    }

    /// Destroys the session and then the NFSv4 client id.
    pub async fn destroy_client_id(mut self) -> Result<()> {
        let session_response = self
            .raw_compound(
                "destroy-session",
                self.minor_version,
                vec![Operation::DestroySession(self.session_id)],
            )
            .await?;
        session_response.ensure_ok()?;
        let client_response = self
            .raw_compound(
                "destroy-clientid",
                self.minor_version,
                vec![Operation::DestroyClientId(self.client_id)],
            )
            .await?;
        client_response.ensure_ok()
    }

    async fn compound(&mut self, operations: Vec<Operation>) -> Result<CompoundResponse> {
        let response = self.compound_status(operations).await?;
        response.ensure_ok()?;
        Ok(response)
    }

    async fn compound_status(&mut self, operations: Vec<Operation>) -> Result<CompoundResponse> {
        validate_session_compound_operation_count(operations.len(), self.max_operations)?;
        let can_replay_after_session_recovery =
            operations_can_replay_after_session_recovery(&operations);
        let mut retry = 0;
        let mut recovered_session = false;
        loop {
            let mut with_sequence = Vec::with_capacity(operations.len() + 1);
            with_sequence.push(Operation::Sequence(SequenceArgs {
                session_id: self.session_id,
                sequence_id: self.sequence_id,
                slot_id: 0,
                highest_slot_id: 0,
                cache_this: false,
            }));
            with_sequence.extend(operations.iter().cloned());

            let response = self
                .raw_compound("nfs-rs-v4", self.minor_version, with_sequence)
                .await?;
            if sequence_succeeded(&response) {
                self.sequence_id = self.sequence_id.wrapping_add(1).max(1);
            }
            if response_requires_session_recovery(&response) && !recovered_session {
                let err = session_recovery_error(&response);
                self.recover_session().await?;
                recovered_session = true;
                if !can_replay_after_session_recovery {
                    return Err(err);
                }
                continue;
            }
            if response_allows_delayed_retry(&operations, &response)
                && let Some(delay) = self.retry_policy.delay_for_retry(retry)
            {
                retry += 1;
                ::tokio::time::sleep(delay).await;
                continue;
            }
            return Ok(response);
        }
    }

    async fn connect_with_builder(builder: ClientBuilder) -> Result<Self> {
        let mut client = Self::connect_session(builder).await?;
        if let Err(err) = client.refresh_root_fsinfo().await {
            return Err(cleanup_error(
                err,
                "cleanup DESTROY_SESSION after failed NFSv4 connect",
                client.shutdown().await,
            ));
        }
        Ok(client)
    }

    async fn connect_session(builder: ClientBuilder) -> Result<Self> {
        validate_host(&builder.host)?;
        validate_port("port", builder.port)?;
        validate_owner_id(&builder.owner_id)?;
        validate_open_owner(&builder.open_owner)?;
        validate_transfer_size("read_size", builder.read_size)?;
        validate_transfer_size("write_size", builder.write_size)?;
        validate_transfer_size("dir_size", builder.dir_size)?;
        validate_max_dir_entries(builder.max_dir_entries)?;
        validate_minor_version("max_minor_version", builder.max_minor_version)?;

        let mut last_minor_error = None;
        for minor_version in negotiated_minor_versions(builder.max_minor_version) {
            match Self::connect_session_minor(builder.clone(), minor_version).await {
                Ok(client) => return Ok(client),
                Err(err) if is_minor_version_mismatch(&err) => {
                    last_minor_error = Some(err);
                }
                Err(err) => return Err(err),
            }
        }

        Err(last_minor_error.unwrap_or_else(|| {
            Error::Protocol("NFSv4 server did not accept a supported minor version".to_owned())
        }))
    }

    async fn connect_session_minor(builder: ClientBuilder, minor_version: u32) -> Result<Self> {
        let stored_builder = builder.clone();
        let mut rpc = RpcClient::connect_with_timeout(
            (builder.host.as_str(), builder.port),
            Auth::sys(builder.auth.clone()),
            builder.timeout,
        )
        .await?;
        rpc.set_timeout(builder.timeout);
        rpc.set_max_record_size(max_record_size_for_payloads(&[
            builder.read_size,
            builder.write_size,
            builder.dir_size,
        ]))?;

        let exchange = ExchangeIdArgs {
            client_owner: ClientOwner {
                verifier: builder.client_owner_verifier,
                owner_id: builder.owner_id.clone(),
            },
            flags: EXCHGID4_FLAG_USE_NON_PNFS,
        };
        let exchange_res = raw_compound_with_delayed_retry(
            &mut rpc,
            "exchange-id",
            minor_version,
            vec![Operation::ExchangeId(exchange)],
            builder.retry_policy,
        )
        .await?;
        exchange_res.ensure_ok()?;
        let exchange = response_exchange_id(&exchange_res)?;

        let create_session = CreateSessionArgs {
            client_id: exchange.client_id,
            sequence_id: exchange.sequence_id,
            flags: 0,
            fore_channel_attrs: ChannelAttrs::fore_channel_default(),
            back_channel_attrs: ChannelAttrs::back_channel_disabled(),
            callback_program: 0,
            callback_sec_parms: Vec::new(),
        };
        let session_res = raw_compound_with_delayed_retry(
            &mut rpc,
            "create-session",
            minor_version,
            vec![Operation::CreateSession(create_session)],
            builder.retry_policy,
        )
        .await?;
        session_res.ensure_ok()?;
        let session = response_create_session(&session_res)?;
        if let Err(err) = validate_session_channel_attrs(&session.fore_channel_attrs) {
            return Err(cleanup_session_setup_error(
                &mut rpc,
                minor_version,
                session.session_id,
                err,
            )
            .await);
        }
        let max_operations = match session_max_operations(&session.fore_channel_attrs) {
            Ok(max_operations) => max_operations,
            Err(err) => {
                return Err(cleanup_session_setup_error(
                    &mut rpc,
                    minor_version,
                    session.session_id,
                    err,
                )
                .await);
            }
        };
        let max_request_size = session.fore_channel_attrs.max_request_size;
        let max_response_size = session.fore_channel_attrs.max_response_size;
        let mut sequence_id = 1;
        let reclaim_res = match reclaim_complete_with_delayed_retry(
            &mut rpc,
            minor_version,
            session.session_id,
            &mut sequence_id,
            max_operations,
            builder.retry_policy,
        )
        .await
        {
            Ok(response) => response,
            Err(err) => {
                return Err(cleanup_session_setup_error(
                    &mut rpc,
                    minor_version,
                    session.session_id,
                    err,
                )
                .await);
            }
        };
        if let Err(err) = ensure_reclaim_complete(&reclaim_res) {
            return Err(cleanup_session_setup_error(
                &mut rpc,
                minor_version,
                session.session_id,
                err,
            )
            .await);
        }

        let client = Self {
            rpc,
            builder: stored_builder,
            client_id: exchange.client_id,
            session_id: session.session_id,
            sequence_id,
            open_seqid: 1,
            open_owner: builder.open_owner.clone(),
            minor_version,
            max_operations,
            max_request_size,
            max_response_size,
            root_fsinfo: None,
            read_size: builder.read_size,
            write_size: builder.write_size,
            dir_size: builder.dir_size,
            max_dir_entries: builder.max_dir_entries,
            retry_policy: builder.retry_policy,
        };

        Ok(client)
    }

    async fn refresh_root_fsinfo(&mut self) -> Result<()> {
        let fsinfo = self.fsinfo("/").await?;
        self.apply_fsinfo_limits(&fsinfo)?;
        self.root_fsinfo = Some(fsinfo);
        Ok(())
    }

    fn apply_fsinfo_limits(&mut self, fsinfo: &FsInfo) -> Result<()> {
        let read_limit = self
            .builder
            .read_size
            .min(session_payload_limit(self.max_response_size));
        let write_limit = self
            .builder
            .write_size
            .min(session_payload_limit(self.max_request_size));
        let dir_limit = self
            .builder
            .dir_size
            .min(session_payload_limit(self.max_response_size));

        self.read_size = clamp_io_size(fsinfo.max_read, read_limit);
        self.write_size = clamp_io_size(fsinfo.max_write, write_limit);
        self.dir_size = dir_limit;
        self.rpc
            .set_max_record_size(max_record_size_for_payloads(&[
                self.read_size,
                self.write_size,
                self.dir_size,
            ]))?;
        Ok(())
    }

    async fn raw_compound(
        &mut self,
        tag: impl Into<String>,
        minor_version: u32,
        operations: Vec<Operation>,
    ) -> Result<CompoundResponse> {
        raw_compound_with_rpc(&mut self.rpc, tag, minor_version, operations).await
    }
}

#[derive(Debug, Clone)]
struct OpenedFile {
    handle: FileHandle,
    stateid: StateId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenFailureCleanup {
    KeepPath,
    RemovePath,
}

impl Client {
    async fn open(
        &mut self,
        path: &str,
        share_access: u32,
        openhow: OpenHow,
    ) -> Result<OpenedFile> {
        self.open_with_failure_cleanup(path, share_access, openhow, OpenFailureCleanup::KeepPath)
            .await
    }

    async fn open_with_owner(
        &mut self,
        path: &str,
        share_access: u32,
        openhow: OpenHow,
        owner: Vec<u8>,
    ) -> Result<OpenedFile> {
        self.open_with_owner_failure_cleanup(
            path,
            share_access,
            openhow,
            OpenFailureCleanup::KeepPath,
            owner,
        )
        .await
    }

    async fn open_temp(
        &mut self,
        path: &str,
        share_access: u32,
        openhow: OpenHow,
    ) -> Result<OpenedFile> {
        self.open_with_failure_cleanup(path, share_access, openhow, OpenFailureCleanup::RemovePath)
            .await
    }

    async fn open_with_failure_cleanup(
        &mut self,
        path: &str,
        share_access: u32,
        openhow: OpenHow,
        cleanup: OpenFailureCleanup,
    ) -> Result<OpenedFile> {
        let owner = self.open_owner.clone();
        self.open_with_owner_failure_cleanup(path, share_access, openhow, cleanup, owner)
            .await
    }

    async fn open_with_owner_failure_cleanup(
        &mut self,
        path: &str,
        share_access: u32,
        openhow: OpenHow,
        cleanup: OpenFailureCleanup,
        owner: Vec<u8>,
    ) -> Result<OpenedFile> {
        let (parent_components, file_name) = split_parent(path)?;
        let mut retry = 0;
        let mut recovered_session = false;

        loop {
            let seqid = self.current_open_seqid();
            let mut ops = vec![Operation::PutRootFh];
            for component in &parent_components {
                ops.push(Operation::Lookup((*component).to_owned()));
            }
            ops.push(Operation::Open(OpenArgs {
                seqid,
                share_access: share_access | OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
                share_deny: OPEN4_SHARE_DENY_NONE,
                owner: OpenOwner {
                    client_id: self.client_id,
                    owner: owner.clone(),
                },
                openhow: openhow.clone(),
                claim: OpenClaim::Null(file_name.clone()),
            }));
            ops.push(Operation::GetFh);

            let response = match self.compound_status(ops).await {
                Ok(response) => response,
                Err(err) if err.is_session_recoverable() && !recovered_session => {
                    recovered_session = true;
                    continue;
                }
                Err(err) => return Err(err),
            };
            if response_consumed_owner_seqid(&response, OpCode::Open) {
                self.advance_open_seqid();
            }
            if response_operation_has_delayed_status(&response, OpCode::Open)
                && let Some(delay) = self.retry_policy.delay_for_retry(retry)
            {
                retry += 1;
                ::tokio::time::sleep(delay).await;
                continue;
            }
            if response_operation_requires_session_recovery(&response, OpCode::Open)
                && !recovered_session
            {
                self.recover_session().await?;
                recovered_session = true;
                continue;
            }
            if let Err(error) = response.ensure_ok() {
                return Err(self
                    .cleanup_open_response(path, &response, error, cleanup)
                    .await);
            }
            let open = response_open(&response)?;
            let handle = match response_getfh(&response) {
                Ok(handle) => handle,
                Err(error) => {
                    let close_result = self.close_state_by_path(path, open.stateid).await;
                    return Err(self
                        .cleanup_failed_open(path, error, close_result, cleanup)
                        .await);
                }
            };
            let opened = OpenedFile {
                handle,
                stateid: open.stateid,
            };

            let delegation = match validate_open_result(&open, self.minor_version) {
                Ok(delegation) => delegation,
                Err(error) => {
                    let close_result = self.close(opened).await;
                    return Err(self
                        .cleanup_failed_open(path, error, close_result, cleanup)
                        .await);
                }
            };
            // The high-level client does not run a callback service, so avoid
            // keeping delegations that the server granted despite WANT_NO_DELEG.
            if let Some(delegation_stateid) = delegation
                && let Err(error) = self
                    .return_open_delegation(&opened.handle, delegation_stateid)
                    .await
            {
                let close_result = self.close(opened).await;
                return Err(self
                    .cleanup_failed_open(path, error, close_result, cleanup)
                    .await);
            }

            return Ok(opened);
        }
    }

    async fn open_named_attr(
        &mut self,
        path: &str,
        name: &str,
        share_access: u32,
        openhow: OpenHow,
        create_dir: bool,
    ) -> Result<OpenedFile> {
        validate_named_attr_name(name)?;
        let owner = self.open_owner.clone();
        let mut retry = 0;
        let mut recovered_session = false;

        loop {
            let seqid = self.current_open_seqid();
            let response = match self
                .compound_status(path_ops(
                    path,
                    vec![
                        Operation::OpenAttr { create_dir },
                        Operation::Open(OpenArgs {
                            seqid,
                            share_access: share_access | OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
                            share_deny: OPEN4_SHARE_DENY_NONE,
                            owner: OpenOwner {
                                client_id: self.client_id,
                                owner: owner.clone(),
                            },
                            openhow: openhow.clone(),
                            claim: OpenClaim::Null(name.to_owned()),
                        }),
                        Operation::GetFh,
                    ],
                )?)
                .await
            {
                Ok(response) => response,
                Err(err) if err.is_session_recoverable() && !recovered_session => {
                    recovered_session = true;
                    continue;
                }
                Err(err) => return Err(err),
            };
            if response_consumed_owner_seqid(&response, OpCode::Open) {
                self.advance_open_seqid();
            }
            if response_operation_has_delayed_status(&response, OpCode::Open)
                && let Some(delay) = self.retry_policy.delay_for_retry(retry)
            {
                retry += 1;
                ::tokio::time::sleep(delay).await;
                continue;
            }
            if response_operation_requires_session_recovery(&response, OpCode::Open)
                && !recovered_session
            {
                self.recover_session().await?;
                recovered_session = true;
                continue;
            }
            if let Err(error) = response.ensure_ok() {
                return Err(self
                    .cleanup_named_attr_open_response(path, name, &response, error)
                    .await);
            }

            let open = response_open(&response)?;
            let handle = match response_getfh(&response) {
                Ok(handle) => handle,
                Err(error) => {
                    let close_result = self
                        .close_named_attr_state_by_path(path, name, open.stateid)
                        .await;
                    return Err(open_cleanup_error(error, close_result));
                }
            };
            let opened = OpenedFile {
                handle,
                stateid: open.stateid,
            };

            let delegation = match validate_open_result(&open, self.minor_version) {
                Ok(delegation) => delegation,
                Err(error) => {
                    let close_result = self.close(opened).await;
                    return Err(open_cleanup_error(error, close_result));
                }
            };
            if let Some(delegation_stateid) = delegation
                && let Err(error) = self
                    .return_open_delegation(&opened.handle, delegation_stateid)
                    .await
            {
                let close_result = self.close(opened).await;
                return Err(open_cleanup_error(error, close_result));
            }

            return Ok(opened);
        }
    }

    async fn cleanup_named_attr_open_response(
        &mut self,
        path: &str,
        name: &str,
        response: &CompoundResponse,
        error: Error,
    ) -> Error {
        match response_open(response) {
            Ok(open) => {
                let close_result = self
                    .close_named_attr_state_by_path(path, name, open.stateid)
                    .await;
                open_cleanup_error(error, close_result)
            }
            Err(_) => error,
        }
    }

    async fn close_named_attr_state_by_path(
        &mut self,
        path: &str,
        name: &str,
        stateid: StateId,
    ) -> Result<()> {
        let prefix = path_ops(
            path,
            vec![
                Operation::OpenAttr { create_dir: false },
                Operation::Lookup(name.to_owned()),
            ],
        )?;
        self.close_with_current_filehandle(prefix, stateid).await
    }

    async fn cleanup_open_response(
        &mut self,
        path: &str,
        response: &CompoundResponse,
        error: Error,
        cleanup: OpenFailureCleanup,
    ) -> Error {
        match response_open(response) {
            Ok(open) => {
                let close_result = self.close_state_by_path(path, open.stateid).await;
                self.cleanup_failed_open(path, error, close_result, cleanup)
                    .await
            }
            Err(_) => error,
        }
    }

    async fn cleanup_failed_open(
        &mut self,
        path: &str,
        error: Error,
        close_result: Result<()>,
        cleanup: OpenFailureCleanup,
    ) -> Error {
        let error = open_cleanup_error(error, close_result);
        match cleanup {
            OpenFailureCleanup::KeepPath => error,
            OpenFailureCleanup::RemovePath => cleanup_error(
                error,
                "cleanup REMOVE after failed OPEN post-processing",
                self.remove(path).await,
            ),
        }
    }

    async fn ensure_directory_type(
        &mut self,
        path: &str,
        file_type: Option<FileType>,
    ) -> Result<()> {
        let is_directory = match file_type {
            Some(FileType::Directory) => true,
            Some(_) => false,
            None => self.probe_directory(path).await?,
        };
        if is_directory {
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "{path:?} exists but is not a directory"
            )))
        }
    }

    async fn path_is_directory(&mut self, path: &str, file_type: Option<FileType>) -> Result<bool> {
        match file_type {
            Some(FileType::Directory) => Ok(true),
            Some(_) => Ok(false),
            None => match self.metadata(path).await?.file_type {
                Some(FileType::Directory) => Ok(true),
                Some(_) => Ok(false),
                None => self.probe_directory(path).await,
            },
        }
    }

    async fn probe_directory(&mut self, path: &str) -> Result<bool> {
        match self
            .compound(path_ops(
                path,
                vec![Operation::ReadDir {
                    cookie: 0,
                    cookieverf: [0; NFS4_VERIFIER_SIZE],
                    dircount: 1,
                    maxcount: self.dir_size.clamp(1, 1024),
                    attr_request: Bitmap::empty(),
                }],
            )?)
            .await
        {
            Ok(response) => response_readdir(&response).map(|_| true),
            Err(Error::NfsV4 {
                status: Status::NotDir | Status::BadType | Status::WrongType,
                ..
            }) => Ok(false),
            Err(err) => Err(err),
        }
    }

    async fn supported_attr_request(&mut self, path: &str, attrs: &[u32]) -> Result<Bitmap> {
        let supported = self.supported_attrs(path).await?;
        Bitmap::from_supported_attrs(&supported, attrs)
    }

    async fn public_supported_attr_request(&mut self, path: &str, attrs: &[u32]) -> Result<Bitmap> {
        let supported = self.public_supported_attrs(path).await?;
        Bitmap::from_supported_attrs(&supported, attrs)
    }

    async fn parent_supported_attr_request(&mut self, path: &str, attrs: &[u32]) -> Result<Bitmap> {
        let supported = self.parent_supported_attrs(path).await?;
        Bitmap::from_supported_attrs(&supported, attrs)
    }

    async fn named_attr_supported_attr_request(
        &mut self,
        path: &str,
        attrs: &[u32],
    ) -> Result<Bitmap> {
        let supported_attrs = Bitmap::from_known_attrs(&[FATTR4_SUPPORTED_ATTRS]);
        let response = self
            .compound(path_ops(
                path,
                vec![
                    Operation::OpenAttr { create_dir: false },
                    Operation::GetAttr(supported_attrs),
                ],
            )?)
            .await?;
        let supported = response_getattr(&response)?.parse_supported_attrs()?;
        Bitmap::from_supported_attrs(&supported, attrs)
    }

    async fn get_supported_attr_values(&mut self, path: &str, attrs: &[u32]) -> Result<Fattr> {
        let attrs = self.supported_attr_request(path, attrs).await?;
        if attrs.is_empty() {
            return Ok(Fattr {
                attrmask: attrs,
                attr_vals: Vec::new(),
            });
        }
        let response = self
            .compound(path_ops(path, vec![Operation::GetAttr(attrs)])?)
            .await?;
        response_getattr(&response)
    }

    async fn read_opened_at(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        count: u32,
    ) -> Result<(bool, Vec<u8>)> {
        let response = self
            .compound(vec![
                Operation::PutFh(opened.handle.clone()),
                Operation::Read {
                    stateid: opened.stateid,
                    offset,
                    count,
                },
            ])
            .await?;
        response_read(&response, count)
    }

    async fn read_plus_opened(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        count: u32,
    ) -> Result<ReadPlusResult> {
        let response = self
            .compound(vec![
                Operation::PutFh(opened.handle.clone()),
                Operation::ReadPlus(ReadPlusArgs {
                    stateid: opened.stateid,
                    offset,
                    count,
                }),
            ])
            .await?;
        response_read_plus(&response, count)
    }

    async fn io_advise_opened(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        count: u64,
        hints: &[IoAdviceType],
    ) -> Result<IoAdviseResult> {
        let response = self
            .compound(vec![
                Operation::PutFh(opened.handle.clone()),
                Operation::IoAdvise(IoAdviseArgs {
                    stateid: opened.stateid,
                    offset,
                    count,
                    hints: io_advice_bitmap(hints),
                }),
            ])
            .await?;
        response_io_advise(&response)
    }

    async fn lock_opened(
        &mut self,
        opened: &OpenedFile,
        lock_type: LockType,
        offset: u64,
        length: u64,
        owner: Vec<u8>,
    ) -> Result<(StateId, u32)> {
        let mut retry = 0;
        let mut lock_seqid = 1;
        loop {
            let response = self
                .compound_status(vec![
                    Operation::PutFh(opened.handle.clone()),
                    Operation::Lock(LockArgs {
                        lock_type,
                        reclaim: false,
                        offset,
                        length,
                        locker: Locker::New {
                            open_seqid: self.current_open_seqid(),
                            open_stateid: opened.stateid,
                            lock_seqid,
                            lock_owner: LockOwner {
                                client_id: self.client_id,
                                owner: owner.clone(),
                            },
                        },
                    }),
                ])
                .await?;
            if response_consumed_owner_seqid(&response, OpCode::Lock) {
                self.advance_open_seqid();
                lock_seqid = lock_seqid.wrapping_add(1).max(1);
            }
            if response_operation_has_delayed_status(&response, OpCode::Lock)
                && let Some(delay) = self.retry_policy.delay_for_retry(retry)
            {
                retry += 1;
                ::tokio::time::sleep(delay).await;
                continue;
            }
            return response_lock(&response).map(|stateid| (stateid, lock_seqid));
        }
    }

    async fn unlock_opened(&mut self, lock: &ByteRangeLock) -> Result<StateId> {
        let mut retry = 0;
        let mut lock_seqid = lock.lock_seqid;
        loop {
            let response = self
                .compound_status(vec![
                    Operation::PutFh(lock.handle.clone()),
                    Operation::LockUnlock(LockUnlockArgs {
                        lock_type: lock.lock_type,
                        seqid: lock_seqid,
                        lock_stateid: lock.lock_stateid,
                        offset: lock.offset,
                        length: lock.length,
                    }),
                ])
                .await?;
            if response_consumed_owner_seqid(&response, OpCode::Locku) {
                lock_seqid = lock_seqid.wrapping_add(1).max(1);
            }
            if response_operation_has_delayed_status(&response, OpCode::Locku)
                && let Some(delay) = self.retry_policy.delay_for_retry(retry)
            {
                retry += 1;
                ::tokio::time::sleep(delay).await;
                continue;
            }
            return response_lock_unlock(&response);
        }
    }

    async fn seek_opened(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        what: SeekContent,
    ) -> Result<SeekResult> {
        let response = self
            .compound(vec![
                Operation::PutFh(opened.handle.clone()),
                Operation::Seek {
                    stateid: opened.stateid,
                    offset,
                    what,
                },
            ])
            .await?;
        response_seek(&response)
    }

    async fn set_opened_size(&mut self, opened: &OpenedFile, size: u64) -> Result<()> {
        self.set_opened_attrs(opened, Fattr::size(size)).await
    }

    async fn set_opened_attrs(&mut self, opened: &OpenedFile, attrs: Fattr) -> Result<()> {
        let setattr_response = self
            .compound(vec![
                Operation::PutFh(opened.handle.clone()),
                Operation::SetAttr {
                    stateid: opened.stateid,
                    attrs,
                },
            ])
            .await?;
        self.ensure_status(setattr_response, "SETATTR")
    }

    async fn return_open_delegation(
        &mut self,
        handle: &FileHandle,
        stateid: StateId,
    ) -> Result<()> {
        let response = self
            .compound(vec![
                Operation::PutFh(handle.clone()),
                Operation::DelegReturn(stateid),
            ])
            .await?;
        self.ensure_status(response, "DELEGRETURN")
    }

    async fn update_allocation(
        &mut self,
        path: &str,
        offset: u64,
        length: u64,
        op: SpaceOp,
    ) -> Result<()> {
        if length == 0 {
            return Ok(());
        }
        require_minor_version(op.name(), self.minor_version, NFS4_MINOR_VERSION_V42)?;

        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)
            .await?;
        let result = self
            .update_opened_allocation(&opened, offset, length, op)
            .await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    async fn update_opened_allocation(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        length: u64,
        op: SpaceOp,
    ) -> Result<()> {
        let response = self
            .compound(vec![
                Operation::PutFh(opened.handle.clone()),
                op.into_operation(opened.stateid, offset, length),
            ])
            .await?;
        self.ensure_status(response, op.name())
    }

    async fn write_same_opened(
        &mut self,
        opened: &OpenedFile,
        block: AppDataBlock,
        stable: StableHow,
    ) -> Result<WriteResponse> {
        let requested_count = app_data_block_len(&block)?;
        let response = self
            .compound(vec![
                Operation::PutFh(opened.handle.clone()),
                Operation::WriteSame(WriteSameArgs {
                    stateid: opened.stateid,
                    stable,
                    block,
                }),
            ])
            .await?;
        let write = response_write_same(&response, requested_count)?;
        if !write.committed.satisfies(stable) {
            return Err(Error::Protocol(
                "NFSv4 WRITE_SAME returned weaker stability than requested".into(),
            ));
        }
        Ok(write)
    }

    async fn write_opened_at(
        &mut self,
        opened: &OpenedFile,
        mut offset: u64,
        mut data: &[u8],
    ) -> Result<()> {
        while !data.is_empty() {
            let chunk_len = data.len().min(self.write_size as usize);
            let response = self
                .compound(vec![
                    Operation::PutFh(opened.handle.clone()),
                    Operation::Write {
                        stateid: opened.stateid,
                        offset,
                        stable: StableHow::FileSync,
                        data: data[..chunk_len].to_vec(),
                    },
                ])
                .await?;
            let result = response_write(&response, chunk_len as u32)?;
            let written = result.count;
            let written = written as usize;
            if !result.committed.satisfies(StableHow::FileSync) {
                let commit = self.commit_opened(opened, offset, result.count).await?;
                if commit.verifier != result.verifier {
                    return Err(Error::Protocol(
                        "NFSv4 COMMIT verifier changed after unstable WRITE".into(),
                    ));
                }
            }
            advance_offset(&mut offset, written, "NFSv4 WRITE")?;
            data = &data[written..];
        }
        Ok(())
    }

    async fn commit_opened(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        count: u32,
    ) -> Result<CommitResult> {
        let response = self
            .compound(vec![
                Operation::PutFh(opened.handle.clone()),
                Operation::Commit { offset, count },
            ])
            .await?;
        response_commit(&response)
    }

    async fn write_opened_from_reader<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        opened: &OpenedFile,
        reader: &mut R,
    ) -> Result<u64> {
        self.write_opened_from_reader_at(opened, 0, reader).await
    }

    async fn write_opened_from_reader_at<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        opened: &OpenedFile,
        mut offset: u64,
        reader: &mut R,
    ) -> Result<u64> {
        let mut written = 0;
        let mut buffer = vec![0; self.write_size as usize];
        loop {
            let read = reader.read(&mut buffer).await?;
            if read == 0 {
                return Ok(written);
            }
            self.write_opened_at(opened, offset, &buffer[..read])
                .await?;
            advance_offset(&mut offset, read, "NFSv4 WRITE reader")?;
            advance_offset(&mut written, read, "NFSv4 WRITE reader total")?;
        }
    }

    async fn copy_opened(&mut self, source: &OpenedFile, target: &OpenedFile) -> Result<u64> {
        let mut offset = 0;
        loop {
            let (eof, data) = self.read_opened_at(source, offset, self.read_size).await?;
            if data.is_empty() {
                return Ok(offset);
            }
            self.write_opened_at(target, offset, &data).await?;
            advance_offset(&mut offset, data.len(), "NFSv4 COPY")?;
            if eof {
                return Ok(offset);
            }
        }
    }

    async fn copy_opened_range_offload(
        &mut self,
        source: &OpenedFile,
        target: &OpenedFile,
        options: CopyOffloadOptions,
    ) -> Result<CopyResult> {
        let count = options.count;
        let response = self
            .compound(vec![
                Operation::PutFh(source.handle.clone()),
                Operation::SaveFh,
                Operation::PutFh(target.handle.clone()),
                Operation::Copy(CopyArgs {
                    src_stateid: source.stateid,
                    dst_stateid: target.stateid,
                    src_offset: options.src_offset,
                    dst_offset: options.dst_offset,
                    count,
                    consecutive: options.consecutive,
                    synchronous: options.synchronous,
                    source_servers: options.source_servers,
                }),
            ])
            .await?;
        response_copy(&response, count)
    }

    async fn copy_notify_opened(
        &mut self,
        source: &OpenedFile,
        destination_server: NetLoc,
    ) -> Result<CopyNotifyResult> {
        let response = self
            .compound(vec![
                Operation::PutFh(source.handle.clone()),
                Operation::CopyNotify(CopyNotifyArgs {
                    src_stateid: source.stateid,
                    destination_server,
                }),
            ])
            .await?;
        response_copy_notify(&response)
    }

    #[allow(clippy::too_many_arguments)]
    async fn layout_get_opened(
        &mut self,
        opened: &OpenedFile,
        layout_type: LayoutType,
        iomode: LayoutIomode,
        offset: u64,
        length: u64,
        min_length: u64,
        max_count: u32,
        signal_layout_avail: bool,
    ) -> Result<LayoutGetResult> {
        let response = self
            .compound(vec![
                Operation::PutFh(opened.handle.clone()),
                Operation::LayoutGet(LayoutGetArgs {
                    signal_layout_avail,
                    layout_type,
                    iomode,
                    offset,
                    length,
                    min_length,
                    stateid: opened.stateid,
                    max_count,
                }),
            ])
            .await?;
        response_layout_get(&response)
    }

    async fn clone_opened_range(
        &mut self,
        source: &OpenedFile,
        target: &OpenedFile,
        src_offset: u64,
        dst_offset: u64,
        count: u64,
    ) -> Result<()> {
        let response = self
            .compound(vec![
                Operation::PutFh(source.handle.clone()),
                Operation::SaveFh,
                Operation::PutFh(target.handle.clone()),
                Operation::Clone(CloneArgs {
                    src_stateid: source.stateid,
                    dst_stateid: target.stateid,
                    src_offset,
                    dst_offset,
                    count,
                }),
            ])
            .await?;
        self.ensure_status(response, "CLONE")
    }

    async fn close(&mut self, opened: OpenedFile) -> Result<()> {
        self.close_with_current_filehandle(vec![Operation::PutFh(opened.handle)], opened.stateid)
            .await
    }

    async fn close_state_by_path(&mut self, path: &str, stateid: StateId) -> Result<()> {
        let prefix = path_ops(path, Vec::new())?;
        self.close_with_current_filehandle(prefix, stateid).await
    }

    async fn close_with_current_filehandle(
        &mut self,
        operations: Vec<Operation>,
        stateid: StateId,
    ) -> Result<()> {
        let mut retry = 0;
        let mut recovered_session = false;
        loop {
            let seqid = self.current_open_seqid();
            let mut compound = operations.clone();
            compound.push(Operation::Close { seqid, stateid });
            let response = match self.compound_status(compound).await {
                Ok(response) => response,
                Err(err) if err.is_session_recoverable() && !recovered_session => {
                    recovered_session = true;
                    continue;
                }
                Err(err) => return Err(err),
            };
            if response_consumed_owner_seqid(&response, OpCode::Close) {
                self.advance_open_seqid();
            }
            if response_operation_has_delayed_status(&response, OpCode::Close)
                && let Some(delay) = self.retry_policy.delay_for_retry(retry)
            {
                retry += 1;
                ::tokio::time::sleep(delay).await;
                continue;
            }
            if response_operation_requires_session_recovery(&response, OpCode::Close)
                && !recovered_session
            {
                let error = response.ensure_ok().err().unwrap_or_else(|| {
                    Error::Protocol("CLOSE required session recovery but response was OK".into())
                });
                self.recover_session().await?;
                return Err(error);
            }
            response.ensure_ok()?;
            return self.ensure_status(response, "CLOSE");
        }
    }

    fn ensure_status(&self, response: CompoundResponse, operation: &'static str) -> Result<()> {
        self.ensure_status_for(&response, operation)
    }

    fn ensure_status_for(
        &self,
        response: &CompoundResponse,
        operation: &'static str,
    ) -> Result<()> {
        ensure_last_status(response, operation)
    }

    fn current_open_seqid(&self) -> u32 {
        self.open_seqid
    }

    fn advance_open_seqid(&mut self) {
        self.open_seqid = self.open_seqid.wrapping_add(1).max(1);
    }
}

async fn raw_compound_with_rpc(
    rpc: &mut RpcClient,
    tag: impl Into<String>,
    minor_version: u32,
    operations: Vec<Operation>,
) -> Result<CompoundResponse> {
    let tag = tag.into();
    let expected = operations
        .iter()
        .map(Operation::op_code)
        .collect::<Vec<_>>();
    let payload = rpc
        .call(
            NFS4_PROGRAM,
            NFS4_VERSION,
            1,
            &CompoundArgs {
                tag: tag.clone(),
                minor_version,
                operations,
            },
        )
        .await?;
    let mut decoder = Decoder::new(&payload);
    let response = CompoundResponse::decode(&mut decoder).map_err(|err| {
        Error::Protocol(format!(
            "failed to decode NFSv4 COMPOUND response for tag {tag:?} at byte {} of {}: {err}",
            decoder.position(),
            payload.len()
        ))
    })?;
    decoder.finish().map_err(|err| {
        Error::Protocol(format!(
            "failed to finish NFSv4 COMPOUND response for tag {tag:?} at byte {} of {}: {err}",
            decoder.position(),
            payload.len()
        ))
    })?;
    validate_compound_response_shape(&tag, &expected, &response)?;
    Ok(response)
}

async fn raw_compound_with_delayed_retry(
    rpc: &mut RpcClient,
    tag: &'static str,
    minor_version: u32,
    operations: Vec<Operation>,
    retry_policy: RetryPolicy,
) -> Result<CompoundResponse> {
    let mut retry = 0;
    loop {
        let response = raw_compound_with_rpc(rpc, tag, minor_version, operations.clone()).await?;
        if response_allows_delayed_retry_without_sequence(&operations, &response)
            && let Some(delay) = retry_policy.delay_for_retry(retry)
        {
            retry += 1;
            ::tokio::time::sleep(delay).await;
            continue;
        }
        return Ok(response);
    }
}

async fn reclaim_complete_with_delayed_retry(
    rpc: &mut RpcClient,
    minor_version: u32,
    session_id: SessionId,
    sequence_id: &mut u32,
    max_operations: usize,
    retry_policy: RetryPolicy,
) -> Result<CompoundResponse> {
    let operations = vec![Operation::ReclaimComplete { one_fs: false }];
    validate_session_compound_operation_count(operations.len(), max_operations)?;

    let mut retry = 0;
    loop {
        let mut compound = Vec::with_capacity(operations.len() + 1);
        compound.push(Operation::Sequence(SequenceArgs {
            session_id,
            sequence_id: *sequence_id,
            slot_id: 0,
            highest_slot_id: 0,
            cache_this: false,
        }));
        compound.extend(operations.iter().cloned());

        let response =
            raw_compound_with_rpc(rpc, "reclaim-complete", minor_version, compound).await?;
        if sequence_succeeded(&response) {
            *sequence_id = (*sequence_id).wrapping_add(1).max(1);
        }
        if response_allows_delayed_retry(&operations, &response)
            && let Some(delay) = retry_policy.delay_for_retry(retry)
        {
            retry += 1;
            ::tokio::time::sleep(delay).await;
            continue;
        }
        return Ok(response);
    }
}

async fn cleanup_session_setup_error(
    rpc: &mut RpcClient,
    minor_version: u32,
    session_id: SessionId,
    error: Error,
) -> Error {
    cleanup_error(
        error,
        "cleanup DESTROY_SESSION after failed NFSv4 session setup",
        destroy_session_with_rpc(rpc, minor_version, session_id).await,
    )
}

async fn destroy_session_with_rpc(
    rpc: &mut RpcClient,
    minor_version: u32,
    session_id: SessionId,
) -> Result<()> {
    let response = raw_compound_with_rpc(
        rpc,
        "destroy-session",
        minor_version,
        vec![Operation::DestroySession(session_id)],
    )
    .await?;
    response.ensure_ok()
}

fn is_minor_version_mismatch(err: &Error) -> bool {
    matches!(
        err,
        Error::NfsV4 {
            status: Status::MinorVersionMismatch,
            ..
        }
    )
}
