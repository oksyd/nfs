//! Blocking NFSv4 client.
//!
//! The client creates an NFSv4 session and executes path-oriented operations
//! against the server's v4 pseudo-filesystem.
//!
//! ```no_run
//! let mut client = nfs::v4::blocking::Client::connect("127.0.0.1")?;
//! client.write("/export/object.txt", b"payload")?;
//! assert_eq!(client.read("/export/object.txt")?, b"payload");
//! client.shutdown()?;
//! # Ok::<(), nfs::Error>(())
//! ```

use std::io::{Read, Write};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::retry::RetryPolicy;
use crate::rpc::{Auth, AuthSys, RpcClient, max_record_size_for_payloads};
use crate::v4::client::{
    CopyOffloadOptions, LockRegistry, LockState, SpaceOp, advance_offset, app_data_block_len,
    attrs_require_open_state, cleanup_error, device_list_page_from_result, dir_page_from_entries,
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

/// Builder for a blocking NFSv4 [`Client`].
///
/// Defaults are conservative: AUTH_SYS credentials from the current process,
/// port 2049, a 30 second timeout, generated client/open owner identifiers,
/// 128 KiB transfer limits, and the default [`RetryPolicy`].
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
    automatic_lease_renewal: bool,
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
            automatic_lease_renewal: false,
        }
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

    /// Enables background lease renewal on a separate session for the same client.
    ///
    /// Disabled by default. The server must support another session, and expose
    /// its lease time. A failed heartbeat triggers recovery on the next client
    /// operation; it cannot guarantee lock recovery after the grace period ends.
    pub fn automatic_lease_renewal(mut self, enabled: bool) -> Self {
        self.automatic_lease_renewal = enabled;
        self
    }

    /// Sets retry behavior for retryable transport and protocol responses.
    pub fn retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    /// Connects, creates an NFSv4 session, and returns a ready client.
    pub fn connect(self) -> Result<Client> {
        Client::connect_with_builder(self)
    }
}

/// Blocking, path-oriented NFSv4 client.
///
/// `Client` owns a session and handles sequencing, retryable delay responses,
/// and one-shot session recovery for recoverable session failures. Paths are
/// absolute paths in the server's v4 pseudo-filesystem.
#[derive(Debug)]
pub struct Client {
    rpc: RpcClient,
    locks: LockRegistry,
    recovery_pending: bool,
    lease_renewal: Option<super::lease::BlockingLease>,
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
    pub fn connect(host: impl Into<String>) -> Result<Self> {
        ClientBuilder::new(host).connect()
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
    pub fn lookup(&mut self, path: &str) -> Result<()> {
        self.compound(path_ops(path, Vec::new())?).map(|_| ())
    }

    /// Resolves a path relative to the NFSv4 public filehandle.
    pub fn lookup_public(&mut self, path: &str) -> Result<()> {
        self.compound(public_path_ops(path, Vec::new())?)
            .map(|_| ())
    }

    /// Returns whether a path exists relative to the NFSv4 public filehandle.
    pub fn public_exists(&mut self, path: &str) -> Result<bool> {
        match self.lookup_public(path) {
            Ok(_) => Ok(true),
            Err(Error::NfsV4 {
                status: Status::NoEnt,
                ..
            }) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Resolves a path and returns its NFSv4 file handle.
    pub fn file_handle(&mut self, path: &str) -> Result<FileHandle> {
        let response = self.compound(path_ops(path, vec![Operation::GetFh])?)?;
        response_getfh(&response)
    }

    /// Resolves a path relative to the public filehandle and returns its file handle.
    pub fn public_file_handle(&mut self, path: &str) -> Result<FileHandle> {
        let response = self.compound(public_path_ops(path, vec![Operation::GetFh])?)?;
        response_getfh(&response)
    }

    /// Resolves `path` and returns the file handle for its parent directory.
    pub fn parent_file_handle(&mut self, path: &str) -> Result<FileHandle> {
        let response = self.compound(parent_path_ops(path, vec![Operation::GetFh])?)?;
        response_getfh(&response)
    }

    /// Returns whether a path exists.
    pub fn exists(&mut self, path: &str) -> Result<bool> {
        match self.lookup(path) {
            Ok(_) => Ok(true),
            Err(Error::NfsV4 {
                status: Status::NoEnt,
                ..
            }) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Reads basic attributes for a path relative to the NFSv4 public filehandle.
    pub fn public_getattr(&mut self, path: &str) -> Result<BasicAttributes> {
        self.public_supported_attr_values(path, FATTR4_BASIC_ATTRS)?
            .parse_basic()
    }

    /// Returns the attribute bitmap supported for a public-filehandle path.
    pub fn public_supported_attrs(&mut self, path: &str) -> Result<Bitmap> {
        let attrs = Bitmap::from_known_attrs(&[FATTR4_SUPPORTED_ATTRS]);
        let response = self.compound(public_path_ops(path, vec![Operation::GetAttr(attrs)])?)?;
        response_getattr(&response)?.parse_supported_attrs()
    }

    /// Reads raw NFSv4 attributes for a public-filehandle path.
    pub fn public_getattr_values(&mut self, path: &str, attr_request: Bitmap) -> Result<Fattr> {
        if attr_request.is_empty() {
            return Ok(Fattr {
                attrmask: attr_request,
                attr_vals: Vec::new(),
            });
        }
        let response = self.compound(public_path_ops(
            path,
            vec![Operation::GetAttr(attr_request)],
        )?)?;
        response_getattr(&response)
    }

    /// Reads public-filehandle attributes after filtering the request by server support.
    pub fn public_supported_attr_values(&mut self, path: &str, attrs: &[u32]) -> Result<Fattr> {
        let supported = self.public_supported_attrs(path)?;
        let attrs = Bitmap::from_supported_attrs(&supported, attrs)?;
        self.public_getattr_values(path, attrs)
    }

    /// Reads all entries in a public-filehandle directory, subject to the client's entry limit.
    pub fn public_read_dir(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        self.public_read_dir_with_limit(path, self.max_dir_entries)
    }

    /// Reads all entries in a public-filehandle directory with a per-call entry limit.
    pub fn public_read_dir_limited(
        &mut self,
        path: &str,
        max_entries: usize,
    ) -> Result<Vec<DirEntry>> {
        validate_max_dir_entries(max_entries)?;
        self.public_read_dir_with_limit(path, max_entries.min(self.max_dir_entries))
    }

    /// Reads one page of public-filehandle directory entries.
    pub fn public_read_dir_page(
        &mut self,
        path: &str,
        cursor: Option<DirPageCursor>,
    ) -> Result<DirPage> {
        self.public_read_dir_page_limited(path, cursor, self.max_dir_entries)
    }

    /// Reads one page of public-filehandle directory entries with a per-page entry limit.
    pub fn public_read_dir_page_limited(
        &mut self,
        path: &str,
        cursor: Option<DirPageCursor>,
        max_entries: usize,
    ) -> Result<DirPage> {
        validate_max_dir_entries(max_entries)?;
        let max_entries = max_entries.min(self.max_dir_entries);
        let attr_request = self.public_supported_attr_request(path, FATTR4_BASIC_ATTRS)?;
        let cursor = cursor.unwrap_or_default();
        let response = self.compound(public_path_ops(
            path,
            vec![Operation::ReadDir {
                cookie: cursor.cookie,
                cookieverf: cursor.cookieverf,
                dircount: (self.dir_size / 2).max(1),
                maxcount: self.dir_size,
                attr_request,
            }],
        )?)?;
        let (cookieverf, entries, eof) = response_readdir(&response)?;
        dir_page_from_entries(cookieverf, entries, eof, cursor.cookie, max_entries)
    }

    /// Reads filesystem capacity attributes for a public-filehandle path.
    pub fn public_fsstat(&mut self, path: &str) -> Result<FsStat> {
        self.public_supported_attr_values(path, FATTR4_FSSTAT_ATTRS)?
            .parse_fsstat()
    }

    /// Reads filesystem capability attributes for a public-filehandle path.
    pub fn public_fsinfo(&mut self, path: &str) -> Result<FsInfo> {
        self.public_supported_attr_values(path, FATTR4_FSINFO_ATTRS)?
            .parse_fsinfo()
    }

    /// Reads path configuration limits for a public-filehandle path.
    pub fn public_pathconf(&mut self, path: &str) -> Result<PathConf> {
        self.public_supported_attr_values(path, FATTR4_PATHCONF_ATTRS)?
            .parse_pathconf()
    }

    /// Checks server-granted access bits for a public-filehandle path.
    pub fn public_access(&mut self, path: &str, access: u32) -> Result<AccessResult> {
        let response = self.compound(public_path_ops(path, vec![Operation::Access(access)])?)?;
        response_access(&response)
    }

    /// Reads basic attributes for the parent filehandle of `path` using `LOOKUPP`.
    pub fn parent_getattr(&mut self, path: &str) -> Result<BasicAttributes> {
        self.parent_supported_attr_values(path, FATTR4_BASIC_ATTRS)?
            .parse_basic()
    }

    /// Returns the attribute bitmap supported by the parent filehandle of `path`.
    pub fn parent_supported_attrs(&mut self, path: &str) -> Result<Bitmap> {
        let attrs = Bitmap::from_known_attrs(&[FATTR4_SUPPORTED_ATTRS]);
        let response = self.compound(parent_path_ops(path, vec![Operation::GetAttr(attrs)])?)?;
        response_getattr(&response)?.parse_supported_attrs()
    }

    /// Reads raw attributes for the parent filehandle of `path`.
    pub fn parent_getattr_values(&mut self, path: &str, attr_request: Bitmap) -> Result<Fattr> {
        if attr_request.is_empty() {
            return Ok(Fattr {
                attrmask: attr_request,
                attr_vals: Vec::new(),
            });
        }
        let response = self.compound(parent_path_ops(
            path,
            vec![Operation::GetAttr(attr_request)],
        )?)?;
        response_getattr(&response)
    }

    /// Reads parent filehandle attributes after filtering the request by server support.
    pub fn parent_supported_attr_values(&mut self, path: &str, attrs: &[u32]) -> Result<Fattr> {
        let supported = self.parent_supported_attrs(path)?;
        let attrs = Bitmap::from_supported_attrs(&supported, attrs)?;
        self.parent_getattr_values(path, attrs)
    }

    /// Reads all entries in the parent directory of `path`, subject to the client's entry limit.
    pub fn parent_read_dir(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        self.parent_read_dir_with_limit(path, self.max_dir_entries)
    }

    /// Reads all entries in the parent directory of `path` with a per-call entry limit.
    pub fn parent_read_dir_limited(
        &mut self,
        path: &str,
        max_entries: usize,
    ) -> Result<Vec<DirEntry>> {
        validate_max_dir_entries(max_entries)?;
        self.parent_read_dir_with_limit(path, max_entries.min(self.max_dir_entries))
    }

    /// Reads one page of entries from the parent directory of `path`.
    pub fn parent_read_dir_page(
        &mut self,
        path: &str,
        cursor: Option<DirPageCursor>,
    ) -> Result<DirPage> {
        self.parent_read_dir_page_limited(path, cursor, self.max_dir_entries)
    }

    /// Reads one page of entries from the parent directory of `path` with a per-page entry limit.
    pub fn parent_read_dir_page_limited(
        &mut self,
        path: &str,
        cursor: Option<DirPageCursor>,
        max_entries: usize,
    ) -> Result<DirPage> {
        validate_max_dir_entries(max_entries)?;
        let max_entries = max_entries.min(self.max_dir_entries);
        let attr_request = self.parent_supported_attr_request(path, FATTR4_BASIC_ATTRS)?;
        let cursor = cursor.unwrap_or_default();
        let response = self.compound(parent_path_ops(
            path,
            vec![Operation::ReadDir {
                cookie: cursor.cookie,
                cookieverf: cursor.cookieverf,
                dircount: (self.dir_size / 2).max(1),
                maxcount: self.dir_size,
                attr_request,
            }],
        )?)?;
        let (cookieverf, entries, eof) = response_readdir(&response)?;
        dir_page_from_entries(cookieverf, entries, eof, cursor.cookie, max_entries)
    }

    /// Reads filesystem capacity attributes for the parent filehandle of `path`.
    pub fn parent_fsstat(&mut self, path: &str) -> Result<FsStat> {
        self.parent_supported_attr_values(path, FATTR4_FSSTAT_ATTRS)?
            .parse_fsstat()
    }

    /// Reads filesystem capability attributes for the parent filehandle of `path`.
    pub fn parent_fsinfo(&mut self, path: &str) -> Result<FsInfo> {
        self.parent_supported_attr_values(path, FATTR4_FSINFO_ATTRS)?
            .parse_fsinfo()
    }

    /// Reads path configuration limits for the parent filehandle of `path`.
    pub fn parent_pathconf(&mut self, path: &str) -> Result<PathConf> {
        self.parent_supported_attr_values(path, FATTR4_PATHCONF_ATTRS)?
            .parse_pathconf()
    }

    /// Checks server-granted access bits for the parent filehandle of `path`.
    pub fn parent_access(&mut self, path: &str, access: u32) -> Result<AccessResult> {
        let response = self.compound(parent_path_ops(path, vec![Operation::Access(access)])?)?;
        response_access(&response)
    }

    /// Reads basic attributes for a path.
    pub fn getattr(&mut self, path: &str) -> Result<BasicAttributes> {
        self.get_supported_attr_values(path, FATTR4_BASIC_ATTRS)?
            .parse_basic()
    }

    /// Alias for [`Client::getattr`].
    pub fn metadata(&mut self, path: &str) -> Result<BasicAttributes> {
        self.getattr(path)
    }

    /// Returns the remote file type for a path.
    pub fn file_type(&mut self, path: &str) -> Result<FileType> {
        self.metadata(path)?.required_file_type()
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

    /// Returns the attribute bitmap supported by the server for a path.
    pub fn supported_attrs(&mut self, path: &str) -> Result<Bitmap> {
        let attrs = Bitmap::from_known_attrs(&[FATTR4_SUPPORTED_ATTRS]);
        let response = self.compound(path_ops(path, vec![Operation::GetAttr(attrs)])?)?;
        response_getattr(&response)?.parse_supported_attrs()
    }

    /// Reads raw NFSv4 attributes selected by `attr_request`.
    pub fn getattr_values(&mut self, path: &str, attr_request: Bitmap) -> Result<Fattr> {
        if attr_request.is_empty() {
            return Ok(Fattr {
                attrmask: attr_request,
                attr_vals: Vec::new(),
            });
        }
        let response = self.compound(path_ops(path, vec![Operation::GetAttr(attr_request)])?)?;
        response_getattr(&response)
    }

    /// Reads raw NFSv4 attributes after filtering the request by server support.
    pub fn supported_attr_values(&mut self, path: &str, attrs: &[u32]) -> Result<Fattr> {
        self.get_supported_attr_values(path, attrs)
    }

    /// Reads filesystem capacity attributes for a path.
    pub fn fsstat(&mut self, path: &str) -> Result<FsStat> {
        self.get_supported_attr_values(path, FATTR4_FSSTAT_ATTRS)?
            .parse_fsstat()
    }

    /// Reads filesystem capability attributes for a path.
    pub fn fsinfo(&mut self, path: &str) -> Result<FsInfo> {
        self.get_supported_attr_values(path, FATTR4_FSINFO_ATTRS)?
            .parse_fsinfo()
    }

    /// Reads path configuration limits for a path.
    pub fn pathconf(&mut self, path: &str) -> Result<PathConf> {
        self.get_supported_attr_values(path, FATTR4_PATHCONF_ATTRS)?
            .parse_pathconf()
    }

    /// Returns root filesystem information discovered at connect time, if available.
    pub fn root_fsinfo(&self) -> Option<&FsInfo> {
        self.root_fsinfo.as_ref()
    }

    /// Recreates the session and preserves or reclaims tracked byte-range locks.
    ///
    /// Returns a lost-state error if the server cannot restore a lock. Such locks
    /// are never silently acquired as new locks after their lease has expired.
    pub fn reconnect(&mut self) -> Result<()> {
        self.recover_session()
    }

    /// Updates callback program and security parameters for the backchannel.
    pub fn backchannel_ctl(
        &mut self,
        callback_program: u32,
        callback_sec_parms: Vec<CallbackSecParms>,
    ) -> Result<()> {
        let response = self.compound(vec![Operation::BackchannelCtl(BackchannelCtlArgs {
            callback_program,
            callback_sec_parms,
        })])?;
        self.ensure_status(response, "BACKCHANNEL_CTL")
    }

    /// Binds the current connection to the session for the requested direction.
    pub fn bind_conn_to_session(
        &mut self,
        direction: ChannelDirFromClient,
    ) -> Result<BindConnToSessionResult> {
        self.bind_conn_to_session_with_options(direction, false)
    }

    /// Binds the current connection to the session with explicit RDMA mode.
    pub fn bind_conn_to_session_with_options(
        &mut self,
        direction: ChannelDirFromClient,
        use_conn_in_rdma_mode: bool,
    ) -> Result<BindConnToSessionResult> {
        let response = self.raw_compound(
            "bind-conn-to-session",
            self.minor_version,
            vec![Operation::BindConnToSession(BindConnToSessionArgs {
                session_id: self.session_id,
                direction,
                use_conn_in_rdma_mode,
            })],
        )?;
        response_bind_conn_to_session(&response)
    }

    /// Executes `SET_SSV` and returns the server digest.
    pub fn set_ssv(&mut self, ssv: Vec<u8>, digest: Vec<u8>) -> Result<SetSsvResult> {
        let response = self.compound(vec![Operation::SetSsv(SetSsvArgs { ssv, digest })])?;
        response_set_ssv(&response)
    }

    fn recover_session(&mut self) -> Result<()> {
        // Keep this set across awaits: cancellation must not expose the old session.
        self.recovery_pending = true;
        let _ = self.stop_lease_renewal();
        let mut retry = 0;
        let mut rebuilt = loop {
            match Self::connect_session(self.builder.clone(), false) {
                Ok(client) => break client,
                Err(err) if err.is_transport_failure() => {
                    let Some(delay) = self.retry_policy.delay_for_retry(retry) else {
                        return Err(err);
                    };
                    retry += 1;
                    std::thread::sleep(delay);
                }
                Err(err) => return Err(err),
            }
        };
        rebuilt.locks = self.locks.clone();
        let same_client = rebuilt.client_id == self.client_id;
        if same_client {
            rebuilt.open_seqid = self.open_seqid;
        }
        let mut states = self.locks.snapshot();
        for (index, state) in states.iter_mut().enumerate() {
            if state.lost.is_some() {
                continue;
            }
            let recovered = if state.client_id == rebuilt.client_id {
                rebuilt.check_recovered_lock(state).map(|()| state.clone())
            } else {
                rebuilt.reclaim_lock(state)
            };
            match recovered {
                Ok(new_state) => *state = new_state,
                Err(Error::NfsV4 { status, .. })
                    if status.indicates_lost_state()
                        || matches!(
                            status,
                            Status::Stale | Status::FhExpired | Status::BadHandle | Status::NoEnt
                        ) =>
                {
                    state.lost = Some(status);
                }
                Err(err) => return Err(err),
            }
            // Preserve progress if a later reclaim or RECLAIM_COMPLETE is interrupted.
            rebuilt.locks.restore(index, state.clone());
        }
        // RFC 8881 section 8.4.2.1: reclaim OPEN and LOCK before completing recovery.
        let response =
            rebuilt.recovery_compound(vec![Operation::ReclaimComplete { one_fs: false }])?;
        ensure_reclaim_complete(&response)?;
        if self.root_fsinfo.is_some() {
            rebuilt.refresh_recovered_fsinfo()?;
        }
        rebuilt.start_lease_renewal()?;
        let old = std::mem::replace(self, rebuilt);
        let _ = old.shutdown();
        self.locks.ensure_valid()
    }

    fn refresh_recovered_fsinfo(&mut self) -> Result<()> {
        let response = self.recovery_compound(vec![
            Operation::PutRootFh,
            Operation::GetAttr(Bitmap::from_known_attrs(&[FATTR4_SUPPORTED_ATTRS])),
        ])?;
        response.ensure_ok()?;
        let supported = response_getattr(&response)?.parse_supported_attrs()?;
        let attrmask = Bitmap::from_supported_attrs(&supported, FATTR4_FSINFO_ATTRS)?;
        let attrs = if attrmask.is_empty() {
            Fattr {
                attrmask,
                attr_vals: Vec::new(),
            }
        } else {
            let response =
                self.recovery_compound(vec![Operation::PutRootFh, Operation::GetAttr(attrmask)])?;
            response.ensure_ok()?;
            response_getattr(&response)?
        };
        let fsinfo = attrs.parse_fsinfo()?;
        self.apply_fsinfo_limits(&fsinfo)?;
        self.root_fsinfo = Some(fsinfo);
        Ok(())
    }

    fn check_revoked_locks(&mut self) -> Result<()> {
        for (index, mut lock) in self.locks.snapshot().into_iter().enumerate() {
            if lock.lost.is_some() {
                continue;
            }
            let ids = vec![lock.open_stateid, lock.lock_stateid];
            let response = self.recovery_compound(vec![Operation::TestStateIds(ids.clone())])?;
            response.ensure_ok()?;
            let statuses = response_test_stateids(&response, ids.len())?;
            for (id, status) in ids.into_iter().zip(statuses) {
                if !status.is_ok() {
                    lock.lost = Some(status);
                    self.locks.restore(index, lock.clone());
                    // Acknowledge revoked state so SEQUENCE need not keep reporting it.
                    let _ = self.recovery_compound(vec![Operation::FreeStateId(id)]);
                }
            }
        }
        Ok(())
    }

    fn check_recovered_lock(&mut self, lock: &LockState) -> Result<()> {
        let response = self.recovery_compound(vec![Operation::TestStateIds(vec![
            lock.open_stateid,
            lock.lock_stateid,
        ])])?;
        response.ensure_ok()?;
        let statuses = response_test_stateids(&response, 2)?;
        for status in statuses {
            if !status.is_ok() {
                return Err(Error::nfsv4("TEST_STATEID", status));
            }
        }
        Ok(())
    }

    fn reclaim_lock(&mut self, lock: &LockState) -> Result<LockState> {
        let response = self.recovery_compound(vec![
            Operation::PutFh(lock.handle.clone()),
            Operation::Open(OpenArgs {
                seqid: self.current_open_seqid(),
                share_access: lock_share_access(lock.lock_type) | OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
                share_deny: OPEN4_SHARE_DENY_NONE,
                owner: OpenOwner {
                    client_id: self.client_id,
                    owner: lock.open_owner.clone(),
                },
                openhow: OpenHow::NoCreate,
                claim: OpenClaim::Previous(OpenDelegationType::None),
            }),
        ])?;
        if response_consumed_owner_seqid(&response, OpCode::Open) {
            self.advance_open_seqid();
        }
        response.ensure_ok()?;
        let open = response_open(&response)?;
        if let Some(stateid) = validate_open_result(&open, self.minor_version)? {
            self.recovery_compound(vec![
                Operation::PutFh(lock.handle.clone()),
                Operation::DelegReturn(stateid),
            ])?
            .ensure_ok()?;
        }
        let response = self.recovery_compound(vec![
            Operation::PutFh(lock.handle.clone()),
            Operation::Lock(LockArgs {
                lock_type: lock.lock_type,
                reclaim: true,
                offset: lock.offset,
                length: lock.length,
                locker: Locker::New {
                    open_seqid: self.current_open_seqid(),
                    open_stateid: open.stateid,
                    lock_seqid: 1,
                    lock_owner: LockOwner {
                        client_id: self.client_id,
                        owner: lock.owner.clone(),
                    },
                },
            }),
        ])?;
        if response_consumed_owner_seqid(&response, OpCode::Lock) {
            self.advance_open_seqid();
        }
        match response.ensure_ok().and_then(|()| response_lock(&response)) {
            Ok(lock_stateid) => Ok(LockState {
                client_id: self.client_id,
                open_stateid: open.stateid,
                lock_stateid,
                lock_seqid: 2,
                ..lock.clone()
            }),
            Err(err) => {
                let _ = self.recovery_compound(vec![
                    Operation::PutFh(lock.handle.clone()),
                    Operation::Close {
                        seqid: self.current_open_seqid(),
                        stateid: open.stateid,
                    },
                ]);
                self.advance_open_seqid();
                Err(err)
            }
        }
    }

    // Recovery RPCs never recursively create another session.
    fn recovery_compound(&mut self, operations: Vec<Operation>) -> Result<CompoundResponse> {
        validate_session_compound_operation_count(operations.len(), self.max_operations)?;
        let mut retry = 0;
        loop {
            let mut compound = vec![Operation::Sequence(SequenceArgs {
                session_id: self.session_id,
                sequence_id: self.sequence_id,
                slot_id: 0,
                highest_slot_id: 0,
                cache_this: false,
            })];
            compound.extend(operations.iter().cloned());
            let response = self.raw_compound("nfs-rs-recovery", self.minor_version, compound)?;
            if sequence_succeeded(&response) {
                self.sequence_id = self.sequence_id.wrapping_add(1).max(1);
            }
            if response_allows_delayed_retry(&operations, &response)
                && let Some(delay) = self.retry_policy.delay_for_retry(retry)
            {
                retry += 1;
                std::thread::sleep(delay);
                continue;
            }
            return Ok(response);
        }
    }

    /// Checks server-granted access bits for a path.
    pub fn access(&mut self, path: &str, access: u32) -> Result<AccessResult> {
        let response = self.compound(path_ops(path, vec![Operation::Access(access)])?)?;
        response_access(&response)
    }

    /// Returns security flavors accepted for `path` by querying its parent directory.
    pub fn secinfo(&mut self, path: &str) -> Result<Vec<SecInfo>> {
        let (parent, name) = split_parent(path)?;
        let mut ops = vec![Operation::PutRootFh];
        for component in parent {
            ops.push(Operation::Lookup(component.to_owned()));
        }
        ops.push(Operation::SecInfo(name));
        let response = self.compound(ops)?;
        response_secinfo(&response, OpCode::SecInfo)
    }

    /// Returns security flavors for the current or parent filehandle selected by `style`.
    pub fn secinfo_no_name(&mut self, path: &str, style: SecInfoStyle) -> Result<Vec<SecInfo>> {
        let response = self.compound(path_ops(path, vec![Operation::SecInfoNoName(style)])?)?;
        response_secinfo(&response, OpCode::SecInfoNoName)
    }

    /// Returns security flavors accepted for `path` using `SECINFO_NO_NAME`.
    pub fn secinfo_current(&mut self, path: &str) -> Result<Vec<SecInfo>> {
        self.secinfo_no_name(path, SecInfoStyle::CurrentFileHandle)
    }

    /// Returns security flavors accepted for the parent of `path` using `SECINFO_NO_NAME`.
    pub fn secinfo_parent(&mut self, path: &str) -> Result<Vec<SecInfo>> {
        self.secinfo_no_name(path, SecInfoStyle::Parent)
    }

    /// Verifies that the server attributes for `path` match `attrs`.
    ///
    /// Returns `Ok(true)` when the server returns `NFS4_OK`, `Ok(false)` when
    /// it returns `NFS4ERR_NOT_SAME`, and an error for other statuses.
    pub fn verify_attrs(&mut self, path: &str, attrs: &Fattr) -> Result<bool> {
        let response = self.compound(path_ops(path, vec![Operation::Verify(attrs.clone())])?)?;
        response_verify(&response, OpCode::Verify, Status::NotSame)
    }

    /// Verifies that the server attributes for `path` do not match `attrs`.
    ///
    /// Returns `Ok(true)` when the server returns `NFS4_OK`, `Ok(false)` when
    /// it returns `NFS4ERR_SAME`, and an error for other statuses.
    pub fn nverify_attrs(&mut self, path: &str, attrs: &Fattr) -> Result<bool> {
        let response = self.compound(path_ops(path, vec![Operation::NVerify(attrs.clone())])?)?;
        response_verify(&response, OpCode::NVerify, Status::Same)
    }

    /// Requests a read or write delegation for a path using the current filehandle claim.
    pub fn want_delegation(&mut self, path: &str, want: u32) -> Result<OpenDelegation> {
        self.want_delegation_with_claim(path, want, DelegationClaim::FileHandle)
    }

    /// Requests a delegation for a path using an explicit delegation claim.
    pub fn want_delegation_with_claim(
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
        let response = self.compound(path_ops(
            path,
            vec![Operation::WantDelegation(WantDelegationArgs {
                want,
                claim,
            })],
        )?)?;
        response_want_delegation(&response)
    }

    /// Requests a directory delegation with explicit protocol arguments.
    pub fn get_dir_delegation(
        &mut self,
        path: &str,
        args: GetDirDelegationArgs,
    ) -> Result<GetDirDelegationResult> {
        require_minor_version(
            "GET_DIR_DELEGATION",
            self.minor_version,
            NFS4_MINOR_VERSION_SESSION_MIN,
        )?;
        let response = self.compound(path_ops(path, vec![Operation::GetDirDelegation(args)])?)?;
        response_get_dir_delegation(&response)
    }

    /// Returns a delegation stateid for a path.
    pub fn return_delegation(&mut self, path: &str, stateid: StateId) -> Result<()> {
        let response = self.compound(path_ops(path, vec![Operation::DelegReturn(stateid)])?)?;
        self.ensure_status(response, "DELEGRETURN")
    }

    /// Purges delegations for this client id.
    pub fn purge_delegations(&mut self) -> Result<()> {
        let response = self.compound(vec![Operation::DelegPurge(self.client_id)])?;
        self.ensure_status(response, "DELEGPURGE")
    }

    /// Tests whether a byte-range lock would conflict with an existing lock.
    ///
    /// Returns `Ok(None)` when the server would grant the lock, or the
    /// conflicting lock details when the server returns `NFS4ERR_DENIED`.
    pub fn test_lock(
        &mut self,
        path: &str,
        lock_type: LockType,
        offset: u64,
        length: u64,
    ) -> Result<Option<LockDenied>> {
        let owner = self.open_owner.clone();
        self.test_lock_with_owner(path, lock_type, offset, length, owner)
    }

    /// Tests a byte-range lock using an explicit lock owner id.
    pub fn test_lock_with_owner(
        &mut self,
        path: &str,
        lock_type: LockType,
        offset: u64,
        length: u64,
        owner: impl Into<Vec<u8>>,
    ) -> Result<Option<LockDenied>> {
        let owner = owner.into();
        validate_lock_owner(&owner)?;
        let response = self.compound_status(path_ops(
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
        )?)?;
        response_lock_test(&response)
    }

    /// Acquires an NFSv4 byte-range lock using a generated lock owner.
    pub fn lock(
        &mut self,
        path: &str,
        lock_type: LockType,
        offset: u64,
        length: u64,
    ) -> Result<ByteRangeLock> {
        let owner = default_lock_owner(&self.builder.host);
        self.lock_with_owner(path, lock_type, offset, length, owner)
    }

    /// Acquires a shared read byte-range lock.
    pub fn read_lock(&mut self, path: &str, offset: u64, length: u64) -> Result<ByteRangeLock> {
        self.lock(path, LockType::Read, offset, length)
    }

    /// Acquires an exclusive write byte-range lock.
    pub fn write_lock(&mut self, path: &str, offset: u64, length: u64) -> Result<ByteRangeLock> {
        self.lock(path, LockType::Write, offset, length)
    }

    /// Acquires an NFSv4 byte-range lock using an explicit lock owner id.
    pub fn lock_with_owner(
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
        let opened = self.open_with_owner(
            path,
            lock_share_access(lock_type),
            OpenHow::NoCreate,
            open_owner.clone(),
        )?;
        let result = self.lock_opened(&opened, lock_type, offset, length, owner.clone());
        match result {
            Ok((lock_stateid, lock_seqid)) => Ok(self.locks.register(LockState {
                client_id: self.client_id,
                handle: opened.handle,
                open_stateid: opened.stateid,
                lock_stateid,
                lock_seqid,
                lock_type,
                offset,
                length,
                owner,
                open_owner,
                lost: None,
            })),
            Err(err) => Err(cleanup_error(
                err,
                "cleanup CLOSE after failed LOCK",
                self.close(opened),
            )),
        }
    }

    /// Releases an active NFSv4 byte-range lock.
    pub fn unlock(&mut self, lock: ByteRangeLock) -> Result<()> {
        let state = self.locks.get(&lock)?;
        // Releasing a lock relinquishes our claim to it even if the reply is lost.
        // A recovery triggered by LOCKU must never reclaim this released range.
        self.locks.remove(&lock);
        if let Some(status) = state.lost {
            if state.client_id == self.client_id {
                let _ = self.recovery_compound(vec![
                    Operation::PutFh(state.handle),
                    Operation::Close {
                        seqid: self.current_open_seqid(),
                        stateid: state.open_stateid,
                    },
                ]);
                self.advance_open_seqid();
            }
            return Err(Error::LockLost { status });
        }
        let opened = OpenedFile {
            handle: state.handle.clone(),
            stateid: state.open_stateid,
        };
        let result = match self.unlock_opened(&state) {
            Ok(stateid) => match self.free_stateid(stateid) {
                Ok(()) => self.release_lock_owner(state.owner).map(|_| ()),
                Err(err) => Err(err),
            },
            Err(err) => Err(err),
        };
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Releases server-side state associated with a stateid.
    pub fn free_stateid(&mut self, stateid: StateId) -> Result<()> {
        let response = self.compound(vec![Operation::FreeStateId(stateid)])?;
        self.ensure_status(response, "FREE_STATEID")
    }

    /// Tests a single NFSv4 stateid and returns its server-reported status.
    pub fn test_stateid(&mut self, stateid: StateId) -> Result<Status> {
        let mut statuses = self.test_stateids(&[stateid])?;
        statuses
            .pop()
            .ok_or_else(|| Error::Protocol("TEST_STATEID returned no status".into()))
    }

    /// Tests NFSv4 stateids and returns one status per requested stateid.
    pub fn test_stateids(&mut self, stateids: &[StateId]) -> Result<Vec<Status>> {
        if stateids.is_empty() {
            return Ok(Vec::new());
        }
        validate_stateid_batch_len(stateids.len())?;
        let response = self.compound(vec![Operation::TestStateIds(stateids.to_vec())])?;
        response_test_stateids(&response, stateids.len())
    }

    /// Releases a lock owner when the server no longer tracks locks for it.
    ///
    /// Returns `Ok(false)` when the server reports `NFS4ERR_LOCKS_HELD`.
    pub fn release_lock_owner(&mut self, owner: impl Into<Vec<u8>>) -> Result<bool> {
        let owner = owner.into();
        validate_lock_owner(&owner)?;
        let response = self.compound_status(vec![Operation::ReleaseLockOwner(LockOwner {
            client_id: self.client_id,
            owner,
        })])?;
        response_release_lock_owner(&response)
    }

    /// Sends NFSv4.2 I/O advice for a byte range.
    pub fn io_advise(
        &mut self,
        path: &str,
        offset: u64,
        count: u64,
        hints: &[IoAdviceType],
    ) -> Result<IoAdviseResult> {
        require_minor_version("IO_ADVISE", self.minor_version, NFS4_MINOR_VERSION_V42)?;
        let opened = self.open(path, io_advice_share_access(hints), OpenHow::NoCreate)?;
        let result = self.io_advise_opened(&opened, offset, count, hints);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Reads an entire file into memory.
    pub fn read(&mut self, path: &str) -> Result<Vec<u8>> {
        let opened = self.open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)?;
        let result = self.read_opened_to_end(&opened);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Streams an entire file into a local writer.
    pub fn read_to_writer<W: Write + ?Sized>(&mut self, path: &str, writer: &mut W) -> Result<u64> {
        let opened = self.open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)?;
        let result = self.read_opened_to_writer(&opened, writer);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Streams a byte range into a local writer.
    pub fn read_range_to_writer<W: Write + ?Sized>(
        &mut self,
        path: &str,
        offset: u64,
        count: u64,
        writer: &mut W,
    ) -> Result<u64> {
        let opened = self.open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)?;
        let result = self.read_opened_range_to_writer(&opened, offset, count, writer);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Reads a byte range into memory.
    pub fn read_range(&mut self, path: &str, offset: u64, count: u64) -> Result<Vec<u8>> {
        let opened = self.open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)?;
        let result = self.read_opened_range_vec(&opened, offset, count);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Reads up to `count` bytes at `offset`.
    pub fn read_at(&mut self, path: &str, offset: u64, count: u32) -> Result<Vec<u8>> {
        let opened = self.open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)?;
        let result = self.read_opened_range(&opened, offset, count);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Reads exactly `count` bytes at `offset`, failing if EOF is reached first.
    pub fn read_exact_at(&mut self, path: &str, offset: u64, count: u32) -> Result<Vec<u8>> {
        let data = self.read_at(path, offset, count)?;
        if data.len() != count as usize {
            return Err(Error::Protocol(format!(
                "NFSv4 READ returned {} bytes before EOF; expected {count}",
                data.len()
            )));
        }
        Ok(data)
    }

    /// Executes an NFSv4.2 `READ_PLUS` for a byte range.
    pub fn read_plus(&mut self, path: &str, offset: u64, count: u32) -> Result<ReadPlusResult> {
        require_minor_version("READ_PLUS", self.minor_version, NFS4_MINOR_VERSION_V42)?;
        let opened = self.open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)?;
        let result = self.read_plus_opened(&opened, offset, count);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Executes an NFSv4.2 SEEK operation.
    pub fn seek(&mut self, path: &str, offset: u64, what: SeekContent) -> Result<SeekResult> {
        require_minor_version("SEEK", self.minor_version, NFS4_MINOR_VERSION_V42)?;
        let opened = self.open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)?;
        let result = self.seek_opened(&opened, offset, what);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Finds the next data offset at or after `offset`.
    pub fn seek_data(&mut self, path: &str, offset: u64) -> Result<Option<u64>> {
        self.seek(path, offset, SeekContent::Data)
            .map(SeekResult::found_offset)
    }

    /// Finds the next hole offset at or after `offset`.
    pub fn seek_hole(&mut self, path: &str, offset: u64) -> Result<Option<u64>> {
        self.seek(path, offset, SeekContent::Hole)
            .map(SeekResult::found_offset)
    }

    /// Reads the target of a symbolic link.
    pub fn read_link(&mut self, path: &str) -> Result<String> {
        let response = self.compound(path_ops(path, vec![Operation::ReadLink])?)?;
        response_readlink(&response)
    }

    fn read_opened_to_end(&mut self, opened: &OpenedFile) -> Result<Vec<u8>> {
        let mut offset = 0;
        let mut out = Vec::new();
        loop {
            let (eof, data) = self.read_opened_at(opened, offset, self.read_size)?;
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

    fn read_opened_to_writer<W: Write + ?Sized>(
        &mut self,
        opened: &OpenedFile,
        writer: &mut W,
    ) -> Result<u64> {
        let mut offset = 0;
        let mut total = 0;
        loop {
            let (eof, data) = self.read_opened_at(opened, offset, self.read_size)?;
            if data.is_empty() {
                return Ok(total);
            }
            writer.write_all(&data)?;
            advance_offset(&mut offset, data.len(), "NFSv4 READ")?;
            advance_offset(&mut total, data.len(), "NFSv4 READ total")?;
            if eof {
                return Ok(total);
            }
        }
    }

    fn read_opened_range(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        count: u32,
    ) -> Result<Vec<u8>> {
        self.read_opened_range_vec(opened, offset, u64::from(count))
    }

    fn read_opened_range_vec(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        count: u64,
    ) -> Result<Vec<u8>> {
        let capacity = usize::try_from(count).unwrap_or(usize::MAX);
        let mut out = Vec::with_capacity(capacity.min(self.read_size as usize));
        self.read_opened_range_to_writer(opened, offset, count, &mut out)?;
        Ok(out)
    }

    fn read_opened_range_to_writer<W: Write + ?Sized>(
        &mut self,
        opened: &OpenedFile,
        mut offset: u64,
        mut remaining: u64,
        writer: &mut W,
    ) -> Result<u64> {
        let mut total = 0;
        while remaining > 0 {
            let request = u64::from(self.read_size).min(remaining) as u32;
            let (eof, data) = self.read_opened_at(opened, offset, request)?;
            if data.is_empty() {
                return Ok(total);
            }
            writer.write_all(&data)?;
            advance_offset(&mut offset, data.len(), "NFSv4 READ")?;
            advance_offset(&mut total, data.len(), "NFSv4 READ total")?;
            remaining -= data.len() as u64;
            if eof {
                return Ok(total);
            }
        }
        Ok(total)
    }

    /// Replaces or creates a file with `data`.
    pub fn write(&mut self, path: &str, data: &[u8]) -> Result<()> {
        self.write_with_mode(path, data, 0o644)
    }

    /// Replaces or creates a file with an explicit mode when created.
    pub fn write_with_mode(&mut self, path: &str, data: &[u8], mode: u32) -> Result<()> {
        let opened = self.open(
            path,
            OPEN4_SHARE_ACCESS_BOTH,
            OpenHow::Unchecked(Fattr::mode(mode)),
        )?;

        let result = self
            .set_opened_size(&opened, 0)
            .and_then(|()| self.write_opened_at(&opened, 0, data));
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Replaces or creates a file by streaming from a local reader.
    pub fn write_from_reader<R: Read + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
    ) -> Result<u64> {
        self.write_from_reader_with_mode(path, reader, 0o644)
    }

    /// Replaces or creates a file from a reader with an explicit mode when created.
    pub fn write_from_reader_with_mode<R: Read + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
        mode: u32,
    ) -> Result<u64> {
        let opened = self.open(
            path,
            OPEN4_SHARE_ACCESS_BOTH,
            OpenHow::Unchecked(Fattr::mode(mode)),
        )?;

        let result = self
            .set_opened_size(&opened, 0)
            .and_then(|()| self.write_opened_from_reader(&opened, reader));
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Writes a file through a temporary sibling and renames it into place.
    pub fn write_atomic(&mut self, path: &str, data: &[u8]) -> Result<()> {
        self.write_atomic_with_mode(path, data, 0o644)
    }

    /// Atomic write with an explicit mode for the temporary file.
    pub fn write_atomic_with_mode(&mut self, path: &str, data: &[u8], mode: u32) -> Result<()> {
        let temp = temporary_sibling_path(path)?;
        let mut created = false;

        let result = match self.open_temp(
            &temp,
            OPEN4_SHARE_ACCESS_BOTH,
            OpenHow::Guarded(Fattr::mode(mode)),
        ) {
            Ok(opened) => {
                created = true;
                let write_result = self.write_opened_at(&opened, 0, data);
                let close_result = self.close(opened);
                finish_with_close(write_result, close_result)
                    .and_then(|()| self.rename(&temp, path))
            }
            Err(err) => Err(err),
        };

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
        self.write_atomic_from_reader_with_mode(path, reader, 0o644)
    }

    /// Atomic reader-based write with an explicit mode for the temporary file.
    pub fn write_atomic_from_reader_with_mode<R: Read + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
        mode: u32,
    ) -> Result<u64> {
        let temp = temporary_sibling_path(path)?;
        let mut created = false;

        let result = match self.open_temp(
            &temp,
            OPEN4_SHARE_ACCESS_BOTH,
            OpenHow::Guarded(Fattr::mode(mode)),
        ) {
            Ok(opened) => {
                created = true;
                let write_result = self.write_opened_from_reader(&opened, reader);
                let close_result = self.close(opened);
                match finish_with_close(write_result, close_result) {
                    Ok(written) => self.rename(&temp, path).map(|()| written),
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
    }

    /// Appends bytes to an existing file and returns bytes written.
    pub fn append(&mut self, path: &str, data: &[u8]) -> Result<u64> {
        let offset = self.metadata(path)?.size.ok_or_else(|| {
            Error::Protocol("NFSv4 size attribute is required for append".to_owned())
        })?;
        let opened = self.open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)?;
        let result = (|| {
            self.write_opened_at(&opened, offset, data)?;
            let mut written = 0;
            advance_offset(&mut written, data.len(), "NFSv4 APPEND")?;
            Ok(written)
        })();
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Appends bytes from a local reader and returns bytes written.
    pub fn append_from_reader<R: Read + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
    ) -> Result<u64> {
        let offset = self.metadata(path)?.size.ok_or_else(|| {
            Error::Protocol("NFSv4 size attribute is required for append".to_owned())
        })?;
        let opened = self.open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)?;
        let result = self.write_opened_from_reader_at(&opened, offset, reader);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Truncates or extends a file to `size` bytes.
    pub fn truncate(&mut self, path: &str, size: u64) -> Result<()> {
        let opened = self.open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)?;
        let result = self.set_opened_size(&opened, size);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Allocates storage for a byte range when supported by the server.
    pub fn allocate(&mut self, path: &str, offset: u64, length: u64) -> Result<()> {
        self.update_allocation(path, offset, length, SpaceOp::Allocate)
    }

    /// Deallocates storage for a byte range when supported by the server.
    pub fn deallocate(&mut self, path: &str, offset: u64, length: u64) -> Result<()> {
        self.update_allocation(path, offset, length, SpaceOp::Deallocate)
    }

    /// Executes an NFSv4.2 `WRITE_SAME` operation.
    pub fn write_same(&mut self, path: &str, block: AppDataBlock) -> Result<WriteResponse> {
        self.write_same_with_stability(path, block, StableHow::FileSync)
    }

    /// Executes an NFSv4.2 `WRITE_SAME` operation with explicit stability.
    pub fn write_same_with_stability(
        &mut self,
        path: &str,
        block: AppDataBlock,
        stable: StableHow,
    ) -> Result<WriteResponse> {
        require_minor_version("WRITE_SAME", self.minor_version, NFS4_MINOR_VERSION_V42)?;
        let opened = self.open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)?;
        let result = self.write_same_opened(&opened, block, stable);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Applies NFSv4 attributes to a path.
    pub fn setattr(&mut self, path: &str, attrs: &SetAttrs) -> Result<()> {
        let attrs = Fattr::from_set_attrs(attrs)?;
        if attrs.attrmask.is_empty() {
            return Ok(());
        }
        if attrs_require_open_state(&attrs) {
            let opened = self.open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)?;
            let result = self.set_opened_attrs(&opened, attrs);
            let close_result = self.close(opened);
            return finish_with_close(result, close_result);
        }
        let response = self.compound(path_ops(
            path,
            vec![Operation::SetAttr {
                stateid: StateId::anonymous(),
                attrs,
            }],
        )?)?;
        self.ensure_status(response, "SETATTR")
    }

    /// Sets POSIX mode bits when the server supports the mode attribute.
    pub fn set_mode(&mut self, path: &str, mode: u32) -> Result<()> {
        self.setattr(path, &SetAttrs::mode(mode))
    }

    /// Sets the owner string.
    pub fn set_owner(&mut self, path: &str, owner: impl Into<String>) -> Result<()> {
        self.setattr(path, &SetAttrs::owner(owner))
    }

    /// Sets the owner group string.
    pub fn set_owner_group(&mut self, path: &str, owner_group: impl Into<String>) -> Result<()> {
        self.setattr(path, &SetAttrs::owner_group(owner_group))
    }

    /// Sets owner and owner group strings.
    pub fn set_ownership(
        &mut self,
        path: &str,
        owner: impl Into<String>,
        owner_group: impl Into<String>,
    ) -> Result<()> {
        self.setattr(path, &SetAttrs::ownership(owner, owner_group))
    }

    /// Sets access and modification times.
    pub fn set_times(
        &mut self,
        path: &str,
        access_time: Option<NfsTime>,
        modify_time: Option<NfsTime>,
    ) -> Result<()> {
        self.setattr(path, &SetAttrs::times(access_time, modify_time))
    }

    /// Updates access and modification times to the server time.
    pub fn touch(&mut self, path: &str) -> Result<()> {
        self.setattr(path, &SetAttrs::touch())
    }

    /// Writes bytes at `offset`.
    pub fn write_at(&mut self, path: &str, offset: u64, data: &[u8]) -> Result<()> {
        let opened = self.open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)?;
        let result = self.write_opened_at(&opened, offset, data);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Copies a file, replacing or creating the destination.
    pub fn copy(&mut self, from: &str, to: &str) -> Result<u64> {
        if path_components(from)? == path_components(to)? {
            return Err(Error::Protocol(
                "copy source and destination must differ".to_owned(),
            ));
        }
        let mode = self.metadata(from)?.mode.unwrap_or(0o644) & 0o7777;
        let source = self.open(from, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)?;
        let target = match self.open(
            to,
            OPEN4_SHARE_ACCESS_BOTH,
            OpenHow::Unchecked(Fattr::mode(mode)),
        ) {
            Ok(target) => target,
            Err(err) => {
                return Err(cleanup_error(
                    err,
                    "cleanup CLOSE source after failed target OPEN",
                    self.close(source),
                ));
            }
        };

        if let Err(error) = ensure_distinct_copy_handles(&source.handle, &target.handle) {
            let target_close = self.close(target);
            let source_close = self.close(source);
            return Err(cleanup_error(
                error,
                "cleanup CLOSE after rejected same-file copy",
                target_close.and(source_close),
            ));
        }

        let result = self
            .set_opened_size(&target, 0)
            .and_then(|()| self.copy_opened(&source, &target));
        let target_close = self.close(target);
        let source_close = self.close(source);
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

    /// Copies through a temporary sibling and renames it into place.
    pub fn copy_atomic(&mut self, from: &str, to: &str) -> Result<u64> {
        if path_components(from)? == path_components(to)? {
            return Err(Error::Protocol(
                "copy source and destination must differ".to_owned(),
            ));
        }
        let mode = self.metadata(from)?.mode.unwrap_or(0o644) & 0o7777;
        let temp = temporary_sibling_path(to)?;
        let source = self.open(from, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)?;
        let target = match self.open_temp(
            &temp,
            OPEN4_SHARE_ACCESS_BOTH,
            OpenHow::Guarded(Fattr::mode(mode)),
        ) {
            Ok(target) => target,
            Err(err) => {
                return Err(cleanup_error(
                    err,
                    "cleanup CLOSE source after failed atomic target OPEN",
                    self.close(source),
                ));
            }
        };

        let copy_result = self.copy_opened(&source, &target);
        let target_close = self.close(target);
        let source_close = self.close(source);
        let close_result = target_close.and(source_close);
        let result = match copy_result {
            Ok(copied) => {
                close_result?;
                self.rename(&temp, to).map(|()| copied)
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
    }

    /// Starts an NFSv4.2 server-side `COPY` for a byte range.
    ///
    /// The destination file must already exist. When the returned
    /// [`CopyResult`] contains a write response with a callback id, the server
    /// accepted an asynchronous offload; use [`Client::offload_status`] or
    /// [`Client::offload_cancel`] with that stateid.
    pub fn copy_range_offload(
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
    }

    /// Starts an NFSv4.2 server-side `COPY` with explicit COPY options.
    ///
    /// `source_servers` is normally empty for same-server copy. For
    /// inter-server copy, pass the source server locations returned by
    /// [`Client::copy_notify`].
    #[allow(clippy::too_many_arguments)]
    pub fn copy_range_offload_with_options(
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

        let source = self.open(from, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)?;
        let target = match self.open(to, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate) {
            Ok(target) => target,
            Err(err) => {
                return Err(cleanup_error(
                    err,
                    "cleanup CLOSE source after failed offload target OPEN",
                    self.close(source),
                ));
            }
        };

        if let Err(error) = ensure_distinct_copy_handles(&source.handle, &target.handle) {
            let target_close = self.close(target);
            let source_close = self.close(source);
            return Err(cleanup_error(
                error,
                "cleanup CLOSE after rejected same-file offload copy",
                target_close.and(source_close),
            ));
        }

        let result = self.copy_opened_range_offload(
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
        );
        let target_close = self.close(target);
        let source_close = self.close(source);
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

    /// Sends NFSv4.2 `COPY_NOTIFY` for a source path and destination server.
    pub fn copy_notify(
        &mut self,
        source: &str,
        destination_server: NetLoc,
    ) -> Result<CopyNotifyResult> {
        require_minor_version("COPY_NOTIFY", self.minor_version, NFS4_MINOR_VERSION_V42)?;
        let opened = self.open(source, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)?;
        let result = self.copy_notify_opened(&opened, destination_server);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Sends NFSv4.2 `COPY_NOTIFY` using an existing source stateid.
    pub fn copy_notify_with_stateid(
        &mut self,
        source: &str,
        stateid: StateId,
        destination_server: NetLoc,
    ) -> Result<CopyNotifyResult> {
        require_minor_version("COPY_NOTIFY", self.minor_version, NFS4_MINOR_VERSION_V42)?;
        let response = self.compound(path_ops(
            source,
            vec![Operation::CopyNotify(CopyNotifyArgs {
                src_stateid: stateid,
                destination_server,
            })],
        )?)?;
        response_copy_notify(&response)
    }

    /// Polls an asynchronous NFSv4.2 copy offload.
    pub fn offload_status(&mut self, stateid: StateId) -> Result<OffloadStatusResult> {
        require_minor_version("OFFLOAD_STATUS", self.minor_version, NFS4_MINOR_VERSION_V42)?;
        let response = self.compound(vec![Operation::OffloadStatus(stateid)])?;
        response_offload_status(&response)
    }

    /// Cancels an asynchronous NFSv4.2 copy offload.
    pub fn offload_cancel(&mut self, stateid: StateId) -> Result<()> {
        require_minor_version("OFFLOAD_CANCEL", self.minor_version, NFS4_MINOR_VERSION_V42)?;
        let response = self.compound(vec![Operation::OffloadCancel(stateid)])?;
        self.ensure_status(response, "OFFLOAD_CANCEL")
    }

    /// Reads pNFS device information for a device id.
    pub fn get_device_info(
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
    }

    /// Reads pNFS device information with an explicit response limit and notification bitmap.
    pub fn get_device_info_with_notify(
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
        let response = self.compound(vec![Operation::GetDeviceInfo(GetDeviceInfoArgs {
            device_id,
            layout_type,
            max_count,
            notify_types,
        })])?;
        response_get_device_info(&response)
    }

    /// Lists all pNFS device ids for a layout type, subject to the client's entry limit.
    pub fn list_devices(&mut self, layout_type: LayoutType) -> Result<Vec<DeviceId>> {
        self.list_devices_limited(layout_type, self.max_dir_entries)
    }

    /// Lists pNFS device ids for a layout type with a per-call device id limit.
    pub fn list_devices_limited(
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
            let page = self.list_device_page_limited(layout_type, cursor, remaining)?;
            device_ids.extend(page.device_ids);
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => return Ok(device_ids),
            }
        }
    }

    /// Reads one page of pNFS device ids for a layout type.
    pub fn list_device_page(
        &mut self,
        layout_type: LayoutType,
        cursor: Option<DeviceListCursor>,
    ) -> Result<DeviceListPage> {
        self.list_device_page_limited(layout_type, cursor, self.max_dir_entries)
    }

    /// Reads one page of pNFS device ids for a layout type with a per-page limit.
    pub fn list_device_page_limited(
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
        let response = self.compound(vec![Operation::GetDeviceList(GetDeviceListArgs {
            layout_type,
            max_devices,
            cookie: cursor.cookie,
            cookieverf: cursor.cookieverf,
        })])?;
        let result = response_get_device_list(&response)?;
        device_list_page_from_result(result, cursor.cookie, max_device_ids)
    }

    /// Gets pNFS layout segments for a file byte range.
    pub fn layout_get(
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
    }

    /// Gets pNFS layout segments with an explicit response limit and availability signal flag.
    #[allow(clippy::too_many_arguments)]
    pub fn layout_get_with_options(
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
        let opened = self.open(path, layout_iomode_share_access(iomode), OpenHow::NoCreate)?;
        let result = self.layout_get_opened(
            &opened,
            layout_type,
            iomode,
            offset,
            length,
            min_length,
            max_count,
            signal_layout_avail,
        );
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Commits layout metadata for a file byte range.
    pub fn layout_commit(
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
    }

    /// Commits layout metadata with optional last-write and modify-time fields.
    #[allow(clippy::too_many_arguments)]
    pub fn layout_commit_with_options(
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
        let response = self.compound(path_ops(
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
        )?)?;
        response_layout_commit(&response)
    }

    /// Reports pNFS data-server I/O errors for a layout range.
    pub fn layout_error(
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
        let response = self.compound(path_ops(
            path,
            vec![Operation::LayoutError(LayoutErrorArgs {
                offset,
                length,
                stateid,
                errors,
            })],
        )?)?;
        self.ensure_status(response, "LAYOUTERROR")
    }

    /// Reports pNFS I/O statistics for a layout range.
    #[allow(clippy::too_many_arguments)]
    pub fn layout_stats(
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
        let response = self.compound(path_ops(
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
        )?)?;
        self.ensure_status(response, "LAYOUTSTATS")
    }

    /// Returns a file-specific pNFS layout.
    #[allow(clippy::too_many_arguments)]
    pub fn layout_return_file(
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
        let response = self.compound(path_ops(
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
        )?)?;
        response_layout_return(&response)
    }

    /// Returns all layouts for the filesystem containing `path`.
    pub fn layout_return_fsid(
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
        let response = self.compound(path_ops(
            path,
            vec![Operation::LayoutReturn(LayoutReturnArgs {
                reclaim: false,
                layout_type,
                iomode,
                layout_return: LayoutReturn::Fsid,
            })],
        )?)?;
        response_layout_return(&response)
    }

    /// Returns all layouts held by this client for a layout type.
    pub fn layout_return_all(
        &mut self,
        layout_type: LayoutType,
        iomode: LayoutIomode,
    ) -> Result<LayoutReturnResult> {
        require_minor_version(
            "LAYOUTRETURN",
            self.minor_version,
            NFS4_MINOR_VERSION_SESSION_MIN,
        )?;
        let response = self.compound(vec![Operation::LayoutReturn(LayoutReturnArgs {
            reclaim: false,
            layout_type,
            iomode,
            layout_return: LayoutReturn::All,
        })])?;
        response_layout_return(&response)
    }

    /// Clones a byte range into an existing destination file with NFSv4.2 `CLONE`.
    pub fn clone_range(
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

        let source = self.open(from, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)?;
        let target = match self.open(to, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate) {
            Ok(target) => target,
            Err(err) => {
                return Err(cleanup_error(
                    err,
                    "cleanup CLOSE source after failed clone target OPEN",
                    self.close(source),
                ));
            }
        };

        let result = self.clone_opened_range(&source, &target, src_offset, dst_offset, count);
        let target_close = self.close(target);
        let source_close = self.close(source);
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

    /// Commits previously unstable writes for a byte range.
    pub fn commit(&mut self, path: &str, offset: u64, count: u32) -> Result<CommitResult> {
        let response = self.compound(path_ops(path, vec![Operation::Commit { offset, count }])?)?;
        response_commit(&response)
    }

    /// Creates a new file using default mode `0o644`.
    pub fn create(&mut self, path: &str) -> Result<()> {
        self.create_new(path)
    }

    /// Creates a new file and fails if it already exists.
    pub fn create_new(&mut self, path: &str) -> Result<()> {
        self.create_new_with_mode(path, 0o644)
    }

    /// Creates or replaces a file with an explicit mode.
    pub fn create_with_mode(&mut self, path: &str, mode: u32) -> Result<()> {
        self.create_new_with_mode(path, mode)
    }

    /// Creates a new file with an explicit mode and fails if it already exists.
    pub fn create_new_with_mode(&mut self, path: &str, mode: u32) -> Result<()> {
        let opened = self.open(
            path,
            OPEN4_SHARE_ACCESS_BOTH,
            OpenHow::Guarded(Fattr::mode(mode)),
        )?;
        self.close(opened)
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

    fn finish_with_named_attr_cleanup<T>(
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
                self.remove_named_attr(path, temp_name),
            )),
            Err(err) => Err(err),
        }
    }

    /// Creates a directory.
    pub fn mkdir(&mut self, path: &str, mode: u32) -> Result<()> {
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

        let response = self.compound(ops)?;
        self.ensure_status_for(&response, "CREATE")
    }

    /// Creates a directory and missing parents, like `mkdir -p`.
    pub fn create_dir_all(&mut self, path: &str, mode: u32) -> Result<()> {
        let components = path_components(path)?;
        let mut current = String::from("/");
        for component in components {
            current = join_path(&current, component);
            match self.metadata(&current) {
                Ok(attrs) => self.ensure_directory_type(&current, attrs.file_type)?,
                Err(Error::NfsV4 {
                    status: Status::NoEnt,
                    ..
                }) => match self.mkdir(&current, mode) {
                    Ok(_) => {}
                    Err(Error::NfsV4 {
                        status: Status::Exist,
                        ..
                    }) => {
                        let attrs = self.metadata(&current)?;
                        self.ensure_directory_type(&current, attrs.file_type)?;
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

        let response = self.compound(ops)?;
        self.ensure_status_for(&response, "CREATE")
    }

    /// Creates a FIFO special file.
    pub fn create_fifo(&mut self, path: &str, mode: u32) -> Result<()> {
        self.create_special(path, CreateKind::Fifo, mode)
    }

    /// Creates a socket special file.
    pub fn create_socket(&mut self, path: &str, mode: u32) -> Result<()> {
        self.create_special(path, CreateKind::Socket, mode)
    }

    /// Creates a block device special file.
    pub fn create_block_device(
        &mut self,
        path: &str,
        major: u32,
        minor: u32,
        mode: u32,
    ) -> Result<()> {
        self.create_special(path, CreateKind::BlockDevice { major, minor }, mode)
    }

    /// Creates a character device special file.
    pub fn create_character_device(
        &mut self,
        path: &str,
        major: u32,
        minor: u32,
        mode: u32,
    ) -> Result<()> {
        self.create_special(path, CreateKind::CharacterDevice { major, minor }, mode)
    }

    fn create_special(&mut self, path: &str, kind: CreateKind, mode: u32) -> Result<()> {
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

        let response = self.compound(ops)?;
        self.ensure_status_for(&response, "CREATE")
    }

    /// Creates a hard link.
    pub fn hard_link(&mut self, existing: &str, link: &str) -> Result<()> {
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

        let response = self.compound(ops)?;
        self.ensure_status(response, "LINK")
    }

    /// Removes a non-directory entry.
    pub fn remove(&mut self, path: &str) -> Result<()> {
        let (parent_components, name) = split_parent(path)?;
        let mut ops = vec![Operation::PutRootFh];
        for component in parent_components {
            ops.push(Operation::Lookup(component.to_owned()));
        }
        ops.push(Operation::Remove(name));

        let response = self.compound(ops)?;
        self.ensure_status(response, "REMOVE")
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
        self.remove(path)
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
    /// The NFSv4 pseudo-filesystem root itself cannot be removed through this method.
    pub fn remove_all(&mut self, path: &str) -> Result<()> {
        if path_components(path)?.is_empty() {
            return Err(Error::InvalidPath(path.to_owned()));
        }

        enum RemoveTask {
            Visit(String, Option<FileType>),
            RemoveDir(String),
        }

        let file_type = self.metadata(path)?.file_type;
        let mut stack = vec![RemoveTask::Visit(path.to_owned(), file_type)];
        while let Some(task) = stack.pop() {
            match task {
                RemoveTask::Visit(path, file_type) => {
                    if self.path_is_directory(&path, file_type)? {
                        stack.push(RemoveTask::RemoveDir(path.clone()));
                        let entries = self.read_dir(&path)?;
                        for entry in entries.into_iter().rev() {
                            if entry.name == "." || entry.name == ".." {
                                continue;
                            }
                            let child = join_path(&path, &entry.name);
                            let child_type = entry.basic_attributes()?.file_type;
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

        let response = self.compound(ops)?;
        self.ensure_status(response, "RENAME")
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
        let attr_request = self.supported_attr_request(path, FATTR4_BASIC_ATTRS)?;
        let cursor = cursor.unwrap_or_default();
        let response = self.compound(path_ops(
            path,
            vec![Operation::ReadDir {
                cookie: cursor.cookie,
                cookieverf: cursor.cookieverf,
                dircount: (self.dir_size / 2).max(1),
                maxcount: self.dir_size,
                attr_request,
            }],
        )?)?;
        let (cookieverf, entries, eof) = response_readdir(&response)?;
        dir_page_from_entries(cookieverf, entries, eof, cursor.cookie, max_entries)
    }

    /// Reads all named attributes for a path, subject to the client's entry limit.
    pub fn read_named_attrs(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        self.read_named_attrs_with_limit(path, self.max_dir_entries)
    }

    /// Reads all named attributes for a path with a per-call entry limit.
    pub fn read_named_attrs_limited(
        &mut self,
        path: &str,
        max_entries: usize,
    ) -> Result<Vec<DirEntry>> {
        validate_max_dir_entries(max_entries)?;
        self.read_named_attrs_with_limit(path, max_entries.min(self.max_dir_entries))
    }

    /// Reads one page of named attributes for a path.
    pub fn read_named_attr_page(
        &mut self,
        path: &str,
        cursor: Option<DirPageCursor>,
    ) -> Result<DirPage> {
        self.read_named_attr_page_limited(path, cursor, self.max_dir_entries)
    }

    /// Reads one page of named attributes for a path with a per-page entry limit.
    pub fn read_named_attr_page_limited(
        &mut self,
        path: &str,
        cursor: Option<DirPageCursor>,
        max_entries: usize,
    ) -> Result<DirPage> {
        validate_max_dir_entries(max_entries)?;
        let max_entries = max_entries.min(self.max_dir_entries);
        let attr_request = self.named_attr_supported_attr_request(path, FATTR4_BASIC_ATTRS)?;
        let cursor = cursor.unwrap_or_default();
        let response = self.compound(path_ops(
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
        )?)?;
        let (cookieverf, entries, eof) = response_openattr_readdir(&response)?;
        dir_page_from_entries(cookieverf, entries, eof, cursor.cookie, max_entries)
    }

    /// Returns whether a named attribute exists.
    pub fn named_attr_exists(&mut self, path: &str, name: &str) -> Result<bool> {
        match self.named_attr_metadata(path, name) {
            Ok(_) => Ok(true),
            Err(err) if err.is_not_found() => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Reads basic attributes for a named attribute.
    pub fn named_attr_metadata(&mut self, path: &str, name: &str) -> Result<BasicAttributes> {
        self.named_attr_supported_attr_values(path, name, FATTR4_BASIC_ATTRS)?
            .parse_basic()
    }

    /// Returns the attribute bitmap supported by a named attribute.
    pub fn named_attr_supported_attrs(&mut self, path: &str, name: &str) -> Result<Bitmap> {
        let attrs = Bitmap::from_known_attrs(&[FATTR4_SUPPORTED_ATTRS]);
        let response =
            self.compound(named_attr_ops(path, name, vec![Operation::GetAttr(attrs)])?)?;
        response_getattr(&response)?.parse_supported_attrs()
    }

    /// Reads raw NFSv4 attributes selected by `attr_request` for a named attribute.
    pub fn named_attr_getattr_values(
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
        let response = self.compound(named_attr_ops(
            path,
            name,
            vec![Operation::GetAttr(attr_request)],
        )?)?;
        response_getattr(&response)
    }

    /// Reads raw NFSv4 attributes for a named attribute after filtering by server support.
    pub fn named_attr_supported_attr_values(
        &mut self,
        path: &str,
        name: &str,
        attrs: &[u32],
    ) -> Result<Fattr> {
        let supported = self.named_attr_supported_attrs(path, name)?;
        let attrs = Bitmap::from_supported_attrs(&supported, attrs)?;
        self.named_attr_getattr_values(path, name, attrs)
    }

    /// Reads a named attribute value into memory.
    pub fn read_named_attr(&mut self, path: &str, name: &str) -> Result<Vec<u8>> {
        let opened = self.open_named_attr(
            path,
            name,
            OPEN4_SHARE_ACCESS_READ,
            OpenHow::NoCreate,
            false,
        )?;
        let result = self.read_opened_to_end(&opened);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Streams a named attribute value into a local writer.
    pub fn read_named_attr_to_writer<W: Write + ?Sized>(
        &mut self,
        path: &str,
        name: &str,
        writer: &mut W,
    ) -> Result<u64> {
        let opened = self.open_named_attr(
            path,
            name,
            OPEN4_SHARE_ACCESS_READ,
            OpenHow::NoCreate,
            false,
        )?;
        let result = self.read_opened_to_writer(&opened, writer);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Streams a named attribute byte range into a local writer.
    pub fn read_named_attr_range_to_writer<W: Write + ?Sized>(
        &mut self,
        path: &str,
        name: &str,
        offset: u64,
        count: u64,
        writer: &mut W,
    ) -> Result<u64> {
        let opened = self.open_named_attr(
            path,
            name,
            OPEN4_SHARE_ACCESS_READ,
            OpenHow::NoCreate,
            false,
        )?;
        let result = self.read_opened_range_to_writer(&opened, offset, count, writer);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Reads a named attribute byte range into memory.
    pub fn read_named_attr_range(
        &mut self,
        path: &str,
        name: &str,
        offset: u64,
        count: u64,
    ) -> Result<Vec<u8>> {
        let opened = self.open_named_attr(
            path,
            name,
            OPEN4_SHARE_ACCESS_READ,
            OpenHow::NoCreate,
            false,
        )?;
        let result = self.read_opened_range_vec(&opened, offset, count);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Reads up to `count` bytes from a named attribute at `offset`.
    pub fn read_named_attr_at(
        &mut self,
        path: &str,
        name: &str,
        offset: u64,
        count: u32,
    ) -> Result<Vec<u8>> {
        let opened = self.open_named_attr(
            path,
            name,
            OPEN4_SHARE_ACCESS_READ,
            OpenHow::NoCreate,
            false,
        )?;
        let result = self.read_opened_range(&opened, offset, count);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Reads exactly `count` bytes from a named attribute at `offset`.
    pub fn read_named_attr_exact_at(
        &mut self,
        path: &str,
        name: &str,
        offset: u64,
        count: u32,
    ) -> Result<Vec<u8>> {
        let data = self.read_named_attr_at(path, name, offset, count)?;
        if data.len() != count as usize {
            return Err(Error::Protocol(format!(
                "NFSv4 named attribute READ returned {} bytes before EOF; expected {count}",
                data.len()
            )));
        }
        Ok(data)
    }

    /// Replaces or creates a named attribute value.
    pub fn write_named_attr(&mut self, path: &str, name: &str, data: &[u8]) -> Result<()> {
        self.write_named_attr_with_mode(path, name, data, 0o644)
    }

    /// Replaces or creates a named attribute value with an explicit mode when created.
    pub fn write_named_attr_with_mode(
        &mut self,
        path: &str,
        name: &str,
        data: &[u8],
        mode: u32,
    ) -> Result<()> {
        let opened = self.open_named_attr(
            path,
            name,
            OPEN4_SHARE_ACCESS_BOTH,
            OpenHow::Unchecked(Fattr::mode(mode)),
            true,
        )?;
        let result = self
            .set_opened_size(&opened, 0)
            .and_then(|()| self.write_opened_at(&opened, 0, data));
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Replaces or creates a named attribute by streaming from a local reader.
    pub fn write_named_attr_from_reader<R: Read + ?Sized>(
        &mut self,
        path: &str,
        name: &str,
        reader: &mut R,
    ) -> Result<u64> {
        self.write_named_attr_from_reader_with_mode(path, name, reader, 0o644)
    }

    /// Replaces or creates a named attribute from a reader with an explicit mode.
    pub fn write_named_attr_from_reader_with_mode<R: Read + ?Sized>(
        &mut self,
        path: &str,
        name: &str,
        reader: &mut R,
        mode: u32,
    ) -> Result<u64> {
        let opened = self.open_named_attr(
            path,
            name,
            OPEN4_SHARE_ACCESS_BOTH,
            OpenHow::Unchecked(Fattr::mode(mode)),
            true,
        )?;
        let result = self
            .set_opened_size(&opened, 0)
            .and_then(|()| self.write_opened_from_reader(&opened, reader));
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Replaces or creates a named attribute through a temporary attribute.
    pub fn write_named_attr_atomic(&mut self, path: &str, name: &str, data: &[u8]) -> Result<()> {
        self.write_named_attr_atomic_with_mode(path, name, data, 0o644)
    }

    /// Atomic named attribute write with an explicit mode for the temporary attribute.
    pub fn write_named_attr_atomic_with_mode(
        &mut self,
        path: &str,
        name: &str,
        data: &[u8],
        mode: u32,
    ) -> Result<()> {
        validate_named_attr_name(name)?;
        let temp_name = temporary_named_attr_name();
        let mut created = false;

        let result = match self.open_named_attr(
            path,
            &temp_name,
            OPEN4_SHARE_ACCESS_BOTH,
            OpenHow::Guarded(Fattr::mode(mode)),
            true,
        ) {
            Ok(opened) => {
                created = true;
                let write_result = self.write_opened_at(&opened, 0, data);
                let close_result = self.close(opened);
                match finish_with_close(write_result, close_result) {
                    Ok(()) => self.rename_named_attr(path, &temp_name, name),
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
    }

    /// Atomically writes a named attribute by streaming from a local reader.
    pub fn write_named_attr_atomic_from_reader<R: Read + ?Sized>(
        &mut self,
        path: &str,
        name: &str,
        reader: &mut R,
    ) -> Result<u64> {
        self.write_named_attr_atomic_from_reader_with_mode(path, name, reader, 0o644)
    }

    /// Atomic reader-based named attribute write with an explicit temporary mode.
    pub fn write_named_attr_atomic_from_reader_with_mode<R: Read + ?Sized>(
        &mut self,
        path: &str,
        name: &str,
        reader: &mut R,
        mode: u32,
    ) -> Result<u64> {
        validate_named_attr_name(name)?;
        let temp_name = temporary_named_attr_name();
        let mut created = false;

        let result = match self.open_named_attr(
            path,
            &temp_name,
            OPEN4_SHARE_ACCESS_BOTH,
            OpenHow::Guarded(Fattr::mode(mode)),
            true,
        ) {
            Ok(opened) => {
                created = true;
                let write_result = self.write_opened_from_reader(&opened, reader);
                let close_result = self.close(opened);
                match finish_with_close(write_result, close_result) {
                    Ok(written) => self
                        .rename_named_attr(path, &temp_name, name)
                        .map(|()| written),
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
    }

    /// Writes bytes to an existing named attribute at `offset`.
    pub fn write_named_attr_at(
        &mut self,
        path: &str,
        name: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<()> {
        let opened = self.open_named_attr(
            path,
            name,
            OPEN4_SHARE_ACCESS_WRITE,
            OpenHow::NoCreate,
            false,
        )?;
        let result = self.write_opened_at(&opened, offset, data);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Appends bytes to an existing named attribute and returns bytes written.
    pub fn append_named_attr(&mut self, path: &str, name: &str, data: &[u8]) -> Result<u64> {
        let offset = self.named_attr_metadata(path, name)?.size.ok_or_else(|| {
            Error::Protocol(
                "NFSv4 named attribute size attribute is required for append".to_owned(),
            )
        })?;
        let opened = self.open_named_attr(
            path,
            name,
            OPEN4_SHARE_ACCESS_WRITE,
            OpenHow::NoCreate,
            false,
        )?;
        let result = (|| {
            self.write_opened_at(&opened, offset, data)?;
            let mut written = 0;
            advance_offset(&mut written, data.len(), "NFSv4 named attribute APPEND")?;
            Ok(written)
        })();
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Appends bytes from a local reader to an existing named attribute.
    pub fn append_named_attr_from_reader<R: Read + ?Sized>(
        &mut self,
        path: &str,
        name: &str,
        reader: &mut R,
    ) -> Result<u64> {
        let offset = self.named_attr_metadata(path, name)?.size.ok_or_else(|| {
            Error::Protocol(
                "NFSv4 named attribute size attribute is required for append".to_owned(),
            )
        })?;
        let opened = self.open_named_attr(
            path,
            name,
            OPEN4_SHARE_ACCESS_WRITE,
            OpenHow::NoCreate,
            false,
        )?;
        let result = self.write_opened_from_reader_at(&opened, offset, reader);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Copies one named attribute value, replacing or creating the destination.
    pub fn copy_named_attr(
        &mut self,
        from_path: &str,
        from_name: &str,
        to_path: &str,
        to_name: &str,
    ) -> Result<u64> {
        let mode = self
            .named_attr_metadata(from_path, from_name)?
            .mode
            .unwrap_or(0o644)
            & 0o7777;
        let source = self.open_named_attr(
            from_path,
            from_name,
            OPEN4_SHARE_ACCESS_READ,
            OpenHow::NoCreate,
            false,
        )?;
        let target = match self.open_named_attr(
            to_path,
            to_name,
            OPEN4_SHARE_ACCESS_BOTH,
            OpenHow::Unchecked(Fattr::mode(mode)),
            true,
        ) {
            Ok(target) => target,
            Err(err) => {
                return Err(cleanup_error(
                    err,
                    "cleanup CLOSE source after failed named attribute target OPEN",
                    self.close(source),
                ));
            }
        };

        if let Err(error) = ensure_distinct_copy_handles(&source.handle, &target.handle) {
            let target_close = self.close(target);
            let source_close = self.close(source);
            return Err(cleanup_error(
                error,
                "cleanup CLOSE after rejected same named attribute copy",
                target_close.and(source_close),
            ));
        }

        let result = self
            .set_opened_size(&target, 0)
            .and_then(|()| self.copy_opened(&source, &target));
        let target_close = self.close(target);
        let source_close = self.close(source);
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

    /// Copies one named attribute through a temporary destination attribute.
    pub fn copy_named_attr_atomic(
        &mut self,
        from_path: &str,
        from_name: &str,
        to_path: &str,
        to_name: &str,
    ) -> Result<u64> {
        validate_named_attr_name(to_name)?;
        let mode = self
            .named_attr_metadata(from_path, from_name)?
            .mode
            .unwrap_or(0o644)
            & 0o7777;
        let temp_name = temporary_named_attr_name();

        let source = self.open_named_attr(
            from_path,
            from_name,
            OPEN4_SHARE_ACCESS_READ,
            OpenHow::NoCreate,
            false,
        )?;
        let target = match self.open_named_attr(
            to_path,
            &temp_name,
            OPEN4_SHARE_ACCESS_BOTH,
            OpenHow::Guarded(Fattr::mode(mode)),
            true,
        ) {
            Ok(target) => target,
            Err(err) => {
                return Err(cleanup_error(
                    err,
                    "cleanup CLOSE source after failed atomic named attribute target OPEN",
                    self.close(source),
                ));
            }
        };

        let copy_result = match ensure_distinct_copy_handles(&source.handle, &target.handle) {
            Ok(()) => self.copy_opened(&source, &target),
            Err(err) => Err(err),
        };
        let target_close = self.close(target);
        let source_close = self.close(source);
        let close_result = target_close.and(source_close);
        let result = match copy_result {
            Ok(copied) => {
                close_result?;
                self.rename_named_attr(to_path, &temp_name, to_name)
                    .map(|()| copied)
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
    }

    /// Updates attributes for an existing named attribute.
    pub fn set_named_attr_attrs(&mut self, path: &str, name: &str, attrs: &SetAttrs) -> Result<()> {
        let attrs = Fattr::from_set_attrs(attrs)?;
        if attrs.attrmask.is_empty() {
            return Ok(());
        }
        let opened = self.open_named_attr(
            path,
            name,
            OPEN4_SHARE_ACCESS_WRITE,
            OpenHow::NoCreate,
            false,
        )?;
        let result = self.set_opened_attrs(&opened, attrs);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Sets the mode bits for an existing named attribute.
    pub fn set_named_attr_mode(&mut self, path: &str, name: &str, mode: u32) -> Result<()> {
        self.set_named_attr_attrs(path, name, &SetAttrs::mode(mode))
    }

    /// Sets ownership for an existing named attribute.
    pub fn set_named_attr_ownership(
        &mut self,
        path: &str,
        name: &str,
        owner: impl Into<String>,
        owner_group: impl Into<String>,
    ) -> Result<()> {
        self.set_named_attr_attrs(path, name, &SetAttrs::ownership(owner, owner_group))
    }

    /// Sets access and modification times for an existing named attribute.
    pub fn set_named_attr_times(
        &mut self,
        path: &str,
        name: &str,
        access_time: Option<NfsTime>,
        modify_time: Option<NfsTime>,
    ) -> Result<()> {
        self.set_named_attr_attrs(path, name, &SetAttrs::times(access_time, modify_time))
    }

    /// Truncates an existing named attribute value.
    pub fn truncate_named_attr(&mut self, path: &str, name: &str, size: u64) -> Result<()> {
        self.set_named_attr_attrs(path, name, &SetAttrs::size(size))
    }

    /// Renames a named attribute on a path.
    pub fn rename_named_attr(&mut self, path: &str, from_name: &str, to_name: &str) -> Result<()> {
        validate_named_attr_name(from_name)?;
        validate_named_attr_name(to_name)?;
        let response = self.compound(path_ops(
            path,
            vec![
                Operation::OpenAttr { create_dir: false },
                Operation::SaveFh,
                Operation::Rename {
                    oldname: from_name.to_owned(),
                    newname: to_name.to_owned(),
                },
            ],
        )?)?;
        self.ensure_status(response, "RENAME")
    }

    /// Renames a named attribute if it exists.
    pub fn rename_named_attr_if_exists(
        &mut self,
        path: &str,
        from_name: &str,
        to_name: &str,
    ) -> Result<bool> {
        match self.rename_named_attr(path, from_name, to_name) {
            Ok(()) => Ok(true),
            Err(err) if err.is_not_found() => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Removes a named attribute from a path.
    pub fn remove_named_attr(&mut self, path: &str, name: &str) -> Result<()> {
        validate_named_attr_name(name)?;
        let response = self.compound(path_ops(
            path,
            vec![
                Operation::OpenAttr { create_dir: false },
                Operation::Remove(name.to_owned()),
            ],
        )?)?;
        self.ensure_status(response, "REMOVE")
    }

    /// Removes a named attribute if it exists.
    pub fn remove_named_attr_if_exists(&mut self, path: &str, name: &str) -> Result<bool> {
        match self.remove_named_attr(path, name) {
            Ok(()) => Ok(true),
            Err(err) if err.is_not_found() => Ok(false),
            Err(err) => Err(err),
        }
    }

    fn read_dir_with_limit(&mut self, path: &str, max_entries: usize) -> Result<Vec<DirEntry>> {
        let attr_request = self.supported_attr_request(path, FATTR4_BASIC_ATTRS)?;
        let mut cookie = 0;
        let mut cookieverf = [0; NFS4_VERIFIER_SIZE];
        let mut entries = Vec::new();
        loop {
            let response = self.compound(path_ops(
                path,
                vec![Operation::ReadDir {
                    cookie,
                    cookieverf,
                    dircount: (self.dir_size / 2).max(1),
                    maxcount: self.dir_size,
                    attr_request: attr_request.clone(),
                }],
            )?)?;
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

    fn public_read_dir_with_limit(
        &mut self,
        path: &str,
        max_entries: usize,
    ) -> Result<Vec<DirEntry>> {
        let attr_request = self.public_supported_attr_request(path, FATTR4_BASIC_ATTRS)?;
        let mut cookie = 0;
        let mut cookieverf = [0; NFS4_VERIFIER_SIZE];
        let mut entries = Vec::new();
        loop {
            let response = self.compound(public_path_ops(
                path,
                vec![Operation::ReadDir {
                    cookie,
                    cookieverf,
                    dircount: (self.dir_size / 2).max(1),
                    maxcount: self.dir_size,
                    attr_request: attr_request.clone(),
                }],
            )?)?;
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

    fn parent_read_dir_with_limit(
        &mut self,
        path: &str,
        max_entries: usize,
    ) -> Result<Vec<DirEntry>> {
        let attr_request = self.parent_supported_attr_request(path, FATTR4_BASIC_ATTRS)?;
        let mut cookie = 0;
        let mut cookieverf = [0; NFS4_VERIFIER_SIZE];
        let mut entries = Vec::new();
        loop {
            let response = self.compound(parent_path_ops(
                path,
                vec![Operation::ReadDir {
                    cookie,
                    cookieverf,
                    dircount: (self.dir_size / 2).max(1),
                    maxcount: self.dir_size,
                    attr_request: attr_request.clone(),
                }],
            )?)?;
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

    fn read_named_attrs_with_limit(
        &mut self,
        path: &str,
        max_entries: usize,
    ) -> Result<Vec<DirEntry>> {
        let attr_request = self.named_attr_supported_attr_request(path, FATTR4_BASIC_ATTRS)?;
        let mut cookie = 0;
        let mut cookieverf = [0; NFS4_VERIFIER_SIZE];
        let mut entries = Vec::new();
        loop {
            let response = self.compound(path_ops(
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
            )?)?;
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

    /// Suggested heartbeat interval derived from the server's advertised lease.
    pub fn lease_renewal_interval(&self) -> Option<Duration> {
        self.root_fsinfo
            .as_ref()?
            .lease_time_seconds
            .filter(|seconds| *seconds > 0)
            .map(|seconds| Duration::from_secs(u64::from(seconds)) / 3)
    }

    fn stop_lease_renewal(&mut self) -> Result<()> {
        if let Some(lease) = self.lease_renewal.take() {
            let session_id = lease.stop();
            let response = self.raw_compound(
                "destroy-lease-session",
                self.minor_version,
                vec![Operation::DestroySession(session_id)],
            )?;
            if !matches!(response.status, Status::BadSession | Status::DeadSession) {
                response.ensure_ok()?;
            }
        }
        Ok(())
    }

    fn start_lease_renewal(&mut self) -> Result<()> {
        if !self.builder.automatic_lease_renewal {
            return Ok(());
        }
        let interval = self.lease_renewal_interval().ok_or_else(|| {
            Error::Protocol("server did not advertise a usable NFSv4 lease time".into())
        })?;
        let mut builder = self.builder.clone();
        builder.automatic_lease_renewal = false;
        builder.timeout = Some(builder.timeout.unwrap_or(interval).min(interval));
        let mut keeper = Self::connect_session(builder, false)?;
        if keeper.client_id != self.client_id {
            let _ = keeper.shutdown();
            return Err(Error::nfsv4("EXCHANGE_ID", Status::StaleClientId));
        }
        self.lease_renewal = Some(super::lease::BlockingLease::start(
            interval,
            keeper.session_id,
            move || {
                keeper.recovery_compound(Vec::new()).is_ok_and(|response| {
                    response.status.is_ok()
                        && crate::v4::client::response_revoked_lock_status(&response).is_none()
                })
            },
        )?);
        Ok(())
    }

    /// Sends an empty COMPOUND to keep the session lease fresh.
    pub fn renew(&mut self) -> Result<()> {
        self.compound(Vec::new()).map(|_| ())
    }

    /// Destroys the NFSv4 session.
    ///
    /// Dropping the client closes the TCP connection, but explicit shutdown is
    /// preferred when the server should release session resources promptly.
    pub fn shutdown(mut self) -> Result<()> {
        self.stop_lease_renewal()?;
        let response = self.raw_compound(
            "destroy-session",
            self.minor_version,
            vec![Operation::DestroySession(self.session_id)],
        )?;
        response.ensure_ok()
    }

    /// Destroys the session and then the NFSv4 client id.
    pub fn destroy_client_id(mut self) -> Result<()> {
        self.stop_lease_renewal()?;
        let session_response = self.raw_compound(
            "destroy-session",
            self.minor_version,
            vec![Operation::DestroySession(self.session_id)],
        )?;
        session_response.ensure_ok()?;
        let client_response = self.raw_compound(
            "destroy-clientid",
            self.minor_version,
            vec![Operation::DestroyClientId(self.client_id)],
        )?;
        client_response.ensure_ok()
    }

    fn compound(&mut self, operations: Vec<Operation>) -> Result<CompoundResponse> {
        let response = self.compound_status(operations)?;
        response.ensure_ok()?;
        Ok(response)
    }

    fn compound_status(&mut self, operations: Vec<Operation>) -> Result<CompoundResponse> {
        validate_session_compound_operation_count(operations.len(), self.max_operations)?;
        let can_replay_after_session_recovery =
            operations_can_replay_after_session_recovery(&operations);
        if self
            .lease_renewal
            .as_ref()
            .is_some_and(|lease| lease.failed())
        {
            self.recovery_pending = true;
        }
        if self.recovery_pending {
            self.recover_session()?;
            if !can_replay_after_session_recovery {
                return Err(Error::nfsv4("SEQUENCE", Status::BadSession));
            }
        }
        if !crate::v4::client::operations_release_state(&operations) {
            self.locks.ensure_valid()?;
        }
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

            let response = match self.raw_compound("nfs-rs-v4", self.minor_version, with_sequence) {
                Ok(response) => response,
                Err(err) if err.is_transport_failure() && !recovered_session => {
                    self.recovery_pending = true;
                    if let Err(recovery) = self.recover_session() {
                        return Err(cleanup_error(err, "NFSv4 session recovery", Err(recovery)));
                    }
                    recovered_session = true;
                    if can_replay_after_session_recovery {
                        continue;
                    }
                    return Err(err);
                }
                Err(err) => return Err(err),
            };
            if sequence_succeeded(&response) {
                self.sequence_id = self.sequence_id.wrapping_add(1).max(1);
            }
            if crate::v4::client::response_revoked_lock_status(&response).is_some() {
                self.check_revoked_locks()?;
                if !crate::v4::client::operations_release_state(&operations) {
                    self.locks.ensure_valid()?;
                }
            }
            if response_requires_session_recovery(&response) && !recovered_session {
                let err = session_recovery_error(&response);
                self.recover_session()?;
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
                std::thread::sleep(delay);
                continue;
            }
            return Ok(response);
        }
    }

    fn connect_with_builder(builder: ClientBuilder) -> Result<Self> {
        let mut client = Self::connect_session(builder, true)?;
        if let Err(err) = client.refresh_root_fsinfo() {
            return Err(cleanup_error(
                err,
                "cleanup DESTROY_SESSION after failed NFSv4 connect",
                client.shutdown(),
            ));
        }
        if let Err(err) = client.start_lease_renewal() {
            return Err(cleanup_error(
                err,
                "cleanup session after lease renewal setup",
                client.shutdown(),
            ));
        }
        Ok(client)
    }

    fn connect_session(builder: ClientBuilder, complete_reclaim: bool) -> Result<Self> {
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
            match Self::connect_session_minor(builder.clone(), minor_version, complete_reclaim) {
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

    fn connect_session_minor(
        builder: ClientBuilder,
        minor_version: u32,
        complete_reclaim: bool,
    ) -> Result<Self> {
        let stored_builder = builder.clone();
        let mut rpc = RpcClient::connect_with_timeout(
            (builder.host.as_str(), builder.port),
            Auth::sys(builder.auth.clone()),
            builder.timeout,
        )?;
        rpc.set_timeout(builder.timeout)?;
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
        )?;
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
        )?;
        session_res.ensure_ok()?;
        let session = response_create_session(&session_res)?;
        if let Err(err) = validate_session_channel_attrs(&session.fore_channel_attrs) {
            return Err(cleanup_session_setup_error(
                &mut rpc,
                minor_version,
                session.session_id,
                err,
            ));
        }
        let max_operations = match session_max_operations(&session.fore_channel_attrs) {
            Ok(max_operations) => max_operations,
            Err(err) => {
                return Err(cleanup_session_setup_error(
                    &mut rpc,
                    minor_version,
                    session.session_id,
                    err,
                ));
            }
        };
        let max_request_size = session.fore_channel_attrs.max_request_size;
        let max_response_size = session.fore_channel_attrs.max_response_size;
        let mut sequence_id = 1;
        if complete_reclaim {
            let reclaim_res = match reclaim_complete_with_delayed_retry(
                &mut rpc,
                minor_version,
                session.session_id,
                &mut sequence_id,
                max_operations,
                builder.retry_policy,
            ) {
                Ok(response) => response,
                Err(err) => {
                    return Err(cleanup_session_setup_error(
                        &mut rpc,
                        minor_version,
                        session.session_id,
                        err,
                    ));
                }
            };
            if let Err(err) = ensure_reclaim_complete(&reclaim_res) {
                return Err(cleanup_session_setup_error(
                    &mut rpc,
                    minor_version,
                    session.session_id,
                    err,
                ));
            }
        }

        let client = Self {
            rpc,
            locks: LockRegistry::default(),
            recovery_pending: false,
            lease_renewal: None,
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

    fn refresh_root_fsinfo(&mut self) -> Result<()> {
        let fsinfo = self.fsinfo("/")?;
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

    fn raw_compound(
        &mut self,
        tag: impl Into<String>,
        minor_version: u32,
        operations: Vec<Operation>,
    ) -> Result<CompoundResponse> {
        raw_compound_with_rpc(&mut self.rpc, tag, minor_version, operations)
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
    fn open(&mut self, path: &str, share_access: u32, openhow: OpenHow) -> Result<OpenedFile> {
        self.open_with_failure_cleanup(path, share_access, openhow, OpenFailureCleanup::KeepPath)
    }

    fn open_with_owner(
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
    }

    fn open_temp(&mut self, path: &str, share_access: u32, openhow: OpenHow) -> Result<OpenedFile> {
        self.open_with_failure_cleanup(path, share_access, openhow, OpenFailureCleanup::RemovePath)
    }

    fn open_with_failure_cleanup(
        &mut self,
        path: &str,
        share_access: u32,
        openhow: OpenHow,
        cleanup: OpenFailureCleanup,
    ) -> Result<OpenedFile> {
        let owner = self.open_owner.clone();
        self.open_with_owner_failure_cleanup(path, share_access, openhow, cleanup, owner)
    }

    fn open_with_owner_failure_cleanup(
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

            let response = match self.compound_status(ops) {
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
                std::thread::sleep(delay);
                continue;
            }
            if response_operation_requires_session_recovery(&response, OpCode::Open)
                && !recovered_session
            {
                self.recover_session()?;
                recovered_session = true;
                continue;
            }
            if let Err(error) = response.ensure_ok() {
                return Err(self.cleanup_open_response(path, &response, error, cleanup));
            }
            let open = response_open(&response)?;
            let handle = match response_getfh(&response) {
                Ok(handle) => handle,
                Err(error) => {
                    let close_result = self.close_state_by_path(path, open.stateid);
                    return Err(self.cleanup_failed_open(path, error, close_result, cleanup));
                }
            };
            let opened = OpenedFile {
                handle,
                stateid: open.stateid,
            };

            let delegation = match validate_open_result(&open, self.minor_version) {
                Ok(delegation) => delegation,
                Err(error) => {
                    let close_result = self.close(opened);
                    return Err(self.cleanup_failed_open(path, error, close_result, cleanup));
                }
            };
            // The high-level client does not run a callback service, so avoid
            // keeping delegations that the server granted despite WANT_NO_DELEG.
            if let Some(delegation_stateid) = delegation
                && let Err(error) = self.return_open_delegation(&opened.handle, delegation_stateid)
            {
                let close_result = self.close(opened);
                return Err(self.cleanup_failed_open(path, error, close_result, cleanup));
            }

            return Ok(opened);
        }
    }

    fn open_named_attr(
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
            let response = match self.compound_status(path_ops(
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
            )?) {
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
                std::thread::sleep(delay);
                continue;
            }
            if response_operation_requires_session_recovery(&response, OpCode::Open)
                && !recovered_session
            {
                self.recover_session()?;
                recovered_session = true;
                continue;
            }
            if let Err(error) = response.ensure_ok() {
                return Err(self.cleanup_named_attr_open_response(path, name, &response, error));
            }

            let open = response_open(&response)?;
            let handle = match response_getfh(&response) {
                Ok(handle) => handle,
                Err(error) => {
                    let close_result =
                        self.close_named_attr_state_by_path(path, name, open.stateid);
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
                    let close_result = self.close(opened);
                    return Err(open_cleanup_error(error, close_result));
                }
            };
            if let Some(delegation_stateid) = delegation
                && let Err(error) = self.return_open_delegation(&opened.handle, delegation_stateid)
            {
                let close_result = self.close(opened);
                return Err(open_cleanup_error(error, close_result));
            }

            return Ok(opened);
        }
    }

    fn cleanup_named_attr_open_response(
        &mut self,
        path: &str,
        name: &str,
        response: &CompoundResponse,
        error: Error,
    ) -> Error {
        match response_open(response) {
            Ok(open) => open_cleanup_error(
                error,
                self.close_named_attr_state_by_path(path, name, open.stateid),
            ),
            Err(_) => error,
        }
    }

    fn close_named_attr_state_by_path(
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
        self.close_with_current_filehandle(prefix, stateid)
    }

    fn cleanup_open_response(
        &mut self,
        path: &str,
        response: &CompoundResponse,
        error: Error,
        cleanup: OpenFailureCleanup,
    ) -> Error {
        match response_open(response) {
            Ok(open) => {
                let close_result = self.close_state_by_path(path, open.stateid);
                self.cleanup_failed_open(path, error, close_result, cleanup)
            }
            Err(_) => error,
        }
    }

    fn cleanup_failed_open(
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
                self.remove(path),
            ),
        }
    }

    fn ensure_directory_type(&mut self, path: &str, file_type: Option<FileType>) -> Result<()> {
        let is_directory = match file_type {
            Some(FileType::Directory) => true,
            Some(_) => false,
            None => self.probe_directory(path)?,
        };
        if is_directory {
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "{path:?} exists but is not a directory"
            )))
        }
    }

    fn path_is_directory(&mut self, path: &str, file_type: Option<FileType>) -> Result<bool> {
        match file_type {
            Some(FileType::Directory) => Ok(true),
            Some(_) => Ok(false),
            None => match self.metadata(path)?.file_type {
                Some(FileType::Directory) => Ok(true),
                Some(_) => Ok(false),
                None => self.probe_directory(path),
            },
        }
    }

    fn probe_directory(&mut self, path: &str) -> Result<bool> {
        match self.compound(path_ops(
            path,
            vec![Operation::ReadDir {
                cookie: 0,
                cookieverf: [0; NFS4_VERIFIER_SIZE],
                dircount: 1,
                maxcount: self.dir_size.clamp(1, 1024),
                attr_request: Bitmap::empty(),
            }],
        )?) {
            Ok(response) => response_readdir(&response).map(|_| true),
            Err(Error::NfsV4 {
                status: Status::NotDir | Status::BadType | Status::WrongType,
                ..
            }) => Ok(false),
            Err(err) => Err(err),
        }
    }

    fn supported_attr_request(&mut self, path: &str, attrs: &[u32]) -> Result<Bitmap> {
        let supported = self.supported_attrs(path)?;
        Bitmap::from_supported_attrs(&supported, attrs)
    }

    fn public_supported_attr_request(&mut self, path: &str, attrs: &[u32]) -> Result<Bitmap> {
        let supported = self.public_supported_attrs(path)?;
        Bitmap::from_supported_attrs(&supported, attrs)
    }

    fn parent_supported_attr_request(&mut self, path: &str, attrs: &[u32]) -> Result<Bitmap> {
        let supported = self.parent_supported_attrs(path)?;
        Bitmap::from_supported_attrs(&supported, attrs)
    }

    fn named_attr_supported_attr_request(&mut self, path: &str, attrs: &[u32]) -> Result<Bitmap> {
        let supported_attrs = Bitmap::from_known_attrs(&[FATTR4_SUPPORTED_ATTRS]);
        let response = self.compound(path_ops(
            path,
            vec![
                Operation::OpenAttr { create_dir: false },
                Operation::GetAttr(supported_attrs),
            ],
        )?)?;
        let supported = response_getattr(&response)?.parse_supported_attrs()?;
        Bitmap::from_supported_attrs(&supported, attrs)
    }

    fn get_supported_attr_values(&mut self, path: &str, attrs: &[u32]) -> Result<Fattr> {
        let attrs = self.supported_attr_request(path, attrs)?;
        if attrs.is_empty() {
            return Ok(Fattr {
                attrmask: attrs,
                attr_vals: Vec::new(),
            });
        }
        let response = self.compound(path_ops(path, vec![Operation::GetAttr(attrs)])?)?;
        response_getattr(&response)
    }

    fn read_opened_at(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        count: u32,
    ) -> Result<(bool, Vec<u8>)> {
        let response = self.compound(vec![
            Operation::PutFh(opened.handle.clone()),
            Operation::Read {
                stateid: opened.stateid,
                offset,
                count,
            },
        ])?;
        response_read(&response, count)
    }

    fn read_plus_opened(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        count: u32,
    ) -> Result<ReadPlusResult> {
        let response = self.compound(vec![
            Operation::PutFh(opened.handle.clone()),
            Operation::ReadPlus(ReadPlusArgs {
                stateid: opened.stateid,
                offset,
                count,
            }),
        ])?;
        response_read_plus(&response, count)
    }

    fn io_advise_opened(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        count: u64,
        hints: &[IoAdviceType],
    ) -> Result<IoAdviseResult> {
        let response = self.compound(vec![
            Operation::PutFh(opened.handle.clone()),
            Operation::IoAdvise(IoAdviseArgs {
                stateid: opened.stateid,
                offset,
                count,
                hints: io_advice_bitmap(hints),
            }),
        ])?;
        response_io_advise(&response)
    }

    fn lock_opened(
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
            let response = self.compound_status(vec![
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
            ])?;
            if response_consumed_owner_seqid(&response, OpCode::Lock) {
                self.advance_open_seqid();
                lock_seqid = lock_seqid.wrapping_add(1).max(1);
            }
            if response_operation_has_delayed_status(&response, OpCode::Lock)
                && let Some(delay) = self.retry_policy.delay_for_retry(retry)
            {
                retry += 1;
                std::thread::sleep(delay);
                continue;
            }
            return response_lock(&response).map(|stateid| (stateid, lock_seqid));
        }
    }

    fn unlock_opened(&mut self, lock: &LockState) -> Result<StateId> {
        let mut retry = 0;
        let mut lock_seqid = lock.lock_seqid;
        loop {
            let response = self.compound_status(vec![
                Operation::PutFh(lock.handle.clone()),
                Operation::LockUnlock(LockUnlockArgs {
                    lock_type: lock.lock_type,
                    seqid: lock_seqid,
                    lock_stateid: lock.lock_stateid,
                    offset: lock.offset,
                    length: lock.length,
                }),
            ])?;
            if response_consumed_owner_seqid(&response, OpCode::Locku) {
                lock_seqid = lock_seqid.wrapping_add(1).max(1);
            }
            if response_operation_has_delayed_status(&response, OpCode::Locku)
                && let Some(delay) = self.retry_policy.delay_for_retry(retry)
            {
                retry += 1;
                std::thread::sleep(delay);
                continue;
            }
            return response_lock_unlock(&response);
        }
    }

    fn seek_opened(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        what: SeekContent,
    ) -> Result<SeekResult> {
        let response = self.compound(vec![
            Operation::PutFh(opened.handle.clone()),
            Operation::Seek {
                stateid: opened.stateid,
                offset,
                what,
            },
        ])?;
        response_seek(&response)
    }

    fn set_opened_size(&mut self, opened: &OpenedFile, size: u64) -> Result<()> {
        self.set_opened_attrs(opened, Fattr::size(size))
    }

    fn set_opened_attrs(&mut self, opened: &OpenedFile, attrs: Fattr) -> Result<()> {
        let setattr_response = self.compound(vec![
            Operation::PutFh(opened.handle.clone()),
            Operation::SetAttr {
                stateid: opened.stateid,
                attrs,
            },
        ])?;
        self.ensure_status(setattr_response, "SETATTR")
    }

    fn return_open_delegation(&mut self, handle: &FileHandle, stateid: StateId) -> Result<()> {
        let response = self.compound(vec![
            Operation::PutFh(handle.clone()),
            Operation::DelegReturn(stateid),
        ])?;
        self.ensure_status(response, "DELEGRETURN")
    }

    fn update_allocation(
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

        let opened = self.open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)?;
        let result = self.update_opened_allocation(&opened, offset, length, op);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    fn update_opened_allocation(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        length: u64,
        op: SpaceOp,
    ) -> Result<()> {
        let response = self.compound(vec![
            Operation::PutFh(opened.handle.clone()),
            op.into_operation(opened.stateid, offset, length),
        ])?;
        self.ensure_status(response, op.name())
    }

    fn write_same_opened(
        &mut self,
        opened: &OpenedFile,
        block: AppDataBlock,
        stable: StableHow,
    ) -> Result<WriteResponse> {
        let requested_count = app_data_block_len(&block)?;
        let response = self.compound(vec![
            Operation::PutFh(opened.handle.clone()),
            Operation::WriteSame(WriteSameArgs {
                stateid: opened.stateid,
                stable,
                block,
            }),
        ])?;
        let write = response_write_same(&response, requested_count)?;
        if !write.committed.satisfies(stable) {
            return Err(Error::Protocol(
                "NFSv4 WRITE_SAME returned weaker stability than requested".into(),
            ));
        }
        Ok(write)
    }

    fn write_opened_at(
        &mut self,
        opened: &OpenedFile,
        mut offset: u64,
        mut data: &[u8],
    ) -> Result<()> {
        while !data.is_empty() {
            let chunk_len = data.len().min(self.write_size as usize);
            let response = self.compound(vec![
                Operation::PutFh(opened.handle.clone()),
                Operation::Write {
                    stateid: opened.stateid,
                    offset,
                    stable: StableHow::FileSync,
                    data: data[..chunk_len].to_vec(),
                },
            ])?;
            let result = response_write(&response, chunk_len as u32)?;
            let written = result.count;
            let written = written as usize;
            if !result.committed.satisfies(StableHow::FileSync) {
                let commit = self.commit_opened(opened, offset, result.count)?;
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

    fn commit_opened(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        count: u32,
    ) -> Result<CommitResult> {
        let response = self.compound(vec![
            Operation::PutFh(opened.handle.clone()),
            Operation::Commit { offset, count },
        ])?;
        response_commit(&response)
    }

    fn write_opened_from_reader<R: Read + ?Sized>(
        &mut self,
        opened: &OpenedFile,
        reader: &mut R,
    ) -> Result<u64> {
        self.write_opened_from_reader_at(opened, 0, reader)
    }

    fn write_opened_from_reader_at<R: Read + ?Sized>(
        &mut self,
        opened: &OpenedFile,
        mut offset: u64,
        reader: &mut R,
    ) -> Result<u64> {
        let mut written = 0;
        let mut buffer = vec![0; self.write_size as usize];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                return Ok(written);
            }
            self.write_opened_at(opened, offset, &buffer[..read])?;
            advance_offset(&mut offset, read, "NFSv4 WRITE reader")?;
            advance_offset(&mut written, read, "NFSv4 WRITE reader total")?;
        }
    }

    fn copy_opened(&mut self, source: &OpenedFile, target: &OpenedFile) -> Result<u64> {
        let mut offset = 0;
        loop {
            let (eof, data) = self.read_opened_at(source, offset, self.read_size)?;
            if data.is_empty() {
                return Ok(offset);
            }
            self.write_opened_at(target, offset, &data)?;
            advance_offset(&mut offset, data.len(), "NFSv4 COPY")?;
            if eof {
                return Ok(offset);
            }
        }
    }

    fn copy_opened_range_offload(
        &mut self,
        source: &OpenedFile,
        target: &OpenedFile,
        options: CopyOffloadOptions,
    ) -> Result<CopyResult> {
        let count = options.count;
        let response = self.compound(vec![
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
        ])?;
        response_copy(&response, count)
    }

    fn copy_notify_opened(
        &mut self,
        source: &OpenedFile,
        destination_server: NetLoc,
    ) -> Result<CopyNotifyResult> {
        let response = self.compound(vec![
            Operation::PutFh(source.handle.clone()),
            Operation::CopyNotify(CopyNotifyArgs {
                src_stateid: source.stateid,
                destination_server,
            }),
        ])?;
        response_copy_notify(&response)
    }

    #[allow(clippy::too_many_arguments)]
    fn layout_get_opened(
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
        let response = self.compound(vec![
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
        ])?;
        response_layout_get(&response)
    }

    fn clone_opened_range(
        &mut self,
        source: &OpenedFile,
        target: &OpenedFile,
        src_offset: u64,
        dst_offset: u64,
        count: u64,
    ) -> Result<()> {
        let response = self.compound(vec![
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
        ])?;
        self.ensure_status(response, "CLONE")
    }

    fn close(&mut self, opened: OpenedFile) -> Result<()> {
        self.close_with_current_filehandle(vec![Operation::PutFh(opened.handle)], opened.stateid)
    }

    fn close_state_by_path(&mut self, path: &str, stateid: StateId) -> Result<()> {
        let prefix = path_ops(path, Vec::new())?;
        self.close_with_current_filehandle(prefix, stateid)
    }

    fn close_with_current_filehandle(
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
            let response = match self.compound_status(compound) {
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
                std::thread::sleep(delay);
                continue;
            }
            if response_operation_requires_session_recovery(&response, OpCode::Close)
                && !recovered_session
            {
                let error = response.ensure_ok().err().unwrap_or_else(|| {
                    Error::Protocol("CLOSE required session recovery but response was OK".into())
                });
                self.recover_session()?;
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

fn raw_compound_with_rpc(
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
    let payload = rpc.call(
        NFS4_PROGRAM,
        NFS4_VERSION,
        1,
        &CompoundArgs {
            tag: tag.clone(),
            minor_version,
            operations,
        },
    )?;
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

fn raw_compound_with_delayed_retry(
    rpc: &mut RpcClient,
    tag: &'static str,
    minor_version: u32,
    operations: Vec<Operation>,
    retry_policy: RetryPolicy,
) -> Result<CompoundResponse> {
    let mut retry = 0;
    loop {
        let response = raw_compound_with_rpc(rpc, tag, minor_version, operations.clone())?;
        if response_allows_delayed_retry_without_sequence(&operations, &response)
            && let Some(delay) = retry_policy.delay_for_retry(retry)
        {
            retry += 1;
            std::thread::sleep(delay);
            continue;
        }
        return Ok(response);
    }
}

fn reclaim_complete_with_delayed_retry(
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

        let response = raw_compound_with_rpc(rpc, "reclaim-complete", minor_version, compound)?;
        if sequence_succeeded(&response) {
            *sequence_id = (*sequence_id).wrapping_add(1).max(1);
        }
        if response_allows_delayed_retry(&operations, &response)
            && let Some(delay) = retry_policy.delay_for_retry(retry)
        {
            retry += 1;
            std::thread::sleep(delay);
            continue;
        }
        return Ok(response);
    }
}

fn cleanup_session_setup_error(
    rpc: &mut RpcClient,
    minor_version: u32,
    session_id: SessionId,
    error: Error,
) -> Error {
    cleanup_error(
        error,
        "cleanup DESTROY_SESSION after failed NFSv4 session setup",
        destroy_session_with_rpc(rpc, minor_version, session_id),
    )
}

fn destroy_session_with_rpc(
    rpc: &mut RpcClient,
    minor_version: u32,
    session_id: SessionId,
) -> Result<()> {
    let response = raw_compound_with_rpc(
        rpc,
        "destroy-session",
        minor_version,
        vec![Operation::DestroySession(session_id)],
    )?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_builder_rejects_invalid_transfer_size_before_network() {
        let result = Client::builder("127.0.0.1").read_size(0).connect();
        assert!(matches!(result, Err(Error::Protocol(_))));
    }

    #[test]
    fn v4_builder_rejects_empty_host_before_network() {
        let result = Client::builder("").connect();
        assert!(matches!(result, Err(Error::InvalidTarget(_))));
    }

    #[test]
    fn v4_builder_rejects_zero_port_before_network() {
        let result = Client::builder("127.0.0.1").port(0).connect();
        assert!(matches!(result, Err(Error::Protocol(_))));
    }

    #[test]
    fn v4_builder_rejects_invalid_max_dir_entries_before_network() {
        let result = Client::builder("127.0.0.1").max_dir_entries(0).connect();
        assert!(matches!(result, Err(Error::Protocol(_))));
    }

    #[test]
    fn v4_builder_rejects_invalid_minor_version_before_network() {
        let result = Client::builder("127.0.0.1").max_minor_version(0).connect();
        assert!(matches!(result, Err(Error::Protocol(_))));

        let result = Client::builder("127.0.0.1").max_minor_version(3).connect();
        assert!(matches!(result, Err(Error::Protocol(_))));
    }

    #[test]
    fn v4_builder_rejects_invalid_open_owner_before_network() {
        let result = Client::builder("127.0.0.1")
            .open_owner(vec![0; NFS4_OPAQUE_LIMIT + 1])
            .connect();
        assert!(matches!(result, Err(Error::Protocol(_))));
    }
}

#[cfg(test)]
mod recovery_regressions {
    use super::*;
    use crate::v4::recovery_tests::{disconnect_script, lock_state, restart_script, stateid};

    fn builder(addr: std::net::SocketAddr) -> ClientBuilder {
        Client::builder("127.0.0.1")
            .port(addr.port())
            .owner_id(b"client".to_vec())
            .client_owner_verifier([0; 8])
            .timeout(Some(Duration::from_secs(2)))
    }

    #[test]
    fn restart_reclaims_open_and_lock_before_reclaim_complete() {
        let server = restart_script(None);
        let mut client = Client::connect_session(builder(server.addr), true).unwrap();
        let lock = client.locks.register(lock_state());
        client.recover_session().unwrap();
        assert_eq!(lock.stateid(), stateid(22));
        assert!(!lock.is_lost());
        client.renew().unwrap();
        client.unlock(lock).unwrap();
        drop(client);
        server.finish();
    }

    #[test]
    fn expired_grace_reports_lost_lock_and_blocks_further_io() {
        let server = restart_script(Some(Status::NoGrace));
        let mut client = Client::connect_session(builder(server.addr), true).unwrap();
        let lock = client.locks.register(lock_state());
        assert!(client.recover_session().unwrap_err().is_lost_state());
        assert!(lock.is_lost());
        assert!(client.renew().unwrap_err().is_lost_state());
        assert!(client.unlock(lock).unwrap_err().is_lost_state());
        client.locks.ensure_valid().unwrap();
        drop(client);
        server.finish();
    }

    #[test]
    fn read_only_rpc_recovers_after_disconnect() {
        let (server, ops) = disconnect_script(false);
        let mut client = Client::connect_session(builder(server.addr), true).unwrap();
        client.compound(ops).unwrap();
        drop(client);
        server.finish();
    }

    #[test]
    fn mutation_with_lost_reply_is_not_replayed() {
        let (server, ops) = disconnect_script(true);
        let mut client = Client::connect_session(builder(server.addr), true).unwrap();
        let err = client.compound(ops).unwrap_err();
        assert!(err.is_outcome_unknown());
        assert!(!err.is_retryable());
        drop(client);
        server.finish();
    }
    #[test]
    fn session_reconnect_preserves_existing_locks() {
        let server = crate::v4::recovery_tests::same_client_script();
        let mut client = Client::connect_session(builder(server.addr), true).unwrap();
        let lock = client.locks.register(lock_state());
        client.recover_session().unwrap();
        assert_eq!(lock.stateid(), stateid(5));
        assert!(!lock.is_lost());
        client.unlock(lock).unwrap();
        drop(client);
        server.finish();
    }

    #[test]
    fn background_renewal_uses_separate_session_and_shuts_it_down() {
        let (server, observed) = crate::v4::recovery_tests::lease_script();
        let mut client =
            Client::connect_session(builder(server.addr).automatic_lease_renewal(true), true)
                .unwrap();
        client.root_fsinfo = Some(
            Fattr {
                attrmask: Bitmap::from_attrs(&[FATTR4_LEASE_TIME]).unwrap(),
                attr_vals: 1_u32.to_be_bytes().to_vec(),
            }
            .parse_fsinfo()
            .unwrap(),
        );
        client.start_lease_renewal().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !observed.load(std::sync::atomic::Ordering::Acquire) {
            assert!(std::time::Instant::now() < deadline, "no idle heartbeat");
            std::thread::sleep(Duration::from_millis(5));
        }
        client.shutdown().unwrap();
        server.finish();
    }
    #[test]
    fn interrupted_recovery_keeps_successfully_reclaimed_state() {
        let server = crate::v4::recovery_tests::interrupted_reclaim_script();
        let mut client = Client::connect_session(builder(server.addr), true).unwrap();
        let lock = client.locks.register(lock_state());
        assert!(client.recover_session().unwrap_err().is_outcome_unknown());
        assert!(client.recovery_pending);
        client.recover_session().unwrap();
        assert_eq!(lock.stateid(), stateid(22));
        client.renew().unwrap();
        drop(client);
        server.finish();
    }

    #[test]
    fn partial_revocation_checks_actual_state_and_acknowledges_only_lost_locks() {
        for lost in [false, true] {
            let server = crate::v4::recovery_tests::revocation_script(lost);
            let mut client = Client::connect_session(builder(server.addr), true).unwrap();
            let lock = client.locks.register(lock_state());
            let result = client.renew();
            assert_eq!(lock.is_lost(), lost);
            if lost {
                assert!(result.unwrap_err().is_lost_state());
            } else {
                result.unwrap();
            }
            let result = client.unlock(lock);
            if lost {
                assert!(result.unwrap_err().is_lost_state());
            } else {
                result.unwrap();
            }
            drop(client);
            server.finish();
        }
    }
}
