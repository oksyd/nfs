#![cfg_attr(not(any(feature = "blocking", feature = "tokio")), allow(dead_code))]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};
use crate::v4::proto::*;

pub(crate) fn sequence_succeeded(response: &CompoundResponse) -> bool {
    matches!(
        response.results.first(),
        Some(OperationResult::Sequence { status, .. }) if status.is_ok()
    )
}

pub(crate) fn response_revoked_lock_status(response: &CompoundResponse) -> Option<Status> {
    let Some(OperationResult::Sequence {
        result: Some(sequence),
        ..
    }) = response.results.first()
    else {
        return None;
    };
    if sequence.status_flags & SEQ4_STATUS_ADMIN_STATE_REVOKED != 0 {
        Some(Status::AdminRevoked)
    } else if sequence.status_flags
        & (SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED | SEQ4_STATUS_EXPIRED_SOME_STATE_REVOKED)
        != 0
    {
        Some(Status::Expired)
    } else {
        None
    }
}

pub(crate) fn response_allows_delayed_retry(
    operations: &[Operation],
    response: &CompoundResponse,
) -> bool {
    response_allows_delayed_retry_after_leading_results(operations, response, 1)
}

pub(crate) fn response_allows_delayed_retry_without_sequence(
    operations: &[Operation],
    response: &CompoundResponse,
) -> bool {
    response_allows_delayed_retry_after_leading_results(operations, response, 0)
}

fn response_allows_delayed_retry_after_leading_results(
    operations: &[Operation],
    response: &CompoundResponse,
    leading_result_count: usize,
) -> bool {
    let Some(retry_index) = first_delayed_retry_result_index(response) else {
        return false;
    };
    if retry_index < leading_result_count {
        return true;
    }

    let delayed_operation_index = retry_index - leading_result_count;
    delayed_operation_index < operations.len()
        && operations[..delayed_operation_index]
            .iter()
            .all(operation_can_replay_after_successful_prefix)
        && operation_can_retry_after_delayed_result(&operations[delayed_operation_index])
}

fn first_delayed_retry_result_index(response: &CompoundResponse) -> Option<usize> {
    if response.results.is_empty() && status_allows_delayed_retry(response.status) {
        return Some(0);
    }

    response
        .results
        .iter()
        .position(|result| status_allows_delayed_retry(result.status()))
}

fn status_allows_delayed_retry(status: Status) -> bool {
    matches!(status, Status::Delay | Status::Grace)
}

pub(crate) fn response_requires_session_recovery(response: &CompoundResponse) -> bool {
    matches!(
        response.results.first(),
        Some(OperationResult::Sequence { status, .. }) if status.requires_session_recovery()
    ) || (response.results.is_empty() && response.status.requires_session_recovery())
}

pub(crate) fn session_recovery_error(response: &CompoundResponse) -> Error {
    match response.results.first() {
        Some(OperationResult::Sequence { status, .. }) if status.requires_session_recovery() => {
            Error::nfsv4("SEQUENCE", *status)
        }
        Some(result) => Error::nfsv4(result.op_name(), result.status()),
        None => Error::nfsv4("COMPOUND", response.status),
    }
}

pub(crate) fn response_consumed_owner_seqid(response: &CompoundResponse, op: OpCode) -> bool {
    response
        .results
        .iter()
        .any(|result| result.op_code() == op && owner_seqid_status_consumes(result.status()))
}

pub(crate) fn response_operation_has_delayed_status(
    response: &CompoundResponse,
    op: OpCode,
) -> bool {
    response
        .results
        .iter()
        .any(|result| result.op_code() == op && status_allows_delayed_retry(result.status()))
}

pub(crate) fn response_operation_requires_session_recovery(
    response: &CompoundResponse,
    op: OpCode,
) -> bool {
    response
        .results
        .iter()
        .any(|result| result.op_code() == op && result.status().requires_session_recovery())
}

fn owner_seqid_status_consumes(status: Status) -> bool {
    !matches!(
        status,
        Status::BadSeqId
            | Status::BadStateId
            | Status::BadXdr
            | Status::Moved
            | Status::NoFileHandle
            | Status::Resource
            | Status::StaleClientId
            | Status::StaleStateId
    )
}

const NFS4_COMPOUND_IO_HEADROOM: u32 = 4096;

pub(crate) fn validate_compound_response_shape(
    tag: &str,
    expected: &[OpCode],
    response: &CompoundResponse,
) -> Result<()> {
    if response.tag != tag {
        return Err(Error::Protocol(format!(
            "NFSv4 COMPOUND response tag {:?} does not match request tag {tag:?}",
            response.tag
        )));
    }

    if response.results.len() > expected.len() {
        return Err(Error::Protocol(format!(
            "NFSv4 COMPOUND {tag:?} returned {} operation results for {} requests",
            response.results.len(),
            expected.len()
        )));
    }

    for (index, (result, expected)) in response.results.iter().zip(expected).enumerate() {
        let actual = result.op_code();
        if !compound_result_matches_expected(result, *expected) {
            return Err(Error::Protocol(format!(
                "NFSv4 COMPOUND {tag:?} result {index} is {}, expected {}",
                actual.name(),
                expected.name()
            )));
        }
    }

    if response.status.is_ok() && response.results.len() != expected.len() {
        return Err(Error::Protocol(format!(
            "NFSv4 COMPOUND {tag:?} succeeded with {} operation results for {} requests",
            response.results.len(),
            expected.len()
        )));
    }

    let failed = response
        .results
        .iter()
        .position(|result| !result.status().is_ok());
    match (response.status.is_ok(), failed) {
        (true, Some(index)) => Err(Error::Protocol(format!(
            "NFSv4 COMPOUND {tag:?} has OK compound status but result {index} failed with {:?}",
            response.results[index].status()
        ))),
        (false, Some(index)) if index + 1 != response.results.len() => {
            Err(Error::Protocol(format!(
                "NFSv4 COMPOUND {tag:?} has non-final failed result {index} with {:?}",
                response.results[index].status()
            )))
        }
        (false, Some(index)) if response.results[index].status() != response.status => {
            Err(Error::Protocol(format!(
                "NFSv4 COMPOUND {tag:?} status {:?} does not match final result status {:?}",
                response.status,
                response.results[index].status()
            )))
        }
        (false, None) if !response.results.is_empty() => Err(Error::Protocol(format!(
            "NFSv4 COMPOUND {tag:?} failed with {:?}, but all operation results were OK",
            response.status
        ))),
        _ => Ok(()),
    }
}

fn compound_result_matches_expected(result: &OperationResult, expected: OpCode) -> bool {
    result.op_code() == expected
        || (result.op_code() == OpCode::Illegal && result.status() == Status::OpIllegal)
}

pub(crate) fn session_payload_limit(channel_size: u32) -> u32 {
    channel_size
        .saturating_sub(NFS4_COMPOUND_IO_HEADROOM)
        .min(NFS4_MAX_IO as u32)
}

pub(crate) fn operations_can_replay_after_session_recovery(operations: &[Operation]) -> bool {
    operations
        .iter()
        .all(operation_can_replay_after_session_recovery)
}

pub(crate) fn operations_release_state(operations: &[Operation]) -> bool {
    !operations.is_empty()
        && operations.iter().all(|operation| {
            matches!(
                operation,
                Operation::PutFh(_)
                    | Operation::Close { .. }
                    | Operation::LockUnlock(_)
                    | Operation::FreeStateId(_)
                    | Operation::ReleaseLockOwner(_)
            )
        })
}

fn operation_can_replay_after_session_recovery(operation: &Operation) -> bool {
    match operation {
        // Recreating a session loses the previous session's reply cache.
        // Replay only read-only operations that do not consume client state;
        // mutating namespace/data/state operations must be retried at a higher
        // layer where fresh state and application idempotency are available.
        Operation::PutRootFh
        | Operation::PutPubFh
        | Operation::PutFh(_)
        | Operation::Lookup(_)
        | Operation::Lookupp
        | Operation::Access(_)
        | Operation::SecInfo(_)
        | Operation::SecInfoNoName(_)
        | Operation::NVerify(_)
        | Operation::GetFh
        | Operation::GetAttr(_)
        | Operation::ReadDir { .. }
        | Operation::ReadLink
        | Operation::Verify(_)
        | Operation::SaveFh
        | Operation::RestoreFh
        | Operation::TestStateIds(_) => true,
        Operation::Read { stateid, .. } => stateid.is_anonymous(),
        Operation::Write { .. }
        | Operation::Commit { .. }
        | Operation::SetAttr { .. }
        | Operation::Remove(_)
        | Operation::Link(_)
        | Operation::Rename { .. }
        | Operation::Create(_)
        | Operation::SetClientId(_)
        | Operation::SetClientIdConfirm(_)
        | Operation::ExchangeId(_)
        | Operation::CreateSession(_)
        | Operation::BackchannelCtl(_)
        | Operation::BindConnToSession(_)
        | Operation::DestroySession(_)
        | Operation::DestroyClientId(_)
        | Operation::ReclaimComplete { .. }
        | Operation::Sequence(_)
        | Operation::DelegPurge(_)
        | Operation::DelegReturn(_)
        | Operation::Open(_)
        | Operation::OpenAttr { .. }
        | Operation::OpenConfirm { .. }
        | Operation::Close { .. }
        | Operation::Lock(_)
        | Operation::LockTest(_)
        | Operation::LockUnlock(_)
        | Operation::OpenDowngrade { .. }
        | Operation::FreeStateId(_)
        | Operation::GetDirDelegation(_)
        | Operation::GetDeviceInfo(_)
        | Operation::GetDeviceList(_)
        | Operation::LayoutCommit(_)
        | Operation::LayoutGet(_)
        | Operation::LayoutReturn(_)
        | Operation::SetSsv(_)
        | Operation::WantDelegation(_)
        | Operation::Allocate { .. }
        | Operation::Deallocate { .. }
        | Operation::IoAdvise(_)
        | Operation::Copy(_)
        | Operation::CopyNotify(_)
        | Operation::LayoutError(_)
        | Operation::LayoutStats(_)
        | Operation::OffloadCancel(_)
        | Operation::OffloadStatus(_)
        | Operation::ReadPlus(_)
        | Operation::Seek { .. }
        | Operation::Clone(_)
        | Operation::WriteSame(_)
        | Operation::Renew(_)
        | Operation::ReleaseLockOwner(_) => false,
    }
}

fn operation_can_replay_after_successful_prefix(operation: &Operation) -> bool {
    match operation {
        Operation::PutRootFh
        | Operation::PutPubFh
        | Operation::PutFh(_)
        | Operation::Lookup(_)
        | Operation::Lookupp
        | Operation::Access(_)
        | Operation::SecInfo(_)
        | Operation::SecInfoNoName(_)
        | Operation::NVerify(_)
        | Operation::GetFh
        | Operation::GetAttr(_)
        | Operation::Read { .. }
        | Operation::ReadDir { .. }
        | Operation::ReadLink
        | Operation::ReadPlus(_)
        | Operation::Seek { .. }
        | Operation::Verify(_)
        | Operation::SaveFh
        | Operation::RestoreFh
        | Operation::LockTest(_)
        | Operation::TestStateIds(_)
        | Operation::GetDeviceInfo(_)
        | Operation::GetDeviceList(_)
        | Operation::OffloadStatus(_) => true,
        Operation::Write { .. }
        | Operation::Commit { .. }
        | Operation::SetAttr { .. }
        | Operation::Remove(_)
        | Operation::Link(_)
        | Operation::Rename { .. }
        | Operation::Create(_)
        | Operation::SetClientId(_)
        | Operation::SetClientIdConfirm(_)
        | Operation::ExchangeId(_)
        | Operation::CreateSession(_)
        | Operation::BackchannelCtl(_)
        | Operation::BindConnToSession(_)
        | Operation::DestroySession(_)
        | Operation::DestroyClientId(_)
        | Operation::ReclaimComplete { .. }
        | Operation::Sequence(_)
        | Operation::DelegPurge(_)
        | Operation::DelegReturn(_)
        | Operation::Open(_)
        | Operation::OpenAttr { .. }
        | Operation::OpenConfirm { .. }
        | Operation::Close { .. }
        | Operation::Lock(_)
        | Operation::LockUnlock(_)
        | Operation::OpenDowngrade { .. }
        | Operation::FreeStateId(_)
        | Operation::GetDirDelegation(_)
        | Operation::LayoutCommit(_)
        | Operation::LayoutGet(_)
        | Operation::LayoutReturn(_)
        | Operation::SetSsv(_)
        | Operation::WantDelegation(_)
        | Operation::Allocate { .. }
        | Operation::Deallocate { .. }
        | Operation::IoAdvise(_)
        | Operation::Copy(_)
        | Operation::CopyNotify(_)
        | Operation::LayoutError(_)
        | Operation::LayoutStats(_)
        | Operation::OffloadCancel(_)
        | Operation::Clone(_)
        | Operation::WriteSame(_)
        | Operation::Renew(_)
        | Operation::ReleaseLockOwner(_) => false,
    }
}

fn operation_can_retry_after_delayed_result(operation: &Operation) -> bool {
    // RFC 7530 requires state-owner seqids to advance on most errors,
    // including DELAY/GRACE. Those operations must be rebuilt by their caller
    // instead of being replayed inside the generic COMPOUND retry loop.
    !matches!(
        operation,
        Operation::Open(_)
            | Operation::OpenConfirm { .. }
            | Operation::Close { .. }
            | Operation::Lock(_)
            | Operation::LockUnlock(_)
            | Operation::OpenDowngrade { .. }
            | Operation::Sequence(_)
    )
}

pub(crate) fn ensure_reclaim_complete(response: &CompoundResponse) -> Result<()> {
    if matches!(response.status, Status::CompleteAlready)
        || matches!(
            response.results.last().map(OperationResult::status),
            Some(Status::CompleteAlready)
        )
    {
        Ok(())
    } else {
        response.ensure_ok()
    }
}

pub(crate) fn session_max_operations(attrs: &ChannelAttrs) -> Result<usize> {
    let max_operations = attrs.max_operations as usize;
    if max_operations == 0 {
        return Err(Error::Protocol(
            "NFSv4 session fore channel returned max_operations=0".to_owned(),
        ));
    }
    Ok(max_operations.min(NFS4_MAX_OPS))
}

pub(crate) fn validate_session_channel_attrs(attrs: &ChannelAttrs) -> Result<()> {
    validate_session_channel_size("max_request_size", attrs.max_request_size)?;
    validate_session_channel_size("max_response_size", attrs.max_response_size)?;
    if attrs.max_requests == 0 {
        return Err(Error::Protocol(
            "NFSv4 session fore channel returned max_requests=0".to_owned(),
        ));
    }
    Ok(())
}

fn validate_session_channel_size(name: &'static str, size: u32) -> Result<()> {
    if size <= NFS4_COMPOUND_IO_HEADROOM {
        return Err(Error::Protocol(format!(
            "NFSv4 session fore channel returned {name}={size}, which leaves no payload capacity"
        )));
    }
    Ok(())
}

pub(crate) fn validate_session_compound_operation_count(
    operation_count: usize,
    max_operations: usize,
) -> Result<()> {
    let total = operation_count
        .checked_add(1)
        .ok_or_else(|| Error::Protocol("NFSv4 COMPOUND operation count overflow".to_owned()))?;
    if total > max_operations {
        return Err(Error::Protocol(format!(
            "NFSv4 COMPOUND has {total} operations including SEQUENCE, but session allows {max_operations}"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpaceOp {
    Allocate,
    Deallocate,
}

impl SpaceOp {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Allocate => "ALLOCATE",
            Self::Deallocate => "DEALLOCATE",
        }
    }

    pub(crate) fn into_operation(self, stateid: StateId, offset: u64, length: u64) -> Operation {
        match self {
            Self::Allocate => Operation::Allocate {
                stateid,
                offset,
                length,
            },
            Self::Deallocate => Operation::Deallocate {
                stateid,
                offset,
                length,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CopyOffloadOptions {
    pub(crate) src_offset: u64,
    pub(crate) dst_offset: u64,
    pub(crate) count: u64,
    pub(crate) consecutive: bool,
    pub(crate) synchronous: bool,
    pub(crate) source_servers: Vec<NetLoc>,
}

/// Active NFSv4 byte-range lock returned by the high-level clients.
///
/// The lock keeps the server-side open state needed to release the byte-range
/// lock. Pass it back to `Client::unlock` on the same client when the protected
/// range is no longer needed.
#[derive(Debug)]
pub struct ByteRangeLock {
    pub(crate) state: Arc<Mutex<LockState>>,
    lock_type: LockType,
    offset: u64,
    length: u64,
    owner: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(crate) struct LockState {
    pub(crate) client_id: u64,
    pub(crate) open_owner: Vec<u8>,
    pub(crate) handle: FileHandle,
    pub(crate) open_stateid: StateId,
    pub(crate) lock_stateid: StateId,
    pub(crate) lock_seqid: u32,
    pub(crate) lock_type: LockType,
    pub(crate) offset: u64,
    pub(crate) length: u64,
    pub(crate) owner: Vec<u8>,
    pub(crate) lost: Option<Status>,
}

/// Authoritative lock state is shared with tokens so recovery updates the
/// stateids observed by callers without requiring them to replace their tokens.
#[derive(Debug, Default, Clone)]
pub(crate) struct LockRegistry {
    entries: Vec<Arc<Mutex<LockState>>>,
}

impl LockRegistry {
    pub(crate) fn register(&mut self, state: LockState) -> ByteRangeLock {
        let lock = ByteRangeLock {
            lock_type: state.lock_type,
            offset: state.offset,
            length: state.length,
            owner: state.owner.clone(),
            state: Arc::new(Mutex::new(state)),
        };
        self.entries.push(lock.state.clone());
        lock
    }

    pub(crate) fn snapshot(&self) -> Vec<LockState> {
        self.entries
            .iter()
            .map(|entry| entry.lock().unwrap().clone())
            .collect()
    }

    pub(crate) fn restore(&self, index: usize, state: LockState) {
        *self.entries[index].lock().unwrap() = state;
    }

    pub(crate) fn get(&self, lock: &ByteRangeLock) -> Result<LockState> {
        if !self
            .entries
            .iter()
            .any(|entry| Arc::ptr_eq(entry, &lock.state))
        {
            return Err(Error::Protocol(
                "lock belongs to a different client or was already released".into(),
            ));
        }
        Ok(lock.state.lock().unwrap().clone())
    }

    pub(crate) fn remove(&mut self, lock: &ByteRangeLock) {
        self.entries
            .retain(|entry| !Arc::ptr_eq(entry, &lock.state));
    }

    pub(crate) fn ensure_valid(&self) -> Result<()> {
        for entry in &self.entries {
            if let Some(status) = entry.lock().unwrap().lost {
                return Err(Error::LockLost { status });
            }
        }
        Ok(())
    }
}

impl ByteRangeLock {
    /// Returns the lock type requested from the server.
    pub fn lock_type(&self) -> LockType {
        self.lock_type
    }

    /// Returns the start offset of the locked byte range.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the locked byte range length.
    pub fn length(&self) -> u64 {
        self.length
    }

    /// Returns the opaque NFSv4 lock-owner id used for this lock.
    pub fn owner(&self) -> &[u8] {
        &self.owner
    }

    /// Returns the NFSv4 stateid for the byte-range lock.
    /// Recovery updates this value. Do not use it after [`Self::is_lost`] is true.
    pub fn stateid(&self) -> StateId {
        self.state.lock().unwrap().lock_stateid
    }

    /// Returns true when recovery has established that this lock was lost.
    /// A lost lock must not be used to protect further application work.
    pub fn is_lost(&self) -> bool {
        self.state.lock().unwrap().lost.is_some()
    }
}

/// Cursor for paged NFSv4 directory reads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirPageCursor {
    /// Cookie of the last entry returned by the previous page.
    pub cookie: u64,
    /// Cookie verifier returned by the server.
    pub cookieverf: Verifier,
}

/// Directory entry returned by high-level NFSv4 directory reads.
///
/// The entry stores parsed basic attributes instead of exposing the raw NFSv4
/// attribute bitmap and payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// Entry cookie used for pagination.
    pub cookie: u64,
    /// Entry name.
    pub name: String,
    /// Parsed basic attributes returned for the entry.
    pub attributes: BasicAttributes,
}

impl DirEntry {
    pub(crate) fn from_wire(entry: crate::v4::proto::DirEntry) -> Result<Self> {
        Ok(Self {
            cookie: entry.cookie,
            name: entry.name,
            attributes: entry.attrs.parse_basic()?,
        })
    }

    /// Returns the parsed basic attributes for this entry.
    pub fn basic_attributes(&self) -> Result<BasicAttributes> {
        Ok(self.attributes.clone())
    }
}

/// A single page of NFSv4 directory entries.
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

/// Cursor for paged NFSv4 pNFS device id reads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeviceListCursor {
    /// Cookie returned by the previous `GETDEVICELIST` page.
    pub cookie: u64,
    /// Cookie verifier returned by the server.
    pub cookieverf: Verifier,
}

/// A single page of NFSv4 pNFS device ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceListPage {
    /// Device ids returned in this page.
    pub device_ids: Vec<DeviceId>,
    /// Cursor for the next page, or `None` when the server reported EOF.
    pub next_cursor: Option<DeviceListCursor>,
}

impl DeviceListPage {
    /// Returns true when there are no further pages to request.
    pub fn is_eof(&self) -> bool {
        self.next_cursor.is_none()
    }
}

pub(crate) fn ensure_last_status(
    response: &CompoundResponse,
    operation: &'static str,
) -> Result<()> {
    if let Some(result) = response.results.last() {
        if result.status().is_ok() {
            return Ok(());
        }
        return Err(Error::nfsv4(operation, result.status()));
    }
    Err(Error::Protocol(format!("{operation} returned no result")))
}

pub(crate) fn finish_with_close<T>(result: Result<T>, close_result: Result<()>) -> Result<T> {
    match result {
        Ok(value) => {
            close_result?;
            Ok(value)
        }
        Err(err) => Err(cleanup_error(
            err,
            "cleanup CLOSE after failed operation",
            close_result,
        )),
    }
}

pub(crate) fn attrs_require_open_state(attrs: &Fattr) -> bool {
    attrs.attrmask.contains(FATTR4_SIZE)
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

pub(crate) fn path_ops(path: &str, tail: Vec<Operation>) -> Result<Vec<Operation>> {
    let mut ops = vec![Operation::PutRootFh];
    for component in path_components(path)? {
        ops.push(Operation::Lookup(component.to_owned()));
    }
    ops.extend(tail);
    Ok(ops)
}

pub(crate) fn public_path_ops(path: &str, tail: Vec<Operation>) -> Result<Vec<Operation>> {
    let mut ops = vec![Operation::PutPubFh];
    for component in path_components(path)? {
        ops.push(Operation::Lookup(component.to_owned()));
    }
    ops.extend(tail);
    Ok(ops)
}

pub(crate) fn parent_path_ops(path: &str, tail: Vec<Operation>) -> Result<Vec<Operation>> {
    let components = path_components(path)?;
    if components.is_empty() {
        return Err(Error::InvalidPath(path.to_owned()));
    }

    let mut ops = vec![Operation::PutRootFh];
    for component in components {
        ops.push(Operation::Lookup(component.to_owned()));
    }
    ops.push(Operation::Lookupp);
    ops.extend(tail);
    Ok(ops)
}

pub(crate) fn path_components(path: &str) -> Result<Vec<&str>> {
    if path.is_empty() {
        return Err(Error::InvalidPath(path.to_owned()));
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => return Err(Error::InvalidPath(path.to_owned())),
            name if name.len() > NFS4_OPAQUE_LIMIT => {
                return Err(Error::NameTooLong {
                    name: name.to_owned(),
                    max: NFS4_OPAQUE_LIMIT,
                });
            }
            name => components.push(name),
        }
    }
    Ok(components)
}

pub(crate) fn named_attr_ops(
    path: &str,
    name: &str,
    tail: Vec<Operation>,
) -> Result<Vec<Operation>> {
    validate_named_attr_name(name)?;
    let mut ops = path_ops(
        path,
        vec![
            Operation::OpenAttr { create_dir: false },
            Operation::Lookup(name.to_owned()),
        ],
    )?;
    ops.extend(tail);
    Ok(ops)
}

pub(crate) fn validate_named_attr_name(name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(Error::InvalidPath(name.to_owned()));
    }
    if name.len() > NFS4_OPAQUE_LIMIT {
        return Err(Error::NameTooLong {
            name: name.to_owned(),
            max: NFS4_OPAQUE_LIMIT,
        });
    }
    Ok(())
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

pub(crate) fn split_parent(path: &str) -> Result<(Vec<&str>, String)> {
    let mut components = path_components(path)?;
    let name = components
        .pop()
        .ok_or_else(|| Error::InvalidPath(path.to_owned()))?
        .to_owned();
    Ok((components, name))
}

pub(crate) fn temporary_sibling_path(path: &str) -> Result<String> {
    let mut components = path_components(path)?;
    components
        .pop()
        .ok_or_else(|| Error::InvalidPath(path.to_owned()))?;

    let mut parent = String::from("/");
    for component in components {
        parent = join_path(&parent, component);
    }

    Ok(join_path(&parent, &temporary_name()))
}

pub(crate) fn temporary_named_attr_name() -> String {
    temporary_name()
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

pub(crate) fn response_exchange_id(response: &CompoundResponse) -> Result<ExchangeIdResult> {
    match response.results.first() {
        Some(OperationResult::ExchangeId {
            status,
            result: Some(result),
        }) if status.is_ok() => Ok(result.clone()),
        Some(result) => Err(Error::Protocol(format!(
            "EXCHANGE_ID failed with {:?}",
            result.status()
        ))),
        None => Err(Error::Protocol("EXCHANGE_ID returned no result".into())),
    }
}

pub(crate) fn response_create_session(response: &CompoundResponse) -> Result<CreateSessionResult> {
    match response.results.first() {
        Some(OperationResult::CreateSession {
            status,
            result: Some(result),
        }) if status.is_ok() => Ok(result.clone()),
        Some(result) => Err(Error::Protocol(format!(
            "CREATE_SESSION failed with {:?}",
            result.status()
        ))),
        None => Err(Error::Protocol("CREATE_SESSION returned no result".into())),
    }
}

pub(crate) fn response_open(response: &CompoundResponse) -> Result<OpenResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::Open {
                status,
                result: Some(open),
            } if status.is_ok() => Some(Ok(open.clone())),
            OperationResult::Open { status, .. } => Some(Err(Error::nfsv4("OPEN", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include OPEN result".into()))?
}

pub(crate) fn validate_open_result(
    open: &OpenResult,
    minor_version: u32,
) -> Result<Option<StateId>> {
    if minor_version >= NFS4_MINOR_VERSION_SESSION_MIN
        && (open.result_flags & OPEN4_RESULT_CONFIRM) != 0
    {
        return Err(Error::Protocol(
            "NFSv4 server requested OPEN_CONFIRM for a session minor version".to_owned(),
        ));
    }

    Ok(open_delegation_stateid(&open.delegation))
}

fn open_delegation_stateid(delegation: &OpenDelegation) -> Option<StateId> {
    match delegation {
        OpenDelegation::Read(delegation) => Some(delegation.stateid),
        OpenDelegation::Write(delegation) => Some(delegation.stateid),
        OpenDelegation::None | OpenDelegation::NoneExt(_) => None,
    }
}

pub(crate) fn open_cleanup_error(error: Error, close_result: Result<()>) -> Error {
    cleanup_error(
        error,
        "cleanup CLOSE after failed OPEN post-processing",
        close_result,
    )
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

pub(crate) fn ensure_distinct_copy_handles(source: &FileHandle, target: &FileHandle) -> Result<()> {
    if source == target {
        return Err(Error::Protocol(
            "copy source and destination refer to the same file handle".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn response_getfh(response: &CompoundResponse) -> Result<FileHandle> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::GetFh {
                status,
                handle: Some(handle),
            } if status.is_ok() => Some(Ok(handle.clone())),
            OperationResult::GetFh { status, .. } => Some(Err(Error::nfsv4("GETFH", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include GETFH result".into()))?
}

pub(crate) fn response_getattr(response: &CompoundResponse) -> Result<Fattr> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::GetAttr {
                status,
                attrs: Some(attrs),
            } if status.is_ok() => Some(Ok(attrs.clone())),
            OperationResult::GetAttr { status, .. } => Some(Err(Error::nfsv4("GETATTR", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include GETATTR result".into()))?
}

pub(crate) fn response_access(response: &CompoundResponse) -> Result<AccessResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::Access {
                status,
                result: Some(access),
            } if status.is_ok() => Some(Ok(*access)),
            OperationResult::Access { status, .. } => Some(Err(Error::nfsv4("ACCESS", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include ACCESS result".into()))?
}

pub(crate) fn response_bind_conn_to_session(
    response: &CompoundResponse,
) -> Result<BindConnToSessionResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::BindConnToSession {
                status,
                result: Some(bind),
            } if status.is_ok() => Some(Ok(*bind)),
            OperationResult::BindConnToSession {
                status,
                result: None,
            } if status.is_ok() => Some(Err(Error::Protocol(
                "NFSv4 BIND_CONN_TO_SESSION returned OK without a result".into(),
            ))),
            OperationResult::BindConnToSession { status, .. } => {
                Some(Err(Error::nfsv4("BIND_CONN_TO_SESSION", *status)))
            }
            _ => None,
        })
        .ok_or_else(|| {
            Error::Protocol("COMPOUND did not include BIND_CONN_TO_SESSION result".into())
        })?
}

pub(crate) fn response_set_ssv(response: &CompoundResponse) -> Result<SetSsvResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::SetSsv {
                status,
                result: Some(set_ssv),
            } if status.is_ok() => Some(Ok(set_ssv.clone())),
            OperationResult::SetSsv {
                status,
                result: None,
            } if status.is_ok() => Some(Err(Error::Protocol(
                "NFSv4 SET_SSV returned OK without a result".into(),
            ))),
            OperationResult::SetSsv { status, .. } => Some(Err(Error::nfsv4("SET_SSV", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include SET_SSV result".into()))?
}

pub(crate) fn response_secinfo(
    response: &CompoundResponse,
    expected: OpCode,
) -> Result<Vec<SecInfo>> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::SecInfo {
                op,
                status,
                flavors,
            } if *op == expected && status.is_ok() => Some(Ok(flavors.clone())),
            OperationResult::SecInfo { op, status, .. } if *op == expected => {
                Some(Err(Error::nfsv4(expected.name(), *status)))
            }
            _ => None,
        })
        .ok_or_else(|| {
            Error::Protocol(format!(
                "COMPOUND did not include {} result",
                expected.name()
            ))
        })?
}

pub(crate) fn response_verify(
    response: &CompoundResponse,
    expected: OpCode,
    false_status: Status,
) -> Result<bool> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::StatusOnly { op, status } if *op == expected && status.is_ok() => {
                Some(Ok(true))
            }
            OperationResult::StatusOnly { op, status }
                if *op == expected && *status == false_status =>
            {
                Some(Ok(false))
            }
            OperationResult::StatusOnly { op, status } if *op == expected => {
                Some(Err(Error::nfsv4(expected.name(), *status)))
            }
            _ => None,
        })
        .ok_or_else(|| {
            Error::Protocol(format!(
                "COMPOUND did not include {} result",
                expected.name()
            ))
        })?
}

pub(crate) fn response_read(
    response: &CompoundResponse,
    requested_count: u32,
) -> Result<(bool, Vec<u8>)> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::Read { status, eof, data } if status.is_ok() => Some(
                validate_read_result_size(requested_count, data.len(), *eof)
                    .map(|()| (*eof, data.clone())),
            ),
            OperationResult::Read { status, .. } => Some(Err(Error::nfsv4("READ", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include READ result".into()))?
}

pub(crate) fn response_read_plus(
    response: &CompoundResponse,
    requested_count: u32,
) -> Result<ReadPlusResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::ReadPlus {
                status,
                result: Some(read_plus),
            } if status.is_ok() => Some(
                validate_read_plus_result(requested_count, read_plus).map(|()| read_plus.clone()),
            ),
            OperationResult::ReadPlus { status, .. } => {
                Some(Err(Error::nfsv4("READ_PLUS", *status)))
            }
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include READ_PLUS result".into()))?
}

pub(crate) fn response_readlink(response: &CompoundResponse) -> Result<String> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::ReadLink {
                status,
                data: Some(data),
            } if status.is_ok() => Some(Ok(data.clone())),
            OperationResult::ReadLink { status, .. } => {
                Some(Err(Error::nfsv4("READLINK", *status)))
            }
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include READLINK result".into()))?
}

pub(crate) fn response_write(
    response: &CompoundResponse,
    requested_count: u32,
) -> Result<WriteResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::Write {
                status,
                result: Some(write),
            } if status.is_ok() => Some(
                validate_write_result_count(requested_count, write.count).map(|()| write.clone()),
            ),
            OperationResult::Write { status, .. } => Some(Err(Error::nfsv4("WRITE", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include WRITE result".into()))?
}

pub(crate) fn response_io_advise(response: &CompoundResponse) -> Result<IoAdviseResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::IoAdvise {
                status,
                result: Some(io_advise),
            } if status.is_ok() => Some(Ok(io_advise.clone())),
            OperationResult::IoAdvise { status, .. } => {
                Some(Err(Error::nfsv4("IO_ADVISE", *status)))
            }
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include IO_ADVISE result".into()))?
}

pub(crate) fn response_copy(
    response: &CompoundResponse,
    requested_count: u64,
) -> Result<CopyResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::Copy {
                status,
                result: Some(copy),
            } if status.is_ok() => {
                Some(validate_copy_result(requested_count, copy).map(|()| copy.clone()))
            }
            OperationResult::Copy {
                status,
                result: None,
            } if status.is_ok() => Some(Err(Error::Protocol(
                "NFSv4 COPY returned OK without a result".into(),
            ))),
            OperationResult::Copy { status, .. } => Some(Err(Error::nfsv4("COPY", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include COPY result".into()))?
}

pub(crate) fn response_copy_notify(response: &CompoundResponse) -> Result<CopyNotifyResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::CopyNotify {
                status,
                result: Some(copy_notify),
            } if status.is_ok() => Some(Ok(copy_notify.clone())),
            OperationResult::CopyNotify {
                status,
                result: None,
            } if status.is_ok() => Some(Err(Error::Protocol(
                "NFSv4 COPY_NOTIFY returned OK without a result".into(),
            ))),
            OperationResult::CopyNotify { status, .. } => {
                Some(Err(Error::nfsv4("COPY_NOTIFY", *status)))
            }
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include COPY_NOTIFY result".into()))?
}

pub(crate) fn response_lock_test(response: &CompoundResponse) -> Result<Option<LockDenied>> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::LockTest { status, .. } if status.is_ok() => Some(Ok(None)),
            OperationResult::LockTest {
                status: Status::Denied,
                denied: Some(denied),
            } => Some(Ok(Some(denied.clone()))),
            OperationResult::LockTest {
                status: Status::Denied,
                denied: None,
            } => Some(Err(Error::Protocol(
                "NFSv4 LOCKT returned DENIED without conflicting lock details".into(),
            ))),
            OperationResult::LockTest { status, .. } => Some(Err(Error::nfsv4("LOCKT", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include LOCKT result".into()))?
}

pub(crate) fn response_lock(response: &CompoundResponse) -> Result<StateId> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::Lock {
                status,
                stateid: Some(stateid),
                ..
            } if status.is_ok() => Some(Ok(*stateid)),
            OperationResult::Lock {
                status, stateid, ..
            } if status.is_ok() => Some(Err(Error::Protocol(format!(
                "NFSv4 LOCK returned {status:?} without a stateid: {stateid:?}"
            )))),
            OperationResult::Lock { status, .. } => Some(Err(Error::nfsv4("LOCK", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include LOCK result".into()))?
}

pub(crate) fn response_lock_unlock(response: &CompoundResponse) -> Result<StateId> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::LockUnlock {
                status,
                stateid: Some(stateid),
            } if status.is_ok() => Some(Ok(*stateid)),
            OperationResult::LockUnlock {
                status, stateid, ..
            } if status.is_ok() => Some(Err(Error::Protocol(format!(
                "NFSv4 LOCKU returned {status:?} without a stateid: {stateid:?}"
            )))),
            OperationResult::LockUnlock { status, .. } => Some(Err(Error::nfsv4("LOCKU", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include LOCKU result".into()))?
}

pub(crate) fn response_test_stateids(
    response: &CompoundResponse,
    requested_count: usize,
) -> Result<Vec<Status>> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::TestStateIds { status, statuses } if status.is_ok() => {
                if statuses.len() == requested_count {
                    Some(Ok(statuses.clone()))
                } else {
                    Some(Err(Error::Protocol(format!(
                        "NFSv4 TEST_STATEID returned {} statuses for {requested_count} stateids",
                        statuses.len()
                    ))))
                }
            }
            OperationResult::TestStateIds { status, .. } => {
                Some(Err(Error::nfsv4("TEST_STATEID", *status)))
            }
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include TEST_STATEID result".into()))?
}

pub(crate) fn response_release_lock_owner(response: &CompoundResponse) -> Result<bool> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::StatusOnly {
                op: OpCode::ReleaseLockOwner,
                status,
            } if status.is_ok() => Some(Ok(true)),
            OperationResult::StatusOnly {
                op: OpCode::ReleaseLockOwner,
                status: Status::LocksHeld,
            } => Some(Ok(false)),
            OperationResult::StatusOnly {
                op: OpCode::ReleaseLockOwner,
                status,
            } => Some(Err(Error::nfsv4("RELEASE_LOCKOWNER", *status))),
            _ => None,
        })
        .ok_or_else(|| {
            Error::Protocol("COMPOUND did not include RELEASE_LOCKOWNER result".into())
        })?
}

pub(crate) fn response_offload_status(response: &CompoundResponse) -> Result<OffloadStatusResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::OffloadStatus {
                status,
                result: Some(status_result),
            } if status.is_ok() => Some(Ok(*status_result)),
            OperationResult::OffloadStatus {
                status,
                result: None,
            } if status.is_ok() => Some(Err(Error::Protocol(
                "NFSv4 OFFLOAD_STATUS returned OK without a result".into(),
            ))),
            OperationResult::OffloadStatus { status, .. } => {
                Some(Err(Error::nfsv4("OFFLOAD_STATUS", *status)))
            }
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include OFFLOAD_STATUS result".into()))?
}

pub(crate) fn response_get_device_info(response: &CompoundResponse) -> Result<GetDeviceInfoResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::GetDeviceInfo {
                status,
                result: Some(device_info),
                ..
            } if status.is_ok() => Some(Ok(device_info.clone())),
            OperationResult::GetDeviceInfo {
                status,
                result: None,
                min_count,
            } if status.is_ok() => Some(Err(Error::Protocol(format!(
                "NFSv4 GETDEVICEINFO returned OK without a result (min_count={min_count:?})"
            )))),
            OperationResult::GetDeviceInfo { status, .. } => {
                Some(Err(Error::nfsv4("GETDEVICEINFO", *status)))
            }
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include GETDEVICEINFO result".into()))?
}

pub(crate) fn response_get_device_list(response: &CompoundResponse) -> Result<GetDeviceListResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::GetDeviceList {
                status,
                result: Some(device_list),
            } if status.is_ok() => Some(Ok(device_list.clone())),
            OperationResult::GetDeviceList {
                status,
                result: None,
            } if status.is_ok() => Some(Err(Error::Protocol(
                "NFSv4 GETDEVICELIST returned OK without a result".into(),
            ))),
            OperationResult::GetDeviceList { status, .. } => {
                Some(Err(Error::nfsv4("GETDEVICELIST", *status)))
            }
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include GETDEVICELIST result".into()))?
}

pub(crate) fn response_get_dir_delegation(
    response: &CompoundResponse,
) -> Result<GetDirDelegationResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::GetDirDelegation {
                status,
                result: Some(delegation),
            } if status.is_ok() => Some(Ok(delegation.clone())),
            OperationResult::GetDirDelegation {
                status,
                result: None,
            } if status.is_ok() => Some(Err(Error::Protocol(
                "NFSv4 GET_DIR_DELEGATION returned OK without a result".into(),
            ))),
            OperationResult::GetDirDelegation { status, .. } => {
                Some(Err(Error::nfsv4("GET_DIR_DELEGATION", *status)))
            }
            _ => None,
        })
        .ok_or_else(|| {
            Error::Protocol("COMPOUND did not include GET_DIR_DELEGATION result".into())
        })?
}

pub(crate) fn response_want_delegation(response: &CompoundResponse) -> Result<OpenDelegation> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::WantDelegation {
                status,
                delegation: Some(delegation),
            } if status.is_ok() => Some(Ok(delegation.clone())),
            OperationResult::WantDelegation {
                status,
                delegation: None,
            } if status.is_ok() => Some(Err(Error::Protocol(
                "NFSv4 WANT_DELEGATION returned OK without a delegation".into(),
            ))),
            OperationResult::WantDelegation { status, .. } => {
                Some(Err(Error::nfsv4("WANT_DELEGATION", *status)))
            }
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include WANT_DELEGATION result".into()))?
}

pub(crate) fn response_layout_commit(response: &CompoundResponse) -> Result<LayoutCommitResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::LayoutCommit {
                status,
                result: Some(layout_commit),
            } if status.is_ok() => Some(Ok(*layout_commit)),
            OperationResult::LayoutCommit {
                status,
                result: None,
            } if status.is_ok() => Some(Err(Error::Protocol(
                "NFSv4 LAYOUTCOMMIT returned OK without a result".into(),
            ))),
            OperationResult::LayoutCommit { status, .. } => {
                Some(Err(Error::nfsv4("LAYOUTCOMMIT", *status)))
            }
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include LAYOUTCOMMIT result".into()))?
}

pub(crate) fn response_layout_get(response: &CompoundResponse) -> Result<LayoutGetResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::LayoutGet {
                status,
                result: Some(layout),
                ..
            } if status.is_ok() => Some(Ok(layout.clone())),
            OperationResult::LayoutGet {
                status,
                result: None,
                will_signal_layout_avail,
            } if status.is_ok() => Some(Err(Error::Protocol(format!(
                "NFSv4 LAYOUTGET returned OK without a result (will_signal_layout_avail={will_signal_layout_avail:?})"
            )))),
            OperationResult::LayoutGet { status, .. } => {
                Some(Err(Error::nfsv4("LAYOUTGET", *status)))
            }
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include LAYOUTGET result".into()))?
}

pub(crate) fn response_layout_return(response: &CompoundResponse) -> Result<LayoutReturnResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::LayoutReturn {
                status,
                result: Some(layout_return),
            } if status.is_ok() => Some(Ok(*layout_return)),
            OperationResult::LayoutReturn {
                status,
                result: None,
            } if status.is_ok() => Some(Err(Error::Protocol(
                "NFSv4 LAYOUTRETURN returned OK without a result".into(),
            ))),
            OperationResult::LayoutReturn { status, .. } => {
                Some(Err(Error::nfsv4("LAYOUTRETURN", *status)))
            }
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include LAYOUTRETURN result".into()))?
}

pub(crate) fn response_write_same(
    response: &CompoundResponse,
    requested_count: u64,
) -> Result<WriteResponse> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::WriteSame {
                status,
                result: Some(write),
            } if status.is_ok() => Some(
                validate_u64_write_result_count("WRITE_SAME", requested_count, write.count)
                    .map(|()| write.clone()),
            ),
            OperationResult::WriteSame { status, .. } => {
                Some(Err(Error::nfsv4("WRITE_SAME", *status)))
            }
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include WRITE_SAME result".into()))?
}

pub(crate) fn validate_read_result_size(
    requested_count: u32,
    data_len: usize,
    eof: bool,
) -> Result<()> {
    if data_len > requested_count as usize {
        return Err(Error::Protocol(format!(
            "NFSv4 READ returned {data_len} bytes for a {requested_count} byte request"
        )));
    }
    if requested_count > 0 && data_len == 0 && !eof {
        return Err(Error::Protocol(
            "NFSv4 READ returned no data before EOF".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_read_plus_result(
    requested_count: u32,
    result: &ReadPlusResult,
) -> Result<()> {
    let mut returned = 0_u64;
    for content in &result.contents {
        let len = match content {
            ReadPlusContent::Data { data, .. } => data.len() as u64,
            ReadPlusContent::Hole { length, .. } => *length,
        };
        returned = returned.checked_add(len).ok_or_else(|| {
            Error::Protocol("NFSv4 READ_PLUS returned content length overflow".into())
        })?;
    }

    if returned > u64::from(requested_count) {
        return Err(Error::Protocol(format!(
            "NFSv4 READ_PLUS returned {returned} bytes for a {requested_count} byte request"
        )));
    }
    if requested_count > 0 && returned == 0 && !result.eof {
        return Err(Error::Protocol(
            "NFSv4 READ_PLUS returned no content before EOF".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_write_result_count(requested_count: u32, returned_count: u32) -> Result<()> {
    if returned_count > requested_count {
        return Err(Error::Protocol(format!(
            "NFSv4 WRITE reported {returned_count} bytes for a {requested_count} byte request"
        )));
    }
    if requested_count > 0 && returned_count == 0 {
        return Err(Error::Protocol("NFSv4 WRITE accepted zero bytes".into()));
    }
    Ok(())
}

fn validate_u64_write_result_count(
    operation: &str,
    requested_count: u64,
    returned_count: u64,
) -> Result<()> {
    if returned_count > requested_count {
        return Err(Error::Protocol(format!(
            "NFSv4 {operation} reported {returned_count} bytes for a {requested_count} byte request"
        )));
    }
    if requested_count > 0 && returned_count == 0 {
        return Err(Error::Protocol(format!(
            "NFSv4 {operation} accepted zero bytes"
        )));
    }
    Ok(())
}

fn validate_copy_result(requested_count: u64, copy: &CopyResult) -> Result<()> {
    let Some(write) = &copy.response else {
        return Err(Error::Protocol(
            "NFSv4 COPY returned OK without a write response".into(),
        ));
    };
    if write.count > requested_count {
        return Err(Error::Protocol(format!(
            "NFSv4 COPY reported {} bytes for a {requested_count} byte request",
            write.count
        )));
    }
    if requested_count > 0 && write.count == 0 && write.callback_id.is_none() {
        return Err(Error::Protocol("NFSv4 COPY accepted zero bytes".into()));
    }
    Ok(())
}

pub(crate) fn response_commit(response: &CompoundResponse) -> Result<CommitResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::Commit {
                status,
                result: Some(commit),
            } if status.is_ok() => Some(Ok(commit.clone())),
            OperationResult::Commit { status, .. } => Some(Err(Error::nfsv4("COMMIT", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include COMMIT result".into()))?
}

pub(crate) fn response_seek(response: &CompoundResponse) -> Result<SeekResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::Seek {
                status,
                result: Some(seek),
            } if status.is_ok() => Some(Ok(*seek)),
            OperationResult::Seek { status, .. } => Some(Err(Error::nfsv4("SEEK", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include SEEK result".into()))?
}

pub(crate) fn response_readdir(
    response: &CompoundResponse,
) -> Result<(Verifier, Vec<crate::v4::proto::DirEntry>, bool)> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::ReadDir {
                status,
                cookieverf,
                entries,
                eof,
            } if status.is_ok() => Some(Ok((*cookieverf, entries.clone(), *eof))),
            OperationResult::ReadDir { status, .. } => Some(Err(Error::nfsv4("READDIR", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include READDIR result".into()))?
}

pub(crate) fn response_openattr_readdir(
    response: &CompoundResponse,
) -> Result<(Verifier, Vec<crate::v4::proto::DirEntry>, bool)> {
    let mut saw_openattr = false;
    for result in &response.results {
        match result {
            OperationResult::StatusOnly { op, status }
                if *op == OpCode::OpenAttr && status.is_ok() =>
            {
                saw_openattr = true;
            }
            OperationResult::StatusOnly { op, status } if *op == OpCode::OpenAttr => {
                return Err(Error::nfsv4("OPENATTR", *status));
            }
            OperationResult::ReadDir {
                status,
                cookieverf,
                entries,
                eof,
            } if status.is_ok() => return Ok((*cookieverf, entries.clone(), *eof)),
            OperationResult::ReadDir { status, .. } => {
                return Err(Error::nfsv4("READDIR", *status));
            }
            _ => {}
        }
    }

    if saw_openattr {
        Err(Error::Protocol(
            "COMPOUND did not include READDIR result after OPENATTR".into(),
        ))
    } else {
        Err(Error::Protocol(
            "COMPOUND did not include OPENATTR result".into(),
        ))
    }
}

pub(crate) fn app_data_block_len(block: &AppDataBlock) -> Result<u64> {
    if block.block_count > 0 && block.block_size == 0 {
        return Err(Error::Protocol(
            "NFSv4 WRITE_SAME block size must be nonzero when block count is nonzero".into(),
        ));
    }
    block
        .block_size
        .checked_mul(block.block_count)
        .ok_or_else(|| Error::Protocol("NFSv4 WRITE_SAME byte count overflow".into()))
}

pub(crate) fn io_advice_bitmap(hints: &[IoAdviceType]) -> Bitmap {
    let attrs = hints.iter().map(|hint| hint.as_u32()).collect::<Vec<_>>();
    Bitmap::from_known_attrs(&attrs)
}

pub(crate) fn io_advice_share_access(hints: &[IoAdviceType]) -> u32 {
    if hints.contains(&IoAdviceType::Write) {
        OPEN4_SHARE_ACCESS_WRITE
    } else {
        OPEN4_SHARE_ACCESS_READ
    }
}

pub(crate) fn lock_share_access(lock_type: LockType) -> u32 {
    match lock_type {
        LockType::Read | LockType::ReadBlocking => OPEN4_SHARE_ACCESS_READ,
        LockType::Write | LockType::WriteBlocking => OPEN4_SHARE_ACCESS_WRITE,
    }
}

pub(crate) fn layout_iomode_share_access(iomode: LayoutIomode) -> u32 {
    match iomode {
        LayoutIomode::Read => OPEN4_SHARE_ACCESS_READ,
        LayoutIomode::ReadWrite | LayoutIomode::Any | LayoutIomode::Unknown(_) => {
            OPEN4_SHARE_ACCESS_BOTH
        }
    }
}

pub(crate) fn validate_stateid_batch_len(count: usize) -> Result<()> {
    if count > NFS4_MAX_OPS {
        return Err(Error::Protocol(format!(
            "NFSv4 TEST_STATEID accepts at most {NFS4_MAX_OPS} stateids, got {count}"
        )));
    }
    Ok(())
}

pub(crate) fn validate_max_device_ids(max_device_ids: usize) -> Result<u32> {
    if max_device_ids == 0 || max_device_ids > u32::MAX as usize {
        return Err(Error::Protocol(format!(
            "max_device_ids must be in 1..={}",
            u32::MAX
        )));
    }
    Ok(max_device_ids as u32)
}

pub(crate) fn dir_page_from_entries(
    cookieverf: Verifier,
    entries: Vec<crate::v4::proto::DirEntry>,
    eof: bool,
    previous_cookie: u64,
    max_entries: usize,
) -> Result<DirPage> {
    if entries.len() > max_entries {
        return Err(Error::Protocol(format!(
            "NFSv4 READDIR exceeded configured limit of {max_entries} entries"
        )));
    }
    let next_cursor = next_dir_cursor(cookieverf, &entries, eof, previous_cookie)?;
    let entries = entries
        .into_iter()
        .map(DirEntry::from_wire)
        .collect::<Result<Vec<_>>>()?;
    Ok(DirPage {
        entries,
        next_cursor,
    })
}

pub(crate) fn next_dir_cursor(
    cookieverf: Verifier,
    entries: &[crate::v4::proto::DirEntry],
    eof: bool,
    previous_cookie: u64,
) -> Result<Option<DirPageCursor>> {
    if eof {
        return Ok(None);
    }

    let last = entries
        .last()
        .ok_or_else(|| Error::Protocol("NFSv4 READDIR returned no entries before EOF".into()))?;
    if last.cookie == previous_cookie {
        return Err(Error::Protocol(format!(
            "NFSv4 READDIR did not advance directory cookie {previous_cookie}"
        )));
    }
    Ok(Some(DirPageCursor {
        cookie: last.cookie,
        cookieverf,
    }))
}

pub(crate) fn device_list_page_from_result(
    result: GetDeviceListResult,
    previous_cookie: u64,
    max_device_ids: usize,
) -> Result<DeviceListPage> {
    if result.device_ids.len() > max_device_ids {
        return Err(Error::Protocol(format!(
            "NFSv4 GETDEVICELIST exceeded configured limit of {max_device_ids} device ids"
        )));
    }
    let next_cursor = next_device_list_cursor(
        result.cookie,
        result.cookieverf,
        result.eof,
        previous_cookie,
    )?;
    Ok(DeviceListPage {
        device_ids: result.device_ids,
        next_cursor,
    })
}

pub(crate) fn next_device_list_cursor(
    cookie: u64,
    cookieverf: Verifier,
    eof: bool,
    previous_cookie: u64,
) -> Result<Option<DeviceListCursor>> {
    if eof {
        return Ok(None);
    }

    if cookie == previous_cookie {
        return Err(Error::Protocol(format!(
            "NFSv4 GETDEVICELIST did not advance device-list cookie {previous_cookie}"
        )));
    }
    Ok(Some(DeviceListCursor { cookie, cookieverf }))
}

pub(crate) fn verifier_from_time() -> Verifier {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (duration.as_secs() ^ u64::from(duration.subsec_nanos())).to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_components_reject_parent_components() {
        assert!(matches!(
            path_components("../x"),
            Err(Error::InvalidPath(_))
        ));
        assert!(matches!(
            path_components("/safe/../x"),
            Err(Error::InvalidPath(_))
        ));
    }

    #[test]
    fn path_components_reject_oversized_names() {
        let path = "x".repeat(NFS4_OPAQUE_LIMIT + 1);
        assert!(matches!(
            path_components(&path),
            Err(Error::NameTooLong {
                max: NFS4_OPAQUE_LIMIT,
                ..
            })
        ));
    }

    #[test]
    fn named_attr_names_are_single_safe_components() {
        assert!(validate_named_attr_name("user.comment").is_ok());
        assert!(matches!(
            validate_named_attr_name(""),
            Err(Error::InvalidPath(_))
        ));
        assert!(matches!(
            validate_named_attr_name("."),
            Err(Error::InvalidPath(_))
        ));
        assert!(matches!(
            validate_named_attr_name("a/b"),
            Err(Error::InvalidPath(_))
        ));
        assert!(matches!(
            validate_named_attr_name(&"x".repeat(NFS4_OPAQUE_LIMIT + 1)),
            Err(Error::NameTooLong { .. })
        ));
    }

    #[test]
    fn builds_named_attr_current_filehandle_ops() {
        let ops = named_attr_ops(
            "/dir/file",
            "user.comment",
            vec![Operation::GetAttr(Bitmap::empty())],
        )
        .unwrap();
        assert_eq!(
            ops.iter().map(Operation::op_code).collect::<Vec<_>>(),
            vec![
                OpCode::PutRootFh,
                OpCode::Lookup,
                OpCode::Lookup,
                OpCode::OpenAttr,
                OpCode::Lookup,
                OpCode::GetAttr,
            ]
        );
    }

    #[test]
    fn builds_public_filehandle_path_ops() {
        let ops = public_path_ops("/dir/file", vec![Operation::GetAttr(Bitmap::empty())]).unwrap();
        assert_eq!(
            ops.iter().map(Operation::op_code).collect::<Vec<_>>(),
            vec![
                OpCode::PutPubFh,
                OpCode::Lookup,
                OpCode::Lookup,
                OpCode::GetAttr,
            ]
        );
    }

    #[test]
    fn builds_parent_filehandle_ops() {
        let ops = parent_path_ops("/dir/file", vec![Operation::GetAttr(Bitmap::empty())]).unwrap();
        assert_eq!(
            ops.iter().map(Operation::op_code).collect::<Vec<_>>(),
            vec![
                OpCode::PutRootFh,
                OpCode::Lookup,
                OpCode::Lookup,
                OpCode::Lookupp,
                OpCode::GetAttr,
            ]
        );
    }

    #[test]
    fn parent_filehandle_ops_reject_root() {
        assert!(matches!(
            parent_path_ops("/", Vec::new()),
            Err(Error::InvalidPath(_))
        ));
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
    fn builds_temporary_named_attr_names() {
        let name = temporary_named_attr_name();
        assert!(name.starts_with(".nfs-rs-tmp-"));
        assert!(validate_named_attr_name(&name).is_ok());
    }

    #[test]
    fn builds_directory_pages_from_entries() {
        let page = dir_page_from_entries(
            [8; NFS4_VERIFIER_SIZE],
            vec![crate::v4::proto::DirEntry {
                cookie: 11,
                name: "file".to_owned(),
                attrs: Fattr::empty(),
            }],
            false,
            0,
            16,
        )
        .unwrap();

        assert_eq!(page.entries.len(), 1);
        assert_eq!(
            page.next_cursor,
            Some(DirPageCursor {
                cookie: 11,
                cookieverf: [8; NFS4_VERIFIER_SIZE],
            })
        );
    }

    #[test]
    fn rejects_non_advancing_directory_cookies() {
        assert!(matches!(
            dir_page_from_entries(
                [8; NFS4_VERIFIER_SIZE],
                vec![crate::v4::proto::DirEntry {
                    cookie: 11,
                    name: "file".to_owned(),
                    attrs: Fattr::empty(),
                }],
                false,
                11,
                16,
            ),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn builds_device_list_pages_from_results() {
        let device_id = [4; NFS4_DEVICEID_SIZE];
        let page = device_list_page_from_result(
            GetDeviceListResult {
                cookie: 10,
                cookieverf: [5; NFS4_VERIFIER_SIZE],
                device_ids: vec![device_id],
                eof: false,
            },
            0,
            4,
        )
        .unwrap();

        assert_eq!(page.device_ids, vec![device_id]);
        assert_eq!(
            page.next_cursor,
            Some(DeviceListCursor {
                cookie: 10,
                cookieverf: [5; NFS4_VERIFIER_SIZE],
            })
        );

        assert!(matches!(
            device_list_page_from_result(
                GetDeviceListResult {
                    cookie: 10,
                    cookieverf: [5; NFS4_VERIFIER_SIZE],
                    device_ids: vec![device_id],
                    eof: false,
                },
                10,
                4,
            ),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn response_openattr_readdir_returns_entries_and_status_errors() {
        let ok = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![
                OperationResult::StatusOnly {
                    op: OpCode::OpenAttr,
                    status: Status::Ok,
                },
                OperationResult::ReadDir {
                    status: Status::Ok,
                    cookieverf: [7; NFS4_VERIFIER_SIZE],
                    entries: vec![crate::v4::proto::DirEntry {
                        cookie: 12,
                        name: "user.comment".to_owned(),
                        attrs: Fattr::empty(),
                    }],
                    eof: true,
                },
            ],
        };
        let (cookieverf, entries, eof) = response_openattr_readdir(&ok).unwrap();
        assert_eq!(cookieverf, [7; NFS4_VERIFIER_SIZE]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "user.comment");
        assert!(eof);

        let failed = CompoundResponse {
            status: Status::NotSupported,
            tag: String::new(),
            results: vec![OperationResult::StatusOnly {
                op: OpCode::OpenAttr,
                status: Status::NotSupported,
            }],
        };
        assert!(matches!(
            response_openattr_readdir(&failed),
            Err(Error::NfsV4 {
                operation: "OPENATTR",
                status: Status::NotSupported
            })
        ));

        let missing_readdir = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::StatusOnly {
                op: OpCode::OpenAttr,
                status: Status::Ok,
            }],
        };
        assert!(matches!(
            response_openattr_readdir(&missing_readdir),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn detects_attrs_that_require_open_state() {
        assert!(attrs_require_open_state(&Fattr::size(10)));
        assert!(!attrs_require_open_state(&Fattr::mode(0o644)));
        assert!(!attrs_require_open_state(&Fattr::empty()));
    }

    #[test]
    fn owner_seqid_advances_only_when_owner_operation_was_seen() {
        let before_open = CompoundResponse {
            status: Status::NoEnt,
            tag: String::new(),
            results: vec![
                OperationResult::Sequence {
                    status: Status::Ok,
                    result: None,
                },
                OperationResult::StatusOnly {
                    op: OpCode::Lookup,
                    status: Status::NoEnt,
                },
            ],
        };
        assert!(!response_consumed_owner_seqid(&before_open, OpCode::Open));

        let failed_open = CompoundResponse {
            status: Status::NoEnt,
            tag: String::new(),
            results: vec![
                OperationResult::Sequence {
                    status: Status::Ok,
                    result: None,
                },
                OperationResult::Open {
                    status: Status::NoEnt,
                    result: None,
                },
            ],
        };
        assert!(response_consumed_owner_seqid(&failed_open, OpCode::Open));

        let bad_seqid = CompoundResponse {
            status: Status::BadSeqId,
            tag: String::new(),
            results: vec![OperationResult::Close {
                status: Status::BadSeqId,
                stateid: None,
            }],
        };
        assert!(!response_consumed_owner_seqid(&bad_seqid, OpCode::Close));

        for status in [
            Status::StaleClientId,
            Status::StaleStateId,
            Status::BadStateId,
            Status::BadSeqId,
            Status::BadXdr,
            Status::Resource,
            Status::NoFileHandle,
            Status::Moved,
        ] {
            let response = CompoundResponse {
                status,
                tag: String::new(),
                results: vec![OperationResult::Open {
                    status,
                    result: None,
                }],
            };
            assert!(
                !response_consumed_owner_seqid(&response, OpCode::Open),
                "{status:?} must not advance the open-owner seqid"
            );
        }

        for status in [Status::Delay, Status::Grace] {
            let response = CompoundResponse {
                status,
                tag: String::new(),
                results: vec![OperationResult::Open {
                    status,
                    result: None,
                }],
            };
            assert!(
                response_consumed_owner_seqid(&response, OpCode::Open),
                "{status:?} must advance the open-owner seqid"
            );
        }
    }

    #[test]
    fn derives_payload_limit_from_session_channel_size() {
        assert_eq!(session_payload_limit(0), 0);
        assert_eq!(session_payload_limit(4096), 0);
        assert_eq!(session_payload_limit(4097), 1);
        assert_eq!(session_payload_limit(8192), 4096);
        assert_eq!(session_payload_limit(u32::MAX), NFS4_MAX_IO as u32);
    }

    #[test]
    fn detects_retryable_delay_and_grace_statuses() {
        let response = CompoundResponse {
            status: Status::Delay,
            tag: String::new(),
            results: vec![OperationResult::StatusOnly {
                op: OpCode::GetFh,
                status: Status::Delay,
            }],
        };
        assert_eq!(first_delayed_retry_result_index(&response), Some(0));

        let response = CompoundResponse {
            status: Status::Grace,
            tag: String::new(),
            results: vec![OperationResult::StatusOnly {
                op: OpCode::Open,
                status: Status::Grace,
            }],
        };
        assert_eq!(first_delayed_retry_result_index(&response), Some(0));
    }

    #[test]
    fn delayed_retry_requires_replayable_successful_prefix() {
        let handle = FileHandle::new(vec![1]).unwrap();
        let write_delay = CompoundResponse {
            status: Status::Delay,
            tag: String::new(),
            results: vec![
                sequence_ok_result(),
                OperationResult::StatusOnly {
                    op: OpCode::PutFh,
                    status: Status::Ok,
                },
                OperationResult::Write {
                    status: Status::Delay,
                    result: None,
                },
            ],
        };
        assert!(response_allows_delayed_retry(
            &[
                Operation::PutFh(handle.clone()),
                Operation::Write {
                    stateid: StateId::anonymous(),
                    offset: 0,
                    stable: StableHow::FileSync,
                    data: b"abc".to_vec(),
                },
            ],
            &write_delay
        ));

        let open_then_getfh_delay = CompoundResponse {
            status: Status::Delay,
            tag: String::new(),
            results: vec![
                sequence_ok_result(),
                OperationResult::Open {
                    status: Status::Ok,
                    result: Some(OpenResult {
                        stateid: StateId::anonymous(),
                        result_flags: 0,
                        attrset: Bitmap::empty(),
                        delegation: OpenDelegation::None,
                    }),
                },
                OperationResult::GetFh {
                    status: Status::Delay,
                    handle: None,
                },
            ],
        };
        assert!(!response_allows_delayed_retry(
            &[Operation::Open(open_args("file.txt")), Operation::GetFh,],
            &open_then_getfh_delay
        ));

        let open_delay = CompoundResponse {
            status: Status::Delay,
            tag: String::new(),
            results: vec![
                sequence_ok_result(),
                OperationResult::Open {
                    status: Status::Delay,
                    result: None,
                },
            ],
        };
        assert!(!response_allows_delayed_retry(
            &[Operation::Open(open_args("file.txt"))],
            &open_delay
        ));
        assert!(response_operation_has_delayed_status(
            &open_delay,
            OpCode::Open
        ));

        let sequence_delay = CompoundResponse {
            status: Status::Delay,
            tag: String::new(),
            results: vec![OperationResult::Sequence {
                status: Status::Delay,
                result: None,
            }],
        };
        assert!(response_allows_delayed_retry(
            &[Operation::Remove("file.txt".to_owned())],
            &sequence_delay
        ));

        let raw_create_session_delay = CompoundResponse {
            status: Status::Delay,
            tag: String::new(),
            results: vec![OperationResult::CreateSession {
                status: Status::Delay,
                result: None,
            }],
        };
        assert!(response_allows_delayed_retry_without_sequence(
            &[Operation::CreateSession(CreateSessionArgs {
                client_id: 1,
                sequence_id: 1,
                flags: 0,
                fore_channel_attrs: ChannelAttrs::fore_channel_default(),
                back_channel_attrs: ChannelAttrs::back_channel_disabled(),
                callback_program: 0,
                callback_sec_parms: Vec::new(),
            })],
            &raw_create_session_delay
        ));
    }

    #[test]
    fn does_not_treat_session_recovery_status_as_delay_retry() {
        let failed_sequence = CompoundResponse {
            status: Status::BadSession,
            tag: String::new(),
            results: vec![OperationResult::Sequence {
                status: Status::BadSession,
                result: None,
            }],
        };
        assert_eq!(first_delayed_retry_result_index(&failed_sequence), None);
        assert!(response_requires_session_recovery(&failed_sequence));

        let failed_later_operation = CompoundResponse {
            status: Status::BadSession,
            tag: String::new(),
            results: vec![
                OperationResult::Sequence {
                    status: Status::Ok,
                    result: Some(SequenceResult {
                        session_id: [1; NFS4_SESSIONID_SIZE],
                        sequence_id: 1,
                        slot_id: 0,
                        highest_slot_id: 0,
                        target_highest_slot_id: 0,
                        status_flags: 0,
                    }),
                },
                OperationResult::StatusOnly {
                    op: OpCode::GetFh,
                    status: Status::BadSession,
                },
            ],
        };
        assert_eq!(
            first_delayed_retry_result_index(&failed_later_operation),
            None
        );
        assert!(!response_requires_session_recovery(&failed_later_operation));
        assert!(response_operation_requires_session_recovery(
            &failed_later_operation,
            OpCode::GetFh
        ));
        assert!(!response_operation_requires_session_recovery(
            &failed_later_operation,
            OpCode::Open
        ));
    }

    #[test]
    fn accepts_reclaim_complete_already_during_session_setup() {
        let complete_already = CompoundResponse {
            status: Status::CompleteAlready,
            tag: String::new(),
            results: vec![OperationResult::StatusOnly {
                op: OpCode::ReclaimComplete,
                status: Status::CompleteAlready,
            }],
        };
        assert!(ensure_reclaim_complete(&complete_already).is_ok());

        let wrong_sec = CompoundResponse {
            status: Status::WrongSec,
            tag: String::new(),
            results: vec![OperationResult::StatusOnly {
                op: OpCode::ReclaimComplete,
                status: Status::WrongSec,
            }],
        };
        assert!(ensure_reclaim_complete(&wrong_sec).is_err());
    }

    #[test]
    fn clamps_session_max_operations_to_protocol_limit() {
        let mut attrs = ChannelAttrs::fore_channel_default();
        attrs.max_operations = 32;
        assert_eq!(session_max_operations(&attrs).unwrap(), 32);

        attrs.max_operations = (NFS4_MAX_OPS as u32) + 1;
        assert_eq!(session_max_operations(&attrs).unwrap(), NFS4_MAX_OPS);

        attrs.max_operations = 0;
        assert!(matches!(
            session_max_operations(&attrs),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn rejects_session_channels_without_payload_capacity() {
        let mut attrs = ChannelAttrs::fore_channel_default();
        assert!(validate_session_channel_attrs(&attrs).is_ok());

        attrs.max_request_size = 4096;
        assert!(matches!(
            validate_session_channel_attrs(&attrs),
            Err(Error::Protocol(_))
        ));

        attrs.max_request_size = ChannelAttrs::fore_channel_default().max_request_size;
        attrs.max_response_size = 0;
        assert!(matches!(
            validate_session_channel_attrs(&attrs),
            Err(Error::Protocol(_))
        ));

        attrs.max_response_size = ChannelAttrs::fore_channel_default().max_response_size;
        attrs.max_requests = 0;
        assert!(matches!(
            validate_session_channel_attrs(&attrs),
            Err(Error::Protocol(_))
        ));
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
    fn finish_with_close_preserves_cleanup_failures() {
        let err = finish_with_close::<()>(
            Err(Error::Protocol("primary failure".to_owned())),
            Err(Error::Protocol("close failure".to_owned())),
        )
        .unwrap_err();

        let message = err.to_string();
        assert!(message.contains("primary failure"));
        assert!(message.contains("close failure"));
    }

    #[test]
    fn validates_compound_response_shape_and_order() {
        let ok = CompoundResponse {
            status: Status::Ok,
            tag: "read".to_owned(),
            results: vec![
                OperationResult::Sequence {
                    status: Status::Ok,
                    result: None,
                },
                OperationResult::StatusOnly {
                    op: OpCode::PutFh,
                    status: Status::Ok,
                },
                OperationResult::Read {
                    status: Status::Ok,
                    eof: true,
                    data: Vec::new(),
                },
            ],
        };
        assert!(
            validate_compound_response_shape(
                "read",
                &[OpCode::Sequence, OpCode::PutFh, OpCode::Read],
                &ok
            )
            .is_ok()
        );
        assert!(matches!(
            validate_compound_response_shape(
                "read",
                &[OpCode::Sequence, OpCode::GetFh, OpCode::Read],
                &ok
            ),
            Err(Error::Protocol(_))
        ));

        let too_many = CompoundResponse {
            status: Status::Ok,
            tag: "getfh".to_owned(),
            results: vec![
                OperationResult::StatusOnly {
                    op: OpCode::PutRootFh,
                    status: Status::Ok,
                },
                OperationResult::StatusOnly {
                    op: OpCode::GetFh,
                    status: Status::Ok,
                },
            ],
        };
        assert!(matches!(
            validate_compound_response_shape("getfh", &[OpCode::PutRootFh], &too_many),
            Err(Error::Protocol(_))
        ));

        let short_success = CompoundResponse {
            status: Status::Ok,
            tag: "getattr".to_owned(),
            results: vec![OperationResult::StatusOnly {
                op: OpCode::PutRootFh,
                status: Status::Ok,
            }],
        };
        assert!(matches!(
            validate_compound_response_shape(
                "getattr",
                &[OpCode::PutRootFh, OpCode::GetAttr],
                &short_success
            ),
            Err(Error::Protocol(_))
        ));

        let failed_lookup = CompoundResponse {
            status: Status::NoEnt,
            tag: "lookup".to_owned(),
            results: vec![
                OperationResult::Sequence {
                    status: Status::Ok,
                    result: None,
                },
                OperationResult::StatusOnly {
                    op: OpCode::Lookup,
                    status: Status::NoEnt,
                },
            ],
        };
        assert!(
            validate_compound_response_shape(
                "lookup",
                &[OpCode::Sequence, OpCode::Lookup, OpCode::GetAttr],
                &failed_lookup
            )
            .is_ok()
        );

        let failed_with_ok_results = CompoundResponse {
            status: Status::NoEnt,
            tag: "lookup".to_owned(),
            results: vec![OperationResult::StatusOnly {
                op: OpCode::Lookup,
                status: Status::Ok,
            }],
        };
        assert!(matches!(
            validate_compound_response_shape("lookup", &[OpCode::Lookup], &failed_with_ok_results),
            Err(Error::Protocol(_))
        ));

        let wrong_tag = CompoundResponse {
            status: Status::Ok,
            tag: "other".to_owned(),
            results: vec![OperationResult::StatusOnly {
                op: OpCode::PutRootFh,
                status: Status::Ok,
            }],
        };
        assert!(matches!(
            validate_compound_response_shape("expected", &[OpCode::PutRootFh], &wrong_tag),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn accepts_spec_illegal_result_for_unsupported_operation() {
        let response = CompoundResponse {
            status: Status::OpIllegal,
            tag: "unsupported".to_owned(),
            results: vec![
                OperationResult::Sequence {
                    status: Status::Ok,
                    result: None,
                },
                OperationResult::StatusOnly {
                    op: OpCode::Illegal,
                    status: Status::OpIllegal,
                },
            ],
        };

        assert!(
            validate_compound_response_shape(
                "unsupported",
                &[OpCode::Sequence, OpCode::Seek],
                &response
            )
            .is_ok()
        );

        let response = CompoundResponse {
            status: Status::BadXdr,
            tag: "bad".to_owned(),
            results: vec![OperationResult::StatusOnly {
                op: OpCode::Illegal,
                status: Status::BadXdr,
            }],
        };
        assert!(matches!(
            validate_compound_response_shape("bad", &[OpCode::Seek], &response),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn validates_session_compound_operation_count_with_sequence() {
        assert!(validate_session_compound_operation_count(3, 4).is_ok());
        assert!(matches!(
            validate_session_compound_operation_count(4, 4),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn rejects_open_confirm_for_session_minor_versions() {
        let open = OpenResult {
            stateid: StateId::anonymous(),
            result_flags: OPEN4_RESULT_CONFIRM,
            attrset: Bitmap::empty(),
            delegation: OpenDelegation::None,
        };

        assert!(matches!(
            validate_open_result(&open, NFS4_MINOR_VERSION_SESSION_MIN),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn detects_open_delegation_stateid_for_return() {
        let delegated = StateId {
            seqid: 7,
            other: [8; 12],
        };
        let open = OpenResult {
            stateid: StateId::anonymous(),
            result_flags: 0,
            attrset: Bitmap::empty(),
            delegation: OpenDelegation::Read(OpenReadDelegation {
                stateid: delegated,
                recall: false,
                permissions: NfsAce {
                    ace_type: 0,
                    flag: 0,
                    access_mask: ACCESS4_READ,
                    who: "OWNER@".to_owned(),
                },
            }),
        };

        assert_eq!(
            validate_open_result(&open, NFS4_MINOR_VERSION_SESSION_MIN).unwrap(),
            Some(delegated)
        );
    }

    #[test]
    fn detects_session_recovery_status_only_when_sequence_failed() {
        let failed_sequence = CompoundResponse {
            status: Status::BadSession,
            tag: String::new(),
            results: vec![OperationResult::Sequence {
                status: Status::BadSession,
                result: None,
            }],
        };
        assert!(response_requires_session_recovery(&failed_sequence));

        let failed_later_operation = CompoundResponse {
            status: Status::BadSession,
            tag: String::new(),
            results: vec![
                OperationResult::Sequence {
                    status: Status::Ok,
                    result: Some(SequenceResult {
                        session_id: [1; NFS4_SESSIONID_SIZE],
                        sequence_id: 1,
                        slot_id: 0,
                        highest_slot_id: 0,
                        target_highest_slot_id: 0,
                        status_flags: 0,
                    }),
                },
                OperationResult::StatusOnly {
                    op: OpCode::GetFh,
                    status: Status::BadSession,
                },
            ],
        };
        assert!(!response_requires_session_recovery(&failed_later_operation));

        let empty_compound_failure = CompoundResponse {
            status: Status::DeadSession,
            tag: String::new(),
            results: Vec::new(),
        };
        assert!(response_requires_session_recovery(&empty_compound_failure));
    }

    #[test]
    fn classifies_session_recovery_replay_safety_conservatively() {
        assert!(operations_can_replay_after_session_recovery(&[
            Operation::PutRootFh,
            Operation::Lookup("dir".to_owned()),
            Operation::GetAttr(Bitmap::empty()),
        ]));
        assert!(operations_can_replay_after_session_recovery(&[
            Operation::PutFh(FileHandle::new(vec![1]).unwrap()),
            Operation::Read {
                stateid: StateId::anonymous(),
                offset: 0,
                count: 1,
            },
        ]));
        assert!(operations_can_replay_after_session_recovery(&[
            Operation::TestStateIds(vec![StateId {
                seqid: 1,
                other: [7; 12],
            }]),
        ]));
        assert!(!operations_can_replay_after_session_recovery(&[
            Operation::Open(OpenArgs {
                seqid: 1,
                share_access: OPEN4_SHARE_ACCESS_READ,
                share_deny: OPEN4_SHARE_DENY_NONE,
                owner: OpenOwner {
                    client_id: 1,
                    owner: b"owner".to_vec(),
                },
                openhow: OpenHow::NoCreate,
                claim: OpenClaim::Null("file".to_owned()),
            }),
            Operation::GetFh,
        ]));
        assert!(!operations_can_replay_after_session_recovery(&[
            Operation::PutRootFh,
            Operation::Lookup("dir".to_owned()),
            Operation::Create(CreateArgs {
                kind: CreateKind::Directory,
                name: "file".to_owned(),
                attrs: Fattr::empty(),
            }),
        ]));
        assert!(!operations_can_replay_after_session_recovery(&[
            Operation::PutRootFh,
            Operation::Lookup("dir".to_owned()),
            Operation::Remove("file".to_owned()),
        ]));
        assert!(!operations_can_replay_after_session_recovery(&[
            Operation::PutFh(FileHandle::new(vec![1]).unwrap()),
            Operation::SetAttr {
                stateid: StateId::anonymous(),
                attrs: Fattr::size(1),
            },
        ]));
        assert!(!operations_can_replay_after_session_recovery(&[
            Operation::PutFh(FileHandle::new(vec![1]).unwrap()),
            Operation::Commit {
                offset: 0,
                count: 0,
            },
        ]));
        assert!(!operations_can_replay_after_session_recovery(&[
            Operation::FreeStateId(StateId {
                seqid: 1,
                other: [7; 12],
            }),
        ]));
        assert!(!operations_can_replay_after_session_recovery(&[
            Operation::PutFh(FileHandle::new(vec![1]).unwrap()),
            Operation::Read {
                stateid: StateId {
                    seqid: 1,
                    other: [7; 12],
                },
                offset: 0,
                count: 1,
            },
        ]));
    }

    #[test]
    fn response_read_validates_returned_size_and_progress() {
        let oversized = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::Read {
                status: Status::Ok,
                eof: false,
                data: vec![1, 2, 3, 4, 5],
            }],
        };
        assert!(matches!(
            response_read(&oversized, 4),
            Err(Error::Protocol(_))
        ));

        let no_progress = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::Read {
                status: Status::Ok,
                eof: false,
                data: Vec::new(),
            }],
        };
        assert!(matches!(
            response_read(&no_progress, 4),
            Err(Error::Protocol(_))
        ));

        let eof = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::Read {
                status: Status::Ok,
                eof: true,
                data: Vec::new(),
            }],
        };
        assert_eq!(response_read(&eof, 4).unwrap(), (true, Vec::new()));
    }

    #[test]
    fn response_secinfo_returns_flavors_and_status_errors() {
        let ok = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::SecInfo {
                op: OpCode::SecInfo,
                status: Status::Ok,
                flavors: vec![SecInfo::AuthSys],
            }],
        };
        assert_eq!(
            response_secinfo(&ok, OpCode::SecInfo).unwrap(),
            vec![SecInfo::AuthSys]
        );

        let failed = CompoundResponse {
            status: Status::WrongSec,
            tag: String::new(),
            results: vec![OperationResult::SecInfo {
                op: OpCode::SecInfoNoName,
                status: Status::WrongSec,
                flavors: Vec::new(),
            }],
        };
        assert!(matches!(
            response_secinfo(&failed, OpCode::SecInfoNoName),
            Err(Error::NfsV4 {
                operation: "SECINFO_NO_NAME",
                status: Status::WrongSec
            })
        ));

        assert!(matches!(
            response_secinfo(&ok, OpCode::SecInfoNoName),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn response_device_operations_return_results_and_status_errors() {
        let device_id = [3; NFS4_DEVICEID_SIZE];
        let device_info = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::GetDeviceInfo {
                status: Status::Ok,
                result: Some(GetDeviceInfoResult {
                    device_addr: DeviceAddr {
                        layout_type: LayoutType::NfsV4_1Files,
                        body: b"addr".to_vec(),
                    },
                    notification: Bitmap::from_known_attrs(&[FATTR4_SIZE]),
                }),
                min_count: None,
            }],
        };
        let info = response_get_device_info(&device_info).unwrap();
        assert_eq!(info.device_addr.layout_type, LayoutType::NfsV4_1Files);
        assert_eq!(info.device_addr.body, b"addr");
        assert!(info.notification.contains(FATTR4_SIZE));

        let device_list = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::GetDeviceList {
                status: Status::Ok,
                result: Some(GetDeviceListResult {
                    cookie: 11,
                    cookieverf: [6; NFS4_VERIFIER_SIZE],
                    device_ids: vec![device_id],
                    eof: true,
                }),
            }],
        };
        let list = response_get_device_list(&device_list).unwrap();
        assert_eq!(list.device_ids, vec![device_id]);
        assert!(list.eof);

        let failed = CompoundResponse {
            status: Status::TooSmall,
            tag: String::new(),
            results: vec![OperationResult::GetDeviceInfo {
                status: Status::TooSmall,
                result: None,
                min_count: Some(8192),
            }],
        };
        assert!(matches!(
            response_get_device_info(&failed),
            Err(Error::NfsV4 {
                operation: "GETDEVICEINFO",
                status: Status::TooSmall
            })
        ));
    }

    #[test]
    fn response_delegation_operations_return_results_and_status_errors() {
        let stateid = StateId {
            seqid: 9,
            other: [1; 12],
        };
        let dir_delegation = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::GetDirDelegation {
                status: Status::Ok,
                result: Some(GetDirDelegationResult::Unavailable {
                    will_signal_deleg_avail: true,
                }),
            }],
        };
        assert_eq!(
            response_get_dir_delegation(&dir_delegation).unwrap(),
            GetDirDelegationResult::Unavailable {
                will_signal_deleg_avail: true
            }
        );

        let want_delegation = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::WantDelegation {
                status: Status::Ok,
                delegation: Some(OpenDelegation::Read(OpenReadDelegation {
                    stateid,
                    recall: false,
                    permissions: NfsAce {
                        ace_type: 0,
                        flag: 0,
                        access_mask: ACCESS4_READ,
                        who: "OWNER@".to_owned(),
                    },
                })),
            }],
        };
        match response_want_delegation(&want_delegation).unwrap() {
            OpenDelegation::Read(delegation) => assert_eq!(delegation.stateid, stateid),
            delegation => panic!("unexpected delegation: {delegation:?}"),
        }

        let failed = CompoundResponse {
            status: Status::RejectDeleg,
            tag: String::new(),
            results: vec![OperationResult::WantDelegation {
                status: Status::RejectDeleg,
                delegation: None,
            }],
        };
        assert!(matches!(
            response_want_delegation(&failed),
            Err(Error::NfsV4 {
                operation: "WANT_DELEGATION",
                status: Status::RejectDeleg
            })
        ));

        let missing_payload = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::GetDirDelegation {
                status: Status::Ok,
                result: None,
            }],
        };
        assert!(matches!(
            response_get_dir_delegation(&missing_payload),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn response_layout_operations_return_results_and_status_errors() {
        let stateid = StateId {
            seqid: 7,
            other: [8; 12],
        };
        let layout_commit = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::LayoutCommit {
                status: Status::Ok,
                result: Some(LayoutCommitResult {
                    new_size: Some(2048),
                }),
            }],
        };
        assert_eq!(
            response_layout_commit(&layout_commit).unwrap(),
            LayoutCommitResult {
                new_size: Some(2048)
            }
        );

        let layout_get = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::LayoutGet {
                status: Status::Ok,
                result: Some(LayoutGetResult {
                    return_on_close: false,
                    stateid,
                    layouts: vec![Layout {
                        offset: 0,
                        length: 1024,
                        iomode: LayoutIomode::Read,
                        content: LayoutContent {
                            layout_type: LayoutType::NfsV4_1Files,
                            body: b"layout".to_vec(),
                        },
                    }],
                }),
                will_signal_layout_avail: None,
            }],
        };
        let get = response_layout_get(&layout_get).unwrap();
        assert_eq!(get.stateid, stateid);
        assert_eq!(get.layouts.len(), 1);
        assert_eq!(get.layouts[0].content.body, b"layout");

        let layout_return = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::LayoutReturn {
                status: Status::Ok,
                result: Some(LayoutReturnResult {
                    stateid: Some(stateid),
                }),
            }],
        };
        assert_eq!(
            response_layout_return(&layout_return).unwrap(),
            LayoutReturnResult {
                stateid: Some(stateid)
            }
        );

        let try_later = CompoundResponse {
            status: Status::LayoutTryLater,
            tag: String::new(),
            results: vec![OperationResult::LayoutGet {
                status: Status::LayoutTryLater,
                result: None,
                will_signal_layout_avail: Some(true),
            }],
        };
        assert!(matches!(
            response_layout_get(&try_later),
            Err(Error::NfsV4 {
                operation: "LAYOUTGET",
                status: Status::LayoutTryLater
            })
        ));

        let bad_commit = CompoundResponse {
            status: Status::BadLayout,
            tag: String::new(),
            results: vec![OperationResult::LayoutCommit {
                status: Status::BadLayout,
                result: None,
            }],
        };
        assert!(matches!(
            response_layout_commit(&bad_commit),
            Err(Error::NfsV4 {
                operation: "LAYOUTCOMMIT",
                status: Status::BadLayout
            })
        ));
    }

    #[test]
    fn response_verify_reports_boolean_match_statuses() {
        let verified = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::StatusOnly {
                op: OpCode::Verify,
                status: Status::Ok,
            }],
        };
        assert!(response_verify(&verified, OpCode::Verify, Status::NotSame).unwrap());

        let not_same = CompoundResponse {
            status: Status::NotSame,
            tag: String::new(),
            results: vec![OperationResult::StatusOnly {
                op: OpCode::Verify,
                status: Status::NotSame,
            }],
        };
        assert!(!response_verify(&not_same, OpCode::Verify, Status::NotSame).unwrap());

        let same = CompoundResponse {
            status: Status::Same,
            tag: String::new(),
            results: vec![OperationResult::StatusOnly {
                op: OpCode::NVerify,
                status: Status::Same,
            }],
        };
        assert!(!response_verify(&same, OpCode::NVerify, Status::Same).unwrap());

        assert!(matches!(
            response_verify(&verified, OpCode::NVerify, Status::Same),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn response_read_plus_validates_returned_size_and_progress() {
        let oversized = read_plus_response(ReadPlusResult {
            eof: false,
            contents: vec![ReadPlusContent::Data {
                offset: 0,
                data: vec![1, 2, 3, 4, 5],
            }],
        });
        assert!(matches!(
            response_read_plus(&oversized, 4),
            Err(Error::Protocol(_))
        ));

        let oversized_hole = read_plus_response(ReadPlusResult {
            eof: false,
            contents: vec![ReadPlusContent::Hole {
                offset: 0,
                length: 5,
            }],
        });
        assert!(matches!(
            response_read_plus(&oversized_hole, 4),
            Err(Error::Protocol(_))
        ));

        let no_progress = read_plus_response(ReadPlusResult {
            eof: false,
            contents: Vec::new(),
        });
        assert!(matches!(
            response_read_plus(&no_progress, 4),
            Err(Error::Protocol(_))
        ));

        let eof = read_plus_response(ReadPlusResult {
            eof: true,
            contents: Vec::new(),
        });
        assert_eq!(
            response_read_plus(&eof, 4).unwrap(),
            ReadPlusResult {
                eof: true,
                contents: Vec::new(),
            }
        );

        let ok = read_plus_response(ReadPlusResult {
            eof: false,
            contents: vec![
                ReadPlusContent::Data {
                    offset: 0,
                    data: vec![1, 2],
                },
                ReadPlusContent::Hole {
                    offset: 2,
                    length: 2,
                },
            ],
        });
        assert!(response_read_plus(&ok, 4).is_ok());
    }

    #[test]
    fn response_write_validates_returned_count() {
        let no_progress = write_response_with_count(0);
        assert!(matches!(
            response_write(&no_progress, 4),
            Err(Error::Protocol(_))
        ));

        let oversized = write_response_with_count(5);
        assert!(matches!(
            response_write(&oversized, 4),
            Err(Error::Protocol(_))
        ));

        let ok = response_write(&write_response_with_count(4), 4).unwrap();
        assert_eq!(ok.count, 4);
    }

    #[test]
    fn response_write_same_validates_returned_count() {
        let no_progress = write_same_response_with_count(0);
        assert!(matches!(
            response_write_same(&no_progress, 4),
            Err(Error::Protocol(_))
        ));

        let oversized = write_same_response_with_count(5);
        assert!(matches!(
            response_write_same(&oversized, 4),
            Err(Error::Protocol(_))
        ));

        let ok = response_write_same(&write_same_response_with_count(4), 4).unwrap();
        assert_eq!(ok.count, 4);
    }

    #[test]
    fn response_lock_test_reports_conflicts() {
        let granted = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::LockTest {
                status: Status::Ok,
                denied: None,
            }],
        };
        assert_eq!(response_lock_test(&granted).unwrap(), None);

        let denied = LockDenied {
            offset: 8,
            length: 16,
            lock_type: LockType::Write,
            owner: LockOwner {
                client_id: 1,
                owner: b"other-owner".to_vec(),
            },
        };
        let conflict = CompoundResponse {
            status: Status::Denied,
            tag: String::new(),
            results: vec![OperationResult::LockTest {
                status: Status::Denied,
                denied: Some(denied.clone()),
            }],
        };
        assert_eq!(response_lock_test(&conflict).unwrap(), Some(denied));

        let malformed = CompoundResponse {
            status: Status::Denied,
            tag: String::new(),
            results: vec![OperationResult::LockTest {
                status: Status::Denied,
                denied: None,
            }],
        };
        assert!(matches!(
            response_lock_test(&malformed),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn response_lock_requires_stateid_on_success() {
        let stateid = StateId {
            seqid: 1,
            other: [7; 12],
        };
        let granted = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::Lock {
                status: Status::Ok,
                stateid: Some(stateid),
                denied: None,
            }],
        };
        assert_eq!(response_lock(&granted).unwrap(), stateid);

        let malformed = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::Lock {
                status: Status::Ok,
                stateid: None,
                denied: None,
            }],
        };
        assert!(matches!(response_lock(&malformed), Err(Error::Protocol(_))));
    }

    #[test]
    fn response_lock_unlock_requires_stateid_on_success() {
        let stateid = StateId {
            seqid: 2,
            other: [8; 12],
        };
        let unlocked = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::LockUnlock {
                status: Status::Ok,
                stateid: Some(stateid),
            }],
        };
        assert_eq!(response_lock_unlock(&unlocked).unwrap(), stateid);

        let malformed = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::LockUnlock {
                status: Status::Ok,
                stateid: None,
            }],
        };
        assert!(matches!(
            response_lock_unlock(&malformed),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn response_test_stateids_validates_status_count() {
        let response = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::TestStateIds {
                status: Status::Ok,
                statuses: vec![Status::Ok, Status::BadStateId],
            }],
        };
        assert_eq!(
            response_test_stateids(&response, 2).unwrap(),
            vec![Status::Ok, Status::BadStateId]
        );
        assert!(matches!(
            response_test_stateids(&response, 1),
            Err(Error::Protocol(_))
        ));

        let failed = CompoundResponse {
            status: Status::BadStateId,
            tag: String::new(),
            results: vec![OperationResult::TestStateIds {
                status: Status::BadStateId,
                statuses: Vec::new(),
            }],
        };
        assert!(matches!(
            response_test_stateids(&failed, 1),
            Err(Error::NfsV4 { operation, .. }) if operation == "TEST_STATEID"
        ));
    }

    #[test]
    fn response_release_lock_owner_reports_locks_held() {
        let released = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::StatusOnly {
                op: OpCode::ReleaseLockOwner,
                status: Status::Ok,
            }],
        };
        assert!(response_release_lock_owner(&released).unwrap());

        let locks_held = CompoundResponse {
            status: Status::LocksHeld,
            tag: String::new(),
            results: vec![OperationResult::StatusOnly {
                op: OpCode::ReleaseLockOwner,
                status: Status::LocksHeld,
            }],
        };
        assert!(!response_release_lock_owner(&locks_held).unwrap());

        let failed = CompoundResponse {
            status: Status::BadOwner,
            tag: String::new(),
            results: vec![OperationResult::StatusOnly {
                op: OpCode::ReleaseLockOwner,
                status: Status::BadOwner,
            }],
        };
        assert!(matches!(
            response_release_lock_owner(&failed),
            Err(Error::NfsV4 { operation, .. }) if operation == "RELEASE_LOCKOWNER"
        ));
    }

    #[test]
    fn response_copy_validates_count_and_async_progress() {
        let ok = response_copy(&copy_response(Some(copy_write_response(4, None))), 4).unwrap();
        assert_eq!(ok.response.unwrap().count, 4);

        let async_started = response_copy(
            &copy_response(Some(copy_write_response(
                0,
                Some(StateId {
                    seqid: 9,
                    other: [10; 12],
                }),
            ))),
            4,
        )
        .unwrap();
        assert!(async_started.response.unwrap().callback_id.is_some());

        assert!(matches!(
            response_copy(&copy_response(Some(copy_write_response(5, None))), 4),
            Err(Error::Protocol(_))
        ));
        assert!(matches!(
            response_copy(&copy_response(Some(copy_write_response(0, None))), 4),
            Err(Error::Protocol(_))
        ));
        assert!(matches!(
            response_copy(&copy_response(None), 4),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn response_copy_notify_returns_result_and_status_errors() {
        let stateid = StateId {
            seqid: 12,
            other: [13; 12],
        };
        let ok = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::CopyNotify {
                status: Status::Ok,
                result: Some(CopyNotifyResult {
                    lease_time: NfsTime {
                        seconds: 10,
                        nseconds: 11,
                    },
                    stateid,
                    source_servers: vec![NetLoc::Url("nfs://source/export".to_owned())],
                }),
            }],
        };
        let result = response_copy_notify(&ok).unwrap();
        assert_eq!(result.stateid, stateid);
        assert_eq!(
            result.source_servers,
            vec![NetLoc::Url("nfs://source/export".to_owned())]
        );

        let failed = CompoundResponse {
            status: Status::OffloadDenied,
            tag: String::new(),
            results: vec![OperationResult::CopyNotify {
                status: Status::OffloadDenied,
                result: None,
            }],
        };
        assert!(matches!(
            response_copy_notify(&failed),
            Err(Error::NfsV4 {
                operation: "COPY_NOTIFY",
                status: Status::OffloadDenied
            })
        ));

        let missing_payload = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::CopyNotify {
                status: Status::Ok,
                result: None,
            }],
        };
        assert!(matches!(
            response_copy_notify(&missing_payload),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn response_offload_status_requires_result_on_success() {
        let status = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::OffloadStatus {
                status: Status::Ok,
                result: Some(OffloadStatusResult {
                    count: 8,
                    complete: Some(Status::Ok),
                }),
            }],
        };
        assert_eq!(
            response_offload_status(&status).unwrap(),
            OffloadStatusResult {
                count: 8,
                complete: Some(Status::Ok),
            }
        );

        let malformed = CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::OffloadStatus {
                status: Status::Ok,
                result: None,
            }],
        };
        assert!(matches!(
            response_offload_status(&malformed),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn validate_stateid_batch_len_rejects_oversized_batches() {
        assert!(validate_stateid_batch_len(NFS4_MAX_OPS).is_ok());
        assert!(matches!(
            validate_stateid_batch_len(NFS4_MAX_OPS + 1),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn app_data_block_len_validates_count() {
        let block = AppDataBlock {
            offset: 0,
            block_size: 4,
            block_count: 3,
            block_number_offset: 0,
            block_number: 0,
            pattern_offset: 0,
            pattern: vec![0; 4],
        };
        assert_eq!(app_data_block_len(&block).unwrap(), 12);

        let zero_size = AppDataBlock {
            block_size: 0,
            block_count: 1,
            ..block.clone()
        };
        assert!(matches!(
            app_data_block_len(&zero_size),
            Err(Error::Protocol(_))
        ));

        let overflow = AppDataBlock {
            block_size: u64::MAX,
            block_count: 2,
            ..block
        };
        assert!(matches!(
            app_data_block_len(&overflow),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn advance_offset_rejects_overflow() {
        let mut offset = u64::MAX;
        assert!(matches!(
            advance_offset(&mut offset, 1, "NFSv4 READ"),
            Err(Error::Protocol(_))
        ));
        assert_eq!(offset, u64::MAX);
    }

    fn read_plus_response(result: ReadPlusResult) -> CompoundResponse {
        CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::ReadPlus {
                status: Status::Ok,
                result: Some(result),
            }],
        }
    }

    fn write_response_with_count(count: u32) -> CompoundResponse {
        CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::Write {
                status: Status::Ok,
                result: Some(WriteResult {
                    count,
                    committed: StableHow::FileSync,
                    verifier: [0; NFS4_VERIFIER_SIZE],
                }),
            }],
        }
    }

    fn write_same_response_with_count(count: u64) -> CompoundResponse {
        CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::WriteSame {
                status: Status::Ok,
                result: Some(WriteResponse {
                    callback_id: None,
                    count,
                    committed: StableHow::FileSync,
                    verifier: [0; NFS4_VERIFIER_SIZE],
                }),
            }],
        }
    }

    fn copy_response(response: Option<WriteResponse>) -> CompoundResponse {
        CompoundResponse {
            status: Status::Ok,
            tag: String::new(),
            results: vec![OperationResult::Copy {
                status: Status::Ok,
                result: Some(CopyResult {
                    response,
                    requirements: Some(CopyRequirements {
                        consecutive: false,
                        synchronous: true,
                    }),
                }),
            }],
        }
    }

    fn copy_write_response(count: u64, callback_id: Option<StateId>) -> WriteResponse {
        WriteResponse {
            callback_id,
            count,
            committed: StableHow::FileSync,
            verifier: [0; NFS4_VERIFIER_SIZE],
        }
    }

    fn sequence_ok_result() -> OperationResult {
        OperationResult::Sequence {
            status: Status::Ok,
            result: Some(SequenceResult {
                session_id: [1; NFS4_SESSIONID_SIZE],
                sequence_id: 1,
                slot_id: 0,
                highest_slot_id: 0,
                target_highest_slot_id: 0,
                status_flags: 0,
            }),
        }
    }

    fn open_args(name: &str) -> OpenArgs {
        OpenArgs {
            seqid: 1,
            share_access: OPEN4_SHARE_ACCESS_READ,
            share_deny: OPEN4_SHARE_DENY_NONE,
            owner: OpenOwner {
                client_id: 1,
                owner: b"owner".to_vec(),
            },
            openhow: OpenHow::NoCreate,
            claim: OpenClaim::Null(name.to_owned()),
        }
    }
}
