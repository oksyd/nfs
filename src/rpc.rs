#![cfg_attr(not(feature = "blocking"), allow(dead_code))]

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};
use crate::xdr::{Decoder, Encode, Encoder};

pub const RPC_VERSION: u32 = 2;
pub const AUTH_NONE: u32 = 0;
pub const AUTH_SYS: u32 = 1;
/// Maximum UTF-8 byte length of an AUTH_SYS machine name.
pub const AUTH_SYS_MACHINE_NAME_MAX: usize = 255;
/// Maximum number of auxiliary groups carried by AUTH_SYS credentials.
pub const AUTH_SYS_MAX_GROUPS: usize = 16;

const MSG_CALL: u32 = 0;
const MSG_REPLY: u32 = 1;
const REPLY_ACCEPTED: u32 = 0;
const REPLY_DENIED: u32 = 1;
const ACCEPT_SUCCESS: u32 = 0;
const ACCEPT_PROG_MISMATCH: u32 = 2;
const REJECT_RPC_MISMATCH: u32 = 0;
const REJECT_AUTH_ERROR: u32 = 1;
pub(crate) const LAST_FRAGMENT: u32 = 0x8000_0000;
pub(crate) const FRAGMENT_LEN_MASK: u32 = 0x7fff_ffff;
pub(crate) const DEFAULT_MAX_RECORD_SIZE: usize = 64 * 1024 * 1024;
const MAX_RECORD_HEADROOM: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    None,
    Sys(AuthSys),
}

impl Auth {
    pub fn none() -> Self {
        Self::None
    }

    pub fn sys(auth: AuthSys) -> Self {
        Self::Sys(auth)
    }

    pub(crate) fn encode_opaque_auth(&self, encoder: &mut Encoder) -> Result<()> {
        match self {
            Self::None => {
                encoder.write_u32(AUTH_NONE);
                encoder.write_opaque(&[], 400)?;
            }
            Self::Sys(auth) => {
                let body = crate::xdr::to_bytes(auth)?;
                encoder.write_u32(AUTH_SYS);
                encoder.write_opaque(&body, 400)?;
            }
        }
        Ok(())
    }
}

/// AUTH_SYS credential used for ONC RPC calls.
///
/// AUTH_SYS carries a machine name, uid, primary gid, and supplementary gids.
/// It is the default authentication flavor for the high-level clients. It is
/// not cryptographically secure; deployments that require Kerberos/RPCSEC_GSS
/// need support outside the current high-level API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSys {
    /// Credential stamp used by the RPC request.
    pub stamp: u32,
    /// Caller machine name.
    pub machine_name: String,
    /// Caller uid.
    pub uid: u32,
    /// Caller primary gid.
    pub gid: u32,
    /// Caller supplementary gids.
    pub gids: Vec<u32>,
}

impl AuthSys {
    /// Builds an AUTH_SYS credential from explicit identity fields.
    ///
    /// Credential fields are normalized to AUTH_SYS wire limits. The machine
    /// name is truncated at a UTF-8 boundary to [`AUTH_SYS_MACHINE_NAME_MAX`]
    /// bytes. Supplementary groups have the primary gid removed, duplicates
    /// removed, and at most [`AUTH_SYS_MAX_GROUPS`] groups retained.
    pub fn new(machine_name: impl Into<String>, uid: u32, gid: u32, gids: Vec<u32>) -> Self {
        Self {
            stamp: default_stamp(),
            machine_name: normalize_machine_name(machine_name.into()),
            uid,
            gid,
            gids: normalize_auxiliary_gids(gid, gids),
        }
    }

    /// Builds an AUTH_SYS credential from the current process identity.
    ///
    /// On Unix this reads the current uid, primary gid, and supplementary
    /// groups. On unsupported platforms the platform shims provide the best
    /// available values.
    pub fn current() -> Self {
        let machine_name = std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_owned());
        let gid = current_gid();
        Self::new(
            machine_name,
            current_uid(),
            gid,
            current_auxiliary_gids(gid),
        )
    }
}

impl Default for AuthSys {
    fn default() -> Self {
        Self::current()
    }
}

impl Encode for AuthSys {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        let gids = normalize_auxiliary_gids(self.gid, self.gids.iter().copied());
        encoder.write_u32(self.stamp);
        encoder.write_string(
            normalized_machine_name_ref(&self.machine_name),
            AUTH_SYS_MACHINE_NAME_MAX,
        )?;
        encoder.write_u32(self.uid);
        encoder.write_u32(self.gid);
        encoder.write_array(&gids, AUTH_SYS_MAX_GROUPS)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct RpcClient {
    stream: TcpStream,
    xid: u32,
    auth: Auth,
    max_record_size: usize,
}

impl RpcClient {
    pub fn connect_with_timeout<A: ToSocketAddrs>(
        addr: A,
        auth: Auth,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        let stream = connect_tcp_stream(addr, timeout)?;
        let client = Self::new(stream, auth)?;
        client.set_timeout(timeout)?;
        Ok(client)
    }

    pub fn new(stream: TcpStream, auth: Auth) -> Result<Self> {
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            xid: default_stamp(),
            auth,
            max_record_size: DEFAULT_MAX_RECORD_SIZE,
        })
    }

    pub fn set_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.stream.set_read_timeout(timeout)?;
        self.stream.set_write_timeout(timeout)?;
        Ok(())
    }

    pub fn set_max_record_size(&mut self, max_record_size: usize) -> Result<()> {
        validate_max_record_size(max_record_size)?;
        self.max_record_size = max_record_size;
        Ok(())
    }

    pub fn call<T: Encode + ?Sized>(
        &mut self,
        program: u32,
        version: u32,
        procedure: u32,
        args: &T,
    ) -> Result<Vec<u8>> {
        let xid = self.next_xid();
        let request = encode_call(xid, program, version, procedure, &self.auth, args)?;
        self.write_record(&request)?;
        let reply = self.read_record()?;
        decode_reply(xid, &reply)
    }

    fn next_xid(&mut self) -> u32 {
        self.xid = self.xid.wrapping_add(1);
        if self.xid == 0 {
            self.xid = 1;
        }
        self.xid
    }

    fn write_record(&mut self, payload: &[u8]) -> Result<()> {
        if payload.len() > FRAGMENT_LEN_MASK as usize {
            return Err(Error::RpcRecordTooLarge {
                len: payload.len(),
                max: FRAGMENT_LEN_MASK as usize,
            });
        }

        let len = u32::try_from(payload.len()).map_err(|_| Error::RpcRecordTooLarge {
            len: payload.len(),
            max: FRAGMENT_LEN_MASK as usize,
        })?;
        let header = LAST_FRAGMENT | len;
        self.stream.write_all(&header.to_be_bytes())?;
        self.stream.write_all(payload)?;
        self.stream.flush()?;
        Ok(())
    }

    fn read_record(&mut self) -> Result<Vec<u8>> {
        let mut record = Vec::new();
        loop {
            let mut header_bytes = [0; 4];
            self.stream.read_exact(&mut header_bytes)?;
            let header = u32::from_be_bytes(header_bytes);
            let is_last = (header & LAST_FRAGMENT) != 0;
            let fragment_len = (header & FRAGMENT_LEN_MASK) as usize;
            if fragment_len == 0 && !is_last {
                return Err(Error::Protocol(
                    "RPC record contained zero-length non-final fragment".to_owned(),
                ));
            }

            let next_len =
                record
                    .len()
                    .checked_add(fragment_len)
                    .ok_or(Error::RpcRecordTooLarge {
                        len: usize::MAX,
                        max: self.max_record_size,
                    })?;
            if next_len > self.max_record_size {
                return Err(Error::RpcRecordTooLarge {
                    len: next_len,
                    max: self.max_record_size,
                });
            }

            let start = record.len();
            record.resize(next_len, 0);
            self.stream.read_exact(&mut record[start..])?;

            if is_last {
                return Ok(record);
            }
        }
    }
}

fn connect_tcp_stream<A: ToSocketAddrs>(addr: A, timeout: Option<Duration>) -> Result<TcpStream> {
    let Some(timeout) = timeout else {
        return Ok(TcpStream::connect(addr)?);
    };

    let mut last_error = None;
    for socket_addr in addr.to_socket_addrs()? {
        match TcpStream::connect_timeout(&socket_addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(err) => last_error = Some(err),
        }
    }

    Err(last_error
        .unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "no socket address resolved")
        })
        .into())
}

pub(crate) fn encode_call<T: Encode + ?Sized>(
    xid: u32,
    program: u32,
    version: u32,
    procedure: u32,
    auth: &Auth,
    args: &T,
) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new();
    encoder.write_u32(xid);
    encoder.write_u32(MSG_CALL);
    encoder.write_u32(RPC_VERSION);
    encoder.write_u32(program);
    encoder.write_u32(version);
    encoder.write_u32(procedure);
    auth.encode_opaque_auth(&mut encoder)?;
    Auth::None.encode_opaque_auth(&mut encoder)?;
    args.encode(&mut encoder)?;
    Ok(encoder.into_bytes())
}

pub(crate) fn decode_reply(expected_xid: u32, reply: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = Decoder::new(reply);
    let actual_xid = decoder.read_u32()?;
    if actual_xid != expected_xid {
        return Err(Error::RpcMismatch {
            expected: expected_xid,
            actual: actual_xid,
        });
    }

    let message_type = decoder.read_u32()?;
    if message_type != MSG_REPLY {
        return Err(Error::RpcUnexpectedMessageType(message_type));
    }

    match decoder.read_u32()? {
        REPLY_ACCEPTED => decode_accepted_reply(&mut decoder),
        REPLY_DENIED => decode_denied_reply(&mut decoder),
        value => {
            ensure_rpc_reply_consumed(&decoder)?;
            Err(Error::RpcDenied {
                reject_stat: value,
                detail: 0,
            })
        }
    }
}

fn decode_accepted_reply(decoder: &mut Decoder<'_>) -> Result<Vec<u8>> {
    read_opaque_auth(decoder)?;
    match decoder.read_u32()? {
        ACCEPT_SUCCESS => {
            let remaining = decoder.remaining();
            let payload = decoder.read_fixed_opaque_unpadded(remaining)?;
            Ok(payload.to_vec())
        }
        ACCEPT_PROG_MISMATCH => {
            let low = decoder.read_u32()?;
            let high = decoder.read_u32()?;
            ensure_rpc_reply_consumed(decoder)?;
            Err(Error::RpcProgramMismatch { low, high })
        }
        accept_stat => {
            ensure_rpc_reply_consumed(decoder)?;
            Err(Error::RpcAcceptedError { accept_stat })
        }
    }
}

fn decode_denied_reply(decoder: &mut Decoder<'_>) -> Result<Vec<u8>> {
    match decoder.read_u32()? {
        REJECT_RPC_MISMATCH => {
            let low = decoder.read_u32()?;
            let high = decoder.read_u32()?;
            ensure_rpc_reply_consumed(decoder)?;
            Err(Error::RpcProgramMismatch { low, high })
        }
        REJECT_AUTH_ERROR => {
            let auth_stat = decoder.read_u32()?;
            ensure_rpc_reply_consumed(decoder)?;
            Err(Error::RpcDenied {
                reject_stat: REJECT_AUTH_ERROR,
                detail: auth_stat,
            })
        }
        reject_stat => {
            ensure_rpc_reply_consumed(decoder)?;
            Err(Error::RpcDenied {
                reject_stat,
                detail: 0,
            })
        }
    }
}

fn ensure_rpc_reply_consumed(decoder: &Decoder<'_>) -> Result<()> {
    if decoder.is_finished() {
        Ok(())
    } else {
        Err(crate::xdr::Error::TrailingBytes {
            remaining: decoder.remaining(),
        }
        .into())
    }
}

pub(crate) fn read_opaque_auth(decoder: &mut Decoder<'_>) -> Result<(u32, Vec<u8>)> {
    let flavor = decoder.read_u32()?;
    let body = decoder.read_opaque(400)?.to_vec();
    Ok((flavor, body))
}

pub(crate) fn max_record_size_for_payloads(payload_sizes: &[u32]) -> usize {
    let configured = payload_sizes
        .iter()
        .map(|size| *size as usize)
        .max()
        .unwrap_or(0)
        .saturating_add(MAX_RECORD_HEADROOM);
    configured.max(DEFAULT_MAX_RECORD_SIZE)
}

pub(crate) fn validate_max_record_size(max_record_size: usize) -> Result<()> {
    if max_record_size == 0 {
        return Err(Error::Protocol(
            "RPC max_record_size must be greater than zero".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn default_stamp() -> u32 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (duration.as_secs() as u32) ^ duration.subsec_nanos()
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    unsafe { libc::geteuid() as u32 }
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

#[cfg(unix)]
fn current_gid() -> u32 {
    // SAFETY: getegid has no preconditions and does not dereference pointers.
    unsafe { libc::getegid() as u32 }
}

#[cfg(not(unix))]
fn current_gid() -> u32 {
    0
}

#[cfg(unix)]
fn current_auxiliary_gids(primary_gid: u32) -> Vec<u32> {
    // SAFETY: getgroups is called with size 0 and a null pointer to query the
    // required group count, as specified by POSIX.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count <= 0 {
        return Vec::new();
    }

    let mut groups = vec![0 as libc::gid_t; count as usize];
    // SAFETY: groups has capacity for `count` gid_t values and the pointer is
    // valid for writes of that length.
    let count = unsafe { libc::getgroups(groups.len() as libc::c_int, groups.as_mut_ptr()) };
    if count <= 0 {
        return Vec::new();
    }

    groups.truncate(count as usize);
    normalize_auxiliary_gids(primary_gid, groups)
}

#[cfg(not(unix))]
fn current_auxiliary_gids(_primary_gid: u32) -> Vec<u32> {
    Vec::new()
}

fn normalize_auxiliary_gids(primary_gid: u32, groups: impl IntoIterator<Item = u32>) -> Vec<u32> {
    let mut normalized = Vec::new();
    for gid in groups {
        if gid == primary_gid || normalized.contains(&gid) {
            continue;
        }
        normalized.push(gid);
        if normalized.len() == AUTH_SYS_MAX_GROUPS {
            break;
        }
    }
    normalized
}

fn normalize_machine_name(mut machine_name: String) -> String {
    let len = normalized_machine_name_len(&machine_name);
    machine_name.truncate(len);
    machine_name
}

fn normalized_machine_name_ref(machine_name: &str) -> &str {
    &machine_name[..normalized_machine_name_len(machine_name)]
}

fn normalized_machine_name_len(machine_name: &str) -> usize {
    if machine_name.len() <= AUTH_SYS_MACHINE_NAME_MAX {
        return machine_name.len();
    }

    let mut len = AUTH_SYS_MACHINE_NAME_MAX;
    while !machine_name.is_char_boundary(len) {
        len -= 1;
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn record_limit_keeps_default_for_small_payloads() {
        assert_eq!(
            max_record_size_for_payloads(&[128 * 1024]),
            DEFAULT_MAX_RECORD_SIZE
        );
    }

    #[test]
    fn record_limit_adds_headroom_for_large_payloads() {
        assert_eq!(
            max_record_size_for_payloads(&[DEFAULT_MAX_RECORD_SIZE as u32]),
            DEFAULT_MAX_RECORD_SIZE + MAX_RECORD_HEADROOM
        );
    }

    #[test]
    fn rejects_zero_max_record_size() {
        assert!(matches!(
            validate_max_record_size(0),
            Err(Error::Protocol(_))
        ));
        assert!(validate_max_record_size(1).is_ok());
    }

    #[test]
    fn connects_with_configured_timeout() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = std::thread::spawn(move || {
            let _ = listener.accept();
        });

        let client =
            RpcClient::connect_with_timeout(addr, Auth::none(), Some(Duration::from_secs(1)))
                .unwrap();
        drop(client);
        accept.join().unwrap();
    }

    #[test]
    fn rejects_zero_length_nonfinal_record_fragments() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(&0_u32.to_be_bytes()).unwrap();
        });

        let stream = TcpStream::connect(addr).unwrap();
        let mut client = RpcClient::new(stream, Auth::none()).unwrap();
        let err = client.read_record().unwrap_err();
        assert!(matches!(
            err,
            Error::Protocol(message) if message.contains("zero-length non-final")
        ));
        accept.join().unwrap();
    }

    #[test]
    fn accepted_error_reply_rejects_trailing_bytes() {
        let mut reply = rpc_reply_prefix(7, REPLY_ACCEPTED);
        Auth::None.encode_opaque_auth(&mut reply).unwrap();
        reply.write_u32(ACCEPT_PROG_MISMATCH);
        reply.write_u32(1);
        reply.write_u32(3);
        reply.write_u32(0);

        assert!(matches!(
            decode_reply(7, reply.as_slice()).unwrap_err(),
            Error::Xdr(crate::xdr::Error::TrailingBytes { remaining: 4 })
        ));
    }

    #[test]
    fn denied_reply_rejects_trailing_bytes() {
        let mut reply = rpc_reply_prefix(7, REPLY_DENIED);
        reply.write_u32(REJECT_AUTH_ERROR);
        reply.write_u32(1);
        reply.write_u32(0);

        assert!(matches!(
            decode_reply(7, reply.as_slice()).unwrap_err(),
            Error::Xdr(crate::xdr::Error::TrailingBytes { remaining: 4 })
        ));
    }

    #[test]
    fn unknown_reply_stat_rejects_trailing_bytes() {
        let mut reply = rpc_reply_prefix(7, 99);
        reply.write_u32(0);

        assert!(matches!(
            decode_reply(7, reply.as_slice()).unwrap_err(),
            Error::Xdr(crate::xdr::Error::TrailingBytes { remaining: 4 })
        ));
    }

    #[test]
    fn normalizes_auxiliary_groups_for_auth_sys() {
        let groups = normalize_auxiliary_gids(
            10,
            [
                10, 1, 2, 1, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18,
            ],
        );

        assert_eq!(
            groups,
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17]
        );
        assert_eq!(groups.len(), AUTH_SYS_MAX_GROUPS);
        assert!(!groups.contains(&10));
    }

    #[test]
    fn current_auth_sys_has_bounded_auxiliary_groups() {
        let auth = AuthSys::current();
        assert!(auth.gids.len() <= AUTH_SYS_MAX_GROUPS);
        assert!(!auth.gids.contains(&auth.gid));
    }

    #[test]
    fn auth_sys_new_normalizes_machine_name() {
        let auth = AuthSys::new(
            "a".repeat(AUTH_SYS_MACHINE_NAME_MAX + 1),
            20,
            10,
            Vec::new(),
        );

        assert_eq!(auth.machine_name.len(), AUTH_SYS_MACHINE_NAME_MAX);
        assert!(auth.machine_name.bytes().all(|byte| byte == b'a'));
    }

    #[test]
    fn auth_sys_new_truncates_machine_name_at_utf8_boundary() {
        let mut machine_name = "a".repeat(AUTH_SYS_MACHINE_NAME_MAX - 1);
        machine_name.push('é');
        let auth = AuthSys::new(machine_name, 20, 10, Vec::new());

        assert_eq!(auth.machine_name.len(), AUTH_SYS_MACHINE_NAME_MAX - 1);
        assert!(auth.machine_name.ends_with('a'));
    }

    #[test]
    fn auth_sys_new_normalizes_auxiliary_groups() {
        let auth = AuthSys::new(
            "host",
            20,
            10,
            vec![10, 1, 2, 1, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17],
        );

        assert_eq!(
            auth.gids,
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17]
        );
        assert_eq!(auth.gids.len(), AUTH_SYS_MAX_GROUPS);
        assert!(!auth.gids.contains(&auth.gid));
    }

    #[test]
    fn auth_sys_encode_normalizes_public_group_field() {
        let auth = AuthSys {
            stamp: 1,
            machine_name: "host".to_owned(),
            uid: 20,
            gid: 10,
            gids: vec![10, 1, 2, 1, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17],
        };

        let bytes = crate::xdr::to_bytes(&auth).unwrap();
        let mut decoder = Decoder::new(&bytes);
        assert_eq!(decoder.read_u32().unwrap(), 1);
        assert_eq!(decoder.read_string(255).unwrap(), "host");
        assert_eq!(decoder.read_u32().unwrap(), 20);
        assert_eq!(decoder.read_u32().unwrap(), 10);
        assert_eq!(
            decoder.read_array::<u32>(AUTH_SYS_MAX_GROUPS).unwrap(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17]
        );
        decoder.finish().unwrap();
    }

    #[test]
    fn auth_sys_encode_normalizes_public_machine_name_field() {
        let auth = AuthSys {
            stamp: 1,
            machine_name: "a".repeat(AUTH_SYS_MACHINE_NAME_MAX + 1),
            uid: 20,
            gid: 10,
            gids: Vec::new(),
        };

        let bytes = crate::xdr::to_bytes(&auth).unwrap();
        let mut decoder = Decoder::new(&bytes);
        assert_eq!(decoder.read_u32().unwrap(), 1);
        assert_eq!(
            decoder.read_string(AUTH_SYS_MACHINE_NAME_MAX).unwrap(),
            "a".repeat(AUTH_SYS_MACHINE_NAME_MAX)
        );
        assert_eq!(decoder.read_u32().unwrap(), 20);
        assert_eq!(decoder.read_u32().unwrap(), 10);
        assert!(
            decoder
                .read_array::<u32>(AUTH_SYS_MAX_GROUPS)
                .unwrap()
                .is_empty()
        );
        decoder.finish().unwrap();
    }

    fn rpc_reply_prefix(xid: u32, reply_stat: u32) -> Encoder {
        let mut encoder = Encoder::new();
        encoder.write_u32(xid);
        encoder.write_u32(MSG_REPLY);
        encoder.write_u32(reply_stat);
        encoder
    }
}
