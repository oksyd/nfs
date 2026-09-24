//! Scripted RPC peers exercise recovery without requiring a running NFS server.
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::client::LockState;
use super::proto::*;
use crate::xdr::{Decode, Decoder, Encode, Encoder, to_bytes};

pub(super) struct Server {
    pub addr: SocketAddr,
    thread: JoinHandle<()>,
}

impl Server {
    pub fn start(connections: Vec<Vec<Step>>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let thread = thread::spawn(move || {
            let mut workers = Vec::new();
            for script in connections {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                let stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "expected recovery connection"
                            );
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(err) => panic!("accept: {err}"),
                    }
                };
                workers.push(thread::spawn(move || serve(stream, script)));
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        Self { addr, thread }
    }

    pub fn finish(self) {
        self.thread.join().unwrap();
    }
}

pub(super) struct Step {
    operations: Vec<Operation>,
    client_id: u64,
    error: Option<Status>,
    disconnect: bool,
    session_id: Option<u8>,
    sequence_flags: u32,
    test_statuses: Option<Vec<Status>>,
    observed: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl Step {
    pub fn ok(operations: Vec<Operation>) -> Self {
        Self {
            operations,
            client_id: 1,
            error: None,
            disconnect: false,
            session_id: None,
            sequence_flags: 0,
            test_statuses: None,
            observed: None,
        }
    }

    pub fn fail(operations: Vec<Operation>, error: Status) -> Self {
        Self {
            error: Some(error),
            ..Self::ok(operations)
        }
    }

    pub fn disconnect(operations: Vec<Operation>) -> Self {
        Self {
            disconnect: true,
            ..Self::ok(operations)
        }
    }
}

fn serve(mut stream: TcpStream, script: Vec<Step>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    for step in script {
        let mut header = [0; 4];
        stream.read_exact(&mut header).unwrap();
        let len = u32::from_be_bytes(header);
        assert_ne!(len & 0x8000_0000, 0);
        let mut record = vec![0; (len & 0x7fff_ffff) as usize];
        stream.read_exact(&mut record).unwrap();
        let mut d = Decoder::new(&record);
        let xid = d.read_u32().unwrap();
        for value in [0, 2, NFS4_PROGRAM, NFS4_VERSION, 1] {
            assert_eq!(d.read_u32().unwrap(), value);
        }
        for _ in 0..2 {
            d.read_u32().unwrap();
            d.read_opaque(400).unwrap();
        }
        let start = d.position();
        let tag = d.read_string(1024).unwrap();
        let expected = CompoundArgs {
            tag: tag.clone(),
            minor_version: 2,
            operations: step.operations.clone(),
        };
        assert_eq!(
            &record[start..],
            to_bytes(&expected).unwrap(),
            "unexpected recovery RPC: {tag}"
        );
        if step.disconnect {
            return;
        }
        let mut e = Encoder::new();
        for value in [xid, 1, 0, 0, 0, 0] {
            e.write_u32(value);
        }
        e.write_u32(step.error.unwrap_or(Status::Ok).as_u32());
        e.write_string(&tag, 1024).unwrap();
        e.write_u32(step.operations.len() as u32);
        for (i, op) in step.operations.iter().enumerate() {
            e.write_u32(op.op_code().as_u32());
            let status = if i + 1 == step.operations.len() {
                step.error.unwrap_or(Status::Ok)
            } else {
                Status::Ok
            };
            e.write_u32(status.as_u32());
            if status.is_ok() {
                reply_body(
                    &mut e,
                    op,
                    step.client_id,
                    step.session_id,
                    step.sequence_flags,
                    step.test_statuses.as_deref(),
                );
            }
        }
        let bytes = e.into_bytes();
        stream
            .write_all(&(0x8000_0000 | bytes.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(&bytes).unwrap();
        if let Some(observed) = step.observed {
            observed.store(true, std::sync::atomic::Ordering::Release);
        }
    }
    assert_eq!(
        stream.read(&mut [0; 1]).unwrap(),
        0,
        "unexpected extra RPC after the scripted exchange"
    );
}

fn reply_body(
    e: &mut Encoder,
    op: &Operation,
    client_id: u64,
    session_id: Option<u8>,
    sequence_flags: u32,
    test_statuses: Option<&[Status]>,
) {
    match op {
        Operation::ExchangeId(_) => {
            e.write_u64(client_id);
            e.write_u32(1);
            e.write_u32(0);
            e.write_u32(0); // SP4_NONE
            e.write_u64(0); // server owner minor id
            e.write_opaque(b"server", 1024).unwrap();
            e.write_opaque(b"scope", 1024).unwrap();
            e.write_u32(0); // implementation ids
        }
        Operation::CreateSession(args) => {
            e.write_fixed_opaque(&[session_id.unwrap_or(args.client_id as u8); 16]);
            e.write_u32(1);
            e.write_u32(0);
            ChannelAttrs::fore_channel_default().encode(e).unwrap();
            ChannelAttrs::back_channel_disabled().encode(e).unwrap();
        }
        Operation::Sequence(args) => {
            e.write_fixed_opaque(&args.session_id);
            for value in [args.sequence_id, 0, 0, 0, sequence_flags] {
                e.write_u32(value);
            }
        }
        Operation::Open(_) => {
            stateid(11).encode(e).unwrap();
            e.write_bool(false);
            e.write_u64(0);
            e.write_u64(0);
            e.write_u32(0);
            e.write_u32(0);
            e.write_u32(0);
        }
        Operation::Lock(_) | Operation::LockUnlock(_) => stateid(22).encode(e).unwrap(),
        Operation::Close { stateid, .. } => stateid.encode(e).unwrap(),
        Operation::TestStateIds(ids) => {
            e.write_u32(ids.len() as u32);
            for i in 0..ids.len() {
                e.write_u32(
                    test_statuses
                        .map_or(Status::Ok, |statuses| statuses[i])
                        .as_u32(),
                );
            }
        }
        _ => {}
    }
}

pub(super) fn stateid(byte: u8) -> StateId {
    let wire = [byte; 16];
    StateId::decode(&mut Decoder::new(&wire)).unwrap()
}

pub(super) fn lock_state() -> LockState {
    LockState {
        client_id: 1,
        handle: FileHandle::new(vec![3]).unwrap(),
        open_stateid: stateid(4),
        lock_stateid: stateid(5),
        lock_seqid: 2,
        lock_type: LockType::Write,
        offset: 10,
        length: 20,
        owner: b"lock-owner".to_vec(),
        open_owner: b"open-owner".to_vec(),
        lost: None,
    }
}

pub(super) fn sequence(client: u8, seq: u32, ops: Vec<Operation>) -> Vec<Operation> {
    let mut result = vec![Operation::Sequence(SequenceArgs {
        session_id: [client; 16],
        sequence_id: seq,
        slot_id: 0,
        highest_slot_id: 0,
        cache_this: false,
    })];
    result.extend(ops);
    result
}

pub(super) fn handshake(client_id: u64, complete: bool) -> Vec<Step> {
    handshake_on(client_id, client_id as u8, complete)
}

fn handshake_on(client_id: u64, session: u8, complete: bool) -> Vec<Step> {
    let mut exchange = Step::ok(vec![Operation::ExchangeId(ExchangeIdArgs {
        client_owner: ClientOwner {
            verifier: [0; 8],
            owner_id: b"client".to_vec(),
        },
        flags: EXCHGID4_FLAG_USE_NON_PNFS,
    })]);
    exchange.client_id = client_id;
    let mut steps = vec![
        exchange,
        Step::ok(vec![Operation::CreateSession(CreateSessionArgs {
            client_id,
            sequence_id: 1,
            flags: 0,
            fore_channel_attrs: ChannelAttrs::fore_channel_default(),
            back_channel_attrs: ChannelAttrs::back_channel_disabled(),
            callback_program: 0,
            callback_sec_parms: Vec::new(),
        })]),
    ];
    steps[1].session_id = Some(session);
    if complete {
        steps.push(Step::ok(sequence(
            session,
            1,
            vec![Operation::ReclaimComplete { one_fs: false }],
        )));
    }
    steps
}

pub(super) fn restart_script(failure: Option<Status>) -> Server {
    Server::start(restart_connections(failure))
}

fn restart_connections(failure: Option<Status>) -> Vec<Vec<Step>> {
    let mut original = handshake(1, true);
    original.push(Step::ok(vec![Operation::DestroySession([1; 16])]));
    let mut restored = handshake(2, false);
    let lock = lock_state();
    let open = sequence(
        2,
        1,
        vec![
            Operation::PutFh(lock.handle.clone()),
            Operation::Open(OpenArgs {
                seqid: 1,
                share_access: OPEN4_SHARE_ACCESS_WRITE | OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
                share_deny: OPEN4_SHARE_DENY_NONE,
                owner: OpenOwner {
                    client_id: 2,
                    owner: lock.open_owner,
                },
                openhow: OpenHow::NoCreate,
                claim: OpenClaim::Previous(OpenDelegationType::None),
            }),
        ],
    );
    if let Some(status) = failure {
        restored.push(Step::fail(open, status));
        restored.push(Step::ok(sequence(
            2,
            2,
            vec![Operation::ReclaimComplete { one_fs: false }],
        )));
    } else {
        restored.push(Step::ok(open));
        restored.push(Step::ok(sequence(
            2,
            2,
            vec![
                Operation::PutFh(lock.handle),
                Operation::Lock(LockArgs {
                    lock_type: LockType::Write,
                    reclaim: true,
                    offset: 10,
                    length: 20,
                    locker: Locker::New {
                        open_seqid: 2,
                        open_stateid: stateid(11),
                        lock_seqid: 1,
                        lock_owner: LockOwner {
                            client_id: 2,
                            owner: lock.owner,
                        },
                    },
                }),
            ],
        )));
        restored.push(Step::ok(sequence(
            2,
            3,
            vec![Operation::ReclaimComplete { one_fs: false }],
        )));
        restored.push(Step::ok(sequence(2, 4, vec![])));
        restored.extend(unlock_script(2, 5, stateid(11), stateid(22), 3));
    }
    vec![original, restored]
}

pub(super) fn disconnect_script(mutation: bool) -> (Server, Vec<Operation>) {
    let ops = vec![
        Operation::PutRootFh,
        if mutation {
            Operation::Remove("file".into())
        } else {
            Operation::Lookup("file".into())
        },
    ];
    let mut original = handshake(1, true);
    original.push(Step::disconnect(sequence(1, 2, ops.clone())));
    let mut recovered = handshake(2, false);
    recovered.push(Step::ok(sequence(
        2,
        1,
        vec![Operation::ReclaimComplete { one_fs: false }],
    )));
    if !mutation {
        recovered.push(Step::ok(sequence(2, 2, ops.clone())));
    }
    (Server::start(vec![original, recovered]), ops)
}

fn unlock_script(
    session: u8,
    sequence_id: u32,
    open: StateId,
    lock: StateId,
    open_seqid: u32,
) -> Vec<Step> {
    let handle = lock_state().handle;
    vec![
        Step::ok(sequence(
            session,
            sequence_id,
            vec![
                Operation::PutFh(handle.clone()),
                Operation::LockUnlock(LockUnlockArgs {
                    lock_type: LockType::Write,
                    seqid: 2,
                    lock_stateid: lock,
                    offset: 10,
                    length: 20,
                }),
            ],
        )),
        Step::ok(sequence(
            session,
            sequence_id + 1,
            vec![Operation::FreeStateId(stateid(22))],
        )),
        Step::ok(sequence(
            session,
            sequence_id + 2,
            vec![Operation::ReleaseLockOwner(LockOwner {
                client_id: if session == 2 { 2 } else { 1 },
                owner: b"lock-owner".to_vec(),
            })],
        )),
        Step::ok(sequence(
            session,
            sequence_id + 3,
            vec![
                Operation::PutFh(handle),
                Operation::Close {
                    seqid: open_seqid,
                    stateid: open,
                },
            ],
        )),
    ]
}

pub(super) fn same_client_script() -> Server {
    let mut original = handshake(1, true);
    original.push(Step::ok(vec![Operation::DestroySession([1; 16])]));
    let mut restored = handshake_on(1, 3, false);
    restored.push(Step::ok(sequence(
        3,
        1,
        vec![Operation::TestStateIds(vec![stateid(4), stateid(5)])],
    )));
    restored.push(Step::ok(sequence(
        3,
        2,
        vec![Operation::ReclaimComplete { one_fs: false }],
    )));
    restored.extend(unlock_script(3, 3, stateid(4), stateid(5), 1));
    Server::start(vec![original, restored])
}

pub(super) fn lease_script() -> (Server, std::sync::Arc<std::sync::atomic::AtomicBool>) {
    let observed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut original = handshake(1, true);
    original.push(Step::ok(vec![Operation::DestroySession([3; 16])]));
    original.push(Step::ok(vec![Operation::DestroySession([1; 16])]));
    let mut keeper = handshake_on(1, 3, false);
    let mut heartbeat = Step::ok(sequence(3, 1, vec![]));
    heartbeat.observed = Some(observed.clone());
    keeper.push(heartbeat);
    (Server::start(vec![original, keeper]), observed)
}

pub(super) fn interrupted_reclaim_script() -> Server {
    let mut scripts = restart_connections(None);
    scripts[1].truncate(4); // EXCHANGE_ID, CREATE_SESSION, reclaimed OPEN and LOCK
    scripts[1].push(Step::disconnect(sequence(
        2,
        3,
        vec![Operation::ReclaimComplete { one_fs: false }],
    )));
    let mut retry = handshake_on(2, 3, false);
    retry.push(Step::ok(sequence(
        3,
        1,
        vec![Operation::TestStateIds(vec![stateid(11), stateid(22)])],
    )));
    retry.push(Step::ok(sequence(
        3,
        2,
        vec![Operation::ReclaimComplete { one_fs: false }],
    )));
    retry.push(Step::ok(sequence(3, 3, vec![])));
    scripts.push(retry);
    Server::start(scripts)
}

pub(super) fn revocation_script(lost: bool) -> Server {
    let mut steps = handshake(1, true);
    let mut renewal = Step::ok(sequence(1, 2, vec![]));
    renewal.sequence_flags = SEQ4_STATUS_EXPIRED_SOME_STATE_REVOKED;
    steps.push(renewal);
    let mut check = Step::ok(sequence(
        1,
        3,
        vec![Operation::TestStateIds(vec![stateid(4), stateid(5)])],
    ));
    check.test_statuses = Some(vec![
        Status::Ok,
        if lost { Status::Expired } else { Status::Ok },
    ]);
    steps.push(check);
    if lost {
        steps.push(Step::ok(sequence(
            1,
            4,
            vec![Operation::FreeStateId(stateid(5))],
        )));
        steps.push(Step::ok(sequence(
            1,
            5,
            vec![
                Operation::PutFh(lock_state().handle),
                Operation::Close {
                    seqid: 1,
                    stateid: stateid(4),
                },
            ],
        )));
    } else {
        steps.extend(unlock_script(1, 4, stateid(4), stateid(5), 1));
    }
    Server::start(vec![steps])
}
