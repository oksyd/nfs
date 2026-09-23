#![cfg(feature = "protocol")]

use nfs::Error;
use nfs::v4::protocol::*;
use nfs::xdr::{Decode, Decoder, Encode, Encoder, to_bytes};

fn bitmap(attrs: &[u32]) -> Bitmap {
    Bitmap::from_attrs(attrs).unwrap()
}

#[test]
fn encodes_compound_with_v42_minor_version() {
    let args = CompoundArgs {
        tag: "t".to_owned(),
        minor_version: NFS4_MINOR_VERSION_LATEST,
        operations: vec![Operation::PutRootFh, Operation::GetFh],
    };

    assert_eq!(
        to_bytes(&args).unwrap(),
        vec![
            0, 0, 0, 1, b't', 0, 0, 0, // tag
            0, 0, 0, 2, // minor version
            0, 0, 0, 2, // op count
            0, 0, 0, 24, // OP_PUTROOTFH
            0, 0, 0, 10, // OP_GETFH
        ]
    );
}

#[test]
fn decodes_getfh_compound_response() {
    let wire = vec![
        0, 0, 0, 0, // compound status
        0, 0, 0, 1, b't', 0, 0, 0, // tag
        0, 0, 0, 2, // result count
        0, 0, 0, 24, 0, 0, 0, 0, // PUTROOTFH status
        0, 0, 0, 10, 0, 0, 0, 0, // GETFH status
        0, 0, 0, 3, 1, 2, 3, 0, // filehandle
    ];

    let mut decoder = Decoder::new(&wire);
    let response = CompoundResponse::decode(&mut decoder).unwrap();
    decoder.finish().unwrap();

    assert_eq!(response.results.len(), 2);
    assert!(matches!(
        &response.results[1],
        OperationResult::GetFh {
            handle: Some(handle),
            ..
        } if handle.as_bytes() == [1, 2, 3]
    ));
}

#[test]
fn rejects_oversized_exchange_id_state_protect_handles() {
    let mut wire = Encoder::new();
    wire.write_u32(Status::Ok.as_u32());
    wire.write_string("t", 1024).unwrap();
    wire.write_u32(1); // result count

    wire.write_u32(OpCode::ExchangeId.as_u32());
    wire.write_u32(Status::Ok.as_u32());
    wire.write_u64(1); // clientid
    wire.write_u32(1); // sequence id
    wire.write_u32(0); // flags
    wire.write_u32(StateProtectHow::SecretStateVerifier.as_u32());
    Bitmap::empty().encode(&mut wire).unwrap(); // must enforce
    Bitmap::empty().encode(&mut wire).unwrap(); // must allow
    wire.write_u32(0); // hash alg
    wire.write_u32(0); // encrypt alg
    wire.write_u32(0); // ssv length
    wire.write_u32(0); // window
    wire.write_u32(1025); // handles

    let bytes = wire.into_bytes();
    let mut decoder = Decoder::new(&bytes);
    assert!(matches!(
        CompoundResponse::decode(&mut decoder),
        Err(nfs::xdr::Error::LengthLimitExceeded {
            len: 1025,
            max: 1024
        })
    ));
}

#[test]
fn decodes_readdir_entries_with_basic_attributes() {
    let mut attr_vals = Encoder::new();
    attr_vals.write_u32(1); // NF4REG
    attr_vals.write_u64(512);
    let attrs = Fattr {
        attrmask: bitmap(&[FATTR4_TYPE, FATTR4_SIZE]),
        attr_vals: attr_vals.into_bytes(),
    };

    let mut wire = Encoder::new();
    wire.write_u32(0); // compound status
    wire.write_string("t", 1024).unwrap();
    wire.write_u32(1); // result count
    wire.write_u32(26); // OP_READDIR
    wire.write_u32(0); // status
    wire.write_fixed_opaque(&[1; 8]); // cookieverf
    wire.write_bool(true); // entry follows
    wire.write_u64(7); // cookie
    wire.write_string("file.txt", 1024).unwrap();
    attrs.encode(&mut wire).unwrap();
    wire.write_bool(false); // no more entries
    wire.write_bool(true); // eof

    let bytes = wire.into_bytes();
    let mut decoder = Decoder::new(&bytes);
    let response = CompoundResponse::decode(&mut decoder).unwrap();
    decoder.finish().unwrap();

    let OperationResult::ReadDir {
        cookieverf,
        entries,
        eof,
        ..
    } = &response.results[0]
    else {
        panic!("expected READDIR result");
    };
    assert_eq!(*cookieverf, [1; 8]);
    assert!(*eof);
    assert_eq!(entries[0].cookie, 7);
    assert_eq!(entries[0].name, "file.txt");

    let parsed = entries[0].basic_attributes().unwrap();
    assert_eq!(parsed.file_type, Some(FileType::Regular));
    assert_eq!(parsed.size, Some(512));
}

#[test]
fn builds_and_queries_v4_bitmaps() {
    let bitmap = bitmap(FATTR4_BASIC_ATTRS);
    assert!(bitmap.contains(FATTR4_TYPE));
    assert!(bitmap.contains(FATTR4_CHANGE));
    assert!(bitmap.contains(FATTR4_SIZE));
    assert!(bitmap.contains(FATTR4_FILEID));
    assert!(bitmap.contains(FATTR4_MODE));
    assert!(bitmap.contains(FATTR4_NUMLINKS));
    assert!(bitmap.contains(FATTR4_OWNER));
    assert!(bitmap.contains(FATTR4_OWNER_GROUP));
    assert!(bitmap.contains(FATTR4_SPACE_USED));
    assert!(bitmap.contains(FATTR4_TIME_ACCESS));
    assert!(bitmap.contains(FATTR4_TIME_METADATA));
    assert!(bitmap.contains(FATTR4_TIME_MODIFY));
    assert!(!bitmap.contains(99));
}

#[test]
fn rejects_oversized_v4_bitmap_construction() {
    assert!(matches!(
        Bitmap::from_attrs(&[u32::MAX]),
        Err(Error::Protocol(_))
    ));
    assert!(matches!(
        Bitmap::from_supported_attrs(&Bitmap::empty(), &[u32::MAX]),
        Err(Error::Protocol(_))
    ));
}

#[test]
fn filters_v4_attr_requests_by_supported_attrs() {
    let supported = bitmap(&[FATTR4_TYPE, FATTR4_SIZE, FATTR4_SPACE_TOTAL]);
    let request = Bitmap::from_supported_attrs(&supported, FATTR4_BASIC_ATTRS).unwrap();

    assert!(!request.is_empty());
    assert!(request.contains(FATTR4_TYPE));
    assert!(request.contains(FATTR4_SIZE));
    assert!(!request.contains(FATTR4_MODE));
    assert!(
        Bitmap::from_supported_attrs(&Bitmap::empty(), FATTR4_BASIC_ATTRS)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn parses_v4_supported_attrs_attribute() {
    let supported = bitmap(&[FATTR4_TYPE, FATTR4_SIZE, FATTR4_MODE]);
    let attrs = Fattr {
        attrmask: bitmap(&[FATTR4_SUPPORTED_ATTRS]),
        attr_vals: to_bytes(&supported).unwrap(),
    };
    let parsed = attrs.parse_supported_attrs().unwrap();

    assert!(parsed.contains(FATTR4_TYPE));
    assert!(parsed.contains(FATTR4_SIZE));
    assert!(parsed.contains(FATTR4_MODE));
    assert!(!parsed.contains(FATTR4_SPACE_TOTAL));
}

#[test]
fn parses_basic_v4_attributes() {
    let mut attr_vals = Encoder::new();
    attr_vals.write_u32(1); // NF4REG
    attr_vals.write_u64(9);
    attr_vals.write_u64(123);
    attr_vals.write_u64(456);
    attr_vals.write_u32(0o644);
    attr_vals.write_u32(2);
    attr_vals.write_string("alice", 1024).unwrap();
    attr_vals.write_string("staff", 1024).unwrap();
    attr_vals.write_u64(4096);
    attr_vals.write_i64(10);
    attr_vals.write_u32(11);
    attr_vals.write_i64(12);
    attr_vals.write_u32(13);
    attr_vals.write_i64(14);
    attr_vals.write_u32(15);

    let attrs = Fattr {
        attrmask: bitmap(FATTR4_BASIC_ATTRS),
        attr_vals: attr_vals.into_bytes(),
    };
    let parsed = attrs.parse_basic().unwrap();

    assert_eq!(parsed.file_type, Some(FileType::Regular));
    assert_eq!(parsed.change, Some(9));
    assert_eq!(parsed.size, Some(123));
    assert_eq!(parsed.fileid, Some(456));
    assert_eq!(parsed.mode, Some(0o644));
    assert_eq!(parsed.numlinks, Some(2));
    assert_eq!(parsed.owner.as_deref(), Some("alice"));
    assert_eq!(parsed.owner_group.as_deref(), Some("staff"));
    assert_eq!(parsed.space_used, Some(4096));
    assert_eq!(
        parsed.access_time,
        Some(NfsTime {
            seconds: 10,
            nseconds: 11
        })
    );
    assert_eq!(
        parsed.metadata_time,
        Some(NfsTime {
            seconds: 12,
            nseconds: 13
        })
    );
    assert_eq!(
        parsed.modify_time,
        Some(NfsTime {
            seconds: 14,
            nseconds: 15
        })
    );
    assert!(parsed.is_file().unwrap());
    assert!(!parsed.is_dir().unwrap());
}

#[test]
fn classifies_v4_file_types() {
    assert!(FileType::Regular.is_file());
    assert!(FileType::Directory.is_dir());
    assert!(FileType::Symlink.is_symlink());
    assert!(!FileType::NamedAttr.is_file());

    let attrs = nfs::v4::BasicAttributes {
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
        raw: Fattr::empty(),
    };
    assert!(attrs.required_file_type().is_err());
}

#[test]
fn builds_v4_setattr_payloads() {
    let attrs = SetAttrs {
        size: Some(5),
        mode: Some(0o600),
        owner: Some("alice".to_owned()),
        owner_group: Some("staff".to_owned()),
        access_time: SetTime::ServerTime,
        modify_time: SetTime::ClientTime(NfsTime {
            seconds: 42,
            nseconds: 7,
        }),
    };
    let fattr = Fattr::from_set_attrs(&attrs).unwrap();

    assert!(fattr.attrmask.contains(FATTR4_SIZE));
    assert!(fattr.attrmask.contains(FATTR4_MODE));
    assert!(fattr.attrmask.contains(FATTR4_OWNER));
    assert!(fattr.attrmask.contains(FATTR4_OWNER_GROUP));
    assert!(fattr.attrmask.contains(FATTR4_TIME_ACCESS_SET));
    assert!(fattr.attrmask.contains(FATTR4_TIME_MODIFY_SET));

    let mut decoder = Decoder::new(&fattr.attr_vals);
    assert_eq!(decoder.read_u64().unwrap(), 5);
    assert_eq!(decoder.read_u32().unwrap(), 0o600);
    assert_eq!(decoder.read_string(1024).unwrap(), "alice");
    assert_eq!(decoder.read_string(1024).unwrap(), "staff");
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert_eq!(decoder.read_u32().unwrap(), 1);
    assert_eq!(decoder.read_i64().unwrap(), 42);
    assert_eq!(decoder.read_u32().unwrap(), 7);
    decoder.finish().unwrap();
}

#[test]
fn parses_v4_fsstat_attributes() {
    let bitmap = bitmap(FATTR4_FSSTAT_ATTRS);
    assert!(bitmap.contains(FATTR4_FILES_AVAIL));
    assert!(bitmap.contains(FATTR4_FILES_FREE));
    assert!(bitmap.contains(FATTR4_FILES_TOTAL));
    assert!(bitmap.contains(FATTR4_SPACE_AVAIL));
    assert!(bitmap.contains(FATTR4_SPACE_FREE));
    assert!(bitmap.contains(FATTR4_SPACE_TOTAL));

    let mut attr_vals = Encoder::new();
    attr_vals.write_u64(10); // files_avail
    attr_vals.write_u64(11); // files_free
    attr_vals.write_u64(12); // files_total
    attr_vals.write_u64(100); // space_avail
    attr_vals.write_u64(101); // space_free
    attr_vals.write_u64(102); // space_total

    let attrs = Fattr {
        attrmask: bitmap,
        attr_vals: attr_vals.into_bytes(),
    };
    let parsed = attrs.parse_fsstat().unwrap();

    assert_eq!(parsed.available_files, Some(10));
    assert_eq!(parsed.free_files, Some(11));
    assert_eq!(parsed.total_files, Some(12));
    assert_eq!(parsed.available_bytes, Some(100));
    assert_eq!(parsed.free_bytes, Some(101));
    assert_eq!(parsed.total_bytes, Some(102));
}

#[test]
fn parses_v4_fsinfo_attributes() {
    let bitmap = bitmap(FATTR4_FSINFO_ATTRS);
    assert!(bitmap.contains(FATTR4_FH_EXPIRE_TYPE));
    assert!(bitmap.contains(FATTR4_LINK_SUPPORT));
    assert!(bitmap.contains(FATTR4_SYMLINK_SUPPORT));
    assert!(bitmap.contains(FATTR4_UNIQUE_HANDLES));
    assert!(bitmap.contains(FATTR4_LEASE_TIME));
    assert!(bitmap.contains(FATTR4_HOMOGENEOUS));
    assert!(bitmap.contains(FATTR4_MAXFILESIZE));
    assert!(bitmap.contains(FATTR4_MAXREAD));
    assert!(bitmap.contains(FATTR4_MAXWRITE));
    assert!(bitmap.contains(FATTR4_TIME_DELTA));

    let mut attr_vals = Encoder::new();
    attr_vals.write_u32(0x0000_0001); // fh_expire_type
    attr_vals.write_bool(true); // link_support
    attr_vals.write_bool(false); // symlink_support
    attr_vals.write_bool(true); // unique_handles
    attr_vals.write_u32(90); // lease_time
    attr_vals.write_bool(true); // cansettime
    attr_vals.write_bool(true); // homogeneous
    attr_vals.write_u64(1 << 40); // maxfilesize
    attr_vals.write_u64(128 * 1024); // maxread
    attr_vals.write_u64(256 * 1024); // maxwrite
    attr_vals.write_i64(0); // time_delta.seconds
    attr_vals.write_u32(1); // time_delta.nseconds

    let attrs = Fattr {
        attrmask: bitmap,
        attr_vals: attr_vals.into_bytes(),
    };
    let parsed = attrs.parse_fsinfo().unwrap();

    assert_eq!(parsed.fh_expire_type, Some(1));
    assert_eq!(parsed.link_support, Some(true));
    assert_eq!(parsed.symlink_support, Some(false));
    assert_eq!(parsed.unique_handles, Some(true));
    assert_eq!(parsed.lease_time_seconds, Some(90));
    assert_eq!(parsed.can_set_time, Some(true));
    assert_eq!(parsed.homogeneous, Some(true));
    assert_eq!(parsed.max_file_size, Some(1 << 40));
    assert_eq!(parsed.max_read, Some(128 * 1024));
    assert_eq!(parsed.max_write, Some(256 * 1024));
    assert_eq!(
        parsed.time_delta,
        Some(NfsTime {
            seconds: 0,
            nseconds: 1
        })
    );
}

#[test]
fn parses_v4_pathconf_attributes() {
    let bitmap = bitmap(FATTR4_PATHCONF_ATTRS);
    assert!(bitmap.contains(FATTR4_CASE_INSENSITIVE));
    assert!(bitmap.contains(FATTR4_CASE_PRESERVING));
    assert!(bitmap.contains(FATTR4_CHOWN_RESTRICTED));
    assert!(bitmap.contains(FATTR4_MAXLINK));
    assert!(bitmap.contains(FATTR4_MAXNAME));
    assert!(bitmap.contains(FATTR4_NO_TRUNC));

    let mut attr_vals = Encoder::new();
    attr_vals.write_bool(false); // case_insensitive
    attr_vals.write_bool(true); // case_preserving
    attr_vals.write_bool(true); // chown_restricted
    attr_vals.write_u32(127); // maxlink
    attr_vals.write_u32(255); // maxname
    attr_vals.write_bool(true); // no_trunc

    let attrs = Fattr {
        attrmask: bitmap,
        attr_vals: attr_vals.into_bytes(),
    };
    let parsed = attrs.parse_pathconf().unwrap();

    assert_eq!(parsed.case_insensitive, Some(false));
    assert_eq!(parsed.case_preserving, Some(true));
    assert_eq!(parsed.chown_restricted, Some(true));
    assert_eq!(parsed.link_max, Some(127));
    assert_eq!(parsed.name_max, Some(255));
    assert_eq!(parsed.no_trunc, Some(true));
}

#[test]
fn encodes_anonymous_stateid_for_special_read_state() {
    let bytes = to_bytes(&StateId::anonymous()).unwrap();
    assert_eq!(bytes, vec![0; 16]);
}

#[test]
fn encodes_destroy_session_operation() {
    let bytes = to_bytes(&Operation::DestroySession([1; 16])).unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(44); // OP_DESTROY_SESSION
    expected.write_fixed_opaque(&[1; 16]);
    assert_eq!(bytes, expected.into_bytes());
}

#[test]
fn encodes_reclaim_complete_operation() {
    let bytes = to_bytes(&Operation::ReclaimComplete { one_fs: false }).unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(58); // OP_RECLAIM_COMPLETE
    expected.write_bool(false);
    assert_eq!(bytes, expected.into_bytes());
}

#[test]
fn encodes_access_operation() {
    let bytes = to_bytes(&Operation::Access(ACCESS4_READ | ACCESS4_LOOKUP)).unwrap();
    assert_eq!(
        bytes,
        vec![
            0, 0, 0, 3, // OP_ACCESS
            0, 0, 0, 3, // ACCESS4_READ | ACCESS4_LOOKUP
        ]
    );
}

#[test]
fn encodes_simple_v4_control_operations() {
    let stateid = StateId {
        seqid: 7,
        other: [8; 12],
    };

    assert_eq!(to_bytes(&Operation::PutPubFh).unwrap(), vec![0, 0, 0, 23]);
    assert_eq!(to_bytes(&Operation::Lookupp).unwrap(), vec![0, 0, 0, 16]);

    let deleg_purge = to_bytes(&Operation::DelegPurge(0x0102_0304_0506_0708)).unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(7); // OP_DELEGPURGE
    expected.write_u64(0x0102_0304_0506_0708);
    assert_eq!(deleg_purge, expected.into_bytes());

    let deleg_return = to_bytes(&Operation::DelegReturn(stateid)).unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(8); // OP_DELEGRETURN
    expected.write_u32(7);
    expected.write_fixed_opaque(&[8; 12]);
    assert_eq!(deleg_return, expected.into_bytes());

    let attrs = Fattr::mode(0o644);
    let verify = to_bytes(&Operation::Verify(attrs.clone())).unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(37); // OP_VERIFY
    attrs.encode(&mut expected).unwrap();
    assert_eq!(verify, expected.into_bytes());

    let nverify = to_bytes(&Operation::NVerify(Fattr::empty())).unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(17); // OP_NVERIFY
    Fattr::empty().encode(&mut expected).unwrap();
    assert_eq!(nverify, expected.into_bytes());

    let open_attr = to_bytes(&Operation::OpenAttr { create_dir: true }).unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(19); // OP_OPENATTR
    expected.write_bool(true);
    assert_eq!(open_attr, expected.into_bytes());

    let open_confirm = to_bytes(&Operation::OpenConfirm { stateid, seqid: 9 }).unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(20); // OP_OPEN_CONFIRM
    expected.write_u32(7);
    expected.write_fixed_opaque(&[8; 12]);
    expected.write_u32(9);
    assert_eq!(open_confirm, expected.into_bytes());

    let renew = to_bytes(&Operation::Renew(0x0102_0304_0506_0708)).unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(30); // OP_RENEW
    expected.write_u64(0x0102_0304_0506_0708);
    assert_eq!(renew, expected.into_bytes());

    let release = to_bytes(&Operation::ReleaseLockOwner(LockOwner {
        client_id: 0x0102_0304_0506_0708,
        owner: b"lock-owner".to_vec(),
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(39); // OP_RELEASE_LOCKOWNER
    expected.write_u64(0x0102_0304_0506_0708);
    expected.write_opaque(b"lock-owner", 1024).unwrap();
    assert_eq!(release, expected.into_bytes());
}

#[test]
fn encodes_v41_security_session_and_offload_controls() {
    let stateid = StateId {
        seqid: 7,
        other: [8; 12],
    };

    let secinfo = to_bytes(&Operation::SecInfo("child".to_owned())).unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(33); // OP_SECINFO
    expected.write_string("child", 1024).unwrap();
    assert_eq!(secinfo, expected.into_bytes());

    let secinfo_no_name =
        to_bytes(&Operation::SecInfoNoName(SecInfoStyle::CurrentFileHandle)).unwrap();
    assert_eq!(
        secinfo_no_name,
        vec![0, 0, 0, 52, 0, 0, 0, 0] // OP_SECINFO_NO_NAME, CURRENT_FH
    );

    let bind = to_bytes(&Operation::BindConnToSession(BindConnToSessionArgs {
        session_id: [9; 16],
        direction: ChannelDirFromClient::ForeOrBoth,
        use_conn_in_rdma_mode: false,
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(41); // OP_BIND_CONN_TO_SESSION
    expected.write_fixed_opaque(&[9; 16]);
    expected.write_u32(0x3); // CDFC4_FORE_OR_BOTH
    expected.write_bool(false);
    assert_eq!(bind, expected.into_bytes());

    let destroy_clientid = to_bytes(&Operation::DestroyClientId(0x0102_0304_0506_0708)).unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(57); // OP_DESTROY_CLIENTID
    expected.write_u64(0x0102_0304_0506_0708);
    assert_eq!(destroy_clientid, expected.into_bytes());

    let cancel = to_bytes(&Operation::OffloadCancel(stateid)).unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(66); // OP_OFFLOAD_CANCEL
    expected.write_u32(7);
    expected.write_fixed_opaque(&[8; 12]);
    assert_eq!(cancel, expected.into_bytes());

    let status = to_bytes(&Operation::OffloadStatus(stateid)).unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(67); // OP_OFFLOAD_STATUS
    expected.write_u32(7);
    expected.write_fixed_opaque(&[8; 12]);
    assert_eq!(status, expected.into_bytes());
}

#[test]
fn encodes_v40_v41_pnfs_delegation_and_ssv_operations() {
    let stateid = StateId {
        seqid: 3,
        other: [4; 12],
    };
    let device_id = [7; 16];

    let set_clientid = to_bytes(&Operation::SetClientId(SetClientIdArgs {
        client: ClientOwner {
            verifier: [1; 8],
            owner_id: b"owner".to_vec(),
        },
        callback: CallbackClient {
            program: 0x4000_0001,
            location: NetAddr {
                netid: "tcp".to_owned(),
                addr: "127.0.0.1.8.1".to_owned(),
            },
        },
        callback_ident: 9,
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(35); // OP_SETCLIENTID
    expected.write_fixed_opaque(&[1; 8]);
    expected.write_opaque(b"owner", 1024).unwrap();
    expected.write_u32(0x4000_0001);
    expected.write_string("tcp", 1024).unwrap();
    expected.write_string("127.0.0.1.8.1", 1024).unwrap();
    expected.write_u32(9);
    assert_eq!(set_clientid, expected.into_bytes());

    let confirm = to_bytes(&Operation::SetClientIdConfirm(SetClientIdConfirmArgs {
        client_id: 0x0102_0304_0506_0708,
        verifier: [2; 8],
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(36); // OP_SETCLIENTID_CONFIRM
    expected.write_u64(0x0102_0304_0506_0708);
    expected.write_fixed_opaque(&[2; 8]);
    assert_eq!(confirm, expected.into_bytes());

    let backchannel = to_bytes(&Operation::BackchannelCtl(BackchannelCtlArgs {
        callback_program: 0x4000_0001,
        callback_sec_parms: vec![CallbackSecParms::RpcSecGss {
            service: RpcGssService::Privacy,
            handle_from_server: b"server".to_vec(),
            handle_from_client: b"client".to_vec(),
        }],
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(40); // OP_BACKCHANNEL_CTL
    expected.write_u32(0x4000_0001);
    expected.write_u32(1); // callback_sec_parms count
    expected.write_u32(RPCSEC_GSS);
    expected.write_u32(RPC_GSS_SVC_PRIVACY);
    expected.write_opaque(b"server", 1024).unwrap();
    expected.write_opaque(b"client", 1024).unwrap();
    assert_eq!(backchannel, expected.into_bytes());

    let get_dir_delegation = to_bytes(&Operation::GetDirDelegation(GetDirDelegationArgs {
        signal_deleg_avail: true,
        notification_types: bitmap(&[1, 33]),
        child_attr_delay: NfsTime {
            seconds: 1,
            nseconds: 2,
        },
        dir_attr_delay: NfsTime {
            seconds: 3,
            nseconds: 4,
        },
        child_attributes: bitmap(&[FATTR4_SIZE]),
        dir_attributes: bitmap(&[FATTR4_CHANGE]),
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(46); // OP_GET_DIR_DELEGATION
    expected.write_bool(true);
    bitmap(&[1, 33]).encode(&mut expected).unwrap();
    NfsTime {
        seconds: 1,
        nseconds: 2,
    }
    .encode(&mut expected)
    .unwrap();
    NfsTime {
        seconds: 3,
        nseconds: 4,
    }
    .encode(&mut expected)
    .unwrap();
    bitmap(&[FATTR4_SIZE]).encode(&mut expected).unwrap();
    bitmap(&[FATTR4_CHANGE]).encode(&mut expected).unwrap();
    assert_eq!(get_dir_delegation, expected.into_bytes());

    let get_device_info = to_bytes(&Operation::GetDeviceInfo(GetDeviceInfoArgs {
        device_id,
        layout_type: LayoutType::NfsV4_1Files,
        max_count: 4096,
        notify_types: bitmap(&[0]),
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(47); // OP_GETDEVICEINFO
    expected.write_fixed_opaque(&device_id);
    expected.write_u32(LAYOUT4_NFSV4_1_FILES);
    expected.write_u32(4096);
    bitmap(&[0]).encode(&mut expected).unwrap();
    assert_eq!(get_device_info, expected.into_bytes());

    let get_device_list = to_bytes(&Operation::GetDeviceList(GetDeviceListArgs {
        layout_type: LayoutType::BlockVolume,
        max_devices: 8,
        cookie: 11,
        cookieverf: [12; 8],
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(48); // OP_GETDEVICELIST
    expected.write_u32(LAYOUT4_BLOCK_VOLUME);
    expected.write_u32(8);
    expected.write_u64(11);
    expected.write_fixed_opaque(&[12; 8]);
    assert_eq!(get_device_list, expected.into_bytes());

    let layout_update = LayoutUpdate {
        layout_type: LayoutType::NfsV4_1Files,
        body: b"layout".to_vec(),
    };
    let layout_commit = to_bytes(&Operation::LayoutCommit(LayoutCommitArgs {
        offset: 1,
        length: 2,
        reclaim: false,
        stateid,
        last_write_offset: Some(3),
        time_modify: Some(NfsTime {
            seconds: 4,
            nseconds: 5,
        }),
        layout_update: layout_update.clone(),
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(49); // OP_LAYOUTCOMMIT
    expected.write_u64(1);
    expected.write_u64(2);
    expected.write_bool(false);
    stateid.encode(&mut expected).unwrap();
    expected.write_bool(true);
    expected.write_u64(3);
    expected.write_bool(true);
    NfsTime {
        seconds: 4,
        nseconds: 5,
    }
    .encode(&mut expected)
    .unwrap();
    expected.write_u32(LAYOUT4_NFSV4_1_FILES);
    expected.write_opaque(b"layout", 64 * 1024 * 1024).unwrap();
    assert_eq!(layout_commit, expected.into_bytes());

    let layout_get = to_bytes(&Operation::LayoutGet(LayoutGetArgs {
        signal_layout_avail: true,
        layout_type: LayoutType::NfsV4_1Files,
        iomode: LayoutIomode::ReadWrite,
        offset: 10,
        length: 20,
        min_length: 5,
        stateid,
        max_count: 8192,
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(50); // OP_LAYOUTGET
    expected.write_bool(true);
    expected.write_u32(LAYOUT4_NFSV4_1_FILES);
    expected.write_u32(LAYOUTIOMODE4_RW);
    expected.write_u64(10);
    expected.write_u64(20);
    expected.write_u64(5);
    stateid.encode(&mut expected).unwrap();
    expected.write_u32(8192);
    assert_eq!(layout_get, expected.into_bytes());

    let layout_return = to_bytes(&Operation::LayoutReturn(LayoutReturnArgs {
        reclaim: false,
        layout_type: LayoutType::NfsV4_1Files,
        iomode: LayoutIomode::Any,
        layout_return: LayoutReturn::File(LayoutReturnFile {
            offset: 1,
            length: 2,
            stateid,
            body: b"return".to_vec(),
        }),
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(51); // OP_LAYOUTRETURN
    expected.write_bool(false);
    expected.write_u32(LAYOUT4_NFSV4_1_FILES);
    expected.write_u32(LAYOUTIOMODE4_ANY);
    expected.write_u32(LAYOUTRETURN4_FILE);
    expected.write_u64(1);
    expected.write_u64(2);
    stateid.encode(&mut expected).unwrap();
    expected.write_opaque(b"return", 64 * 1024 * 1024).unwrap();
    assert_eq!(layout_return, expected.into_bytes());

    let set_ssv = to_bytes(&Operation::SetSsv(SetSsvArgs {
        ssv: b"secret".to_vec(),
        digest: b"digest".to_vec(),
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(54); // OP_SET_SSV
    expected.write_opaque(b"secret", 1024).unwrap();
    expected.write_opaque(b"digest", 1024).unwrap();
    assert_eq!(set_ssv, expected.into_bytes());

    let want_delegation = to_bytes(&Operation::WantDelegation(WantDelegationArgs {
        want: OPEN4_SHARE_ACCESS_WANT_READ_DELEG,
        claim: DelegationClaim::Previous(OpenDelegationType::Read),
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(56); // OP_WANT_DELEGATION
    expected.write_u32(OPEN4_SHARE_ACCESS_WANT_READ_DELEG);
    expected.write_u32(1); // CLAIM_PREVIOUS
    expected.write_u32(1); // OPEN_DELEGATE_READ
    assert_eq!(want_delegation, expected.into_bytes());

    let layout_error = to_bytes(&Operation::LayoutError(LayoutErrorArgs {
        offset: 1,
        length: 2,
        stateid,
        errors: vec![DeviceError {
            device_id,
            status: Status::Io,
            opnum: OpCode::Read,
        }],
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(64); // OP_LAYOUTERROR
    expected.write_u64(1);
    expected.write_u64(2);
    stateid.encode(&mut expected).unwrap();
    expected.write_u32(1);
    expected.write_fixed_opaque(&device_id);
    expected.write_u32(Status::Io.as_u32());
    expected.write_u32(OpCode::Read.as_u32());
    assert_eq!(layout_error, expected.into_bytes());

    let layout_stats = to_bytes(&Operation::LayoutStats(LayoutStatsArgs {
        offset: 1,
        length: 2,
        stateid,
        read: IoInfo { count: 3, bytes: 4 },
        write: IoInfo { count: 5, bytes: 6 },
        device_id,
        layout_update,
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(65); // OP_LAYOUTSTATS
    expected.write_u64(1);
    expected.write_u64(2);
    stateid.encode(&mut expected).unwrap();
    expected.write_u64(3);
    expected.write_u64(4);
    expected.write_u64(5);
    expected.write_u64(6);
    expected.write_fixed_opaque(&device_id);
    expected.write_u32(LAYOUT4_NFSV4_1_FILES);
    expected.write_opaque(b"layout", 64 * 1024 * 1024).unwrap();
    assert_eq!(layout_stats, expected.into_bytes());
}

#[test]
fn encodes_link_operation() {
    let bytes = to_bytes(&Operation::Link("alias".to_owned())).unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(11); // OP_LINK
    expected.write_string("alias", 1024).unwrap();
    assert_eq!(bytes, expected.into_bytes());
}

#[test]
fn encodes_commit_operation() {
    let bytes = to_bytes(&Operation::Commit {
        offset: 0x0102_0304_0506_0708,
        count: 4096,
    })
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(5); // OP_COMMIT
    expected.write_u64(0x0102_0304_0506_0708);
    expected.write_u32(4096);
    assert_eq!(bytes, expected.into_bytes());
}

#[test]
fn encodes_v42_space_management_operations() {
    let stateid = StateId {
        seqid: 3,
        other: [4; 12],
    };

    let allocate = to_bytes(&Operation::Allocate {
        stateid,
        offset: 0x0102_0304_0506_0708,
        length: 0x1112_1314_1516_1718,
    })
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(59); // OP_ALLOCATE
    expected.write_u32(3);
    expected.write_fixed_opaque(&[4; 12]);
    expected.write_u64(0x0102_0304_0506_0708);
    expected.write_u64(0x1112_1314_1516_1718);
    assert_eq!(allocate, expected.into_bytes());

    let deallocate = to_bytes(&Operation::Deallocate {
        stateid,
        offset: 1024,
        length: 4096,
    })
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(62); // OP_DEALLOCATE
    expected.write_u32(3);
    expected.write_fixed_opaque(&[4; 12]);
    expected.write_u64(1024);
    expected.write_u64(4096);
    assert_eq!(deallocate, expected.into_bytes());
}

#[test]
fn encodes_v42_data_range_operations() {
    let stateid = StateId {
        seqid: 3,
        other: [4; 12],
    };

    let io_advise = to_bytes(&Operation::IoAdvise(IoAdviseArgs {
        stateid,
        offset: 0x0102_0304_0506_0708,
        count: 0x1112_1314_1516_1718,
        hints: bitmap(&[
            IoAdviceType::Sequential.as_u32(),
            IoAdviceType::WillNeed.as_u32(),
        ]),
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(63); // OP_IO_ADVISE
    expected.write_u32(3);
    expected.write_fixed_opaque(&[4; 12]);
    expected.write_u64(0x0102_0304_0506_0708);
    expected.write_u64(0x1112_1314_1516_1718);
    expected.write_u32(1); // bitmap word count
    expected.write_u32((1 << 1) | (1 << 4));
    assert_eq!(io_advise, expected.into_bytes());

    let read_plus = to_bytes(&Operation::ReadPlus(ReadPlusArgs {
        stateid,
        offset: 8192,
        count: 4096,
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(68); // OP_READ_PLUS
    expected.write_u32(3);
    expected.write_fixed_opaque(&[4; 12]);
    expected.write_u64(8192);
    expected.write_u32(4096);
    assert_eq!(read_plus, expected.into_bytes());

    let clone = to_bytes(&Operation::Clone(CloneArgs {
        src_stateid: stateid,
        dst_stateid: StateId {
            seqid: 5,
            other: [6; 12],
        },
        src_offset: 1024,
        dst_offset: 2048,
        count: 4096,
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(71); // OP_CLONE
    expected.write_u32(3);
    expected.write_fixed_opaque(&[4; 12]);
    expected.write_u32(5);
    expected.write_fixed_opaque(&[6; 12]);
    expected.write_u64(1024);
    expected.write_u64(2048);
    expected.write_u64(4096);
    assert_eq!(clone, expected.into_bytes());

    let copy = to_bytes(&Operation::Copy(CopyArgs {
        src_stateid: stateid,
        dst_stateid: StateId {
            seqid: 5,
            other: [6; 12],
        },
        src_offset: 1024,
        dst_offset: 2048,
        count: 4096,
        consecutive: true,
        synchronous: false,
        source_servers: vec![NetLoc::Name("source.example".to_owned())],
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(60); // OP_COPY
    expected.write_u32(3);
    expected.write_fixed_opaque(&[4; 12]);
    expected.write_u32(5);
    expected.write_fixed_opaque(&[6; 12]);
    expected.write_u64(1024);
    expected.write_u64(2048);
    expected.write_u64(4096);
    expected.write_bool(true);
    expected.write_bool(false);
    expected.write_u32(1); // source server count
    expected.write_u32(1); // NL4_NAME
    expected.write_string("source.example", 1024).unwrap();
    assert_eq!(copy, expected.into_bytes());

    let notify = to_bytes(&Operation::CopyNotify(CopyNotifyArgs {
        src_stateid: stateid,
        destination_server: NetLoc::NetAddr {
            netid: "tcp".to_owned(),
            addr: "127.0.0.1.8.1".to_owned(),
        },
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(61); // OP_COPY_NOTIFY
    expected.write_u32(3);
    expected.write_fixed_opaque(&[4; 12]);
    expected.write_u32(3); // NL4_NETADDR
    expected.write_string("tcp", 1024).unwrap();
    expected.write_string("127.0.0.1.8.1", 1024).unwrap();
    assert_eq!(notify, expected.into_bytes());

    let write_same = to_bytes(&Operation::WriteSame(WriteSameArgs {
        stateid,
        stable: StableHow::FileSync,
        block: AppDataBlock {
            offset: 11,
            block_size: 4096,
            block_count: 2,
            block_number_offset: 8,
            block_number: 42,
            pattern_offset: 16,
            pattern: b"pattern".to_vec(),
        },
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(70); // OP_WRITE_SAME
    expected.write_u32(3);
    expected.write_fixed_opaque(&[4; 12]);
    expected.write_u32(StableHow::FileSync.as_u32());
    expected.write_u64(11);
    expected.write_u64(4096);
    expected.write_u64(2);
    expected.write_u64(8);
    expected.write_u32(42);
    expected.write_u64(16);
    expected.write_opaque(b"pattern", 64 * 1024 * 1024).unwrap();
    assert_eq!(write_same, expected.into_bytes());
}

#[test]
fn encodes_v41_state_operations() {
    let stateid = StateId {
        seqid: 9,
        other: [10; 12],
    };

    let open_downgrade = to_bytes(&Operation::OpenDowngrade {
        seqid: 7,
        stateid,
        share_access: OPEN4_SHARE_ACCESS_READ,
        share_deny: OPEN4_SHARE_DENY_NONE,
    })
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(21); // OP_OPEN_DOWNGRADE
    expected.write_u32(9);
    expected.write_fixed_opaque(&[10; 12]);
    expected.write_u32(7);
    expected.write_u32(OPEN4_SHARE_ACCESS_READ);
    expected.write_u32(OPEN4_SHARE_DENY_NONE);
    assert_eq!(open_downgrade, expected.into_bytes());

    let free = to_bytes(&Operation::FreeStateId(stateid)).unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(45); // OP_FREE_STATEID
    expected.write_u32(9);
    expected.write_fixed_opaque(&[10; 12]);
    assert_eq!(free, expected.into_bytes());

    let test = to_bytes(&Operation::TestStateIds(vec![stateid])).unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(55); // OP_TEST_STATEID
    expected.write_u32(1); // stateid count
    expected.write_u32(9);
    expected.write_fixed_opaque(&[10; 12]);
    assert_eq!(test, expected.into_bytes());
}

#[test]
fn encodes_v4_lock_operations() {
    let stateid = StateId {
        seqid: 9,
        other: [10; 12],
    };
    let owner = LockOwner {
        client_id: 0x0102_0304_0506_0708,
        owner: b"lock-owner".to_vec(),
    };

    let lock = to_bytes(&Operation::Lock(LockArgs {
        lock_type: LockType::WriteBlocking,
        reclaim: false,
        offset: 1024,
        length: 4096,
        locker: Locker::New {
            open_seqid: 1,
            open_stateid: stateid,
            lock_seqid: 2,
            lock_owner: owner.clone(),
        },
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(12); // OP_LOCK
    expected.write_u32(4); // WRITEW_LT
    expected.write_bool(false);
    expected.write_u64(1024);
    expected.write_u64(4096);
    expected.write_bool(true); // new lock owner
    expected.write_u32(1);
    expected.write_u32(9);
    expected.write_fixed_opaque(&[10; 12]);
    expected.write_u32(2);
    expected.write_u64(0x0102_0304_0506_0708);
    expected.write_opaque(b"lock-owner", 1024).unwrap();
    assert_eq!(lock, expected.into_bytes());

    let lockt = to_bytes(&Operation::LockTest(LockTestArgs {
        lock_type: LockType::Read,
        offset: 0,
        length: 1,
        owner: owner.clone(),
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(13); // OP_LOCKT
    expected.write_u32(1); // READ_LT
    expected.write_u64(0);
    expected.write_u64(1);
    expected.write_u64(0x0102_0304_0506_0708);
    expected.write_opaque(b"lock-owner", 1024).unwrap();
    assert_eq!(lockt, expected.into_bytes());

    let locku = to_bytes(&Operation::LockUnlock(LockUnlockArgs {
        lock_type: LockType::Write,
        seqid: 3,
        lock_stateid: stateid,
        offset: 2048,
        length: 8192,
    }))
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(14); // OP_LOCKU
    expected.write_u32(2); // WRITE_LT
    expected.write_u32(3);
    expected.write_u32(9);
    expected.write_fixed_opaque(&[10; 12]);
    expected.write_u64(2048);
    expected.write_u64(8192);
    assert_eq!(locku, expected.into_bytes());
}

#[test]
fn encodes_v42_seek_operation() {
    let bytes = to_bytes(&Operation::Seek {
        stateid: StateId {
            seqid: 5,
            other: [6; 12],
        },
        offset: 0x0102_0304_0506_0708,
        what: SeekContent::Hole,
    })
    .unwrap();

    let mut expected = Encoder::new();
    expected.write_u32(69); // OP_SEEK
    expected.write_u32(5);
    expected.write_fixed_opaque(&[6; 12]);
    expected.write_u64(0x0102_0304_0506_0708);
    expected.write_u32(1); // NFS4_CONTENT_HOLE
    assert_eq!(bytes, expected.into_bytes());
}

#[test]
fn encodes_setattr_mode_operation() {
    let bytes = to_bytes(&Operation::SetAttr {
        stateid: StateId::anonymous(),
        attrs: Fattr::mode(0o600),
    })
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(34); // OP_SETATTR
    expected.write_fixed_opaque(&[0; 16]);
    expected.write_u32(2); // bitmap words
    expected.write_u32(0);
    expected.write_u32(1 << (FATTR4_MODE - 32));
    expected
        .write_opaque(&0o600_u32.to_be_bytes(), 64 * 1024 * 1024)
        .unwrap();
    assert_eq!(bytes, expected.into_bytes());
}

#[test]
fn encodes_open_create_and_write_operations() {
    let open = Operation::Open(OpenArgs {
        seqid: 7,
        share_access: OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
        share_deny: OPEN4_SHARE_DENY_NONE,
        owner: OpenOwner {
            client_id: 0x0102_0304_0506_0708,
            owner: b"o".to_vec(),
        },
        openhow: OpenHow::Unchecked(Fattr::mode(0o644)),
        claim: OpenClaim::Null("file".to_owned()),
    });
    let mut expected = Encoder::new();
    expected.write_u32(18); // OP_OPEN
    expected.write_u32(7);
    expected.write_u32(OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_NO_DELEG);
    expected.write_u32(OPEN4_SHARE_DENY_NONE);
    expected.write_u64(0x0102_0304_0506_0708);
    expected.write_opaque(b"o", 1024).unwrap();
    expected.write_u32(1); // OPEN4_CREATE
    expected.write_u32(0); // UNCHECKED4
    expected.write_u32(2); // bitmap words
    expected.write_u32(0);
    expected.write_u32(1 << (FATTR4_MODE - 32));
    expected
        .write_opaque(&0o644_u32.to_be_bytes(), 64 * 1024 * 1024)
        .unwrap();
    expected.write_u32(0); // CLAIM_NULL
    expected.write_string("file", 1024).unwrap();
    assert_eq!(to_bytes(&open).unwrap(), expected.into_bytes());

    let create = Operation::Create(CreateArgs {
        kind: CreateKind::Directory,
        name: "dir".to_owned(),
        attrs: Fattr::mode(0o755),
    });
    let mut expected = Encoder::new();
    expected.write_u32(6); // OP_CREATE
    expected.write_u32(2); // NF4DIR
    expected.write_string("dir", 1024).unwrap();
    expected.write_u32(2);
    expected.write_u32(0);
    expected.write_u32(1 << (FATTR4_MODE - 32));
    expected
        .write_opaque(&0o755_u32.to_be_bytes(), 64 * 1024 * 1024)
        .unwrap();
    assert_eq!(to_bytes(&create).unwrap(), expected.into_bytes());

    let symlink = Operation::Create(CreateArgs {
        kind: CreateKind::Symlink("target".to_owned()),
        name: "link".to_owned(),
        attrs: Fattr::empty(),
    });
    let mut expected = Encoder::new();
    expected.write_u32(6); // OP_CREATE
    expected.write_u32(5); // NF4LNK
    expected.write_string("target", 1024).unwrap();
    expected.write_string("link", 1024).unwrap();
    expected.write_u32(0); // empty bitmap
    expected.write_u32(0); // empty attr_vals
    assert_eq!(to_bytes(&symlink).unwrap(), expected.into_bytes());

    let write = Operation::Write {
        stateid: StateId {
            seqid: 1,
            other: [2; 12],
        },
        offset: 9,
        stable: StableHow::FileSync,
        data: b"abc".to_vec(),
    };
    let mut expected = Encoder::new();
    expected.write_u32(38); // OP_WRITE
    expected.write_u32(1);
    expected.write_fixed_opaque(&[2; 12]);
    expected.write_u64(9);
    expected.write_u32(2); // FILE_SYNC4
    expected.write_opaque(b"abc", 64 * 1024 * 1024).unwrap();
    assert_eq!(to_bytes(&write).unwrap(), expected.into_bytes());
}

#[test]
fn encodes_v41_exclusive_open_and_claim_variants() {
    let stateid = StateId {
        seqid: 7,
        other: [8; 12],
    };
    let open = Operation::Open(OpenArgs {
        seqid: 1,
        share_access: OPEN4_SHARE_ACCESS_READ,
        share_deny: OPEN4_SHARE_DENY_NONE,
        owner: OpenOwner {
            client_id: 2,
            owner: b"owner".to_vec(),
        },
        openhow: OpenHow::ExclusiveWithAttrs {
            verifier: [3; 8],
            attrs: Fattr::mode(0o600),
        },
        claim: OpenClaim::DelegateCurrent {
            delegate_stateid: stateid,
            file: "delegated.txt".to_owned(),
        },
    });

    let mut expected = Encoder::new();
    expected.write_u32(18); // OP_OPEN
    expected.write_u32(1); // seqid
    expected.write_u32(OPEN4_SHARE_ACCESS_READ);
    expected.write_u32(OPEN4_SHARE_DENY_NONE);
    expected.write_u64(2);
    expected.write_opaque(b"owner", 1024).unwrap();
    expected.write_u32(1); // OPEN4_CREATE
    expected.write_u32(3); // EXCLUSIVE4_1
    expected.write_fixed_opaque(&[3; 8]);
    expected.write_u32(2); // bitmap words
    expected.write_u32(0);
    expected.write_u32(1 << (FATTR4_MODE - 32));
    expected
        .write_opaque(&0o600_u32.to_be_bytes(), 64 * 1024 * 1024)
        .unwrap();
    expected.write_u32(2); // CLAIM_DELEGATE_CUR
    stateid.encode(&mut expected).unwrap();
    expected.write_string("delegated.txt", 1024).unwrap();
    assert_eq!(to_bytes(&open).unwrap(), expected.into_bytes());

    assert_eq!(
        to_bytes(&OpenClaim::Previous(OpenDelegationType::Read)).unwrap(),
        vec![0, 0, 0, 1, 0, 0, 0, 1]
    );
    assert_eq!(
        to_bytes(&OpenClaim::DelegatePrevious("old.txt".to_owned())).unwrap(),
        vec![
            0, 0, 0, 3, // CLAIM_DELEGATE_PREV
            0, 0, 0, 7, b'o', b'l', b'd', b'.', b't', b'x', b't', 0,
        ]
    );
    assert_eq!(
        to_bytes(&OpenClaim::CurrentFileHandle).unwrap(),
        vec![0, 0, 0, 4]
    );
    let mut expected = Encoder::new();
    expected.write_u32(5); // CLAIM_DELEG_CUR_FH
    stateid.encode(&mut expected).unwrap();
    assert_eq!(
        to_bytes(&OpenClaim::DelegateCurrentFileHandle(stateid)).unwrap(),
        expected.into_bytes()
    );
    assert_eq!(
        to_bytes(&OpenClaim::DelegatePreviousFileHandle).unwrap(),
        vec![0, 0, 0, 6]
    );
}

#[test]
fn decodes_open_write_and_create_results() {
    let mut wire = Encoder::new();
    wire.write_u32(0); // compound status
    wire.write_string("t", 1024).unwrap();
    wire.write_u32(5); // result count
    wire.write_u32(18); // OP_OPEN
    wire.write_u32(0); // status
    wire.write_u32(9); // stateid seqid
    wire.write_fixed_opaque(&[1; 12]);
    wire.write_bool(true); // change_info atomic
    wire.write_u64(1);
    wire.write_u64(2);
    wire.write_u32(0); // result flags
    wire.write_u32(0); // attrset bitmap
    wire.write_u32(0); // OPEN_DELEGATE_NONE
    wire.write_u32(38); // OP_WRITE
    wire.write_u32(0);
    wire.write_u32(3);
    wire.write_u32(2); // FILE_SYNC4
    wire.write_fixed_opaque(&[8; 8]);
    wire.write_u32(6); // OP_CREATE
    wire.write_u32(0);
    wire.write_bool(true);
    wire.write_u64(3);
    wire.write_u64(4);
    wire.write_u32(0); // attrset bitmap
    wire.write_u32(10); // OP_GETFH
    wire.write_u32(0);
    wire.write_opaque(&[7, 8, 9], 128).unwrap();
    wire.write_u32(27); // OP_READLINK
    wire.write_u32(0);
    wire.write_string("target", 1024).unwrap();

    let bytes = wire.into_bytes();
    let mut decoder = Decoder::new(&bytes);
    let response = CompoundResponse::decode(&mut decoder).unwrap();
    decoder.finish().unwrap();

    assert!(matches!(
        &response.results[0],
        OperationResult::Open {
            status: Status::Ok,
            result: Some(result),
        } if result.stateid.seqid == 9 && result.stateid.other == [1; 12]
    ));
    assert!(matches!(
        &response.results[1],
        OperationResult::Write {
            status: Status::Ok,
            result: Some(result),
        } if result.count == 3
            && result.committed == StableHow::FileSync
            && result.verifier == [8; 8]
    ));
    assert!(matches!(
        &response.results[2],
        OperationResult::StatusOnly {
            op,
            status: Status::Ok,
        } if op.name() == "CREATE"
    ));
    assert!(matches!(
        &response.results[3],
        OperationResult::GetFh {
            handle: Some(handle),
            ..
        } if handle.as_bytes() == [7, 8, 9]
    ));
    assert!(matches!(
        &response.results[4],
        OperationResult::ReadLink {
            status: Status::Ok,
            data: Some(target),
        } if target == "target"
    ));
}

#[test]
fn decodes_access_result() {
    let mut wire = Encoder::new();
    wire.write_u32(0); // compound status
    wire.write_string("t", 1024).unwrap();
    wire.write_u32(1); // result count
    wire.write_u32(3); // OP_ACCESS
    wire.write_u32(0); // status
    wire.write_u32(ACCESS4_READ | ACCESS4_LOOKUP); // supported
    wire.write_u32(ACCESS4_READ); // access

    let bytes = wire.into_bytes();
    let mut decoder = Decoder::new(&bytes);
    let response = CompoundResponse::decode(&mut decoder).unwrap();
    decoder.finish().unwrap();

    assert!(matches!(
        response.results.first(),
        Some(OperationResult::Access {
            status: Status::Ok,
            result: Some(result),
        }) if result.supported == (ACCESS4_READ | ACCESS4_LOOKUP)
            && result.access == ACCESS4_READ
    ));
}

#[test]
fn decodes_link_result() {
    let mut wire = Encoder::new();
    wire.write_u32(0); // compound status
    wire.write_string("t", 1024).unwrap();
    wire.write_u32(1); // result count
    wire.write_u32(11); // OP_LINK
    wire.write_u32(0); // status
    wire.write_bool(true); // change_info atomic
    wire.write_u64(1);
    wire.write_u64(2);

    let bytes = wire.into_bytes();
    let mut decoder = Decoder::new(&bytes);
    let response = CompoundResponse::decode(&mut decoder).unwrap();
    decoder.finish().unwrap();

    assert!(matches!(
        response.results.first(),
        Some(OperationResult::StatusOnly {
            op,
            status: Status::Ok,
        }) if *op == OpCode::Link
    ));
}

#[test]
fn decodes_failed_setattr_without_success_bitmap() {
    let mut wire = Encoder::new();
    wire.write_u32(Status::AttrNotSupp.as_u32());
    wire.write_string("t", 1024).unwrap();
    wire.write_u32(1); // result count
    wire.write_u32(OpCode::SetAttr.as_u32());
    wire.write_u32(Status::AttrNotSupp.as_u32());

    let bytes = wire.into_bytes();
    let mut decoder = Decoder::new(&bytes);
    let response = CompoundResponse::decode(&mut decoder).unwrap();
    decoder.finish().unwrap();

    assert!(matches!(
        response.results.first(),
        Some(OperationResult::StatusOnly {
            op: OpCode::SetAttr,
            status: Status::AttrNotSupp,
        })
    ));
}

#[test]
fn decodes_commit_result() {
    let mut wire = Encoder::new();
    wire.write_u32(0); // compound status
    wire.write_string("t", 1024).unwrap();
    wire.write_u32(1); // result count
    wire.write_u32(5); // OP_COMMIT
    wire.write_u32(0); // status
    wire.write_fixed_opaque(&[9; 8]);

    let bytes = wire.into_bytes();
    let mut decoder = Decoder::new(&bytes);
    let response = CompoundResponse::decode(&mut decoder).unwrap();
    decoder.finish().unwrap();

    assert!(matches!(
        response.results.first(),
        Some(OperationResult::Commit {
            status: Status::Ok,
            result: Some(result),
        }) if result.verifier == [9; 8]
    ));
}

#[test]
fn decodes_seek_result() {
    let mut wire = Encoder::new();
    wire.write_u32(0); // compound status
    wire.write_string("t", 1024).unwrap();
    wire.write_u32(1); // result count
    wire.write_u32(69); // OP_SEEK
    wire.write_u32(0); // status
    wire.write_bool(false); // not EOF
    wire.write_u64(4096);

    let bytes = wire.into_bytes();
    let mut decoder = Decoder::new(&bytes);
    let response = CompoundResponse::decode(&mut decoder).unwrap();
    decoder.finish().unwrap();

    assert!(matches!(
        response.results.first(),
        Some(OperationResult::Seek {
            status: Status::Ok,
            result: Some(result),
        }) if *result == (SeekResult { eof: false, offset: 4096 })
            && result.found_offset() == Some(4096)
    ));

    assert_eq!(
        SeekResult {
            eof: true,
            offset: 8192
        }
        .found_offset(),
        None
    );
}

#[test]
fn decodes_v42_data_range_results() {
    let mut wire = Encoder::new();
    wire.write_u32(0); // compound status
    wire.write_string("t", 1024).unwrap();
    wire.write_u32(5); // result count

    wire.write_u32(63); // OP_IO_ADVISE
    wire.write_u32(0); // status
    bitmap(&[IoAdviceType::Sequential.as_u32()])
        .encode(&mut wire)
        .unwrap();

    wire.write_u32(68); // OP_READ_PLUS
    wire.write_u32(0); // status
    wire.write_bool(true); // eof
    wire.write_u32(2); // content count
    wire.write_u32(0); // NFS4_CONTENT_DATA
    wire.write_u64(1024);
    wire.write_opaque(b"data", 1024).unwrap();
    wire.write_u32(1); // NFS4_CONTENT_HOLE
    wire.write_u64(2048);
    wire.write_u64(4096);

    wire.write_u32(60); // OP_COPY
    wire.write_u32(0); // status
    wire.write_u32(1); // callback id present
    wire.write_u32(9);
    wire.write_fixed_opaque(&[10; 12]);
    wire.write_u64(8192);
    wire.write_u32(StableHow::FileSync.as_u32());
    wire.write_fixed_opaque(&[11; 8]);
    wire.write_bool(true); // consecutive required
    wire.write_bool(false); // synchronous required

    wire.write_u32(61); // OP_COPY_NOTIFY
    wire.write_u32(0); // status
    wire.write_i64(12);
    wire.write_u32(13);
    wire.write_u32(14);
    wire.write_fixed_opaque(&[15; 12]);
    wire.write_u32(1); // source server count
    wire.write_u32(2); // NL4_URL
    wire.write_string("nfs://source/export", 1024).unwrap();

    wire.write_u32(70); // OP_WRITE_SAME
    wire.write_u32(0); // status
    wire.write_u32(0); // no callback id
    wire.write_u64(4096);
    wire.write_u32(StableHow::DataSync.as_u32());
    wire.write_fixed_opaque(&[16; 8]);

    let bytes = wire.into_bytes();
    let mut decoder = Decoder::new(&bytes);
    let response = CompoundResponse::decode(&mut decoder).unwrap();
    decoder.finish().unwrap();

    assert!(matches!(
        response.results.first(),
        Some(OperationResult::IoAdvise {
            status: Status::Ok,
            result: Some(result),
        }) if result.hints.contains(IoAdviceType::Sequential.as_u32())
    ));
    assert!(matches!(
        response.results.get(1),
        Some(OperationResult::ReadPlus {
            status: Status::Ok,
            result: Some(result),
        }) if result.eof
            && result.contents
                == vec![
                    ReadPlusContent::Data {
                        offset: 1024,
                        data: b"data".to_vec(),
                    },
                    ReadPlusContent::Hole {
                        offset: 2048,
                        length: 4096,
                    },
                ]
    ));
    assert!(matches!(
        response.results.get(2),
        Some(OperationResult::Copy {
            status: Status::Ok,
            result: Some(result),
        }) if result.response
            == Some(WriteResponse {
                callback_id: Some(StateId {
                    seqid: 9,
                    other: [10; 12],
                }),
                count: 8192,
                committed: StableHow::FileSync,
                verifier: [11; 8],
            })
            && result.requirements
                == Some(CopyRequirements {
                    consecutive: true,
                    synchronous: false,
                })
    ));
    assert!(matches!(
        response.results.get(3),
        Some(OperationResult::CopyNotify {
            status: Status::Ok,
            result: Some(result),
        }) if result.lease_time == NfsTime {
                seconds: 12,
                nseconds: 13,
            }
            && result.stateid
                == StateId {
                    seqid: 14,
                    other: [15; 12],
                }
            && result.source_servers == [NetLoc::Url("nfs://source/export".to_owned())]
    ));
    assert!(matches!(
        response.results.get(4),
        Some(OperationResult::WriteSame {
            status: Status::Ok,
            result: Some(result),
        }) if result.callback_id.is_none()
            && result.count == 4096
            && result.committed == StableHow::DataSync
            && result.verifier == [16; 8]
    ));
}

#[test]
fn rejects_unknown_read_plus_content_arm() {
    let mut wire = Encoder::new();
    wire.write_u32(0); // compound status
    wire.write_string("t", 1024).unwrap();
    wire.write_u32(1); // result count
    wire.write_u32(OpCode::ReadPlus.as_u32());
    wire.write_u32(Status::Ok.as_u32());
    wire.write_bool(false); // eof
    wire.write_u32(1); // content count
    wire.write_u32(99); // unknown data_content4 arm

    let bytes = wire.into_bytes();
    let mut decoder = Decoder::new(&bytes);
    assert!(matches!(
        CompoundResponse::decode(&mut decoder),
        Err(nfs::xdr::Error::InvalidDiscriminant {
            type_name: "data_content4",
            value: 99,
        })
    ));
}

#[test]
fn decodes_v41_security_session_and_offload_results() {
    let mut wire = Encoder::new();
    wire.write_u32(0); // compound status
    wire.write_string("t", 1024).unwrap();
    wire.write_u32(4); // result count

    wire.write_u32(33); // OP_SECINFO
    wire.write_u32(0); // status
    wire.write_u32(3); // flavor count
    wire.write_u32(AUTH_NONE);
    wire.write_u32(AUTH_SYS);
    wire.write_u32(RPCSEC_GSS);
    wire.write_opaque(&[1, 2, 3], 1024).unwrap();
    wire.write_u32(0); // qop
    wire.write_u32(RPC_GSS_SVC_PRIVACY);

    wire.write_u32(41); // OP_BIND_CONN_TO_SESSION
    wire.write_u32(0); // status
    wire.write_fixed_opaque(&[9; 16]);
    wire.write_u32(ChannelDirFromServer::Both.as_u32());
    wire.write_bool(false);

    wire.write_u32(67); // OP_OFFLOAD_STATUS
    wire.write_u32(0); // status
    wire.write_u64(4096);
    wire.write_u32(1); // optional completion status present
    wire.write_u32(Status::Ok.as_u32());

    wire.write_u32(52); // OP_SECINFO_NO_NAME
    wire.write_u32(0); // status
    wire.write_u32(1); // flavor count
    wire.write_u32(AUTH_SYS);

    let bytes = wire.into_bytes();
    let mut decoder = Decoder::new(&bytes);
    let response = CompoundResponse::decode(&mut decoder).unwrap();
    decoder.finish().unwrap();

    assert!(matches!(
        response.results.first(),
        Some(OperationResult::SecInfo {
            op: OpCode::SecInfo,
            status: Status::Ok,
            flavors,
        }) if flavors
            == &[
                SecInfo::AuthNone,
                SecInfo::AuthSys,
                SecInfo::RpcSecGss {
                    oid: vec![1, 2, 3],
                    qop: 0,
                    service: RpcGssService::Privacy,
                },
            ]
    ));
    assert!(matches!(
        response.results.get(1),
        Some(OperationResult::BindConnToSession {
            status: Status::Ok,
            result: Some(BindConnToSessionResult {
                session_id,
                direction: ChannelDirFromServer::Both,
                use_conn_in_rdma_mode: false,
            }),
        }) if *session_id == [9; 16]
    ));
    assert!(matches!(
        response.results.get(2),
        Some(OperationResult::OffloadStatus {
            status: Status::Ok,
            result: Some(result),
        }) if result.count == 4096 && result.complete == Some(Status::Ok)
    ));
    assert!(matches!(
        response.results.get(3),
        Some(OperationResult::SecInfo {
            op: OpCode::SecInfoNoName,
            status: Status::Ok,
            flavors,
        }) if flavors == &[SecInfo::AuthSys]
    ));
}

#[test]
fn decodes_v40_v41_pnfs_delegation_and_ssv_results() {
    let stateid = StateId {
        seqid: 3,
        other: [4; 12],
    };
    let device_id = [7; 16];

    let mut wire = Encoder::new();
    wire.write_u32(0); // compound status
    wire.write_string("t", 1024).unwrap();
    wire.write_u32(11); // result count

    wire.write_u32(35); // OP_SETCLIENTID
    wire.write_u32(0); // status
    wire.write_u64(0x0102_0304_0506_0708);
    wire.write_fixed_opaque(&[1; 8]);

    wire.write_u32(46); // OP_GET_DIR_DELEGATION
    wire.write_u32(0); // status
    wire.write_u32(GDD4_OK);
    wire.write_fixed_opaque(&[2; 8]);
    stateid.encode(&mut wire).unwrap();
    bitmap(&[1]).encode(&mut wire).unwrap();
    bitmap(&[FATTR4_SIZE]).encode(&mut wire).unwrap();
    bitmap(&[FATTR4_CHANGE]).encode(&mut wire).unwrap();

    wire.write_u32(47); // OP_GETDEVICEINFO
    wire.write_u32(0); // status
    wire.write_u32(LAYOUT4_NFSV4_1_FILES);
    wire.write_opaque(b"addr", 64 * 1024 * 1024).unwrap();
    bitmap(&[0]).encode(&mut wire).unwrap();

    wire.write_u32(47); // OP_GETDEVICEINFO
    wire.write_u32(Status::TooSmall.as_u32());
    wire.write_u32(8192);

    wire.write_u32(48); // OP_GETDEVICELIST
    wire.write_u32(0); // status
    wire.write_u64(99);
    wire.write_fixed_opaque(&[3; 8]);
    wire.write_u32(1); // device ids
    wire.write_fixed_opaque(&device_id);
    wire.write_bool(true);

    wire.write_u32(49); // OP_LAYOUTCOMMIT
    wire.write_u32(0); // status
    wire.write_bool(true);
    wire.write_u64(1234);

    wire.write_u32(50); // OP_LAYOUTGET
    wire.write_u32(0); // status
    wire.write_bool(false);
    stateid.encode(&mut wire).unwrap();
    wire.write_u32(1); // layout count
    wire.write_u64(10);
    wire.write_u64(20);
    wire.write_u32(LAYOUTIOMODE4_RW);
    wire.write_u32(LAYOUT4_NFSV4_1_FILES);
    wire.write_opaque(b"layout-body", 64 * 1024 * 1024).unwrap();

    wire.write_u32(50); // OP_LAYOUTGET
    wire.write_u32(Status::LayoutTryLater.as_u32());
    wire.write_bool(true);

    wire.write_u32(51); // OP_LAYOUTRETURN
    wire.write_u32(0); // status
    wire.write_bool(true);
    wire.write_u32(8);
    wire.write_fixed_opaque(&[9; 12]);

    wire.write_u32(54); // OP_SET_SSV
    wire.write_u32(0); // status
    wire.write_opaque(b"digest", 1024).unwrap();

    wire.write_u32(56); // OP_WANT_DELEGATION
    wire.write_u32(0); // status
    wire.write_u32(OpenDelegationType::Read.as_u32());
    wire.write_u32(10);
    wire.write_fixed_opaque(&[11; 12]);
    wire.write_bool(false);
    wire.write_u32(0); // ace type
    wire.write_u32(0); // ace flag
    wire.write_u32(ACCESS4_READ);
    wire.write_string("OWNER@", 1024).unwrap();

    let bytes = wire.into_bytes();
    let mut decoder = Decoder::new(&bytes);
    let response = CompoundResponse::decode(&mut decoder).unwrap();
    decoder.finish().unwrap();

    assert!(matches!(
        response.results.first(),
        Some(OperationResult::SetClientId {
            status: Status::Ok,
            result: Some(result),
            client_using: None,
        }) if result.client_id == 0x0102_0304_0506_0708 && result.verifier == [1; 8]
    ));
    assert!(matches!(
        response.results.get(1),
        Some(OperationResult::GetDirDelegation {
            status: Status::Ok,
            result:
                Some(GetDirDelegationResult::Granted {
                    cookieverf,
                    stateid: delegated,
                    notification,
                    child_attributes,
                    dir_attributes,
                }),
        }) if *cookieverf == [2; 8]
            && *delegated == stateid
            && notification.contains(1)
            && child_attributes.contains(FATTR4_SIZE)
            && dir_attributes.contains(FATTR4_CHANGE)
    ));
    assert!(matches!(
        response.results.get(2),
        Some(OperationResult::GetDeviceInfo {
            status: Status::Ok,
            result: Some(result),
            min_count: None,
        }) if result.device_addr.layout_type == LayoutType::NfsV4_1Files
            && result.device_addr.body == b"addr"
            && result.notification.contains(0)
    ));
    assert!(matches!(
        response.results.get(3),
        Some(OperationResult::GetDeviceInfo {
            status: Status::TooSmall,
            result: None,
            min_count: Some(8192),
        })
    ));
    assert!(matches!(
        response.results.get(4),
        Some(OperationResult::GetDeviceList {
            status: Status::Ok,
            result: Some(result),
        }) if result.cookie == 99
            && result.cookieverf == [3; 8]
            && result.device_ids == vec![device_id]
            && result.eof
    ));
    assert!(matches!(
        response.results.get(5),
        Some(OperationResult::LayoutCommit {
            status: Status::Ok,
            result: Some(LayoutCommitResult {
                new_size: Some(1234),
            }),
        })
    ));
    assert!(matches!(
        response.results.get(6),
        Some(OperationResult::LayoutGet {
            status: Status::Ok,
            result: Some(result),
            will_signal_layout_avail: None,
        }) if !result.return_on_close
            && result.stateid == stateid
            && result.layouts.len() == 1
            && result.layouts[0].offset == 10
            && result.layouts[0].length == 20
            && result.layouts[0].iomode == LayoutIomode::ReadWrite
            && result.layouts[0].content.body == b"layout-body"
    ));
    assert!(matches!(
        response.results.get(7),
        Some(OperationResult::LayoutGet {
            status: Status::LayoutTryLater,
            result: None,
            will_signal_layout_avail: Some(true),
        })
    ));
    assert!(matches!(
        response.results.get(8),
        Some(OperationResult::LayoutReturn {
            status: Status::Ok,
            result: Some(LayoutReturnResult {
                stateid: Some(StateId { seqid: 8, other }),
            }),
        }) if *other == [9; 12]
    ));
    assert!(matches!(
        response.results.get(9),
        Some(OperationResult::SetSsv {
            status: Status::Ok,
            result: Some(SetSsvResult { digest }),
        }) if digest == b"digest"
    ));
    assert!(matches!(
        response.results.get(10),
        Some(OperationResult::WantDelegation {
            status: Status::Ok,
            delegation: Some(OpenDelegation::Read(delegation)),
        }) if delegation.stateid.seqid == 10
            && delegation.stateid.other == [11; 12]
            && !delegation.recall
            && delegation.permissions.who == "OWNER@"
    ));
}

#[test]
fn decodes_v41_state_results() {
    let mut wire = Encoder::new();
    wire.write_u32(0); // compound status
    wire.write_string("t", 1024).unwrap();
    wire.write_u32(3); // result count

    wire.write_u32(21); // OP_OPEN_DOWNGRADE
    wire.write_u32(0); // status
    wire.write_u32(3);
    wire.write_fixed_opaque(&[4; 12]);

    wire.write_u32(20); // OP_OPEN_CONFIRM
    wire.write_u32(0); // status
    wire.write_u32(5);
    wire.write_fixed_opaque(&[6; 12]);

    wire.write_u32(55); // OP_TEST_STATEID
    wire.write_u32(0); // status
    wire.write_u32(2); // status count
    wire.write_u32(Status::Ok.as_u32());
    wire.write_u32(Status::BadStateId.as_u32());

    let bytes = wire.into_bytes();
    let mut decoder = Decoder::new(&bytes);
    let response = CompoundResponse::decode(&mut decoder).unwrap();
    decoder.finish().unwrap();

    assert!(matches!(
        response.results.first(),
        Some(OperationResult::OpenDowngrade {
            status: Status::Ok,
            stateid: Some(StateId { seqid: 3, other }),
        }) if *other == [4; 12]
    ));
    assert!(matches!(
        response.results.get(1),
        Some(OperationResult::OpenConfirm {
            status: Status::Ok,
            stateid: Some(StateId { seqid: 5, other }),
        }) if *other == [6; 12]
    ));
    assert!(matches!(
        response.results.get(2),
        Some(OperationResult::TestStateIds {
            status: Status::Ok,
            statuses,
        }) if statuses == &[Status::Ok, Status::BadStateId]
    ));
}

#[test]
fn decodes_v4_lock_results() {
    let mut wire = Encoder::new();
    wire.write_u32(0); // compound status
    wire.write_string("t", 1024).unwrap();
    wire.write_u32(3); // result count

    wire.write_u32(12); // OP_LOCK
    wire.write_u32(0); // status
    wire.write_u32(7);
    wire.write_fixed_opaque(&[8; 12]);

    wire.write_u32(13); // OP_LOCKT
    wire.write_u32(Status::Denied.as_u32());
    wire.write_u64(1024);
    wire.write_u64(4096);
    wire.write_u32(LockType::Write.as_u32());
    wire.write_u64(0x0102_0304_0506_0708);
    wire.write_opaque(b"owner", 1024).unwrap();

    wire.write_u32(14); // OP_LOCKU
    wire.write_u32(0); // status
    wire.write_u32(9);
    wire.write_fixed_opaque(&[10; 12]);

    let bytes = wire.into_bytes();
    let mut decoder = Decoder::new(&bytes);
    let response = CompoundResponse::decode(&mut decoder).unwrap();
    decoder.finish().unwrap();

    assert!(matches!(
        response.results.first(),
        Some(OperationResult::Lock {
            status: Status::Ok,
            stateid: Some(StateId { seqid: 7, other }),
            denied: None,
        }) if *other == [8; 12]
    ));
    assert!(matches!(
        response.results.get(1),
        Some(OperationResult::LockTest {
            status: Status::Denied,
            denied: Some(denied),
        }) if denied.offset == 1024
            && denied.length == 4096
            && denied.lock_type == LockType::Write
            && denied.owner.client_id == 0x0102_0304_0506_0708
            && denied.owner.owner == b"owner"
    ));
    assert!(matches!(
        response.results.get(2),
        Some(OperationResult::LockUnlock {
            status: Status::Ok,
            stateid: Some(StateId { seqid: 9, other }),
        }) if *other == [10; 12]
    ));
}

#[test]
fn compound_error_reports_failing_v4_operation() {
    let response = CompoundResponse {
        status: Status::NoEnt,
        tag: "t".to_owned(),
        results: vec![OperationResult::StatusOnly {
            op: OpCode::Lookup,
            status: Status::NoEnt,
        }],
    };

    let err = response.ensure_ok().unwrap_err();
    assert!(matches!(
        err,
        Error::NfsV4 {
            operation: "LOOKUP",
            status: Status::NoEnt,
        }
    ));
}

#[test]
fn decodes_status_only_known_operation_errors_by_opcode() {
    let mut wire = Encoder::new();
    wire.write_u32(Status::BadStateId.as_u32());
    wire.write_string("t", 1024).unwrap();
    wire.write_u32(1);
    wire.write_u32(OpCode::BackchannelCtl.as_u32());
    wire.write_u32(Status::BadStateId.as_u32());

    let bytes = wire.into_bytes();
    let mut decoder = Decoder::new(&bytes);
    let response = CompoundResponse::decode(&mut decoder).unwrap();
    decoder.finish().unwrap();

    assert!(matches!(
        response.results.first(),
        Some(OperationResult::StatusOnly {
            op: OpCode::BackchannelCtl,
            status: Status::BadStateId,
        })
    ));
    let err = response.ensure_ok().unwrap_err();
    assert!(matches!(
        err,
        Error::NfsV4 {
            operation: "BACKCHANNEL_CTL",
            status: Status::BadStateId,
        }
    ));
}

#[test]
fn rejects_oversized_v4_file_handles() {
    assert!(FileHandle::new(vec![0; 129]).is_err());
}
