#![cfg(feature = "protocol")]

use nfs::v4::protocol::*;
use nfs::xdr::to_bytes;

fn bitmap(attrs: &[u32]) -> Bitmap {
    Bitmap::from_attrs(attrs).unwrap()
}

#[test]
fn rfc7530_8881_7862_program_constants_match_spec() {
    assert_eq!(NFS4_PROGRAM, 100003);
    assert_eq!(NFS4_VERSION, 4);
    assert_eq!(NFS4_PORT, 2049);
    assert_eq!(NFS4_MINOR_VERSION_SESSION_MIN, 1);
    assert_eq!(NFS4_MINOR_VERSION_V42, 2);
    assert_eq!(NFS4_MINOR_VERSION_LATEST, 2);
    assert_eq!(NFS4_FHSIZE, 128);
    assert_eq!(NFS4_VERIFIER_SIZE, 8);
    assert_eq!(NFS4_SESSIONID_SIZE, 16);
    assert_eq!(NFS4_DEVICEID_SIZE, 16);
    assert_eq!(NFS4_OPAQUE_LIMIT, 1024);
    assert_eq!(NFS4_NSECONDS_PER_SECOND, 1_000_000_000);
    assert_eq!(NFS4_MAX_SECINFO_FLAVORS, 128);
    assert_eq!(NFS4_MAX_NETLOCATIONS, 128);
    assert_eq!(NFS4_MAX_CALLBACK_SEC_PARMS, 16);
    assert_eq!(NFS4_INT64_MAX, 0x7fff_ffff_ffff_ffff);
    assert_eq!(NFS4_UINT64_MAX, 0xffff_ffff_ffff_ffff);
    assert_eq!(NFS4_INT32_MAX, 0x7fff_ffff);
    assert_eq!(NFS4_UINT32_MAX, 0xffff_ffff);
    assert_eq!(NFS4_MAXFILELEN, 0xffff_ffff_ffff_ffff);
    assert_eq!(NFS4_MAXFILEOFF, 0xffff_ffff_ffff_fffe);
}

#[test]
fn rfc7530_access_and_file_type_constants_match_spec() {
    assert_eq!(ACCESS4_READ, 0x0001);
    assert_eq!(ACCESS4_LOOKUP, 0x0002);
    assert_eq!(ACCESS4_MODIFY, 0x0004);
    assert_eq!(ACCESS4_EXTEND, 0x0008);
    assert_eq!(ACCESS4_DELETE, 0x0010);
    assert_eq!(ACCESS4_EXECUTE, 0x0020);

    assert_eq!(OPEN4_SHARE_ACCESS_READ, 0x0000_0001);
    assert_eq!(OPEN4_SHARE_ACCESS_WRITE, 0x0000_0002);
    assert_eq!(OPEN4_SHARE_ACCESS_BOTH, 0x0000_0003);
    assert_eq!(OPEN4_SHARE_ACCESS_WANT_DELEG_MASK, 0x0000_ff00);
    assert_eq!(OPEN4_SHARE_ACCESS_WANT_NO_PREFERENCE, 0x0000_0000);
    assert_eq!(OPEN4_SHARE_ACCESS_WANT_READ_DELEG, 0x0000_0100);
    assert_eq!(OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG, 0x0000_0200);
    assert_eq!(OPEN4_SHARE_ACCESS_WANT_ANY_DELEG, 0x0000_0300);
    assert_eq!(OPEN4_SHARE_ACCESS_WANT_NO_DELEG, 0x0000_0400);
    assert_eq!(OPEN4_SHARE_ACCESS_WANT_CANCEL, 0x0000_0500);
    assert_eq!(
        OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL,
        0x0001_0000
    );
    assert_eq!(
        OPEN4_SHARE_ACCESS_WANT_PUSH_DELEG_WHEN_UNCONTENDED,
        0x0002_0000
    );
    assert_eq!(OPEN4_SHARE_DENY_NONE, 0);
    assert_eq!(OPEN4_SHARE_DENY_READ, 0x0000_0001);
    assert_eq!(OPEN4_SHARE_DENY_WRITE, 0x0000_0002);
    assert_eq!(OPEN4_SHARE_DENY_BOTH, 0x0000_0003);

    assert_eq!(OPEN4_RESULT_CONFIRM, 0x0000_0002);
    assert_eq!(OPEN4_RESULT_LOCKTYPE_POSIX, 0x0000_0004);
    assert_eq!(OPEN4_RESULT_PRESERVE_UNLINKED, 0x0000_0008);
    assert_eq!(OPEN4_RESULT_MAY_NOTIFY_LOCK, 0x0000_0020);

    assert_eq!(EXCHGID4_FLAG_SUPP_MOVED_REFER, 0x0000_0001);
    assert_eq!(EXCHGID4_FLAG_SUPP_MOVED_MIGR, 0x0000_0002);
    assert_eq!(EXCHGID4_FLAG_BIND_PRINC_STATEID, 0x0000_0100);
    assert_eq!(EXCHGID4_FLAG_USE_NON_PNFS, 0x0001_0000);
    assert_eq!(EXCHGID4_FLAG_USE_PNFS_MDS, 0x0002_0000);
    assert_eq!(EXCHGID4_FLAG_USE_PNFS_DS, 0x0004_0000);
    assert_eq!(EXCHGID4_FLAG_MASK_PNFS, 0x0007_0000);
    assert_eq!(EXCHGID4_FLAG_UPD_CONFIRMED_REC_A, 0x4000_0000);
    assert_eq!(EXCHGID4_FLAG_CONFIRMED_R, 0x8000_0000);

    assert_eq!(CREATE_SESSION4_FLAG_PERSIST, 0x0000_0001);
    assert_eq!(CREATE_SESSION4_FLAG_CONN_BACK_CHAN, 0x0000_0002);
    assert_eq!(CREATE_SESSION4_FLAG_CONN_RDMA, 0x0000_0004);

    assert_eq!(LAYOUT4_NFSV4_1_FILES, 1);
    assert_eq!(LAYOUT4_OSD2_OBJECTS, 2);
    assert_eq!(LAYOUT4_BLOCK_VOLUME, 3);
    assert_eq!(LAYOUTIOMODE4_READ, 1);
    assert_eq!(LAYOUTIOMODE4_RW, 2);
    assert_eq!(LAYOUTIOMODE4_ANY, 3);
    assert_eq!(LAYOUTRETURN4_FILE, 1);
    assert_eq!(LAYOUTRETURN4_FSID, 2);
    assert_eq!(LAYOUTRETURN4_ALL, 3);
    assert_eq!(GDD4_OK, 0);
    assert_eq!(GDD4_UNAVAIL, 1);

    assert_eq!(SEQ4_STATUS_CB_PATH_DOWN, 0x0000_0001);
    assert_eq!(SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRING, 0x0000_0002);
    assert_eq!(SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRED, 0x0000_0004);
    assert_eq!(SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED, 0x0000_0008);
    assert_eq!(SEQ4_STATUS_EXPIRED_SOME_STATE_REVOKED, 0x0000_0010);
    assert_eq!(SEQ4_STATUS_ADMIN_STATE_REVOKED, 0x0000_0020);
    assert_eq!(SEQ4_STATUS_RECALLABLE_STATE_REVOKED, 0x0000_0040);
    assert_eq!(SEQ4_STATUS_LEASE_MOVED, 0x0000_0080);
    assert_eq!(SEQ4_STATUS_RESTART_RECLAIM_NEEDED, 0x0000_0100);
    assert_eq!(SEQ4_STATUS_CB_PATH_DOWN_SESSION, 0x0000_0200);
    assert_eq!(SEQ4_STATUS_BACKCHANNEL_FAULT, 0x0000_0400);
    assert_eq!(SEQ4_STATUS_DEVID_CHANGED, 0x0000_0800);
    assert_eq!(SEQ4_STATUS_DEVID_DELETED, 0x0000_1000);

    assert_eq!(AUTH_NONE, 0);
    assert_eq!(AUTH_SYS, 1);
    assert_eq!(RPCSEC_GSS, 6);
    assert_eq!(RPC_GSS_SVC_NONE, 1);
    assert_eq!(RPC_GSS_SVC_INTEGRITY, 2);
    assert_eq!(RPC_GSS_SVC_PRIVACY, 3);

    assert_eq!(NF4REG, 1);
    assert_eq!(NF4DIR, 2);
    assert_eq!(NF4BLK, 3);
    assert_eq!(NF4CHR, 4);
    assert_eq!(NF4LNK, 5);
    assert_eq!(NF4SOCK, 6);
    assert_eq!(NF4FIFO, 7);
}

#[test]
fn rfc7530_8881_7862_attribute_numbers_match_spec() {
    let attrs = [
        (FATTR4_SUPPORTED_ATTRS, 0),
        (FATTR4_TYPE, 1),
        (FATTR4_FH_EXPIRE_TYPE, 2),
        (FATTR4_CHANGE, 3),
        (FATTR4_SIZE, 4),
        (FATTR4_LINK_SUPPORT, 5),
        (FATTR4_SYMLINK_SUPPORT, 6),
        (FATTR4_NAMED_ATTR, 7),
        (FATTR4_FSID, 8),
        (FATTR4_UNIQUE_HANDLES, 9),
        (FATTR4_LEASE_TIME, 10),
        (FATTR4_RDATTR_ERROR, 11),
        (FATTR4_ACL, 12),
        (FATTR4_ACLSUPPORT, 13),
        (FATTR4_ARCHIVE, 14),
        (FATTR4_CANSETTIME, 15),
        (FATTR4_CASE_INSENSITIVE, 16),
        (FATTR4_CASE_PRESERVING, 17),
        (FATTR4_CHOWN_RESTRICTED, 18),
        (FATTR4_FILEHANDLE, 19),
        (FATTR4_FILEID, 20),
        (FATTR4_FILES_AVAIL, 21),
        (FATTR4_FILES_FREE, 22),
        (FATTR4_FILES_TOTAL, 23),
        (FATTR4_FS_LOCATIONS, 24),
        (FATTR4_HIDDEN, 25),
        (FATTR4_HOMOGENEOUS, 26),
        (FATTR4_MAXFILESIZE, 27),
        (FATTR4_MAXLINK, 28),
        (FATTR4_MAXNAME, 29),
        (FATTR4_MAXREAD, 30),
        (FATTR4_MAXWRITE, 31),
        (FATTR4_MIMETYPE, 32),
        (FATTR4_MODE, 33),
        (FATTR4_NO_TRUNC, 34),
        (FATTR4_NUMLINKS, 35),
        (FATTR4_OWNER, 36),
        (FATTR4_OWNER_GROUP, 37),
        (FATTR4_QUOTA_AVAIL_HARD, 38),
        (FATTR4_QUOTA_AVAIL_SOFT, 39),
        (FATTR4_QUOTA_USED, 40),
        (FATTR4_RAWDEV, 41),
        (FATTR4_SPACE_AVAIL, 42),
        (FATTR4_SPACE_FREE, 43),
        (FATTR4_SPACE_TOTAL, 44),
        (FATTR4_SPACE_USED, 45),
        (FATTR4_SYSTEM, 46),
        (FATTR4_TIME_ACCESS, 47),
        (FATTR4_TIME_ACCESS_SET, 48),
        (FATTR4_TIME_BACKUP, 49),
        (FATTR4_TIME_CREATE, 50),
        (FATTR4_TIME_DELTA, 51),
        (FATTR4_TIME_METADATA, 52),
        (FATTR4_TIME_MODIFY, 53),
        (FATTR4_TIME_MODIFY_SET, 54),
        (FATTR4_MOUNTED_ON_FILEID, 55),
        (FATTR4_DIR_NOTIF_DELAY, 56),
        (FATTR4_DIRENT_NOTIF_DELAY, 57),
        (FATTR4_DACL, 58),
        (FATTR4_SACL, 59),
        (FATTR4_CHANGE_POLICY, 60),
        (FATTR4_FS_STATUS, 61),
        (FATTR4_FS_LAYOUT_TYPE, 62),
        (FATTR4_LAYOUT_HINT, 63),
        (FATTR4_LAYOUT_TYPE, 64),
        (FATTR4_LAYOUT_BLKSIZE, 65),
        (FATTR4_LAYOUT_ALIGNMENT, 66),
        (FATTR4_FS_LOCATIONS_INFO, 67),
        (FATTR4_MDSTHRESHOLD, 68),
        (FATTR4_RETENTION_GET, 69),
        (FATTR4_RETENTION_SET, 70),
        (FATTR4_RETENTEVT_GET, 71),
        (FATTR4_RETENTEVT_SET, 72),
        (FATTR4_RETENTION_HOLD, 73),
        (FATTR4_MODE_SET_MASKED, 74),
        (FATTR4_SUPPATTR_EXCLCREAT, 75),
        (FATTR4_FS_CHARSET_CAP, 76),
        (FATTR4_CLONE_BLKSIZE, 77),
        (FATTR4_SPACE_FREED, 78),
        (FATTR4_CHANGE_ATTR_TYPE, 79),
        (FATTR4_SEC_LABEL, 80),
    ];

    for (actual, expected) in attrs {
        assert_eq!(actual, expected);
    }

    assert_eq!(
        FATTR4_BASIC_ATTRS,
        &[
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
        ]
    );
    assert_eq!(
        FATTR4_FSSTAT_ATTRS,
        &[
            FATTR4_FILES_AVAIL,
            FATTR4_FILES_FREE,
            FATTR4_FILES_TOTAL,
            FATTR4_SPACE_AVAIL,
            FATTR4_SPACE_FREE,
            FATTR4_SPACE_TOTAL,
        ]
    );
    assert_eq!(
        FATTR4_PATHCONF_ATTRS,
        &[
            FATTR4_CASE_INSENSITIVE,
            FATTR4_CASE_PRESERVING,
            FATTR4_CHOWN_RESTRICTED,
            FATTR4_MAXLINK,
            FATTR4_MAXNAME,
            FATTR4_NO_TRUNC,
        ]
    );
}

#[test]
fn rfc7530_8881_7862_status_codes_round_trip() {
    let statuses = [
        (0, Status::Ok),
        (1, Status::Perm),
        (2, Status::NoEnt),
        (5, Status::Io),
        (6, Status::Nxio),
        (13, Status::Access),
        (17, Status::Exist),
        (18, Status::Xdev),
        (20, Status::NotDir),
        (21, Status::IsDir),
        (22, Status::Inval),
        (27, Status::Fbig),
        (28, Status::NoSpc),
        (30, Status::ReadOnlyFs),
        (31, Status::Mlink),
        (63, Status::NameTooLong),
        (66, Status::NotEmpty),
        (69, Status::Dquot),
        (70, Status::Stale),
        (10001, Status::BadHandle),
        (10003, Status::BadCookie),
        (10004, Status::NotSupported),
        (10005, Status::TooSmall),
        (10006, Status::ServerFault),
        (10007, Status::BadType),
        (10008, Status::Delay),
        (10009, Status::Same),
        (10010, Status::Denied),
        (10011, Status::Expired),
        (10012, Status::Locked),
        (10013, Status::Grace),
        (10014, Status::FhExpired),
        (10015, Status::ShareDenied),
        (10016, Status::WrongSec),
        (10017, Status::ClidInUse),
        (10018, Status::Resource),
        (10019, Status::Moved),
        (10020, Status::NoFileHandle),
        (10021, Status::MinorVersionMismatch),
        (10022, Status::StaleClientId),
        (10023, Status::StaleStateId),
        (10024, Status::OldStateId),
        (10025, Status::BadStateId),
        (10026, Status::BadSeqId),
        (10027, Status::NotSame),
        (10028, Status::LockRange),
        (10029, Status::Symlink),
        (10030, Status::RestoreFh),
        (10031, Status::LeaseMoved),
        (10032, Status::AttrNotSupp),
        (10033, Status::NoGrace),
        (10034, Status::ReclaimBad),
        (10035, Status::ReclaimConflict),
        (10036, Status::BadXdr),
        (10037, Status::LocksHeld),
        (10038, Status::OpenMode),
        (10039, Status::BadOwner),
        (10040, Status::BadChar),
        (10041, Status::BadName),
        (10042, Status::BadRange),
        (10043, Status::LockNotSupp),
        (10044, Status::OpIllegal),
        (10045, Status::Deadlock),
        (10046, Status::FileOpen),
        (10047, Status::AdminRevoked),
        (10048, Status::CbPathDown),
        (10049, Status::BadIoMode),
        (10050, Status::BadLayout),
        (10051, Status::BadSessionDigest),
        (10052, Status::BadSession),
        (10053, Status::BadSlot),
        (10054, Status::CompleteAlready),
        (10055, Status::ConnNotBoundToSession),
        (10056, Status::DelegAlreadyWanted),
        (10057, Status::BackChanBusy),
        (10058, Status::LayoutTryLater),
        (10059, Status::LayoutUnavailable),
        (10060, Status::NoMatchingLayout),
        (10061, Status::RecallConflict),
        (10062, Status::UnknownLayoutType),
        (10063, Status::SeqMisordered),
        (10064, Status::SequencePos),
        (10065, Status::ReqTooBig),
        (10066, Status::RepTooBig),
        (10067, Status::RepTooBigToCache),
        (10068, Status::RetryUncachedRep),
        (10069, Status::UnsafeCompound),
        (10070, Status::TooManyOps),
        (10071, Status::OpNotInSession),
        (10072, Status::HashAlgUnsupported),
        (10074, Status::ClientIdBusy),
        (10075, Status::PnfsIoHole),
        (10076, Status::SeqFalseRetry),
        (10077, Status::BadHighSlot),
        (10078, Status::DeadSession),
        (10079, Status::EncrAlgUnsupported),
        (10080, Status::PnfsNoLayout),
        (10081, Status::NotOnlyOp),
        (10082, Status::WrongCred),
        (10083, Status::WrongType),
        (10084, Status::DirDelegUnavailable),
        (10085, Status::RejectDeleg),
        (10086, Status::ReturnConflict),
        (10087, Status::DelegRevoked),
        (10088, Status::PartnerNotSupp),
        (10089, Status::PartnerNoAuth),
        (10090, Status::UnionNotSupported),
        (10091, Status::OffloadDenied),
        (10092, Status::WrongLfs),
        (10093, Status::BadLabel),
        (10094, Status::OffloadNoReqs),
    ];

    for (code, status) in statuses {
        assert_eq!(Status::from_u32(code), status);
        assert_eq!(status.as_u32(), code);
    }
    assert_eq!(Status::from_u32(4242), Status::Unknown(4242));
    assert_eq!(Status::Unknown(4242).as_u32(), 4242);
}

#[test]
fn rfc8881_session_and_state_statuses_are_classified() {
    assert!(Status::BadSession.requires_session_recovery());
    assert!(Status::ConnNotBoundToSession.requires_session_recovery());
    assert!(Status::DeadSession.requires_session_recovery());
    assert!(Status::StaleClientId.requires_session_recovery());
    assert!(!Status::BadStateId.requires_session_recovery());
    assert!(Status::Delay.is_retryable());
    assert!(Status::Grace.is_retryable());
    assert!(!Status::BadSession.is_retryable());

    assert!(Status::AdminRevoked.indicates_lost_state());
    assert!(Status::BadStateId.indicates_lost_state());
    assert!(Status::DelegRevoked.indicates_lost_state());
    assert!(Status::Expired.indicates_lost_state());
    assert!(Status::LeaseMoved.indicates_lost_state());
    assert!(Status::NoGrace.indicates_lost_state());
    assert!(Status::OldStateId.indicates_lost_state());
    assert!(Status::ReclaimBad.indicates_lost_state());
    assert!(Status::ReclaimConflict.indicates_lost_state());
    assert!(Status::StaleClientId.indicates_lost_state());
    assert!(Status::StaleStateId.indicates_lost_state());
    assert!(!Status::Delay.indicates_lost_state());
}

#[test]
fn rfc7530_8881_7862_operation_codes_round_trip() {
    let opcodes = [
        (3, OpCode::Access, "ACCESS"),
        (4, OpCode::Close, "CLOSE"),
        (5, OpCode::Commit, "COMMIT"),
        (6, OpCode::Create, "CREATE"),
        (7, OpCode::DelegPurge, "DELEGPURGE"),
        (8, OpCode::DelegReturn, "DELEGRETURN"),
        (9, OpCode::GetAttr, "GETATTR"),
        (10, OpCode::GetFh, "GETFH"),
        (11, OpCode::Link, "LINK"),
        (12, OpCode::Lock, "LOCK"),
        (13, OpCode::Lockt, "LOCKT"),
        (14, OpCode::Locku, "LOCKU"),
        (15, OpCode::Lookup, "LOOKUP"),
        (16, OpCode::Lookupp, "LOOKUPP"),
        (17, OpCode::NVerify, "NVERIFY"),
        (18, OpCode::Open, "OPEN"),
        (19, OpCode::OpenAttr, "OPENATTR"),
        (20, OpCode::OpenConfirm, "OPEN_CONFIRM"),
        (21, OpCode::OpenDowngrade, "OPEN_DOWNGRADE"),
        (22, OpCode::PutFh, "PUTFH"),
        (23, OpCode::PutPubFh, "PUTPUBFH"),
        (24, OpCode::PutRootFh, "PUTROOTFH"),
        (25, OpCode::Read, "READ"),
        (26, OpCode::ReadDir, "READDIR"),
        (27, OpCode::ReadLink, "READLINK"),
        (28, OpCode::Remove, "REMOVE"),
        (29, OpCode::Rename, "RENAME"),
        (30, OpCode::Renew, "RENEW"),
        (31, OpCode::RestoreFh, "RESTOREFH"),
        (32, OpCode::SaveFh, "SAVEFH"),
        (33, OpCode::SecInfo, "SECINFO"),
        (34, OpCode::SetAttr, "SETATTR"),
        (35, OpCode::SetClientId, "SETCLIENTID"),
        (36, OpCode::SetClientIdConfirm, "SETCLIENTID_CONFIRM"),
        (37, OpCode::Verify, "VERIFY"),
        (38, OpCode::Write, "WRITE"),
        (39, OpCode::ReleaseLockOwner, "RELEASE_LOCKOWNER"),
        (40, OpCode::BackchannelCtl, "BACKCHANNEL_CTL"),
        (41, OpCode::BindConnToSession, "BIND_CONN_TO_SESSION"),
        (42, OpCode::ExchangeId, "EXCHANGE_ID"),
        (43, OpCode::CreateSession, "CREATE_SESSION"),
        (44, OpCode::DestroySession, "DESTROY_SESSION"),
        (45, OpCode::FreeStateId, "FREE_STATEID"),
        (46, OpCode::GetDirDelegation, "GET_DIR_DELEGATION"),
        (47, OpCode::GetDeviceInfo, "GETDEVICEINFO"),
        (48, OpCode::GetDeviceList, "GETDEVICELIST"),
        (49, OpCode::LayoutCommit, "LAYOUTCOMMIT"),
        (50, OpCode::LayoutGet, "LAYOUTGET"),
        (51, OpCode::LayoutReturn, "LAYOUTRETURN"),
        (52, OpCode::SecInfoNoName, "SECINFO_NO_NAME"),
        (53, OpCode::Sequence, "SEQUENCE"),
        (54, OpCode::SetSsv, "SET_SSV"),
        (55, OpCode::TestStateId, "TEST_STATEID"),
        (56, OpCode::WantDelegation, "WANT_DELEGATION"),
        (57, OpCode::DestroyClientId, "DESTROY_CLIENTID"),
        (58, OpCode::ReclaimComplete, "RECLAIM_COMPLETE"),
        (59, OpCode::Allocate, "ALLOCATE"),
        (60, OpCode::Copy, "COPY"),
        (61, OpCode::CopyNotify, "COPY_NOTIFY"),
        (62, OpCode::Deallocate, "DEALLOCATE"),
        (63, OpCode::IoAdvise, "IO_ADVISE"),
        (64, OpCode::LayoutError, "LAYOUTERROR"),
        (65, OpCode::LayoutStats, "LAYOUTSTATS"),
        (66, OpCode::OffloadCancel, "OFFLOAD_CANCEL"),
        (67, OpCode::OffloadStatus, "OFFLOAD_STATUS"),
        (68, OpCode::ReadPlus, "READ_PLUS"),
        (69, OpCode::Seek, "SEEK"),
        (70, OpCode::WriteSame, "WRITE_SAME"),
        (71, OpCode::Clone, "CLONE"),
        (10044, OpCode::Illegal, "ILLEGAL"),
    ];

    for (code, opcode, name) in opcodes {
        assert_eq!(OpCode::from_u32(code), Some(opcode));
        assert_eq!(opcode.as_u32(), code);
        assert_eq!(opcode.name(), name);
    }
    assert_eq!(OpCode::from_u32(4242), None);
}

#[test]
fn rfc7530_7862_discriminants_match_spec() {
    assert_eq!(StableHow::Unstable.as_u32(), 0);
    assert_eq!(StableHow::DataSync.as_u32(), 1);
    assert_eq!(StableHow::FileSync.as_u32(), 2);
    assert_eq!(StableHow::from_u32(0), Some(StableHow::Unstable));
    assert_eq!(StableHow::from_u32(1), Some(StableHow::DataSync));
    assert_eq!(StableHow::from_u32(2), Some(StableHow::FileSync));
    assert_eq!(StableHow::from_u32(3), None);

    assert_eq!(SeekContent::Data.as_u32(), 0);
    assert_eq!(SeekContent::Hole.as_u32(), 1);
    assert_eq!(NFS4_CONTENT_DATA, 0);
    assert_eq!(NFS4_CONTENT_HOLE, 1);
    assert_eq!(SeekContent::from_u32(0), Some(SeekContent::Data));
    assert_eq!(SeekContent::from_u32(1), Some(SeekContent::Hole));
    assert_eq!(SeekContent::from_u32(2), None);

    let create_modes = [
        (0, CreateMode::Unchecked),
        (1, CreateMode::Guarded),
        (2, CreateMode::Exclusive),
        (3, CreateMode::Exclusive4_1),
    ];
    for (discriminant, value) in create_modes {
        assert_eq!(value.as_u32(), discriminant);
        assert_eq!(CreateMode::from_u32(discriminant), Some(value));
    }
    assert_eq!(CreateMode::from_u32(4), None);

    assert_eq!(OpenType::NoCreate.as_u32(), 0);
    assert_eq!(OpenType::Create.as_u32(), 1);
    assert_eq!(OpenType::from_u32(0), Some(OpenType::NoCreate));
    assert_eq!(OpenType::from_u32(1), Some(OpenType::Create));
    assert_eq!(OpenType::from_u32(2), None);

    assert_eq!(RpcGssService::None.as_u32(), 1);
    assert_eq!(RpcGssService::Integrity.as_u32(), 2);
    assert_eq!(RpcGssService::Privacy.as_u32(), 3);
    assert_eq!(RpcGssService::Unknown(99).as_u32(), 99);
    assert_eq!(RpcGssService::from_u32(1), RpcGssService::None);
    assert_eq!(RpcGssService::from_u32(2), RpcGssService::Integrity);
    assert_eq!(RpcGssService::from_u32(3), RpcGssService::Privacy);
    assert_eq!(RpcGssService::from_u32(99), RpcGssService::Unknown(99));

    assert_eq!(SecInfoStyle::CurrentFileHandle.as_u32(), 0);
    assert_eq!(SecInfoStyle::Parent.as_u32(), 1);
    assert_eq!(
        SecInfoStyle::from_u32(0),
        Some(SecInfoStyle::CurrentFileHandle)
    );
    assert_eq!(SecInfoStyle::from_u32(1), Some(SecInfoStyle::Parent));
    assert_eq!(SecInfoStyle::from_u32(2), None);

    let client_dirs = [
        (0x1, ChannelDirFromClient::Fore),
        (0x2, ChannelDirFromClient::Back),
        (0x3, ChannelDirFromClient::ForeOrBoth),
        (0x7, ChannelDirFromClient::BackOrBoth),
    ];
    for (discriminant, value) in client_dirs {
        assert_eq!(value.as_u32(), discriminant);
        assert_eq!(ChannelDirFromClient::from_u32(discriminant), Some(value));
    }
    assert_eq!(ChannelDirFromClient::from_u32(0x4), None);

    let server_dirs = [
        (0x1, ChannelDirFromServer::Fore),
        (0x2, ChannelDirFromServer::Back),
        (0x3, ChannelDirFromServer::Both),
    ];
    for (discriminant, value) in server_dirs {
        assert_eq!(value.as_u32(), discriminant);
        assert_eq!(ChannelDirFromServer::from_u32(discriminant), Some(value));
    }
    assert_eq!(ChannelDirFromServer::from_u32(0x7), None);

    let state_protection = [
        (0, StateProtectHow::None),
        (1, StateProtectHow::MachineCredentials),
        (2, StateProtectHow::SecretStateVerifier),
    ];
    for (discriminant, value) in state_protection {
        assert_eq!(value.as_u32(), discriminant);
        assert_eq!(StateProtectHow::from_u32(discriminant), Some(value));
    }
    assert_eq!(StateProtectHow::from_u32(3), None);

    let delegation_types = [
        (0, OpenDelegationType::None),
        (1, OpenDelegationType::Read),
        (2, OpenDelegationType::Write),
        (3, OpenDelegationType::NoneExt),
    ];
    for (discriminant, value) in delegation_types {
        assert_eq!(value.as_u32(), discriminant);
        assert_eq!(OpenDelegationType::from_u32(discriminant), Some(value));
    }
    assert_eq!(OpenDelegationType::from_u32(4), None);

    let claim_types = [
        (0, OpenClaimType::Null),
        (1, OpenClaimType::Previous),
        (2, OpenClaimType::DelegateCurrent),
        (3, OpenClaimType::DelegatePrevious),
        (4, OpenClaimType::FileHandle),
        (5, OpenClaimType::DelegateCurrentFileHandle),
        (6, OpenClaimType::DelegatePreviousFileHandle),
    ];
    for (discriminant, value) in claim_types {
        assert_eq!(value.as_u32(), discriminant);
        assert_eq!(OpenClaimType::from_u32(discriminant), Some(value));
    }
    assert_eq!(OpenClaimType::from_u32(7), None);

    let lock_types = [
        (1, LockType::Read),
        (2, LockType::Write),
        (3, LockType::ReadBlocking),
        (4, LockType::WriteBlocking),
    ];
    for (discriminant, value) in lock_types {
        assert_eq!(value.as_u32(), discriminant);
        assert_eq!(LockType::from_u32(discriminant), Some(value));
    }
    assert_eq!(LockType::from_u32(0), None);
    assert_eq!(LockType::from_u32(5), None);

    let io_advice_types = [
        (0, IoAdviceType::Normal),
        (1, IoAdviceType::Sequential),
        (2, IoAdviceType::SequentialBackwards),
        (3, IoAdviceType::Random),
        (4, IoAdviceType::WillNeed),
        (5, IoAdviceType::WillNeedOpportunistic),
        (6, IoAdviceType::DontNeed),
        (7, IoAdviceType::NoReuse),
        (8, IoAdviceType::Read),
        (9, IoAdviceType::Write),
        (10, IoAdviceType::InitProximity),
    ];
    for (discriminant, value) in io_advice_types {
        assert_eq!(value.as_u32(), discriminant);
        assert_eq!(IoAdviceType::from_u32(discriminant), Some(value));
    }
    assert_eq!(IoAdviceType::from_u32(11), None);

    let change_attr_types = [
        (0, ChangeAttrType::MonotonicIncr),
        (1, ChangeAttrType::VersionCounter),
        (2, ChangeAttrType::VersionCounterNoPnfs),
        (3, ChangeAttrType::TimeMetadata),
        (4, ChangeAttrType::Undefined),
    ];
    for (discriminant, value) in change_attr_types {
        assert_eq!(value.as_u32(), discriminant);
        assert_eq!(ChangeAttrType::from_u32(discriminant), Some(value));
    }
    assert_eq!(ChangeAttrType::from_u32(5), None);

    let file_types = [
        (1, FileType::Regular),
        (2, FileType::Directory),
        (3, FileType::BlockDevice),
        (4, FileType::CharacterDevice),
        (5, FileType::Symlink),
        (6, FileType::Socket),
        (7, FileType::Fifo),
        (8, FileType::AttrDir),
        (9, FileType::NamedAttr),
    ];
    for (code, file_type) in file_types {
        assert_eq!(FileType::from_u32(code), file_type);
    }
    assert_eq!(FileType::from_u32(4242), FileType::Unknown(4242));
}

#[test]
fn rfc8881_bitmap_word_layout_uses_attribute_number_bits() {
    let bitmap = bitmap(&[FATTR4_TYPE, FATTR4_MODE, FATTR4_TIME_MODIFY]);

    assert_eq!(
        bitmap.words(),
        &[
            1 << FATTR4_TYPE,
            (1 << (FATTR4_MODE - 32)) | (1 << (FATTR4_TIME_MODIFY - 32))
        ]
    );
    assert!(bitmap.contains(FATTR4_TYPE));
    assert!(bitmap.contains(FATTR4_MODE));
    assert!(bitmap.contains(FATTR4_TIME_MODIFY));
    assert!(!bitmap.contains(FATTR4_SIZE));
}

#[test]
fn implemented_operation_variants_map_to_spec_opcodes() {
    let handle = FileHandle::new(vec![1, 2, 3]).unwrap();
    let stateid = StateId {
        seqid: 7,
        other: [8; 12],
    };
    let device_id = [9; 16];
    let exchange = ExchangeIdArgs {
        client_owner: ClientOwner {
            verifier: [1; 8],
            owner_id: b"owner".to_vec(),
        },
        flags: 0,
    };
    let create_session = CreateSessionArgs {
        client_id: 1,
        sequence_id: 2,
        flags: 0,
        fore_channel_attrs: ChannelAttrs::fore_channel_default(),
        back_channel_attrs: ChannelAttrs::back_channel_disabled(),
        callback_program: 0,
        callback_sec_parms: Vec::new(),
    };
    let sequence = SequenceArgs {
        session_id: [9; 16],
        sequence_id: 3,
        slot_id: 0,
        highest_slot_id: 0,
        cache_this: false,
    };
    let open = OpenArgs {
        seqid: 1,
        share_access: OPEN4_SHARE_ACCESS_READ,
        share_deny: OPEN4_SHARE_DENY_NONE,
        owner: OpenOwner {
            client_id: 1,
            owner: b"open".to_vec(),
        },
        openhow: OpenHow::NoCreate,
        claim: OpenClaim::Null("file".to_owned()),
    };

    let operations = [
        (
            Operation::SetClientId(SetClientIdArgs {
                client: ClientOwner {
                    verifier: [1; 8],
                    owner_id: b"owner".to_vec(),
                },
                callback: CallbackClient {
                    program: 0,
                    location: NetAddr {
                        netid: "tcp".to_owned(),
                        addr: "127.0.0.1.8.1".to_owned(),
                    },
                },
                callback_ident: 0,
            }),
            OpCode::SetClientId,
        ),
        (
            Operation::SetClientIdConfirm(SetClientIdConfirmArgs {
                client_id: 1,
                verifier: [0; 8],
            }),
            OpCode::SetClientIdConfirm,
        ),
        (Operation::ExchangeId(exchange), OpCode::ExchangeId),
        (
            Operation::CreateSession(create_session),
            OpCode::CreateSession,
        ),
        (
            Operation::BackchannelCtl(BackchannelCtlArgs {
                callback_program: 0,
                callback_sec_parms: Vec::new(),
            }),
            OpCode::BackchannelCtl,
        ),
        (
            Operation::BindConnToSession(BindConnToSessionArgs {
                session_id: [9; 16],
                direction: ChannelDirFromClient::Fore,
                use_conn_in_rdma_mode: false,
            }),
            OpCode::BindConnToSession,
        ),
        (Operation::DestroySession([0; 16]), OpCode::DestroySession),
        (Operation::DestroyClientId(1), OpCode::DestroyClientId),
        (
            Operation::ReclaimComplete { one_fs: false },
            OpCode::ReclaimComplete,
        ),
        (Operation::Sequence(sequence), OpCode::Sequence),
        (Operation::PutRootFh, OpCode::PutRootFh),
        (Operation::PutPubFh, OpCode::PutPubFh),
        (Operation::PutFh(handle.clone()), OpCode::PutFh),
        (Operation::Lookup("name".to_owned()), OpCode::Lookup),
        (Operation::Lookupp, OpCode::Lookupp),
        (Operation::Access(ACCESS4_READ), OpCode::Access),
        (Operation::SecInfo("name".to_owned()), OpCode::SecInfo),
        (
            Operation::SecInfoNoName(SecInfoStyle::CurrentFileHandle),
            OpCode::SecInfoNoName,
        ),
        (Operation::DelegPurge(1), OpCode::DelegPurge),
        (Operation::DelegReturn(stateid), OpCode::DelegReturn),
        (Operation::NVerify(Fattr::empty()), OpCode::NVerify),
        (Operation::Open(open), OpCode::Open),
        (Operation::OpenAttr { create_dir: false }, OpCode::OpenAttr),
        (
            Operation::OpenConfirm { stateid, seqid: 1 },
            OpCode::OpenConfirm,
        ),
        (Operation::Close { seqid: 1, stateid }, OpCode::Close),
        (
            Operation::Lock(LockArgs {
                lock_type: LockType::Read,
                reclaim: false,
                offset: 0,
                length: 1,
                locker: Locker::Existing {
                    lock_stateid: stateid,
                    lock_seqid: 1,
                },
            }),
            OpCode::Lock,
        ),
        (
            Operation::LockTest(LockTestArgs {
                lock_type: LockType::Read,
                offset: 0,
                length: 1,
                owner: LockOwner {
                    client_id: 1,
                    owner: b"lock".to_vec(),
                },
            }),
            OpCode::Lockt,
        ),
        (
            Operation::LockUnlock(LockUnlockArgs {
                lock_type: LockType::Read,
                seqid: 1,
                lock_stateid: stateid,
                offset: 0,
                length: 1,
            }),
            OpCode::Locku,
        ),
        (
            Operation::OpenDowngrade {
                seqid: 2,
                stateid,
                share_access: OPEN4_SHARE_ACCESS_READ,
                share_deny: OPEN4_SHARE_DENY_NONE,
            },
            OpCode::OpenDowngrade,
        ),
        (Operation::FreeStateId(stateid), OpCode::FreeStateId),
        (Operation::TestStateIds(vec![stateid]), OpCode::TestStateId),
        (
            Operation::GetDirDelegation(GetDirDelegationArgs {
                signal_deleg_avail: false,
                notification_types: Bitmap::empty(),
                child_attr_delay: NfsTime {
                    seconds: 0,
                    nseconds: 0,
                },
                dir_attr_delay: NfsTime {
                    seconds: 0,
                    nseconds: 0,
                },
                child_attributes: Bitmap::empty(),
                dir_attributes: Bitmap::empty(),
            }),
            OpCode::GetDirDelegation,
        ),
        (
            Operation::GetDeviceInfo(GetDeviceInfoArgs {
                device_id,
                layout_type: LayoutType::NfsV4_1Files,
                max_count: 0,
                notify_types: Bitmap::empty(),
            }),
            OpCode::GetDeviceInfo,
        ),
        (
            Operation::GetDeviceList(GetDeviceListArgs {
                layout_type: LayoutType::NfsV4_1Files,
                max_devices: 1,
                cookie: 0,
                cookieverf: [0; 8],
            }),
            OpCode::GetDeviceList,
        ),
        (
            Operation::LayoutCommit(LayoutCommitArgs {
                offset: 0,
                length: 1,
                reclaim: false,
                stateid,
                last_write_offset: None,
                time_modify: None,
                layout_update: LayoutUpdate {
                    layout_type: LayoutType::NfsV4_1Files,
                    body: Vec::new(),
                },
            }),
            OpCode::LayoutCommit,
        ),
        (
            Operation::LayoutGet(LayoutGetArgs {
                signal_layout_avail: false,
                layout_type: LayoutType::NfsV4_1Files,
                iomode: LayoutIomode::Read,
                offset: 0,
                length: 1,
                min_length: 1,
                stateid,
                max_count: 1,
            }),
            OpCode::LayoutGet,
        ),
        (
            Operation::LayoutReturn(LayoutReturnArgs {
                reclaim: false,
                layout_type: LayoutType::NfsV4_1Files,
                iomode: LayoutIomode::Any,
                layout_return: LayoutReturn::All,
            }),
            OpCode::LayoutReturn,
        ),
        (
            Operation::SetSsv(SetSsvArgs {
                ssv: Vec::new(),
                digest: Vec::new(),
            }),
            OpCode::SetSsv,
        ),
        (
            Operation::WantDelegation(WantDelegationArgs {
                want: OPEN4_SHARE_ACCESS_WANT_READ_DELEG,
                claim: DelegationClaim::FileHandle,
            }),
            OpCode::WantDelegation,
        ),
        (Operation::GetFh, OpCode::GetFh),
        (Operation::GetAttr(Bitmap::empty()), OpCode::GetAttr),
        (
            Operation::SetAttr {
                stateid,
                attrs: Fattr::empty(),
            },
            OpCode::SetAttr,
        ),
        (
            Operation::Read {
                stateid,
                offset: 0,
                count: 1,
            },
            OpCode::Read,
        ),
        (
            Operation::Write {
                stateid,
                offset: 0,
                stable: StableHow::FileSync,
                data: vec![1],
            },
            OpCode::Write,
        ),
        (
            Operation::Allocate {
                stateid,
                offset: 0,
                length: 1,
            },
            OpCode::Allocate,
        ),
        (
            Operation::Deallocate {
                stateid,
                offset: 0,
                length: 1,
            },
            OpCode::Deallocate,
        ),
        (
            Operation::IoAdvise(IoAdviseArgs {
                stateid,
                offset: 0,
                count: 1,
                hints: bitmap(&[IoAdviceType::Normal.as_u32()]),
            }),
            OpCode::IoAdvise,
        ),
        (
            Operation::Copy(CopyArgs {
                src_stateid: stateid,
                dst_stateid: stateid,
                src_offset: 0,
                dst_offset: 0,
                count: 1,
                consecutive: false,
                synchronous: true,
                source_servers: Vec::new(),
            }),
            OpCode::Copy,
        ),
        (
            Operation::CopyNotify(CopyNotifyArgs {
                src_stateid: stateid,
                destination_server: NetLoc::Name("server".to_owned()),
            }),
            OpCode::CopyNotify,
        ),
        (
            Operation::LayoutError(LayoutErrorArgs {
                offset: 0,
                length: 1,
                stateid,
                errors: Vec::new(),
            }),
            OpCode::LayoutError,
        ),
        (
            Operation::LayoutStats(LayoutStatsArgs {
                offset: 0,
                length: 1,
                stateid,
                read: IoInfo { count: 0, bytes: 0 },
                write: IoInfo { count: 0, bytes: 0 },
                device_id,
                layout_update: LayoutUpdate {
                    layout_type: LayoutType::NfsV4_1Files,
                    body: Vec::new(),
                },
            }),
            OpCode::LayoutStats,
        ),
        (Operation::OffloadCancel(stateid), OpCode::OffloadCancel),
        (Operation::OffloadStatus(stateid), OpCode::OffloadStatus),
        (
            Operation::ReadPlus(ReadPlusArgs {
                stateid,
                offset: 0,
                count: 1,
            }),
            OpCode::ReadPlus,
        ),
        (
            Operation::Seek {
                stateid,
                offset: 0,
                what: SeekContent::Data,
            },
            OpCode::Seek,
        ),
        (
            Operation::Clone(CloneArgs {
                src_stateid: stateid,
                dst_stateid: stateid,
                src_offset: 0,
                dst_offset: 0,
                count: 1,
            }),
            OpCode::Clone,
        ),
        (
            Operation::WriteSame(WriteSameArgs {
                stateid,
                stable: StableHow::FileSync,
                block: AppDataBlock {
                    offset: 0,
                    block_size: 1,
                    block_count: 1,
                    block_number_offset: 0,
                    block_number: 0,
                    pattern_offset: 0,
                    pattern: Vec::new(),
                },
            }),
            OpCode::WriteSame,
        ),
        (
            Operation::Commit {
                offset: 0,
                count: 1,
            },
            OpCode::Commit,
        ),
        (Operation::Renew(1), OpCode::Renew),
        (
            Operation::ReadDir {
                cookie: 0,
                cookieverf: [0; 8],
                dircount: 1,
                maxcount: 2,
                attr_request: Bitmap::empty(),
            },
            OpCode::ReadDir,
        ),
        (Operation::ReadLink, OpCode::ReadLink),
        (Operation::Remove("name".to_owned()), OpCode::Remove),
        (Operation::Link("name".to_owned()), OpCode::Link),
        (
            Operation::Rename {
                oldname: "old".to_owned(),
                newname: "new".to_owned(),
            },
            OpCode::Rename,
        ),
        (Operation::Verify(Fattr::empty()), OpCode::Verify),
        (
            Operation::ReleaseLockOwner(LockOwner {
                client_id: 1,
                owner: b"lock".to_vec(),
            }),
            OpCode::ReleaseLockOwner,
        ),
        (
            Operation::Create(CreateArgs {
                kind: CreateKind::Directory,
                name: "dir".to_owned(),
                attrs: Fattr::empty(),
            }),
            OpCode::Create,
        ),
        (Operation::SaveFh, OpCode::SaveFh),
        (Operation::RestoreFh, OpCode::RestoreFh),
    ];

    for (operation, opcode) in operations {
        assert_eq!(operation.op_code(), opcode);
        assert_eq!(
            &to_bytes(&operation).unwrap()[..4],
            &opcode.as_u32().to_be_bytes()
        );
    }
}
