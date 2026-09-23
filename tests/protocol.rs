#![cfg(feature = "protocol")]

use std::io;

use nfs::v3::protocol::{CreateHow, FileHandle};
use nfs::v3::{FileType, MountStatus, NfsStatus, NfsTime, RemoteTarget, SetAttr, SetTime};
use nfs::v4::Status;
use nfs::xdr;
use nfs::xdr::{from_bytes, to_bytes};
use nfs::{AUTH_SYS_MACHINE_NAME_MAX, AUTH_SYS_MAX_GROUPS, AuthSys, Error};

#[test]
fn parses_remote_targets() {
    let target = RemoteTarget::parse("127.0.0.1:/export/data").unwrap();
    assert_eq!(target.host, "127.0.0.1");
    assert_eq!(target.export, "/export/data");

    let target = RemoteTarget::parse("[::1]:/export/data").unwrap();
    assert_eq!(target.host, "::1");
    assert_eq!(target.export, "/export/data");

    assert!(RemoteTarget::parse("127.0.0.1").is_err());
    assert!(RemoteTarget::parse("127.0.0.1:relative").is_err());
    assert!(RemoteTarget::parse("[::1:/export").is_err());
}

#[test]
fn maps_nfs_status_values() {
    assert_eq!(NfsStatus::from_u32(0), NfsStatus::Ok);
    assert_eq!(NfsStatus::from_u32(2), NfsStatus::NoEnt);
    assert_eq!(NfsStatus::from_u32(10004), NfsStatus::NotSupported);
    assert_eq!(NfsStatus::from_u32(10008), NfsStatus::Jukebox);
    assert_eq!(NfsStatus::from_u32(4242), NfsStatus::Unknown(4242));
    assert_eq!(NfsStatus::NameTooLong.as_u32(), 63);
}

#[test]
fn classifies_common_errors() {
    assert!(Error::Io(io::Error::from(io::ErrorKind::NotFound)).is_not_found());
    assert!(
        Error::Mount {
            status: MountStatus::NoEnt
        }
        .is_not_found()
    );
    assert!(
        Error::Nfs {
            procedure: "LOOKUP",
            status: NfsStatus::NoEnt,
        }
        .is_not_found()
    );
    assert!(
        Error::NfsV4 {
            operation: "LOOKUP",
            status: Status::NoEnt,
        }
        .is_not_found()
    );

    assert!(Error::Io(io::Error::from(io::ErrorKind::AlreadyExists)).is_already_exists());
    assert!(
        Error::Nfs {
            procedure: "CREATE",
            status: NfsStatus::Exist,
        }
        .is_already_exists()
    );
    assert!(
        Error::NfsV4 {
            operation: "OPEN",
            status: Status::Exist,
        }
        .is_already_exists()
    );
}

#[test]
fn classifies_operational_error_semantics() {
    assert!(
        Error::Mount {
            status: MountStatus::Access
        }
        .is_permission_denied()
    );
    assert!(
        Error::Nfs {
            procedure: "READ",
            status: NfsStatus::Perm,
        }
        .is_permission_denied()
    );
    assert!(
        Error::NfsV4 {
            operation: "READ",
            status: Status::Access,
        }
        .is_permission_denied()
    );
    assert!(
        Error::NfsV4 {
            operation: "READ",
            status: Status::WrongSec,
        }
        .is_permission_denied()
    );

    assert!(Error::Io(io::Error::from(io::ErrorKind::TimedOut)).is_retryable());
    assert!(
        Error::Nfs {
            procedure: "READ",
            status: NfsStatus::Jukebox,
        }
        .is_retryable()
    );
    assert!(
        Error::NfsV4 {
            operation: "READ",
            status: Status::Delay,
        }
        .is_retryable()
    );
    let bad_session = Error::NfsV4 {
        operation: "SEQUENCE",
        status: Status::BadSession,
    };
    assert!(!bad_session.is_retryable());
    assert!(bad_session.requires_session_recovery());

    assert!(
        Error::Nfs {
            procedure: "WRITE",
            status: NfsStatus::Dquot,
        }
        .is_no_space()
    );
    assert!(
        Error::NfsV4 {
            operation: "WRITE",
            status: Status::NoSpc,
        }
        .is_no_space()
    );
    assert!(
        Error::Nfs {
            procedure: "WRITE",
            status: NfsStatus::ReadOnlyFs,
        }
        .is_read_only()
    );
    assert!(
        Error::NfsV4 {
            operation: "WRITE",
            status: Status::ReadOnlyFs,
        }
        .is_read_only()
    );

    let cleanup = Error::Cleanup {
        context: "cleanup CLOSE",
        primary: Box::new(Error::Nfs {
            procedure: "WRITE",
            status: NfsStatus::Dquot,
        }),
        cleanup: Box::new(Error::Protocol("cleanup failed".to_owned())),
    };
    assert!(cleanup.is_no_space());
    assert!(cleanup.to_string().contains("cleanup failed"));
}

#[test]
fn classifies_handle_and_v4_state_errors() {
    assert!(
        Error::Nfs {
            procedure: "READ",
            status: NfsStatus::Stale,
        }
        .is_stale_handle()
    );
    assert!(
        Error::NfsV4 {
            operation: "GETFH",
            status: Status::BadHandle,
        }
        .is_stale_handle()
    );
    assert!(
        Error::NfsV4 {
            operation: "GETFH",
            status: Status::FhExpired,
        }
        .is_stale_handle()
    );

    let lost_state = Error::NfsV4 {
        operation: "READ",
        status: Status::DelegRevoked,
    };
    assert!(lost_state.is_lost_state());
    assert!(!lost_state.is_session_recoverable());

    let recoverable_session = Error::NfsV4 {
        operation: "SEQUENCE",
        status: Status::DeadSession,
    };
    assert!(!recoverable_session.is_lost_state());
    assert!(recoverable_session.is_session_recoverable());
}

#[test]
fn classifies_v3_file_types() {
    assert!(FileType::Regular.is_file());
    assert!(FileType::Directory.is_dir());
    assert!(FileType::Symlink.is_symlink());
    assert!(!FileType::Socket.is_file());
}

#[test]
fn encodes_nfs_file_handles_as_variable_opaque() {
    let handle = FileHandle::new(vec![1, 2, 3]).unwrap();
    assert_eq!(to_bytes(&handle).unwrap(), vec![0, 0, 0, 3, 1, 2, 3, 0]);
    assert!(FileHandle::new(vec![0; 65]).is_err());
}

#[test]
fn encodes_setattr_discriminated_unions() {
    let attr = SetAttr {
        mode: Some(0o644),
        uid: None,
        gid: None,
        size: Some(0),
        atime: SetTime::ServerTime,
        mtime: SetTime::ClientTime(NfsTime {
            seconds: 7,
            nseconds: 9,
        }),
    };

    assert_eq!(
        to_bytes(&attr).unwrap(),
        vec![
            0, 0, 0, 1, // mode follows
            0, 0, 1, 0xa4, // 0o644
            0, 0, 0, 0, // uid absent
            0, 0, 0, 0, // gid absent
            0, 0, 0, 1, // size follows
            0, 0, 0, 0, 0, 0, 0, 0, // size
            0, 0, 0, 1, // atime server time
            0, 0, 0, 2, // mtime client time
            0, 0, 0, 7, // seconds
            0, 0, 0, 9, // nseconds
        ]
    );
}

#[test]
fn rejects_invalid_nfs_timestamp_nanoseconds() {
    let invalid_v3_time = NfsTime {
        seconds: 7,
        nseconds: nfs::v3::NFS3_NSECONDS_PER_SECOND,
    };
    assert!(matches!(
        to_bytes(&invalid_v3_time),
        Err(xdr::Error::LengthLimitExceeded { .. })
    ));
    assert!(matches!(
        from_bytes::<NfsTime>(&[0, 0, 0, 7, 0x3b, 0x9a, 0xca, 0x00]),
        Err(xdr::Error::LengthLimitExceeded { .. })
    ));

    let invalid_v3_attr = SetAttr::times(Some(invalid_v3_time), None);
    assert!(matches!(
        to_bytes(&invalid_v3_attr),
        Err(xdr::Error::LengthLimitExceeded { .. })
    ));

    let invalid_v4_time = nfs::v4::NfsTime {
        seconds: 7,
        nseconds: nfs::v4::NFS4_NSECONDS_PER_SECOND,
    };
    assert!(matches!(
        to_bytes(&invalid_v4_time),
        Err(xdr::Error::LengthLimitExceeded { .. })
    ));
    assert!(matches!(
        from_bytes::<nfs::v4::NfsTime>(&[0, 0, 0, 0, 0, 0, 0, 7, 0x3b, 0x9a, 0xca, 0x00]),
        Err(xdr::Error::LengthLimitExceeded { .. })
    ));

    let invalid_v4_attrs = nfs::v4::SetAttrs::times(Some(invalid_v4_time), None);
    assert!(matches!(
        nfs::v4::Fattr::from_set_attrs(&invalid_v4_attrs),
        Err(Error::Xdr(xdr::Error::LengthLimitExceeded { .. }))
    ));
}

#[test]
fn encodes_exclusive_create_mode() {
    let how = CreateHow::Exclusive([1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(
        to_bytes(&how).unwrap(),
        vec![0, 0, 0, 2, 1, 2, 3, 4, 5, 6, 7, 8]
    );
}

#[test]
fn encodes_auth_sys_credentials() {
    assert_eq!(AUTH_SYS_MACHINE_NAME_MAX, 255);
    assert_eq!(AUTH_SYS_MAX_GROUPS, 16);

    let auth = AuthSys {
        stamp: 1,
        machine_name: "host".to_owned(),
        uid: 2,
        gid: 3,
        gids: vec![4, 5],
    };

    assert_eq!(
        xdr::to_bytes(&auth).unwrap(),
        vec![
            0, 0, 0, 1, // stamp
            0, 0, 0, 4, b'h', b'o', b's', b't', // machine
            0, 0, 0, 2, // uid
            0, 0, 0, 3, // gid
            0, 0, 0, 2, // gids len
            0, 0, 0, 4, // gid 1
            0, 0, 0, 5, // gid 2
        ]
    );
}
