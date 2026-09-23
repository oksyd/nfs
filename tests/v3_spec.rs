#![cfg(feature = "protocol")]

use nfs::v3::protocol::*;
use nfs::xdr::{from_bytes, to_bytes};

#[test]
fn rfc1813_program_constants_match_spec() {
    assert_eq!(NFS_PROGRAM, 100003);
    assert_eq!(NFS_VERSION, 3);
    assert_eq!(NFS_PORT, 2049);
    assert_eq!(NFS3_FHSIZE, 64);
    assert_eq!(NFS3_COOKIEVERFSIZE, 8);
    assert_eq!(NFS3_CREATEVERFSIZE, 8);
    assert_eq!(NFS3_WRITEVERFSIZE, 8);
    assert_eq!(NFS3_NSECONDS_PER_SECOND, 1_000_000_000);

    assert_eq!(MOUNT_PROGRAM, 100005);
    assert_eq!(MOUNT_VERSION, 3);
    assert_eq!(PMAP_PROGRAM, 100000);
    assert_eq!(PMAP_VERSION, 2);
    assert_eq!(PMAP_PORT, 111);
    assert_eq!(IPPROTO_TCP, 6);
    assert_eq!(IPPROTO_UDP, 17);
}

#[test]
fn rfc1813_access_and_fsinfo_bitmasks_match_spec() {
    assert_eq!(ACCESS3_READ, 0x0001);
    assert_eq!(ACCESS3_LOOKUP, 0x0002);
    assert_eq!(ACCESS3_MODIFY, 0x0004);
    assert_eq!(ACCESS3_EXTEND, 0x0008);
    assert_eq!(ACCESS3_DELETE, 0x0010);
    assert_eq!(ACCESS3_EXECUTE, 0x0020);

    assert_eq!(FSF3_LINK, 0x0001);
    assert_eq!(FSF3_SYMLINK, 0x0002);
    assert_eq!(FSF3_HOMOGENEOUS, 0x0008);
    assert_eq!(FSF3_CANSETTIME, 0x0010);
}

#[test]
fn rfc1813_status_codes_round_trip() {
    let statuses = [
        (0, NfsStatus::Ok),
        (1, NfsStatus::Perm),
        (2, NfsStatus::NoEnt),
        (5, NfsStatus::Io),
        (6, NfsStatus::Nxio),
        (13, NfsStatus::Access),
        (17, NfsStatus::Exist),
        (18, NfsStatus::Xdev),
        (19, NfsStatus::Nodev),
        (20, NfsStatus::NotDir),
        (21, NfsStatus::IsDir),
        (22, NfsStatus::Inval),
        (27, NfsStatus::Fbig),
        (28, NfsStatus::NoSpc),
        (30, NfsStatus::ReadOnlyFs),
        (31, NfsStatus::Mlink),
        (63, NfsStatus::NameTooLong),
        (66, NfsStatus::NotEmpty),
        (69, NfsStatus::Dquot),
        (70, NfsStatus::Stale),
        (71, NfsStatus::Remote),
        (10001, NfsStatus::BadHandle),
        (10002, NfsStatus::NotSync),
        (10003, NfsStatus::BadCookie),
        (10004, NfsStatus::NotSupported),
        (10005, NfsStatus::TooSmall),
        (10006, NfsStatus::ServerFault),
        (10007, NfsStatus::BadType),
        (10008, NfsStatus::Jukebox),
    ];

    for (code, status) in statuses {
        assert_eq!(NfsStatus::from_u32(code), status);
        assert_eq!(status.as_u32(), code);
    }
    assert_eq!(NfsStatus::from_u32(4242), NfsStatus::Unknown(4242));
    assert_eq!(NfsStatus::Unknown(4242).as_u32(), 4242);
}

#[test]
fn rfc1813_file_type_discriminants_match_spec() {
    let types: [(i32, FileType); 7] = [
        (1, FileType::Regular),
        (2, FileType::Directory),
        (3, FileType::BlockDevice),
        (4, FileType::CharacterDevice),
        (5, FileType::Symlink),
        (6, FileType::Socket),
        (7, FileType::Fifo),
    ];

    for (discriminant, file_type) in types {
        assert_eq!(
            to_bytes(&file_type).unwrap(),
            discriminant.to_be_bytes().to_vec()
        );
        assert_eq!(
            from_bytes::<FileType>(&discriminant.to_be_bytes()).unwrap(),
            file_type
        );
    }
    assert!(from_bytes::<FileType>(&8_i32.to_be_bytes()).is_err());
}

#[test]
fn rfc1813_stable_how_discriminants_match_spec() {
    let values: [(i32, StableHow); 3] = [
        (0, StableHow::Unstable),
        (1, StableHow::DataSync),
        (2, StableHow::FileSync),
    ];

    for (discriminant, stable_how) in values {
        assert_eq!(
            to_bytes(&stable_how).unwrap(),
            discriminant.to_be_bytes().to_vec()
        );
        assert_eq!(
            from_bytes::<StableHow>(&discriminant.to_be_bytes()).unwrap(),
            stable_how
        );
    }
    assert!(from_bytes::<StableHow>(&3_i32.to_be_bytes()).is_err());
}

#[test]
fn rfc1813_create_how_discriminants_match_spec() {
    let unchecked = CreateHow::Unchecked(SetAttr::default());
    let guarded = CreateHow::Guarded(SetAttr::default());
    let exclusive = CreateHow::Exclusive([1, 2, 3, 4, 5, 6, 7, 8]);

    let mut expected = vec![0, 0, 0, 0];
    expected.extend([0; 24]);
    assert_eq!(to_bytes(&unchecked).unwrap(), expected);

    let mut expected = vec![0, 0, 0, 1];
    expected.extend([0; 24]);
    assert_eq!(to_bytes(&guarded).unwrap(), expected);

    assert_eq!(
        to_bytes(&exclusive).unwrap(),
        vec![0, 0, 0, 2, 1, 2, 3, 4, 5, 6, 7, 8]
    );
}

#[test]
fn rfc1813_mknod_data_discriminants_match_spec() {
    let socket = MknodData::Socket {
        attributes: SetAttr::default(),
    };
    let fifo = MknodData::Fifo {
        attributes: SetAttr::default(),
    };
    let char_device = MknodData::CharacterDevice {
        attributes: SetAttr::default(),
        spec: SpecData {
            specdata1: 8,
            specdata2: 1,
        },
    };

    let mut expected = vec![0, 0, 0, 6];
    expected.extend([0; 24]);
    assert_eq!(to_bytes(&socket).unwrap(), expected);

    let mut expected = vec![0, 0, 0, 7];
    expected.extend([0; 24]);
    assert_eq!(to_bytes(&fifo).unwrap(), expected);

    let mut expected = vec![0, 0, 0, 4];
    expected.extend([0; 24]);
    expected.extend(8_u32.to_be_bytes());
    expected.extend(1_u32.to_be_bytes());
    assert_eq!(to_bytes(&char_device).unwrap(), expected);
}
