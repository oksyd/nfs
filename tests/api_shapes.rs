#[cfg(feature = "blocking")]
#[test]
fn exposes_blocking_special_node_api_shapes() {
    fn v3(mut client: nfs::v3::blocking::Client) -> nfs::Result<()> {
        let _root_fsinfo: Option<&nfs::v3::FsInfo> = client.root_fsinfo();
        let _fsinfo: nfs::v3::FsInfo = client.path_fsinfo("/object")?;
        let _handle: nfs::v3::FileHandle = client.file_handle("/object")?;
        let _handle: nfs::v3::FileHandle = client.parent_file_handle("/object")?;
        let _attrs: nfs::v3::FileAttr = client.getattr("/object")?;
        let _attrs: nfs::v3::FileAttr = client.parent_getattr("/object")?;
        let _attrs: nfs::v3::FileAttr = client.parent_metadata("/object")?;
        client.create_fifo("/fifo", 0o644)?;
        client.create_socket("/socket", 0o644)?;
        client.create_block_device("/block", 8, 1, 0o600)?;
        client.create_character_device("/character", 1, 3, 0o600)?;
        Ok(())
    }

    fn v4(mut client: nfs::v4::blocking::Client) -> nfs::Result<()> {
        client.create_fifo("/fifo", 0o644)?;
        client.create_socket("/socket", 0o644)?;
        client.create_block_device("/block", 8, 1, 0o600)?;
        client.create_character_device("/character", 1, 3, 0o600)?;
        Ok(())
    }

    let _ = v3;
    let _ = v4;
}

#[cfg(feature = "blocking")]
#[test]
fn exposes_blocking_mount_listing_api_shapes() {
    let _list_exports: fn(&str) -> nfs::Result<Vec<nfs::v3::Export>> =
        nfs::v3::blocking::list_exports;
    let _list_exports_with_timeout: fn(
        &str,
        Option<std::time::Duration>,
    ) -> nfs::Result<Vec<nfs::v3::Export>> = nfs::v3::blocking::list_exports_with_timeout;
    let _list_exports_with_mount_port: fn(
        &str,
        u16,
        Option<std::time::Duration>,
    ) -> nfs::Result<Vec<nfs::v3::Export>> = nfs::v3::blocking::list_exports_with_mount_port;
    let _list_mounts: fn(&str) -> nfs::Result<Vec<nfs::v3::MountEntry>> =
        nfs::v3::blocking::list_mounts;
    let _list_mounts_with_timeout: fn(
        &str,
        Option<std::time::Duration>,
    ) -> nfs::Result<Vec<nfs::v3::MountEntry>> = nfs::v3::blocking::list_mounts_with_timeout;
    let _list_mounts_with_mount_port: fn(
        &str,
        u16,
        Option<std::time::Duration>,
    ) -> nfs::Result<Vec<nfs::v3::MountEntry>> = nfs::v3::blocking::list_mounts_with_mount_port;
    let _unmount: fn(&str) -> nfs::Result<()> = nfs::v3::blocking::unmount;
    let _unmount_with_timeout: fn(&str, Option<std::time::Duration>) -> nfs::Result<()> =
        nfs::v3::blocking::unmount_with_timeout;
    let _unmount_with_mount_port: fn(&str, u16, Option<std::time::Duration>) -> nfs::Result<()> =
        nfs::v3::blocking::unmount_with_mount_port;
    let _unmount_all: fn(&str) -> nfs::Result<()> = nfs::v3::blocking::unmount_all;
    let _unmount_all_with_timeout: fn(&str, Option<std::time::Duration>) -> nfs::Result<()> =
        nfs::v3::blocking::unmount_all_with_timeout;
    let _unmount_all_with_mount_port: fn(
        &str,
        u16,
        Option<std::time::Duration>,
    ) -> nfs::Result<()> = nfs::v3::blocking::unmount_all_with_mount_port;
}

#[cfg(feature = "blocking")]
#[test]
fn exposes_blocking_v4_security_info_api_shapes() {
    fn v4(mut client: nfs::v4::blocking::Client) -> nfs::Result<()> {
        let _flavors: Vec<nfs::v4::SecInfo> = client.secinfo("/export/object")?;
        let _flavors: Vec<nfs::v4::SecInfo> =
            client.secinfo_no_name("/export/object", nfs::v4::SecInfoStyle::CurrentFileHandle)?;
        let _flavors: Vec<nfs::v4::SecInfo> = client.secinfo_current("/export/object")?;
        let _flavors: Vec<nfs::v4::SecInfo> = client.secinfo_parent("/export/object")?;
        let _service = nfs::v4::RpcGssService::None;
        let _raw_attrs: nfs::v4::Fattr = client.getattr_values(
            "/export/object",
            nfs::v4::Bitmap::from_attrs(&[nfs::v4::FATTR4_SIZE, nfs::v4::FATTR4_MODE])?,
        )?;
        let _raw_attrs: nfs::v4::Fattr = client.supported_attr_values(
            "/export/object",
            &[nfs::v4::FATTR4_SIZE, nfs::v4::FATTR4_MODE],
        )?;
        let _handle: nfs::v4::FileHandle = client.file_handle("/export/object")?;
        client.lookup_public("/export/object")?;
        let _exists: bool = client.public_exists("/export/object")?;
        let _handle: nfs::v4::FileHandle = client.public_file_handle("/export/object")?;
        let _access: nfs::v4::AccessResult =
            client.public_access("/export/object", nfs::v4::ACCESS4_READ)?;
        let _attrs: nfs::v4::BasicAttributes = client.public_getattr("/export/object")?;
        let _supported: nfs::v4::Bitmap = client.public_supported_attrs("/export/object")?;
        let _raw_attrs: nfs::v4::Fattr = client.public_getattr_values(
            "/export/object",
            nfs::v4::Bitmap::from_attrs(&[nfs::v4::FATTR4_SIZE, nfs::v4::FATTR4_MODE])?,
        )?;
        let _raw_attrs: nfs::v4::Fattr = client.public_supported_attr_values(
            "/export/object",
            &[nfs::v4::FATTR4_SIZE, nfs::v4::FATTR4_MODE],
        )?;
        let _fsstat: nfs::v4::FsStat = client.public_fsstat("/export/object")?;
        let _fsinfo: nfs::v4::FsInfo = client.public_fsinfo("/export/object")?;
        let _pathconf: nfs::v4::PathConf = client.public_pathconf("/export/object")?;
        let _entries: Vec<nfs::v4::DirEntry> = client.public_read_dir("/export")?;
        let _entries: Vec<nfs::v4::DirEntry> = client.public_read_dir_limited("/export", 16)?;
        let _page: nfs::v4::DirPage = client.public_read_dir_page("/export", None)?;
        let _page: nfs::v4::DirPage = client.public_read_dir_page_limited("/export", None, 16)?;
        let _handle: nfs::v4::FileHandle = client.parent_file_handle("/export/object")?;
        let _access: nfs::v4::AccessResult =
            client.parent_access("/export/object", nfs::v4::ACCESS4_LOOKUP)?;
        let _attrs: nfs::v4::BasicAttributes = client.parent_getattr("/export/object")?;
        let _supported: nfs::v4::Bitmap = client.parent_supported_attrs("/export/object")?;
        let _raw_attrs: nfs::v4::Fattr = client.parent_getattr_values(
            "/export/object",
            nfs::v4::Bitmap::from_attrs(&[nfs::v4::FATTR4_SIZE, nfs::v4::FATTR4_MODE])?,
        )?;
        let _raw_attrs: nfs::v4::Fattr = client.parent_supported_attr_values(
            "/export/object",
            &[nfs::v4::FATTR4_SIZE, nfs::v4::FATTR4_MODE],
        )?;
        let _fsstat: nfs::v4::FsStat = client.parent_fsstat("/export/object")?;
        let _fsinfo: nfs::v4::FsInfo = client.parent_fsinfo("/export/object")?;
        let _pathconf: nfs::v4::PathConf = client.parent_pathconf("/export/object")?;
        let _entries: Vec<nfs::v4::DirEntry> = client.parent_read_dir("/export/object")?;
        let _entries: Vec<nfs::v4::DirEntry> =
            client.parent_read_dir_limited("/export/object", 16)?;
        let _page: nfs::v4::DirPage = client.parent_read_dir_page("/export/object", None)?;
        let _page: nfs::v4::DirPage =
            client.parent_read_dir_page_limited("/export/object", None, 16)?;
        let _matched: bool = client.verify_attrs("/export/object", &nfs::v4::Fattr::mode(0o644))?;
        let _not_matched: bool =
            client.nverify_attrs("/export/object", &nfs::v4::Fattr::mode(0o600))?;
        client.backchannel_ctl(0, vec![nfs::v4::CallbackSecParms::AuthNone])?;
        let _bound: nfs::v4::BindConnToSessionResult =
            client.bind_conn_to_session(nfs::v4::ChannelDirFromClient::Fore)?;
        let _bound: nfs::v4::BindConnToSessionResult = client
            .bind_conn_to_session_with_options(nfs::v4::ChannelDirFromClient::ForeOrBoth, false)?;
        let _direction = nfs::v4::ChannelDirFromServer::Fore;
        let _set_ssv: nfs::v4::SetSsvResult = client.set_ssv(Vec::new(), Vec::new())?;
        client.destroy_client_id()?;
        Ok(())
    }

    let _ = v4;
}

#[cfg(feature = "blocking")]
#[test]
fn exposes_blocking_v4_named_attr_api_shapes() {
    fn v4(mut client: nfs::v4::blocking::Client) -> nfs::Result<()> {
        let _entries: Vec<nfs::v4::DirEntry> = client.read_named_attrs("/export/object")?;
        let _entries: Vec<nfs::v4::DirEntry> =
            client.read_named_attrs_limited("/export/object", 16)?;
        let _page: nfs::v4::DirPage = client.read_named_attr_page("/export/object", None)?;
        let _page: nfs::v4::DirPage =
            client.read_named_attr_page_limited("/export/object", None, 16)?;
        let _exists: bool = client.named_attr_exists("/export/object", "user.comment")?;
        let _meta: nfs::v4::BasicAttributes =
            client.named_attr_metadata("/export/object", "user.comment")?;
        let _supported: nfs::v4::Bitmap =
            client.named_attr_supported_attrs("/export/object", "user.comment")?;
        let _raw_attrs: nfs::v4::Fattr = client.named_attr_getattr_values(
            "/export/object",
            "user.comment",
            nfs::v4::Bitmap::from_attrs(&[nfs::v4::FATTR4_SIZE, nfs::v4::FATTR4_MODE])?,
        )?;
        let _raw_attrs: nfs::v4::Fattr = client.named_attr_supported_attr_values(
            "/export/object",
            "user.comment",
            &[nfs::v4::FATTR4_SIZE, nfs::v4::FATTR4_MODE],
        )?;
        let _value: Vec<u8> = client.read_named_attr("/export/object", "user.comment")?;
        let mut sink = Vec::new();
        let _written: u64 =
            client.read_named_attr_to_writer("/export/object", "user.comment", &mut sink)?;
        let _range: Vec<u8> =
            client.read_named_attr_range("/export/object", "user.comment", 0, 16)?;
        let _at: Vec<u8> = client.read_named_attr_at("/export/object", "user.comment", 0, 16)?;
        let _exact: Vec<u8> =
            client.read_named_attr_exact_at("/export/object", "user.comment", 0, 16)?;
        let mut sink = Vec::new();
        let _written: u64 = client.read_named_attr_range_to_writer(
            "/export/object",
            "user.comment",
            0,
            16,
            &mut sink,
        )?;
        client.write_named_attr("/export/object", "user.comment", b"value")?;
        client.write_named_attr_with_mode("/export/object", "user.comment", b"value", 0o600)?;
        let mut reader = std::io::Cursor::new(b"value");
        let _written: u64 =
            client.write_named_attr_from_reader("/export/object", "user.comment", &mut reader)?;
        let mut reader = std::io::Cursor::new(b"value");
        let _written: u64 = client.write_named_attr_from_reader_with_mode(
            "/export/object",
            "user.comment",
            &mut reader,
            0o600,
        )?;
        client.write_named_attr_atomic("/export/object", "user.comment", b"value")?;
        client.write_named_attr_atomic_with_mode(
            "/export/object",
            "user.comment",
            b"value",
            0o600,
        )?;
        let mut reader = std::io::Cursor::new(b"value");
        let _written: u64 = client.write_named_attr_atomic_from_reader(
            "/export/object",
            "user.comment",
            &mut reader,
        )?;
        let mut reader = std::io::Cursor::new(b"value");
        let _written: u64 = client.write_named_attr_atomic_from_reader_with_mode(
            "/export/object",
            "user.comment",
            &mut reader,
            0o600,
        )?;
        client.write_named_attr_at("/export/object", "user.comment", 0, b"value")?;
        let _copied: u64 = client.copy_named_attr(
            "/export/object",
            "user.comment",
            "/export/object",
            "user.copy",
        )?;
        let _copied: u64 = client.copy_named_attr_atomic(
            "/export/object",
            "user.comment",
            "/export/object",
            "user.copy",
        )?;
        let _appended: u64 =
            client.append_named_attr("/export/object", "user.comment", b"value")?;
        let mut reader = std::io::Cursor::new(b"value");
        let _appended: u64 =
            client.append_named_attr_from_reader("/export/object", "user.comment", &mut reader)?;
        client.set_named_attr_attrs(
            "/export/object",
            "user.comment",
            &nfs::v4::SetAttrs::mode(0o644),
        )?;
        client.set_named_attr_mode("/export/object", "user.comment", 0o644)?;
        client.set_named_attr_ownership("/export/object", "user.comment", "owner", "group")?;
        client.set_named_attr_times(
            "/export/object",
            "user.comment",
            Some(nfs::v4::NfsTime {
                seconds: 0,
                nseconds: 0,
            }),
            None,
        )?;
        client.truncate_named_attr("/export/object", "user.comment", 0)?;
        client.rename_named_attr("/export/object", "user.copy", "user.renamed")?;
        let _renamed: bool =
            client.rename_named_attr_if_exists("/export/object", "user.renamed", "user.copy")?;
        client.remove_named_attr("/export/object", "user.comment")?;
        let _removed: bool =
            client.remove_named_attr_if_exists("/export/object", "user.comment")?;
        Ok(())
    }

    let _ = v4;
}

#[cfg(feature = "blocking")]
#[test]
fn exposes_blocking_v4_delegation_api_shapes() {
    fn v4(mut client: nfs::v4::blocking::Client) -> nfs::Result<()> {
        let stateid = nfs::v4::StateId::anonymous();
        let _delegation: nfs::v4::OpenDelegation = client.want_delegation(
            "/export/object",
            nfs::v4::OPEN4_SHARE_ACCESS_WANT_READ_DELEG,
        )?;
        let _delegation: nfs::v4::OpenDelegation = client.want_delegation_with_claim(
            "/export/object",
            nfs::v4::OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG,
            nfs::v4::DelegationClaim::FileHandle,
        )?;
        let args = nfs::v4::GetDirDelegationArgs {
            signal_deleg_avail: false,
            notification_types: nfs::v4::Bitmap::empty(),
            child_attr_delay: nfs::v4::NfsTime {
                seconds: 0,
                nseconds: 0,
            },
            dir_attr_delay: nfs::v4::NfsTime {
                seconds: 0,
                nseconds: 0,
            },
            child_attributes: nfs::v4::Bitmap::empty(),
            dir_attributes: nfs::v4::Bitmap::empty(),
        };
        let _dir_delegation: nfs::v4::GetDirDelegationResult =
            client.get_dir_delegation("/export/dir", args)?;
        client.return_delegation("/export/object", stateid)?;
        client.purge_delegations()?;
        let _claim = nfs::v4::DelegationClaim::Previous(nfs::v4::OpenDelegationType::Read);
        let _reason = nfs::v4::WhyNoDelegation::NotWanted;
        let _mask = nfs::v4::OPEN4_SHARE_ACCESS_WANT_DELEG_MASK;
        Ok(())
    }

    let _ = v4;
}

#[cfg(feature = "blocking")]
#[test]
fn exposes_blocking_v4_copy_notify_api_shapes() {
    fn v4(mut client: nfs::v4::blocking::Client) -> nfs::Result<()> {
        let stateid = nfs::v4::StateId::anonymous();
        let destination = nfs::v4::NetLoc::Name("dest.example".to_owned());
        let _notify: nfs::v4::CopyNotifyResult =
            client.copy_notify("/export/source", destination.clone())?;
        let _notify: nfs::v4::CopyNotifyResult =
            client.copy_notify_with_stateid("/export/source", stateid, destination)?;
        let _copy: nfs::v4::CopyResult = client.copy_range_offload_with_options(
            "/export/source",
            "/export/target",
            0,
            0,
            4096,
            true,
            false,
            vec![nfs::v4::NetLoc::Url("nfs://source/export".to_owned())],
        )?;
        Ok(())
    }

    let _ = v4;
}

#[cfg(feature = "blocking")]
#[test]
fn exposes_blocking_v4_pnfs_device_api_shapes() {
    fn v4(mut client: nfs::v4::blocking::Client) -> nfs::Result<()> {
        let device_id: nfs::v4::DeviceId = [0; 16];
        let layout_type = nfs::v4::LayoutType::NfsV4_1Files;
        let _info: nfs::v4::GetDeviceInfoResult = client.get_device_info(device_id, layout_type)?;
        let _info: nfs::v4::GetDeviceInfoResult = client.get_device_info_with_notify(
            device_id,
            layout_type,
            1024,
            nfs::v4::Bitmap::empty(),
        )?;
        let _ids: Vec<nfs::v4::DeviceId> = client.list_devices(layout_type)?;
        let _ids: Vec<nfs::v4::DeviceId> = client.list_devices_limited(layout_type, 16)?;
        let _page: nfs::v4::DeviceListPage = client.list_device_page(layout_type, None)?;
        let _page: nfs::v4::DeviceListPage =
            client.list_device_page_limited(layout_type, None, 16)?;
        let iomode = nfs::v4::LayoutIomode::Read;
        let stateid = nfs::v4::StateId::anonymous();
        let _layout: nfs::v4::LayoutGetResult =
            client.layout_get("/export/object", layout_type, iomode, 0, 1024, 1024)?;
        let _layout: nfs::v4::LayoutGetResult = client.layout_get_with_options(
            "/export/object",
            layout_type,
            iomode,
            0,
            1024,
            1024,
            4096,
            false,
        )?;
        let layout_update = nfs::v4::LayoutUpdate {
            layout_type,
            body: Vec::new(),
        };
        let _committed: nfs::v4::LayoutCommitResult =
            client.layout_commit("/export/object", 0, 1024, stateid, layout_update.clone())?;
        let _committed: nfs::v4::LayoutCommitResult = client.layout_commit_with_options(
            "/export/object",
            0,
            1024,
            stateid,
            Some(1023),
            None,
            layout_update.clone(),
            false,
        )?;
        client.layout_error(
            "/export/object",
            0,
            1024,
            stateid,
            vec![nfs::v4::DeviceError {
                device_id,
                status: nfs::v4::Status::Io,
                opnum: nfs::v4::OpCode::Read,
            }],
        )?;
        client.layout_stats(
            "/export/object",
            0,
            1024,
            stateid,
            nfs::v4::IoInfo { count: 1, bytes: 2 },
            nfs::v4::IoInfo { count: 3, bytes: 4 },
            device_id,
            layout_update.clone(),
        )?;
        let _returned: nfs::v4::LayoutReturnResult = client.layout_return_file(
            "/export/object",
            layout_type,
            iomode,
            0,
            1024,
            stateid,
            Vec::new(),
        )?;
        let _returned: nfs::v4::LayoutReturnResult =
            client.layout_return_fsid("/export/object", layout_type, iomode)?;
        let _returned: nfs::v4::LayoutReturnResult =
            client.layout_return_all(layout_type, iomode)?;
        let _content = nfs::v4::LayoutContent {
            layout_type,
            body: Vec::new(),
        };
        let _cursor = nfs::v4::DeviceListCursor::default();
        let _addr = nfs::v4::DeviceAddr {
            layout_type,
            body: Vec::new(),
        };
        Ok(())
    }

    let _ = v4;
}

#[cfg(feature = "tokio")]
#[test]
fn exposes_tokio_special_node_api_shapes() {
    async fn v3(mut client: nfs::v3::tokio::Client) -> nfs::Result<()> {
        let _root_fsinfo: Option<&nfs::v3::FsInfo> = client.root_fsinfo();
        let _fsinfo: nfs::v3::FsInfo = client.path_fsinfo("/object").await?;
        let _handle: nfs::v3::FileHandle = client.file_handle("/object").await?;
        let _handle: nfs::v3::FileHandle = client.parent_file_handle("/object").await?;
        let _attrs: nfs::v3::FileAttr = client.getattr("/object").await?;
        let _attrs: nfs::v3::FileAttr = client.parent_getattr("/object").await?;
        let _attrs: nfs::v3::FileAttr = client.parent_metadata("/object").await?;
        client.create_fifo("/fifo", 0o644).await?;
        client.create_socket("/socket", 0o644).await?;
        client.create_block_device("/block", 8, 1, 0o600).await?;
        client
            .create_character_device("/character", 1, 3, 0o600)
            .await?;
        Ok(())
    }

    async fn v4(mut client: nfs::v4::tokio::Client) -> nfs::Result<()> {
        client.create_fifo("/fifo", 0o644).await?;
        client.create_socket("/socket", 0o644).await?;
        client.create_block_device("/block", 8, 1, 0o600).await?;
        client
            .create_character_device("/character", 1, 3, 0o600)
            .await?;
        Ok(())
    }

    let _ = v3;
    let _ = v4;
}

#[cfg(feature = "tokio")]
#[test]
fn exposes_tokio_mount_listing_api_shapes() {
    async fn uses_api() -> nfs::Result<()> {
        let _exports: Vec<nfs::v3::Export> = nfs::v3::tokio::list_exports("server").await?;
        let _exports: Vec<nfs::v3::Export> =
            nfs::v3::tokio::list_exports_with_timeout("server", None).await?;
        let _exports: Vec<nfs::v3::Export> =
            nfs::v3::tokio::list_exports_with_mount_port("server", 20048, None).await?;
        let _mounts: Vec<nfs::v3::MountEntry> = nfs::v3::tokio::list_mounts("server").await?;
        let _mounts: Vec<nfs::v3::MountEntry> =
            nfs::v3::tokio::list_mounts_with_timeout("server", None).await?;
        let _mounts: Vec<nfs::v3::MountEntry> =
            nfs::v3::tokio::list_mounts_with_mount_port("server", 20048, None).await?;
        nfs::v3::tokio::unmount("server:/export").await?;
        nfs::v3::tokio::unmount_with_timeout("server:/export", None).await?;
        nfs::v3::tokio::unmount_with_mount_port("server:/export", 20048, None).await?;
        nfs::v3::tokio::unmount_all("server").await?;
        nfs::v3::tokio::unmount_all_with_timeout("server", None).await?;
        nfs::v3::tokio::unmount_all_with_mount_port("server", 20048, None).await?;
        Ok(())
    }

    let _ = uses_api;
}

#[cfg(feature = "tokio")]
#[test]
fn exposes_tokio_v4_named_attr_api_shapes() {
    async fn uses_api(mut client: nfs::v4::tokio::Client) -> nfs::Result<()> {
        let _entries: Vec<nfs::v4::DirEntry> = client.read_named_attrs("/export/object").await?;
        let _entries: Vec<nfs::v4::DirEntry> = client
            .read_named_attrs_limited("/export/object", 16)
            .await?;
        let _page: nfs::v4::DirPage = client.read_named_attr_page("/export/object", None).await?;
        let _page: nfs::v4::DirPage = client
            .read_named_attr_page_limited("/export/object", None, 16)
            .await?;
        let _exists: bool = client
            .named_attr_exists("/export/object", "user.comment")
            .await?;
        let _meta: nfs::v4::BasicAttributes = client
            .named_attr_metadata("/export/object", "user.comment")
            .await?;
        let _supported: nfs::v4::Bitmap = client
            .named_attr_supported_attrs("/export/object", "user.comment")
            .await?;
        let _raw_attrs: nfs::v4::Fattr = client
            .named_attr_getattr_values(
                "/export/object",
                "user.comment",
                nfs::v4::Bitmap::from_attrs(&[nfs::v4::FATTR4_SIZE, nfs::v4::FATTR4_MODE])?,
            )
            .await?;
        let _raw_attrs: nfs::v4::Fattr = client
            .named_attr_supported_attr_values(
                "/export/object",
                "user.comment",
                &[nfs::v4::FATTR4_SIZE, nfs::v4::FATTR4_MODE],
            )
            .await?;
        let _value: Vec<u8> = client
            .read_named_attr("/export/object", "user.comment")
            .await?;
        let mut sink = Vec::new();
        let _written: u64 = client
            .read_named_attr_to_writer("/export/object", "user.comment", &mut sink)
            .await?;
        let _range: Vec<u8> = client
            .read_named_attr_range("/export/object", "user.comment", 0, 16)
            .await?;
        let _at: Vec<u8> = client
            .read_named_attr_at("/export/object", "user.comment", 0, 16)
            .await?;
        let _exact: Vec<u8> = client
            .read_named_attr_exact_at("/export/object", "user.comment", 0, 16)
            .await?;
        let mut sink = Vec::new();
        let _written: u64 = client
            .read_named_attr_range_to_writer("/export/object", "user.comment", 0, 16, &mut sink)
            .await?;
        client
            .write_named_attr("/export/object", "user.comment", b"value")
            .await?;
        client
            .write_named_attr_with_mode("/export/object", "user.comment", b"value", 0o600)
            .await?;
        let mut reader = tokio::io::empty();
        let _written: u64 = client
            .write_named_attr_from_reader("/export/object", "user.comment", &mut reader)
            .await?;
        let mut reader = tokio::io::empty();
        let _written: u64 = client
            .write_named_attr_from_reader_with_mode(
                "/export/object",
                "user.comment",
                &mut reader,
                0o600,
            )
            .await?;
        client
            .write_named_attr_atomic("/export/object", "user.comment", b"value")
            .await?;
        client
            .write_named_attr_atomic_with_mode("/export/object", "user.comment", b"value", 0o600)
            .await?;
        let mut reader = tokio::io::empty();
        let _written: u64 = client
            .write_named_attr_atomic_from_reader("/export/object", "user.comment", &mut reader)
            .await?;
        let mut reader = tokio::io::empty();
        let _written: u64 = client
            .write_named_attr_atomic_from_reader_with_mode(
                "/export/object",
                "user.comment",
                &mut reader,
                0o600,
            )
            .await?;
        client
            .write_named_attr_at("/export/object", "user.comment", 0, b"value")
            .await?;
        let _copied: u64 = client
            .copy_named_attr(
                "/export/object",
                "user.comment",
                "/export/object",
                "user.copy",
            )
            .await?;
        let _copied: u64 = client
            .copy_named_attr_atomic(
                "/export/object",
                "user.comment",
                "/export/object",
                "user.copy",
            )
            .await?;
        let _appended: u64 = client
            .append_named_attr("/export/object", "user.comment", b"value")
            .await?;
        let mut reader = tokio::io::empty();
        let _appended: u64 = client
            .append_named_attr_from_reader("/export/object", "user.comment", &mut reader)
            .await?;
        client
            .set_named_attr_attrs(
                "/export/object",
                "user.comment",
                &nfs::v4::SetAttrs::mode(0o644),
            )
            .await?;
        client
            .set_named_attr_mode("/export/object", "user.comment", 0o644)
            .await?;
        client
            .set_named_attr_ownership("/export/object", "user.comment", "owner", "group")
            .await?;
        client
            .set_named_attr_times(
                "/export/object",
                "user.comment",
                Some(nfs::v4::NfsTime {
                    seconds: 0,
                    nseconds: 0,
                }),
                None,
            )
            .await?;
        client
            .truncate_named_attr("/export/object", "user.comment", 0)
            .await?;
        client
            .rename_named_attr("/export/object", "user.copy", "user.renamed")
            .await?;
        let _renamed: bool = client
            .rename_named_attr_if_exists("/export/object", "user.renamed", "user.copy")
            .await?;
        client
            .remove_named_attr("/export/object", "user.comment")
            .await?;
        let _removed: bool = client
            .remove_named_attr_if_exists("/export/object", "user.comment")
            .await?;
        Ok(())
    }

    let _ = uses_api;
}

#[cfg(feature = "tokio")]
#[test]
fn exposes_tokio_v4_delegation_api_shapes() {
    async fn uses_api(mut client: nfs::v4::tokio::Client) -> nfs::Result<()> {
        let stateid = nfs::v4::StateId::anonymous();
        let _delegation: nfs::v4::OpenDelegation = client
            .want_delegation(
                "/export/object",
                nfs::v4::OPEN4_SHARE_ACCESS_WANT_READ_DELEG,
            )
            .await?;
        let _delegation: nfs::v4::OpenDelegation = client
            .want_delegation_with_claim(
                "/export/object",
                nfs::v4::OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG,
                nfs::v4::DelegationClaim::FileHandle,
            )
            .await?;
        let args = nfs::v4::GetDirDelegationArgs {
            signal_deleg_avail: false,
            notification_types: nfs::v4::Bitmap::empty(),
            child_attr_delay: nfs::v4::NfsTime {
                seconds: 0,
                nseconds: 0,
            },
            dir_attr_delay: nfs::v4::NfsTime {
                seconds: 0,
                nseconds: 0,
            },
            child_attributes: nfs::v4::Bitmap::empty(),
            dir_attributes: nfs::v4::Bitmap::empty(),
        };
        let _dir_delegation: nfs::v4::GetDirDelegationResult =
            client.get_dir_delegation("/export/dir", args).await?;
        client.return_delegation("/export/object", stateid).await?;
        client.purge_delegations().await?;
        let _claim = nfs::v4::DelegationClaim::Previous(nfs::v4::OpenDelegationType::Read);
        let _reason = nfs::v4::WhyNoDelegation::NotWanted;
        let _mask = nfs::v4::OPEN4_SHARE_ACCESS_WANT_DELEG_MASK;
        Ok(())
    }

    let _ = uses_api;
}

#[cfg(feature = "tokio")]
#[test]
fn exposes_tokio_v4_copy_notify_api_shapes() {
    async fn uses_api(mut client: nfs::v4::tokio::Client) -> nfs::Result<()> {
        let stateid = nfs::v4::StateId::anonymous();
        let destination = nfs::v4::NetLoc::Name("dest.example".to_owned());
        let _notify: nfs::v4::CopyNotifyResult = client
            .copy_notify("/export/source", destination.clone())
            .await?;
        let _notify: nfs::v4::CopyNotifyResult = client
            .copy_notify_with_stateid("/export/source", stateid, destination)
            .await?;
        let _copy: nfs::v4::CopyResult = client
            .copy_range_offload_with_options(
                "/export/source",
                "/export/target",
                0,
                0,
                4096,
                true,
                false,
                vec![nfs::v4::NetLoc::Url("nfs://source/export".to_owned())],
            )
            .await?;
        Ok(())
    }

    let _ = uses_api;
}

#[cfg(feature = "tokio")]
#[test]
fn exposes_tokio_v4_pnfs_device_api_shapes() {
    async fn uses_api(mut client: nfs::v4::tokio::Client) -> nfs::Result<()> {
        let device_id: nfs::v4::DeviceId = [0; 16];
        let layout_type = nfs::v4::LayoutType::NfsV4_1Files;
        let _info: nfs::v4::GetDeviceInfoResult =
            client.get_device_info(device_id, layout_type).await?;
        let _info: nfs::v4::GetDeviceInfoResult = client
            .get_device_info_with_notify(device_id, layout_type, 1024, nfs::v4::Bitmap::empty())
            .await?;
        let _ids: Vec<nfs::v4::DeviceId> = client.list_devices(layout_type).await?;
        let _ids: Vec<nfs::v4::DeviceId> = client.list_devices_limited(layout_type, 16).await?;
        let _page: nfs::v4::DeviceListPage = client.list_device_page(layout_type, None).await?;
        let _page: nfs::v4::DeviceListPage = client
            .list_device_page_limited(layout_type, None, 16)
            .await?;
        let iomode = nfs::v4::LayoutIomode::Read;
        let stateid = nfs::v4::StateId::anonymous();
        let _layout: nfs::v4::LayoutGetResult = client
            .layout_get("/export/object", layout_type, iomode, 0, 1024, 1024)
            .await?;
        let _layout: nfs::v4::LayoutGetResult = client
            .layout_get_with_options(
                "/export/object",
                layout_type,
                iomode,
                0,
                1024,
                1024,
                4096,
                false,
            )
            .await?;
        let layout_update = nfs::v4::LayoutUpdate {
            layout_type,
            body: Vec::new(),
        };
        let _committed: nfs::v4::LayoutCommitResult = client
            .layout_commit("/export/object", 0, 1024, stateid, layout_update.clone())
            .await?;
        let _committed: nfs::v4::LayoutCommitResult = client
            .layout_commit_with_options(
                "/export/object",
                0,
                1024,
                stateid,
                Some(1023),
                None,
                layout_update.clone(),
                false,
            )
            .await?;
        client
            .layout_error(
                "/export/object",
                0,
                1024,
                stateid,
                vec![nfs::v4::DeviceError {
                    device_id,
                    status: nfs::v4::Status::Io,
                    opnum: nfs::v4::OpCode::Read,
                }],
            )
            .await?;
        client
            .layout_stats(
                "/export/object",
                0,
                1024,
                stateid,
                nfs::v4::IoInfo { count: 1, bytes: 2 },
                nfs::v4::IoInfo { count: 3, bytes: 4 },
                device_id,
                layout_update.clone(),
            )
            .await?;
        let _returned: nfs::v4::LayoutReturnResult = client
            .layout_return_file(
                "/export/object",
                layout_type,
                iomode,
                0,
                1024,
                stateid,
                Vec::new(),
            )
            .await?;
        let _returned: nfs::v4::LayoutReturnResult = client
            .layout_return_fsid("/export/object", layout_type, iomode)
            .await?;
        let _returned: nfs::v4::LayoutReturnResult =
            client.layout_return_all(layout_type, iomode).await?;
        let _content = nfs::v4::LayoutContent {
            layout_type,
            body: Vec::new(),
        };
        let _cursor = nfs::v4::DeviceListCursor::default();
        let _addr = nfs::v4::DeviceAddr {
            layout_type,
            body: Vec::new(),
        };
        Ok(())
    }

    let _ = uses_api;
}

#[cfg(feature = "tokio")]
#[test]
fn exposes_tokio_v4_security_info_api_shapes() {
    async fn uses_api(mut client: nfs::v4::tokio::Client) -> nfs::Result<()> {
        let _flavors: Vec<nfs::v4::SecInfo> = client.secinfo("/export/object").await?;
        let _flavors: Vec<nfs::v4::SecInfo> = client
            .secinfo_no_name("/export/object", nfs::v4::SecInfoStyle::CurrentFileHandle)
            .await?;
        let _flavors: Vec<nfs::v4::SecInfo> = client.secinfo_current("/export/object").await?;
        let _flavors: Vec<nfs::v4::SecInfo> = client.secinfo_parent("/export/object").await?;
        let _service = nfs::v4::RpcGssService::None;
        let _raw_attrs: nfs::v4::Fattr = client
            .getattr_values(
                "/export/object",
                nfs::v4::Bitmap::from_attrs(&[nfs::v4::FATTR4_SIZE, nfs::v4::FATTR4_MODE])?,
            )
            .await?;
        let _raw_attrs: nfs::v4::Fattr = client
            .supported_attr_values(
                "/export/object",
                &[nfs::v4::FATTR4_SIZE, nfs::v4::FATTR4_MODE],
            )
            .await?;
        let _handle: nfs::v4::FileHandle = client.file_handle("/export/object").await?;
        client.lookup_public("/export/object").await?;
        let _exists: bool = client.public_exists("/export/object").await?;
        let _handle: nfs::v4::FileHandle = client.public_file_handle("/export/object").await?;
        let _access: nfs::v4::AccessResult = client
            .public_access("/export/object", nfs::v4::ACCESS4_READ)
            .await?;
        let _attrs: nfs::v4::BasicAttributes = client.public_getattr("/export/object").await?;
        let _supported: nfs::v4::Bitmap = client.public_supported_attrs("/export/object").await?;
        let _raw_attrs: nfs::v4::Fattr = client
            .public_getattr_values(
                "/export/object",
                nfs::v4::Bitmap::from_attrs(&[nfs::v4::FATTR4_SIZE, nfs::v4::FATTR4_MODE])?,
            )
            .await?;
        let _raw_attrs: nfs::v4::Fattr = client
            .public_supported_attr_values(
                "/export/object",
                &[nfs::v4::FATTR4_SIZE, nfs::v4::FATTR4_MODE],
            )
            .await?;
        let _fsstat: nfs::v4::FsStat = client.public_fsstat("/export/object").await?;
        let _fsinfo: nfs::v4::FsInfo = client.public_fsinfo("/export/object").await?;
        let _pathconf: nfs::v4::PathConf = client.public_pathconf("/export/object").await?;
        let _entries: Vec<nfs::v4::DirEntry> = client.public_read_dir("/export").await?;
        let _entries: Vec<nfs::v4::DirEntry> =
            client.public_read_dir_limited("/export", 16).await?;
        let _page: nfs::v4::DirPage = client.public_read_dir_page("/export", None).await?;
        let _page: nfs::v4::DirPage = client
            .public_read_dir_page_limited("/export", None, 16)
            .await?;
        let _handle: nfs::v4::FileHandle = client.parent_file_handle("/export/object").await?;
        let _access: nfs::v4::AccessResult = client
            .parent_access("/export/object", nfs::v4::ACCESS4_LOOKUP)
            .await?;
        let _attrs: nfs::v4::BasicAttributes = client.parent_getattr("/export/object").await?;
        let _supported: nfs::v4::Bitmap = client.parent_supported_attrs("/export/object").await?;
        let _raw_attrs: nfs::v4::Fattr = client
            .parent_getattr_values(
                "/export/object",
                nfs::v4::Bitmap::from_attrs(&[nfs::v4::FATTR4_SIZE, nfs::v4::FATTR4_MODE])?,
            )
            .await?;
        let _raw_attrs: nfs::v4::Fattr = client
            .parent_supported_attr_values(
                "/export/object",
                &[nfs::v4::FATTR4_SIZE, nfs::v4::FATTR4_MODE],
            )
            .await?;
        let _fsstat: nfs::v4::FsStat = client.parent_fsstat("/export/object").await?;
        let _fsinfo: nfs::v4::FsInfo = client.parent_fsinfo("/export/object").await?;
        let _pathconf: nfs::v4::PathConf = client.parent_pathconf("/export/object").await?;
        let _entries: Vec<nfs::v4::DirEntry> = client.parent_read_dir("/export/object").await?;
        let _entries: Vec<nfs::v4::DirEntry> =
            client.parent_read_dir_limited("/export/object", 16).await?;
        let _page: nfs::v4::DirPage = client.parent_read_dir_page("/export/object", None).await?;
        let _page: nfs::v4::DirPage = client
            .parent_read_dir_page_limited("/export/object", None, 16)
            .await?;
        let _matched: bool = client
            .verify_attrs("/export/object", &nfs::v4::Fattr::mode(0o644))
            .await?;
        let _not_matched: bool = client
            .nverify_attrs("/export/object", &nfs::v4::Fattr::mode(0o600))
            .await?;
        client
            .backchannel_ctl(0, vec![nfs::v4::CallbackSecParms::AuthNone])
            .await?;
        let _bound: nfs::v4::BindConnToSessionResult = client
            .bind_conn_to_session(nfs::v4::ChannelDirFromClient::Fore)
            .await?;
        let _bound: nfs::v4::BindConnToSessionResult = client
            .bind_conn_to_session_with_options(nfs::v4::ChannelDirFromClient::ForeOrBoth, false)
            .await?;
        let _direction = nfs::v4::ChannelDirFromServer::Fore;
        let _set_ssv: nfs::v4::SetSsvResult = client.set_ssv(Vec::new(), Vec::new()).await?;
        client.destroy_client_id().await?;
        Ok(())
    }

    let _ = uses_api;
}
