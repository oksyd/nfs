#![cfg(feature = "tokio")]

use nfs::v3::tokio::{Client, ClientBuilder, RemoteTarget};

#[tokio::test(flavor = "current_thread")]
async fn exposes_tokio_api_shapes() {
    let target = RemoteTarget::parse("127.0.0.1:/export").unwrap();
    assert_eq!(target.host, "127.0.0.1");
    assert_eq!(target.export, "/export");

    let _builder = Client::builder("127.0.0.1", "/export")
        .timeout(None)
        .mount_port(111)
        .nfs_port(2049)
        .io_size(64 * 1024)
        .dir_size(32 * 1024)
        .max_dir_entries(1024)
        .retry_policy(nfs::RetryPolicy::disabled());

    let _builder = ClientBuilder::from_target("[::1]:/export").unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn exposes_v4_tokio_api_shapes() {
    let _builder = nfs::v4::tokio::Client::builder("127.0.0.1")
        .timeout(None)
        .port(2049)
        .owner_id(b"test-client".to_vec())
        .open_owner(b"test-open-owner".to_vec())
        .client_owner_verifier([7; nfs::v4::NFS4_VERIFIER_SIZE])
        .read_size(64 * 1024)
        .write_size(64 * 1024)
        .dir_size(32 * 1024)
        .max_dir_entries(1024)
        .max_minor_version(nfs::v4::NFS4_MINOR_VERSION_V42)
        .retry_policy(nfs::RetryPolicy::disabled());

    let _mask = nfs::v4::ACCESS4_READ | nfs::v4::ACCESS4_LOOKUP;
}
