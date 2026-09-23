//! Minimal NFSv3 Tokio quickstart.
//!
//! For a broader end-to-end example, see `examples/v3_tokio_cookbook.rs`.

#[cfg(feature = "tokio")]
use std::time::Duration;

#[cfg(feature = "tokio")]
use nfs::v3::tokio::ClientBuilder;

#[cfg(feature = "tokio")]
const CONTENT: &[u8] = b"hello from async nfs-rs over NFSv3\n";

#[cfg(feature = "tokio")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> nfs::Result<()> {
    // Usage:
    //   cargo run --example tokio_basic --features tokio -- 127.0.0.1:/export /writable-dir
    //
    // The first argument is an NFSv3 target in `host:/export` form.
    // The second argument is a writable directory inside that export.
    let mut args = std::env::args().skip(1);
    let target = args
        .next()
        .unwrap_or_else(|| "127.0.0.1:/export".to_owned());
    let dir = args.next().unwrap_or_else(|| "/".to_owned());
    let file = remote_path(&dir, &format!("nfs-rs-v3-async-{}.txt", std::process::id()));

    let mut client = ClientBuilder::from_target(&target)?
        .timeout(Some(Duration::from_secs(10)))
        .connect()
        .await?;

    println!("connected to NFSv3 target {target}");
    println!("writing {file}");
    client.write_atomic(&file, CONTENT).await?;

    let data = client.read(&file).await?;
    println!("read: {}", String::from_utf8_lossy(&data));

    let range = client.read_range(&file, 0, 5).await?;
    println!("first 5 bytes: {:?}", String::from_utf8_lossy(&range));

    let metadata = client.metadata(&file).await?;
    println!(
        "metadata: type={:?} size={} mode={:o}",
        metadata.file_type,
        metadata.size,
        metadata.mode & 0o777
    );

    println!("first entries in {dir}:");
    for entry in client.read_dir(&dir).await?.into_iter().take(8) {
        println!("  {}", entry.name);
    }

    client.remove_if_exists(&file).await?;
    println!("removed {file}");
    Ok(())
}

#[cfg(feature = "tokio")]
fn remote_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{}/{name}", parent.trim_end_matches('/'))
    }
}

#[cfg(not(feature = "tokio"))]
fn main() {
    eprintln!("enable the `tokio` feature to run this example");
}
