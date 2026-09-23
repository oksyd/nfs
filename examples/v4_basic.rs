//! Minimal NFSv4.2 blocking quickstart.
//!
//! For a broader end-to-end example, see `examples/v4_cookbook.rs`.

use std::time::Duration;

use nfs::v4::blocking::Client;

const CONTENT: &[u8] = b"hello from nfs-rs over NFSv4\n";

fn main() -> nfs::Result<()> {
    // Usage:
    //   cargo run --example v4_basic -- 127.0.0.1 /export/writable-dir
    //
    // The first argument is the NFSv4 server host.
    // The second argument is a writable path in the server's v4 pseudo-filesystem.
    let mut args = std::env::args().skip(1);
    let host = args.next().unwrap_or_else(|| "127.0.0.1".to_owned());
    let dir = args.next().unwrap_or_else(|| "/".to_owned());
    let file = remote_path(&dir, &format!("nfs-rs-v4-{}.txt", std::process::id()));

    let mut client = Client::builder(host.clone())
        .timeout(Some(Duration::from_secs(10)))
        .connect()?;

    println!("connected to NFSv4 host {host}");
    println!("writing {file}");
    client.write_atomic(&file, CONTENT)?;

    let data = client.read(&file)?;
    println!("read: {}", String::from_utf8_lossy(&data));

    let range = client.read_range(&file, 0, 5)?;
    println!("first 5 bytes: {:?}", String::from_utf8_lossy(&range));

    let metadata = client.metadata(&file)?;
    println!(
        "metadata: type={:?} size={:?} mode={:?}",
        metadata.file_type, metadata.size, metadata.mode
    );

    println!("first entries in {dir}:");
    for entry in client.read_dir(&dir)?.into_iter().take(8) {
        let metadata = entry.basic_attributes()?;
        println!("  {} {:?}", entry.name, metadata.file_type);
    }

    client.remove_if_exists(&file)?;
    client.shutdown()?;
    println!("removed {file}");
    Ok(())
}

fn remote_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{}/{name}", parent.trim_end_matches('/'))
    }
}
