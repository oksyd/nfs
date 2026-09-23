//! Minimal NFSv3 blocking quickstart.
//!
//! For a broader end-to-end example, see `examples/v3_cookbook.rs`.

use std::time::Duration;

use nfs::v3::blocking::ClientBuilder;

const CONTENT: &[u8] = b"hello from nfs-rs over NFSv3\n";

fn main() -> nfs::Result<()> {
    // Usage:
    //   cargo run --example basic -- 127.0.0.1:/export /writable-dir
    //
    // The first argument is an NFSv3 target in `host:/export` form.
    // The second argument is a writable directory inside that export.
    let mut args = std::env::args().skip(1);
    let target = args
        .next()
        .unwrap_or_else(|| "127.0.0.1:/export".to_owned());
    let dir = args.next().unwrap_or_else(|| "/".to_owned());
    let file = remote_path(&dir, &format!("nfs-rs-v3-{}.txt", std::process::id()));

    let mut client = ClientBuilder::from_target(&target)?
        .timeout(Some(Duration::from_secs(10)))
        .connect()?;

    println!("connected to NFSv3 target {target}");
    println!("writing {file}");
    client.write_atomic(&file, CONTENT)?;

    let data = client.read(&file)?;
    println!("read: {}", String::from_utf8_lossy(&data));

    let range = client.read_range(&file, 0, 5)?;
    println!("first 5 bytes: {:?}", String::from_utf8_lossy(&range));

    let metadata = client.metadata(&file)?;
    println!(
        "metadata: type={:?} size={} mode={:o}",
        metadata.file_type,
        metadata.size,
        metadata.mode & 0o777
    );

    println!("first entries in {dir}:");
    for entry in client.read_dir(&dir)?.into_iter().take(8) {
        println!("  {}", entry.name);
    }

    client.remove_if_exists(&file)?;
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
