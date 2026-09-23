//! NFSv3 blocking cookbook.
//!
//! Run against a writable export:
//!
//! ```text
//! cargo run --example v3_cookbook -- 127.0.0.1:/export /writable-dir
//! ```
//!
//! The first argument is the NFSv3 target in `host:/export` form. The second
//! argument is a writable directory path inside that export.

use std::io::Cursor;
use std::time::Duration;

use nfs::v3::blocking::{Client, ClientBuilder};
use nfs::v3::{
    ACCESS3_DELETE, ACCESS3_EXTEND, ACCESS3_LOOKUP, ACCESS3_MODIFY, ACCESS3_READ, DirPageCursor,
    FileAttr, StableHow,
};
use nfs::{AuthSys, RetryPolicy};

const OBJECT: &[u8] = b"nfs-rs v3 cookbook object\nline two\nline three\n";
const STREAMED: &[u8] = b"streamed through write_from_reader\n";

fn main() -> nfs::Result<()> {
    let config = Config::from_env();
    let mut client = connect(&config.target)?;

    println!("connected to NFSv3 target {}", config.target);
    if let Some(info) = client.fsinfo() {
        println!(
            "server fsinfo: read_preferred={} write_preferred={} dir_preferred={}",
            info.read_preferred, info.write_preferred, info.dir_preferred
        );
    }

    let work_dir = remote_path(
        &config.remote_dir,
        &format!("nfs-rs-v3-cookbook-{}", std::process::id()),
    );
    client.remove_all_if_exists(&work_dir)?;
    client.create_dir_all(&work_dir, 0o755)?;

    let flow_result = run_filesystem_flow(&mut client, &work_dir);
    let cleanup_result = client.remove_all_if_exists(&work_dir);
    let unmount_result = client.unmount();
    finish(flow_result, cleanup_result, unmount_result)
}

fn connect(target: &str) -> nfs::Result<Client> {
    ClientBuilder::from_target(target)?
        .auth_sys(AuthSys::current())
        .timeout(Some(Duration::from_secs(10)))
        .io_size(128 * 1024)
        .dir_size(64 * 1024)
        .max_dir_entries(4096)
        .retry_policy(RetryPolicy::new(
            4,
            Duration::from_millis(50),
            Duration::from_secs(2),
        ))
        .connect()
}

fn run_filesystem_flow(client: &mut Client, work_dir: &str) -> nfs::Result<()> {
    let object = remote_path(work_dir, "object.txt");
    let streamed = remote_path(work_dir, "streamed.txt");
    let created = remote_path(work_dir, "created.txt");
    let copied = remote_path(work_dir, "copied.txt");
    let renamed = remote_path(work_dir, "renamed.txt");
    let nested_dir = remote_path(work_dir, "nested/a/b");
    let nested_file = remote_path(&nested_dir, "payload.bin");

    println!("workspace: {work_dir}");

    client.write_atomic_with_mode_and_stability(&object, OBJECT, 0o640, StableHow::FileSync)?;
    print_v3_metadata("object after atomic write", &client.metadata(&object)?);

    let exists = client.exists(&object)?;
    println!("exists({object}) = {exists}");

    let access = client.access(
        &object,
        ACCESS3_READ | ACCESS3_LOOKUP | ACCESS3_MODIFY | ACCESS3_EXTEND | ACCESS3_DELETE,
    )?;
    println!("access mask granted by server: 0x{:x}", access.access);

    let first_five = client.read_exact_at(&object, 0, 5)?;
    println!(
        "first five bytes: {:?}",
        String::from_utf8_lossy(&first_five)
    );

    let middle = client.read_range(&object, 7, 14)?;
    println!("range read: {:?}", String::from_utf8_lossy(&middle));

    let mut downloaded = Vec::new();
    let downloaded_len = client.read_to_writer(&object, &mut downloaded)?;
    println!(
        "streamed object into local Vec: {downloaded_len} bytes, {}",
        String::from_utf8_lossy(&downloaded)
    );

    let mut upload = Cursor::new(STREAMED);
    let uploaded_len = client.write_atomic_from_reader_with_mode_and_stability(
        &streamed,
        &mut upload,
        0o644,
        StableHow::FileSync,
    )?;
    println!("streamed upload wrote {uploaded_len} bytes");

    client.append_with_stability(&streamed, b"appended\n", StableHow::FileSync)?;
    client.write_at_with_stability(&streamed, 0, b"STREAMED", StableHow::FileSync)?;
    client.truncate(&streamed, 24)?;
    let commit = client.commit(&streamed, 0, 0)?;
    println!("commit verifier: {:02x?}", commit.verifier);

    client.create_new(&created, 0o600)?;
    client.write_at_with_stability(
        &created,
        0,
        b"created with create_new\n",
        StableHow::FileSync,
    )?;
    let _ = optional(
        "create_new existing file",
        client.create_new(&created, 0o600),
    );

    let copied_len = client.copy_atomic_with_stability(&streamed, &copied, StableHow::FileSync)?;
    println!("copied {copied_len} bytes from {streamed} to {copied}");

    client.rename(&copied, &renamed)?;
    let _ = optional("touch", client.touch(&renamed));
    let _ = optional("set_mode", client.set_mode(&renamed, 0o644));

    client.create_dir_all(&nested_dir, 0o755)?;
    client.write_atomic(&nested_file, b"nested file\n")?;

    demonstrate_optional_links(client, &object, work_dir)?;
    demonstrate_directory_reads(client, work_dir)?;
    demonstrate_filesystem_queries(client, work_dir)?;
    demonstrate_error_handling(client, work_dir);
    demonstrate_reconnect(client, work_dir)?;

    Ok(())
}

fn demonstrate_optional_links(
    client: &mut Client,
    object: &str,
    work_dir: &str,
) -> nfs::Result<()> {
    let symlink = remote_path(work_dir, "object.symlink");
    if optional("symlink", client.symlink(&symlink, "object.txt")).is_some() {
        let target = client.read_link(&symlink)?;
        println!("symlink target: {target}");
    }

    let hard_link = remote_path(work_dir, "object.hardlink");
    if optional("hard_link", client.hard_link(object, &hard_link)).is_some() {
        println!("created hard link: {hard_link}");
    }

    Ok(())
}

fn demonstrate_directory_reads(client: &mut Client, work_dir: &str) -> nfs::Result<()> {
    println!("limited directory listing:");
    for entry in client.read_dir_limited(work_dir, 16)? {
        let kind = entry
            .attributes
            .as_ref()
            .map(|attrs| format!("{:?}", attrs.file_type))
            .unwrap_or_else(|| "unknown".to_owned());
        println!("  {} fileid={} type={kind}", entry.name, entry.fileid);
    }

    println!("paged directory listing:");
    let mut cursor: Option<DirPageCursor> = None;
    loop {
        let page = client.read_dir_page_limited(work_dir, cursor, 4)?;
        for entry in &page.entries {
            println!("  page entry: {}", entry.name);
        }
        if page.is_eof() {
            break;
        }
        cursor = page.next_cursor;
    }

    Ok(())
}

fn demonstrate_filesystem_queries(client: &mut Client, work_dir: &str) -> nfs::Result<()> {
    let fsstat = client.fsstat(work_dir)?;
    println!(
        "fsstat: total={} free={} available={}",
        fsstat.total_bytes, fsstat.free_bytes, fsstat.available_bytes
    );

    let pathconf = client.pathconf(work_dir)?;
    println!(
        "pathconf: name_max={} link_max={} case_preserving={}",
        pathconf.name_max, pathconf.link_max, pathconf.case_preserving
    );

    Ok(())
}

fn demonstrate_error_handling(client: &mut Client, work_dir: &str) {
    let missing = remote_path(work_dir, "does-not-exist.txt");
    match client.read(&missing) {
        Ok(_) => println!("unexpectedly read missing file"),
        Err(err) if err.is_not_found() => println!("missing file classified as not found"),
        Err(err) if err.is_retryable() => println!("retryable error: {err}"),
        Err(err) if err.is_permission_denied() => println!("permission error: {err}"),
        Err(err) => println!("other read error: {err}"),
    }
}

fn demonstrate_reconnect(client: &mut Client, work_dir: &str) -> nfs::Result<()> {
    client.reconnect()?;
    println!(
        "reconnected; workspace still exists = {}",
        client.exists(work_dir)?
    );
    Ok(())
}

fn print_v3_metadata(label: &str, metadata: &FileAttr) {
    println!(
        "{label}: type={:?} size={} used={} mode={:o} uid={} gid={}",
        metadata.file_type,
        metadata.size,
        metadata.used,
        metadata.mode & 0o7777,
        metadata.uid,
        metadata.gid
    );
}

fn optional<T>(operation: &str, result: nfs::Result<T>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(err) => {
            println!(
                "optional operation {operation} skipped: {err} ({})",
                classify_error(&err)
            );
            None
        }
    }
}

fn classify_error(err: &nfs::Error) -> &'static str {
    if err.is_not_found() {
        "not found"
    } else if err.is_permission_denied() {
        "permission denied"
    } else if err.is_retryable() {
        "retryable"
    } else if err.is_no_space() {
        "no space"
    } else if err.is_read_only() {
        "read-only filesystem"
    } else if err.is_stale_handle() {
        "stale handle"
    } else if err.is_already_exists() {
        "already exists"
    } else {
        "unclassified"
    }
}

fn finish(
    flow_result: nfs::Result<()>,
    cleanup_result: nfs::Result<bool>,
    unmount_result: nfs::Result<()>,
) -> nfs::Result<()> {
    match flow_result {
        Ok(()) => {
            cleanup_result?;
            if let Err(err) = unmount_result {
                println!("optional unmount skipped: {err}");
            }
            Ok(())
        }
        Err(err) => {
            if let Err(cleanup_err) = cleanup_result {
                println!("cleanup after failure also failed: {cleanup_err}");
            }
            if let Err(unmount_err) = unmount_result {
                println!("optional unmount after failure skipped: {unmount_err}");
            }
            Err(err)
        }
    }
}

fn remote_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{}/{name}", parent.trim_end_matches('/'))
    }
}

struct Config {
    target: String,
    remote_dir: String,
}

impl Config {
    fn from_env() -> Self {
        let mut args = std::env::args().skip(1);
        Self {
            target: args
                .next()
                .unwrap_or_else(|| "127.0.0.1:/export".to_owned()),
            remote_dir: args.next().unwrap_or_else(|| "/".to_owned()),
        }
    }
}
