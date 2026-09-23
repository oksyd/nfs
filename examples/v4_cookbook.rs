//! NFSv4.2 blocking cookbook.
//!
//! Run against a writable path in the server's v4 pseudo-filesystem:
//!
//! ```text
//! cargo run --example v4_cookbook -- 127.0.0.1 /export/writable-dir
//! ```
//!
//! The first argument is the NFSv4 server host. The second argument is an
//! absolute writable path as seen through the NFSv4 pseudo-filesystem.

use std::io::Cursor;
use std::time::Duration;

use nfs::v4::blocking::Client;
use nfs::v4::{
    ACCESS4_DELETE, ACCESS4_EXTEND, ACCESS4_LOOKUP, ACCESS4_MODIFY, ACCESS4_READ, BasicAttributes,
    DirPageCursor, FATTR4_MODE, FATTR4_OWNER, FATTR4_OWNER_GROUP, FATTR4_SIZE, LockType,
};
use nfs::{AuthSys, RetryPolicy};

const OBJECT: &[u8] = b"nfs-rs v4 cookbook object\nline two\nline three\n";
const STREAMED: &[u8] = b"streamed through NFSv4 open/write/close\n";

fn main() -> nfs::Result<()> {
    let config = Config::from_env();
    let mut client = connect(&config.host)?;

    println!("connected to NFSv4 host {}", config.host);
    if let Some(info) = client.root_fsinfo() {
        println!(
            "root fsinfo: max_read={:?} max_write={:?} lease={:?}",
            info.max_read, info.max_write, info.lease_time_seconds
        );
    }

    let work_dir = remote_path(
        &config.remote_dir,
        &format!("nfs-rs-v4-cookbook-{}", std::process::id()),
    );
    client.remove_all_if_exists(&work_dir)?;
    client.create_dir_all(&work_dir, 0o755)?;

    let flow_result = run_filesystem_flow(&mut client, &work_dir);
    let cleanup_result = client.remove_all_if_exists(&work_dir);
    let shutdown_result = client.shutdown();
    finish(flow_result, cleanup_result, shutdown_result)
}

fn connect(host: &str) -> nfs::Result<Client> {
    let process_id = std::process::id();
    Client::builder(host.to_owned())
        .auth_sys(AuthSys::current())
        .timeout(Some(Duration::from_secs(10)))
        .port(2049)
        .owner_id(format!("nfs-rs:v4-cookbook:{host}:{process_id}").into_bytes())
        .open_owner(format!("nfs-rs:v4-open-owner:{process_id}").into_bytes())
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
    let offloaded = remote_path(work_dir, "offloaded.txt");
    let renamed = remote_path(work_dir, "renamed.txt");
    let nested_dir = remote_path(work_dir, "nested/a/b");
    let nested_file = remote_path(&nested_dir, "payload.bin");

    println!("workspace: {work_dir}");

    client.write_atomic_with_mode(&object, OBJECT, 0o640)?;
    print_v4_metadata("object after atomic write", &client.metadata(&object)?);

    let exists = client.exists(&object)?;
    println!("exists({object}) = {exists}");

    let access = client.access(
        &object,
        ACCESS4_READ | ACCESS4_LOOKUP | ACCESS4_MODIFY | ACCESS4_EXTEND | ACCESS4_DELETE,
    )?;
    println!(
        "access mask: supported=0x{:x} granted=0x{:x}",
        access.supported, access.access
    );

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
    let uploaded_len = client.write_atomic_from_reader_with_mode(&streamed, &mut upload, 0o644)?;
    println!("streamed upload wrote {uploaded_len} bytes");

    client.append(&streamed, b"appended\n")?;
    client.write_at(&streamed, 0, b"STREAMED")?;
    client.truncate(&streamed, 24)?;
    let commit = client.commit(&streamed, 0, 0)?;
    println!("commit verifier: {:02x?}", commit.verifier);

    client.create_new_with_mode(&created, 0o600)?;
    client.write_at(&created, 0, b"created with create_new_with_mode\n")?;
    let _ = optional(
        "create_new_with_mode existing file",
        client.create_new_with_mode(&created, 0o600),
    );

    let copied_len = client.copy_atomic(&streamed, &copied)?;
    println!("copied {copied_len} bytes from {streamed} to {copied}");

    client.create_new_with_mode(&offloaded, 0o644)?;
    if let Some(response) = optional(
        "copy_range_offload",
        client.copy_range_offload(&streamed, &offloaded, 0, 0, copied_len),
    )
    .and_then(|result| result.response)
    {
        println!(
            "server-side COPY accepted {} bytes async={}",
            response.count,
            response.callback_id.is_some()
        );
    }

    client.rename(&copied, &renamed)?;
    let _ = optional("touch", client.touch(&renamed));
    let _ = optional("set_mode", client.set_mode(&renamed, 0o644));

    client.create_dir_all(&nested_dir, 0o755)?;
    client.write_atomic(&nested_file, b"nested file\n")?;

    demonstrate_optional_links(client, &object, work_dir)?;
    demonstrate_v4_sparse_file_ops(client, &object);
    demonstrate_v4_locking(client, &object)?;
    demonstrate_directory_reads(client, work_dir)?;
    demonstrate_filesystem_queries(client, work_dir)?;
    demonstrate_error_handling(client, work_dir);
    demonstrate_reconnect(client, work_dir)?;

    client.renew()?;
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

fn demonstrate_v4_sparse_file_ops(client: &mut Client, object: &str) {
    if let Some(offset) = optional("seek_data", client.seek_data(object, 0)) {
        println!("first data offset: {offset:?}");
    }
    if let Some(offset) = optional("seek_hole", client.seek_hole(object, 0)) {
        println!("first hole offset: {offset:?}");
    }
    if optional("allocate", client.allocate(object, 0, 4096)).is_some() {
        let _ = optional("deallocate", client.deallocate(object, 2048, 1024));
    }
}

fn demonstrate_v4_locking(client: &mut Client, object: &str) -> nfs::Result<()> {
    if let Some(conflict) = optional("test_lock", client.test_lock(object, LockType::Read, 0, 16)) {
        println!("read lock conflict: {}", conflict.is_some());
    }

    if let Some(lock) = optional("read_lock", client.read_lock(object, 0, 16)) {
        println!(
            "read lock granted: offset={} length={} owner_len={}",
            lock.offset(),
            lock.length(),
            lock.owner().len()
        );
        if let Some(status) = optional("test_stateid", client.test_stateid(lock.stateid())) {
            println!("lock stateid status: {status:?}");
        }
        client.unlock(lock)?;
        println!("read lock released");
    }

    Ok(())
}

fn demonstrate_directory_reads(client: &mut Client, work_dir: &str) -> nfs::Result<()> {
    println!("limited directory listing:");
    for entry in client.read_dir_limited(work_dir, 16)? {
        let attrs = entry.basic_attributes()?;
        println!(
            "  {} type={:?} size={:?}",
            entry.name, attrs.file_type, attrs.size
        );
    }

    println!("paged directory listing:");
    let mut cursor: Option<DirPageCursor> = None;
    loop {
        let page = client.read_dir_page_limited(work_dir, cursor, 4)?;
        for entry in &page.entries {
            let attrs = entry.basic_attributes()?;
            println!("  page entry: {} type={:?}", entry.name, attrs.file_type);
        }
        if page.is_eof() {
            break;
        }
        cursor = page.next_cursor;
    }

    Ok(())
}

fn demonstrate_filesystem_queries(client: &mut Client, work_dir: &str) -> nfs::Result<()> {
    let supported = client.supported_attrs(work_dir)?;
    println!(
        "supported attrs: size={} mode={} owner={} owner_group={}",
        supported.contains(FATTR4_SIZE),
        supported.contains(FATTR4_MODE),
        supported.contains(FATTR4_OWNER),
        supported.contains(FATTR4_OWNER_GROUP)
    );

    let fsstat = client.fsstat(work_dir)?;
    println!(
        "fsstat: total={:?} free={:?} available={:?}",
        fsstat.total_bytes, fsstat.free_bytes, fsstat.available_bytes
    );

    let fsinfo = client.fsinfo(work_dir)?;
    println!(
        "fsinfo: link_support={:?} symlink_support={:?} max_file_size={:?}",
        fsinfo.link_support, fsinfo.symlink_support, fsinfo.max_file_size
    );

    let pathconf = client.pathconf(work_dir)?;
    println!(
        "pathconf: name_max={:?} link_max={:?} case_preserving={:?}",
        pathconf.name_max, pathconf.link_max, pathconf.case_preserving
    );

    Ok(())
}

fn demonstrate_error_handling(client: &mut Client, work_dir: &str) {
    let missing = remote_path(work_dir, "does-not-exist.txt");
    match client.read(&missing) {
        Ok(_) => println!("unexpectedly read missing file"),
        Err(err) if err.is_not_found() => println!("missing file classified as not found"),
        Err(err) if err.is_session_recoverable() => println!("recoverable session error: {err}"),
        Err(err) if err.is_lost_state() => println!("lost NFSv4 state: {err}"),
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

fn print_v4_metadata(label: &str, metadata: &BasicAttributes) {
    println!(
        "{label}: type={:?} size={:?} mode={:?} owner={:?} group={:?}",
        metadata.file_type,
        metadata.size,
        metadata.mode.map(|mode| mode & 0o7777),
        metadata.owner,
        metadata.owner_group
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
    } else if err.is_session_recoverable() {
        "session recoverable"
    } else if err.is_lost_state() {
        "lost state"
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
    shutdown_result: nfs::Result<()>,
) -> nfs::Result<()> {
    match flow_result {
        Ok(()) => {
            cleanup_result?;
            shutdown_result?;
            Ok(())
        }
        Err(err) => {
            if let Err(cleanup_err) = cleanup_result {
                println!("cleanup after failure also failed: {cleanup_err}");
            }
            if let Err(shutdown_err) = shutdown_result {
                println!("shutdown after failure also failed: {shutdown_err}");
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
    host: String,
    remote_dir: String,
}

impl Config {
    fn from_env() -> Self {
        let mut args = std::env::args().skip(1);
        Self {
            host: args.next().unwrap_or_else(|| "127.0.0.1".to_owned()),
            remote_dir: args.next().unwrap_or_else(|| "/".to_owned()),
        }
    }
}
