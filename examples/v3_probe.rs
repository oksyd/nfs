//! Probe one or more paths inside an NFSv3 export and list directory entries.
//!
//! Usage:
//!   cargo run --example v3_probe -- --check-access --check-file-handle --check-fsinfo --check-parent --write-check --read-bytes 64 127.0.0.1:/export / /logs /data

use std::time::Duration;

use nfs::v3::blocking::ClientBuilder;
use nfs::v3::{
    ACCESS3_DELETE, ACCESS3_EXECUTE, ACCESS3_EXTEND, ACCESS3_LOOKUP, ACCESS3_MODIFY, ACCESS3_READ,
    FileAttr,
};
use nfs::{Error, RetryPolicy};

const DEFAULT_MAX_LIST_ENTRIES: usize = 64;
const DEFAULT_READ_BYTES: u64 = 0;
const DEFAULT_TIMEOUT_SECS: u64 = 10;
const MAX_READ_PREVIEW_BYTES: usize = 64;
const WRITE_CHECK_CONTENT: &[u8] = b"nfs-rs probe write check\n";
const V3_ACCESS_MASK: u32 = ACCESS3_READ
    | ACCESS3_LOOKUP
    | ACCESS3_MODIFY
    | ACCESS3_EXTEND
    | ACCESS3_DELETE
    | ACCESS3_EXECUTE;
const V3_ACCESS_BITS: &[(u32, &str)] = &[
    (ACCESS3_READ, "READ"),
    (ACCESS3_LOOKUP, "LOOKUP"),
    (ACCESS3_MODIFY, "MODIFY"),
    (ACCESS3_EXTEND, "EXTEND"),
    (ACCESS3_DELETE, "DELETE"),
    (ACCESS3_EXECUTE, "EXECUTE"),
];

fn main() -> nfs::Result<()> {
    let Some(config) = Config::from_env()? else {
        return Ok(());
    };

    let mut builder = ClientBuilder::from_target(&config.target)?
        .timeout(config.timeout)
        .max_dir_entries(config.max_entries)
        .retry_policy(RetryPolicy::default());
    if let Some(port) = config.mount_port {
        builder = builder.mount_port(port);
    }
    if let Some(port) = config.nfs_port {
        builder = builder.nfs_port(port);
    }
    let mut client = builder.connect()?;

    println!("connected to NFSv3 target {}", config.target);
    println!(
        "probe options: max_entries={} read_bytes={} check_access={} check_file_handle={} check_fsinfo={} check_parent={} write_check={} timeout={}",
        config.max_entries,
        config.read_bytes,
        config.check_access,
        config.check_file_handle,
        config.check_fsinfo,
        config.check_parent,
        config.write_check,
        timeout_text(config.timeout)
    );

    let options = ProbeOptions {
        max_entries: config.max_entries,
        read_bytes: config.read_bytes,
        check_access: config.check_access,
        check_file_handle: config.check_file_handle,
        check_fsinfo: config.check_fsinfo,
        check_parent: config.check_parent,
        write_check: config.write_check,
    };

    let mut failures = 0usize;
    for (path_index, path) in config.paths.iter().enumerate() {
        println!();
        if let Err(err) = probe_path(&mut client, path, options, path_index) {
            failures += 1;
            println!("{path}: ERROR: {err}");
        }
    }

    if let Err(err) = client.unmount() {
        println!("optional unmount skipped: {err}");
    }

    if failures == 0 {
        Ok(())
    } else {
        Err(Error::Protocol(format!("{failures} path(s) failed")))
    }
}

struct Config {
    target: String,
    paths: Vec<String>,
    timeout: Option<Duration>,
    max_entries: usize,
    read_bytes: u64,
    check_access: bool,
    check_file_handle: bool,
    check_fsinfo: bool,
    check_parent: bool,
    write_check: bool,
    mount_port: Option<u16>,
    nfs_port: Option<u16>,
}

#[derive(Debug, Clone, Copy)]
struct ProbeOptions {
    max_entries: usize,
    read_bytes: u64,
    check_access: bool,
    check_file_handle: bool,
    check_fsinfo: bool,
    check_parent: bool,
    write_check: bool,
}

impl Config {
    fn from_env() -> nfs::Result<Option<Self>> {
        let mut args = std::env::args();
        let program = args.next().unwrap_or_else(|| "v3_probe".to_owned());
        let mut positionals = Vec::new();
        let mut timeout = Some(Duration::from_secs(DEFAULT_TIMEOUT_SECS));
        let mut max_entries = DEFAULT_MAX_LIST_ENTRIES;
        let mut read_bytes = DEFAULT_READ_BYTES;
        let mut check_access = false;
        let mut check_file_handle = false;
        let mut check_fsinfo = false;
        let mut check_parent = false;
        let mut write_check = false;
        let mut mount_port = None;
        let mut nfs_port = None;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-h" | "--help" => {
                    print_usage(&program);
                    return Ok(None);
                }
                "--timeout-secs" => {
                    timeout = parse_timeout(&next_option_value(&mut args, "--timeout-secs")?)?;
                }
                "--max-entries" => {
                    max_entries =
                        parse_max_entries(&next_option_value(&mut args, "--max-entries")?)?;
                }
                "--read-bytes" => {
                    read_bytes = parse_read_bytes(&next_option_value(&mut args, "--read-bytes")?)?;
                }
                "--check-access" => {
                    check_access = true;
                }
                "--check-file-handle" => {
                    check_file_handle = true;
                }
                "--check-fsinfo" => {
                    check_fsinfo = true;
                }
                "--check-parent" => {
                    check_parent = true;
                }
                "--write-check" => {
                    write_check = true;
                }
                "--mount-port" => {
                    mount_port = Some(parse_port(
                        "--mount-port",
                        &next_option_value(&mut args, "--mount-port")?,
                    )?);
                }
                "--nfs-port" => {
                    nfs_port = Some(parse_port(
                        "--nfs-port",
                        &next_option_value(&mut args, "--nfs-port")?,
                    )?);
                }
                "--" => {
                    positionals.extend(args);
                    break;
                }
                option if option.starts_with('-') => {
                    print_usage(&program);
                    return Err(Error::Protocol(format!("unknown option {option}")));
                }
                _ => positionals.push(arg),
            }
        }

        if positionals.len() < 2 {
            print_usage(&program);
            return Err(Error::Protocol(
                "missing target or path argument".to_owned(),
            ));
        }

        let target = positionals[0].clone();
        let paths = positionals[1..].to_vec();
        for path in &paths {
            if path.is_empty() || !path.starts_with('/') {
                return Err(Error::InvalidPath(path.clone()));
            }
        }

        Ok(Some(Self {
            target,
            paths,
            timeout,
            max_entries,
            read_bytes,
            check_access,
            check_file_handle,
            check_fsinfo,
            check_parent,
            write_check,
            mount_port,
            nfs_port,
        }))
    }
}

fn probe_path(
    client: &mut nfs::v3::blocking::Client,
    path: &str,
    options: ProbeOptions,
    path_index: usize,
) -> nfs::Result<()> {
    let metadata = client.metadata(path)?;
    print_metadata(path, &metadata);
    if options.check_access {
        print_access(client, path)?;
    }
    if options.check_file_handle {
        print_file_handle(client, path)?;
    }
    if options.check_fsinfo {
        print_fsinfo(client, path)?;
    }
    if options.check_parent {
        print_parent_metadata(client, path)?;
    }

    if metadata.is_dir() {
        let entries = client.read_dir_limited(path, options.max_entries)?;
        println!("  entries: {}", entries.len());

        for entry in entries {
            println!(
                "  - {} fileid={} type={} size={} mode={} uid={} gid={}",
                entry.name,
                entry.fileid,
                file_type_text(entry.attributes.as_ref()),
                optional_attr_u64(entry.attributes.as_ref(), |attrs| attrs.size),
                optional_attr_mode(entry.attributes.as_ref()),
                optional_attr_u32(entry.attributes.as_ref(), |attrs| attrs.uid),
                optional_attr_u32(entry.attributes.as_ref(), |attrs| attrs.gid)
            );
        }
        if options.write_check {
            run_write_check(client, path, path_index)?;
        }
    } else if metadata.is_file() && options.read_bytes > 0 {
        let count = options.read_bytes.min(metadata.size);
        let bytes = client.read_range(path, 0, count)?;
        print_read_sample(&bytes);
    } else if options.write_check {
        println!("  write-check: skipped (not a directory)");
    }

    Ok(())
}

fn print_metadata(path: &str, attrs: &FileAttr) {
    println!(
        "{path}: type={:?} size={} mode={:o} uid={} gid={}",
        attrs.file_type,
        attrs.size,
        attrs.mode & 0o7777,
        attrs.uid,
        attrs.gid
    );
}

fn print_usage(program: &str) {
    eprintln!(
        "Usage: {program} [--timeout-secs N] [--max-entries N] [--read-bytes N] [--check-access] [--check-file-handle] [--check-fsinfo] [--check-parent] [--write-check] [--mount-port PORT] [--nfs-port PORT] <host:/export> <absolute-export-path> [absolute-export-path ...]"
    );
    eprintln!("Example: {program} 127.0.0.1:/export / /logs /data");
    eprintln!("Use --timeout-secs 0 to disable socket timeouts.");
}

fn file_type_text(attrs: Option<&FileAttr>) -> String {
    attrs
        .map(|attrs| format!("{:?}", attrs.file_type))
        .unwrap_or_else(|| "-".to_owned())
}

fn optional_attr_u64(attrs: Option<&FileAttr>, value: impl FnOnce(&FileAttr) -> u64) -> String {
    attrs
        .map(|attrs| value(attrs).to_string())
        .unwrap_or_else(|| "-".to_owned())
}

fn optional_attr_u32(attrs: Option<&FileAttr>, value: impl FnOnce(&FileAttr) -> u32) -> String {
    attrs
        .map(|attrs| value(attrs).to_string())
        .unwrap_or_else(|| "-".to_owned())
}

fn optional_attr_mode(attrs: Option<&FileAttr>) -> String {
    attrs
        .map(|attrs| format!("{:o}", attrs.mode & 0o7777))
        .unwrap_or_else(|| "-".to_owned())
}

fn print_access(client: &mut nfs::v3::blocking::Client, path: &str) -> nfs::Result<()> {
    let result = client.access(path, V3_ACCESS_MASK)?;
    println!(
        "  access: granted=0x{:02x} ({})",
        result.access,
        access_bits_text(result.access)
    );
    Ok(())
}

fn print_file_handle(client: &mut nfs::v3::blocking::Client, path: &str) -> nfs::Result<()> {
    let handle = client.file_handle(path)?;
    println!("  file-handle: {} bytes", handle.as_bytes().len());
    Ok(())
}

fn print_fsinfo(client: &mut nfs::v3::blocking::Client, path: &str) -> nfs::Result<()> {
    let info = client.path_fsinfo(path)?;
    println!(
        "  fsinfo: read_max={} read_preferred={} write_max={} write_preferred={} dir_preferred={} max_file_size={} properties=0x{:x}",
        info.read_max,
        info.read_preferred,
        info.write_max,
        info.write_preferred,
        info.dir_preferred,
        info.max_file_size,
        info.properties
    );
    Ok(())
}

fn print_parent_metadata(client: &mut nfs::v3::blocking::Client, path: &str) -> nfs::Result<()> {
    if !has_parent_path(path) {
        println!("  parent: skipped (root has no parent path)");
        return Ok(());
    }

    let handle = client.parent_file_handle(path)?;
    let attrs = client.parent_getattr(path)?;
    println!(
        "  parent: handle={} bytes type={:?} size={} mode={:o} uid={} gid={}",
        handle.as_bytes().len(),
        attrs.file_type,
        attrs.size,
        attrs.mode & 0o7777,
        attrs.uid,
        attrs.gid
    );
    Ok(())
}

fn access_bits_text(mask: u32) -> String {
    let names = V3_ACCESS_BITS
        .iter()
        .filter_map(|(bit, name)| ((mask & *bit) != 0).then_some(*name))
        .collect::<Vec<_>>();
    if names.is_empty() {
        "-".to_owned()
    } else {
        names.join("|")
    }
}

fn run_write_check(
    client: &mut nfs::v3::blocking::Client,
    dir: &str,
    path_index: usize,
) -> nfs::Result<()> {
    let file = remote_path(
        dir,
        &format!(".nfs-rs-probe-{}-{path_index}.tmp", std::process::id()),
    );
    client.remove_if_exists(&file)?;

    let result = (|| {
        client.write_atomic(&file, WRITE_CHECK_CONTENT)?;
        let data = client.read(&file)?;
        if data != WRITE_CHECK_CONTENT {
            return Err(Error::Protocol(format!(
                "write-check readback mismatch for {file}: read {} bytes, expected {}",
                data.len(),
                WRITE_CHECK_CONTENT.len()
            )));
        }
        Ok(())
    })();

    let cleanup = client.remove_if_exists(&file);
    match (result, cleanup) {
        (Ok(()), Ok(_)) => {
            println!("  write-check: wrote/read/removed {file}");
            Ok(())
        }
        (Ok(()), Err(err)) => Err(err),
        (Err(err), Ok(_)) => Err(err),
        (Err(err), Err(cleanup_err)) => Err(Error::Cleanup {
            context: "remove probe write-check file",
            primary: Box::new(err),
            cleanup: Box::new(cleanup_err),
        }),
    }
}

fn print_read_sample(bytes: &[u8]) {
    let preview_len = bytes.len().min(MAX_READ_PREVIEW_BYTES);
    let preview = &bytes[..preview_len];
    println!(
        "  read: {} bytes, hex_prefix={}, text_prefix=\"{}\"",
        bytes.len(),
        hex_preview(preview),
        text_preview(preview)
    );
}

fn next_option_value(
    args: &mut impl Iterator<Item = String>,
    option: &'static str,
) -> nfs::Result<String> {
    args.next()
        .ok_or_else(|| Error::Protocol(format!("{option} requires a value")))
}

fn parse_timeout(value: &str) -> nfs::Result<Option<Duration>> {
    let seconds = value
        .parse::<u64>()
        .map_err(|_| Error::Protocol("--timeout-secs must be a non-negative integer".to_owned()))?;
    Ok((seconds != 0).then_some(Duration::from_secs(seconds)))
}

fn parse_max_entries(value: &str) -> nfs::Result<usize> {
    let max_entries = value
        .parse::<usize>()
        .map_err(|_| Error::Protocol("--max-entries must be a positive integer".to_owned()))?;
    if max_entries == 0 {
        return Err(Error::Protocol(
            "--max-entries must be a positive integer".to_owned(),
        ));
    }
    Ok(max_entries)
}

fn parse_read_bytes(value: &str) -> nfs::Result<u64> {
    value
        .parse::<u64>()
        .map_err(|_| Error::Protocol("--read-bytes must be a non-negative integer".to_owned()))
}

fn parse_port(option: &'static str, value: &str) -> nfs::Result<u16> {
    let port = value
        .parse::<u16>()
        .map_err(|_| Error::Protocol(format!("{option} must be a TCP port in 1..=65535")))?;
    if port == 0 {
        return Err(Error::Protocol(format!(
            "{option} must be a TCP port in 1..=65535"
        )));
    }
    Ok(port)
}

fn timeout_text(timeout: Option<Duration>) -> String {
    timeout
        .map(|timeout| format!("{}s", timeout.as_secs()))
        .unwrap_or_else(|| "disabled".to_owned())
}

fn hex_preview(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".to_owned();
    }

    let mut out = String::new();
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn text_preview(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .flat_map(char::escape_default)
        .collect()
}

fn has_parent_path(path: &str) -> bool {
    path.split('/').any(|component| !component.is_empty())
}

fn remote_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{}/{name}", parent.trim_end_matches('/'))
    }
}
