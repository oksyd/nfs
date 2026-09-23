//! Probe one or more NFSv4 paths and list directory entries.
//!
//! Usage:
//!   cargo run --example v4_probe -- --check-access --check-file-handle --check-fsinfo --check-public-fh --check-parent --check-named-attrs --write-check --read-bytes 64 127.0.0.1 / /export /export/logs

use std::time::Duration;

use nfs::v4::blocking::Client;
use nfs::v4::{
    ACCESS4_DELETE, ACCESS4_EXECUTE, ACCESS4_EXTEND, ACCESS4_LOOKUP, ACCESS4_MODIFY, ACCESS4_READ,
    BasicAttributes, NFS4_MINOR_VERSION_LATEST, NFS4_MINOR_VERSION_SESSION_MIN, RpcGssService,
    SecInfo,
};
use nfs::{Error, RetryPolicy};

const DEFAULT_MAX_LIST_ENTRIES: usize = 64;
const DEFAULT_READ_BYTES: u64 = 0;
const DEFAULT_TIMEOUT_SECS: u64 = 10;
const MAX_READ_PREVIEW_BYTES: usize = 64;
const WRITE_CHECK_CONTENT: &[u8] = b"nfs-rs probe write check\n";
const V4_ACCESS_MASK: u32 = ACCESS4_READ
    | ACCESS4_LOOKUP
    | ACCESS4_MODIFY
    | ACCESS4_EXTEND
    | ACCESS4_DELETE
    | ACCESS4_EXECUTE;
const V4_ACCESS_BITS: &[(u32, &str)] = &[
    (ACCESS4_READ, "READ"),
    (ACCESS4_LOOKUP, "LOOKUP"),
    (ACCESS4_MODIFY, "MODIFY"),
    (ACCESS4_EXTEND, "EXTEND"),
    (ACCESS4_DELETE, "DELETE"),
    (ACCESS4_EXECUTE, "EXECUTE"),
];

fn main() -> nfs::Result<()> {
    let Some(config) = Config::from_env()? else {
        return Ok(());
    };

    let mut builder = Client::builder(config.host.clone())
        .timeout(config.timeout)
        .max_dir_entries(config.max_entries)
        .retry_policy(RetryPolicy::default())
        .max_minor_version(config.max_minor_version);
    if let Some(port) = config.port {
        builder = builder.port(port);
    }
    let mut client = builder.connect()?;

    println!("connected to NFSv4 host {}", config.host);
    println!(
        "probe options: max_entries={} read_bytes={} check_access={} check_secinfo={} check_file_handle={} check_fsinfo={} check_public_fh={} check_parent={} check_named_attrs={} write_check={} timeout={} max_minor_version={}",
        config.max_entries,
        config.read_bytes,
        config.check_access,
        config.check_secinfo,
        config.check_file_handle,
        config.check_fsinfo,
        config.check_public_fh,
        config.check_parent,
        config.check_named_attrs,
        config.write_check,
        timeout_text(config.timeout),
        config.max_minor_version
    );

    let options = ProbeOptions {
        max_entries: config.max_entries,
        read_bytes: config.read_bytes,
        check_access: config.check_access,
        check_secinfo: config.check_secinfo,
        check_file_handle: config.check_file_handle,
        check_fsinfo: config.check_fsinfo,
        check_public_fh: config.check_public_fh,
        check_parent: config.check_parent,
        check_named_attrs: config.check_named_attrs,
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

    client.shutdown()?;

    if failures == 0 {
        Ok(())
    } else {
        Err(Error::Protocol(format!("{failures} path(s) failed")))
    }
}

struct Config {
    host: String,
    paths: Vec<String>,
    timeout: Option<Duration>,
    max_entries: usize,
    read_bytes: u64,
    check_access: bool,
    check_secinfo: bool,
    check_file_handle: bool,
    check_fsinfo: bool,
    check_public_fh: bool,
    check_parent: bool,
    check_named_attrs: bool,
    write_check: bool,
    port: Option<u16>,
    max_minor_version: u32,
}

#[derive(Debug, Clone, Copy)]
struct ProbeOptions {
    max_entries: usize,
    read_bytes: u64,
    check_access: bool,
    check_secinfo: bool,
    check_file_handle: bool,
    check_fsinfo: bool,
    check_public_fh: bool,
    check_parent: bool,
    check_named_attrs: bool,
    write_check: bool,
}

impl Config {
    fn from_env() -> nfs::Result<Option<Self>> {
        let mut args = std::env::args();
        let program = args.next().unwrap_or_else(|| "v4_probe".to_owned());
        let mut positionals = Vec::new();
        let mut timeout = Some(Duration::from_secs(DEFAULT_TIMEOUT_SECS));
        let mut max_entries = DEFAULT_MAX_LIST_ENTRIES;
        let mut read_bytes = DEFAULT_READ_BYTES;
        let mut check_access = false;
        let mut check_secinfo = false;
        let mut check_file_handle = false;
        let mut check_fsinfo = false;
        let mut check_public_fh = false;
        let mut check_parent = false;
        let mut check_named_attrs = false;
        let mut write_check = false;
        let mut port = None;
        let mut max_minor_version = NFS4_MINOR_VERSION_LATEST;

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
                "--check-secinfo" => {
                    check_secinfo = true;
                }
                "--check-file-handle" => {
                    check_file_handle = true;
                }
                "--check-fsinfo" => {
                    check_fsinfo = true;
                }
                "--check-public-fh" => {
                    check_public_fh = true;
                }
                "--check-parent" => {
                    check_parent = true;
                }
                "--check-named-attrs" => {
                    check_named_attrs = true;
                }
                "--write-check" => {
                    write_check = true;
                }
                "--port" => {
                    port = Some(parse_port(
                        "--port",
                        &next_option_value(&mut args, "--port")?,
                    )?);
                }
                "--max-minor-version" => {
                    max_minor_version =
                        parse_minor_version(&next_option_value(&mut args, "--max-minor-version")?)?;
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
            return Err(Error::Protocol("missing host or path argument".to_owned()));
        }

        let host = positionals[0].clone();
        let paths = positionals[1..].to_vec();
        for path in &paths {
            if path.is_empty() || !path.starts_with('/') {
                return Err(Error::InvalidPath(path.clone()));
            }
        }

        Ok(Some(Self {
            host,
            paths,
            timeout,
            max_entries,
            read_bytes,
            check_access,
            check_secinfo,
            check_file_handle,
            check_fsinfo,
            check_public_fh,
            check_parent,
            check_named_attrs,
            write_check,
            port,
            max_minor_version,
        }))
    }
}

fn probe_path(
    client: &mut Client,
    path: &str,
    options: ProbeOptions,
    path_index: usize,
) -> nfs::Result<()> {
    let metadata = client.metadata(path)?;
    print_metadata(path, &metadata);
    if options.check_access {
        print_access(client, path)?;
    }
    if options.check_secinfo {
        print_secinfo(client, path)?;
    }
    if options.check_file_handle {
        print_file_handle(client, path)?;
    }
    if options.check_fsinfo {
        print_fsinfo(client, path)?;
    }
    if options.check_public_fh {
        print_public_filehandle_metadata(client, path)?;
    }
    if options.check_parent {
        print_parent_metadata(client, path)?;
    }
    if options.check_named_attrs {
        print_named_attrs(client, path, options.max_entries)?;
    }

    if metadata.is_dir()? {
        let entries = client.read_dir_limited(path, options.max_entries)?;
        println!("  entries: {}", entries.len());

        for entry in entries {
            let attrs = entry.basic_attributes()?;
            println!(
                "  - {} type={} size={} mode={} owner={}",
                entry.name,
                file_type_text(&attrs),
                optional_u64(attrs.size),
                mode_text(attrs.mode),
                optional_str(attrs.owner.as_deref())
            );
        }
        if options.write_check {
            run_write_check(client, path, path_index)?;
        }
    } else if metadata.is_file()? && options.read_bytes > 0 {
        let count = metadata
            .size
            .map(|size| options.read_bytes.min(size))
            .unwrap_or(options.read_bytes);
        let bytes = client.read_range(path, 0, count)?;
        print_read_sample(&bytes);
    } else if options.write_check {
        println!("  write-check: skipped (not a directory)");
    }

    Ok(())
}

fn print_metadata(path: &str, attrs: &BasicAttributes) {
    println!(
        "{path}: type={} size={} mode={} owner={} group={}",
        file_type_text(attrs),
        optional_u64(attrs.size),
        mode_text(attrs.mode),
        optional_str(attrs.owner.as_deref()),
        optional_str(attrs.owner_group.as_deref())
    );
}

fn print_usage(program: &str) {
    eprintln!(
        "Usage: {program} [--timeout-secs N] [--max-entries N] [--read-bytes N] [--check-access] [--check-secinfo] [--check-file-handle] [--check-fsinfo] [--check-public-fh] [--check-parent] [--check-named-attrs] [--write-check] [--port PORT] [--max-minor-version 1|2] <host> <absolute-nfs-v4-path> [absolute-nfs-v4-path ...]"
    );
    eprintln!("Example: {program} 127.0.0.1 / /export /export/logs");
    eprintln!("Use --timeout-secs 0 to disable socket timeouts.");
}

fn file_type_text(attrs: &BasicAttributes) -> String {
    attrs
        .file_type
        .map(|file_type| format!("{file_type:?}"))
        .unwrap_or_else(|| "-".to_owned())
}

fn optional_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_owned())
}

fn optional_u32(value: Option<u32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_owned())
}

fn optional_bool(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "-",
    }
}

fn mode_text(value: Option<u32>) -> String {
    value
        .map(|mode| format!("{mode:o}"))
        .unwrap_or_else(|| "-".to_owned())
}

fn optional_str(value: Option<&str>) -> &str {
    value.unwrap_or("-")
}

fn print_access(client: &mut Client, path: &str) -> nfs::Result<()> {
    let result = client.access(path, V4_ACCESS_MASK)?;
    println!(
        "  access: supported=0x{:02x} ({}) granted=0x{:02x} ({})",
        result.supported,
        access_bits_text(result.supported),
        result.access,
        access_bits_text(result.access)
    );
    Ok(())
}

fn print_secinfo(client: &mut Client, path: &str) -> nfs::Result<()> {
    let flavors = client.secinfo_current(path)?;
    let text = if flavors.is_empty() {
        "-".to_owned()
    } else {
        flavors
            .iter()
            .map(secinfo_text)
            .collect::<Vec<_>>()
            .join(",")
    };
    println!("  secinfo: {text}");
    Ok(())
}

fn print_file_handle(client: &mut Client, path: &str) -> nfs::Result<()> {
    let handle = client.file_handle(path)?;
    println!("  file-handle: {} bytes", handle.as_bytes().len());
    Ok(())
}

fn print_fsinfo(client: &mut Client, path: &str) -> nfs::Result<()> {
    let fsinfo = client.fsinfo(path)?;
    let fsstat = client.fsstat(path)?;
    let pathconf = client.pathconf(path)?;
    println!(
        "  fsinfo: max_read={} max_write={} max_file_size={} link_support={} symlink_support={} lease_time={}",
        optional_u64(fsinfo.max_read),
        optional_u64(fsinfo.max_write),
        optional_u64(fsinfo.max_file_size),
        optional_bool(fsinfo.link_support),
        optional_bool(fsinfo.symlink_support),
        optional_u32(fsinfo.lease_time_seconds)
    );
    println!(
        "  fsstat: total_bytes={} free_bytes={} available_bytes={} total_files={} free_files={} available_files={}",
        optional_u64(fsstat.total_bytes),
        optional_u64(fsstat.free_bytes),
        optional_u64(fsstat.available_bytes),
        optional_u64(fsstat.total_files),
        optional_u64(fsstat.free_files),
        optional_u64(fsstat.available_files)
    );
    println!(
        "  pathconf: link_max={} name_max={} no_trunc={} chown_restricted={} case_insensitive={} case_preserving={}",
        optional_u32(pathconf.link_max),
        optional_u32(pathconf.name_max),
        optional_bool(pathconf.no_trunc),
        optional_bool(pathconf.chown_restricted),
        optional_bool(pathconf.case_insensitive),
        optional_bool(pathconf.case_preserving)
    );
    Ok(())
}

fn print_public_filehandle_metadata(client: &mut Client, path: &str) -> nfs::Result<()> {
    if !client.public_exists(path)? {
        return Err(Error::Protocol(format!(
            "public filehandle path {path} did not resolve"
        )));
    }
    let handle = client.public_file_handle(path)?;
    let attrs = client.public_getattr(path)?;
    let access = client.public_access(path, V4_ACCESS_MASK)?;
    println!(
        "  public-fh: handle={} bytes type={} size={} mode={} owner={} access=0x{:02x} ({})",
        handle.as_bytes().len(),
        file_type_text(&attrs),
        optional_u64(attrs.size),
        mode_text(attrs.mode),
        optional_str(attrs.owner.as_deref()),
        access.access,
        access_bits_text(access.access)
    );
    if attrs.is_dir()? {
        let page = client.public_read_dir_page_limited(path, None, 1)?;
        println!(
            "  public-fh entries-page: {} eof={}",
            page.entries.len(),
            page.is_eof()
        );
    }
    Ok(())
}

fn print_parent_metadata(client: &mut Client, path: &str) -> nfs::Result<()> {
    if !has_parent_path(path) {
        println!("  parent: skipped (root has no parent path)");
        return Ok(());
    }

    let handle = client.parent_file_handle(path)?;
    let attrs = client.parent_getattr(path)?;
    let access = client.parent_access(path, V4_ACCESS_MASK)?;
    println!(
        "  parent: handle={} bytes type={} size={} mode={} owner={} access=0x{:02x} ({})",
        handle.as_bytes().len(),
        file_type_text(&attrs),
        optional_u64(attrs.size),
        mode_text(attrs.mode),
        optional_str(attrs.owner.as_deref()),
        access.access,
        access_bits_text(access.access)
    );
    if attrs.is_dir()? {
        let page = client.parent_read_dir_page_limited(path, None, 1)?;
        println!(
            "  parent entries-page: {} eof={}",
            page.entries.len(),
            page.is_eof()
        );
    }
    Ok(())
}

fn print_named_attrs(client: &mut Client, path: &str, max_entries: usize) -> nfs::Result<()> {
    let entries = client.read_named_attrs_limited(path, max_entries)?;
    println!("  named-attrs: {}", entries.len());
    for entry in entries {
        let attrs = entry.basic_attributes()?;
        println!(
            "  @ {} type={} size={} mode={} owner={}",
            entry.name,
            file_type_text(&attrs),
            optional_u64(attrs.size),
            mode_text(attrs.mode),
            optional_str(attrs.owner.as_deref())
        );
    }
    Ok(())
}

fn secinfo_text(flavor: &SecInfo) -> String {
    match flavor {
        SecInfo::AuthNone => "AUTH_NONE".to_owned(),
        SecInfo::AuthSys => "AUTH_SYS".to_owned(),
        SecInfo::RpcSecGss { oid, qop, service } => format!(
            "RPCSEC_GSS(oid_len={},qop={},service={})",
            oid.len(),
            qop,
            rpc_gss_service_text(*service)
        ),
        SecInfo::Unknown(value) => format!("UNKNOWN({value})"),
    }
}

fn rpc_gss_service_text(service: RpcGssService) -> &'static str {
    match service {
        RpcGssService::None => "none",
        RpcGssService::Integrity => "integrity",
        RpcGssService::Privacy => "privacy",
        RpcGssService::Unknown(_) => "unknown",
    }
}

fn access_bits_text(mask: u32) -> String {
    let names = V4_ACCESS_BITS
        .iter()
        .filter_map(|(bit, name)| ((mask & *bit) != 0).then_some(*name))
        .collect::<Vec<_>>();
    if names.is_empty() {
        "-".to_owned()
    } else {
        names.join("|")
    }
}

fn run_write_check(client: &mut Client, dir: &str, path_index: usize) -> nfs::Result<()> {
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

fn parse_minor_version(value: &str) -> nfs::Result<u32> {
    let version = value.parse::<u32>().map_err(|_| {
        Error::Protocol(format!(
            "--max-minor-version must be between {NFS4_MINOR_VERSION_SESSION_MIN} and {NFS4_MINOR_VERSION_LATEST}"
        ))
    })?;
    if !(NFS4_MINOR_VERSION_SESSION_MIN..=NFS4_MINOR_VERSION_LATEST).contains(&version) {
        return Err(Error::Protocol(format!(
            "--max-minor-version must be between {NFS4_MINOR_VERSION_SESSION_MIN} and {NFS4_MINOR_VERSION_LATEST}"
        )));
    }
    Ok(version)
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
