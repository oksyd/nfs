//! List exports advertised by an NFSv3 server's MOUNT service with Tokio.
//!
//! Usage:
//!   cargo run --example v3_tokio_exports --features tokio -- --show-mounts 127.0.0.1

use std::time::Duration;

use nfs::Error;
use nfs::v3::tokio::{
    list_exports_with_mount_port, list_exports_with_timeout, list_mounts_with_mount_port,
    list_mounts_with_timeout,
};

const DEFAULT_TIMEOUT_SECS: u64 = 10;

#[tokio::main(flavor = "current_thread")]
async fn main() -> nfs::Result<()> {
    let Some(config) = Config::from_env()? else {
        return Ok(());
    };

    let exports = match config.mount_port {
        Some(port) => list_exports_with_mount_port(&config.host, port, config.timeout).await?,
        None => list_exports_with_timeout(&config.host, config.timeout).await?,
    };

    println!("exports from {}: {}", config.host, exports.len());
    for export in exports {
        println!(
            "  {} groups={}",
            export.directory,
            groups_text(&export.groups)
        );
    }

    if config.show_mounts {
        let mounts = match config.mount_port {
            Some(port) => list_mounts_with_mount_port(&config.host, port, config.timeout).await?,
            None => list_mounts_with_timeout(&config.host, config.timeout).await?,
        };
        println!();
        println!("mount records from {}: {}", config.host, mounts.len());
        for mount in mounts {
            println!("  {} mounted {}", mount.host, mount.directory);
        }
    }

    Ok(())
}

struct Config {
    host: String,
    timeout: Option<Duration>,
    mount_port: Option<u16>,
    show_mounts: bool,
}

impl Config {
    fn from_env() -> nfs::Result<Option<Self>> {
        let mut args = std::env::args();
        let program = args.next().unwrap_or_else(|| "v3_tokio_exports".to_owned());
        let mut host = None;
        let mut timeout = Some(Duration::from_secs(DEFAULT_TIMEOUT_SECS));
        let mut mount_port = None;
        let mut show_mounts = false;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-h" | "--help" => {
                    print_usage(&program);
                    return Ok(None);
                }
                "--timeout-secs" => {
                    timeout = parse_timeout(&next_option_value(&mut args, "--timeout-secs")?)?;
                }
                "--mount-port" => {
                    mount_port = Some(parse_port(
                        "--mount-port",
                        &next_option_value(&mut args, "--mount-port")?,
                    )?);
                }
                "--show-mounts" => {
                    show_mounts = true;
                }
                "--" => {
                    let remaining = args.collect::<Vec<_>>();
                    if remaining.is_empty() {
                        break;
                    }
                    if host.is_some() || remaining.len() > 1 {
                        print_usage(&program);
                        return Err(Error::Protocol("too many positional arguments".to_owned()));
                    }
                    host = Some(remaining[0].clone());
                    break;
                }
                option if option.starts_with('-') => {
                    print_usage(&program);
                    return Err(Error::Protocol(format!("unknown option {option}")));
                }
                _ => {
                    if host.replace(arg).is_some() {
                        print_usage(&program);
                        return Err(Error::Protocol("too many positional arguments".to_owned()));
                    }
                }
            }
        }

        let Some(host) = host else {
            print_usage(&program);
            return Err(Error::Protocol("missing host argument".to_owned()));
        };
        if host.trim().is_empty() {
            return Err(Error::InvalidTarget(host));
        }

        Ok(Some(Self {
            host,
            timeout,
            mount_port,
            show_mounts,
        }))
    }
}

fn print_usage(program: &str) {
    eprintln!("Usage: {program} [--timeout-secs N] [--mount-port PORT] [--show-mounts] <host>");
    eprintln!("Example: {program} --show-mounts 127.0.0.1");
    eprintln!("Use --timeout-secs 0 to disable socket timeouts.");
}

fn groups_text(groups: &[String]) -> String {
    if groups.is_empty() {
        "-".to_owned()
    } else {
        groups.join(",")
    }
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
        .map_err(|_| Error::Protocol(format!("invalid timeout value {value:?}")))?;
    Ok((seconds > 0).then(|| Duration::from_secs(seconds)))
}

fn parse_port(option: &'static str, value: &str) -> nfs::Result<u16> {
    let port = value
        .parse::<u16>()
        .map_err(|_| Error::Protocol(format!("invalid {option} value {value:?}")))?;
    if port == 0 {
        return Err(Error::Protocol(format!("{option} must be non-zero")));
    }
    Ok(port)
}
