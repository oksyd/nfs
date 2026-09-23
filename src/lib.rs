//! Userspace NFS client library.
//!
//! This crate talks to NFS servers directly from a Rust process. It is meant
//! for applications that want NFS as an object/file storage backend without
//! mounting the export into the local filesystem.
//!
//! The default feature set enables blocking clients:
//!
//! ```no_run
//! # #[cfg(feature = "blocking")]
//! # {
//! let mut client = nfs::v3::blocking::Client::connect("127.0.0.1:/export")?;
//! client.write("/hello.txt", b"hello")?;
//! let bytes = client.read("/hello.txt")?;
//! assert_eq!(bytes, b"hello");
//! # }
//! # Ok::<(), nfs::Error>(())
//! ```
//!
//! ```no_run
//! # #[cfg(feature = "blocking")]
//! # {
//! let mut client = nfs::v4::blocking::Client::connect("127.0.0.1")?;
//! client.write("/export/hello.txt", b"hello")?;
//! let bytes = client.read("/export/hello.txt")?;
//! assert_eq!(bytes, b"hello");
//! client.shutdown()?;
//! # }
//! # Ok::<(), nfs::Error>(())
//! ```
//!
//! # Feature flags
//!
//! - `blocking`: Enables synchronous clients. This is enabled by default.
//! - `tokio`: Enables asynchronous clients backed by Tokio.
//! - `protocol`: Exposes low-level XDR and protocol wire types for tests,
//!   custom integrations, and protocol tooling.
//!
//! # API layers
//!
//! Most applications should use [`v3::blocking::Client`],
//! [`v4::blocking::Client`], or the corresponding Tokio clients. The raw
//! protocol modules are intentionally kept behind the `protocol` feature so
//! high-level users do not depend on unstable wire-level details.

mod error;
mod retry;
pub(crate) mod rpc;
#[cfg(feature = "tokio")]
mod tokio_rpc;
pub mod v3;
pub mod v4;
#[cfg(not(feature = "protocol"))]
pub(crate) mod xdr;
#[cfg(feature = "protocol")]
pub mod xdr;

pub use error::{Error, Result};
pub use retry::RetryPolicy;
pub use rpc::{AUTH_SYS_MACHINE_NAME_MAX, AUTH_SYS_MAX_GROUPS, AuthSys};
