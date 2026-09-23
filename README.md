# nfs

Userspace Rust NFS client library.

Use NFS exports without mounting them into the local filesystem.

## Status

Under active development. Not recommended for production use yet.

## Protocols

- NFSv3 over ONC RPC/TCP
- NFSv4.2 over ONC RPC/TCP
- Blocking clients by default
- Tokio clients with the `tokio` feature

## Install

```toml
[dependencies]
nfs = "0.1"
```

```toml
# Enable async clients
nfs = { version = "0.1", features = ["tokio"] }
```

```toml
# Protocol types only
nfs = { version = "0.1", default-features = false, features = ["protocol"] }
```

## Example

```rust
let mut client = nfs::v3::blocking::Client::connect("127.0.0.1:/export")?;
client.write("/hello.txt", b"hello")?;
let data = client.read("/hello.txt")?;
# Ok::<(), nfs::Error>(())
```

```rust
let mut client = nfs::v4::blocking::Client::connect("127.0.0.1")?;
client.write("/export/hello.txt", b"hello")?;
let data = client.read("/export/hello.txt")?;
client.shutdown()?;
# Ok::<(), nfs::Error>(())
```

## Notes

- `timeout(...)`, `retry_policy(...)`, and `reconnect()` are available on high-level clients.
- `AuthSys::current()` sends uid, primary gid, and up to 16 supplementary groups.
- Common errors expose helpers such as `is_not_found()`, `is_retryable()`, and `is_permission_denied()`.

## Not Implemented

- RPCSEC_GSS/Kerberos
- pNFS
- NFSv4 callbacks/delegations
- NLM file locking
- UDP transport

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
