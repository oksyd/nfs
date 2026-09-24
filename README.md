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

## Recovery and leases

NFSv4 clients rebuild failed sessions and retry safe, stateless read-only requests
once. Reconnection attempts use `RetryPolicy`. Mutating requests whose replies
were lost return an error with `is_outcome_unknown() == true`; check the server's
state before retrying them. Interrupted or cancelled RPCs invalidate the TCP
stream. NFSv4 recovers it on subsequent use; NFSv3 requires `reconnect()`.

Byte-range locks are tracked by the client. Recovery validates surviving state
or reclaims the old OPEN and LOCK before sending RECLAIM_COMPLETE, following
[RFC 8881 section 8.4.2.1](https://www.rfc-editor.org/rfc/rfc8881.html#section-8.4.2.1).
Lock tokens expose updated stateids after recovery. If the server refuses a
reclaim, `is_lost_state()` and `ByteRangeLock::is_lost()` report the loss; the
client blocks further file operations until the lost tokens are passed to
`unlock()` (which also reports the loss). Revalidate the application's protected
data before acquiring a new lock. Dropping a token does not release its lock.

Applications holding locks while idle can enable background lease renewal:

```rust
let client = nfs::v4::blocking::Client::builder("127.0.0.1")
    .automatic_lease_renewal(true)
    .connect()?;
# client.shutdown()?;
# Ok::<(), nfs::Error>(())
```

The Tokio builder supports the same option. Renewal is opt-in and uses a second
connection and session for the same client ID, at one-third of the advertised
lease time. The server must support the extra session and advertise its lease
time. A failed heartbeat triggers recovery on the next foreground operation;
an outage extending beyond the server's recovery grace period can still lose
locks. `shutdown()` stops renewal and destroys both sessions. Without background
renewal, call `renew()` at the interval returned by `lease_renewal_interval()`
while the client is idle.

## Not Implemented

- RPCSEC_GSS/Kerberos
- pNFS
- NFSv4 callbacks/delegations
- NLM file locking
- UDP transport

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
