use std::time::Duration;

use ::tokio::io::{AsyncReadExt, AsyncWriteExt};
use ::tokio::net::{TcpStream, ToSocketAddrs};

use crate::error::{Error, Result};
use crate::rpc::{
    Auth, DEFAULT_MAX_RECORD_SIZE, FRAGMENT_LEN_MASK, LAST_FRAGMENT, decode_reply, default_stamp,
    encode_call, validate_max_record_size,
};
use crate::xdr::Encode;

#[derive(Debug)]
pub(crate) struct RpcClient {
    stream: TcpStream,
    xid: u32,
    auth: Auth,
    max_record_size: usize,
    timeout: Option<Duration>,
}

impl RpcClient {
    pub(crate) async fn connect_with_timeout<A: ToSocketAddrs>(
        addr: A,
        auth: Auth,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        let stream = connect_tcp_stream(addr, timeout).await?;
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            xid: default_stamp(),
            auth,
            max_record_size: DEFAULT_MAX_RECORD_SIZE,
            timeout,
        })
    }

    pub(crate) fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }

    pub(crate) fn set_max_record_size(&mut self, max_record_size: usize) -> Result<()> {
        validate_max_record_size(max_record_size)?;
        self.max_record_size = max_record_size;
        Ok(())
    }

    pub(crate) async fn call<T: Encode + ?Sized>(
        &mut self,
        program: u32,
        version: u32,
        procedure: u32,
        args: &T,
    ) -> Result<Vec<u8>> {
        let xid = self.next_xid();
        let request = encode_call(xid, program, version, procedure, &self.auth, args)?;
        self.write_record(&request).await?;
        let reply = self.read_record().await?;
        decode_reply(xid, &reply)
    }

    fn next_xid(&mut self) -> u32 {
        self.xid = self.xid.wrapping_add(1);
        if self.xid == 0 {
            self.xid = 1;
        }
        self.xid
    }

    async fn write_record(&mut self, payload: &[u8]) -> Result<()> {
        if payload.len() > FRAGMENT_LEN_MASK as usize {
            return Err(Error::RpcRecordTooLarge {
                len: payload.len(),
                max: FRAGMENT_LEN_MASK as usize,
            });
        }

        let len = u32::try_from(payload.len()).map_err(|_| Error::RpcRecordTooLarge {
            len: payload.len(),
            max: FRAGMENT_LEN_MASK as usize,
        })?;
        let header = LAST_FRAGMENT | len;
        write_all(&mut self.stream, &header.to_be_bytes(), self.timeout).await?;
        write_all(&mut self.stream, payload, self.timeout).await?;
        flush(&mut self.stream, self.timeout).await
    }

    async fn read_record(&mut self) -> Result<Vec<u8>> {
        let mut record = Vec::new();
        loop {
            let mut header_bytes = [0; 4];
            read_exact(&mut self.stream, &mut header_bytes, self.timeout).await?;
            let header = u32::from_be_bytes(header_bytes);
            let is_last = (header & LAST_FRAGMENT) != 0;
            let fragment_len = (header & FRAGMENT_LEN_MASK) as usize;
            if fragment_len == 0 && !is_last {
                return Err(Error::Protocol(
                    "RPC record contained zero-length non-final fragment".to_owned(),
                ));
            }

            let next_len =
                record
                    .len()
                    .checked_add(fragment_len)
                    .ok_or(Error::RpcRecordTooLarge {
                        len: usize::MAX,
                        max: self.max_record_size,
                    })?;
            if next_len > self.max_record_size {
                return Err(Error::RpcRecordTooLarge {
                    len: next_len,
                    max: self.max_record_size,
                });
            }

            let start = record.len();
            record.resize(next_len, 0);
            read_exact(&mut self.stream, &mut record[start..], self.timeout).await?;

            if is_last {
                return Ok(record);
            }
        }
    }
}

async fn connect_tcp_stream<A: ToSocketAddrs>(
    addr: A,
    timeout: Option<Duration>,
) -> Result<TcpStream> {
    if let Some(timeout) = timeout {
        ::tokio::time::timeout(timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| timeout_error())?
            .map_err(Error::from)
    } else {
        TcpStream::connect(addr).await.map_err(Error::from)
    }
}

async fn write_all(stream: &mut TcpStream, buf: &[u8], timeout: Option<Duration>) -> Result<()> {
    if let Some(timeout) = timeout {
        ::tokio::time::timeout(timeout, stream.write_all(buf))
            .await
            .map_err(|_| timeout_error())??;
    } else {
        stream.write_all(buf).await?;
    }
    Ok(())
}

async fn flush(stream: &mut TcpStream, timeout: Option<Duration>) -> Result<()> {
    if let Some(timeout) = timeout {
        ::tokio::time::timeout(timeout, stream.flush())
            .await
            .map_err(|_| timeout_error())??;
    } else {
        stream.flush().await?;
    }
    Ok(())
}

async fn read_exact(
    stream: &mut TcpStream,
    buf: &mut [u8],
    timeout: Option<Duration>,
) -> Result<()> {
    if let Some(timeout) = timeout {
        ::tokio::time::timeout(timeout, stream.read_exact(buf))
            .await
            .map_err(|_| timeout_error())??;
    } else {
        stream.read_exact(buf).await?;
    }
    Ok(())
}

fn timeout_error() -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "NFS async operation timed out",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::tokio::io::AsyncWriteExt;
    use ::tokio::net::TcpListener;

    #[tokio::test(flavor = "current_thread")]
    async fn rejects_zero_length_nonfinal_record_fragments() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(&0_u32.to_be_bytes()).await.unwrap();
        });

        let mut client =
            RpcClient::connect_with_timeout(addr, Auth::none(), Some(Duration::from_secs(1)))
                .await
                .unwrap();
        let err = client.read_record().await.unwrap_err();
        assert!(matches!(
            err,
            Error::Protocol(message) if message.contains("zero-length non-final")
        ));
        accept.await.unwrap();
    }
}
