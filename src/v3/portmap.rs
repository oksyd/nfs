#![cfg_attr(not(feature = "protocol"), allow(dead_code))]

use std::net::ToSocketAddrs;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::rpc::{Auth, RpcClient};
use crate::xdr::{Decode, Decoder, Encode, Encoder};

pub const PMAP_PROGRAM: u32 = 100000;
pub const PMAP_VERSION: u32 = 2;
pub const PMAP_PORT: u16 = 111;
pub const IPPROTO_TCP: u32 = 6;
pub const IPPROTO_UDP: u32 = 17;

const PMAPPROC_GETPORT: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    pub program: u32,
    pub version: u32,
    pub protocol: u32,
    pub port: u32,
}

impl Mapping {
    pub fn tcp(program: u32, version: u32) -> Self {
        Self {
            program,
            version,
            protocol: IPPROTO_TCP,
            port: 0,
        }
    }
}

impl Encode for Mapping {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u32(self.program);
        encoder.write_u32(self.version);
        encoder.write_u32(self.protocol);
        encoder.write_u32(self.port);
        Ok(())
    }
}

#[derive(Debug)]
pub struct PortmapperClient {
    rpc: RpcClient,
}

impl PortmapperClient {
    pub fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self> {
        Self::connect_with_timeout(addr, None)
    }

    pub fn connect_with_timeout<A: ToSocketAddrs>(
        addr: A,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        Ok(Self {
            rpc: RpcClient::connect_with_timeout(addr, Auth::none(), timeout)?,
        })
    }

    pub fn set_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.rpc.set_timeout(timeout)
    }

    pub fn get_port(&mut self, mapping: Mapping) -> Result<u16> {
        let payload = self
            .rpc
            .call(PMAP_PROGRAM, PMAP_VERSION, PMAPPROC_GETPORT, &mapping)?;
        let mut decoder = Decoder::new(&payload);
        let port = u32::decode(&mut decoder)?;
        decoder.finish()?;
        u16::try_from(port).map_err(|_| {
            Error::Protocol(format!(
                "portmapper returned out-of-range port {port} for program {} version {}",
                mapping.program, mapping.version
            ))
        })
    }
}

pub fn get_tcp_port(host: &str, program: u32, version: u32) -> Result<u16> {
    get_tcp_port_with_timeout(host, program, version, None)
}

pub fn get_tcp_port_with_timeout(
    host: &str,
    program: u32,
    version: u32,
    timeout: Option<Duration>,
) -> Result<u16> {
    let mut client = PortmapperClient::connect_with_timeout((host, PMAP_PORT), timeout)?;
    let port = client.get_port(Mapping::tcp(program, version))?;
    if port == 0 {
        return Err(Error::PortUnavailable { program, version });
    }
    Ok(port)
}
