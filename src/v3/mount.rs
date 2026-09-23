#![cfg_attr(not(feature = "protocol"), allow(dead_code))]

use std::net::ToSocketAddrs;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::rpc::{Auth, AuthSys, RpcClient};
use crate::v3::proto::FileHandle;
use crate::xdr::{Decode, Decoder, Encode, Encoder};

pub const MOUNT_PROGRAM: u32 = 100005;
pub const MOUNT_VERSION: u32 = 3;
pub const MNTPATHLEN: usize = 1024;
pub const MNTNAMLEN: usize = 255;

const MOUNTPROC3_MNT: u32 = 1;
const MOUNTPROC3_DUMP: u32 = 2;
const MOUNTPROC3_UMNT: u32 = 3;
const MOUNTPROC3_UMNTALL: u32 = 4;
const MOUNTPROC3_EXPORT: u32 = 5;

const MOUNT_MAX_LIST_ENTRIES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MountStatus {
    Ok = 0,
    Perm = 1,
    NoEnt = 2,
    Io = 5,
    Access = 13,
    NotDir = 20,
    Invalid = 22,
    NameTooLong = 63,
    NotSupported = 10004,
    ServerFault = 10006,
    Unknown(u32),
}

impl MountStatus {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::Ok,
            1 => Self::Perm,
            2 => Self::NoEnt,
            5 => Self::Io,
            13 => Self::Access,
            20 => Self::NotDir,
            22 => Self::Invalid,
            63 => Self::NameTooLong,
            10004 => Self::NotSupported,
            10006 => Self::ServerFault,
            value => Self::Unknown(value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountInfo {
    pub file_handle: FileHandle,
    pub auth_flavors: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub host: String,
    pub directory: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub directory: String,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirPath<'a>(&'a str);

impl Encode for DirPath<'_> {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_string(self.0, MNTPATHLEN)
    }
}

#[derive(Debug)]
pub struct MountClient {
    rpc: RpcClient,
}

impl MountClient {
    pub fn connect<A: ToSocketAddrs>(addr: A, auth: AuthSys) -> Result<Self> {
        Self::connect_with_timeout(addr, auth, None)
    }

    pub fn connect_with_timeout<A: ToSocketAddrs>(
        addr: A,
        auth: AuthSys,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        Ok(Self {
            rpc: RpcClient::connect_with_timeout(addr, Auth::sys(auth), timeout)?,
        })
    }

    pub fn set_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.rpc.set_timeout(timeout)
    }

    pub fn mount(&mut self, export_path: &str) -> Result<MountInfo> {
        let payload = self.rpc.call(
            MOUNT_PROGRAM,
            MOUNT_VERSION,
            MOUNTPROC3_MNT,
            &DirPath(export_path),
        )?;
        let mut decoder = Decoder::new(&payload);
        let status = MountStatus::from_u32(u32::decode(&mut decoder)?);
        if status != MountStatus::Ok {
            decoder.finish()?;
            return Err(Error::Mount { status });
        }

        let file_handle = FileHandle::decode(&mut decoder)?;
        let auth_flavors = decoder.read_array::<u32>(128)?;
        decoder.finish()?;
        Ok(MountInfo {
            file_handle,
            auth_flavors,
        })
    }

    pub fn dump(&mut self) -> Result<Vec<MountEntry>> {
        let payload = self
            .rpc
            .call(MOUNT_PROGRAM, MOUNT_VERSION, MOUNTPROC3_DUMP, &())?;
        let mut decoder = Decoder::new(&payload);
        let mounts = decode_mount_list(&mut decoder)?;
        decoder.finish()?;
        Ok(mounts)
    }

    pub fn unmount(&mut self, export_path: &str) -> Result<()> {
        let payload = self.rpc.call(
            MOUNT_PROGRAM,
            MOUNT_VERSION,
            MOUNTPROC3_UMNT,
            &DirPath(export_path),
        )?;
        let decoder = Decoder::new(&payload);
        decoder.finish()?;
        Ok(())
    }

    pub fn unmount_all(&mut self) -> Result<()> {
        let payload = self
            .rpc
            .call(MOUNT_PROGRAM, MOUNT_VERSION, MOUNTPROC3_UMNTALL, &())?;
        let decoder = Decoder::new(&payload);
        decoder.finish()?;
        Ok(())
    }

    pub fn exports(&mut self) -> Result<Vec<Export>> {
        let payload = self
            .rpc
            .call(MOUNT_PROGRAM, MOUNT_VERSION, MOUNTPROC3_EXPORT, &())?;
        let mut decoder = Decoder::new(&payload);
        let exports = decode_export_list(&mut decoder)?;
        decoder.finish()?;
        Ok(exports)
    }
}

pub(crate) fn decode_mount_list(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Vec<MountEntry>> {
    decode_linked_list(decoder, |decoder| {
        Ok(MountEntry {
            host: decoder.read_string(MNTNAMLEN)?,
            directory: decoder.read_string(MNTPATHLEN)?,
        })
    })
}

pub(crate) fn decode_export_list(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Vec<Export>> {
    decode_linked_list(decoder, |decoder| {
        Ok(Export {
            directory: decoder.read_string(MNTPATHLEN)?,
            groups: decode_group_list(decoder)?,
        })
    })
}

fn decode_group_list(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Vec<String>> {
    decode_linked_list(decoder, |decoder| decoder.read_string(MNTNAMLEN))
}

fn decode_linked_list<T>(
    decoder: &mut Decoder<'_>,
    mut decode_entry: impl FnMut(&mut Decoder<'_>) -> crate::xdr::Result<T>,
) -> crate::xdr::Result<Vec<T>> {
    let mut entries = Vec::new();
    while decoder.read_bool()? {
        if entries.len() == MOUNT_MAX_LIST_ENTRIES {
            return Err(crate::xdr::Error::LengthLimitExceeded {
                len: MOUNT_MAX_LIST_ENTRIES + 1,
                max: MOUNT_MAX_LIST_ENTRIES,
            });
        }
        entries.push(decode_entry(decoder)?);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdr::Encoder;

    #[test]
    fn decodes_mount_dump_list() {
        let mut encoder = Encoder::new();
        encoder.write_bool(true);
        encoder.write_string("client-a", MNTNAMLEN).unwrap();
        encoder.write_string("/export/a", MNTPATHLEN).unwrap();
        encoder.write_bool(true);
        encoder.write_string("client-b", MNTNAMLEN).unwrap();
        encoder.write_string("/export/b", MNTPATHLEN).unwrap();
        encoder.write_bool(false);

        let mut decoder = Decoder::new(encoder.as_slice());
        let mounts = decode_mount_list(&mut decoder).unwrap();
        decoder.finish().unwrap();

        assert_eq!(
            mounts,
            vec![
                MountEntry {
                    host: "client-a".to_owned(),
                    directory: "/export/a".to_owned()
                },
                MountEntry {
                    host: "client-b".to_owned(),
                    directory: "/export/b".to_owned()
                }
            ]
        );
    }

    #[test]
    fn decodes_export_list_with_groups() {
        let mut encoder = Encoder::new();
        encoder.write_bool(true);
        encoder.write_string("/export", MNTPATHLEN).unwrap();
        encoder.write_bool(true);
        encoder.write_string("clients", MNTNAMLEN).unwrap();
        encoder.write_bool(true);
        encoder.write_string("admins", MNTNAMLEN).unwrap();
        encoder.write_bool(false);
        encoder.write_bool(true);
        encoder.write_string("/public", MNTPATHLEN).unwrap();
        encoder.write_bool(false);
        encoder.write_bool(false);

        let mut decoder = Decoder::new(encoder.as_slice());
        let exports = decode_export_list(&mut decoder).unwrap();
        decoder.finish().unwrap();

        assert_eq!(
            exports,
            vec![
                Export {
                    directory: "/export".to_owned(),
                    groups: vec!["clients".to_owned(), "admins".to_owned()]
                },
                Export {
                    directory: "/public".to_owned(),
                    groups: Vec::new()
                }
            ]
        );
    }
}
