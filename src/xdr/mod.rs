//! XDR encoding and decoding primitives used by ONC RPC and NFSv3.
//!
//! This module intentionally stays small and protocol-oriented. It covers the
//! XDR building blocks NFSv3 needs, while higher-level modules define the
//! protocol structs and discriminated unions.

#![cfg_attr(not(feature = "protocol"), allow(dead_code))]

mod decode;
mod encode;
mod error;

#[cfg(feature = "protocol")]
pub use decode::from_bytes;
pub use decode::{Decode, Decoder};
pub use encode::{Encode, Encoder, to_bytes};
pub use error::{Error, Result};

pub(crate) fn padding_len(len: usize) -> usize {
    (4 - (len % 4)) % 4
}

pub(crate) fn checked_u32_len(len: usize) -> Result<u32> {
    u32::try_from(len).map_err(|_| Error::LengthOutOfRange { len })
}
