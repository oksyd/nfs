use super::{Result, checked_u32_len, padding_len};

/// Trait for types that can be encoded as XDR.
pub trait Encode {
    /// Encodes `self` into `encoder`.
    fn encode(&self, encoder: &mut Encoder) -> Result<()>;
}

/// Streaming XDR encoder.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    /// Creates an empty encoder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty encoder with preallocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    /// Consumes the encoder and returns encoded bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Returns encoded bytes without consuming the encoder.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the current encoded length.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns true when no bytes have been encoded.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Writes an unsigned 32-bit integer in network byte order.
    pub fn write_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Writes a signed 32-bit integer in network byte order.
    pub fn write_i32(&mut self, value: i32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Writes an unsigned 64-bit integer in network byte order.
    pub fn write_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Writes a signed 64-bit integer in network byte order.
    pub fn write_i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Writes an XDR boolean.
    pub fn write_bool(&mut self, value: bool) {
        self.write_u32(u32::from(value));
    }

    /// Writes an enum discriminant.
    pub fn write_discriminant(&mut self, value: i32) {
        self.write_i32(value);
    }

    /// Writes fixed-length opaque data and XDR zero padding.
    pub fn write_fixed_opaque(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
        self.write_padding(value.len());
    }

    /// Writes variable-length opaque data with a maximum length.
    pub fn write_opaque(&mut self, value: &[u8], max: usize) -> Result<()> {
        self.write_len(value.len(), max)?;
        self.write_fixed_opaque(value);
        Ok(())
    }

    /// Writes a UTF-8 XDR string with a maximum byte length.
    pub fn write_string(&mut self, value: &str, max: usize) -> Result<()> {
        self.write_opaque(value.as_bytes(), max)
    }

    /// Writes a variable-length array with a maximum element count.
    pub fn write_array<T: Encode>(&mut self, values: &[T], max: usize) -> Result<()> {
        self.write_len(values.len(), max)?;
        for value in values {
            value.encode(self)?;
        }
        Ok(())
    }

    /// Writes an XDR optional value encoded as a boolean followed by a value.
    pub fn write_optional<T: Encode>(&mut self, value: Option<&T>) -> Result<()> {
        self.write_bool(value.is_some());
        if let Some(value) = value {
            value.encode(self)?;
        }
        Ok(())
    }

    fn write_len(&mut self, len: usize, max: usize) -> Result<()> {
        if len > max {
            return Err(super::Error::LengthLimitExceeded { len, max });
        }
        self.write_u32(checked_u32_len(len)?);
        Ok(())
    }

    fn write_padding(&mut self, len: usize) {
        const ZERO_PADDING: [u8; 3] = [0; 3];
        self.bytes
            .extend_from_slice(&ZERO_PADDING[..padding_len(len)]);
    }
}

/// Encodes a value into a fresh byte vector.
pub fn to_bytes<T: Encode + ?Sized>(value: &T) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new();
    value.encode(&mut encoder)?;
    Ok(encoder.into_bytes())
}

impl Encode for u32 {
    fn encode(&self, encoder: &mut Encoder) -> Result<()> {
        encoder.write_u32(*self);
        Ok(())
    }
}

impl Encode for i32 {
    fn encode(&self, encoder: &mut Encoder) -> Result<()> {
        encoder.write_i32(*self);
        Ok(())
    }
}

impl Encode for u64 {
    fn encode(&self, encoder: &mut Encoder) -> Result<()> {
        encoder.write_u64(*self);
        Ok(())
    }
}

impl Encode for i64 {
    fn encode(&self, encoder: &mut Encoder) -> Result<()> {
        encoder.write_i64(*self);
        Ok(())
    }
}

impl Encode for bool {
    fn encode(&self, encoder: &mut Encoder) -> Result<()> {
        encoder.write_bool(*self);
        Ok(())
    }
}

impl Encode for () {
    fn encode(&self, _encoder: &mut Encoder) -> Result<()> {
        Ok(())
    }
}
