use super::{Error, Result, padding_len};

const MAX_ARRAY_PREALLOC: usize = 1024;

/// Trait for types that can be decoded from XDR.
pub trait Decode: Sized {
    /// Decodes a value from `decoder`.
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self>;
}

/// Streaming XDR decoder over an immutable byte slice.
#[derive(Debug, Clone, Copy)]
pub struct Decoder<'de> {
    input: &'de [u8],
    position: usize,
}

impl<'de> Decoder<'de> {
    /// Creates a decoder for `input`.
    pub fn new(input: &'de [u8]) -> Self {
        Self { input, position: 0 }
    }

    /// Returns the current byte offset.
    pub fn position(&self) -> usize {
        self.position
    }

    /// Returns the number of unread bytes.
    pub fn remaining(&self) -> usize {
        self.input.len() - self.position
    }

    /// Returns true when the decoder has consumed all input.
    pub fn is_finished(&self) -> bool {
        self.remaining() == 0
    }

    /// Fails if any trailing bytes remain.
    pub fn finish(self) -> Result<()> {
        if self.is_finished() {
            Ok(())
        } else {
            Err(Error::TrailingBytes {
                remaining: self.remaining(),
            })
        }
    }

    /// Reads an unsigned 32-bit integer in network byte order.
    pub fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_byte_array::<4>()?;
        Ok(u32::from_be_bytes(bytes))
    }

    /// Reads a signed 32-bit integer in network byte order.
    pub fn read_i32(&mut self) -> Result<i32> {
        let bytes = self.read_byte_array::<4>()?;
        Ok(i32::from_be_bytes(bytes))
    }

    /// Reads an unsigned 64-bit integer in network byte order.
    pub fn read_u64(&mut self) -> Result<u64> {
        let bytes = self.read_byte_array::<8>()?;
        Ok(u64::from_be_bytes(bytes))
    }

    /// Reads a signed 64-bit integer in network byte order.
    pub fn read_i64(&mut self) -> Result<i64> {
        let bytes = self.read_byte_array::<8>()?;
        Ok(i64::from_be_bytes(bytes))
    }

    /// Reads an XDR boolean.
    pub fn read_bool(&mut self) -> Result<bool> {
        match self.read_u32()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(Error::InvalidBool { value }),
        }
    }

    /// Reads an enum discriminant.
    pub fn read_discriminant(&mut self) -> Result<i32> {
        self.read_i32()
    }

    /// Reads fixed-length opaque data and skips XDR padding.
    pub fn read_fixed_opaque(&mut self, len: usize) -> Result<&'de [u8]> {
        let value = self.read_bytes(len)?;
        self.skip_padding(len)?;
        Ok(value)
    }

    pub(crate) fn read_fixed_opaque_unpadded(&mut self, len: usize) -> Result<&'de [u8]> {
        self.read_bytes(len)
    }

    /// Reads variable-length opaque data with a maximum length.
    pub fn read_opaque(&mut self, max: usize) -> Result<&'de [u8]> {
        let len = self.read_len(max)?;
        self.read_fixed_opaque(len)
    }

    /// Reads variable-length opaque data into a `Vec`.
    pub fn read_opaque_vec(&mut self, max: usize) -> Result<Vec<u8>> {
        Ok(self.read_opaque(max)?.to_vec())
    }

    /// Reads a UTF-8 XDR string with a maximum byte length.
    pub fn read_string(&mut self, max: usize) -> Result<String> {
        let bytes = self.read_opaque(max)?;
        let value = std::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
        Ok(value.to_owned())
    }

    /// Reads a variable-length array with a maximum element count.
    pub fn read_array<T: Decode>(&mut self, max: usize) -> Result<Vec<T>> {
        let len = self.read_len(max)?;
        let mut values = Vec::with_capacity(len.min(MAX_ARRAY_PREALLOC));
        for _ in 0..len {
            values.push(T::decode(self)?);
        }
        Ok(values)
    }

    /// Reads an XDR optional value encoded as a boolean followed by a value.
    pub fn read_optional<T: Decode>(&mut self) -> Result<Option<T>> {
        if self.read_bool()? {
            Ok(Some(T::decode(self)?))
        } else {
            Ok(None)
        }
    }

    fn read_len(&mut self, max: usize) -> Result<usize> {
        let len = self.read_u32()? as usize;
        if len > max {
            return Err(Error::LengthLimitExceeded { len, max });
        }
        Ok(len)
    }

    fn read_byte_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.read_bytes(N)?;
        let mut out = [0; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'de [u8]> {
        let end = self.position.checked_add(len).ok_or(Error::UnexpectedEof {
            needed: len,
            remaining: self.remaining(),
        })?;
        if end > self.input.len() {
            return Err(Error::UnexpectedEof {
                needed: len,
                remaining: self.remaining(),
            });
        }

        let bytes = &self.input[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    fn skip_padding(&mut self, len: usize) -> Result<()> {
        self.read_bytes(padding_len(len))?;
        Ok(())
    }
}

/// Decodes a complete XDR value and rejects trailing input.
pub fn from_bytes<T: Decode>(input: &[u8]) -> Result<T> {
    let mut decoder = Decoder::new(input);
    let value = T::decode(&mut decoder)?;
    decoder.finish()?;
    Ok(value)
}

impl Decode for u32 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self> {
        decoder.read_u32()
    }
}

impl Decode for i32 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self> {
        decoder.read_i32()
    }
}

impl Decode for u64 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self> {
        decoder.read_u64()
    }
}

impl Decode for i64 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self> {
        decoder.read_i64()
    }
}

impl Decode for bool {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self> {
        decoder.read_bool()
    }
}

impl Decode for () {
    fn decode(_decoder: &mut Decoder<'_>) -> Result<Self> {
        Ok(())
    }
}
