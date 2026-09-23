#![cfg(feature = "protocol")]

use nfs::xdr::{Decode, Decoder, Encode, Encoder, Error, from_bytes, to_bytes};

#[derive(Debug, PartialEq, Eq)]
struct Pair {
    left: u32,
    right: i64,
}

impl Encode for Pair {
    fn encode(&self, encoder: &mut Encoder) -> nfs::xdr::Result<()> {
        self.left.encode(encoder)?;
        self.right.encode(encoder)
    }
}

impl Decode for Pair {
    fn decode(decoder: &mut Decoder<'_>) -> nfs::xdr::Result<Self> {
        Ok(Self {
            left: u32::decode(decoder)?,
            right: i64::decode(decoder)?,
        })
    }
}

#[test]
fn encodes_primitives_in_network_order() {
    let mut encoder = Encoder::new();
    encoder.write_u32(0x0102_0304);
    encoder.write_i32(-2);
    encoder.write_u64(0x0102_0304_0506_0708);
    encoder.write_bool(true);

    assert_eq!(
        encoder.into_bytes(),
        [
            0x01, 0x02, 0x03, 0x04, //
            0xff, 0xff, 0xff, 0xfe, //
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
            0x00, 0x00, 0x00, 0x01,
        ]
    );
}

#[test]
fn decodes_primitives_in_network_order() {
    let input = [
        0x01, 0x02, 0x03, 0x04, //
        0xff, 0xff, 0xff, 0xfe, //
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
        0x00, 0x00, 0x00, 0x01,
    ];
    let mut decoder = Decoder::new(&input);

    assert_eq!(decoder.read_u32().unwrap(), 0x0102_0304);
    assert_eq!(decoder.read_i32().unwrap(), -2);
    assert_eq!(decoder.read_u64().unwrap(), 0x0102_0304_0506_0708);
    assert!(decoder.read_bool().unwrap());
    assert!(decoder.finish().is_ok());
}

#[test]
fn rejects_invalid_bool_values() {
    assert_eq!(
        from_bytes::<bool>(&[0, 0, 0, 2]).unwrap_err(),
        Error::InvalidBool { value: 2 }
    );
}

#[test]
fn encodes_and_decodes_variable_opaque_with_padding() {
    let mut encoder = Encoder::new();
    encoder.write_opaque(b"abc", 8).unwrap();
    assert_eq!(encoder.as_slice(), &[0, 0, 0, 3, b'a', b'b', b'c', 0]);

    let mut decoder = Decoder::new(encoder.as_slice());
    assert_eq!(decoder.read_opaque(8).unwrap(), b"abc");
    assert!(decoder.finish().is_ok());
}

#[test]
fn encodes_and_decodes_fixed_opaque_with_padding() {
    let mut encoder = Encoder::new();
    encoder.write_fixed_opaque(&[1, 2, 3, 4, 5]);
    assert_eq!(encoder.as_slice(), &[1, 2, 3, 4, 5, 0, 0, 0]);

    let mut decoder = Decoder::new(encoder.as_slice());
    assert_eq!(decoder.read_fixed_opaque(5).unwrap(), &[1, 2, 3, 4, 5]);
    assert!(decoder.finish().is_ok());
}

#[test]
fn encodes_and_decodes_strings() {
    let mut encoder = Encoder::new();
    encoder.write_string("hello", 16).unwrap();

    let mut decoder = Decoder::new(encoder.as_slice());
    assert_eq!(decoder.read_string(16).unwrap(), "hello");
}

#[test]
fn rejects_lengths_above_declared_limit() {
    let mut encoder = Encoder::new();
    let err = encoder.write_opaque(b"abcdef", 3).unwrap_err();
    assert_eq!(err, Error::LengthLimitExceeded { len: 6, max: 3 });

    let input = [0, 0, 0, 4, b'a', b'b', b'c', b'd'];
    let mut decoder = Decoder::new(&input);
    let err = decoder.read_opaque(3).unwrap_err();
    assert_eq!(err, Error::LengthLimitExceeded { len: 4, max: 3 });
}

#[test]
fn skips_non_zero_padding_from_remote_peers() {
    let mut decoder = Decoder::new(&[0, 0, 0, 1, b'a', 0, 7, 0]);
    assert_eq!(decoder.read_opaque(8).unwrap(), b"a");
    assert!(decoder.finish().is_ok());
}

#[test]
fn rejects_invalid_utf8_strings() {
    let mut decoder = Decoder::new(&[0, 0, 0, 1, 0xff, 0, 0, 0]);
    assert_eq!(decoder.read_string(8).unwrap_err(), Error::InvalidUtf8);
}

#[test]
fn rejects_truncated_input() {
    let mut decoder = Decoder::new(&[0, 0, 0]);
    assert_eq!(
        decoder.read_u32().unwrap_err(),
        Error::UnexpectedEof {
            needed: 4,
            remaining: 3
        }
    );
}

#[test]
fn rejects_trailing_input_from_top_level_helper() {
    assert_eq!(
        from_bytes::<u32>(&[0, 0, 0, 1, 0]).unwrap_err(),
        Error::TrailingBytes { remaining: 1 }
    );
}

#[test]
fn supports_trait_based_round_trip() {
    let value = Pair { left: 7, right: -9 };

    let encoded = to_bytes(&value).unwrap();
    assert_eq!(from_bytes::<Pair>(&encoded).unwrap(), value);
}

#[test]
fn encodes_and_decodes_arrays() {
    let mut encoder = Encoder::new();
    encoder.write_array(&[1_u32, 2, 3], 4).unwrap();

    let mut decoder = Decoder::new(encoder.as_slice());
    assert_eq!(decoder.read_array::<u32>(4).unwrap(), vec![1, 2, 3]);
    assert!(decoder.finish().is_ok());
}

#[test]
fn decodes_arrays_larger_than_initial_preallocation() {
    let values = (0..1500_u32).collect::<Vec<_>>();
    let mut encoder = Encoder::new();
    encoder.write_array(&values, values.len()).unwrap();

    let mut decoder = Decoder::new(encoder.as_slice());
    assert_eq!(decoder.read_array::<u32>(values.len()).unwrap(), values);
    assert!(decoder.finish().is_ok());
}

#[test]
fn encodes_and_decodes_optional_values() {
    let mut encoder = Encoder::new();
    encoder.write_optional(Some(&42_u32)).unwrap();
    encoder.write_optional::<u32>(None).unwrap();

    let mut decoder = Decoder::new(encoder.as_slice());
    assert_eq!(decoder.read_optional::<u32>().unwrap(), Some(42));
    assert_eq!(decoder.read_optional::<u32>().unwrap(), None);
    assert!(decoder.finish().is_ok());
}
