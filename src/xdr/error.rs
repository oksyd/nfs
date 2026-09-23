use std::fmt;

/// Result type used by XDR helpers.
pub type Result<T> = std::result::Result<T, Error>;

/// XDR encoding and decoding error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The input ended before the requested value could be decoded.
    UnexpectedEof { needed: usize, remaining: usize },
    /// Top-level decoding left unread bytes.
    TrailingBytes { remaining: usize },
    /// XDR boolean was not `0` or `1`.
    InvalidBool { value: u32 },
    /// Enum discriminant was unknown for the target type.
    InvalidDiscriminant { type_name: &'static str, value: i32 },
    /// Encoded length exceeded the caller-provided limit.
    LengthLimitExceeded { len: usize, max: usize },
    /// Encoded length cannot fit in an XDR `u32`.
    LengthOutOfRange { len: usize },
    /// XDR string payload was not valid UTF-8.
    InvalidUtf8,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof { needed, remaining } => {
                write!(
                    f,
                    "unexpected end of XDR input: need {needed} bytes, have {remaining}"
                )
            }
            Self::TrailingBytes { remaining } => {
                write!(f, "XDR input has {remaining} trailing bytes")
            }
            Self::InvalidBool { value } => {
                write!(f, "invalid XDR bool value {value}")
            }
            Self::InvalidDiscriminant { type_name, value } => {
                write!(f, "invalid XDR discriminant {value} for {type_name}")
            }
            Self::LengthLimitExceeded { len, max } => {
                write!(f, "XDR length {len} exceeds limit {max}")
            }
            Self::LengthOutOfRange { len } => {
                write!(f, "XDR length {len} cannot be represented as u32")
            }
            Self::InvalidUtf8 => f.write_str("XDR string is not valid UTF-8"),
        }
    }
}

impl std::error::Error for Error {}
