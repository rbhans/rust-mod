use core::fmt;

/// Errors that can occur while encoding Modbus data into an output buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EncodeError {
    BufferTooSmall,
    ValueOutOfRange,
    InvalidLength,
    Unsupported,
    Message(&'static str),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall => f.write_str("buffer too small"),
            Self::ValueOutOfRange => f.write_str("value out of range"),
            Self::InvalidLength => f.write_str("invalid length"),
            Self::Unsupported => f.write_str("operation unsupported"),
            Self::Message(msg) => f.write_str(msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EncodeError {}

/// Errors that can occur while decoding Modbus data from an input buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DecodeError {
    UnexpectedEof,
    InvalidFunctionCode,
    InvalidLength,
    InvalidValue,
    InvalidCrc,
    Unsupported,
    Message(&'static str),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => f.write_str("unexpected end of input"),
            Self::InvalidFunctionCode => f.write_str("invalid function code"),
            Self::InvalidLength => f.write_str("invalid length"),
            Self::InvalidValue => f.write_str("invalid value"),
            Self::InvalidCrc => f.write_str("invalid crc"),
            Self::Unsupported => f.write_str("operation unsupported"),
            Self::Message(msg) => f.write_str(msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}
