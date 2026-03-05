use core::fmt;

/// Errors that can occur while encoding Modbus data into an output buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum EncodeError {
    /// The output buffer does not have enough space.
    BufferTooSmall,
    /// A value exceeds the allowed range for the field.
    ValueOutOfRange,
    /// The data length is invalid for the operation.
    InvalidLength,
    /// The operation is not supported.
    Unsupported,
    /// A descriptive error message.
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
#[non_exhaustive]
pub enum DecodeError {
    /// The input buffer ended before the expected data was fully read.
    UnexpectedEof,
    /// The function code byte is invalid (0x00 or has the exception bit set).
    InvalidFunctionCode,
    /// A length field does not match the actual data.
    InvalidLength,
    /// A field value is outside the allowed range.
    InvalidValue,
    /// The CRC check failed (RTU framing).
    InvalidCrc,
    /// The operation is not supported.
    Unsupported,
    /// A descriptive error message.
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
