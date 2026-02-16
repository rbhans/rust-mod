use crate::encoding::{Reader, Writer};
use crate::{DecodeError, EncodeError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ExceptionCode {
    IllegalFunction,
    IllegalDataAddress,
    IllegalDataValue,
    ServerDeviceFailure,
    Acknowledge,
    ServerDeviceBusy,
    MemoryParityError,
    GatewayPathUnavailable,
    GatewayTargetFailedToRespond,
    Unknown(u8),
}

impl ExceptionCode {
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0x01 => Self::IllegalFunction,
            0x02 => Self::IllegalDataAddress,
            0x03 => Self::IllegalDataValue,
            0x04 => Self::ServerDeviceFailure,
            0x05 => Self::Acknowledge,
            0x06 => Self::ServerDeviceBusy,
            0x08 => Self::MemoryParityError,
            0x0A => Self::GatewayPathUnavailable,
            0x0B => Self::GatewayTargetFailedToRespond,
            other => Self::Unknown(other),
        }
    }

    pub const fn as_u8(self) -> u8 {
        match self {
            Self::IllegalFunction => 0x01,
            Self::IllegalDataAddress => 0x02,
            Self::IllegalDataValue => 0x03,
            Self::ServerDeviceFailure => 0x04,
            Self::Acknowledge => 0x05,
            Self::ServerDeviceBusy => 0x06,
            Self::MemoryParityError => 0x08,
            Self::GatewayPathUnavailable => 0x0A,
            Self::GatewayTargetFailedToRespond => 0x0B,
            Self::Unknown(raw) => raw,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExceptionResponse {
    /// Raw function code without the exception bit (bit 7).
    pub function_code: u8,
    pub exception_code: ExceptionCode,
}

impl ExceptionResponse {
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.write_u8(self.function_code | 0x80)?;
        w.write_u8(self.exception_code.as_u8())?;
        Ok(())
    }

    pub fn decode(function_byte: u8, r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        if (function_byte & 0x80) == 0 {
            return Err(DecodeError::InvalidFunctionCode);
        }
        let exception = r.read_u8()?;
        Ok(Self {
            function_code: function_byte & 0x7F,
            exception_code: ExceptionCode::from_u8(exception),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{ExceptionCode, ExceptionResponse};
    use crate::encoding::{Reader, Writer};

    #[test]
    fn roundtrip_exception_response() {
        let mut buf = [0u8; 2];
        let mut w = Writer::new(&mut buf);
        let resp = ExceptionResponse {
            function_code: 0x03,
            exception_code: ExceptionCode::ServerDeviceBusy,
        };
        resp.encode(&mut w).unwrap();
        assert_eq!(w.as_written(), &[0x83, 0x06]);

        let mut r = Reader::new(w.as_written());
        let fc = r.read_u8().unwrap();
        let decoded = ExceptionResponse::decode(fc, &mut r).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn preserves_unknown_exception_codes() {
        let mut r = Reader::new(&[0x11]);
        let decoded = ExceptionResponse::decode(0x83, &mut r).unwrap();
        assert_eq!(decoded.exception_code, ExceptionCode::Unknown(0x11));
    }
}
