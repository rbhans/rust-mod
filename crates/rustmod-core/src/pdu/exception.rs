use crate::encoding::{Reader, Writer};
use crate::{DecodeError, EncodeError};

/// Modbus exception codes returned by a device to indicate an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum ExceptionCode {
    /// 0x01 — The function code is not supported.
    IllegalFunction,
    /// 0x02 — The data address is not valid.
    IllegalDataAddress,
    /// 0x03 — The data value is not valid.
    IllegalDataValue,
    /// 0x04 — An unrecoverable error occurred on the server.
    ServerDeviceFailure,
    /// 0x05 — The request has been accepted but will take time to process.
    Acknowledge,
    /// 0x06 — The server is busy processing another request.
    ServerDeviceBusy,
    /// 0x08 — Memory parity error detected.
    MemoryParityError,
    /// 0x0A — The gateway path is not available.
    GatewayPathUnavailable,
    /// 0x0B — The gateway target device failed to respond.
    GatewayTargetFailedToRespond,
    /// An exception code not defined in the standard.
    Unknown(u8),
}

impl ExceptionCode {
    /// Parse an exception code from its wire byte value.
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

}

impl core::fmt::Display for ExceptionCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::IllegalFunction => write!(f, "illegal function (0x01)"),
            Self::IllegalDataAddress => write!(f, "illegal data address (0x02)"),
            Self::IllegalDataValue => write!(f, "illegal data value (0x03)"),
            Self::ServerDeviceFailure => write!(f, "server device failure (0x04)"),
            Self::Acknowledge => write!(f, "acknowledge (0x05)"),
            Self::ServerDeviceBusy => write!(f, "server device busy (0x06)"),
            Self::MemoryParityError => write!(f, "memory parity error (0x08)"),
            Self::GatewayPathUnavailable => write!(f, "gateway path unavailable (0x0A)"),
            Self::GatewayTargetFailedToRespond => {
                write!(f, "gateway target failed to respond (0x0B)")
            }
            Self::Unknown(code) => write!(f, "unknown exception (0x{code:02X})"),
        }
    }
}

impl ExceptionCode {
    /// Return the wire byte value for this exception code.
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
/// A Modbus exception response (function code with bit 7 set + exception code).
pub struct ExceptionResponse {
    /// The original function code (without the exception bit).
    pub function_code: u8,
    /// The exception code describing the error.
    pub exception_code: ExceptionCode,
}

impl core::fmt::Display for ExceptionResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "exception on FC 0x{:02X}: {}",
            self.function_code, self.exception_code
        )
    }
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
