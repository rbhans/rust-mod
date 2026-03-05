use crate::DecodeError;

/// Modbus function codes identifying the type of request or response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum FunctionCode {
    /// FC01 — Read Coils.
    ReadCoils,
    /// FC02 — Read Discrete Inputs.
    ReadDiscreteInputs,
    /// FC03 — Read Holding Registers.
    ReadHoldingRegisters,
    /// FC04 — Read Input Registers.
    ReadInputRegisters,
    /// FC05 — Write Single Coil.
    WriteSingleCoil,
    /// FC06 — Write Single Register.
    WriteSingleRegister,
    /// FC15 (0x0F) — Write Multiple Coils.
    WriteMultipleCoils,
    /// FC16 (0x10) — Write Multiple Registers.
    WriteMultipleRegisters,
    /// FC22 (0x16) — Mask Write Register.
    MaskWriteRegister,
    /// FC23 (0x17) — Read/Write Multiple Registers.
    ReadWriteMultipleRegisters,
    /// FC07 — Read Exception Status.
    ReadExceptionStatus,
    /// FC08 — Diagnostics.
    Diagnostics,
    /// FC24 (0x18) — Read FIFO Queue.
    ReadFifoQueue,
    /// A function code not recognised by this library.
    Custom(u8),
}

impl FunctionCode {
    /// Return the wire byte value for this function code.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::ReadCoils => 0x01,
            Self::ReadDiscreteInputs => 0x02,
            Self::ReadHoldingRegisters => 0x03,
            Self::ReadInputRegisters => 0x04,
            Self::WriteSingleCoil => 0x05,
            Self::WriteSingleRegister => 0x06,
            Self::WriteMultipleCoils => 0x0F,
            Self::WriteMultipleRegisters => 0x10,
            Self::MaskWriteRegister => 0x16,
            Self::ReadWriteMultipleRegisters => 0x17,
            Self::ReadExceptionStatus => 0x07,
            Self::Diagnostics => 0x08,
            Self::ReadFifoQueue => 0x18,
            Self::Custom(code) => code,
        }
    }

    /// Parse a function code from its wire byte value.
    pub fn from_u8(value: u8) -> Result<Self, DecodeError> {
        if value == 0 || Self::is_exception(value) {
            return Err(DecodeError::InvalidFunctionCode);
        }
        match value {
            0x01 => Ok(Self::ReadCoils),
            0x02 => Ok(Self::ReadDiscreteInputs),
            0x03 => Ok(Self::ReadHoldingRegisters),
            0x04 => Ok(Self::ReadInputRegisters),
            0x05 => Ok(Self::WriteSingleCoil),
            0x06 => Ok(Self::WriteSingleRegister),
            0x0F => Ok(Self::WriteMultipleCoils),
            0x10 => Ok(Self::WriteMultipleRegisters),
            0x16 => Ok(Self::MaskWriteRegister),
            0x17 => Ok(Self::ReadWriteMultipleRegisters),
            0x07 => Ok(Self::ReadExceptionStatus),
            0x08 => Ok(Self::Diagnostics),
            0x18 => Ok(Self::ReadFifoQueue),
            _ => Ok(Self::Custom(value)),
        }
    }

    /// Returns `true` if the high bit (0x80) is set, indicating an exception response.
    pub const fn is_exception(value: u8) -> bool {
        (value & 0x80) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::FunctionCode;
    use crate::DecodeError;

    #[test]
    fn parses_known_codes() {
        assert_eq!(FunctionCode::from_u8(0x03).unwrap(), FunctionCode::ReadHoldingRegisters);
        assert_eq!(FunctionCode::from_u8(0x10).unwrap(), FunctionCode::WriteMultipleRegisters);
        assert_eq!(FunctionCode::from_u8(0x16).unwrap(), FunctionCode::MaskWriteRegister);
        assert_eq!(
            FunctionCode::from_u8(0x17).unwrap(),
            FunctionCode::ReadWriteMultipleRegisters
        );
    }

    #[test]
    fn preserves_custom_codes() {
        assert_eq!(FunctionCode::from_u8(0x41).unwrap(), FunctionCode::Custom(0x41));
    }

    #[test]
    fn rejects_zero_function_code() {
        assert_eq!(FunctionCode::from_u8(0x00).unwrap_err(), DecodeError::InvalidFunctionCode);
    }

    #[test]
    fn rejects_exception_bit_codes() {
        assert_eq!(FunctionCode::from_u8(0x83).unwrap_err(), DecodeError::InvalidFunctionCode);
    }

    #[test]
    fn exception_bit_is_detected() {
        assert!(FunctionCode::is_exception(0x83));
        assert!(!FunctionCode::is_exception(0x03));
    }
}
