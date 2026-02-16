use crate::DecodeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FunctionCode {
    ReadCoils,
    ReadDiscreteInputs,
    ReadHoldingRegisters,
    ReadInputRegisters,
    WriteSingleCoil,
    WriteSingleRegister,
    WriteMultipleCoils,
    WriteMultipleRegisters,
    MaskWriteRegister,
    ReadWriteMultipleRegisters,
    Custom(u8),
}

impl FunctionCode {
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
            Self::Custom(code) => code,
        }
    }

    pub fn from_u8(value: u8) -> Result<Self, DecodeError> {
        if Self::is_exception(value) {
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
            _ => Ok(Self::Custom(value)),
        }
    }

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
    fn rejects_exception_bit_codes() {
        assert_eq!(FunctionCode::from_u8(0x83).unwrap_err(), DecodeError::InvalidFunctionCode);
    }

    #[test]
    fn exception_bit_is_detected() {
        assert!(FunctionCode::is_exception(0x83));
        assert!(!FunctionCode::is_exception(0x03));
    }
}
