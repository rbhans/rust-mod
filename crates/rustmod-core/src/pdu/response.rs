use crate::encoding::{Reader, Writer};
use crate::pdu::{ExceptionResponse, FunctionCode};
use crate::{DecodeError, EncodeError};

const MAX_READ_REGISTERS: u16 = 125;
const MAX_WRITE_COILS: u16 = 1968;
const MAX_WRITE_REGISTERS: u16 = 123;

fn validate_echo_quantity(quantity: u16, max: u16) -> Result<(), DecodeError> {
    if quantity == 0 || quantity > max {
        return Err(DecodeError::InvalidValue);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadCoilsResponse<'a> {
    pub coil_status: &'a [u8],
}

impl<'a> ReadCoilsResponse<'a> {
    fn decode_body(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let byte_count = usize::from(r.read_u8()?);
        if byte_count == 0 {
            return Err(DecodeError::InvalidLength);
        }
        let data = r.read_exact(byte_count)?;
        Ok(Self { coil_status: data })
    }

    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        let byte_count: u8 = self
            .coil_status
            .len()
            .try_into()
            .map_err(|_| EncodeError::ValueOutOfRange)?;
        w.write_u8(FunctionCode::ReadCoils.as_u8())?;
        w.write_u8(byte_count)?;
        w.write_all(self.coil_status)?;
        Ok(())
    }

    pub fn coil(&self, index: usize) -> Option<bool> {
        let byte = self.coil_status.get(index / 8)?;
        Some((byte & (1u8 << (index % 8))) != 0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadDiscreteInputsResponse<'a> {
    pub input_status: &'a [u8],
}

impl<'a> ReadDiscreteInputsResponse<'a> {
    fn decode_body(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let byte_count = usize::from(r.read_u8()?);
        if byte_count == 0 {
            return Err(DecodeError::InvalidLength);
        }
        let data = r.read_exact(byte_count)?;
        Ok(Self { input_status: data })
    }

    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        let byte_count: u8 = self
            .input_status
            .len()
            .try_into()
            .map_err(|_| EncodeError::ValueOutOfRange)?;
        w.write_u8(FunctionCode::ReadDiscreteInputs.as_u8())?;
        w.write_u8(byte_count)?;
        w.write_all(self.input_status)?;
        Ok(())
    }

    pub fn coil(&self, index: usize) -> Option<bool> {
        let byte = self.input_status.get(index / 8)?;
        Some((byte & (1u8 << (index % 8))) != 0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadHoldingRegistersResponse<'a> {
    pub data: &'a [u8],
}

impl<'a> ReadHoldingRegistersResponse<'a> {
    fn decode_body(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let byte_count = usize::from(r.read_u8()?);
        if byte_count == 0 || (byte_count % 2) != 0 {
            return Err(DecodeError::InvalidLength);
        }
        if byte_count > usize::from(MAX_READ_REGISTERS) * 2 {
            return Err(DecodeError::InvalidLength);
        }
        let data = r.read_exact(byte_count)?;
        Ok(Self { data })
    }

    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        if (self.data.len() % 2) != 0 {
            return Err(EncodeError::InvalidLength);
        }
        let byte_count: u8 = self
            .data
            .len()
            .try_into()
            .map_err(|_| EncodeError::ValueOutOfRange)?;
        w.write_u8(FunctionCode::ReadHoldingRegisters.as_u8())?;
        w.write_u8(byte_count)?;
        w.write_all(self.data)?;
        Ok(())
    }

    pub fn register_count(&self) -> usize {
        self.data.len() / 2
    }

    pub fn register(&self, index: usize) -> Option<u16> {
        let offset = index.checked_mul(2)?;
        let bytes = self.data.get(offset..offset + 2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadInputRegistersResponse<'a> {
    pub data: &'a [u8],
}

impl<'a> ReadInputRegistersResponse<'a> {
    fn decode_body(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let byte_count = usize::from(r.read_u8()?);
        if byte_count == 0 || (byte_count % 2) != 0 {
            return Err(DecodeError::InvalidLength);
        }
        if byte_count > usize::from(MAX_READ_REGISTERS) * 2 {
            return Err(DecodeError::InvalidLength);
        }
        let data = r.read_exact(byte_count)?;
        Ok(Self { data })
    }

    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        if (self.data.len() % 2) != 0 {
            return Err(EncodeError::InvalidLength);
        }
        let byte_count: u8 = self
            .data
            .len()
            .try_into()
            .map_err(|_| EncodeError::ValueOutOfRange)?;
        w.write_u8(FunctionCode::ReadInputRegisters.as_u8())?;
        w.write_u8(byte_count)?;
        w.write_all(self.data)?;
        Ok(())
    }

    pub fn register_count(&self) -> usize {
        self.data.len() / 2
    }

    pub fn register(&self, index: usize) -> Option<u16> {
        let offset = index.checked_mul(2)?;
        let bytes = self.data.get(offset..offset + 2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteSingleCoilResponse {
    pub address: u16,
    pub value: bool,
}

impl WriteSingleCoilResponse {
    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let address = r.read_be_u16()?;
        let raw = r.read_be_u16()?;
        let value = match raw {
            0xFF00 => true,
            0x0000 => false,
            _ => return Err(DecodeError::InvalidValue),
        };
        Ok(Self { address, value })
    }

    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.write_u8(FunctionCode::WriteSingleCoil.as_u8())?;
        w.write_be_u16(self.address)?;
        w.write_be_u16(if self.value { 0xFF00 } else { 0x0000 })?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteSingleRegisterResponse {
    pub address: u16,
    pub value: u16,
}

impl WriteSingleRegisterResponse {
    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            address: r.read_be_u16()?,
            value: r.read_be_u16()?,
        })
    }

    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.write_u8(FunctionCode::WriteSingleRegister.as_u8())?;
        w.write_be_u16(self.address)?;
        w.write_be_u16(self.value)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteMultipleCoilsResponse {
    pub start_address: u16,
    pub quantity: u16,
}

impl WriteMultipleCoilsResponse {
    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let start_address = r.read_be_u16()?;
        let quantity = r.read_be_u16()?;
        validate_echo_quantity(quantity, MAX_WRITE_COILS)?;
        Ok(Self {
            start_address,
            quantity,
        })
    }

    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        if self.quantity == 0 || self.quantity > MAX_WRITE_COILS {
            return Err(EncodeError::ValueOutOfRange);
        }
        w.write_u8(FunctionCode::WriteMultipleCoils.as_u8())?;
        w.write_be_u16(self.start_address)?;
        w.write_be_u16(self.quantity)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteMultipleRegistersResponse {
    pub start_address: u16,
    pub quantity: u16,
}

impl WriteMultipleRegistersResponse {
    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let start_address = r.read_be_u16()?;
        let quantity = r.read_be_u16()?;
        validate_echo_quantity(quantity, MAX_WRITE_REGISTERS)?;
        Ok(Self {
            start_address,
            quantity,
        })
    }

    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        if self.quantity == 0 || self.quantity > MAX_WRITE_REGISTERS {
            return Err(EncodeError::ValueOutOfRange);
        }
        w.write_u8(FunctionCode::WriteMultipleRegisters.as_u8())?;
        w.write_be_u16(self.start_address)?;
        w.write_be_u16(self.quantity)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaskWriteRegisterResponse {
    pub address: u16,
    pub and_mask: u16,
    pub or_mask: u16,
}

impl MaskWriteRegisterResponse {
    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            address: r.read_be_u16()?,
            and_mask: r.read_be_u16()?,
            or_mask: r.read_be_u16()?,
        })
    }

    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.write_u8(FunctionCode::MaskWriteRegister.as_u8())?;
        w.write_be_u16(self.address)?;
        w.write_be_u16(self.and_mask)?;
        w.write_be_u16(self.or_mask)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadWriteMultipleRegistersResponse<'a> {
    pub data: &'a [u8],
}

impl<'a> ReadWriteMultipleRegistersResponse<'a> {
    fn decode_body(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let byte_count = usize::from(r.read_u8()?);
        if byte_count == 0 || (byte_count % 2) != 0 {
            return Err(DecodeError::InvalidLength);
        }
        if byte_count > usize::from(MAX_READ_REGISTERS) * 2 {
            return Err(DecodeError::InvalidLength);
        }
        let data = r.read_exact(byte_count)?;
        Ok(Self { data })
    }

    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        if (self.data.len() % 2) != 0 {
            return Err(EncodeError::InvalidLength);
        }
        let byte_count = u8::try_from(self.data.len()).map_err(|_| EncodeError::ValueOutOfRange)?;
        w.write_u8(FunctionCode::ReadWriteMultipleRegisters.as_u8())?;
        w.write_u8(byte_count)?;
        w.write_all(self.data)?;
        Ok(())
    }

    pub fn register_count(&self) -> usize {
        self.data.len() / 2
    }

    pub fn register(&self, index: usize) -> Option<u16> {
        let offset = index.checked_mul(2)?;
        let bytes = self.data.get(offset..offset + 2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustomResponse<'a> {
    pub function_code: u8,
    pub data: &'a [u8],
}

impl<'a> CustomResponse<'a> {
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        if self.function_code == 0 || FunctionCode::is_exception(self.function_code) {
            return Err(EncodeError::ValueOutOfRange);
        }
        w.write_u8(self.function_code)?;
        w.write_all(self.data)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Response<'a> {
    ReadCoils(ReadCoilsResponse<'a>),
    ReadDiscreteInputs(ReadDiscreteInputsResponse<'a>),
    ReadHoldingRegisters(ReadHoldingRegistersResponse<'a>),
    ReadInputRegisters(ReadInputRegistersResponse<'a>),
    WriteSingleCoil(WriteSingleCoilResponse),
    WriteSingleRegister(WriteSingleRegisterResponse),
    WriteMultipleCoils(WriteMultipleCoilsResponse),
    WriteMultipleRegisters(WriteMultipleRegistersResponse),
    MaskWriteRegister(MaskWriteRegisterResponse),
    ReadWriteMultipleRegisters(ReadWriteMultipleRegistersResponse<'a>),
    Custom(CustomResponse<'a>),
    Exception(ExceptionResponse),
}

impl<'a> Response<'a> {
    pub fn decode(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let function_byte = r.read_u8()?;
        if FunctionCode::is_exception(function_byte) {
            return Ok(Self::Exception(ExceptionResponse::decode(function_byte, r)?));
        }

        let fc = FunctionCode::from_u8(function_byte)?;
        match fc {
            FunctionCode::ReadCoils => Ok(Self::ReadCoils(ReadCoilsResponse::decode_body(r)?)),
            FunctionCode::ReadDiscreteInputs => {
                Ok(Self::ReadDiscreteInputs(ReadDiscreteInputsResponse::decode_body(r)?))
            }
            FunctionCode::ReadHoldingRegisters => Ok(Self::ReadHoldingRegisters(
                ReadHoldingRegistersResponse::decode_body(r)?,
            )),
            FunctionCode::ReadInputRegisters => Ok(Self::ReadInputRegisters(
                ReadInputRegistersResponse::decode_body(r)?,
            )),
            FunctionCode::WriteSingleCoil => {
                Ok(Self::WriteSingleCoil(WriteSingleCoilResponse::decode_body(r)?))
            }
            FunctionCode::WriteSingleRegister => Ok(Self::WriteSingleRegister(
                WriteSingleRegisterResponse::decode_body(r)?,
            )),
            FunctionCode::WriteMultipleCoils => Ok(Self::WriteMultipleCoils(
                WriteMultipleCoilsResponse::decode_body(r)?,
            )),
            FunctionCode::WriteMultipleRegisters => Ok(Self::WriteMultipleRegisters(
                WriteMultipleRegistersResponse::decode_body(r)?,
            )),
            FunctionCode::MaskWriteRegister => Ok(Self::MaskWriteRegister(
                MaskWriteRegisterResponse::decode_body(r)?,
            )),
            FunctionCode::ReadWriteMultipleRegisters => Ok(Self::ReadWriteMultipleRegisters(
                ReadWriteMultipleRegistersResponse::decode_body(r)?,
            )),
            FunctionCode::Custom(function_code) => {
                let data = r.read_exact(r.remaining())?;
                Ok(Self::Custom(CustomResponse {
                    function_code,
                    data,
                }))
            }
        }
    }

    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        match self {
            Self::ReadCoils(resp) => resp.encode(w),
            Self::ReadDiscreteInputs(resp) => resp.encode(w),
            Self::ReadHoldingRegisters(resp) => resp.encode(w),
            Self::ReadInputRegisters(resp) => resp.encode(w),
            Self::WriteSingleCoil(resp) => resp.encode(w),
            Self::WriteSingleRegister(resp) => resp.encode(w),
            Self::WriteMultipleCoils(resp) => resp.encode(w),
            Self::WriteMultipleRegisters(resp) => resp.encode(w),
            Self::MaskWriteRegister(resp) => resp.encode(w),
            Self::ReadWriteMultipleRegisters(resp) => resp.encode(w),
            Self::Custom(resp) => resp.encode(w),
            Self::Exception(resp) => resp.encode(w),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CustomResponse, MaskWriteRegisterResponse, ReadHoldingRegistersResponse,
        ReadWriteMultipleRegistersResponse, Response, WriteSingleCoilResponse,
    };
    use crate::encoding::{Reader, Writer};
    use crate::pdu::ExceptionCode;
    use crate::DecodeError;

    #[test]
    fn register_helpers_work() {
        let resp = ReadHoldingRegistersResponse {
            data: &[0x12, 0x34, 0xAB, 0xCD],
        };
        assert_eq!(resp.register_count(), 2);
        assert_eq!(resp.register(0), Some(0x1234));
        assert_eq!(resp.register(1), Some(0xABCD));
        assert_eq!(resp.register(2), None);
    }

    #[test]
    fn response_decode_exception_unknown_code() {
        let mut r = Reader::new(&[0x83, 0x19]);
        match Response::decode(&mut r).unwrap() {
            Response::Exception(ex) => {
                assert_eq!(ex.function_code, 0x03);
                assert_eq!(ex.exception_code, ExceptionCode::Unknown(0x19));
            }
            _ => panic!("expected exception"),
        }
    }

    #[test]
    fn write_single_coil_rejects_invalid_payload() {
        let mut r = Reader::new(&[0x05, 0x00, 0x01, 0x12, 0x34]);
        assert_eq!(Response::decode(&mut r).unwrap_err(), DecodeError::InvalidValue);
    }

    #[test]
    fn enum_encode_roundtrip() {
        let original = Response::WriteSingleCoil(WriteSingleCoilResponse {
            address: 0x0007,
            value: true,
        });
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        original.encode(&mut w).unwrap();

        let mut r = Reader::new(w.as_written());
        let decoded = Response::decode(&mut r).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn custom_response_roundtrip() {
        let original = Response::Custom(CustomResponse {
            function_code: 0x41,
            data: &[0xAA, 0x55],
        });
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        original.encode(&mut w).unwrap();
        assert_eq!(w.as_written(), &[0x41, 0xAA, 0x55]);

        let mut r = Reader::new(w.as_written());
        let decoded = Response::decode(&mut r).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn mask_write_response_roundtrip() {
        let original = Response::MaskWriteRegister(MaskWriteRegisterResponse {
            address: 0x0007,
            and_mask: 0xFF00,
            or_mask: 0x00A5,
        });
        let mut buf = [0u8; 16];
        let mut w = Writer::new(&mut buf);
        original.encode(&mut w).unwrap();
        assert_eq!(w.as_written(), &[0x16, 0x00, 0x07, 0xFF, 0x00, 0x00, 0xA5]);

        let mut r = Reader::new(w.as_written());
        let decoded = Response::decode(&mut r).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn read_write_multiple_registers_response_roundtrip() {
        let original = Response::ReadWriteMultipleRegisters(ReadWriteMultipleRegistersResponse {
            data: &[0x12, 0x34, 0xAB, 0xCD],
        });
        let mut buf = [0u8; 16];
        let mut w = Writer::new(&mut buf);
        original.encode(&mut w).unwrap();
        assert_eq!(w.as_written(), &[0x17, 0x04, 0x12, 0x34, 0xAB, 0xCD]);

        let mut r = Reader::new(w.as_written());
        match Response::decode(&mut r).unwrap() {
            Response::ReadWriteMultipleRegisters(resp) => {
                assert_eq!(resp.register_count(), 2);
                assert_eq!(resp.register(0), Some(0x1234));
                assert_eq!(resp.register(1), Some(0xABCD));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }
}
