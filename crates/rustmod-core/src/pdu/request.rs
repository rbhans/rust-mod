use crate::encoding::{Reader, Writer};
use crate::pdu::FunctionCode;
use crate::{DecodeError, EncodeError};

const MAX_READ_BITS: u16 = 2000;
const MAX_READ_REGISTERS: u16 = 125;
const MAX_WRITE_COILS: u16 = 1968;
const MAX_WRITE_REGISTERS: u16 = 123;
const MAX_RW_WRITE_REGISTERS: u16 = 121;

fn validate_quantity(quantity: u16, max: u16) -> Result<(), EncodeError> {
    if quantity == 0 || quantity > max {
        return Err(EncodeError::ValueOutOfRange);
    }
    Ok(())
}

fn validate_quantity_decode(quantity: u16, max: u16) -> Result<(), DecodeError> {
    if quantity == 0 || quantity > max {
        return Err(DecodeError::InvalidValue);
    }
    Ok(())
}

fn write_header(
    w: &mut Writer<'_>,
    function: FunctionCode,
    start_address: u16,
    quantity: u16,
) -> Result<(), EncodeError> {
    w.write_u8(function.as_u8())?;
    w.write_be_u16(start_address)?;
    w.write_be_u16(quantity)?;
    Ok(())
}

fn pack_coils(values: &[bool], out: &mut [u8]) {
    out.fill(0);
    for (i, value) in values.iter().enumerate() {
        if *value {
            out[i / 8] |= 1u8 << (i % 8);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadCoilsRequest {
    pub start_address: u16,
    pub quantity: u16,
}

impl ReadCoilsRequest {
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        validate_quantity(self.quantity, MAX_READ_BITS)?;
        write_header(
            w,
            FunctionCode::ReadCoils,
            self.start_address,
            self.quantity,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadDiscreteInputsRequest {
    pub start_address: u16,
    pub quantity: u16,
}

impl ReadDiscreteInputsRequest {
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        validate_quantity(self.quantity, MAX_READ_BITS)?;
        write_header(
            w,
            FunctionCode::ReadDiscreteInputs,
            self.start_address,
            self.quantity,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadHoldingRegistersRequest {
    pub start_address: u16,
    pub quantity: u16,
}

impl ReadHoldingRegistersRequest {
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        validate_quantity(self.quantity, MAX_READ_REGISTERS)?;
        write_header(
            w,
            FunctionCode::ReadHoldingRegisters,
            self.start_address,
            self.quantity,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadInputRegistersRequest {
    pub start_address: u16,
    pub quantity: u16,
}

impl ReadInputRegistersRequest {
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        validate_quantity(self.quantity, MAX_READ_REGISTERS)?;
        write_header(
            w,
            FunctionCode::ReadInputRegisters,
            self.start_address,
            self.quantity,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteSingleCoilRequest {
    pub address: u16,
    pub value: bool,
}

impl WriteSingleCoilRequest {
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.write_u8(FunctionCode::WriteSingleCoil.as_u8())?;
        w.write_be_u16(self.address)?;
        w.write_be_u16(if self.value { 0xFF00 } else { 0x0000 })?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteSingleRegisterRequest {
    pub address: u16,
    pub value: u16,
}

impl WriteSingleRegisterRequest {
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.write_u8(FunctionCode::WriteSingleRegister.as_u8())?;
        w.write_be_u16(self.address)?;
        w.write_be_u16(self.value)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteMultipleCoilsRequest<'a> {
    pub start_address: u16,
    pub values: &'a [bool],
}

impl<'a> WriteMultipleCoilsRequest<'a> {
    pub fn quantity(&self) -> Result<u16, EncodeError> {
        let quantity: u16 = self
            .values
            .len()
            .try_into()
            .map_err(|_| EncodeError::ValueOutOfRange)?;
        validate_quantity(quantity, MAX_WRITE_COILS)?;
        Ok(quantity)
    }

    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        let quantity = self.quantity()?;
        let byte_count_usize = self.values.len().div_ceil(8);
        let byte_count: u8 = byte_count_usize
            .try_into()
            .map_err(|_| EncodeError::ValueOutOfRange)?;

        w.write_u8(FunctionCode::WriteMultipleCoils.as_u8())?;
        w.write_be_u16(self.start_address)?;
        w.write_be_u16(quantity)?;
        w.write_u8(byte_count)?;

        let mut packed = [0u8; 246];
        let used = usize::from(byte_count);
        pack_coils(self.values, &mut packed[..used]);
        w.write_all(&packed[..used])?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteMultipleRegistersRequest<'a> {
    pub start_address: u16,
    pub values: &'a [u16],
}

impl<'a> WriteMultipleRegistersRequest<'a> {
    pub fn quantity(&self) -> Result<u16, EncodeError> {
        let quantity: u16 = self
            .values
            .len()
            .try_into()
            .map_err(|_| EncodeError::ValueOutOfRange)?;
        validate_quantity(quantity, MAX_WRITE_REGISTERS)?;
        Ok(quantity)
    }

    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        let quantity = self.quantity()?;
        let byte_count_usize = self.values.len() * 2;
        let byte_count: u8 = byte_count_usize
            .try_into()
            .map_err(|_| EncodeError::ValueOutOfRange)?;

        w.write_u8(FunctionCode::WriteMultipleRegisters.as_u8())?;
        w.write_be_u16(self.start_address)?;
        w.write_be_u16(quantity)?;
        w.write_u8(byte_count)?;
        for value in self.values {
            w.write_be_u16(*value)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaskWriteRegisterRequest {
    pub address: u16,
    pub and_mask: u16,
    pub or_mask: u16,
}

impl MaskWriteRegisterRequest {
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.write_u8(FunctionCode::MaskWriteRegister.as_u8())?;
        w.write_be_u16(self.address)?;
        w.write_be_u16(self.and_mask)?;
        w.write_be_u16(self.or_mask)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadWriteMultipleRegistersRequest<'a> {
    pub read_start_address: u16,
    pub read_quantity: u16,
    pub write_start_address: u16,
    pub values: &'a [u16],
}

impl<'a> ReadWriteMultipleRegistersRequest<'a> {
    pub fn write_quantity(&self) -> Result<u16, EncodeError> {
        let quantity: u16 = self
            .values
            .len()
            .try_into()
            .map_err(|_| EncodeError::ValueOutOfRange)?;
        validate_quantity(quantity, MAX_RW_WRITE_REGISTERS)?;
        Ok(quantity)
    }

    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        validate_quantity(self.read_quantity, MAX_READ_REGISTERS)?;
        let write_quantity = self.write_quantity()?;
        let byte_count = u8::try_from(usize::from(write_quantity) * 2)
            .map_err(|_| EncodeError::ValueOutOfRange)?;

        w.write_u8(FunctionCode::ReadWriteMultipleRegisters.as_u8())?;
        w.write_be_u16(self.read_start_address)?;
        w.write_be_u16(self.read_quantity)?;
        w.write_be_u16(self.write_start_address)?;
        w.write_be_u16(write_quantity)?;
        w.write_u8(byte_count)?;
        for value in self.values {
            w.write_be_u16(*value)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustomRequest<'a> {
    pub function_code: u8,
    pub data: &'a [u8],
}

impl<'a> CustomRequest<'a> {
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        if self.function_code == 0 || FunctionCode::is_exception(self.function_code) {
            return Err(EncodeError::ValueOutOfRange);
        }
        w.write_u8(self.function_code)?;
        w.write_all(self.data)?;
        Ok(())
    }
}

/// Borrowed decode representation for FC15 payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteMultipleCoilsRequestData<'a> {
    pub start_address: u16,
    pub quantity: u16,
    pub values_packed: &'a [u8],
}

impl<'a> WriteMultipleCoilsRequestData<'a> {
    pub fn coil(&self, index: usize) -> Option<bool> {
        if index >= usize::from(self.quantity) {
            return None;
        }
        let byte = self.values_packed.get(index / 8)?;
        Some((byte & (1u8 << (index % 8))) != 0)
    }
}

/// Borrowed decode representation for FC16 payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteMultipleRegistersRequestData<'a> {
    pub start_address: u16,
    pub values_bytes: &'a [u8],
}

impl<'a> WriteMultipleRegistersRequestData<'a> {
    pub fn quantity(&self) -> usize {
        self.values_bytes.len() / 2
    }

    pub fn register(&self, index: usize) -> Option<u16> {
        let offset = index.checked_mul(2)?;
        let bytes = self.values_bytes.get(offset..offset + 2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadWriteMultipleRegistersRequestData<'a> {
    pub read_start_address: u16,
    pub read_quantity: u16,
    pub write_start_address: u16,
    pub values_bytes: &'a [u8],
}

impl<'a> ReadWriteMultipleRegistersRequestData<'a> {
    pub fn write_quantity(&self) -> usize {
        self.values_bytes.len() / 2
    }

    pub fn register(&self, index: usize) -> Option<u16> {
        let offset = index.checked_mul(2)?;
        let bytes = self.values_bytes.get(offset..offset + 2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustomRequestData<'a> {
    pub function_code: u8,
    pub data: &'a [u8],
}

#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedWriteMultipleCoilsRequest {
    pub start_address: u16,
    pub values: alloc::vec::Vec<bool>,
}

#[cfg(feature = "alloc")]
impl OwnedWriteMultipleCoilsRequest {
    pub fn as_borrowed(&self) -> WriteMultipleCoilsRequest<'_> {
        WriteMultipleCoilsRequest {
            start_address: self.start_address,
            values: &self.values,
        }
    }
}

#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedWriteMultipleRegistersRequest {
    pub start_address: u16,
    pub values: alloc::vec::Vec<u16>,
}

#[cfg(feature = "alloc")]
impl OwnedWriteMultipleRegistersRequest {
    pub fn as_borrowed(&self) -> WriteMultipleRegistersRequest<'_> {
        WriteMultipleRegistersRequest {
            start_address: self.start_address,
            values: &self.values,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request<'a> {
    ReadCoils(ReadCoilsRequest),
    ReadDiscreteInputs(ReadDiscreteInputsRequest),
    ReadHoldingRegisters(ReadHoldingRegistersRequest),
    ReadInputRegisters(ReadInputRegistersRequest),
    WriteSingleCoil(WriteSingleCoilRequest),
    WriteSingleRegister(WriteSingleRegisterRequest),
    WriteMultipleCoils(WriteMultipleCoilsRequest<'a>),
    WriteMultipleRegisters(WriteMultipleRegistersRequest<'a>),
    MaskWriteRegister(MaskWriteRegisterRequest),
    ReadWriteMultipleRegisters(ReadWriteMultipleRegistersRequest<'a>),
    Custom(CustomRequest<'a>),
}

impl<'a> Request<'a> {
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        match self {
            Self::ReadCoils(req) => req.encode(w),
            Self::ReadDiscreteInputs(req) => req.encode(w),
            Self::ReadHoldingRegisters(req) => req.encode(w),
            Self::ReadInputRegisters(req) => req.encode(w),
            Self::WriteSingleCoil(req) => req.encode(w),
            Self::WriteSingleRegister(req) => req.encode(w),
            Self::WriteMultipleCoils(req) => req.encode(w),
            Self::WriteMultipleRegisters(req) => req.encode(w),
            Self::MaskWriteRegister(req) => req.encode(w),
            Self::ReadWriteMultipleRegisters(req) => req.encode(w),
            Self::Custom(req) => req.encode(w),
        }
    }

    pub fn function_code(&self) -> FunctionCode {
        match self {
            Self::ReadCoils(_) => FunctionCode::ReadCoils,
            Self::ReadDiscreteInputs(_) => FunctionCode::ReadDiscreteInputs,
            Self::ReadHoldingRegisters(_) => FunctionCode::ReadHoldingRegisters,
            Self::ReadInputRegisters(_) => FunctionCode::ReadInputRegisters,
            Self::WriteSingleCoil(_) => FunctionCode::WriteSingleCoil,
            Self::WriteSingleRegister(_) => FunctionCode::WriteSingleRegister,
            Self::WriteMultipleCoils(_) => FunctionCode::WriteMultipleCoils,
            Self::WriteMultipleRegisters(_) => FunctionCode::WriteMultipleRegisters,
            Self::MaskWriteRegister(_) => FunctionCode::MaskWriteRegister,
            Self::ReadWriteMultipleRegisters(_) => FunctionCode::ReadWriteMultipleRegisters,
            Self::Custom(req) => FunctionCode::Custom(req.function_code),
        }
    }
}

/// Decoded request model used by simulator/server implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodedRequest<'a> {
    ReadCoils(ReadCoilsRequest),
    ReadDiscreteInputs(ReadDiscreteInputsRequest),
    ReadHoldingRegisters(ReadHoldingRegistersRequest),
    ReadInputRegisters(ReadInputRegistersRequest),
    WriteSingleCoil(WriteSingleCoilRequest),
    WriteSingleRegister(WriteSingleRegisterRequest),
    WriteMultipleCoils(WriteMultipleCoilsRequestData<'a>),
    WriteMultipleRegisters(WriteMultipleRegistersRequestData<'a>),
    MaskWriteRegister(MaskWriteRegisterRequest),
    ReadWriteMultipleRegisters(ReadWriteMultipleRegistersRequestData<'a>),
    Custom(CustomRequestData<'a>),
}

impl<'a> DecodedRequest<'a> {
    pub fn function_code(&self) -> FunctionCode {
        match self {
            Self::ReadCoils(_) => FunctionCode::ReadCoils,
            Self::ReadDiscreteInputs(_) => FunctionCode::ReadDiscreteInputs,
            Self::ReadHoldingRegisters(_) => FunctionCode::ReadHoldingRegisters,
            Self::ReadInputRegisters(_) => FunctionCode::ReadInputRegisters,
            Self::WriteSingleCoil(_) => FunctionCode::WriteSingleCoil,
            Self::WriteSingleRegister(_) => FunctionCode::WriteSingleRegister,
            Self::WriteMultipleCoils(_) => FunctionCode::WriteMultipleCoils,
            Self::WriteMultipleRegisters(_) => FunctionCode::WriteMultipleRegisters,
            Self::MaskWriteRegister(_) => FunctionCode::MaskWriteRegister,
            Self::ReadWriteMultipleRegisters(_) => FunctionCode::ReadWriteMultipleRegisters,
            Self::Custom(req) => FunctionCode::Custom(req.function_code),
        }
    }

    pub fn decode(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let function = FunctionCode::from_u8(r.read_u8()?)?;
        match function {
            FunctionCode::ReadCoils => {
                let start_address = r.read_be_u16()?;
                let quantity = r.read_be_u16()?;
                validate_quantity_decode(quantity, MAX_READ_BITS)?;
                Ok(Self::ReadCoils(ReadCoilsRequest {
                    start_address,
                    quantity,
                }))
            }
            FunctionCode::ReadDiscreteInputs => {
                let start_address = r.read_be_u16()?;
                let quantity = r.read_be_u16()?;
                validate_quantity_decode(quantity, MAX_READ_BITS)?;
                Ok(Self::ReadDiscreteInputs(ReadDiscreteInputsRequest {
                    start_address,
                    quantity,
                }))
            }
            FunctionCode::ReadHoldingRegisters => {
                let start_address = r.read_be_u16()?;
                let quantity = r.read_be_u16()?;
                validate_quantity_decode(quantity, MAX_READ_REGISTERS)?;
                Ok(Self::ReadHoldingRegisters(ReadHoldingRegistersRequest {
                    start_address,
                    quantity,
                }))
            }
            FunctionCode::ReadInputRegisters => {
                let start_address = r.read_be_u16()?;
                let quantity = r.read_be_u16()?;
                validate_quantity_decode(quantity, MAX_READ_REGISTERS)?;
                Ok(Self::ReadInputRegisters(ReadInputRegistersRequest {
                    start_address,
                    quantity,
                }))
            }
            FunctionCode::WriteSingleCoil => {
                let address = r.read_be_u16()?;
                let raw = r.read_be_u16()?;
                let value = match raw {
                    0xFF00 => true,
                    0x0000 => false,
                    _ => return Err(DecodeError::InvalidValue),
                };
                Ok(Self::WriteSingleCoil(WriteSingleCoilRequest {
                    address,
                    value,
                }))
            }
            FunctionCode::WriteSingleRegister => {
                let address = r.read_be_u16()?;
                let value = r.read_be_u16()?;
                Ok(Self::WriteSingleRegister(WriteSingleRegisterRequest {
                    address,
                    value,
                }))
            }
            FunctionCode::WriteMultipleCoils => {
                let start_address = r.read_be_u16()?;
                let quantity = r.read_be_u16()?;
                validate_quantity_decode(quantity, MAX_WRITE_COILS)?;
                let byte_count = usize::from(r.read_u8()?);
                let expected = usize::from(quantity).div_ceil(8);
                if byte_count != expected {
                    return Err(DecodeError::InvalidLength);
                }
                let values_packed = r.read_exact(byte_count)?;
                Ok(Self::WriteMultipleCoils(WriteMultipleCoilsRequestData {
                    start_address,
                    quantity,
                    values_packed,
                }))
            }
            FunctionCode::WriteMultipleRegisters => {
                let start_address = r.read_be_u16()?;
                let quantity = r.read_be_u16()?;
                validate_quantity_decode(quantity, MAX_WRITE_REGISTERS)?;
                let byte_count = usize::from(r.read_u8()?);
                let expected = usize::from(quantity) * 2;
                if byte_count != expected {
                    return Err(DecodeError::InvalidLength);
                }
                let values_bytes = r.read_exact(byte_count)?;
                Ok(Self::WriteMultipleRegisters(WriteMultipleRegistersRequestData {
                    start_address,
                    values_bytes,
                }))
            }
            FunctionCode::MaskWriteRegister => {
                let address = r.read_be_u16()?;
                let and_mask = r.read_be_u16()?;
                let or_mask = r.read_be_u16()?;
                Ok(Self::MaskWriteRegister(MaskWriteRegisterRequest {
                    address,
                    and_mask,
                    or_mask,
                }))
            }
            FunctionCode::ReadWriteMultipleRegisters => {
                let read_start_address = r.read_be_u16()?;
                let read_quantity = r.read_be_u16()?;
                validate_quantity_decode(read_quantity, MAX_READ_REGISTERS)?;
                let write_start_address = r.read_be_u16()?;
                let write_quantity = r.read_be_u16()?;
                validate_quantity_decode(write_quantity, MAX_RW_WRITE_REGISTERS)?;
                let byte_count = usize::from(r.read_u8()?);
                let expected = usize::from(write_quantity) * 2;
                if byte_count != expected {
                    return Err(DecodeError::InvalidLength);
                }
                let values_bytes = r.read_exact(byte_count)?;
                Ok(Self::ReadWriteMultipleRegisters(
                    ReadWriteMultipleRegistersRequestData {
                        read_start_address,
                        read_quantity,
                        write_start_address,
                        values_bytes,
                    },
                ))
            }
            FunctionCode::Custom(function_code) => {
                let data = r.read_exact(r.remaining())?;
                Ok(Self::Custom(CustomRequestData {
                    function_code,
                    data,
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CustomRequest, DecodedRequest, MaskWriteRegisterRequest, ReadHoldingRegistersRequest,
        ReadWriteMultipleRegistersRequest, Request, WriteMultipleCoilsRequest,
        WriteMultipleRegistersRequest,
    };
    use crate::encoding::{Reader, Writer};
    use crate::{DecodeError, EncodeError};

    #[test]
    fn read_holding_validates_quantity() {
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        let req = ReadHoldingRegistersRequest {
            start_address: 0,
            quantity: 0,
        };
        assert_eq!(req.encode(&mut w).unwrap_err(), EncodeError::ValueOutOfRange);
    }

    #[test]
    fn write_multiple_coils_packs_lsb_first() {
        let req = WriteMultipleCoilsRequest {
            start_address: 0x0013,
            values: &[true, false, true, true, false, false, true, false, true],
        };
        let mut buf = [0u8; 32];
        let mut w = Writer::new(&mut buf);
        req.encode(&mut w).unwrap();
        assert_eq!(
            w.as_written(),
            &[0x0F, 0x00, 0x13, 0x00, 0x09, 0x02, 0b0100_1101, 0b0000_0001]
        );
    }

    #[test]
    fn write_multiple_registers_rejects_too_many() {
        let values = [0u16; 124];
        let req = WriteMultipleRegistersRequest {
            start_address: 0,
            values: &values,
        };
        let mut buf = [0u8; 300];
        let mut w = Writer::new(&mut buf);
        assert_eq!(req.encode(&mut w).unwrap_err(), EncodeError::ValueOutOfRange);
    }

    #[test]
    fn enum_dispatch_works() {
        let req = Request::ReadHoldingRegisters(ReadHoldingRegistersRequest {
            start_address: 0x006B,
            quantity: 3,
        });
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        req.encode(&mut w).unwrap();
        assert_eq!(w.as_written(), &[0x03, 0x00, 0x6B, 0x00, 0x03]);
    }

    #[test]
    fn decode_fc03_request() {
        let mut r = Reader::new(&[0x03, 0x00, 0x6B, 0x00, 0x03]);
        let decoded = DecodedRequest::decode(&mut r).unwrap();
        assert!(matches!(
            decoded,
            DecodedRequest::ReadHoldingRegisters(ReadHoldingRegistersRequest {
                start_address: 0x006B,
                quantity: 3
            })
        ));
        assert!(r.is_empty());
    }

    #[test]
    fn decode_fc15_request_and_bits() {
        let mut r = Reader::new(&[0x0F, 0x00, 0x13, 0x00, 0x09, 0x02, 0b0100_1101, 0b0000_0001]);
        let decoded = DecodedRequest::decode(&mut r).unwrap();
        match decoded {
            DecodedRequest::WriteMultipleCoils(req) => {
                assert_eq!(req.start_address, 0x0013);
                assert_eq!(req.quantity, 9);
                assert_eq!(req.coil(0), Some(true));
                assert_eq!(req.coil(1), Some(false));
                assert_eq!(req.coil(8), Some(true));
                assert_eq!(req.coil(9), None);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_invalid_fc16_byte_count() {
        let mut r = Reader::new(&[0x10, 0x00, 0x00, 0x00, 0x02, 0x03, 0x12, 0x34, 0x56]);
        assert_eq!(DecodedRequest::decode(&mut r).unwrap_err(), DecodeError::InvalidLength);
    }

    #[test]
    fn decode_rejects_invalid_single_coil_value() {
        let mut r = Reader::new(&[0x05, 0x00, 0x01, 0x12, 0x34]);
        assert_eq!(DecodedRequest::decode(&mut r).unwrap_err(), DecodeError::InvalidValue);
    }

    #[test]
    fn custom_request_roundtrip() {
        let req = Request::Custom(CustomRequest {
            function_code: 0x41,
            data: &[0xAA, 0x55],
        });
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        req.encode(&mut w).unwrap();
        assert_eq!(w.as_written(), &[0x41, 0xAA, 0x55]);

        let mut r = Reader::new(w.as_written());
        match DecodedRequest::decode(&mut r).unwrap() {
            DecodedRequest::Custom(decoded) => {
                assert_eq!(decoded.function_code, 0x41);
                assert_eq!(decoded.data, &[0xAA, 0x55]);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn mask_write_register_roundtrip() {
        let req = Request::MaskWriteRegister(MaskWriteRegisterRequest {
            address: 0x0004,
            and_mask: 0xFF00,
            or_mask: 0x0012,
        });
        let mut buf = [0u8; 16];
        let mut w = Writer::new(&mut buf);
        req.encode(&mut w).unwrap();
        assert_eq!(w.as_written(), &[0x16, 0x00, 0x04, 0xFF, 0x00, 0x00, 0x12]);

        let mut r = Reader::new(w.as_written());
        match DecodedRequest::decode(&mut r).unwrap() {
            DecodedRequest::MaskWriteRegister(decoded) => {
                assert_eq!(decoded.address, 0x0004);
                assert_eq!(decoded.and_mask, 0xFF00);
                assert_eq!(decoded.or_mask, 0x0012);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn read_write_multiple_registers_roundtrip() {
        let req = Request::ReadWriteMultipleRegisters(ReadWriteMultipleRegistersRequest {
            read_start_address: 0x0010,
            read_quantity: 2,
            write_start_address: 0x0020,
            values: &[0x1111, 0x2222],
        });

        let mut buf = [0u8; 32];
        let mut w = Writer::new(&mut buf);
        req.encode(&mut w).unwrap();
        assert_eq!(
            w.as_written(),
            &[0x17, 0x00, 0x10, 0x00, 0x02, 0x00, 0x20, 0x00, 0x02, 0x04, 0x11, 0x11, 0x22, 0x22]
        );

        let mut r = Reader::new(w.as_written());
        match DecodedRequest::decode(&mut r).unwrap() {
            DecodedRequest::ReadWriteMultipleRegisters(decoded) => {
                assert_eq!(decoded.read_start_address, 0x0010);
                assert_eq!(decoded.read_quantity, 2);
                assert_eq!(decoded.write_start_address, 0x0020);
                assert_eq!(decoded.write_quantity(), 2);
                assert_eq!(decoded.register(0), Some(0x1111));
                assert_eq!(decoded.register(1), Some(0x2222));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_invalid_fc23_byte_count() {
        let mut r = Reader::new(&[0x17, 0x00, 0x10, 0x00, 0x01, 0x00, 0x20, 0x00, 0x01, 0x01, 0x12]);
        assert_eq!(DecodedRequest::decode(&mut r).unwrap_err(), DecodeError::InvalidLength);
    }
}
