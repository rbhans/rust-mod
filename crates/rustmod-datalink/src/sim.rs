use crate::{ModbusService, ServiceError};
use rustmod_core::encoding::Writer;
use rustmod_core::pdu::{DecodedRequest, FunctionCode};
use rustmod_core::EncodeError;
use std::sync::RwLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoilBank {
    values: Vec<bool>,
}

impl CoilBank {
    pub fn new(size: usize) -> Self {
        Self {
            values: vec![false; size],
        }
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<bool> {
        self.values.get(index).copied()
    }

    pub fn set(&mut self, index: usize, value: bool) -> Result<(), ServiceError> {
        let slot = self
            .values
            .get_mut(index)
            .ok_or(ServiceError::InvalidRequest("coil address out of range"))?;
        *slot = value;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterBank {
    values: Vec<u16>,
}

impl RegisterBank {
    pub fn new(size: usize) -> Self {
        Self {
            values: vec![0u16; size],
        }
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<u16> {
        self.values.get(index).copied()
    }

    pub fn set(&mut self, index: usize, value: u16) -> Result<(), ServiceError> {
        let slot = self
            .values
            .get_mut(index)
            .ok_or(ServiceError::InvalidRequest("register address out of range"))?;
        *slot = value;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InMemoryPointModel {
    pub coils: CoilBank,
    pub discrete_inputs: CoilBank,
    pub holding_registers: RegisterBank,
    pub input_registers: RegisterBank,
}

impl InMemoryPointModel {
    pub fn new(
        coil_count: usize,
        discrete_input_count: usize,
        holding_register_count: usize,
        input_register_count: usize,
    ) -> Self {
        Self {
            coils: CoilBank::new(coil_count),
            discrete_inputs: CoilBank::new(discrete_input_count),
            holding_registers: RegisterBank::new(holding_register_count),
            input_registers: RegisterBank::new(input_register_count),
        }
    }
}

#[derive(Debug)]
pub struct InMemoryModbusService {
    model: RwLock<InMemoryPointModel>,
}

impl InMemoryModbusService {
    pub fn new(
        coil_count: usize,
        discrete_input_count: usize,
        holding_register_count: usize,
        input_register_count: usize,
    ) -> Self {
        Self::with_model(InMemoryPointModel::new(
            coil_count,
            discrete_input_count,
            holding_register_count,
            input_register_count,
        ))
    }

    pub fn with_model(model: InMemoryPointModel) -> Self {
        Self {
            model: RwLock::new(model),
        }
    }

    pub fn snapshot(&self) -> InMemoryPointModel {
        self.model
            .read()
            .expect("in-memory point model lock poisoned")
            .clone()
    }

    pub fn set_coil(&self, address: u16, value: bool) -> Result<(), ServiceError> {
        self.model
            .write()
            .expect("in-memory point model lock poisoned")
            .coils
            .set(usize::from(address), value)
    }

    pub fn set_discrete_input(&self, address: u16, value: bool) -> Result<(), ServiceError> {
        self.model
            .write()
            .expect("in-memory point model lock poisoned")
            .discrete_inputs
            .set(usize::from(address), value)
    }

    pub fn set_holding_register(&self, address: u16, value: u16) -> Result<(), ServiceError> {
        self.model
            .write()
            .expect("in-memory point model lock poisoned")
            .holding_registers
            .set(usize::from(address), value)
    }

    pub fn set_input_register(&self, address: u16, value: u16) -> Result<(), ServiceError> {
        self.model
            .write()
            .expect("in-memory point model lock poisoned")
            .input_registers
            .set(usize::from(address), value)
    }

    pub fn coil(&self, address: u16) -> Option<bool> {
        self.model
            .read()
            .expect("in-memory point model lock poisoned")
            .coils
            .get(usize::from(address))
    }

    pub fn holding_register(&self, address: u16) -> Option<u16> {
        self.model
            .read()
            .expect("in-memory point model lock poisoned")
            .holding_registers
            .get(usize::from(address))
    }
}

impl ModbusService for InMemoryModbusService {
    fn handle(
        &self,
        unit_id: u8,
        request: DecodedRequest<'_>,
        response_pdu: &mut [u8],
    ) -> Result<usize, ServiceError> {
        let mut model = self
            .model
            .write()
            .expect("in-memory point model lock poisoned");

        let mut w = Writer::new(response_pdu);

        match request {
            DecodedRequest::ReadCoils(req) => {
                let range = checked_range(req.start_address, req.quantity, model.coils.len())
                    .ok_or(ServiceError::Exception(
                        rustmod_core::pdu::ExceptionCode::IllegalDataAddress,
                    ))?;
                let byte_count = range.len().div_ceil(8);
                let byte_count_u8 = u8::try_from(byte_count)
                    .map_err(|_| ServiceError::Internal("coil response too large"))?;

                w.write_u8(FunctionCode::ReadCoils.as_u8())
                    .map_err(map_encode)?;
                w.write_u8(byte_count_u8).map_err(map_encode)?;

                let mut packed = [0u8; 250];
                for (i, address) in range.enumerate() {
                    if model.coils.get(address).unwrap_or(false) {
                        packed[i / 8] |= 1u8 << (i % 8);
                    }
                }
                w.write_all(&packed[..byte_count]).map_err(map_encode)?;
            }
            DecodedRequest::ReadDiscreteInputs(req) => {
                let range = checked_range(
                    req.start_address,
                    req.quantity,
                    model.discrete_inputs.len(),
                )
                .ok_or(ServiceError::Exception(
                    rustmod_core::pdu::ExceptionCode::IllegalDataAddress,
                ))?;
                let byte_count = range.len().div_ceil(8);
                let byte_count_u8 = u8::try_from(byte_count)
                    .map_err(|_| ServiceError::Internal("discrete input response too large"))?;

                w.write_u8(FunctionCode::ReadDiscreteInputs.as_u8())
                    .map_err(map_encode)?;
                w.write_u8(byte_count_u8).map_err(map_encode)?;

                let mut packed = [0u8; 250];
                for (i, address) in range.enumerate() {
                    if model.discrete_inputs.get(address).unwrap_or(false) {
                        packed[i / 8] |= 1u8 << (i % 8);
                    }
                }
                w.write_all(&packed[..byte_count]).map_err(map_encode)?;
            }
            DecodedRequest::ReadHoldingRegisters(req) => {
                let range = checked_range(
                    req.start_address,
                    req.quantity,
                    model.holding_registers.len(),
                )
                .ok_or(ServiceError::Exception(
                    rustmod_core::pdu::ExceptionCode::IllegalDataAddress,
                ))?;

                let byte_count = range.len() * 2;
                let byte_count_u8 = u8::try_from(byte_count)
                    .map_err(|_| ServiceError::Internal("register response too large"))?;

                w.write_u8(FunctionCode::ReadHoldingRegisters.as_u8())
                    .map_err(map_encode)?;
                w.write_u8(byte_count_u8).map_err(map_encode)?;
                for address in range {
                    w.write_be_u16(model.holding_registers.get(address).unwrap_or(0))
                        .map_err(map_encode)?;
                }
            }
            DecodedRequest::ReadInputRegisters(req) => {
                let range = checked_range(req.start_address, req.quantity, model.input_registers.len())
                    .ok_or(ServiceError::Exception(
                        rustmod_core::pdu::ExceptionCode::IllegalDataAddress,
                    ))?;

                let byte_count = range.len() * 2;
                let byte_count_u8 = u8::try_from(byte_count)
                    .map_err(|_| ServiceError::Internal("input register response too large"))?;

                w.write_u8(FunctionCode::ReadInputRegisters.as_u8())
                    .map_err(map_encode)?;
                w.write_u8(byte_count_u8).map_err(map_encode)?;
                for address in range {
                    w.write_be_u16(model.input_registers.get(address).unwrap_or(0))
                        .map_err(map_encode)?;
                }
            }
            DecodedRequest::WriteSingleCoil(req) => {
                model
                    .coils
                    .set(usize::from(req.address), req.value)
                    .map_err(|_| {
                        ServiceError::Exception(rustmod_core::pdu::ExceptionCode::IllegalDataAddress)
                    })?;
                w.write_u8(FunctionCode::WriteSingleCoil.as_u8())
                    .map_err(map_encode)?;
                w.write_be_u16(req.address).map_err(map_encode)?;
                w.write_be_u16(if req.value { 0xFF00 } else { 0x0000 })
                    .map_err(map_encode)?;
            }
            DecodedRequest::WriteSingleRegister(req) => {
                model
                    .holding_registers
                    .set(usize::from(req.address), req.value)
                    .map_err(|_| {
                        ServiceError::Exception(rustmod_core::pdu::ExceptionCode::IllegalDataAddress)
                    })?;
                w.write_u8(FunctionCode::WriteSingleRegister.as_u8())
                    .map_err(map_encode)?;
                w.write_be_u16(req.address).map_err(map_encode)?;
                w.write_be_u16(req.value).map_err(map_encode)?;
            }
            DecodedRequest::WriteMultipleCoils(req) => {
                let range = checked_range(req.start_address, req.quantity, model.coils.len()).ok_or(
                    ServiceError::Exception(rustmod_core::pdu::ExceptionCode::IllegalDataAddress),
                )?;

                for (i, address) in range.enumerate() {
                    let value = req.coil(i).ok_or(ServiceError::InvalidRequest(
                        "invalid packed coil write payload",
                    ))?;
                    model.coils.set(address, value)?;
                }

                w.write_u8(FunctionCode::WriteMultipleCoils.as_u8())
                    .map_err(map_encode)?;
                w.write_be_u16(req.start_address).map_err(map_encode)?;
                w.write_be_u16(req.quantity).map_err(map_encode)?;
            }
            DecodedRequest::WriteMultipleRegisters(req) => {
                let quantity = req.quantity();
                let quantity_u16 = u16::try_from(quantity)
                    .map_err(|_| ServiceError::InvalidRequest("register quantity too large"))?;
                let range = checked_range(
                    req.start_address,
                    quantity_u16,
                    model.holding_registers.len(),
                )
                .ok_or(ServiceError::Exception(
                    rustmod_core::pdu::ExceptionCode::IllegalDataAddress,
                ))?;

                for (i, address) in range.enumerate() {
                    let value = req
                        .register(i)
                        .ok_or(ServiceError::InvalidRequest("invalid register payload"))?;
                    model.holding_registers.set(address, value)?;
                }

                w.write_u8(FunctionCode::WriteMultipleRegisters.as_u8())
                    .map_err(map_encode)?;
                w.write_be_u16(req.start_address).map_err(map_encode)?;
                w.write_be_u16(quantity_u16).map_err(map_encode)?;
            }
            DecodedRequest::MaskWriteRegister(req) => {
                let address = usize::from(req.address);
                let current = model.holding_registers.get(address).ok_or(ServiceError::Exception(
                    rustmod_core::pdu::ExceptionCode::IllegalDataAddress,
                ))?;
                let next = (current & req.and_mask) | (req.or_mask & !req.and_mask);
                model.holding_registers.set(address, next).map_err(|_| {
                    ServiceError::Exception(rustmod_core::pdu::ExceptionCode::IllegalDataAddress)
                })?;

                w.write_u8(FunctionCode::MaskWriteRegister.as_u8())
                    .map_err(map_encode)?;
                w.write_be_u16(req.address).map_err(map_encode)?;
                w.write_be_u16(req.and_mask).map_err(map_encode)?;
                w.write_be_u16(req.or_mask).map_err(map_encode)?;
            }
            DecodedRequest::ReadWriteMultipleRegisters(req) => {
                let write_quantity = req.write_quantity();
                let write_quantity_u16 = u16::try_from(write_quantity)
                    .map_err(|_| ServiceError::InvalidRequest("write quantity too large"))?;

                let write_range = checked_range(
                    req.write_start_address,
                    write_quantity_u16,
                    model.holding_registers.len(),
                )
                .ok_or(ServiceError::Exception(
                    rustmod_core::pdu::ExceptionCode::IllegalDataAddress,
                ))?;

                for (i, address) in write_range.enumerate() {
                    let value = req
                        .register(i)
                        .ok_or(ServiceError::InvalidRequest("invalid register payload"))?;
                    model.holding_registers.set(address, value)?;
                }

                let read_range = checked_range(
                    req.read_start_address,
                    req.read_quantity,
                    model.holding_registers.len(),
                )
                .ok_or(ServiceError::Exception(
                    rustmod_core::pdu::ExceptionCode::IllegalDataAddress,
                ))?;

                let byte_count = read_range.len() * 2;
                let byte_count_u8 = u8::try_from(byte_count)
                    .map_err(|_| ServiceError::Internal("register response too large"))?;
                w.write_u8(FunctionCode::ReadWriteMultipleRegisters.as_u8())
                    .map_err(map_encode)?;
                w.write_u8(byte_count_u8).map_err(map_encode)?;
                for address in read_range {
                    w.write_be_u16(model.holding_registers.get(address).unwrap_or(0))
                        .map_err(map_encode)?;
                }
            }
            DecodedRequest::Custom(req) => {
                if req.function_code == 0x11 {
                    // FC17 Report Server ID: byte-count + server-id + run-indicator.
                    w.write_u8(0x11).map_err(map_encode)?;
                    w.write_u8(0x02).map_err(map_encode)?;
                    w.write_u8(unit_id).map_err(map_encode)?;
                    w.write_u8(0xFF).map_err(map_encode)?;
                } else if req.function_code == 0x2B {
                    // FC43/MEI 0x0E Read Device Identification.
                    if req.data.len() != 3 || req.data[0] != 0x0E {
                        return Err(ServiceError::Exception(
                            rustmod_core::pdu::ExceptionCode::IllegalDataValue,
                        ));
                    }
                    let read_code = req.data[1];
                    w.write_u8(0x2B).map_err(map_encode)?;
                    w.write_u8(0x0E).map_err(map_encode)?;
                    w.write_u8(read_code).map_err(map_encode)?;
                    w.write_u8(0x01).map_err(map_encode)?; // basic conformity level
                    w.write_u8(0x00).map_err(map_encode)?; // no more follows
                    w.write_u8(0x00).map_err(map_encode)?; // next object id

                    let objects = [
                        (0x00u8, b"rust-mod-sim".as_slice()),
                        (0x01u8, b"in-memory".as_slice()),
                        (0x02u8, b"0.1".as_slice()),
                    ];
                    w.write_u8(objects.len() as u8).map_err(map_encode)?;
                    for (id, value) in objects {
                        let value_len = u8::try_from(value.len()).map_err(|_| {
                            ServiceError::Internal("device identification object too large")
                        })?;
                        w.write_u8(id).map_err(map_encode)?;
                        w.write_u8(value_len).map_err(map_encode)?;
                        w.write_all(value).map_err(map_encode)?;
                    }
                } else {
                    return Err(ServiceError::Exception(
                        rustmod_core::pdu::ExceptionCode::IllegalFunction,
                    ));
                }
            }
        }

        Ok(w.position())
    }
}

fn checked_range(start: u16, quantity: u16, len: usize) -> Option<std::ops::Range<usize>> {
    let start = usize::from(start);
    let quantity = usize::from(quantity);
    let end = start.checked_add(quantity)?;
    if quantity == 0 || end > len {
        return None;
    }
    Some(start..end)
}

fn map_encode(err: EncodeError) -> ServiceError {
    let msg = match err {
        EncodeError::BufferTooSmall => "response buffer too small",
        EncodeError::ValueOutOfRange => "response value out of range",
        EncodeError::InvalidLength => "response length invalid",
        EncodeError::Unsupported => "response operation unsupported",
        EncodeError::Message(_) => "response encode message",
    };
    ServiceError::Internal(msg)
}

#[cfg(test)]
mod tests {
    use super::{InMemoryModbusService, InMemoryPointModel};
    use crate::ModbusService;
    use rustmod_core::encoding::Reader;
    use rustmod_core::pdu::{DecodedRequest, Response};

    #[test]
    fn in_memory_service_reads_and_writes() {
        let service = InMemoryModbusService::with_model(InMemoryPointModel::new(16, 16, 16, 16));
        service.set_holding_register(0, 42).unwrap();

        let mut pdu = [0u8; 260];
        let request = {
            let mut r = Reader::new(&[0x03, 0x00, 0x00, 0x00, 0x01]);
            DecodedRequest::decode(&mut r).unwrap()
        };
        let len = service.handle(1, request, &mut pdu).unwrap();

        let mut rr = Reader::new(&pdu[..len]);
        match Response::decode(&mut rr).unwrap() {
            Response::ReadHoldingRegisters(resp) => assert_eq!(resp.register(0), Some(42)),
            other => panic!("unexpected response: {other:?}"),
        }

        let write_req = {
            let mut r = Reader::new(&[0x06, 0x00, 0x01, 0x12, 0x34]);
            DecodedRequest::decode(&mut r).unwrap()
        };
        let _ = service.handle(1, write_req, &mut pdu).unwrap();
        assert_eq!(service.holding_register(1), Some(0x1234));

        let mask_req = {
            let mut r = Reader::new(&[0x16, 0x00, 0x01, 0xFF, 0x00, 0x00, 0x12]);
            DecodedRequest::decode(&mut r).unwrap()
        };
        let _ = service.handle(1, mask_req, &mut pdu).unwrap();
        assert_eq!(service.holding_register(1), Some(0x1212));

        let rw_req = {
            let mut r = Reader::new(&[
                0x17, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x04, 0xBE, 0xEF, 0xCA,
                0xFE,
            ]);
            DecodedRequest::decode(&mut r).unwrap()
        };
        let len = service.handle(1, rw_req, &mut pdu).unwrap();
        let mut rr = Reader::new(&pdu[..len]);
        match Response::decode(&mut rr).unwrap() {
            Response::ReadWriteMultipleRegisters(resp) => {
                assert_eq!(resp.register(0), Some(0xBEEF));
                assert_eq!(resp.register(1), Some(0xCAFE));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn in_memory_service_supports_report_server_id() {
        let service = InMemoryModbusService::with_model(InMemoryPointModel::new(4, 4, 4, 4));
        let mut pdu = [0u8; 260];

        let request = {
            let mut r = Reader::new(&[0x11]);
            DecodedRequest::decode(&mut r).unwrap()
        };
        let len = service.handle(0x2A, request, &mut pdu).unwrap();

        let mut rr = Reader::new(&pdu[..len]);
        match Response::decode(&mut rr).unwrap() {
            Response::Custom(resp) => {
                assert_eq!(resp.function_code, 0x11);
                assert_eq!(resp.data, &[0x02, 0x2A, 0xFF]);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn in_memory_service_supports_read_device_identification() {
        let service = InMemoryModbusService::with_model(InMemoryPointModel::new(4, 4, 4, 4));
        let mut pdu = [0u8; 260];

        let request = {
            let mut r = Reader::new(&[0x2B, 0x0E, 0x01, 0x00]);
            DecodedRequest::decode(&mut r).unwrap()
        };
        let len = service.handle(0x2A, request, &mut pdu).unwrap();

        let mut rr = Reader::new(&pdu[..len]);
        match Response::decode(&mut rr).unwrap() {
            Response::Custom(resp) => {
                assert_eq!(resp.function_code, 0x2B);
                assert_eq!(resp.data[0], 0x0E);
                assert_eq!(resp.data[1], 0x01);
                assert_eq!(resp.data[5], 0x03);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }
}
