use rustmod_core::encoding::{Reader, Writer};
use rustmod_core::frame;
use rustmod_core::pdu::{
    ReadHoldingRegistersRequest, Request, Response, WriteMultipleCoilsRequest,
    WriteMultipleRegistersRequest,
};
use rustmod_core::{DecodeError, EncodeError};

const READ_HOLDING_REQ: &[u8] = &[0x03, 0x00, 0x6B, 0x00, 0x03];
const READ_HOLDING_RESP: &[u8] = &[0x03, 0x06, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64];
const TCP_READ_HOLDING: &[u8] = &[
    0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x6B, 0x00, 0x03,
];

#[test]
fn fc03_request_golden_encode() {
    let request = Request::ReadHoldingRegisters(ReadHoldingRegistersRequest {
        start_address: 0x006B,
        quantity: 0x0003,
    });

    let mut buf = [0u8; 16];
    let mut w = Writer::new(&mut buf);
    request.encode(&mut w).unwrap();
    assert_eq!(w.as_written(), READ_HOLDING_REQ);
}

#[test]
fn fc03_response_decode_and_helpers() {
    let mut r = Reader::new(READ_HOLDING_RESP);
    let response = Response::decode(&mut r).unwrap();

    match response {
        Response::ReadHoldingRegisters(resp) => {
            assert_eq!(resp.register_count(), 3);
            assert_eq!(resp.register(0), Some(0x022B));
            assert_eq!(resp.register(1), Some(0x0000));
            assert_eq!(resp.register(2), Some(0x0064));
        }
        _ => panic!("expected read holding registers response"),
    }
}

#[test]
fn mbap_frame_roundtrip() {
    let mut buf = [0u8; 32];
    let mut w = Writer::new(&mut buf);
    frame::tcp::encode_frame(&mut w, 1, 1, READ_HOLDING_REQ).unwrap();
    assert_eq!(w.as_written(), TCP_READ_HOLDING);

    let mut r = Reader::new(w.as_written());
    let (header, pdu) = frame::tcp::decode_frame(&mut r).unwrap();
    assert_eq!(header.transaction_id, 1);
    assert_eq!(header.protocol_id, 0);
    assert_eq!(header.length, 6);
    assert_eq!(header.unit_id, 1);
    assert_eq!(pdu, READ_HOLDING_REQ);
}

#[test]
fn rtu_frame_crc_tamper_detected() {
    let mut buf = [0u8; 32];
    let mut w = Writer::new(&mut buf);
    frame::rtu::encode_frame(&mut w, 1, READ_HOLDING_REQ).unwrap();

    let mut tampered = w.as_written().to_vec();
    tampered[2] ^= 0x01;

    assert_eq!(
        frame::rtu::decode_frame(&tampered).unwrap_err(),
        DecodeError::InvalidCrc
    );
}

#[test]
fn quantity_boundaries_are_validated() {
    let mut buf = [0u8; 512];

    let mut w = Writer::new(&mut buf);
    let req = Request::ReadHoldingRegisters(ReadHoldingRegistersRequest {
        start_address: 0,
        quantity: 0,
    });
    assert_eq!(req.encode(&mut w).unwrap_err(), EncodeError::ValueOutOfRange);

    let values_too_many = [0u16; 124];
    let multi_regs = WriteMultipleRegistersRequest {
        start_address: 0,
        values: &values_too_many,
    };
    let mut w = Writer::new(&mut buf);
    assert_eq!(
        multi_regs.encode(&mut w).unwrap_err(),
        EncodeError::ValueOutOfRange
    );

    let too_many_coils = [false; 1969];
    let multi_coils = WriteMultipleCoilsRequest {
        start_address: 0,
        values: &too_many_coils,
    };
    let mut w = Writer::new(&mut buf);
    assert_eq!(
        multi_coils.encode(&mut w).unwrap_err(),
        EncodeError::ValueOutOfRange
    );
}

#[test]
fn exception_roundtrip() {
    let bytes = [0x83u8, 0x02];
    let mut r = Reader::new(&bytes);
    let decoded = Response::decode(&mut r).unwrap();

    let mut out = [0u8; 8];
    let mut w = Writer::new(&mut out);
    decoded.encode(&mut w).unwrap();
    assert_eq!(w.as_written(), &bytes);
}
