use proptest::prelude::*;
use rustmod_core::encoding::{Reader, Writer};
use rustmod_core::pdu::{ReadHoldingRegistersRequest, Request, Response};

proptest! {
    #[test]
    fn request_encode_does_not_panic(start in any::<u16>(), quantity in 0u16..=130u16) {
        let req = Request::ReadHoldingRegisters(ReadHoldingRegistersRequest {
            start_address: start,
            quantity,
        });
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        let _ = req.encode(&mut w);
    }

    #[test]
    fn random_response_decode_does_not_panic(data in proptest::collection::vec(any::<u8>(), 0..260)) {
        let mut r = Reader::new(&data);
        let _ = Response::decode(&mut r);
    }

    #[test]
    fn simple_response_roundtrip(registers in proptest::collection::vec(any::<u16>(), 1..=125)) {
        let mut data = Vec::with_capacity(registers.len() * 2);
        for reg in &registers {
            data.extend_from_slice(&reg.to_be_bytes());
        }

        let mut frame = Vec::with_capacity(data.len() + 2);
        frame.push(0x03);
        frame.push(data.len() as u8);
        frame.extend_from_slice(&data);

        let mut r = Reader::new(&frame);
        let decoded = Response::decode(&mut r).unwrap();

        let mut out = vec![0u8; frame.len() + 8];
        let mut w = Writer::new(&mut out);
        decoded.encode(&mut w).unwrap();
        prop_assert_eq!(w.as_written(), frame.as_slice());
    }
}
