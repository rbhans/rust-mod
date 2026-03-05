#![no_main]
use libfuzzer_sys::fuzz_target;
use rustmod_core::encoding::Reader;
use rustmod_core::pdu::Response;

fuzz_target!(|data: &[u8]| {
    let mut reader = Reader::new(data);
    let _ = Response::decode(&mut reader);
});
