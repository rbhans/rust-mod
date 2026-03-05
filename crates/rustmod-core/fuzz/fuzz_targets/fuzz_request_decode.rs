#![no_main]
use libfuzzer_sys::fuzz_target;
use rustmod_core::encoding::Reader;
use rustmod_core::pdu::DecodedRequest;

fuzz_target!(|data: &[u8]| {
    let mut reader = Reader::new(data);
    let _ = DecodedRequest::decode(&mut reader);
});
