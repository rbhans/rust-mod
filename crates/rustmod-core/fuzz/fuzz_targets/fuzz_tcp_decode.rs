#![no_main]
use libfuzzer_sys::fuzz_target;
use rustmod_core::encoding::Reader;
use rustmod_core::frame::tcp::MbapHeader;

fuzz_target!(|data: &[u8]| {
    let mut reader = Reader::new(data);
    let _ = MbapHeader::decode(&mut reader);
});
