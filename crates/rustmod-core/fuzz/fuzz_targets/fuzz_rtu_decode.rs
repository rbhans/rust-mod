#![no_main]
use libfuzzer_sys::fuzz_target;
use rustmod_core::frame::rtu;

fuzz_target!(|data: &[u8]| {
    let _ = rtu::decode_frame(data);
});
