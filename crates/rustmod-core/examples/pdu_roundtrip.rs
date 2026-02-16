use rustmod_core::encoding::{Reader, Writer};
use rustmod_core::pdu::{ReadHoldingRegistersRequest, Request, Response};

fn main() {
    let request = Request::ReadHoldingRegisters(ReadHoldingRegistersRequest {
        start_address: 0x006B,
        quantity: 2,
    });

    let mut request_buf = [0u8; 16];
    let mut w = Writer::new(&mut request_buf);
    request
        .encode(&mut w)
        .expect("request encoding should succeed for valid sample data");
    println!("encoded request pdu: {:02X?}", w.as_written());

    let response_bytes = [0x03, 0x04, 0x00, 0x2A, 0x00, 0x64];
    let mut r = Reader::new(&response_bytes);
    let response = Response::decode(&mut r)
        .expect("response decoding should succeed for valid sample response bytes");

    match response {
        Response::ReadHoldingRegisters(resp) => {
            for idx in 0..resp.register_count() {
                println!("register[{idx}] = {}", resp.register(idx).unwrap_or_default());
            }
        }
        other => println!("unexpected response: {other:?}"),
    }
}
