use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rustmod_core::encoding::{Reader, Writer};
use rustmod_core::pdu::{DecodedRequest, ReadHoldingRegistersRequest, ReadHoldingRegistersResponse, Response};
use rustmod_core::frame::rtu;
use rustmod_core::UnitId;

// Benchmark for encoding a FC03 request (ReadHoldingRegistersRequest)
fn bench_encode_fc03_request(c: &mut Criterion) {
    c.bench_function("encode_fc03_request", |b| {
        b.iter(|| {
            let req = black_box(ReadHoldingRegistersRequest {
                start_address: 0x006B,
                quantity: 10,
            });
            let mut buf = [0u8; 256];
            let mut w = Writer::new(&mut buf);
            req.encode(&mut w).unwrap();
        });
    });
}

// Benchmark for decoding a FC03 request
fn bench_decode_fc03_request(c: &mut Criterion) {
    let data = black_box([0x03u8, 0x00, 0x6B, 0x00, 0x0A]);
    c.bench_function("decode_fc03_request", |b| {
        b.iter(|| {
            let mut r = Reader::new(&data);
            DecodedRequest::decode(&mut r).unwrap();
        });
    });
}

// Benchmark for encoding a FC03 response (ReadHoldingRegistersResponse with 10 registers)
fn bench_encode_fc03_response(c: &mut Criterion) {
    c.bench_function("encode_fc03_response_10_registers", |b| {
        b.iter(|| {
            let register_data = black_box([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
            ]);
            let resp = ReadHoldingRegistersResponse {
                data: &register_data,
            };
            let mut buf = [0u8; 256];
            let mut w = Writer::new(&mut buf);
            resp.encode(&mut w).unwrap();
        });
    });
}

// Benchmark for decoding a FC03 response
fn bench_decode_fc03_response(c: &mut Criterion) {
    let response_data = black_box([
        0x03, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
    ]);
    c.bench_function("decode_fc03_response", |b| {
        b.iter(|| {
            let mut r = Reader::new(&response_data);
            Response::decode(&mut r).unwrap();
        });
    });
}

// Benchmark for CRC16 calculation
fn bench_crc16_calculation(c: &mut Criterion) {
    let data = black_box([0x01u8, 0x03, 0x00, 0x6B, 0x00, 0x0A]);
    c.bench_function("crc16_calculation", |b| {
        b.iter(|| {
            rtu::crc16(&data);
        });
    });
}

// Benchmark for full RTU encode+decode roundtrip
fn bench_rtu_roundtrip(c: &mut Criterion) {
    c.bench_function("rtu_roundtrip", |b| {
        b.iter(|| {
            let pdu = black_box([0x03u8, 0x00, 0x6B, 0x00, 0x0A]);
            let unit_id = black_box(UnitId::new(0x01));

            // Encode
            let mut buf = [0u8; 256];
            let mut w = Writer::new(&mut buf);
            rtu::encode_frame(&mut w, unit_id, &pdu).unwrap();
            let encoded = w.as_written();

            // Decode
            let (decoded_unit_id, decoded_pdu) = rtu::decode_frame(encoded).unwrap();
            assert_eq!(decoded_unit_id, unit_id);
            assert_eq!(decoded_pdu, &pdu);
        });
    });
}

criterion_group!(
    benches,
    bench_encode_fc03_request,
    bench_decode_fc03_request,
    bench_encode_fc03_response,
    bench_decode_fc03_response,
    bench_crc16_calculation,
    bench_rtu_roundtrip
);
criterion_main!(benches);
