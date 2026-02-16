use rustmod_core::encoding::Reader;
use rustmod_core::pdu::Response;
use rustmod_datalink::{DataLink, InMemoryModbusService, ModbusTcpServer, ModbusTcpTransport};

#[tokio::test]
async fn datalink_transport_works_with_simulator_fixture() {
    let service = std::sync::Arc::new(InMemoryModbusService::new(64, 64, 64, 64));
    service.set_holding_register(0, 123).unwrap();

    let server = ModbusTcpServer::bind("127.0.0.1:0", std::sync::Arc::clone(&service))
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let transport = ModbusTcpTransport::connect(addr).await.unwrap();

    let mut response = [0u8; 260];
    let len = transport
        .exchange(1, &[0x03, 0x00, 0x00, 0x00, 0x01], &mut response)
        .await
        .unwrap();

    let mut r = Reader::new(&response[..len]);
    match Response::decode(&mut r).unwrap() {
        Response::ReadHoldingRegisters(resp) => assert_eq!(resp.register(0), Some(123)),
        other => panic!("unexpected response: {other:?}"),
    }

    let len = transport
        .exchange(1, &[0x06, 0x00, 0x00, 0x00, 0x2A], &mut response)
        .await
        .unwrap();
    assert_eq!(&response[..len], &[0x06, 0x00, 0x00, 0x00, 0x2A]);
    assert_eq!(service.holding_register(0), Some(42));

    server_task.abort();
    let _ = server_task.await;
}
