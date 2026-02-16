use rustmod_client::ModbusClient;
use rustmod_datalink::{InMemoryModbusService, ModbusTcpServer, ModbusTcpTransport};

#[tokio::test]
async fn client_can_interact_with_in_memory_simulator_service() {
    let service = std::sync::Arc::new(InMemoryModbusService::new(64, 64, 64, 64));
    service.set_holding_register(0, 11).unwrap();
    service.set_holding_register(1, 22).unwrap();

    let server = ModbusTcpServer::bind("127.0.0.1:0", std::sync::Arc::clone(&service))
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let link = ModbusTcpTransport::connect(addr).await.unwrap();
    let client = ModbusClient::new(link);

    let initial = client.read_holding_registers(1, 0, 2).await.unwrap();
    assert_eq!(initial, vec![11, 22]);

    client.write_single_register(1, 1, 42).await.unwrap();
    assert_eq!(service.holding_register(1), Some(42));

    client
        .write_multiple_coils(1, 10, &[true, false, true, true])
        .await
        .unwrap();
    let coils = client.read_coils(1, 10, 4).await.unwrap();
    assert_eq!(coils, vec![true, false, true, true]);

    client
        .mask_write_register(1, 1, 0xFF00, 0x0012)
        .await
        .unwrap();
    let masked = client.read_holding_registers(1, 1, 1).await.unwrap();
    assert_eq!(masked, vec![0x0012]);

    let rw = client
        .read_write_multiple_registers(1, 0, 2, 0, &[0x7777, 0x8888])
        .await
        .unwrap();
    assert_eq!(rw, vec![0x7777, 0x8888]);

    let report = client.report_server_id(1).await.unwrap();
    assert_eq!(report.server_id, 1);
    assert!(report.run_indicator_status);
    assert!(report.additional_data.is_empty());

    let device_id = client.read_device_identification(1, 0x01, 0x00).await.unwrap();
    assert_eq!(device_id.read_device_id_code, 0x01);
    assert_eq!(device_id.objects.len(), 3);

    server_task.abort();
    let _ = server_task.await;
}
