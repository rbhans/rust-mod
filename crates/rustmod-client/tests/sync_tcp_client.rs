use rustmod_client::SyncModbusTcpClient;
use rustmod_datalink::{InMemoryModbusService, ModbusTcpServer};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;
use tokio::sync::oneshot;

#[test]
fn sync_client_can_interact_with_simulator() {
    let (addr_tx, addr_rx) = mpsc::channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let server_thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime should build");

        runtime.block_on(async move {
            let service = Arc::new(InMemoryModbusService::new(64, 64, 64, 64));
            service
                .set_holding_register(0, 100)
                .expect("fixture register set should succeed");

            let server = ModbusTcpServer::bind("127.0.0.1:0", Arc::clone(&service))
                .await
                .expect("server should bind");
            addr_tx
                .send(server.local_addr().expect("local addr should be available"))
                .expect("address should be sent");

            let task = tokio::spawn(server.run());
            let _ = shutdown_rx.await;
            task.abort();
            let _ = task.await;
        });
    });

    let addr = addr_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("server address should arrive");

    let client =
        SyncModbusTcpClient::connect(&addr.to_string()).expect("sync client should connect");

    let before = client
        .read_holding_registers(1, 0, 1)
        .expect("read should succeed");
    assert_eq!(before, vec![100]);

    client
        .write_single_register(1, 0, 1234)
        .expect("write should succeed");
    let after = client
        .read_holding_registers(1, 0, 1)
        .expect("read after write should succeed");
    assert_eq!(after, vec![1234]);

    client
        .mask_write_register(1, 0, 0xFF00, 0x002A)
        .expect("mask write should succeed");
    let masked = client
        .read_holding_registers(1, 0, 1)
        .expect("masked read should succeed");
    assert_eq!(masked, vec![0x042A]);

    let rw = client
        .read_write_multiple_registers(1, 0, 1, 0, &[0xBEEF])
        .expect("read-write registers should succeed");
    assert_eq!(rw, vec![0xBEEF]);

    let report = client
        .report_server_id(1)
        .expect("report server id should succeed");
    assert_eq!(report.server_id, 1);
    assert!(report.run_indicator_status);

    let device_id = client
        .read_device_identification(1, 0x01, 0x00)
        .expect("read device identification should succeed");
    assert_eq!(device_id.read_device_id_code, 0x01);
    assert_eq!(device_id.objects.len(), 3);

    shutdown_tx.send(()).expect("shutdown signal should be sent");
    server_thread.join().expect("server thread should join");
}
