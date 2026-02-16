use rustmod_datalink::{DataLink, InMemoryModbusService, ModbusTcpServer, ModbusTcpTransport};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = std::sync::Arc::new(InMemoryModbusService::new(64, 64, 64, 64));
    service.set_holding_register(0, 1234)?;

    let server = ModbusTcpServer::bind("127.0.0.1:0", std::sync::Arc::clone(&service)).await?;
    let addr = server.local_addr()?;
    let server_task = tokio::spawn(server.run());

    let client = ModbusTcpTransport::connect(addr).await?;
    let mut response = [0u8; 260];
    let len = client
        .exchange(1, &[0x03, 0x00, 0x00, 0x00, 0x01], &mut response)
        .await?;

    println!("response pdu: {:02X?}", &response[..len]);

    server_task.abort();
    let _ = server_task.await;
    Ok(())
}
