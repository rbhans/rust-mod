use rustmod_core::encoding::Reader;
use rustmod_core::pdu::Response;
use rustmod_datalink::{DataLink, InMemoryModbusService, ModbusTcpServer, ModbusTcpTransport};

#[derive(Debug, Default)]
struct BacnetSimulatorState {
    analog_value_1: f32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bacnet = BacnetSimulatorState { analog_value_1: 42.5 };

    // Bridge BACnet simulation state into Modbus holding register view.
    let service = std::sync::Arc::new(InMemoryModbusService::new(64, 64, 64, 64));
    service.set_holding_register(0, (bacnet.analog_value_1 * 10.0) as u16)?;

    let server = ModbusTcpServer::bind("127.0.0.1:0", std::sync::Arc::clone(&service)).await?;
    let addr = server.local_addr()?;
    let server_task = tokio::spawn(server.run());

    let transport = ModbusTcpTransport::connect(addr).await?;
    let mut response = [0u8; 260];
    let len = transport
        .exchange(1, &[0x03, 0x00, 0x00, 0x00, 0x01], &mut response)
        .await?;

    let mut reader = Reader::new(&response[..len]);
    if let Response::ReadHoldingRegisters(resp) = Response::decode(&mut reader)? {
        let raw = resp.register(0).unwrap_or_default();
        bacnet.analog_value_1 = raw as f32 / 10.0;
    }

    println!("combined simulator state: {:?}", bacnet);

    server_task.abort();
    let _ = server_task.await;
    Ok(())
}
