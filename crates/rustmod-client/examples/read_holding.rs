use rustmod_client::ModbusClient;
use rustmod_datalink::ModbusTcpTransport;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let transport = ModbusTcpTransport::connect("127.0.0.1:502").await?;
    let client = ModbusClient::new(transport);

    let values = client.read_holding_registers(1, 0, 4).await?;
    println!("holding registers: {values:?}");
    Ok(())
}
