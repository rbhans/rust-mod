use clap::Args;
use rustmod_client::{ClientConfig, ModbusClient};
use rustmod_datalink::{DataLinkError, ModbusTcpTransport};
use std::time::Duration;

#[derive(Debug, Clone, Args)]
pub struct TcpConnectionArgs {
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,
    #[arg(long, default_value_t = 502)]
    pub port: u16,
    #[arg(long, default_value_t = 5000)]
    pub timeout: u64,
    #[arg(long, default_value_t = 1)]
    pub retries: u8,
}

pub async fn build_client(
    args: &TcpConnectionArgs,
) -> Result<ModbusClient<ModbusTcpTransport>, DataLinkError> {
    let addr = format!("{}:{}", args.host, args.port);
    let transport = ModbusTcpTransport::connect(addr).await?;

    let config = ClientConfig::default()
        .with_response_timeout(Duration::from_millis(args.timeout))
        .with_retry_count(args.retries);

    Ok(ModbusClient::with_config(transport, config))
}

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .try_init();
}

pub fn parse_bool(input: &str) -> Result<bool, String> {
    match input.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" => Ok(true),
        "0" | "false" | "off" | "no" => Ok(false),
        _ => Err(format!("invalid bool value: {input}")),
    }
}
