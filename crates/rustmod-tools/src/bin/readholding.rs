use clap::Parser;
use rustmod_tools::common::{TcpConnectionArgs, build_client, init_tracing};

#[derive(Debug, Parser)]
#[command(name = "readholding", about = "Read holding registers (FC03)")]
struct Args {
    #[command(flatten)]
    conn: TcpConnectionArgs,
    #[arg(long, default_value_t = 1)]
    unit_id: u8,
    #[arg(long)]
    start: u16,
    #[arg(long)]
    quantity: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let args = Args::parse();
    let client = build_client(&args.conn).await?;

    let values = client
        .read_holding_registers(args.unit_id, args.start, args.quantity)
        .await?;

    for (idx, value) in values.iter().enumerate() {
        println!("addr={} value={} (0x{:04X})", args.start + idx as u16, value, value);
    }
    Ok(())
}
