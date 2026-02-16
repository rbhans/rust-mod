use clap::Parser;
use rustmod_tools::common::{TcpConnectionArgs, build_client, init_tracing};

#[derive(Debug, Parser)]
#[command(name = "readcoils", about = "Read coils (FC01)")]
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
        .read_coils(args.unit_id, args.start, args.quantity)
        .await?;

    for (idx, value) in values.iter().enumerate() {
        println!("coil={} value={}", args.start + idx as u16, value);
    }
    Ok(())
}
