use clap::Parser;
use rustmod_tools::common::{TcpConnectionArgs, build_client, init_tracing, parse_bool};

#[derive(Debug, Parser)]
#[command(name = "writecoil", about = "Write a single coil (FC05)")]
struct Args {
    #[command(flatten)]
    conn: TcpConnectionArgs,
    #[arg(long, default_value_t = 1)]
    unit_id: u8,
    #[arg(long)]
    address: u16,
    #[arg(long, value_parser = parse_bool)]
    value: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let args = Args::parse();
    let client = build_client(&args.conn).await?;

    client
        .write_single_coil(args.unit_id, args.address, args.value)
        .await?;

    println!("wrote coil {} => {}", args.address, args.value);
    Ok(())
}
