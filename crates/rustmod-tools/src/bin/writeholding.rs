use clap::Parser;
use rustmod_client::UnitId;
use rustmod_tools::common::{TcpConnectionArgs, build_client, init_tracing};

#[derive(Debug, Parser)]
#[command(
    name = "writeholding",
    about = "Write one or more holding registers (FC06/FC16)"
)]
struct Args {
    #[command(flatten)]
    conn: TcpConnectionArgs,
    #[arg(long, default_value_t = 1)]
    unit_id: u8,
    #[arg(long)]
    start: u16,
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    values: Vec<u16>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let args = Args::parse();
    let client = build_client(&args.conn).await?;

    if args.values.len() == 1 {
        client
            .write_single_register(UnitId::new(args.unit_id), args.start, args.values[0])
            .await?;
    } else {
        client
            .write_multiple_registers(UnitId::new(args.unit_id), args.start, &args.values)
            .await?;
    }

    println!(
        "wrote {} register(s) starting at {}",
        args.values.len(),
        args.start
    );
    Ok(())
}
