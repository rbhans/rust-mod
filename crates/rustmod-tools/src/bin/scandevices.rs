use clap::Parser;
use rustmod_tools::common::{TcpConnectionArgs, build_client, init_tracing};

#[derive(Debug, Parser)]
#[command(name = "scandevices", about = "Scan Modbus unit IDs over TCP")]
struct Args {
    #[command(flatten)]
    conn: TcpConnectionArgs,
    #[arg(long, default_value_t = 1)]
    unit_start: u8,
    #[arg(long, default_value_t = 247)]
    unit_end: u8,
    #[arg(long, default_value_t = 0)]
    probe_start: u16,
    #[arg(long, default_value_t = 1)]
    probe_quantity: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let args = Args::parse();

    if args.unit_start == 0 || args.unit_start > args.unit_end {
        return Err("invalid unit id range".into());
    }

    let client = build_client(&args.conn).await?;
    let mut found = Vec::new();

    for unit_id in args.unit_start..=args.unit_end {
        let result = client
            .read_holding_registers(unit_id, args.probe_start, args.probe_quantity)
            .await;

        if result.is_ok() {
            println!("unit {} responded", unit_id);
            found.push(unit_id);
        }
    }

    if found.is_empty() {
        println!("no responding units found");
    } else {
        println!("found {} unit(s): {:?}", found.len(), found);
    }

    Ok(())
}
