# rust-mod

A modern, safe Rust Modbus library for building automation and industrial integrations.

## Crate Structure

`rust-mod` is organized as a workspace of focused crates:

| Crate | Description |
|-------|-------------|
| `rustmod-core` | `no_std`-compatible protocol codec (PDU encoding/decoding, TCP MBAP and RTU CRC framing) |
| `rustmod-datalink` | Async transport abstraction, TCP/RTU transports, TCP and RTU servers, in-memory simulator |
| `rustmod-client` | High-level async client with retries, timeouts, throttling, and metrics |
| `rustmod-tools` | CLI binaries for quick Modbus operations |

## Supported Function Codes

| FC | Name | Client Method |
|----|------|---------------|
| 01 | Read Coils | `read_coils` / `read_coils_raw` |
| 02 | Read Discrete Inputs | `read_discrete_inputs` / `read_discrete_inputs_raw` |
| 03 | Read Holding Registers | `read_holding_registers` |
| 04 | Read Input Registers | `read_input_registers` |
| 05 | Write Single Coil | `write_single_coil` |
| 06 | Write Single Register | `write_single_register` |
| 07 | Read Exception Status | `read_exception_status` |
| 08 | Diagnostics | `diagnostics` |
| 15 | Write Multiple Coils | `write_multiple_coils` |
| 16 | Write Multiple Registers | `write_multiple_registers` |
| 17 | Report Server ID | `report_server_id` |
| 22 | Mask Write Register | `mask_write_register` |
| 23 | Read/Write Multiple Registers | `read_write_multiple_registers` |
| 24 | Read FIFO Queue | `read_fifo_queue` |
| 43 | Read Device Identification (MEI 0x0E) | `read_device_identification` |
| — | Custom/vendor function codes | `custom_request` |

## Features

- **Zero-copy codec** — `rustmod-core` decodes PDUs by borrowing from the input buffer with no heap allocation
- **`no_std` support** — `rustmod-core` works without `std` or `alloc` for embedded use
- **Async and sync clients** — `ModbusClient` for async workflows, `SyncModbusTcpClient` for blocking
- **Resilient by default** — configurable timeouts, retries (read-only safe by default), inter-request throttling, and automatic reconnection
- **TCP and RTU transports** — TCP built-in, RTU serial via optional `rtu` feature
- **Server support** — TCP server, RTU-over-TCP server, and optional native RTU serial server for simulator/virtual-device hosting
- **Connection limits** — servers support configurable max concurrent connections
- **Graceful shutdown** — `run_until()` accepts a shutdown future for clean server teardown
- **In-memory simulator** — `InMemoryModbusService` with a point model for testing without hardware
- **Metrics** — optional feature-gated request/response counters and error tracking
- **Tracing** — correlated `tracing` spans for each request/response cycle
- **Clonable clients** — `ModbusClient` is `Clone` for sharing across tasks
- **Fully documented** — every public type and method has rustdoc comments

## Quick Start

Build everything:

```bash
cargo build --workspace
```

### Library Usage

```rust
use rustmod_client::ModbusClient;
use rustmod_datalink::ModbusTcpTransport;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let link = ModbusTcpTransport::connect("127.0.0.1:502").await?;
    let client = ModbusClient::new(link);

    let regs = client.read_holding_registers(1, 0x006B, 3).await?;
    println!("registers: {regs:?}");
    Ok(())
}
```

### CLI Tools

Read holding registers:

```bash
cargo run -p rustmod-tools --bin readholding -- \
  --host 127.0.0.1 --port 502 --unit-id 1 --start 107 --quantity 3
```

Write registers (FC06 for single, FC16 for multiple):

```bash
cargo run -p rustmod-tools --bin writeholding -- \
  --host 127.0.0.1 --port 502 --unit-id 1 --start 10 --values 42,43,44
```

Scan for responding unit IDs:

```bash
cargo run -p rustmod-tools --bin scandevices -- \
  --host 127.0.0.1 --port 502 --unit-start 1 --unit-end 20 --timeout 300
```

Available binaries: `readholding`, `readinput`, `readcoils`, `writeholding`, `writecoil`, `scandevices`

## Validation

```bash
cargo check --workspace --all-features
cargo test --workspace --all-features
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo doc --workspace --no-deps
cargo check -p rustmod-core --no-default-features   # verify no_std
```

## License

See [LICENSE](LICENSE) for details.
