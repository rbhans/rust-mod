# rust-mod

A modern Rust Modbus workspace for building automation and industrial integrations.

`rust-mod` is organized as a crate family:

- `rustmod-core`: `no_std`-compatible protocol codec layer (PDU + TCP/RTU framing)
- `rustmod-datalink`: async transport abstraction + TCP transport implementation
- `rustmod-client`: high-level resilient async client API
- `rustmod-tools`: CLI tools built on top of the client

## Current Status

Implemented and validated:

- Core Modbus function codes: FC01, FC02, FC03, FC04, FC05, FC06, FC15, FC16, FC22, FC23
- Custom function-code pass-through support for vendor extensions
- FC17 (`Report Server ID`) support via client API + simulator service
- FC43/MEI 0x0E (`Read Device Identification`) typed client API + simulator support
- Exception response decoding (including unknown exception codes)
- TCP MBAP framing and RTU CRC/frame codec in `rustmod-core`
- Async `DataLink::exchange` contract in `rustmod-datalink`
- Production-usable TCP transport (`ModbusTcpTransport`)
- Optional RTU serial transport (`ModbusRtuTransport`, `rtu` feature)
- Optional native RTU serial server (`ModbusRtuServer`, `rtu` feature)
- RTU-over-TCP server support (`ModbusRtuOverTcpServer`)
- In-memory simulator service and point-model helpers for virtual device hosting
- Simulator fixture integration tests for both client and datalink paths
- Correlated tracing hooks and feature-gated metrics counters
- Resilient client with timeout/retry/throttle controls
- Blocking sync TCP facade (`SyncModbusTcpClient`) for non-async applications
- Safe retry defaults (`RetryPolicy::ReadOnly`) to avoid duplicate writes after ambiguous failures
- CLI binaries:
  - `readholding`
  - `readinput`
  - `readcoils`
  - `writeholding`
  - `writecoil`
  - `scandevices`

## Workspace Validation

All of the following pass:

- `cargo check --workspace`
- `cargo test --workspace`
- `cargo check --workspace --all-features`
- `cargo test --workspace --all-features`
- `cargo clippy --workspace --all-features --all-targets -- -D warnings`
- `cargo check -p rustmod-core --no-default-features`
- `cargo test -p rustmod-core --no-default-features`
- `cargo clippy --workspace --all-targets -- -D warnings`

## Quick Start

Build everything:

```bash
cargo build --workspace
```

Read holding registers from a TCP device:

```bash
cargo run -p rustmod-tools --bin readholding -- \
  --host 127.0.0.1 --port 502 --unit-id 1 --start 107 --quantity 3
```

Write holding register(s):

```bash
# single register (FC06)
cargo run -p rustmod-tools --bin writeholding -- \
  --host 127.0.0.1 --port 502 --unit-id 1 --start 10 --values 42

# multiple registers (FC16)
cargo run -p rustmod-tools --bin writeholding -- \
  --host 127.0.0.1 --port 502 --unit-id 1 --start 10 --values 42,43,44
```

Scan unit IDs:

```bash
cargo run -p rustmod-tools --bin scandevices -- \
  --host 127.0.0.1 --port 502 --unit-start 1 --unit-end 20 --timeout 300
```

## Library Example

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

## Notes

- `rustmod-core` is `no_std`-compatible with `std` + `alloc` enabled by default.
- `rustmod-datalink` supports TCP, optional RTU client transport, optional RTU serial server, and RTU-over-TCP server.
- The simulator components in `rustmod-datalink::sim` are designed for BACnet+Modbus app simulation workflows and virtual device hosting.
- Unknown Modbus exception codes are preserved as `ExceptionCode::Unknown(u8)`.
- `ModbusClient::custom_request` provides a compatibility path for vendor/private function codes.
- `ModbusClient::report_server_id` (FC17) is available for device identity/status polling.
- `ModbusClient::read_device_identification` supports typed FC43/MEI 0x0E reads.
- `ModbusClient` includes typed helpers for FC22 (`mask_write_register`) and FC23 (`read_write_multiple_registers`).
- `SyncModbusTcpClient` provides a blocking API over the same high-level operations.

## Parity Snapshot

Relative to `tokio-modbus` (0.17.x), `rust-mod` now has comparable support for:

- Async TCP client operations
- Blocking TCP client facade
- Optional async RTU client transport
- TCP server path suitable for simulator/virtual-device hosting
- Optional RTU serial server path
- RTU-over-TCP server path
- Custom function-code interoperability
- FC17 Report Server ID access
- FC22/FC23 typed operations
- Typed FC43/MEI 0x0E Read Device Identification client support

Still intentionally not at parity:
- Blocking sync RTU facade equivalent to `tokio-modbus` `rtu-sync`
- Typed wrappers for some less-common/public function families (can still be used via `custom_request`)
