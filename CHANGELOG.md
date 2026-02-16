# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic Versioning.

## [Unreleased]

### Added
- `rustmod-datalink` in-memory simulator support:
  - `InMemoryPointModel`
  - `CoilBank`
  - `RegisterBank`
  - `InMemoryModbusService`
- Optional RTU serial transport in `rustmod-datalink` (`rtu` feature) via `tokio-serial`.
- TCP server request decoding and service dispatch for in-process virtual Modbus devices.
- Integration tests using simulator fixtures for:
  - `rustmod-client`
  - `rustmod-datalink`
- Request/response tracing with stable correlation IDs in client and server paths.
- Feature-gated metrics counters:
  - client requests/retries/timeouts/exceptions
  - server requests/exceptions/timeouts
- Point helper types in `rustmod-client`:
  - `CoilPoints`
  - `RegisterPoints`
- Crate-level examples:
  - `crates/rustmod-core/examples/pdu_roundtrip.rs`
  - `crates/rustmod-datalink/examples/in_memory_simulator.rs`
  - `crates/rustmod-datalink/examples/bacnet_modbus_combined_simulator.rs`
  - `crates/rustmod-client/examples/read_holding.rs`
  - `crates/rustmod-tools/examples/common_helpers.rs`
- CI workflow for:
  - `cargo check --workspace`
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo check -p rustmod-core --no-default-features`
  - `cargo check --workspace --all-features`
  - `cargo test --workspace --all-features`
- Custom function-code support in core PDU types:
  - `FunctionCode::Custom(u8)`
  - `Request::Custom`
  - `DecodedRequest::Custom`
  - `Response::Custom`
- `rustmod-client` APIs:
  - `custom_request(unit_id, function_code, payload)`
  - `report_server_id(unit_id)` (FC17)
- Simulator support for FC17 (`Report Server ID`) in `InMemoryModbusService`.
- RTU suffix-frame decoding tests for leading-noise and partial-frame scenarios.
- Blocking sync client facade:
  - `SyncModbusTcpClient`
  - `SyncClientError`
  - sync integration test coverage
- RTU-over-TCP server:
  - `ModbusRtuOverTcpServer`
  - RTU-over-TCP request/exception test coverage
- FC22/FC23 typed protocol support:
  - `FunctionCode::{MaskWriteRegister, ReadWriteMultipleRegisters}`
  - `Request`/`DecodedRequest` variants and codec coverage
  - `Response` variants and codec coverage
  - `ModbusClient::{mask_write_register, read_write_multiple_registers}`
  - sync client wrappers and simulator fixture coverage
- Native RTU serial server in `rustmod-datalink` (`rtu` feature):
  - `ModbusRtuServer`
  - `ModbusRtuServerConfig`
  - request/exception RTU server unit coverage
- FC43/MEI 0x0E (`Read Device Identification`) support:
  - `ModbusClient::read_device_identification`
  - `SyncModbusTcpClient::read_device_identification`
  - simulator service response handling for custom FC43 requests

### Changed
- `rustmod-client` retry behavior now supports policy configuration via `RetryPolicy`:
  - `ReadOnly` (default)
  - `All`
  - `Never`

### Fixed
- Prevented silent false-value filling for truncated FC01/FC02 bit responses.
- Prevented default retries of write requests to reduce duplicate-write risk after ambiguous failures.
- Improved RTU stream resynchronization behavior when leading noise/misaligned bytes are present.
- Fixed sync client integration test harness to avoid runtime blocking deadlock.
- Corrected FC22 mask-write expectations in simulator/client integration tests to match Modbus mask semantics.
