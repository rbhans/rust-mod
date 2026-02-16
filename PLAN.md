# Plan
## Summary
Build a four-crate Modbus workspace that mirrors rust-bac design principles while avoiding early over-scoping. Prioritize a strong `rustmod-core` first (no_std-compatible, zero-copy decode, strict protocol invariants, golden tests), then layer a coherent async datalink and client, then ship TCP-first CLI tools.

The corrected plan explicitly resolves prior contradictions:
- `rustmod-core` is **no_std-compatible** with `std` + `alloc` enabled by default.
- Datalink uses a **single request/response contract** (no conflicting `send`/`recv` + tx-id API).
- Protocol limit checks are first-class acceptance criteria.
- Reconnect behavior is defined through transport factory/reconnector boundaries, not assumed.

## Scope
In scope:
- Workspace scaffold for:
  - `crates/rustmod-core`
  - `crates/rustmod-datalink`
  - `crates/rustmod-client`
  - `crates/rustmod-tools`
- `rustmod-core`:
  - Error types (no `thiserror`)
  - Encoding primitives (`Reader`, `Writer`)
  - PDU types for FC01/02/03/04/05/06/15/16
  - Exception response parsing/encoding strategy (known + unknown codes)
  - TCP MBAP framing
  - RTU framing + CRC16
  - Unit tests, golden packet tests, property tests
- `rustmod-datalink`:
  - Async trait with coherent request/response behavior
  - TCP transport (v1 required)
  - RTU transport (v1 optional, phase-gated)
- `rustmod-client`:
  - Timeout/retry handling
  - Exception propagation
  - Minimal reconnect strategy tied to explicit abstraction
- `rustmod-tools`:
  - TCP-first binaries for core reads/writes and device scan

Out of scope (v1):
- Full telemetry/point quality subsystem
- Complex scheduler/poll engine
- Aggressive TCP multiplexing before trait and test coverage justify it
- Non-core function code expansion beyond FC01/02/03/04/05/06/15/16

## Assumptions
- Rust toolchain target is `rust-version = 1.75`, `edition = 2021`.
- `rustmod-core` feature model follows rust-bac style:
  - `default = ["std", "alloc"]`
  - `--no-default-features` must compile.
- `rustmod-core` remains allocator-free unless `alloc` APIs are explicitly enabled.
- CLI v1 is TCP-first; RTU CLI flags are added only if RTU transport lands in scope for v1.
- Unknown function/exception values are handled without panics and surfaced as typed errors.

## Milestones
### M1: Workspace And Core Skeleton
Acceptance:
- Root `Cargo.toml` workspace members configured.
- Four crates exist with minimal compilable `lib.rs`/bins.
- `cargo check --workspace` passes.

### M2: Core Foundation (`rustmod-core`)
Acceptance:
- `error.rs` complete with manual `Display`, optional `std::error::Error`.
- `encoding/reader.rs` and `encoding/writer.rs` implemented and tested.
- `cargo check -p rustmod-core --no-default-features` passes.

### M3: PDU Codec + Validation Rules
Acceptance:
- Request and response types implemented for FC01/02/03/04/05/06/15/16.
- Explicit request validation implemented:
  - Read Coils/Discrete Inputs quantity: `1..=2000`
  - Read Holding/Input Registers quantity: `1..=125`
  - Write Multiple Coils quantity: `1..=1968`
  - Write Multiple Registers quantity: `1..=123`
  - Byte count fields match quantity-derived expected lengths
  - Coil ON/OFF encoding strictly `0xFF00` / `0x0000`
- Exception response decoding supports known constants and unknown raw values.

### M4: Frame Layer + Golden Coverage
Acceptance:
- MBAP header encode/decode with protocol ID and length checks.
- RTU encode/decode with CRC16 known vectors and tamper detection.
- Golden integration tests pass for canonical FC03 and exception cases.
- Property tests verify no panics and basic codec roundtrip invariants.

### M5: Datalink MVP (Coherent API)
Acceptance:
- Datalink contract finalized as request/response call (example shape):
  - `exchange(unit_id, request_pdu, response_buf) -> Result<response_len, DataLinkError>`
- TCP transport implemented and tested against frame decoding boundaries.
- If RTU is included in v1, RTU transport lands behind clear feature/module gate.
- Dependency alignment complete (`tokio`, `tracing`, `async-trait` if used, `thiserror` in non-core only).

### M6: Client MVP
Acceptance:
- High-level methods for core read/write operations implemented.
- Timeout + retry behavior covered by tests.
- Exception responses mapped to `ClientError::Exception`.
- Reconnect semantics explicit and testable (factory/reconnector-based, not implicit generic magic).

### M7: Tools MVP
Acceptance:
- TCP CLI binaries implemented for read/write/scan basics.
- Shared CLI args (`--host`, `--port`, `--unit-id`, `--timeout`) wired consistently.
- End-to-end smoke run documented for at least one read and one write path.

## Deliverables
- `Cargo.toml` (workspace root)
- `crates/rustmod-core/*` complete for v1 core functionality and tests
- `crates/rustmod-datalink/*` with coherent trait and TCP transport
- `crates/rustmod-client/*` with stable high-level API and retry/timeout behavior
- `crates/rustmod-tools/src/bin/*` TCP-first operational binaries
- CI-quality checks documented and runnable:
  - `cargo check --workspace`
  - `cargo test -p rustmod-core`
  - `cargo check -p rustmod-core --no-default-features`
  - `cargo clippy --workspace`

## Risks And Mitigations
- Trait/API mismatch risk:
  - Mitigation: freeze datalink API before transport/client implementation; add compile-time contract tests.
- Protocol invariant drift risk:
  - Mitigation: centralized validators + table-driven tests for all quantity/byte-count limits.
- Reconnect ambiguity risk:
  - Mitigation: define reconnect as explicit dependency (`Connector`/factory) rather than hidden requirement on `D: DataLink`.
- RTU timing complexity risk:
  - Mitigation: phase-gate RTU in v1, keep TCP-first delivery guaranteed.
- Over-scoping risk:
  - Mitigation: ship milestone-gated MVP first; defer pipelined multiplexing and advanced observability.

## Dependencies
Core:
- Optional: `serde`, `defmt`
- Dev: `proptest`

Datalink:
- `rustmod-core`
- `tokio` (`net`, `io`, `time`, `sync`)
- `tracing`
- `tokio-serial` (if RTU enabled)
- `async-trait` (only if trait style requires it)
- `thiserror`

Client:
- `rustmod-core`
- `rustmod-datalink`
- `tokio`
- `tracing`
- `thiserror`

Tools:
- `rustmod-client`
- `rustmod-datalink`
- `clap` (derive)
- `tokio`
- `tracing-subscriber`

## Open Questions
- Should RTU transport be mandatory in v1 or explicitly post-MVP?
- Do we want unknown function/exception codes represented as `Unknown(u8)` enums or decode errors only?
- Is TCP pipelining needed for v1, or should we keep strictly serialized requests until benchmark pressure appears?
- Should tools expose RTU flags in v1 or only after RTU transport is stable?

## Next Actions
1. Implement M1 scaffold and verify `cargo check --workspace`.
2. Implement `rustmod-core` errors + encoding primitives (M2).
3. Add PDU request/response with explicit validation rules (M3).
4. Add frame layer and golden/property tests (M4).
5. Freeze datalink API in code comments/docs before transport implementation (M5 gate).
