# TODO

## High Priority
- [x] Simulator integration baseline: first-class server-side support for in-process Modbus simulation (request decode + TCP server handler) so BACnet/Modbus simulator apps can host virtual devices directly.
- [x] Simulator integration polish: add reusable point-model helpers and BACnet+Modbus combined simulator examples.
- [x] Implement Modbus RTU transport in `rustmod-datalink` (tokio-serial based) under the same `DataLink::exchange` contract.
- [x] Implement native Modbus RTU serial server in `rustmod-datalink` for simulator and device-emulation deployments.
- [x] Add integration tests against a Modbus simulator fixture for both client and server paths.

## Medium Priority
- [x] Add request/response tracing hooks with stable correlation IDs for simulator event timelines.
- [x] Add feature-gated metrics counters (requests, exceptions, timeouts, retries).
- [x] Add richer point helpers for coils/register maps in simulator use cases.
- [x] Add typed FC22/FC23 support across core, client, and simulator service paths.
- [x] Add typed FC43/MEI 0x0E read-device-identification client API and simulator coverage.

## Release Prep
- [x] Add crate-level examples per crate.
- [x] Add `CHANGELOG.md`.
- [x] Add CI workflow for `check`, `test`, `clippy`, and `no-default-features` core validation.
- [x] Align feature scope with `tokio-modbus` baseline for common client/server flows (TCP, RTU, RTU-over-TCP, sync facade, custom passthrough).
