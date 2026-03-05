//! Command-line utilities for Modbus device interaction.
//!
//! This crate provides ready-to-use binaries for reading registers and coils,
//! writing values, and scanning for devices on a Modbus network.
//!
//! Available binaries:
//!
//! - `readholding` — Read holding registers (FC03)
//! - `readinput` — Read input registers (FC04)
//! - `readcoils` — Read coils (FC01)
//! - `writecoil` — Write a single coil (FC05)
//! - `writeholding` — Write one or more holding registers (FC06/FC16)
//! - `scandevices` — Scan a range of unit IDs for responding devices

#![forbid(unsafe_code)]

pub mod common;
