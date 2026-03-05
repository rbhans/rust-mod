//! Modbus protocol encoding and framing in pure Rust.
//!
//! `rustmod-core` provides zero-copy, `no_std`-compatible encoding and decoding
//! of Modbus PDUs and TCP/RTU frames.
//!
//! # Supported Function Codes
//!
//! - FC01 Read Coils
//! - FC02 Read Discrete Inputs
//! - FC03 Read Holding Registers
//! - FC04 Read Input Registers
//! - FC05 Write Single Coil
//! - FC06 Write Single Register
//! - FC07 Read Exception Status
//! - FC08 Diagnostics
//! - FC15 Write Multiple Coils
//! - FC16 Write Multiple Registers
//! - FC22 Mask Write Register
//! - FC23 Read/Write Multiple Registers
//! - FC24 Read FIFO Queue
//! - Custom function codes via `FunctionCode::Custom`
//!
//! # Design
//!
//! All encoding uses caller-owned `&mut [u8]` buffers via [`encoding::Writer`],
//! and all decoding uses zero-copy [`encoding::Reader`] over `&[u8]` slices.
//! No heap allocation is required (the `alloc` feature adds owned request types
//! for convenience).

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod encoding;
pub mod error;
pub mod frame;
pub mod pdu;

pub use error::{DecodeError, EncodeError};

/// A Modbus unit identifier (station address).
///
/// Valid addresses are 0–247, where 0 is the broadcast address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnitId(u8);

impl UnitId {
    /// The broadcast address (0). Write requests sent to this address are
    /// processed by all devices on the bus; no response is returned.
    pub const BROADCAST: Self = Self(0);

    /// The minimum valid unicast address (1).
    pub const MIN: Self = Self(1);

    /// The maximum valid unicast address (247).
    pub const MAX: Self = Self(247);

    /// Create a `UnitId` from a raw `u8` value.
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Return the raw `u8` value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

impl From<u8> for UnitId {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<UnitId> for u8 {
    fn from(unit_id: UnitId) -> Self {
        unit_id.0
    }
}

impl core::fmt::Display for UnitId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}
