//! Modbus protocol encoding and framing in pure Rust.
//!
//! `rustmod-core` provides zero-copy, `no_std`-compatible encoding and decoding
//! of Modbus PDUs and TCP/RTU frames.

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
