#![cfg_attr(not(test), no_std)]
// #![no_std]

//! `ctap-types` maps the various types involved in the FIDO CTAP protocol
//! to Rust structures consisting of `heapless` data types.
//!
//! We currently follow the non-public editor's draft dated 19 March 2019.
//! It still uses `FIDO_2_1_PRE` to signal new commands, but uses non-vendor
//! API numbering (e.g. 0xA for credential management).
//!
//! It also contains a lightweight CBOR deserializer, as the existing `serde_cbor`
//! creates very large code.
//!
//! The various transport protocols (USB, NFC, BLE) are expected to handle
//! low-level protocol details and deserialize requests / serialize responses,
//! so the authenticator logic is decoupled from these details.

#[macro_use]
extern crate delog;
generate_macros!();

pub use heapless;
pub use heapless::{String, Vec};
pub use heapless_bytes;
pub use heapless_bytes::Bytes;
pub use serde_bytes::ByteArray;

pub mod authenticator;
pub mod ctap1;
pub mod ctap2;
pub(crate) mod operation;
pub use cbor_smol as serde;
pub mod sizes;
pub mod webauthn;

pub use ctap2::{Error, Result};

use core::fmt::{self, Display, Formatter};

/// An error returned by the `TryFrom<&str>` implementation for enums if an invalid value is
/// provided.
#[derive(Debug)]
pub struct TryFromStrError;

impl Display for TryFromStrError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        "invalid enum value".fmt(f)
    }
}

#[cfg(test)]
mod tests {}

/// Call a remote procedure with a request, receive a response, maybe.
pub trait Rpc<Error, Request, Response> {
    fn call(&mut self, request: &Request) -> core::result::Result<Response, Error>;
}
