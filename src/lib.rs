//! Mythic C2 4.0 plaintext protocol library.
//!
//! Pure protocol structures and wire encoding for unencrypted checkin,
//! get_tasking and post_response. Designed as a `no_std` + `alloc` library
//! suitable for freestanding agent environments.
//!
//! ## Serialization features
//!
//! - `json` (default): body is JSON. Wire = `Base64(UUID + JSON)`.
//! - `raw`: body is a compact length-prefixed binary format that uses
//!   `zerocopy` for fixed headers. Wire = `Base64(UUID + raw)`.
//!
//! Action strings are compile-time obfuscated. Error text appears only in
//! debug builds.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

#[doc(hidden)]
pub use obfstr as libobfstr;

#[macro_use]
mod macros;

pub mod error;
pub mod types;
pub mod wire;

pub use error::{Error, Result};
pub use types::*;

#[cfg(feature = "json")]
pub use wire::{decode_plaintext, encode_plaintext};

#[cfg(feature = "raw")]
pub use wire::{
    raw_decode_checkin, raw_decode_checkin_resp, raw_decode_get_tasking, raw_decode_post_response,
    raw_encode_checkin, raw_encode_checkin_resp, raw_encode_get_tasking, raw_encode_post_response,
};
