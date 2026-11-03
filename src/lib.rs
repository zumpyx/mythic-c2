//! Mythic C2 4.0 plaintext protocol library.
//!
//! Focuses exclusively on unencrypted (plaintext) checkin, get_tasking and
//! post_response message structures and Base64(UUID + JSON) wire format.
//!
//! Error messages and debug strings are only present in debug builds.
//! Protocol action strings are obfuscated at compile time via `obfstr`.

#![deny(unsafe_code)]

#[doc(hidden)]
pub use obfstr as libobfstr;

#[macro_use]
mod macros;

pub mod error;
pub mod types;
pub mod wire;

pub use error::{Error, Result};
pub use types::*;
pub use wire::{decode_plaintext, encode_plaintext};
