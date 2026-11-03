//! Mythic C2 4.0 plaintext protocol library.
//!
//! Pure protocol structures and wire encoding for unencrypted checkin,
//! get_tasking and post_response. Designed as a `no_std` + `alloc` library
//! suitable for freestanding agent environments.
//!
//! Wire format is always `Base64(UUID(36 ASCII chars) + JSON)`.
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
pub use wire::{decode_plaintext, encode_plaintext, encode_plaintext_urlsafe};
