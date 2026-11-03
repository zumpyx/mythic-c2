//! Mythic C2 4.0 plaintext protocol library.
//!
//! Pure message structures for unencrypted checkin, get_tasking and
//! post_response. Designed as a `no_std` + `alloc` library suitable for
//! freestanding agent environments.
//!
//! The library owns the message types only. UUID prefixing and base64
//! wrapping are the agent's responsibility.
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

pub use error::{Error, Result};
pub use types::*;
