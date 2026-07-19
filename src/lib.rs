#![doc = include_str!("../README.md")]

#[doc(hidden)]
pub use obfstr as libobfstr;

#[macro_use]
pub mod macros;
pub mod common;

pub mod agent;
pub mod c2;
pub mod error;

pub use agent::MythicAgent;
pub use c2::{C2Trait, MythicC2};
pub use common::{base64_decode, base64_encode};
pub use error::{MythicError, MythicResult};
