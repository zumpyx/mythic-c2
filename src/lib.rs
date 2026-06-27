#[doc(hidden)]
pub use obfstr as libobfstr;
#[macro_use]
mod macros;
mod common;

pub mod agent;
pub mod c2;
pub mod error;
pub mod protocol;

// pub use agent::MythicAgent;
pub use c2::MythicC2;
use common::*;
pub use error::{MythicError, MythicResult};
pub use protocol::MythicAgent;

// #[cfg(any(feature = "http", feature = "httpx"))]
// pub use c2::config::{C2Profile, C2Profiles};
