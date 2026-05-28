//! # mythic-c2
//!
//! Mythic C2 agent protocol library — message encoding/decoding,
//! AES-256-CBC-HMAC encryption, and transport abstraction.
//!
//! `#![no_std]` compatible with `alloc`, suitable for embedded agent binaries.
//!
//! ## Quick Example
//!
//! ```no_run
//! use mythic::{C2Transport, MythicAgent, MythicError};
//! use uuid::Uuid;
//!
//! # struct HttpC2;
//! # impl C2Transport for HttpC2 {
//! #     fn checkin(&self, p: &str) -> Result<String, MythicError> { Ok(String::new()) }
//! #     fn get_tasking(&self, p: &str) -> Result<String, MythicError> { Ok(String::new()) }
//! #     fn post_response(&self, p: &str) -> Result<String, MythicError> { Ok(String::new()) }
//! # }
//! let c2 = HttpC2;
//! let payload_uuid = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
//!
//! let agent = MythicAgent::easy_checkin(
//!     payload_uuid,
//!     &c2,
//!         vec!["10.0.0.1".into()],
//!         Some("linux".into()),
//!         Some("root".into()),
//!         Some("web01".into()),
//!         Some(1337),
//!         Some("x86_64".into()),
//!         None, None, None, None, None, None,
//!     )
//!     .unwrap();
//!
//! println!("callback UUID: {}", agent.callback_uuid());
//! ```

#![no_std]

extern crate alloc;

pub mod agent;
pub mod error;
pub mod protocol;
pub mod transport;

pub use agent::MythicAgent;
pub use error::{MythicError, MythicResult};
pub use protocol::*;
pub use transport::C2Transport;
