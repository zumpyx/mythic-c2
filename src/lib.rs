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
//! use mythic::{C2Transport, MythicAgent, ReqCheckin};
//! use uuid::Uuid;
//!
//! # struct HttpC2;
//! # impl C2Transport for HttpC2 {
//! #     type Error = &'static str;
//! #     fn random_iv(&self) -> Result<[u8; 16], Self::Error> { Ok([0u8; 16]) }
//! #     fn checkin(&self, p: &str) -> Result<String, Self::Error> { Ok(String::new()) }
//! #     fn get_tasking(&self, p: &str) -> Result<String, Self::Error> { Ok(String::new()) }
//! #     fn post_response(&self, p: &str) -> Result<String, Self::Error> { Ok(String::new()) }
//! # }
//! let c2 = HttpC2;
//! let payload_uuid = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
//!
//! let mut agent = MythicAgent::new(payload_uuid);
//! let req = ReqCheckin::new(
//!     payload_uuid,
//!     vec!["10.0.0.1".into()],
//!     Some("linux".into()),
//!     Some("root".into()),
//!     Some("web01".into()),
//!     Some(1337),
//!     Some("x86_64".into()),
//!     None, None, None, None, None, None,
//! );
//! agent.checkin(req, &c2).unwrap();
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
