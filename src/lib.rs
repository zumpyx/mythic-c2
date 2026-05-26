//! # mythic-c2
//!
//! Mythic C2 agent protocol library — message encoding/decoding,
//! AES-256-CBC-HMAC encryption, and transport abstraction.
//!
//! `#![no_std]` compatible with `alloc`, suitable for embedded agent binaries.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────┐
//! │  [`Mythic`] facade       │  build_* / parse_* / checkin() / get_tasking() / …
//! │  holds UUID + crypto     │
//! └──────────┬──────────────┘
//!            │  base64 string
//! └──────────┼──────────────┘
//! │  [`C2Transport`] trait   │  deliver to Mythic server (HTTP, DNS, WS, …)
//! └──────────┬──────────────┘
//!            │
//! └──────────┼──────────────┘
//! │  `protocol` layer        │  message types, framing, crypto
//! └─────────────────────────┘
//! ```
//!
//! ## Quick Example
//!
//! ```rust
//! use mythic::{Mythic, Aes256HmacCrypto, CheckinInfo, C2Transport};
//! use uuid::Uuid;
//!
//! # struct HttpC2;
//! # impl C2Transport for HttpC2 {
//! #     type Error = &'static str;
//! #     fn checkin(&self, p: &str) -> Result<String, Self::Error> { Ok(String::new()) }
//! #     fn get_tasking(&self, p: &str) -> Result<String, Self::Error> { Ok(String::new()) }
//! #     fn post_response(&self, p: &str) -> Result<String, Self::Error> { Ok(String::new()) }
//! # }
//! let crypto = Aes256HmacCrypto::new([0xAB; 32], [0xCD; 16]);
//! let mut mythic = Mythic::with_crypto(
//!     Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap(),
//!     crypto,
//! );
//!
//! // Build a checkin packet
//! let pkt = mythic.build_checkin(CheckinInfo {
//!     os: Some("linux".into()),
//!     host: Some("web01".into()),
//!     user: Some("root".into()),
//!     pid: Some(1337),
//!     ips: vec!["10.0.0.1".into()],
//!     ..Default::default()
//! }).unwrap();
//!
//! // Or combined: build → send → parse in one call
//! // let (uuid, resp) = mythic.checkin(info, &transport)?;
//! ```
//!
//! ## Three Communication Scenarios
//!
//! | Scenario | Setup | First Message |
//! |---|---|---|
//! | Plaintext | `Mythic::new(uuid)` | `build_checkin()` — no encryption |
//! | Static key | `Mythic::with_crypto(uuid, key)` | `build_checkin()` — AES encrypted |
//! | RSA EKE | `Mythic::with_crypto(uuid, aes_psk)` → `staging_rsa()` → `set_crypto(…)` | `build_checkin()` — negotiated key |

#![no_std]

extern crate alloc;

pub mod c2;
pub mod mythic;
pub mod protocol;

pub use c2::{C2Transport, MythicError, NoopC2};
pub use mythic::Mythic;
pub use protocol::*;
