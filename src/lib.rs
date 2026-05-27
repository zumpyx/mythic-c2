//! # mythic-c2
//!
//! Mythic C2 agent protocol library — message encoding/decoding,
//! AES-256-CBC-HMAC encryption, and transport abstraction.
//!
//! `#![no_std]` compatible with `alloc`, suitable for embedded agent binaries.
//!
//! ## Debug builds
//!
//! In debug mode (`cargo build` without `--release`), every `build_*` call
//! automatically captures a [`PackTrace`](Mythic::PackTrace) with the
//! pre-encryption JSON and the wire packet.  Access it via
//! [`mythic.last_trace()`](Mythic::last_trace).  Release builds omit this
//! code entirely — zero overhead.
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
//! // C2 carries its own crypto config
//! # struct HttpC2;
//! # impl C2Transport for HttpC2 {
//! #     type Error = &'static str;
//! #     fn aes_psk(&self) -> Option<String> {
//! #         Some(Aes256HmacCrypto::new([0xAB; 32]).key_b64())
//! #     }
//! #     fn checkin(&self, p: &str) -> Result<String, Self::Error> { Ok(String::new()) }
//! #     fn get_tasking(&self, p: &str) -> Result<String, Self::Error> { Ok(String::new()) }
//! #     fn post_response(&self, p: &str) -> Result<String, Self::Error> { Ok(String::new()) }
//! # }
//! let c2 = HttpC2;
//! let mut mythic = Mythic::new(
//!     Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap(),
//! );
//!
//! // Build a checkin packet — C2's aes_psk() decides encrypt vs plain
//! let pkt = mythic.build_checkin(CheckinInfo {
//!     os: Some("linux".into()),
//!     host: Some("web01".into()),
//!     user: Some("root".into()),
//!     pid: Some(1337),
//!     ips: vec!["10.0.0.1".into()],
//!     ..Default::default()
//! }, &c2).unwrap();
//!
//! // Or combined: build → send → parse in one call
//! // let (uuid, resp) = mythic.checkin(info, &c2)?;
//! ```
//!
//! ## Three Communication Scenarios
//!
//! | Scenario | Setup | First Message |
//! |---|---|---|
//! | Plaintext | `c2.aes_psk() = None` | `build_checkin(info, &c2)` — no encryption |
//! | Static key | `c2.aes_psk() = Some(key)` | `build_checkin(info, &c2)` — AES encrypted |
//! | RSA EKE | `c2.aes_psk() = Some(aes_psk)`, `encrypted_exchange_check() = true` | `staging_rsa(…, &c2)` → checkin |

#![no_std]

extern crate alloc;

pub mod c2;
pub mod mythic;
pub mod protocol;
pub mod staging;

pub use c2::{C2Transport, MythicError, NoopC2};
pub use mythic::Mythic;
pub use protocol::*;
pub use staging::RsaKeys;
