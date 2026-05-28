//! Transport abstraction — deliver messages to the Mythic server.
//!
//! This module provides the [`C2Transport`] trait, the only interface an agent
//! needs to implement for its C2 channel (HTTP, DNS, WebSocket, etc.).
//!
//! # Quick start
//!
//! ```ignore
//! use mythic::C2Transport;
//!
//! impl C2Transport for HttpC2 {
//!     type Error = &'static str;
//!     fn random_iv(&self) -> Result<[u8; 16], Self::Error> { /* TRNG */ Ok([0u8; 16]) }
//!     fn checkin(&self, packed: &str) -> Result<String, Self::Error> { ... }
//!     fn get_tasking(&self, packed: &str) -> Result<String, Self::Error> { ... }
//!     fn post_response(&self, packed: &str) -> Result<String, Self::Error> { ... }
//! }
//! ```

use alloc::string::String;
use crate::protocol::codec::AES256_IV_LEN;

/// Transport layer — three core methods: checkin, get_tasking, post_response.
///
/// The protocol layer handles **when** to call each method and whether to use
/// staging. The transport only moves bytes.
pub trait C2Transport {
    /// Error type for transport failures (timeout, DNS resolution, etc.).
    type Error: core::fmt::Display;

    /// The pre-shared AES key for this transport, if any.
    ///
    /// Return the base64-encoded key for static-key payloads.
    /// Return `None` for plaintext.
    fn aes_psk(&self) -> Option<String> {
        None
    }

    /// Whether this transport requires an encrypted key exchange (RSA or
    /// translation staging) before checking in.
    ///
    /// Return `true` for RSA-staging and translation-staging payloads;
    /// `false` (the default) for plaintext and static-key payloads.
    fn encrypted_exchange_check(&self) -> bool {
        false
    }

    /// Generate a cryptographically random 16-byte IV for AES-CBC.
    ///
    /// **Must** return fresh random bytes on every call when `aes_psk()` returns
    /// `Some(_)`. Predictable IVs in CBC mode break semantic security.
    ///
    /// Plaintext transports (`aes_psk() = None`) can return a zero IV — it
    /// will never be used.
    fn random_iv(&self) -> Result<[u8; AES256_IV_LEN], Self::Error>;

    /// Deliver a message to the server's checkin endpoint.
    fn checkin(&self, packed: &str) -> Result<String, Self::Error>;

    /// Deliver a message to the server's get_tasking endpoint.
    fn get_tasking(&self, packed: &str) -> Result<String, Self::Error>;

    /// Deliver a message to the server's post_response endpoint.
    fn post_response(&self, packed: &str) -> Result<String, Self::Error>;
}
