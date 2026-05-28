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
/// The transport owns the encryption key so an agent can switch transports
/// (HTTP → DNS fallback, etc.) without duplicating key state.
///
/// # Key lifecycle
///
/// | Scenario | `get_encryption_key()` | `set_encryption_key()` |
/// |---|---|---|
/// | Plaintext | returns `None` | never called |
/// | Static PSK | returns build-time key | never called |
/// | RSA / EKE staging | returns `None` initially | called after key negotiation |
pub trait C2Transport {
    /// Error type for transport failures (timeout, DNS resolution, etc.).
    type Error: core::fmt::Display;

    /// Current AES-256 encryption key, base64-encoded.
    ///
    /// Return `None` for plaintext or before key negotiation.
    /// After RSA / translation staging, return the negotiated key
    /// set via [`set_encryption_key`](Self::set_encryption_key).
    fn get_encryption_key(&self) -> Option<String> {
        None
    }

    /// Store a dynamically negotiated session key (base64-encoded).
    ///
    /// Called after RSA or translation staging completes.  Static-PSK and
    /// plaintext transports can leave the default (no-op).
    fn set_encryption_key(&mut self, _key: &str) {}

    /// Whether any encryption key is currently set.
    fn is_encrypted(&self) -> bool {
        self.get_encryption_key().is_some()
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
    /// **Must** return fresh random bytes on every call when
    /// [`get_encryption_key`](Self::get_encryption_key) returns `Some(_)`.
    /// Predictable IVs in CBC mode break semantic security.
    fn random_iv(&self) -> Result<[u8; AES256_IV_LEN], Self::Error>;

    /// Deliver a message to the server's checkin endpoint.
    fn checkin(&self, packed: &str) -> Result<String, Self::Error>;

    /// Deliver a message to the server's get_tasking endpoint.
    fn get_tasking(&self, packed: &str) -> Result<String, Self::Error>;

    /// Deliver a message to the server's post_response endpoint.
    fn post_response(&self, packed: &str) -> Result<String, Self::Error>;
}
