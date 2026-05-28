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
//!     fn random_iv(&self) -> Result<[u8; 16], MythicError> { /* TRNG */ Ok([0u8; 16]) }
//!     fn checkin(&self, packed: &str) -> Result<String, MythicError> { ... }
//!     fn get_tasking(&self, packed: &str) -> Result<String, MythicError> { ... }
//!     fn post_response(&self, packed: &str) -> Result<String, MythicError> { ... }
//! }
//! ```

use crate::error::MythicError;
use crate::protocol::codec::AES256_IV_LEN;
use alloc::string::String;

/// Transport layer — required: `random_iv`, `checkin`, `get_tasking`,
/// `post_response`.  Optional: `get_aes_psk`, `set_aes_psk`,
/// `encrypted_exchange_check`.
///
/// The transport owns the encryption key so an agent can switch transports
/// (HTTP → DNS fallback, etc.) without duplicating key state.
pub trait C2Transport {
    /// AES-256 pre-shared key, base64-encoded.
    ///
    /// Return `None` for plaintext or before key negotiation.
    fn get_aes_psk(&self) -> Option<String> {
        None
    }

    /// Store a dynamically negotiated session key (base64-encoded).
    ///
    /// Called after RSA or translation staging completes.
    fn set_aes_psk(&mut self, _key: &str) -> Option<bool> {
        None
    }

    /// Whether this transport requires an encrypted key exchange (RSA or
    /// translation staging) before checking in.
    fn encrypted_exchange_check(&self) -> bool {
        false
    }

    /// Generate a cryptographically random 16-byte IV for AES-CBC.
    ///
    /// **Must** return fresh random bytes on every call when
    /// [`get_aes_psk`](Self::get_aes_psk) returns `Some(_)`.
    fn random_iv(&self) -> Result<[u8; AES256_IV_LEN], MythicError>;

    /// Deliver a message to the server's checkin endpoint.
    fn checkin(&self, packed: &str) -> Result<String, MythicError>;

    /// Deliver a message to the server's get_tasking endpoint.
    fn get_tasking(&self, packed: &str) -> Result<String, MythicError>;

    /// Deliver a message to the server's post_response endpoint.
    fn post_response(&self, packed: &str) -> Result<String, MythicError>;
}
