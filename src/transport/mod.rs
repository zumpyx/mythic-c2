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
//!     fn checkin(&self, packed: &str) -> Result<String, MythicError> { ... }
//!     fn get_tasking(&self, packed: &str) -> Result<String, MythicError> { ... }
//!     fn post_response(&self, packed: &str) -> Result<String, MythicError> { ... }
//! }
//! ```

use crate::error::MythicError;
use crate::protocol::codec::AES256_IV_LEN;
use std::string::String;

#[cfg(any(
    feature = "http",
    feature = "httpx",
    feature = "dns",
    feature = "websocket",
    feature = "github"
))]
pub mod config;

#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "http")]
pub use http::{HttpConfig, HttpTransport};

#[cfg(feature = "httpx")]
pub mod httpx;
#[cfg(feature = "httpx")]
pub use httpx::{HttpxConfig, HttpxTransport};

#[cfg(feature = "websocket")]
pub mod websocket;
#[cfg(feature = "websocket")]
pub use websocket::{WebsocketConfig, WebsocketTransport};

#[cfg(feature = "dns")]
pub mod dns;
#[cfg(feature = "dns")]
pub use dns::{DnsConfig, DnsTransport};

#[cfg(feature = "github")]
pub mod github;
#[cfg(feature = "github")]
pub use github::{GithubConfig, GithubTransport};

/// A benign default User-Agent. Blends in with normal browser traffic.
pub(crate) const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

/// Transport layer — required: `checkin`, `get_tasking`, `post_response`.
/// Optional: `get_aes_psk`, `set_aes_psk`, `encrypted_exchange_check`,
/// `random_iv` (has a default that errors — encrypting transports MUST override it).
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
    /// Called after RSA or translation staging completes so that subsequent
    /// `get_tasking`/`post_response` calls use the new session key.
    ///
    /// The default does nothing — transports that support dynamic keys must
    /// override it.
    fn set_aes_psk(&mut self, _key: &str) -> Option<String> {
        None
    }

    /// Whether this transport requires an encrypted key exchange (RSA or
    /// translation staging) before checking in.
    fn encrypted_exchange_check(&self) -> bool {
        false
    }

    /// Generate a cryptographically random 16-byte IV for AES-CBC.
    ///
    /// Encrypting transports SHOULD still override this with their own
    /// CSPRNG source, but when the `getrandom` feature is enabled the default
    /// implementation will use `getrandom::getrandom` so that forgetting to
    /// override does not silently break encryption.
    ///
    /// Plaintext transports (`get_aes_psk = None`) can keep the default — it
    /// will never be called.
    fn random_iv(&self) -> Result<[u8; AES256_IV_LEN], MythicError> {
        #[cfg(feature = "getrandom")]
        {
            let mut iv = [0u8; AES256_IV_LEN];
            ::getrandom::getrandom(&mut iv).map_err(|_| MythicError::Crypto)?;
            Ok(iv)
        }
        #[cfg(not(feature = "getrandom"))]
        Err(MythicError::Crypto)
    }

    /// Deliver a message to the server's checkin endpoint.
    fn checkin(&self, packed: &str) -> Result<String, MythicError>;

    /// Deliver a message to the server's get_tasking endpoint.
    fn get_tasking(&self, packed: &str) -> Result<String, MythicError>;

    /// Deliver a message to the server's post_response endpoint.
    fn post_response(&self, packed: &str) -> Result<String, MythicError>;
}
