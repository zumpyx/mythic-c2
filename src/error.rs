//! Unified error type for all mythic-c2 operations.
//!
//! Each variant carries a stable numeric code used by [`Display`](MythicError::fmt).
//! In `no_std` release builds every error is a single-digit number — zero strings.

use alloc::string::String;
use core::fmt;

/// Unified error covering codec, crypto, transport, and protocol failures.
///
/// # Error codes
///
/// | Code | Variant | Meaning |
/// |------|---------|---------|
/// | 1 | `Serialize` | JSON serialization failed |
/// | 2 | `Deserialize` | JSON deserialization failed |
/// | 3 | `Base64` | Base64 decode failed |
/// | 4 | `Utf8` | UUID portion is not valid UTF-8 |
/// | 5 | `InvalidPacket` | Packet too short or malformed |
/// | 6 | `InvalidUuid` | UUID string is not valid |
/// | 7 | `UuidMismatch` | UUID in response does not match expected |
/// | 8 | `Crypto` | Cryptographic operation failed |
/// | 9 | `Timeout` | Transport timed out |
/// | 10 | `ConnectionFailed` | TCP/TLS connection failed |
/// | 11 | `DnsFailed` | DNS resolution failed |
/// | 12 | `TlsFailed` | TLS handshake or certificate error |
/// | 13 | `HttpStatus` | HTTP error — carries the status code |
/// | 14 | `ServerError` | Server returned 5xx — carries the status code |
/// | 15 | `AuthFailed` | Authentication or key mismatch |
/// | 16 | `ServerRejected` | Server returned a rejection response |
/// | 17 | `NotCheckedIn` | get_tasking / post_response called before checkin |
/// | 18 | `PayloadTooLarge` | Message exceeds server size limit |
/// | 19 | `KeyExchangeFailed` | RSA / translation staging negotiation failed |
/// | 20 | `RateLimited` | Client or server rate limiting |
/// | 21 | `Transport` | Transport fallback — carries a message string |
/// | 22 | `Protocol` | Protocol fallback — carries a message string |
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum MythicError {
    // ── Codec ──
    Serialize = 1,
    Deserialize = 2,
    Base64 = 3,
    Utf8 = 4,
    InvalidPacket = 5,
    InvalidUuid = 6,
    UuidMismatch = 7,

    // ── Crypto ──
    Crypto = 8,

    // ── Transport ──
    Timeout = 9,
    ConnectionFailed = 10,
    DnsFailed = 11,
    TlsFailed = 12,
    HttpStatus(u16) = 13,
    ServerError(u16) = 14,

    // ── Protocol ──
    AuthFailed = 15,
    ServerRejected = 16,
    NotCheckedIn = 17,
    PayloadTooLarge = 18,
    KeyExchangeFailed = 19,
    RateLimited = 20,

    // ── Fallback ──
    Transport(String) = 21,
    Protocol(String) = 22,
}

impl MythicError {
    /// Numeric error code.
    pub const fn code(&self) -> u8 {
        match self {
            Self::Serialize => 1,
            Self::Deserialize => 2,
            Self::Base64 => 3,
            Self::Utf8 => 4,
            Self::InvalidPacket => 5,
            Self::InvalidUuid => 6,
            Self::UuidMismatch => 7,
            Self::Crypto => 8,
            Self::Timeout => 9,
            Self::ConnectionFailed => 10,
            Self::DnsFailed => 11,
            Self::TlsFailed => 12,
            Self::HttpStatus(_) => 13,
            Self::ServerError(_) => 14,
            Self::AuthFailed => 15,
            Self::ServerRejected => 16,
            Self::NotCheckedIn => 17,
            Self::PayloadTooLarge => 18,
            Self::KeyExchangeFailed => 19,
            Self::RateLimited => 20,
            Self::Transport(_) => 21,
            Self::Protocol(_) => 22,
        }
    }

    /// Build a `Transport` variant from any `Display` error.
    pub fn transport<E: fmt::Display>(e: E) -> Self {
        Self::Transport(alloc::format!("{e}"))
    }

    /// Build a `Protocol` variant from any `Display` error.
    pub fn protocol<E: fmt::Display>(e: E) -> Self {
        Self::Protocol(alloc::format!("{e}"))
    }
}

impl fmt::Display for MythicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code())
    }
}

/// Convenience alias.
pub type MythicResult<T> = Result<T, MythicError>;
