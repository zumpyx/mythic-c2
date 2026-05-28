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
/// | 3 | `Base64` | Base64 decode failed (tried URL_SAFE then STANDARD) |
/// | 4 | `Utf8` | UUID portion of the wire packet is not valid UTF-8 |
/// | 5 | `InvalidPacket` | Packet too short or malformed |
/// | 6 | `InvalidUuid` | UUID string is not valid |
/// | 7 | `UuidMismatch` | UUID in response does not match expected |
/// | 8 | `Crypto` | Cryptographic operation failed (encrypt, decrypt, HMAC, key) |
/// | 9 | `Timeout` | Transport timed out |
/// | 10 | `ConnectionFailed` | Could not reach server (refused, unreachable) |
/// | 11 | `DnsFailed` | DNS resolution failed |
/// | 12 | `TlsFailed` | TLS handshake or certificate error |
/// | 13 | `HttpStatus` | HTTP-level error — carries the status code |
/// | 14 | `AuthFailed` | Authentication or key mismatch |
/// | 15 | `ServerRejected` | Server returned a rejection response |
/// | 16 | `Transport` | Transport fallback — carries a message string |
/// | 17 | `Protocol` | Protocol fallback — carries a message string |
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

    // ── Protocol ──
    AuthFailed = 14,
    ServerRejected = 15,

    // ── Fallback ──
    Transport(String) = 16,
    Protocol(String) = 17,
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
            Self::AuthFailed => 14,
            Self::ServerRejected => 15,
            Self::Transport(_) => 16,
            Self::Protocol(_) => 17,
        }
    }

    /// Build a `Transport` variant from anything that implements `Display`.
    /// Use this when no specific transport variant fits.
    pub fn transport<E: fmt::Display>(e: E) -> Self {
        Self::Transport(alloc::format!("{}", e))
    }
}

impl fmt::Display for MythicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code())
    }
}

/// Convenience alias.
pub type MythicResult<T> = Result<T, MythicError>;
