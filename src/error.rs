//! Unified error type for all mythic-c2 operations.
//!
//! Each variant carries a stable numeric code used by [`Display`](MythicError::fmt).
//! In `no_std` release builds every error is a single-digit number — zero strings.

use alloc::string::String;
use core::fmt;

/// Unified error covering codec, crypto, protocol, and transport failures.
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
/// | 8 | `Crypto` | Cryptographic operation failed (key, encrypt, decrypt, HMAC, RSA) |
/// | 9 | `Transport` | Transport layer failure (HTTP, DNS, pipe, etc.) — message stored |
/// | 10 | `Protocol` | Protocol-level rejection (server returned non-success status) |
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum MythicError {
    Serialize = 1,
    Deserialize = 2,
    Base64 = 3,
    Utf8 = 4,
    InvalidPacket = 5,
    InvalidUuid = 6,
    UuidMismatch = 7,
    Crypto = 8,
    Transport(String),
    Protocol(String),
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
            Self::Transport(_) => 9,
            Self::Protocol(_) => 10,
        }
    }

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
