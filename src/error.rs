//! Unified error type for the full mythic-c2 lifecycle — codec, crypto,
//! transport, protocol, task execution, and runtime.
//!
//! Each variant carries a stable numeric code used by [`Display`](std::fmt::Display).
//! In release builds every error is a single-digit number — zero strings.

use std::fmt;

/// Unified error covering the full C2 agent lifecycle.
///
/// # Error codes
///
/// | Code | Variant | Category |
/// |------|---------|----------|
/// | 1 | `Serialize` | Codec |
/// | 2 | `Deserialize` | Codec |
/// | 3 | `Base64` | Codec |
/// | 4 | `Utf8` | Codec |
/// | 5 | `InvalidPacket` | Codec |
/// | 6 | `InvalidUuid` | Codec |
/// | 7 | `UuidMismatch` | Codec |
/// | 8 | `Crypto` | Crypto |
/// | 9 | `Timeout` | Transport |
/// | 10 | `ConnectionFailed` | Transport |
/// | 11 | `DnsFailed` | Transport |
/// | 12 | `TlsFailed` | Transport |
/// | 13 | `HttpStatus(u16)` | Transport |
/// | 14 | `ServerError(u16)` | Transport |
/// | 15 | `AuthFailed` | Protocol |
/// | 16 | `ServerRejected` | Protocol |
/// | 17 | `NotCheckedIn` | Protocol |
/// | 18 | `PayloadTooLarge` | Protocol |
/// | 19 | `KeyExchangeFailed` | Protocol |
/// | 20 | `RateLimited` | Protocol |
/// | 21 | `CommandNotFound` | Task |
/// | 22 | `InvalidTaskData` | Task |
/// | 23 | `TaskTimeout` | Task |
/// | 24 | `ResourceExhausted` | Runtime |
/// | 25 | `PermissionDenied` | Runtime |
/// | 26 | `ProcessFailed` | Runtime |
/// | 27 | `IoFailed` | Runtime |
/// | 28 | `Transport` | Fallback |
/// | 29 | `Protocol` | Fallback |
/// | 30 | `Task` | Fallback |
/// | 31 | `Runtime` | Fallback |
/// | 32 | `RsaKeyGen` | Crypto |
/// | 33 | `RsaEncrypt` | Crypto |
/// | 34 | `RsaDecrypt` | Crypto |
/// | 35 | `TransportConfig` | Config |
/// | 36 | `InvalidTransport` | Config |
/// | 37 | `ConfigParse` | Config |
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum MythicError {
    // ── Codec ──────────────────────────────────────────
    Serialize = 1,
    Deserialize = 2,
    Base64 = 3,
    Utf8 = 4,
    InvalidPacket = 5,
    InvalidUuid = 6,
    UuidMismatch = 7,

    // ── Crypto ─────────────────────────────────────────
    Crypto = 8,
    RsaKeyGen = 32,
    RsaEncrypt = 33,
    RsaDecrypt = 34,

    // ── Transport ──────────────────────────────────────
    Timeout = 9,
    ConnectionFailed = 10,
    DnsFailed = 11,
    TlsFailed = 12,
    HttpStatus(u16) = 13,
    ServerError(u16) = 14,

    // ── Protocol ───────────────────────────────────────
    AuthFailed = 15,
    ServerRejected = 16,
    NotCheckedIn = 17,
    PayloadTooLarge = 18,
    KeyExchangeFailed = 19,
    RateLimited = 20,

    // ── Task ───────────────────────────────────────────
    CommandNotFound = 21,
    InvalidTaskData = 22,
    TaskTimeout = 23,

    // ── Runtime ────────────────────────────────────────
    ResourceExhausted = 24,
    PermissionDenied = 25,
    ProcessFailed = 26,
    IoFailed = 27,

    // ── Fallback ───────────────────────────────────────
    Transport(String) = 28,
    Protocol(String) = 29,
    Task(String) = 30,
    Runtime(String) = 31,

    // ── Config ─────────────────────────────────────────
    TransportConfig = 35,
    InvalidTransport = 36,
    ConfigParse = 37,
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
            Self::CommandNotFound => 21,
            Self::InvalidTaskData => 22,
            Self::TaskTimeout => 23,
            Self::ResourceExhausted => 24,
            Self::PermissionDenied => 25,
            Self::ProcessFailed => 26,
            Self::IoFailed => 27,
            Self::Transport(_) => 28,
            Self::Protocol(_) => 29,
            Self::Task(_) => 30,
            Self::Runtime(_) => 31,
            Self::RsaKeyGen => 32,
            Self::RsaEncrypt => 33,
            Self::RsaDecrypt => 34,
            Self::TransportConfig => 35,
            Self::InvalidTransport => 36,
            Self::ConfigParse => 37,
        }
    }

    /// Build a `Transport` variant from any `Display` error.
    pub fn transport<E: fmt::Display>(e: E) -> Self {
        Self::Transport(format!("{e}"))
    }

    /// Build a `Protocol` variant from any `Display` error.
    pub fn protocol<E: fmt::Display>(e: E) -> Self {
        Self::Protocol(format!("{e}"))
    }

    /// Build a `Task` variant from any `Display` error.
    pub fn task<E: fmt::Display>(e: E) -> Self {
        Self::Task(format!("{e}"))
    }

    /// Build a `Runtime` variant from any `Display` error.
    pub fn runtime<E: fmt::Display>(e: E) -> Self {
        Self::Runtime(format!("{e}"))
    }
}

impl fmt::Display for MythicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code())
    }
}

impl std::error::Error for MythicError {}

/// Convenience alias.
pub type MythicResult<T> = Result<T, MythicError>;
