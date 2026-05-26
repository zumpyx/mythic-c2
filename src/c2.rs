use alloc::string::String;

use crate::protocol::MythicMessageError;

/// Combined error covering both protocol encoding failures and transport errors.
#[derive(Debug)]
pub enum MythicError<E> {
    Protocol(MythicMessageError),
    Transport(E),
}

impl<E: core::fmt::Display> core::fmt::Display for MythicError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "protocol error: {e}"),
            Self::Transport(e) => write!(f, "transport error: {e}"),
        }
    }
}

impl<E> From<MythicMessageError> for MythicError<E> {
    fn from(e: MythicMessageError) -> Self {
        Self::Protocol(e)
    }
}

/// Encryption mode for the C2 channel — determined by the payload's
/// `crypto_type` build parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoMode {
    /// No encryption — payload built with `crypto_type = "none"`.
    None,
    /// Pre-shared AES-256 key embedded in the payload at build time
    /// (`crypto_type = "aes256_hmac"`).  The agent checks in directly with
    /// the embedded key; no staging required.
    StaticKey,
    /// RSA key exchange — the agent sends a `staging_rsa` message first to
    /// negotiate a session key, then checks in with the negotiated key.
    StagingRSA,
    /// Custom EKE via a translation container — the agent goes through a
    /// `staging_translation` handshake before checking in.
    StagingTranslation,
}

/// Transport layer — one method per message type.
///
/// Every transport must implement the three core methods:
/// [`checkin`](C2Transport::checkin), [`get_tasking`](C2Transport::get_tasking),
/// [`post_response`](C2Transport::post_response).
///
/// The two staging methods ([`staging_rsa`](C2Transport::staging_rsa) and
/// [`staging_translation`](C2Transport::staging_translation)) default to
/// calling [`checkin`](C2Transport::checkin).  Override them only if your C2
/// needs different routing for staging messages.
///
/// If every message uses the same pipe, implement the three core methods by
/// delegating to a shared internal helper — that choice stays in the
/// implementation, not the trait.
pub trait C2Transport {
    /// Error type for transport failures (timeout, DNS resolution, etc.).
    type Error;

    /// The encryption mode this transport was built with.  Defaults to
    /// [`CryptoMode::None`] (plaintext).  Override to declare support for
    /// static keys or staging.
    fn crypto_mode(&self) -> CryptoMode {
        CryptoMode::None
    }

    /// Deliver a `checkin` message and return the raw server response.
    fn checkin(&self, packed: &str) -> Result<String, Self::Error>;

    /// Deliver a `get_tasking` poll and return the raw server response.
    fn get_tasking(&self, packed: &str) -> Result<String, Self::Error>;

    /// Deliver a `post_response` message and return the raw server response.
    fn post_response(&self, packed: &str) -> Result<String, Self::Error>;

    /// Deliver a `staging_rsa` message.  Defaults to [`checkin`](Self::checkin).
    fn staging_rsa(&self, packed: &str) -> Result<String, Self::Error> {
        self.checkin(packed)
    }

    /// Deliver a `staging_translation` message.  Defaults to [`checkin`](Self::checkin).
    fn staging_translation(&self, packed: &str) -> Result<String, Self::Error> {
        self.checkin(packed)
    }
}

/// No-op C2 that discards all messages — for offline construction or testing.
pub struct NoopC2;

impl C2Transport for NoopC2 {
    type Error = core::convert::Infallible;

    fn checkin(&self, _packed: &str) -> Result<String, Self::Error> {
        Ok(String::new())
    }
    fn get_tasking(&self, _packed: &str) -> Result<String, Self::Error> {
        Ok(String::new())
    }
    fn post_response(&self, _packed: &str) -> Result<String, Self::Error> {
        Ok(String::new())
    }
}
