//! Plaintext wire format.
//!
//! `Base64( UUID(36 ASCII bytes) + JSON body )`
//!
//! Serialization of the body is handled by serde. This module only owns the
//! UUID prefix, concatenation and base64 wrapping.
//!
//! Use `encode_plaintext_urlsafe` when the C2 profile places the message in a
//! URL query parameter.

use crate::error::{Error, Result};
use alloc::string::String;
use alloc::vec::Vec;
use base64::{engine::general_purpose::{STANDARD, URL_SAFE}, Engine};

const UUID_LEN: usize = 36;

fn finish(uuid: &str, body: &[u8], url_safe: bool) -> Result<String> {
    if uuid.len() != UUID_LEN {
        return Err(Error::Uuid);
    }
    let mut raw = Vec::with_capacity(UUID_LEN + body.len());
    raw.extend_from_slice(uuid.as_bytes());
    raw.extend_from_slice(body);
    if url_safe {
        Ok(URL_SAFE.encode(&raw))
    } else {
        Ok(STANDARD.encode(&raw))
    }
}

fn split(b64: &str) -> Result<(String, Vec<u8>)> {
    let raw = STANDARD
        .decode(b64)
        .or_else(|_| URL_SAFE.decode(b64))
        .map_err(|_| Error::Base64)?;
    if raw.len() < UUID_LEN {
        return Err(Error::InvalidFormat);
    }
    let uuid = String::from_utf8(raw[..UUID_LEN].to_vec()).map_err(|_| Error::Utf8)?;
    Ok((uuid, raw[UUID_LEN..].to_vec()))
}

/// Encode any serializable message (standard base64).
#[cfg(feature = "json")]
pub fn encode_plaintext<T: serde::Serialize>(uuid: &str, msg: &T) -> Result<String> {
    let body = serde_json::to_vec(msg).map_err(|_| Error::Json)?;
    finish(uuid, &body, false)
}

/// Encode using URL-safe base64 (for query-parameter C2 profiles).
#[cfg(feature = "json")]
pub fn encode_plaintext_urlsafe<T: serde::Serialize>(uuid: &str, msg: &T) -> Result<String> {
    let body = serde_json::to_vec(msg).map_err(|_| Error::Json)?;
    finish(uuid, &body, true)
}

/// Decode a wire packet. Accepts both standard and URL-safe base64.
#[cfg(feature = "json")]
pub fn decode_plaintext<T: serde::de::DeserializeOwned>(b64: &str) -> Result<(String, T)> {
    let (uuid, body) = split(b64)?;
    let msg = serde_json::from_slice(&body).map_err(|_| Error::Json)?;
    Ok((uuid, msg))
}
