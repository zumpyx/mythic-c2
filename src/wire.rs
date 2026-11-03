//! Plaintext wire format.
//!
//! The protocol layer is `Base64( UUID(36 ASCII bytes) + JSON body )`.
//! Serialization of the body is handled by serde; this module only owns the
//! UUID prefix, concatenation and base64 wrapping.

use crate::error::{Error, Result};
use alloc::string::String;
use alloc::vec::Vec;
use base64::{engine::general_purpose::STANDARD, Engine};

const UUID_LEN: usize = 36;

fn finish(uuid: &str, body: &[u8]) -> Result<String> {
    if uuid.len() != UUID_LEN {
        return Err(Error::Uuid);
    }
    let mut raw = Vec::with_capacity(UUID_LEN + body.len());
    raw.extend_from_slice(uuid.as_bytes());
    raw.extend_from_slice(body);
    Ok(STANDARD.encode(&raw))
}

fn split(b64: &str) -> Result<(String, Vec<u8>)> {
    let raw = STANDARD.decode(b64).map_err(|_| Error::Base64)?;
    if raw.len() < UUID_LEN {
        return Err(Error::InvalidFormat);
    }
    let uuid = String::from_utf8(raw[..UUID_LEN].to_vec()).map_err(|_| Error::Utf8)?;
    Ok((uuid, raw[UUID_LEN..].to_vec()))
}

#[cfg(feature = "json")]
mod json {
    use super::*;
    use serde::{de::DeserializeOwned, Serialize};

    pub fn encode<T: Serialize>(uuid: &str, msg: &T) -> Result<String> {
        let body = serde_json::to_vec(msg).map_err(|_| Error::Json)?;
        finish(uuid, &body)
    }

    pub fn decode<T: DeserializeOwned>(b64: &str) -> Result<(String, T)> {
        let (uuid, body) = split(b64)?;
        let msg = serde_json::from_slice(&body).map_err(|_| Error::Json)?;
        Ok((uuid, msg))
    }
}

/// Encode any serializable message into the Mythic plaintext wire format.
#[cfg(feature = "json")]
pub fn encode_plaintext<T: serde::Serialize>(uuid: &str, msg: &T) -> Result<String> {
    json::encode(uuid, msg)
}

/// Decode a Mythic plaintext wire packet into the outer UUID and the inner message.
#[cfg(feature = "json")]
pub fn decode_plaintext<T: serde::de::DeserializeOwned>(b64: &str) -> Result<(String, T)> {
    json::decode(b64)
}
