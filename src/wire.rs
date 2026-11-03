//! Plaintext wire format helpers.
//!
//! Wire format for unencrypted messages:
//! `Base64( UUID(36 bytes ASCII) + JSON bytes )`

use crate::error::{Error, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{de::DeserializeOwned, Serialize};

const UUID_LEN: usize = 36;

/// Encode a serializable message as a plaintext Mythic agent message.
///
/// The outer UUID is the payload UUID on first check-in, or the callback UUID
/// thereafter.
pub fn encode_plaintext<T: Serialize>(uuid: &str, msg: &T) -> Result<String> {
    if uuid.len() != UUID_LEN {
        return Err(Error::Uuid);
    }
    let json = serde_json::to_vec(msg).map_err(|_| Error::Json)?;
    let mut raw = Vec::with_capacity(UUID_LEN + json.len());
    raw.extend_from_slice(uuid.as_bytes());
    raw.extend_from_slice(&json);
    Ok(STANDARD.encode(&raw))
}

/// Decode a plaintext Mythic agent message.
///
/// Returns the outer UUID and the deserialized JSON body.
pub fn decode_plaintext<T: DeserializeOwned>(b64: &str) -> Result<(String, T)> {
    let raw = STANDARD.decode(b64).map_err(|_| Error::Base64)?;
    if raw.len() < UUID_LEN {
        return Err(Error::InvalidFormat);
    }
    let uuid = String::from_utf8(raw[..UUID_LEN].to_vec()).map_err(|_| Error::Utf8)?;
    let msg = serde_json::from_slice(&raw[UUID_LEN..]).map_err(|_| Error::Json)?;
    Ok((uuid, msg))
}
