//! Wire format: UUID prefix + optional AES encryption + URL-safe base64.
//!
//! Every Mythic message is structured as:
//! ```text
//! Base64( UUID + [AES256-CBC-HMAC]( payload ) )
//! ```
//! The AES layer is optional — omitted when `crypto_type = "none"`.
//!
//! **Public API:** [`encode_message`], [`encode_message_plain`],
//! [`decode_message`], [`decode_message_plain`].
//! The [`MythicMessage`] trait provides `.to_wire()` / `.from_wire()` sugar.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use serde::{Serialize, de::DeserializeOwned};
use uuid::Uuid;

use super::crypto::{AES256_IV_LEN, MythicCrypto};
use super::error::MythicMessageError;

pub const MYTHIC_UUID_LEN: usize = 36;
pub const MYTHIC_UUID_BIN_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UuidEncoding {
    Hyphenated,
    #[allow(dead_code)]
    Binary,
}

fn build_packet(uuid: Uuid, payload: &[u8], encoding: UuidEncoding) -> Vec<u8> {
    let header_len = match encoding {
        UuidEncoding::Hyphenated => MYTHIC_UUID_LEN,
        UuidEncoding::Binary => MYTHIC_UUID_BIN_LEN,
    };
    let mut packet = Vec::with_capacity(header_len + payload.len());
    match encoding {
        UuidEncoding::Hyphenated => {
            packet.extend_from_slice(uuid.hyphenated().to_string().as_bytes());
        }
        UuidEncoding::Binary => packet.extend_from_slice(uuid.as_bytes()),
    }
    packet.extend_from_slice(payload);
    packet
}

fn parse_packet<'a>(
    packet: &'a [u8],
    expected_uuid: Option<Uuid>,
    encoding: UuidEncoding,
) -> Result<(Uuid, &'a [u8]), MythicMessageError> {
    let header_len = match encoding {
        UuidEncoding::Hyphenated => MYTHIC_UUID_LEN,
        UuidEncoding::Binary => MYTHIC_UUID_BIN_LEN,
    };

    if packet.len() < header_len {
        return Err(MythicMessageError::InvalidPacket);
    }

    let (uuid_bytes, payload) = packet.split_at(header_len);
    let uuid = match encoding {
        UuidEncoding::Hyphenated => {
            let uuid_str =
                core::str::from_utf8(uuid_bytes).map_err(|_| MythicMessageError::Utf8)?;
            Uuid::parse_str(uuid_str).map_err(|_| MythicMessageError::InvalidUuid)?
        }
        UuidEncoding::Binary => {
            let mut arr = [0u8; MYTHIC_UUID_BIN_LEN];
            arr.copy_from_slice(uuid_bytes);
            Uuid::from_bytes(arr)
        }
    };

    if expected_uuid.is_some_and(|expected| expected != uuid) {
        return Err(MythicMessageError::UuidMismatch);
    }

    Ok((uuid, payload))
}

fn base64_decode(packed: &str) -> Result<Vec<u8>, MythicMessageError> {
    URL_SAFE
        .decode(packed.trim().as_bytes())
        .map_err(|_| MythicMessageError::Base64Decode)
}

fn base64_encode(data: &[u8]) -> String {
    URL_SAFE.encode(data)
}

// ── Public API ──────────────────────────────────────────────

/// Serialize, encrypt, frame, and base64-encode a message into a wire-ready string.
///
/// This is the primary function for building a request to send to the Mythic server.
/// It takes your message struct, the agent UUID, and a crypto instance, and returns
/// a base64 string you can put directly on the wire.
///
/// # Example
///
/// ```ignore
/// let crypto = Aes256HmacCrypto::new(key);
/// let iv = [0xCC; 16]; // fresh random IV per message
/// let req = ReqCheckin::new(uuid, info);
/// let packet = encode_message(&req, uuid, &crypto, &iv)?;
/// // send `packet` to the Mythic server
/// ```
pub fn encode_message<T: Serialize>(
    msg: &T,
    uuid: Uuid,
    crypto: &impl MythicCrypto,
    iv: &[u8; AES256_IV_LEN],
) -> Result<String, MythicMessageError> {
    let json = serde_json::to_vec(msg).map_err(|_| MythicMessageError::Serialize)?;
    let ciphertext = crypto.encrypt(&json, iv)?;
    Ok(base64_encode(&build_packet(
        uuid,
        &ciphertext,
        UuidEncoding::Hyphenated,
    )))
}

/// Serialize, frame, and base64-encode a message **without encryption.**
///
/// Used when the payload's `crypto_type` is `"none"`, or when no crypto keys
/// have been set on the [`Mythic`](crate::Mythic) facade.
pub fn encode_message_plain<T: Serialize>(
    msg: &T,
    uuid: Uuid,
) -> Result<String, MythicMessageError> {
    let json = serde_json::to_vec(msg).map_err(|_| MythicMessageError::Serialize)?;
    Ok(base64_encode(&build_packet(
        uuid,
        &json,
        UuidEncoding::Hyphenated,
    )))
}

/// Base64-decode, unframe, decrypt, and deserialize a wire message.
///
/// This is the primary function for parsing a response from the Mythic server.
/// Returns the server UUID that sent the message and the deserialized struct.
///
/// # Example
///
/// ```ignore
/// let (server_uuid, response) = decode_message::<RespCheckin>(&packet, Some(expected_uuid), &crypto)?;
/// ```
pub fn decode_message<T: DeserializeOwned>(
    packed: &str,
    expected_uuid: Option<Uuid>,
    crypto: &impl MythicCrypto,
) -> Result<(Uuid, T), MythicMessageError> {
    let packet = base64_decode(packed)?;
    let (uuid, ciphertext) = parse_packet(&packet, expected_uuid, UuidEncoding::Hyphenated)?;
    let plaintext = crypto.decrypt(ciphertext)?;
    let msg = serde_json::from_slice(&plaintext).map_err(|_| MythicMessageError::Deserialize)?;
    Ok((uuid, msg))
}

/// Base64-decode, unframe, and deserialize a wire message **without decryption.**
///
/// Used when the payload's `crypto_type` is `"none"`, or when no crypto keys
/// have been set on the [`Mythic`](crate::Mythic) facade.
pub fn decode_message_plain<T: DeserializeOwned>(
    packed: &str,
    expected_uuid: Option<Uuid>,
) -> Result<(Uuid, T), MythicMessageError> {
    let packet = base64_decode(packed)?;
    let (uuid, payload) = parse_packet(&packet, expected_uuid, UuidEncoding::Hyphenated)?;
    let msg = serde_json::from_slice(payload).map_err(|_| MythicMessageError::Deserialize)?;
    Ok((uuid, msg))
}

// ── MythicMessage trait ─────────────────────────────────────

/// Convenience trait that adds `to_wire` / `from_wire` methods to every message type.
///
/// Blanket-implemented for all `Serialize + DeserializeOwned` types.
pub trait MythicMessage: Serialize + DeserializeOwned + Sized {
    /// Encrypt and encode this message into a wire-ready base64 string.
    fn to_wire(
        &self,
        uuid: Uuid,
        crypto: &impl MythicCrypto,
        iv: &[u8; AES256_IV_LEN],
    ) -> Result<String, MythicMessageError> {
        encode_message(self, uuid, crypto, iv)
    }

    /// Encode this message without encryption (for staging).
    fn to_wire_plain(&self, uuid: Uuid) -> Result<String, MythicMessageError> {
        encode_message_plain(self, uuid)
    }

    /// Decode and decrypt a wire message into `(uuid, Self)`.
    fn from_wire(
        packed: &str,
        expected_uuid: Option<Uuid>,
        crypto: &impl MythicCrypto,
    ) -> Result<(Uuid, Self), MythicMessageError> {
        decode_message(packed, expected_uuid, crypto)
    }

    /// Decode a wire message without decryption (for staging).
    fn from_wire_plain(
        packed: &str,
        expected_uuid: Option<Uuid>,
    ) -> Result<(Uuid, Self), MythicMessageError> {
        decode_message_plain(packed, expected_uuid)
    }
}

impl<T: Serialize + DeserializeOwned + Sized> MythicMessage for T {}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec, vec::Vec};
    use serde::{Serialize, Serializer};

    use crate::protocol::staging::{ReqStagingRSA, ReqStagingTranslation};

    const TEST_IV: [u8; AES256_IV_LEN] = [0xCC; AES256_IV_LEN];

    struct ReverseCrypto;

    impl MythicCrypto for ReverseCrypto {
        fn encrypt(
            &self,
            plaintext: &[u8],
            iv: &[u8; AES256_IV_LEN],
        ) -> Result<Vec<u8>, MythicMessageError> {
            let mut out = iv.to_vec();
            out.extend(plaintext.iter().rev().copied().collect::<Vec<_>>());
            Ok(out)
        }

        fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, MythicMessageError> {
            if ciphertext.len() < AES256_IV_LEN {
                return Err(MythicMessageError::Crypto);
            }
            let payload = &ciphertext[AES256_IV_LEN..];
            Ok(payload.iter().rev().copied().collect())
        }
    }

    struct FailingCrypto;

    impl MythicCrypto for FailingCrypto {
        fn encrypt(
            &self,
            _plaintext: &[u8],
            _iv: &[u8; AES256_IV_LEN],
        ) -> Result<Vec<u8>, MythicMessageError> {
            Err(MythicMessageError::Crypto)
        }

        fn decrypt(&self, _ciphertext: &[u8]) -> Result<Vec<u8>, MythicMessageError> {
            Err(MythicMessageError::Crypto)
        }
    }

    struct BrokenSerialize;

    impl Serialize for BrokenSerialize {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Err(serde::ser::Error::custom("broken"))
        }
    }

    #[test]
    fn plain_roundtrip() {
        let uuid = Uuid::nil();
        let req = ReqStagingRSA::new("pub".to_string(), "sid".to_string());

        let packed = req.to_wire_plain(uuid).unwrap();
        let (decoded_uuid, decoded_req) =
            ReqStagingRSA::from_wire_plain(&packed, Some(uuid)).unwrap();

        assert_eq!(decoded_uuid, uuid);
        assert_eq!(decoded_req, req);
    }

    #[test]
    fn encrypted_roundtrip() {
        let uuid = Uuid::nil();
        let req = ReqStagingTranslation::new(
            "sid".to_string(),
            "enc".to_string(),
            "dec".to_string(),
            "aes".to_string(),
            uuid,
            "hello".to_string(),
        );

        let packed = req.to_wire(uuid, &ReverseCrypto, &TEST_IV).unwrap();
        let (decoded_uuid, decoded_req) =
            ReqStagingTranslation::from_wire(&packed, Some(uuid), &ReverseCrypto).unwrap();

        assert_eq!(decoded_uuid, uuid);
        assert_eq!(decoded_req, req);
    }

    #[test]
    fn encoding_error_paths() {
        let uuid = Uuid::nil();

        // Invalid base64
        assert!(matches!(
            decode_message::<ReqStagingRSA>("!!!", None, &ReverseCrypto),
            Err(MythicMessageError::Base64Decode)
        ));

        // Too short
        assert!(matches!(
            decode_message_plain::<ReqStagingRSA>(&URL_SAFE.encode(b"short"), None),
            Err(MythicMessageError::InvalidPacket)
        ));

        // Invalid UTF-8 in UUID field
        // build_packet with hyphenated UUID always has valid UTF-8.
        // Test via parse_packet directly with non-UTF-8 header.
        let mut bad = vec![0xff; MYTHIC_UUID_LEN];
        bad.extend_from_slice(b"payload");
        assert!(matches!(
            parse_packet(&bad, None, UuidEncoding::Hyphenated),
            Err(MythicMessageError::Utf8)
        ));

        // Invalid UUID format
        let mut invalid_uuid = b"xxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".to_vec();
        invalid_uuid.extend_from_slice(b"payload");
        assert!(matches!(
            parse_packet(&invalid_uuid, None, UuidEncoding::Hyphenated),
            Err(MythicMessageError::InvalidUuid)
        ));

        // UUID mismatch
        let ok_packet = encode_message_plain(&ReqStagingRSA::new("p".into(), "s".into()), uuid).unwrap();
        let other = Uuid::from_u128(7);
        assert!(matches!(
            decode_message_plain::<ReqStagingRSA>(&ok_packet, Some(other)),
            Err(MythicMessageError::UuidMismatch)
        ));
    }

    #[test]
    fn serialization_and_crypto_errors() {
        let uuid = Uuid::nil();

        // Serialization failure
        assert!(matches!(
            encode_message(&BrokenSerialize, uuid, &ReverseCrypto, &TEST_IV),
            Err(MythicMessageError::Serialize)
        ));
        assert!(matches!(
            encode_message_plain(&BrokenSerialize, uuid),
            Err(MythicMessageError::Serialize)
        ));

        // Deserialization failure: valid base64 + UUID, but non-JSON payload
        let mut packet = vec![0u8; MYTHIC_UUID_LEN];
        // Valid hyphenated UUID
        packet[..MYTHIC_UUID_LEN].copy_from_slice(
            "00000000-0000-0000-0000-000000000000".as_bytes(),
        );
        packet.extend_from_slice(b"not-json");
        let encoded = base64_encode(&packet);
        assert!(matches!(
            decode_message_plain::<ReqStagingRSA>(&encoded, None),
            Err(MythicMessageError::Deserialize)
        ));

        // Crypto failure on encrypt
        let req = ReqStagingRSA::new("p".into(), "s".into());
        assert!(matches!(
            req.to_wire(uuid, &FailingCrypto, &TEST_IV),
            Err(MythicMessageError::Crypto)
        ));

        // Crypto failure on decrypt
        let ok_packet =
            encode_message_plain(&ReqStagingRSA::new("p".into(), "s".into()), uuid).unwrap();
        assert!(matches!(
            decode_message::<ReqStagingRSA>(&ok_packet, None, &FailingCrypto),
            Err(MythicMessageError::Crypto)
        ));
    }

    #[test]
    fn trait_methods_match_free_functions() {
        let uuid = Uuid::from_u128(2);
        let msg = ReqStagingTranslation::new(
            "sid".into(), "enc".into(), "dec".into(), "aes".into(), uuid, "hello".into(),
        );

        let packed_fn = encode_message(&msg, uuid, &ReverseCrypto, &TEST_IV).unwrap();
        let packed_trait = msg.to_wire(uuid, &ReverseCrypto, &TEST_IV).unwrap();
        assert_eq!(packed_fn, packed_trait);

        let (uuid_fn, msg_fn): (Uuid, ReqStagingTranslation) =
            decode_message(&packed_fn, Some(uuid), &ReverseCrypto).unwrap();
        let (uuid_trait, msg_trait) =
            ReqStagingTranslation::from_wire(&packed_trait, Some(uuid), &ReverseCrypto).unwrap();
        assert_eq!(uuid_fn, uuid_trait);
        assert_eq!(msg_fn, msg_trait);
    }

    #[test]
    fn plain_trait_methods_match() {
        let uuid = Uuid::from_u128(9);
        let msg = ReqStagingRSA::new("pub".into(), "sid".into());

        let packed_fn = encode_message_plain(&msg, uuid).unwrap();
        let packed_trait = msg.to_wire_plain(uuid).unwrap();
        assert_eq!(packed_fn, packed_trait);

        let (uuid_fn, msg_fn): (Uuid, ReqStagingRSA) =
            decode_message_plain(&packed_fn, Some(uuid)).unwrap();
        let (uuid_trait, msg_trait) =
            ReqStagingRSA::from_wire_plain(&packed_trait, Some(uuid)).unwrap();
        assert_eq!(uuid_fn, uuid_trait);
        assert_eq!(msg_fn, msg_trait);
    }

    #[test]
    fn binary_encoding_roundtrip() {
        let uuid = Uuid::from_u128(1);
        let payload = b"binary payload".to_vec();

        let packet = build_packet(uuid, &payload, UuidEncoding::Binary);
        let (decoded_uuid, decoded_payload) =
            parse_packet(&packet, Some(uuid), UuidEncoding::Binary).unwrap();

        assert_eq!(decoded_uuid, uuid);
        assert_eq!(decoded_payload, payload);
    }
}
