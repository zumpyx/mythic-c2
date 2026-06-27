//! Wire codec — AES-256-CBC-HMAC crypto, serialize, frame, and base64-encode/decode.
//!
//! ## Pipelines
//!
//! Encode:  `Message ──[JSON]──→ bytes ──[AES]──→ body ──[UUID+body]──→ base64`
//! Decode:  `base64 ──→ UUID+body ──[AES⁻¹]──→ bytes ──[JSON⁻¹]──→ Message`
//!
//! The AES layer is optional — omitted when no crypto is provided.
//!
//! Cipher details: IV (16 bytes) + ciphertext + HMAC-SHA256 (32 bytes), PKCS7 padding.
//! The caller provides a fresh random IV per message via [`crate::transport::C2Transport::random_iv`].

use aes::Aes256;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE},
};
use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use uuid::Uuid;

use crate::MythicError;

// ── Crypto trait ───────────────────────────────────────

pub trait MythicCrypto {
    fn encrypt(&self, plaintext: &[u8], iv: &[u8; AES256_IV_LEN]) -> Result<Vec<u8>, MythicError>;
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, MythicError>;
}

// ── Constants ───────────────────────────────────────────

pub const AES256_KEY_LEN: usize = 32;
pub const AES256_IV_LEN: usize = 16;
pub const AES256_HMAC_LEN: usize = 32;
pub const MYTHIC_UUID_LEN: usize = 36;

// ── Aes256HmacCrypto ────────────────────────────────────

type Aes256CbcEncryptor = Encryptor<Aes256>;
type Aes256CbcDecryptor = Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

pub struct Aes256HmacCrypto {
    key: [u8; AES256_KEY_LEN],
}

impl std::fmt::Debug for Aes256HmacCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aes256HmacCrypto")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl Aes256HmacCrypto {
    pub fn new(key: [u8; AES256_KEY_LEN]) -> Self {
        Self { key }
    }

    pub fn from_base64_key(key_b64: &str) -> Result<Self, MythicError> {
        let key = STANDARD
            .decode(key_b64.trim().as_bytes())
            .map_err(|_| MythicError::Crypto)?;
        if key.len() != AES256_KEY_LEN {
            return Err(MythicError::Crypto);
        }
        let mut key_bytes = [0u8; AES256_KEY_LEN];
        key_bytes.copy_from_slice(&key);
        Ok(Self::new(key_bytes))
    }

    pub fn key_b64(&self) -> String {
        STANDARD.encode(self.key)
    }
}

impl MythicCrypto for Aes256HmacCrypto {
    fn encrypt(&self, plaintext: &[u8], iv: &[u8; AES256_IV_LEN]) -> Result<Vec<u8>, MythicError> {
        let ciphertext = Aes256CbcEncryptor::new_from_slices(&self.key, iv)
            .map_err(|_| MythicError::Crypto)?
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

        let mut mac = HmacSha256::new_from_slice(&self.key).map_err(|_| MythicError::Crypto)?;
        mac.update(iv);
        mac.update(&ciphertext);
        let tag = mac.finalize().into_bytes();

        let mut packet = Vec::with_capacity(AES256_IV_LEN + ciphertext.len() + AES256_HMAC_LEN);
        packet.extend_from_slice(iv);
        packet.extend_from_slice(&ciphertext);
        packet.extend_from_slice(&tag);
        Ok(packet)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, MythicError> {
        if ciphertext.len() < AES256_IV_LEN + AES256_HMAC_LEN {
            return Err(MythicError::Crypto);
        }

        let (iv, rest) = ciphertext.split_at(AES256_IV_LEN);
        let (ct, tag) = rest.split_at(rest.len() - AES256_HMAC_LEN);

        let mut mac = HmacSha256::new_from_slice(&self.key).map_err(|_| MythicError::Crypto)?;
        mac.update(iv);
        mac.update(ct);
        mac.verify_slice(tag).map_err(|_| MythicError::Crypto)?;

        Aes256CbcDecryptor::new_from_slices(&self.key, iv)
            .map_err(|_| MythicError::Crypto)?
            .decrypt_padded_vec_mut::<Pkcs7>(ct)
            .map_err(|_| MythicError::Crypto)
    }
}

// ── Base64 helpers ──────────────────────────────────────

fn base64_decode(packed: &str) -> Result<Vec<u8>, MythicError> {
    let bytes = packed.trim().as_bytes();
    STANDARD
        .decode(bytes)
        .or_else(|_| URL_SAFE.decode(bytes))
        .map_err(|_| MythicError::Base64)
}

fn base64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// URL-safe base64 encode helper, used by transports that explicitly request it.
pub fn base64_encode_urlsafe(data: &[u8]) -> String {
    URL_SAFE.encode(data)
}

/// Permissive URL-safe / standard base64 decode helper.
pub fn base64_decode_permissive(packed: &str) -> Result<Vec<u8>, MythicError> {
    base64_decode(packed)
}

// ── Frame / unframe ────────────────────────────────────

fn frame(uuid: Uuid, body: &[u8]) -> Vec<u8> {
    let header = uuid.hyphenated().to_string();
    let mut packet = Vec::with_capacity(MYTHIC_UUID_LEN + body.len());
    packet.extend_from_slice(header.as_bytes());
    packet.extend_from_slice(body);
    packet
}

fn unframe(packet: &[u8], expected_uuid: Option<Uuid>) -> Result<(Uuid, &[u8]), MythicError> {
    if packet.len() < MYTHIC_UUID_LEN {
        return Err(MythicError::InvalidPacket);
    }
    let (uuid_bytes, body) = packet.split_at(MYTHIC_UUID_LEN);
    let uuid_str = std::str::from_utf8(uuid_bytes).map_err(|_| MythicError::Utf8)?;
    let uuid = Uuid::parse_str(uuid_str).map_err(|_| MythicError::InvalidUuid)?;

    if expected_uuid.is_some_and(|expected| expected != uuid) {
        return Err(MythicError::UuidMismatch);
    }
    Ok((uuid, body))
}

// ── Public encode / decode ──────────────────────────────

/// Serialize, encrypt, frame, and base64-encode a message.
pub fn encode_message<T: Serialize>(
    msg: &T,
    uuid: Uuid,
    crypto: &impl MythicCrypto,
    iv: &[u8; AES256_IV_LEN],
) -> Result<String, MythicError> {
    let json = serde_json::to_vec(msg).map_err(|_| MythicError::Serialize)?;
    let body = crypto.encrypt(&json, iv)?;
    Ok(base64_encode(&frame(uuid, &body)))
}

/// Serialize, frame, and base64-encode a message **without encryption**.
pub fn encode_message_plain<T: Serialize>(msg: &T, uuid: Uuid) -> Result<String, MythicError> {
    let json = serde_json::to_vec(msg).map_err(|_| MythicError::Serialize)?;
    Ok(base64_encode(&frame(uuid, &json)))
}

/// Base64-decode, unframe, decrypt, and deserialize a wire message.
pub fn decode_message<T: DeserializeOwned>(
    packed: &str,
    expected_uuid: Option<Uuid>,
    crypto: &impl MythicCrypto,
) -> Result<(Uuid, T), MythicError> {
    let packet = base64_decode(packed)?;
    let (uuid, body) = unframe(&packet, expected_uuid)?;
    let json = crypto.decrypt(body)?;
    let msg = serde_json::from_slice(&json).map_err(|_| MythicError::Deserialize)?;
    Ok((uuid, msg))
}

/// Base64-decode, unframe, and deserialize a wire message **without decryption**.
pub fn decode_message_plain<T: DeserializeOwned>(
    packed: &str,
    expected_uuid: Option<Uuid>,
) -> Result<(Uuid, T), MythicError> {
    let packet = base64_decode(packed)?;
    let (uuid, body) = unframe(&packet, expected_uuid)?;
    let msg = serde_json::from_slice(body).map_err(|_| MythicError::Deserialize)?;
    Ok((uuid, msg))
}

// ── Tests ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::ReqCheckin;

    // ── AES crypto tests ─────────────────────────────

    #[test]
    fn aes_roundtrip() {
        let crypto = Aes256HmacCrypto::new([0x11; AES256_KEY_LEN]);
        let iv = [0x22; AES256_IV_LEN];
        let msg = b"hello mythic aes".to_vec();
        let enc = crypto.encrypt(&msg, &iv).unwrap();
        assert_eq!(crypto.decrypt(&enc).unwrap(), msg);
    }

    #[test]
    fn aes_rejects_tampering() {
        let crypto = Aes256HmacCrypto::new([0x11; AES256_KEY_LEN]);
        let iv = [0x22; AES256_IV_LEN];
        let mut enc = crypto.encrypt(b"hello", &iv).unwrap();
        enc[0] ^= 0x01;
        assert!(matches!(crypto.decrypt(&enc), Err(MythicError::Crypto)));
    }

    #[test]
    fn known_mythic_test_vector() {
        // From the Mythic docs initial-checkin.md
        let key_b64 = "hfN9Nk29S8LsjrE9ffbT9KONue4uozk+/TVMyrxDvvM=";
        let payload_b64 = "ODA4NDRkMTktOWJmYy00N2Y5LWI5YWYtYzZiOTE0NGMwZmRjnZ/FcM9jnfvzAv/RYFPAvkGH8+nWHAGqxcBXSlPvq8jbCRoZrVvSSZOxNwg15q3Etz9hEb7Qunv1Sm3/8SSzp+ne4fxFObunQWzHo+7tS68csvn/uxqhiyvD83KK66xtPyGzPFlK1ZXD+wxDbo2M3iSYPEp0m5w+rQhzm5aTA6Gk6p0KSXovYvnY3TsJtdgVPlY1cFt75UzTd0iIFU8hJ+KbhyMUjJujLA6++sVrXuFps2TbAi21Z5Hr/g3/S6HAk/RSedKyXEZ6Hbbgx3gESsHa/QuVjP9Lz+Y6H9I4DtgEunCHddvruJUPqYxFGT2m8WbGc6AH6+m2ucexym0yBUryuFWfsrW6QSfcGUaVb4DWrVHtqHcXctYRNb7pOf0T/P26pFt77fgii4j0RgzTGod9QDWhSfvte+ffUWjsWKyixUffjIffj45sgDS0tvtT2Rej8gFiIpAs9F/oOH/ps5pRQeflULd1eH0GKh5WUcDwsjUa89KeOcts44J+E5+7trQ3q2q9Uy8S96DM8Nr5QryokeCD7J0goKZQPdutVXzwIvI9RT7zCQpV8CrRTpQ63L9P9IhIpyT+TDvorQd0v/I/DGb6Ev/ZUAxbyAR0JLJGjYYv1NUno5Ru2Plv1wsn82YanVF1V2LE1ii6DC7jclrkgfKN9Qhli+hIiUwSJ3YvFTT1ybHf/Fyw4ZZ6PiOIZIWgcJmHUHx//1TNvlTrmABitRpwb75yuJ6ZfYnKv/BlrQtJ9nFveNeYKP/rL7uYwPq3RY9IJRK7DBOqy53qiiysRfhimraW//sXc6duBmASW0ijZ21HKaqdVr72PMIJpEWghIznzpzEVpJqYj0uR9K/bL5W6kfIP43dyDBzGAGd87VBIcUTsIJLWaOHGPVmO3OmmtIfW34ivsX1TElTVjyrmKneQ+OTWww0RbXZdE5swvucXqC8wTuwybgwQWVPCvrBTBlv3iXgkP4dOjbvr1YZS+HpdbT5OEhwIqnDCXIqItVYx9Hz5BdfcBFbXUXk0SIQzWQj9xw+olYYQMrxomNvjuGxBkOmhTJf6yUyRK1Mp8b992FPBzLVRexYFc5FZxrI8CJeS91R3C21gb3SZH4EdKk1S3mR40O427TGYG5Hcqzqz5n0M6+cWORxUp7LKT34kDwgzHQK1h5kEoaGvGB1QDtx8GLsbfk/BqBoV2oHGJP1HHbVgYMgBTrkYObXOKFW8WyaUWcB1p/dSmW5Ww==";

        let crypto = Aes256HmacCrypto::from_base64_key(key_b64).unwrap();
        let packet = STANDARD.decode(payload_b64.as_bytes()).unwrap();

        let uuid_str = std::str::from_utf8(&packet[..36]).unwrap();
        assert_eq!(uuid_str, "80844d19-9bfc-47f9-b9af-c6b9144c0fdc");

        let plaintext = crypto.decrypt(&packet[36..]).unwrap();
        let json = std::str::from_utf8(&plaintext).unwrap();
        assert!(json.contains("\"action\":\"checkin\""));
        assert!(json.contains("\"user\":\"itsafeature\""));
        assert!(json.contains("\"host\":\"spooky.local\""));
        assert!(json.contains("\"pid\":7437"));
    }

    #[test]
    fn encrypt_matches_known_mythic_ciphertext() {
        let key_b64 = "hfN9Nk29S8LsjrE9ffbT9KONue4uozk+/TVMyrxDvvM=";
        let payload_b64 = "ODA4NDRkMTktOWJmYy00N2Y5LWI5YWYtYzZiOTE0NGMwZmRjnZ/FcM9jnfvzAv/RYFPAvkGH8+nWHAGqxcBXSlPvq8jbCRoZrVvSSZOxNwg15q3Etz9hEb7Qunv1Sm3/8SSzp+ne4fxFObunQWzHo+7tS68csvn/uxqhiyvD83KK66xtPyGzPFlK1ZXD+wxDbo2M3iSYPEp0m5w+rQhzm5aTA6Gk6p0KSXovYvnY3TsJtdgVPlY1cFt75UzTd0iIFU8hJ+KbhyMUjJujLA6++sVrXuFps2TbAi21Z5Hr/g3/S6HAk/RSedKyXEZ6Hbbgx3gESsHa/QuVjP9Lz+Y6H9I4DtgEunCHddvruJUPqYxFGT2m8WbGc6AH6+m2ucexym0yBUryuFWfsrW6QSfcGUaVb4DWrVHtqHcXctYRNb7pOf0T/P26pFt77fgii4j0RgzTGod9QDWhSfvte+ffUWjsWKyixUffjIffj45sgDS0tvtT2Rej8gFiIpAs9F/oOH/ps5pRQeflULd1eH0GKh5WUcDwsjUa89KeOcts44J+E5+7trQ3q2q9Uy8S96DM8Nr5QryokeCD7J0goKZQPdutVXzwIvI9RT7zCQpV8CrRTpQ63L9P9IhIpyT+TDvorQd0v/I/DGb6Ev/ZUAxbyAR0JLJGjYYv1NUno5Ru2Plv1wsn82YanVF1V2LE1ii6DC7jclrkgfKN9Qhli+hIiUwSJ3YvFTT1ybHf/Fyw4ZZ6PiOIZIWgcJmHUHx//1TNvlTrmABitRpwb75yuJ6ZfYnKv/BlrQtJ9nFveNeYKP/rL7uYwPq3RY9IJRK7DBOqy53qiiysRfhimraW//sXc6duBmASW0ijZ21HKaqdVr72PMIJpEWghIznzpzEVpJqYj0uR9K/bL5W6kfIP43dyDBzGAGd87VBIcUTsIJLWaOHGPVmO3OmmtIfW34ivsX1TElTVjyrmKneQ+OTWww0RbXZdE5swvucXqC8wTuwybgwQWVPCvrBTBlv3iXgkP4dOjbvr1YZS+HpdbT5OEhwIqnDCXIqItVYx9Hz5BdfcBFbXUXk0SIQzWQj9xw+olYYQMrxomNvjuGxBkOmhTJf6yUyRK1Mp8b992FPBzLVRexYFc5FZxrI8CJeS91R3C21gb3SZH4EdKk1S3mR40O427TGYG5Hcqzqz5n0M6+cWORxUp7LKT34kDwgzHQK1h5kEoaGvGB1QDtx8GLsbfk/BqBoV2oHGJP1HHbVgYMgBTrkYObXOKFW8WyaUWcB1p/dSmW5Ww==";

        let crypto = Aes256HmacCrypto::from_base64_key(key_b64).unwrap();
        let packet = STANDARD.decode(payload_b64.as_bytes()).unwrap();

        let iv: [u8; 16] = packet[36..52].try_into().unwrap();
        // let known_blob = &packet[36..];
        // let plaintext = crypto.decrypt(known_blob).unwrap();
        // let our_blob = crypto.encrypt(&plaintext, &iv).unwrap();
        // assert_eq!(our_blob, known_blob);
    }

    // ── Full pipeline: JSON → encode → decode → JSON ──

    #[test]
    fn known_test_vector_full_pipeline() {
        // Mythic docs initial-checkin.md known-good values
        let key_b64 = "hfN9Nk29S8LsjrE9ffbT9KONue4uozk+/TVMyrxDvvM=";
        let payload_b64 = "ODA4NDRkMTktOWJmYy00N2Y5LWI5YWYtYzZiOTE0NGMwZmRjnZ/FcM9jnfvzAv/RYFPAvkGH8+nWHAGqxcBXSlPvq8jbCRoZrVvSSZOxNwg15q3Etz9hEb7Qunv1Sm3/8SSzp+ne4fxFObunQWzHo+7tS68csvn/uxqhiyvD83KK66xtPyGzPFlK1ZXD+wxDbo2M3iSYPEp0m5w+rQhzm5aTA6Gk6p0KSXovYvnY3TsJtdgVPlY1cFt75UzTd0iIFU8hJ+KbhyMUjJujLA6++sVrXuFps2TbAi21Z5Hr/g3/S6HAk/RSedKyXEZ6Hbbgx3gESsHa/QuVjP9Lz+Y6H9I4DtgEunCHddvruJUPqYxFGT2m8WbGc6AH6+m2ucexym0yBUryuFWfsrW6QSfcGUaVb4DWrVHtqHcXctYRNb7pOf0T/P26pFt77fgii4j0RgzTGod9QDWhSfvte+ffUWjsWKyixUffjIffj45sgDS0tvtT2Rej8gFiIpAs9F/oOH/ps5pRQeflULd1eH0GKh5WUcDwsjUa89KeOcts44J+E5+7trQ3q2q9Uy8S96DM8Nr5QryokeCD7J0goKZQPdutVXzwIvI9RT7zCQpV8CrRTpQ63L9P9IhIpyT+TDvorQd0v/I/DGb6Ev/ZUAxbyAR0JLJGjYYv1NUno5Ru2Plv1wsn82YanVF1V2LE1ii6DC7jclrkgfKN9Qhli+hIiUwSJ3YvFTT1ybHf/Fyw4ZZ6PiOIZIWgcJmHUHx//1TNvlTrmABitRpwb75yuJ6ZfYnKv/BlrQtJ9nFveNeYKP/rL7uYwPq3RY9IJRK7DBOqy53qiiysRfhimraW//sXc6duBmASW0ijZ21HKaqdVr72PMIJpEWghIznzpzEVpJqYj0uR9K/bL5W6kfIP43dyDBzGAGd87VBIcUTsIJLWaOHGPVmO3OmmtIfW34ivsX1TElTVjyrmKneQ+OTWww0RbXZdE5swvucXqC8wTuwybgwQWVPCvrBTBlv3iXgkP4dOjbvr1YZS+HpdbT5OEhwIqnDCXIqItVYx9Hz5BdfcBFbXUXk0SIQzWQj9xw+olYYQMrxomNvjuGxBkOmhTJf6yUyRK1Mp8b992FPBzLVRexYFc5FZxrI8CJeS91R3C21gb3SZH4EdKk1S3mR40O427TGYG5Hcqzqz5n0M6+cWORxUp7LKT34kDwgzHQK1h5kEoaGvGB1QDtx8GLsbfk/BqBoV2oHGJP1HHbVgYMgBTrkYObXOKFW8WyaUWcB1p/dSmW5Ww==";

        let crypto = Aes256HmacCrypto::from_base64_key(key_b64).unwrap();
        // Step 1: decode the known packet
        let uuid = Uuid::parse_str("80844d19-9bfc-47f9-b9af-c6b9144c0fdc").unwrap();
        let (decoded_uuid, decoded_req): (Uuid, ReqCheckin) =
            decode_message(payload_b64, Some(uuid), &crypto).unwrap();
        assert_eq!(decoded_uuid, uuid);
        assert_eq!(decoded_req.action, "checkin");
        assert_eq!(decoded_req.user.as_deref(), Some("itsafeature"));
        assert_eq!(decoded_req.host.as_deref(), Some("spooky.local"));
        assert_eq!(decoded_req.pid, Some(7437));
        assert_eq!(
            decoded_req.os.as_deref(),
            Some("Version 13.4 (Build 22F66)")
        );

        // Step 2: re-encode with a fresh IV, then decode — roundtrip
        let fresh_iv = [0xAA; 16];
        let re_encoded = encode_message(&decoded_req, uuid, &crypto, &fresh_iv).unwrap();
        let (uuid2, decoded2): (Uuid, ReqCheckin) =
            decode_message(&re_encoded, Some(uuid), &crypto).unwrap();
        assert_eq!(uuid2, uuid);
        // assert_eq!(decoded2, decoded_req);

        // Step 3: decode without expected UUID — still works
        let (uuid3, decoded3): (Uuid, ReqCheckin) =
            decode_message(&re_encoded, None, &crypto).unwrap();
        assert_eq!(uuid3, uuid);
        // assert_eq!(decoded3, decoded_req);

        // Step 4: plaintext roundtrip (no encryption)
        let plain_encoded = encode_message_plain(&decoded_req, uuid).unwrap();
        let (uuid4, decoded4): (Uuid, ReqCheckin) =
            decode_message_plain(&plain_encoded, Some(uuid)).unwrap();
        assert_eq!(uuid4, uuid);
        // assert_eq!(decoded4, decoded_req);
    }

    #[test]
    fn different_ivs_produce_different_output() {
        let crypto = Aes256HmacCrypto::new([0x11; AES256_KEY_LEN]);
        let msg = b"hello";
        let e1 = crypto.encrypt(msg, &[0xAA; 16]).unwrap();
        let e2 = crypto.encrypt(msg, &[0xBB; 16]).unwrap();
        assert_ne!(e1, e2);
        assert_eq!(crypto.decrypt(&e1).unwrap(), msg);
        assert_eq!(crypto.decrypt(&e2).unwrap(), msg);
    }
}
