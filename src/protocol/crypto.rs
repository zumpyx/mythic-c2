//! AES-256-CBC-HMAC encryption as used by the Mythic protocol.
//!
//! Wire format: `IV (16 bytes) + ciphertext + HMAC-SHA256 (32 bytes)`.
//! Padding: PKCS7.
//!
//! Per the Mythic spec the IV is 16 random bytes, generated fresh for each
//! message.  Callers pass the IV to [`MythicCrypto::encrypt`]; decryption
//! reads the IV from the message header so no IV is needed on the decrypt
//! side.

use alloc::{string::String, vec::Vec};

use aes::Aes256;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::error::MythicMessageError;

pub trait MythicCrypto {
    fn encrypt(
        &self,
        plaintext: &[u8],
        iv: &[u8; AES256_IV_LEN],
    ) -> Result<Vec<u8>, MythicMessageError>;
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, MythicMessageError>;
}

pub const AES256_KEY_LEN: usize = 32;
pub const AES256_IV_LEN: usize = 16;
pub const AES256_HMAC_LEN: usize = 32;

type Aes256CbcEncryptor = Encryptor<Aes256>;
type Aes256CbcDecryptor = Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aes256HmacCrypto {
    key: [u8; AES256_KEY_LEN],
}

impl Aes256HmacCrypto {
    pub fn new(key: [u8; AES256_KEY_LEN]) -> Self {
        Self { key }
    }

    pub fn from_base64_key(key_b64: &str) -> Result<Self, MythicMessageError> {
        let key = STANDARD
            .decode(key_b64.trim().as_bytes())
            .map_err(|_| MythicMessageError::Crypto)?;

        if key.len() != AES256_KEY_LEN {
            return Err(MythicMessageError::Crypto);
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
    fn encrypt(
        &self,
        plaintext: &[u8],
        iv: &[u8; AES256_IV_LEN],
    ) -> Result<Vec<u8>, MythicMessageError> {
        let ciphertext = Aes256CbcEncryptor::new_from_slices(&self.key, iv)
            .map_err(|_| MythicMessageError::Crypto)?
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

        let mut mac =
            HmacSha256::new_from_slice(&self.key).map_err(|_| MythicMessageError::Crypto)?;
        mac.update(iv);
        mac.update(&ciphertext);
        let tag = mac.finalize().into_bytes();

        let mut packet = Vec::with_capacity(AES256_IV_LEN + ciphertext.len() + AES256_HMAC_LEN);
        packet.extend_from_slice(iv);
        packet.extend_from_slice(&ciphertext);
        packet.extend_from_slice(&tag);
        Ok(packet)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, MythicMessageError> {
        if ciphertext.len() < AES256_IV_LEN + AES256_HMAC_LEN {
            return Err(MythicMessageError::Crypto);
        }

        let (iv, rest) = ciphertext.split_at(AES256_IV_LEN);
        let (ciphertext, tag) = rest.split_at(rest.len() - AES256_HMAC_LEN);

        let mut mac =
            HmacSha256::new_from_slice(&self.key).map_err(|_| MythicMessageError::Crypto)?;
        mac.update(iv);
        mac.update(ciphertext);
        mac.verify_slice(tag)
            .map_err(|_| MythicMessageError::Crypto)?;

        let plaintext = Aes256CbcDecryptor::new_from_slices(&self.key, iv)
            .map_err(|_| MythicMessageError::Crypto)?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            .map_err(|_| MythicMessageError::Crypto)?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{MythicMessage, ReqStagingRSA};
    use alloc::string::ToString;
    use uuid::Uuid;

    #[test]
    fn aes256_hmac_roundtrip() {
        let crypto = Aes256HmacCrypto::new([0x11; AES256_KEY_LEN]);
        let iv = [0x22; AES256_IV_LEN];
        let message = b"hello mythic aes".to_vec();

        let encrypted = crypto.encrypt(&message, &iv).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn aes256_hmac_pack_and_unpack_message() {
        let crypto = Aes256HmacCrypto::new([0x11; AES256_KEY_LEN]);
        let iv = [0x22; AES256_IV_LEN];
        let uuid = Uuid::from_u128(0x1234);
        let message = ReqStagingRSA::new("pub-key".to_string(), "session-1".to_string());

        let packed = message.to_wire(uuid, &crypto, &iv).unwrap();
        let (decoded_uuid, decoded_msg) =
            ReqStagingRSA::from_wire(&packed, Some(uuid), &crypto).unwrap();

        assert_eq!(decoded_uuid, uuid);
        assert_eq!(decoded_msg, message);
    }

    #[test]
    fn aes256_hmac_rejects_tampering() {
        let crypto = Aes256HmacCrypto::new([0x11; AES256_KEY_LEN]);
        let iv = [0x22; AES256_IV_LEN];
        let encrypted = crypto.encrypt(b"hello", &iv).unwrap();

        let mut tampered = encrypted.clone();
        tampered[0] ^= 0x01;

        assert!(matches!(
            crypto.decrypt(&tampered),
            Err(MythicMessageError::Crypto)
        ));
    }

    #[test]
    fn known_mythic_test_vector() {
        // From the Mythic docs initial-checkin.md
        let key_b64 = "hfN9Nk29S8LsjrE9ffbT9KONue4uozk+/TVMyrxDvvM=";
        let payload_b64 = "ODA4NDRkMTktOWJmYy00N2Y5LWI5YWYtYzZiOTE0NGMwZmRjnZ/FcM9jnfvzAv/RYFPAvkGH8+nWHAGqxcBXSlPvq8jbCRoZrVvSSZOxNwg15q3Etz9hEb7Qunv1Sm3/8SSzp+ne4fxFObunQWzHo+7tS68csvn/uxqhiyvD83KK66xtPyGzPFlK1ZXD+wxDbo2M3iSYPEp0m5w+rQhzm5aTA6Gk6p0KSXovYvnY3TsJtdgVPlY1cFt75UzTd0iIFU8hJ+KbhyMUjJujLA6++sVrXuFps2TbAi21Z5Hr/g3/S6HAk/RSedKyXEZ6Hbbgx3gESsHa/QuVjP9Lz+Y6H9I4DtgEunCHddvruJUPqYxFGT2m8WbGc6AH6+m2ucexym0yBUryuFWfsrW6QSfcGUaVb4DWrVHtqHcXctYRNb7pOf0T/P26pFt77fgii4j0RgzTGod9QDWhSfvte+ffUWjsWKyixUffjIffj45sgDS0tvtT2Rej8gFiIpAs9F/oOH/ps5pRQeflULd1eH0GKh5WUcDwsjUa89KeOcts44J+E5+7trQ3q2q9Uy8S96DM8Nr5QryokeCD7J0goKZQPdutVXzwIvI9RT7zCQpV8CrRTpQ63L9P9IhIpyT+TDvorQd0v/I/DGb6Ev/ZUAxbyAR0JLJGjYYv1NUno5Ru2Plv1wsn82YanVF1V2LE1ii6DC7jclrkgfKN9Qhli+hIiUwSJ3YvFTT1ybHf/Fyw4ZZ6PiOIZIWgcJmHUHx//1TNvlTrmABitRpwb75yuJ6ZfYnKv/BlrQtJ9nFveNeYKP/rL7uYwPq3RY9IJRK7DBOqy53qiiysRfhimraW//sXc6duBmASW0ijZ21HKaqdVr72PMIJpEWghIznzpzEVpJqYj0uR9K/bL5W6kfIP43dyDBzGAGd87VBIcUTsIJLWaOHGPVmO3OmmtIfW34ivsX1TElTVjyrmKneQ+OTWww0RbXZdE5swvucXqC8wTuwybgwQWVPCvrBTBlv3iXgkP4dOjbvr1YZS+HpdbT5OEhwIqnDCXIqItVYx9Hz5BdfcBFbXUXk0SIQzWQj9xw+olYYQMrxomNvjuGxBkOmhTJf6yUyRK1Mp8b992FPBzLVRexYFc5FZxrI8CJeS91R3C21gb3SZH4EdKk1S3mR40O427TGYG5Hcqzqz5n0M6+cWORxUp7LKT34kDwgzHQK1h5kEoaGvGB1QDtx8GLsbfk/BqBoV2oHGJP1HHbVgYMgBTrkYObXOKFW8WyaUWcB1p/dSmW5Ww==";

        let crypto = Aes256HmacCrypto::from_base64_key(key_b64).unwrap();

        // The docs use STANDARD base64, not URL_SAFE
        let packet = base64::engine::general_purpose::STANDARD
            .decode(payload_b64.as_bytes())
            .unwrap();

        // First 36 bytes = hyphenated UUID
        let uuid_str = core::str::from_utf8(&packet[..36]).unwrap();
        assert_eq!(uuid_str, "80844d19-9bfc-47f9-b9af-c6b9144c0fdc");

        // Rest = IV + ciphertext + HMAC
        let ciphertext = &packet[36..];
        let plaintext = crypto.decrypt(ciphertext).unwrap();
        let json = core::str::from_utf8(&plaintext).unwrap();

        assert!(json.contains("\"action\":\"checkin\""));
        assert!(json.contains("\"user\":\"itsafeature\""));
        assert!(json.contains("\"host\":\"spooky.local\""));
        assert!(json.contains("\"pid\":7437"));
    }

    #[test]
    fn encrypt_matches_known_mythic_ciphertext() {
        // Same test vector, verify our encrypt = Mythic's encrypt
        let key_b64 = "hfN9Nk29S8LsjrE9ffbT9KONue4uozk+/TVMyrxDvvM=";
        let payload_b64 = "ODA4NDRkMTktOWJmYy00N2Y5LWI5YWYtYzZiOTE0NGMwZmRjnZ/FcM9jnfvzAv/RYFPAvkGH8+nWHAGqxcBXSlPvq8jbCRoZrVvSSZOxNwg15q3Etz9hEb7Qunv1Sm3/8SSzp+ne4fxFObunQWzHo+7tS68csvn/uxqhiyvD83KK66xtPyGzPFlK1ZXD+wxDbo2M3iSYPEp0m5w+rQhzm5aTA6Gk6p0KSXovYvnY3TsJtdgVPlY1cFt75UzTd0iIFU8hJ+KbhyMUjJujLA6++sVrXuFps2TbAi21Z5Hr/g3/S6HAk/RSedKyXEZ6Hbbgx3gESsHa/QuVjP9Lz+Y6H9I4DtgEunCHddvruJUPqYxFGT2m8WbGc6AH6+m2ucexym0yBUryuFWfsrW6QSfcGUaVb4DWrVHtqHcXctYRNb7pOf0T/P26pFt77fgii4j0RgzTGod9QDWhSfvte+ffUWjsWKyixUffjIffj45sgDS0tvtT2Rej8gFiIpAs9F/oOH/ps5pRQeflULd1eH0GKh5WUcDwsjUa89KeOcts44J+E5+7trQ3q2q9Uy8S96DM8Nr5QryokeCD7J0goKZQPdutVXzwIvI9RT7zCQpV8CrRTpQ63L9P9IhIpyT+TDvorQd0v/I/DGb6Ev/ZUAxbyAR0JLJGjYYv1NUno5Ru2Plv1wsn82YanVF1V2LE1ii6DC7jclrkgfKN9Qhli+hIiUwSJ3YvFTT1ybHf/Fyw4ZZ6PiOIZIWgcJmHUHx//1TNvlTrmABitRpwb75yuJ6ZfYnKv/BlrQtJ9nFveNeYKP/rL7uYwPq3RY9IJRK7DBOqy53qiiysRfhimraW//sXc6duBmASW0ijZ21HKaqdVr72PMIJpEWghIznzpzEVpJqYj0uR9K/bL5W6kfIP43dyDBzGAGd87VBIcUTsIJLWaOHGPVmO3OmmtIfW34ivsX1TElTVjyrmKneQ+OTWww0RbXZdE5swvucXqC8wTuwybgwQWVPCvrBTBlv3iXgkP4dOjbvr1YZS+HpdbT5OEhwIqnDCXIqItVYx9Hz5BdfcBFbXUXk0SIQzWQj9xw+olYYQMrxomNvjuGxBkOmhTJf6yUyRK1Mp8b992FPBzLVRexYFc5FZxrI8CJeS91R3C21gb3SZH4EdKk1S3mR40O427TGYG5Hcqzqz5n0M6+cWORxUp7LKT34kDwgzHQK1h5kEoaGvGB1QDtx8GLsbfk/BqBoV2oHGJP1HHbVgYMgBTrkYObXOKFW8WyaUWcB1p/dSmW5Ww==";

        let crypto = Aes256HmacCrypto::from_base64_key(key_b64).unwrap();
        let packet = base64::engine::general_purpose::STANDARD
            .decode(payload_b64.as_bytes())
            .unwrap();

        // Known IV from the test vector (first 16 bytes after UUID)
        let iv: [u8; 16] = packet[36..52].try_into().unwrap();
        // Known ciphertext blob (after UUID)
        let known_blob = &packet[36..];

        // Decrypt to get the plaintext
        let plaintext = crypto.decrypt(known_blob).unwrap();

        // Re-encrypt with the SAME key + IV — must produce identical ciphertext
        let our_blob = crypto.encrypt(&plaintext, &iv).unwrap();
        assert_eq!(our_blob, known_blob, "encrypt must produce identical ciphertext");
    }

    #[test]
    fn different_ivs_produce_different_output() {
        let crypto = Aes256HmacCrypto::new([0x11; AES256_KEY_LEN]);
        let msg = b"hello";

        let e1 = crypto.encrypt(msg, &[0xAA; 16]).unwrap();
        let e2 = crypto.encrypt(msg, &[0xBB; 16]).unwrap();

        assert_ne!(e1, e2); // different IV → different ciphertext
        assert_eq!(crypto.decrypt(&e1).unwrap(), msg);
        assert_eq!(crypto.decrypt(&e2).unwrap(), msg);
    }
}
