//! AES-256-CBC-HMAC encryption as used by the Mythic protocol.
//!
//! Wire format: `IV (16 bytes) + ciphertext + HMAC-SHA256 (32 bytes)`.
//! Padding: PKCS7.

use alloc::{string::String, vec::Vec};

use aes::Aes256;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::error::MythicMessageError;

pub trait MythicCrypto {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, MythicMessageError>;
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
    iv: [u8; AES256_IV_LEN],
}

impl Aes256HmacCrypto {
    pub fn new(key: [u8; AES256_KEY_LEN], iv: [u8; AES256_IV_LEN]) -> Self {
        Self { key, iv }
    }

    pub fn from_base64_key(
        key_b64: &str,
        iv: [u8; AES256_IV_LEN],
    ) -> Result<Self, MythicMessageError> {
        let key = STANDARD
            .decode(key_b64.trim().as_bytes())
            .map_err(|_| MythicMessageError::Crypto)?;

        if key.len() != AES256_KEY_LEN {
            return Err(MythicMessageError::Crypto);
        }

        let mut key_bytes = [0u8; AES256_KEY_LEN];
        key_bytes.copy_from_slice(&key);
        Ok(Self::new(key_bytes, iv))
    }

    pub fn key_b64(&self) -> String {
        STANDARD.encode(self.key)
    }

    pub fn iv(&self) -> &[u8; AES256_IV_LEN] {
        &self.iv
    }
}

impl MythicCrypto for Aes256HmacCrypto {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, MythicMessageError> {
        let ciphertext = Aes256CbcEncryptor::new_from_slices(&self.key, &self.iv)
            .map_err(|_| MythicMessageError::Crypto)?
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

        let mut mac =
            HmacSha256::new_from_slice(&self.key).map_err(|_| MythicMessageError::Crypto)?;
        mac.update(&self.iv);
        mac.update(&ciphertext);
        let tag = mac.finalize().into_bytes();

        let mut packet = Vec::with_capacity(AES256_IV_LEN + ciphertext.len() + AES256_HMAC_LEN);
        packet.extend_from_slice(&self.iv);
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
        let crypto = Aes256HmacCrypto::new([0x11; AES256_KEY_LEN], [0x22; AES256_IV_LEN]);
        let message = b"hello mythic aes".to_vec();

        let encrypted = crypto.encrypt(&message).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn aes256_hmac_pack_and_unpack_message() {
        let crypto = Aes256HmacCrypto::new([0x11; AES256_KEY_LEN], [0x22; AES256_IV_LEN]);
        let uuid = Uuid::from_u128(0x1234);
        let message = ReqStagingRSA::new("pub-key".to_string(), "session-1".to_string());

        let packed = message.to_wire(uuid, &crypto).unwrap();
        let (decoded_uuid, decoded_msg) =
            ReqStagingRSA::from_wire(&packed, Some(uuid), &crypto).unwrap();

        assert_eq!(decoded_uuid, uuid);
        assert_eq!(decoded_msg, message);
    }

    #[test]
    fn aes256_hmac_rejects_tampering() {
        let crypto = Aes256HmacCrypto::new([0x11; AES256_KEY_LEN], [0x22; AES256_IV_LEN]);
        let encrypted = crypto.encrypt(b"hello").unwrap();

        let mut tampered = encrypted.clone();
        tampered[0] ^= 0x01;

        assert!(matches!(
            crypto.decrypt(&tampered),
            Err(MythicMessageError::Crypto)
        ));
    }
}
