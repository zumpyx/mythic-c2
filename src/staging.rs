//! RSA key generation and session-key decryption for Mythic's
//! staging (encrypted key exchange) flow.
//!
//! Only available when the `staging` feature is enabled.

use alloc::string::String;
use alloc::vec::Vec;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::rngs::OsRng;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use sha1::Sha1;

use crate::protocol::MythicMessageError;

/// A generated RSA-4096 key pair for use in the staging handshake.
pub struct RsaKeys {
    public_pem: String,
    private: RsaPrivateKey,
}

impl RsaKeys {
    /// Generate a fresh 4096-bit RSA key pair.
    pub fn generate() -> Result<Self, MythicMessageError> {
        let mut rng = OsRng;
        let private = RsaPrivateKey::new(&mut rng, 4096)
            .map_err(|_| MythicMessageError::Crypto)?;
        let public = RsaPublicKey::from(&private);
        let public_pem = public
            .to_public_key_pem(LineEnding::LF)
            .map_err(|_| MythicMessageError::Crypto)?;
        Ok(Self { public_pem, private })
    }

    /// The public key in PEM format — pass this to
    /// [`Mythic::build_staging_rsa`](crate::Mythic::build_staging_rsa).
    pub fn public_key(&self) -> &str {
        &self.public_pem
    }

    /// Decrypt the `session_key` field from a [`RespStagingRSA`]
    /// (RSA-OAEP-SHA1 encrypted by Mythic).
    pub fn decrypt_session_key(
        &self,
        encrypted_b64: &str,
    ) -> Result<Vec<u8>, MythicMessageError> {
        let ciphertext = STANDARD
            .decode(encrypted_b64.trim().as_bytes())
            .map_err(|_| MythicMessageError::Crypto)?;
        let padding = Oaep::new::<Sha1>();
        self.private
            .decrypt(padding, &ciphertext)
            .map_err(|_| MythicMessageError::Crypto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_rsa_keys() {
        let keys = RsaKeys::generate().unwrap();
        assert!(!keys.public_pem.is_empty());
        assert!(keys.public_pem.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let keys = RsaKeys::generate().unwrap();

        // Simulate server: encrypt a session key with the public key
        let session_key = b"0123456789abcdef0123456789abcdef"; // 32 bytes for AES-256

        let pub_key = rsa::RsaPublicKey::from(keys.private.clone());
        let mut rng = rand::thread_rng();
        let padding = Oaep::new::<Sha1>();
        let encrypted = pub_key
            .encrypt(&mut rng, padding, session_key.as_slice())
            .unwrap();
        let encrypted_b64 = STANDARD.encode(&encrypted);

        // Agent decrypts
        let decrypted = keys.decrypt_session_key(&encrypted_b64).unwrap();
        assert_eq!(decrypted, session_key);
    }

    #[test]
    fn decrypt_invalid_base64_fails() {
        let keys = RsaKeys::generate().unwrap();
        assert!(matches!(
            keys.decrypt_session_key("!!!not-base64!!!"),
            Err(MythicMessageError::Crypto)
        ));
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let keys1 = RsaKeys::generate().unwrap();
        let keys2 = RsaKeys::generate().unwrap();

        // Encrypt with keys1's public key
        let pub_key = rsa::RsaPublicKey::from(keys1.private.clone());
        let mut rng = rand::thread_rng();
        let padding = Oaep::new::<Sha1>();
        let encrypted = pub_key.encrypt(&mut rng, padding, b"secret").unwrap();
        let encrypted_b64 = STANDARD.encode(&encrypted);

        // Try to decrypt with keys2's private key — must fail
        assert!(matches!(
            keys2.decrypt_session_key(&encrypted_b64),
            Err(MythicMessageError::Crypto)
        ));
    }

    #[test]
    fn generate_multiple_keys_are_different() {
        let keys1 = RsaKeys::generate().unwrap();
        let keys2 = RsaKeys::generate().unwrap();
        assert_ne!(keys1.public_pem, keys2.public_pem);
    }
}
