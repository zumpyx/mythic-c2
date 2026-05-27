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
    /// Generate a fresh 4096-bit RSA key pair (required by Mythic).
    pub fn generate() -> Result<Self, MythicMessageError> {
        Self::generate_with_bits(4096)
    }

    /// Generate an RSA key pair with the given bit size.
    pub fn generate_with_bits(bits: usize) -> Result<Self, MythicMessageError> {
        let mut rng = OsRng;
        let private = RsaPrivateKey::new(&mut rng, bits)
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

    // Generate once, reuse across all tests (4096-bit RSA is slow)
    static mut KEYS: Option<RsaKeys> = None;
    static mut KEYS2: Option<RsaKeys> = None;

    fn keys() -> &'static RsaKeys {
        unsafe {
            let p: *mut Option<RsaKeys> = core::ptr::addr_of_mut!(KEYS);
            if (*p).is_none() { *p = Some(RsaKeys::generate().unwrap()); }
            (*p).as_ref().unwrap()
        }
    }
    fn keys2() -> &'static RsaKeys {
        unsafe {
            let p: *mut Option<RsaKeys> = core::ptr::addr_of_mut!(KEYS2);
            if (*p).is_none() { *p = Some(RsaKeys::generate().unwrap()); }
            (*p).as_ref().unwrap()
        }
    }

    #[test]
    fn generate_4096_bit_keys() {
        assert!(!keys().public_pem.is_empty());
        assert!(keys().public_pem.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let session_key = b"0123456789abcdef0123456789abcdef";

        let pub_key = rsa::RsaPublicKey::from(&keys().private);
        let mut rng = rand::thread_rng();
        let padding = Oaep::new::<Sha1>();
        let encrypted = pub_key
            .encrypt(&mut rng, padding, session_key.as_slice())
            .unwrap();
        let encrypted_b64 = STANDARD.encode(&encrypted);

        let decrypted = keys().decrypt_session_key(&encrypted_b64).unwrap();
        assert_eq!(decrypted, session_key);
    }

    #[test]
    fn decrypt_invalid_base64_fails() {
        assert!(matches!(
            keys().decrypt_session_key("!!!not-base64!!!"),
            Err(MythicMessageError::Crypto)
        ));
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let pub_key = rsa::RsaPublicKey::from(&keys().private);
        let mut rng = rand::thread_rng();
        let padding = Oaep::new::<Sha1>();
        let encrypted = pub_key.encrypt(&mut rng, padding, b"secret").unwrap();
        let encrypted_b64 = STANDARD.encode(&encrypted);

        assert!(matches!(
            keys2().decrypt_session_key(&encrypted_b64),
            Err(MythicMessageError::Crypto)
        ));
    }

    #[test]
    fn generate_multiple_keys_are_different() {
        assert_ne!(keys().public_pem, keys2().public_pem);
    }
}
