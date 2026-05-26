//! Staging message types — RSA key exchange and custom EKE.

use alloc::string::{String, ToString};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{ACTION_STAGING_RSA, ACTION_STAGING_TRANSLATION, ACTION_TRANSLATION_STAGING};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReqStagingRSA {
    pub action: String,
    pub pub_key: String,
    pub session_id: String,
}

impl ReqStagingRSA {
    pub fn new(pub_key: String, session_id: String) -> Self {
        Self {
            action: ACTION_STAGING_RSA.to_string(),
            pub_key,
            session_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RespStagingRSA {
    pub action: String,
    pub uuid: Uuid,
    pub session_key: String,
    pub session_id: String,
}

impl RespStagingRSA {
    pub fn new(uuid: Uuid, session_key: String, session_id: String) -> Self {
        Self {
            action: ACTION_STAGING_RSA.to_string(),
            uuid,
            session_key,
            session_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReqStagingTranslation {
    pub action: String,
    pub session_id: String,
    pub enc_key: String,
    pub dec_key: String,
    pub crypto_type: String,
    pub next_uuid: Uuid,
    pub message: String,
}

impl ReqStagingTranslation {
    pub fn new(
        session_id: String,
        enc_key: String,
        dec_key: String,
        crypto_type: String,
        next_uuid: Uuid,
        message: String,
    ) -> Self {
        Self {
            action: ACTION_STAGING_TRANSLATION.to_string(),
            session_id,
            enc_key,
            dec_key,
            crypto_type,
            next_uuid,
            message,
        }
    }
}

pub type ReqTranslationStaging = ReqStagingTranslation;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RespStagingTranslation {
    pub action: String,
    pub session_id: String,
    pub enc_key: String,
    pub dec_key: String,
    pub crypto_type: String,
    pub next_uuid: Uuid,
    pub message: String,
}

impl RespStagingTranslation {
    pub fn new(
        session_id: String,
        enc_key: String,
        dec_key: String,
        crypto_type: String,
        next_uuid: Uuid,
        message: String,
    ) -> Self {
        Self {
            action: ACTION_TRANSLATION_STAGING.to_string(),
            session_id,
            enc_key,
            dec_key,
            crypto_type,
            next_uuid,
            message,
        }
    }
}

pub type RespTranslationStaging = RespStagingTranslation;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::MythicMessage;
    use alloc::string::ToString;

    struct ReverseCrypto;

    impl super::super::crypto::MythicCrypto for ReverseCrypto {
        fn encrypt(
            &self,
            plaintext: &[u8],
        ) -> Result<alloc::vec::Vec<u8>, super::super::error::MythicMessageError> {
            let mut out = plaintext.to_vec();
            out.reverse();
            Ok(out)
        }

        fn decrypt(
            &self,
            ciphertext: &[u8],
        ) -> Result<alloc::vec::Vec<u8>, super::super::error::MythicMessageError> {
            let mut out = ciphertext.to_vec();
            out.reverse();
            Ok(out)
        }
    }

    #[test]
    fn staging_rsa_roundtrip() {
        let req = ReqStagingRSA::new("pub".to_string(), "sid".to_string());
        assert_eq!(req.action, ACTION_STAGING_RSA);
        assert_eq!(
            serde_json::from_str::<ReqStagingRSA>(&serde_json::to_string(&req).unwrap()).unwrap(),
            req
        );
    }

    #[test]
    fn staging_translation_roundtrip() {
        let uuid = Uuid::from_u128(1);
        let req = ReqStagingTranslation::new(
            "sid".to_string(),
            "enc".to_string(),
            "dec".to_string(),
            "aes".to_string(),
            uuid,
            "hello".to_string(),
        );
        assert_eq!(req.action, ACTION_STAGING_TRANSLATION);
        assert_eq!(
            serde_json::from_str::<ReqStagingTranslation>(&serde_json::to_string(&req).unwrap())
                .unwrap(),
            req
        );
    }

    #[test]
    fn staging_response_roundtrip() {
        let uuid = Uuid::from_u128(2);
        let resp_rsa = RespStagingRSA::new(uuid, "key".into(), "sid".into());
        assert_eq!(
            serde_json::from_str::<RespStagingRSA>(&serde_json::to_string(&resp_rsa).unwrap())
                .unwrap(),
            resp_rsa
        );

        let resp_translation = RespStagingTranslation::new(
            "sid".into(), "enc".into(), "dec".into(), "aes".into(), uuid, "hello".into(),
        );
        assert_eq!(
            serde_json::from_str::<RespStagingTranslation>(
                &serde_json::to_string(&resp_translation).unwrap()
            )
            .unwrap(),
            resp_translation
        );
    }

    #[test]
    fn encrypted_pack_and_unpack() {
        let uuid = Uuid::nil();
        let req = ReqStagingTranslation::new(
            "sid".to_string(),
            "enc".to_string(),
            "dec".to_string(),
            "aes".to_string(),
            uuid,
            "hello".to_string(),
        );

        let packed = req.to_wire(uuid, &ReverseCrypto).unwrap();
        let (decoded_uuid, decoded_req) =
            ReqStagingTranslation::from_wire(&packed, Some(uuid), &ReverseCrypto).unwrap();

        assert_eq!(decoded_uuid, uuid);
        assert_eq!(decoded_req.action, ACTION_STAGING_TRANSLATION);
        assert_eq!(decoded_req.message, "hello");
        assert_eq!(decoded_req.crypto_type, "aes");
    }
}
