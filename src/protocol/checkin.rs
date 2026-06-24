//! Checkin message types: plaintext, static-key, and RSA/translation staging.
//!
//! # Modes
//!
//! | Mode | Message | Encryption |
//! |---|---|---|
//! | Plaintext | [`ReqCheckin`] | none (`c2.get_aes_psk() = None`) |
//! | Static key | [`ReqCheckin`] | AES-256-CBC-HMAC (`c2.get_aes_psk() = Some(key)`) |
//! | RSA staging | [`ReqStagingRSA`] | types defined, RSA crypto not yet implemented |
//! | Translation | [`ReqStagingTranslation`] | types defined, EKE logic left to implementor |

use serde::{Deserialize, Serialize};
use std::{
    string::{String, ToString},
    vec::Vec,
};
use uuid::Uuid;

use super::codec::{
    AES256_IV_LEN, Aes256HmacCrypto, decode_message, decode_message_plain, encode_message,
    encode_message_plain,
};
use super::{
    ACTION_CHECKIN, ACTION_STAGING_RSA, ACTION_STAGING_TRANSLATION, ACTION_TRANSLATION_STAGING,
};
use crate::MythicResult;
use crate::error::MythicError;
use crate::transport::C2Transport;
// ── Standard checkin (plaintext / static key) ──────────────

/// Standard checkin request — matches the official Mythic JSON schema.
///
/// ```json
/// {
///     "action": "checkin",
///     "uuid": "payload uuid",
///     "ips": ["127.0.0.1"],
///     "os": "macOS 10.15",
///     "user": "its-a-feature",
///     "host": "spooky.local",
///     "pid": 4444,
///     "architecture": "x64",
///     "domain": "test",
///     "integrity_level": 3,
///     "external_ip": "8.8.8.8",
///     "encryption_key": "base64 of key",
///     "decryption_key": "base64 of key",
///     "process_name": "osascript"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ReqCheckin {
    pub action: String,
    pub uuid: Uuid,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_level: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decryption_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
}

impl ReqCheckin {
    pub fn default(uuid: Uuid) -> Self {
        Self {
            action: ACTION_CHECKIN.to_string(),
            uuid,
            ..Default::default()
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        uuid: Uuid,
        ips: Vec<String>,
        os: Option<String>,
        user: Option<String>,
        host: Option<String>,
        pid: Option<u32>,
        architecture: Option<String>,
        domain: Option<String>,
        integrity_level: Option<u32>,
        external_ip: Option<String>,
        encryption_key: Option<String>,
        decryption_key: Option<String>,
        process_name: Option<String>,
    ) -> Self {
        Self {
            action: ACTION_CHECKIN.to_string(),
            uuid,
            ips,
            os,
            user,
            host,
            pid,
            architecture,
            domain,
            integrity_level,
            external_ip,
            encryption_key,
            decryption_key,
            process_name,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RespCheckin {
    pub action: String,
    pub id: Uuid,
    pub status: String,
}

impl RespCheckin {
    pub fn new(id: Uuid, status: String) -> Self {
        Self {
            action: ACTION_CHECKIN.to_string(),
            id,
            status,
        }
    }

    pub fn success(id: Uuid) -> Self {
        Self::new(id, "success".into())
    }
}

// ── RSA key-exchange staging (RESERVED) ────────────────────
//
// The structs below model the Mythic RSA staging wire format but RSA
// encryption itself is **not yet implemented** in this library.
//
// To use RSA staging today an agent implementor must:
//   1. Generate an RSA keypair (the agent holds the private key).
//   2. Send `ReqStagingRSA { pub_key, session_id }` to Mythic.
//   3. Mythic returns `RespStagingRSA { session_key }` —
//      the AES-256 session key RSA-encrypted with the agent's public key.
//   4. The agent decrypts `session_key` with its RSA private key
//      and uses the result as the `Aes256HmacCrypto` key for all
//      subsequent messages.
//
// A built-in implementation (behind an optional `staging-rsa` feature)
// is planned.  For now these types serve as the correct wire-format
// definition so serialization / deserialization is always accurate.

/// RSA staging request — the first message when using encrypted key exchange.
///
/// **RSA encryption is not yet implemented.** These types define the wire
/// format; the agent implementor is responsible for RSA key generation
/// and OAEP decryption of the `session_key` returned by Mythic.
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

/// RSA staging response — contains the RSA-encrypted session key.
///
/// The `session_key` field is the AES-256 key encrypted with the agent's
/// RSA public key (OAEP padding).  The agent must decrypt it with its
/// private key.
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

// ── Translation / custom EKE staging (RESERVED) ────────────
//
// These types model the translation-container staging flow used when
// a payload type declares `MythicEncrypts=False`.  The translation
// container handles key negotiation, which can be any custom EKE
// (Diffie-Hellman, ECDH, etc.).
//
// Like RSA staging, the wire-format types are correct but the
// exchange logic is left to the agent implementor for now.

/// Custom EKE staging request.
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

/// Alias for backwards compatibility with Mythic server naming.
pub type ReqTranslationStaging = ReqStagingTranslation;

/// Custom EKE staging response.
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

/// Alias for backwards compatibility with Mythic server naming.
pub type RespTranslationStaging = RespStagingTranslation;

// ── Checkin flow ─────────────────────────────────────────────

/// Result of a direct checkin — callback UUID and wire packets for debug.
pub struct DirectResult {
    pub callback_uuid: Uuid,
    /// Base64 wire packet that was sent.
    pub packet_sent: String,
    /// Base64 wire packet received from the server.
    pub packet_received: String,
}

/// Perform a direct checkin (plaintext or static-key).
///
/// Uses [`C2Transport::get_aes_psk`] from the transport to decide:
/// - `None` → plaintext
/// - `Some(key)` → AES-256-CBC-HMAC with the given key
///
/// `iv` is only used when the transport provides a key.
/// Callers must obtain fresh random IVs via [`C2Transport::random_iv`].
pub fn direct_checkin<C: C2Transport>(
    c2: &C,
    req: &ReqCheckin,
    payload_uuid: Uuid,
    iv: &[u8; AES256_IV_LEN],
) -> MythicResult<DirectResult> {
    let (resp, packed, response) = if let Some(key_b64) = c2.get_aes_psk() {
        let crypto = Aes256HmacCrypto::from_base64_key(&key_b64)?;
        let packed = encode_message(req, payload_uuid, &crypto, iv)?;
        let response = c2.checkin(&packed)?;
        let (_, resp): (Uuid, RespCheckin) =
            decode_message(&response, Some(payload_uuid), &crypto)?;
        (resp, packed, response)
    } else {
        let packed = encode_message_plain(req, payload_uuid)?;
        let response = c2.checkin(&packed)?;
        let (_, resp): (Uuid, RespCheckin) = decode_message_plain(&response, Some(payload_uuid))?;
        (resp, packed, response)
    };

    if resp.status != "success" {
        return Err(MythicError::protocol(format!(
            "checkin rejected: status={}",
            resp.status
        )));
    }

    Ok(DirectResult {
        callback_uuid: resp.id,
        packet_sent: packed,
        packet_received: response,
    })
}

/// Result of a successful RSA EKE staging exchange.
#[cfg(feature = "rsa-staging")]
pub struct RsaStagingResult {
    /// Temporary UUID returned by Mythic; used as the outer UUID for the
    /// follow-up checkin.
    pub temp_uuid: Uuid,
    /// The newly negotiated AES-256 session key.
    pub crypto: Aes256HmacCrypto,
    /// Base64 wire packet that was sent for the staging_rsa request.
    pub packet_sent: String,
    /// Base64 wire packet received from Mythic.
    pub packet_received: String,
}

/// Perform RSA encrypted key exchange staging.
///
/// This generates a 4096-bit RSA keypair, sends it to Mythic encrypted with
/// the transport's initial AES PSK, decrypts the returned session key, and
/// returns the temporary UUID + new AES crypto for the follow-up checkin.
#[cfg(feature = "rsa-staging")]
pub fn rsa_staging_checkin<C: C2Transport>(
    c2: &C,
    payload_uuid: Uuid,
) -> MythicResult<RsaStagingResult> {
    use crate::protocol::crypto::{RsaEke, generate_session_id, random_iv};

    let rsa = RsaEke::generate()?;
    let pub_key_b64 = rsa.public_key_b64()?;
    let session_id = generate_session_id();

    let staging_req = ReqStagingRSA::new(pub_key_b64, session_id);

    let initial_key_b64 = c2.get_aes_psk().ok_or(MythicError::KeyExchangeFailed)?;
    let initial_crypto = Aes256HmacCrypto::from_base64_key(&initial_key_b64)?;
    let iv = random_iv()?;

    let packed = encode_message(&staging_req, payload_uuid, &initial_crypto, &iv)?;
    let response = c2.checkin(&packed)?;
    let (_, staging_resp): (Uuid, RespStagingRSA) =
        decode_message(&response, Some(payload_uuid), &initial_crypto)?;

    let crypto = rsa.session_crypto(&staging_resp.session_key)?;

    Ok(RsaStagingResult {
        temp_uuid: staging_resp.uuid,
        crypto,
        packet_sent: packed,
        packet_received: response,
    })
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    // ── ReqCheckin tests ─────────────────────────

    #[test]
    fn checkin_default_is_minimal() {
        let uuid = Uuid::nil();
        let req = ReqCheckin::default(uuid);
        assert_eq!(req.action, ACTION_CHECKIN);
        assert_eq!(req.uuid, uuid);
        assert!(req.ips.is_empty());
        assert!(req.os.is_none());
        assert!(req.user.is_none());
        assert!(req.host.is_none());
        assert!(req.pid.is_none());
        assert!(req.architecture.is_none());
    }

    #[test]
    fn checkin_json_roundtrip() {
        let uuid = Uuid::nil();
        let req = ReqCheckin {
            action: ACTION_CHECKIN.to_string(),
            uuid,
            ips: vec!["127.0.0.1".to_string()],
            os: Some("linux".to_string()),
            user: None,
            host: Some("box".to_string()),
            pid: None,
            architecture: None,
            domain: None,
            integrity_level: None,
            external_ip: None,
            encryption_key: None,
            decryption_key: None,
            process_name: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        let decoded: ReqCheckin = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.action, ACTION_CHECKIN);
        assert_eq!(decoded.uuid, uuid);
        assert_eq!(decoded.ips, vec!["127.0.0.1".to_string()]);
        assert_eq!(decoded.os.as_deref(), Some("linux"));
        assert_eq!(decoded.host.as_deref(), Some("box"));
        assert!(!json.contains("\"user\""));
        assert!(!json.contains("\"pid\""));
    }

    #[test]
    fn checkin_all_fields_roundtrip() {
        let uuid = Uuid::nil();
        let req = ReqCheckin {
            action: ACTION_CHECKIN.to_string(),
            uuid,
            ips: vec!["10.0.0.5".to_string()],
            os: Some("linux".to_string()),
            user: Some("alice".to_string()),
            host: Some("host-a".to_string()),
            pid: Some(1337),
            architecture: Some("x86_64".to_string()),
            domain: Some("corp".to_string()),
            integrity_level: Some(3),
            external_ip: Some("1.2.3.4".to_string()),
            encryption_key: Some("enc".to_string()),
            decryption_key: Some("dec".to_string()),
            process_name: Some("agent".to_string()),
        };

        let json = serde_json::to_string(&req).unwrap();
        let decoded: ReqCheckin = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, req);
        assert!(json.contains("\"encryption_key\":\"enc\""));
        assert!(json.contains("\"process_name\":\"agent\""));
    }

    #[test]
    fn checkin_serializes_as_flat_json() {
        // Must match the official Mythic checkin schema — all fields at top level.
        let req = ReqCheckin {
            action: ACTION_CHECKIN.to_string(),
            uuid: Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap(),
            ips: vec!["10.0.0.1".to_string()],
            os: Some("linux".to_string()),
            user: Some("root".to_string()),
            host: Some("web01".to_string()),
            pid: Some(1337),
            ..Default::default()
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"action\":\"checkin\""));
        assert!(json.contains("\"uuid\":\"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\""));
        assert!(json.contains("\"os\":\"linux\""));
        assert!(json.contains("\"user\":\"root\""));
        assert!(json.contains("\"host\":\"web01\""));
        assert!(json.contains("\"pid\":1337"));
    }
}
