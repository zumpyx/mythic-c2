//! Checkin message types — the agent's first message after execution.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::ACTION_CHECKIN;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CheckinInfo {
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

impl CheckinInfo {
    pub fn new() -> Self {
        Self::default()
    }
}

pub trait CheckinInfoSource {
    fn checkin_info(&self) -> CheckinInfo;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReqCheckin {
    pub action: String,
    pub uuid: Uuid,
    #[serde(flatten)]
    pub info: CheckinInfo,
}

impl ReqCheckin {
    pub fn new(uuid: Uuid, info: CheckinInfo) -> Self {
        Self {
            action: ACTION_CHECKIN.to_string(),
            uuid,
            info,
        }
    }

    pub fn minimal(uuid: Uuid) -> Self {
        Self::new(uuid, CheckinInfo::default())
    }

    pub fn from_source<S>(uuid: Uuid, source: &S) -> Self
    where
        S: CheckinInfoSource + ?Sized,
    {
        Self::new(uuid, source.checkin_info())
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};

    struct FixedSource;

    impl CheckinInfoSource for FixedSource {
        fn checkin_info(&self) -> CheckinInfo {
            CheckinInfo {
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
            }
        }
    }

    #[test]
    fn checkin_info_from_source() {
        let uuid = Uuid::nil();
        let req = ReqCheckin::from_source(uuid, &FixedSource);

        assert_eq!(req.action, ACTION_CHECKIN);
        assert_eq!(req.uuid, uuid);
        assert_eq!(req.info.ips, vec!["10.0.0.5".to_string()]);
        assert_eq!(req.info.os.as_deref(), Some("linux"));
        assert_eq!(req.info.user.as_deref(), Some("alice"));
        assert_eq!(req.info.host.as_deref(), Some("host-a"));
        assert_eq!(req.info.pid, Some(1337));
        assert_eq!(req.info.architecture.as_deref(), Some("x86_64"));
        assert_eq!(req.info.domain.as_deref(), Some("corp"));
        assert_eq!(req.info.integrity_level, Some(3));
        assert_eq!(req.info.external_ip.as_deref(), Some("1.2.3.4"));
        assert_eq!(req.info.encryption_key.as_deref(), Some("enc"));
        assert_eq!(req.info.decryption_key.as_deref(), Some("dec"));
        assert_eq!(req.info.process_name.as_deref(), Some("agent"));
    }

    #[test]
    fn checkin_info_default_is_empty() {
        let uuid = Uuid::nil();
        let req = ReqCheckin::minimal(uuid);

        assert_eq!(req.action, ACTION_CHECKIN);
        assert_eq!(req.uuid, uuid);
        assert!(req.info.ips.is_empty());
        assert!(req.info.os.is_none());
        assert!(req.info.user.is_none());
        assert!(req.info.host.is_none());
        assert!(req.info.pid.is_none());
        assert!(req.info.architecture.is_none());
    }

    #[test]
    fn checkin_info_new_is_default() {
        let info = CheckinInfo::new();
        assert!(info.ips.is_empty());
        assert!(info.os.is_none());
        assert!(info.process_name.is_none());
    }

    #[test]
    fn checkin_json_roundtrip() {
        let uuid = Uuid::nil();
        let req = ReqCheckin::new(
            uuid,
            CheckinInfo {
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
            },
        );

        let json = serde_json::to_string(&req).unwrap();
        let decoded: ReqCheckin = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.action, ACTION_CHECKIN);
        assert_eq!(decoded.uuid, uuid);
        assert_eq!(decoded.info.ips, vec!["127.0.0.1".to_string()]);
        assert_eq!(decoded.info.os.as_deref(), Some("linux"));
        assert_eq!(decoded.info.host.as_deref(), Some("box"));
        assert!(!json.contains("\"user\""));
        assert!(!json.contains("\"pid\""));
    }
}
