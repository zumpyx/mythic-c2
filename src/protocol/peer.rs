//! P2P and auxiliary message types — delegates, SOCKS, reverse port forward,
//! interactive tasking, alerts, and edges.

use alloc::string::{String, ToString};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DelegateMessage {
    pub message: String,
    /// Required in agent-to-Mythic delegate messages; absent in Mythic-to-agent responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub c2_profile: Option<String>,
    pub uuid: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "new_uuid")]
    pub mythic_uuid: Option<Uuid>,
}

pub type P2PMessage = DelegateMessage;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AlertMessage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default = "default_alert_level", skip_serializing_if = "is_warning")]
    pub level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_webhook: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_alert: Option<Value>,
}

impl Default for AlertMessage {
    fn default() -> Self {
        Self {
            source: None,
            level: default_alert_level(),
            alert: None,
            send_webhook: None,
            webhook_alert: None,
        }
    }
}

fn default_alert_level() -> Option<String> {
    Some("warning".to_string())
}

fn is_warning(level: &Option<String>) -> bool {
    matches!(level.as_deref(), Some("warning"))
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct EdgeMessage {
    pub source: String,
    pub destination: String,
    pub action: String,
    pub c2_profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SocksMessage {
    pub server_id: u32,
    pub exit: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ReversePortForwardMessage {
    pub server_id: u32,
    pub exit: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// Optional — required when the agent listens on multiple rpfwd ports so
    /// Mythic can route data to the correct remote IP:Port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u32>,
}

pub type RpfwdMessage = ReversePortForwardMessage;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct InteractiveMessage {
    pub task_id: Uuid,
    pub data: String,
    pub message_type: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn peer_messages_roundtrip() {
        let uuid = Uuid::nil();
        let next_uuid = Uuid::from_u128(1);

        let delegate = DelegateMessage {
            message: "msg".to_string(),
            c2_profile: Some("p2p".to_string()),
            uuid,
            mythic_uuid: Some(next_uuid),
        };
        assert_eq!(
            serde_json::from_str::<DelegateMessage>(&serde_json::to_string(&delegate).unwrap())
                .unwrap(),
            delegate
        );

        let alert = AlertMessage {
            source: Some("src".to_string()),
            level: Some("low".to_string()),
            alert: Some("warn".to_string()),
            send_webhook: Some(true),
            webhook_alert: Some(serde_json::json!({"a": 1})),
        };
        assert_eq!(
            serde_json::from_str::<AlertMessage>(&serde_json::to_string(&alert).unwrap()).unwrap(),
            alert
        );

        let edge = EdgeMessage {
            source: "src".to_string(),
            destination: "dst".to_string(),
            action: "link".to_string(),
            c2_profile: "http".to_string(),
            metadata: Some("{}".to_string()),
        };
        assert_eq!(
            serde_json::from_str::<EdgeMessage>(&serde_json::to_string(&edge).unwrap()).unwrap(),
            edge
        );

        let socks = SocksMessage {
            server_id: 9,
            exit: false,
            data: Some("d".to_string()),
        };
        assert_eq!(
            serde_json::from_str::<SocksMessage>(&serde_json::to_string(&socks).unwrap()).unwrap(),
            socks
        );

        let rpfwd = ReversePortForwardMessage {
            server_id: 3,
            exit: true,
            data: None,
            port: Some(80),
        };
        assert_eq!(
            serde_json::from_str::<ReversePortForwardMessage>(
                &serde_json::to_string(&rpfwd).unwrap()
            )
            .unwrap(),
            rpfwd
        );

        let interactive = InteractiveMessage {
            task_id: next_uuid,
            data: "abc".to_string(),
            message_type: 1,
        };
        assert_eq!(
            serde_json::from_str::<InteractiveMessage>(
                &serde_json::to_string(&interactive).unwrap()
            )
            .unwrap(),
            interactive
        );

        let minimal_alert: AlertMessage = serde_json::from_str(r#"{"alert":"hello"}"#).unwrap();
        assert_eq!(minimal_alert.alert.as_deref(), Some("hello"));
        assert!(minimal_alert.source.is_none());
        assert_eq!(minimal_alert.level.as_deref(), Some("warning"));

        let socks_json: SocksMessage =
            serde_json::from_str(r#"{"server_id":1,"exit":true}"#).unwrap();
        assert!(socks_json.exit);
        assert!(socks_json.data.is_none());

        let rpfwd_json: ReversePortForwardMessage =
            serde_json::from_str(r#"{"server_id":2,"exit":false,"data":"YQ"}"#).unwrap();
        assert!(!rpfwd_json.exit);
        assert_eq!(rpfwd_json.data.as_deref(), Some("YQ"));
        assert!(rpfwd_json.port.is_none());

        let rpfwd_with_port: ReversePortForwardMessage =
            serde_json::from_str(r#"{"server_id":3,"exit":true,"data":"","port":445}"#).unwrap();
        assert_eq!(rpfwd_with_port.port, Some(445));
    }
}
