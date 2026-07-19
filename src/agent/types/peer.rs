//! P2P and auxiliary message types — delegates, SOCKS, reverse port forward,
//! interactive tasking, alerts, and edges.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Delegate {
    pub message: String,
    /// Required in agent-to-Mythic delegate messages; absent in Mythic-to-agent responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub c2_profile: Option<String>,
    pub uuid: String,
}

impl Delegate {
    pub fn new(message: impl Into<String>, uuid: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            uuid: uuid.into(),
            c2_profile: None,
        }
    }

    pub fn with_c2_profile(mut self, c2_profile: impl Into<String>) -> Self {
        self.c2_profile = Some(c2_profile.into());
        self
    }
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

impl EdgeMessage {
    pub fn new(
        source: impl Into<String>,
        destination: impl Into<String>,
        action: impl Into<String>,
        c2_profile: impl Into<String>,
    ) -> Self {
        Self {
            source: source.into(),
            destination: destination.into(),
            action: action.into(),
            c2_profile: c2_profile.into(),
            metadata: None,
        }
    }

    pub fn with_metadata(mut self, metadata: impl Into<String>) -> Self {
        self.metadata = Some(metadata.into());
        self
    }
}

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

impl AlertMessage {
    pub fn new(alert: impl Into<String>) -> Self {
        Self {
            alert: Some(alert.into()),
            ..Default::default()
        }
    }

    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    pub fn with_level(mut self, level: impl Into<String>) -> Self {
        self.level = Some(level.into());
        self
    }

    pub fn with_webhook(mut self, send: bool, alert: Value) -> Self {
        self.send_webhook = Some(send);
        self.webhook_alert = Some(alert);
        self
    }
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

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SocksMessage {
    pub server_id: u32,
    pub exit: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

impl SocksMessage {
    pub fn new(server_id: u32, exit: bool) -> Self {
        Self {
            server_id,
            exit,
            data: None,
        }
    }

    pub fn with_data(mut self, data: impl Into<String>) -> Self {
        self.data = Some(data.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct RpfwdMessage {
    pub server_id: u32,
    pub exit: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// Optional — required when the agent listens on multiple rpfwd ports so
    /// Mythic can route data to the correct remote IP:Port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u32>,
}

impl RpfwdMessage {
    pub fn new(server_id: u32, exit: bool) -> Self {
        Self {
            server_id,
            exit,
            data: None,
            port: None,
        }
    }

    pub fn with_data(mut self, data: impl Into<String>) -> Self {
        self.data = Some(data.into());
        self
    }

    pub fn with_port(mut self, port: u32) -> Self {
        self.port = Some(port);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct InteractiveMessage {
    pub task_id: String,
    pub data: String,
    pub message_type: u8,
}

impl InteractiveMessage {
    pub fn new(task_id: impl Into<String>, data: impl Into<String>, message_type: u8) -> Self {
        Self {
            task_id: task_id.into(),
            data: data.into(),
            message_type,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_messages_roundtrip() {
        let delegate = Delegate::new("msg", "uuid").with_c2_profile("p2p");

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

        let edge = EdgeMessage::new("src", "dst", "link", "http").with_metadata("{}");

        let socks = SocksMessage::new(9, false).with_data("d");

        let rpfwd = RpfwdMessage::new(3, true).with_port(80);

        let interactive = InteractiveMessage::new("task-uuid", "abc", 1);

        assert_eq!(
            serde_json::from_str::<Delegate>(&serde_json::to_string(&delegate).unwrap()).unwrap(),
            delegate
        );
        assert_eq!(
            serde_json::from_str::<EdgeMessage>(&serde_json::to_string(&edge).unwrap()).unwrap(),
            edge
        );
        assert_eq!(
            serde_json::from_str::<SocksMessage>(&serde_json::to_string(&socks).unwrap()).unwrap(),
            socks
        );
        assert_eq!(
            serde_json::from_str::<RpfwdMessage>(&serde_json::to_string(&rpfwd).unwrap()).unwrap(),
            rpfwd
        );
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
    }
}
