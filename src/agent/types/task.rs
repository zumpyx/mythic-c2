//! Task message dispatched by Mythic to the agent.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct TaskMessage {
    pub command: String,
    pub parameters: String,
    pub timestamp: i64,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<i64>,
}

impl TaskMessage {
    pub fn new(command: String, parameters: String, id: String) -> Self {
        Self {
            command,
            parameters,
            timestamp: 0,
            id,
            token: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_message_token_roundtrip() {
        let task = TaskMessage {
            command: "shell".into(),
            parameters: "{\"str\":\"whoami\"}".to_string(),
            timestamp: 1,
            id: "".to_string(),
            token: Some(12345),
        };
        let json = serde_json::to_string(&task).unwrap();
        assert!(json.contains("\"token\":12345"));
        assert_eq!(serde_json::from_str::<TaskMessage>(&json).unwrap(), task);

        let no_token = TaskMessage {
            token: None,
            ..task.clone()
        };
        let json_no_token = serde_json::to_string(&no_token).unwrap();
        assert!(!json_no_token.contains("token"));
    }
}
