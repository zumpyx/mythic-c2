//! Post-response message types — delivering task output back to Mythic.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    ACTION_POST_RESPONSE,
    get_tasking::{AgentMessageExtras, AgentResponseExtras, TaskResponse},
};

// ── Response receipt ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ResponseReceipt {
    pub task_id: Uuid,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ── Post-response request / response ──────────────────────

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
                shared: super::get_tasking::AgentExtras::default(),
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

// ── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn post_response_wraps_responses() {
        let task_id = Uuid::nil();
        let req = ReqPostResponse::new(vec![TaskResponse::completed(task_id, "ok")]);

        assert_eq!(req.action, ACTION_POST_RESPONSE);
        assert_eq!(req.extras.responses.len(), 1);
        assert_eq!(req.extras.responses[0].task_id, task_id);
        assert_eq!(req.extras.responses[0].status.as_deref(), Some("completed"));
    }

    #[test]
    fn receipt_roundtrip() {
        let uuid = Uuid::nil();
        let receipt = ResponseReceipt {
            task_id: uuid,
            status: "sent".to_string(),
            file_id: Some(Uuid::from_u128(1)),
            error: Some("none".to_string()),
        };
        assert_eq!(
            serde_json::from_str::<ResponseReceipt>(&serde_json::to_string(&receipt).unwrap())
                .unwrap(),
            receipt
        );
    }

    #[test]
    fn resp_post_response_roundtrip() {
        let uuid = Uuid::nil();
        let next_uuid = Uuid::from_u128(1);
        let resp = RespPostResponse {
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
            serde_json::from_str::<RespPostResponse>(&serde_json::to_string(&resp).unwrap())
                .unwrap(),
            resp
        );
    }
}
