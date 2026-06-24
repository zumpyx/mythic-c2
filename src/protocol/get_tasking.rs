//! Get-tasking message types — polling for new tasks, plus task/response/hooking
//! types shared with [`super::post_response`].

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    string::{String, ToString},
    vec::Vec,
};
use uuid::Uuid;

use super::{
    ACTION_GET_TASKING,
    peer::{
        AlertMessage, DelegateMessage, EdgeMessage, InteractiveMessage, ReversePortForwardMessage,
        SocksMessage,
    },
};

fn default_tasking_size() -> i32 {
    1
}

fn default_get_delegate_tasks() -> bool {
    true
}

fn default_is_screenshot() -> bool {
    false
}

fn is_false(value: &bool) -> bool {
    !*value
}

// ── Shared extras ─────────────────────────────────────────

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

/// Extras that an agent can attach to any request message.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct AgentMessageExtras {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub responses: Vec<TaskResponse>,
    #[serde(flatten)]
    pub shared: AgentExtras,
}

/// Extras that Mythic can attach to any response message.
pub type AgentResponseExtras = AgentExtras;

// ── Get-tasking request / response ────────────────────────

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

    /// Build a `get_tasking` request carrying delegates, SOCKS, RPFWD,
    /// interactive data, edges, alerts, and/or responses.
    pub fn with_extras(tasking_size: i32, extras: AgentMessageExtras) -> Self {
        Self {
            action: ACTION_GET_TASKING.to_string(),
            tasking_size,
            get_delegate_tasks: true,
            extras,
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

// ── TaskMessage ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct TaskMessage {
    pub command: String,
    pub parameters: String,
    pub timestamp: f64,
    pub id: Uuid,
}

// ── TaskResponse and hooking feature types ─────────────────

/// Task output sent by the agent.  All fields are optional except `task_id` so
/// an agent can send back only what it needs (user output, file chunk, SOCKS
/// data, etc.).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct TaskResponse {
    pub task_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_output: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_response: Option<Value>,

    // ── File transfer ──────────────────────────
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download: Option<TaskDownload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload: Option<TaskUpload>,

    // ── Hooking features ───────────────────────
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_browser: Option<FileBrowserEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<Credential>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<Artifact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub processes: Vec<ProcessEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<CommandAction>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keylogs: Vec<KeylogEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tokens: Vec<TokenEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callback_tokens: Vec<CallbackToken>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_files: Vec<RemovedFileInfo>,

    // ── P2P / proxy ────────────────────────────
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alerts: Vec<AlertMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edges: Vec<EdgeMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub socks: Vec<SocksMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rpfwd: Vec<ReversePortForwardMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interactive: Vec<InteractiveMessage>,
}

impl TaskResponse {
    pub fn completed(task_id: Uuid, user_output: &str) -> Self {
        Self {
            task_id,
            completed: Some(true),
            status: Some("success".into()),
            user_output: Some(user_output.into()),
            ..Default::default()
        }
    }

    pub fn failed(task_id: Uuid, error: &str) -> Self {
        Self {
            task_id,
            completed: Some(true),
            status: Some("error".into()),
            user_output: Some(error.into()),
            ..Default::default()
        }
    }
}

// ── File transfer types ────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct TaskDownload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_chunks: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default = "default_is_screenshot", skip_serializing_if = "is_false")]
    pub is_screenshot: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_num: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_data: Option<String>,
}

/// Agent-to-Mythic file chunk request (agent pulls a file from the server).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct TaskUpload {
    pub chunk_size: u32,
    pub file_id: Uuid,
    /// 1-based chunk number the agent is requesting.
    pub chunk_num: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

// ── Hooking feature types ──────────────────────────────────

/// File/directory entry for file browser results.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct FileBrowserEntry {
    pub is_file: bool,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modify_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub update_deleted: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub set_as_user_output: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<FileBrowserEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Credential {
    pub credential_type: String,
    pub credential: String,
    pub account: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Artifact {
    pub base_artifact: String,
    pub artifact: String,
    #[serde(default)]
    pub needs_cleanup: bool,
    #[serde(default)]
    pub resolved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ProcessEntry {
    pub process_id: i64,
    pub name: String,
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_process_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bin_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_level: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected_process_level: Option<i32>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub update_deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CommandAction {
    pub action: String,
    pub cmd: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct KeylogEntry {
    pub keystrokes: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct TokenEntry {
    pub token_id: i64,
    pub host: String,
    pub user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_dacl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restricted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logon_sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_level_sid: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_container_number: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_container_sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileges: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CallbackToken {
    pub action: String,
    pub host: String,
    pub token_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct RemovedFileInfo {
    pub host: String,
    pub path: String,
}

// ── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::{string::ToString, vec};

    use crate::protocol::peer::{
        AlertMessage, EdgeMessage, InteractiveMessage, ReversePortForwardMessage, SocksMessage,
    };

    #[test]
    fn get_tasking_defaults_are_correct() {
        let req = ReqGetTasking::new(9);
        let req_all = ReqGetTasking::new(-1);
        let req_without = ReqGetTasking::with_delegate_tasks(3, false);

        assert_eq!(req.action, ACTION_GET_TASKING);
        assert_eq!(req.tasking_size, 9);
        assert_eq!(req_all.tasking_size, -1);
        assert!(req.get_delegate_tasks);
        assert!(!req_without.get_delegate_tasks);
    }

    #[test]
    fn extras_roundtrip() {
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
    }

    #[test]
    fn resp_get_tasking_roundtrip() {
        let uuid = Uuid::nil();
        let resp = RespGetTasking {
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
            serde_json::from_str::<RespGetTasking>(&serde_json::to_string(&resp).unwrap()).unwrap(),
            resp
        );
    }

    #[test]
    fn task_response_default_is_empty() {
        let resp = TaskResponse::default();
        assert!(resp.user_output.is_none());
        assert!(resp.download.is_none());
        assert!(resp.upload.is_none());
        assert!(resp.file_browser.is_none());
        assert!(resp.credentials.is_empty());
        assert!(resp.artifacts.is_empty());
        assert!(resp.processes.is_empty());
        assert!(resp.commands.is_empty());
        assert!(resp.keylogs.is_empty());
        assert!(resp.tokens.is_empty());
        assert!(resp.callback_tokens.is_empty());
        assert!(resp.removed_files.is_empty());
    }

    #[test]
    fn task_models_roundtrip() {
        let uuid = Uuid::nil();

        let task_message = TaskMessage {
            command: "ls".to_string(),
            parameters: "-la".to_string(),
            timestamp: 1.5,
            id: uuid,
        };
        assert_eq!(
            serde_json::from_str::<TaskMessage>(&serde_json::to_string(&task_message).unwrap())
                .unwrap(),
            task_message
        );

        let task_download = TaskDownload {
            total_chunks: Some(2),
            chunk_size: Some(64),
            filename: Some("out.txt".to_string()),
            full_path: Some("/tmp/out.txt".to_string()),
            host: Some("host-a".to_string()),
            is_screenshot: false,
            file_id: None,
            chunk_num: None,
            chunk_data: None,
        };
        assert_eq!(
            serde_json::from_str::<TaskDownload>(&serde_json::to_string(&task_download).unwrap())
                .unwrap(),
            task_download
        );

        let task_upload = TaskUpload {
            chunk_size: 512000,
            file_id: uuid,
            chunk_num: 1,
            full_path: Some("/tmp/target".into()),
            host: Some("host-a".into()),
        };
        assert_eq!(
            serde_json::from_str::<TaskUpload>(&serde_json::to_string(&task_upload).unwrap())
                .unwrap(),
            task_upload
        );

        let file_entry = FileBrowserEntry {
            is_file: false,
            name: "dir".into(),
            host: Some("h".into()),
            parent_path: Some("/".into()),
            success: Some(true),
            permissions: Some(serde_json::json!({"x": 1})),
            files: vec![FileBrowserEntry {
                is_file: true,
                name: "f.txt".into(),
                size: Some(100),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            serde_json::from_str::<FileBrowserEntry>(&serde_json::to_string(&file_entry).unwrap())
                .unwrap(),
            file_entry
        );

        let credential = Credential {
            credential_type: "plaintext".into(),
            credential: "pass123".into(),
            account: "admin".into(),
            realm: Some("DOMAIN".into()),
            comment: None,
        };
        assert_eq!(
            serde_json::from_str::<Credential>(&serde_json::to_string(&credential).unwrap())
                .unwrap(),
            credential
        );

        let artifact = Artifact {
            base_artifact: "Process Create".into(),
            artifact: "sh -c whoami".into(),
            needs_cleanup: false,
            resolved: false,
        };
        assert_eq!(
            serde_json::from_str::<Artifact>(&serde_json::to_string(&artifact).unwrap()).unwrap(),
            artifact
        );

        let process = ProcessEntry {
            process_id: 12345,
            name: "evil.exe".into(),
            host: "a.b.com".into(),
            parent_process_id: Some(1234),
            architecture: Some("x64".into()),
            user: Some("bob".into()),
            ..Default::default()
        };
        assert_eq!(
            serde_json::from_str::<ProcessEntry>(&serde_json::to_string(&process).unwrap())
                .unwrap(),
            process
        );

        let cmd = CommandAction {
            action: "add".into(),
            cmd: "shell".into(),
        };
        assert_eq!(
            serde_json::from_str::<CommandAction>(&serde_json::to_string(&cmd).unwrap()).unwrap(),
            cmd
        );

        let keylog = KeylogEntry {
            keystrokes: "password123".into(),
            user: Some("alice".into()),
            window_title: Some("Notepad".into()),
        };
        assert_eq!(
            serde_json::from_str::<KeylogEntry>(&serde_json::to_string(&keylog).unwrap()).unwrap(),
            keylog
        );

        let token = TokenEntry {
            token_id: 18947,
            host: "bob.com".into(),
            user: "bob".into(),
            process_id: Some(2345),
            ..Default::default()
        };
        assert_eq!(
            serde_json::from_str::<TokenEntry>(&serde_json::to_string(&token).unwrap()).unwrap(),
            token
        );

        let cb_token = CallbackToken {
            action: "add".into(),
            host: "a.b.com".into(),
            token_id: 12345,
        };
        assert_eq!(
            serde_json::from_str::<CallbackToken>(&serde_json::to_string(&cb_token).unwrap())
                .unwrap(),
            cb_token
        );

        let removed = RemovedFileInfo {
            host: "h".into(),
            path: "/tmp/f".into(),
        };
        assert_eq!(
            serde_json::from_str::<RemovedFileInfo>(&serde_json::to_string(&removed).unwrap())
                .unwrap(),
            removed
        );

        let chunk_download = TaskDownload {
            total_chunks: None,
            chunk_size: None,
            filename: None,
            full_path: None,
            host: None,
            is_screenshot: true,
            file_id: Some(Uuid::from_u128(3)),
            chunk_num: Some(1),
            chunk_data: Some("cGFydA".to_string()),
        };
        assert_eq!(
            serde_json::from_str::<TaskDownload>(&serde_json::to_string(&chunk_download).unwrap())
                .unwrap(),
            chunk_download
        );

        // Full TaskResponse roundtrip with all hooking features populated
        let full_response = TaskResponse {
            task_id: uuid,
            completed: Some(true),
            status: Some("done".into()),
            user_output: Some("ok".into()),
            process_response: Some(serde_json::json!({"k": "v"})),
            download: Some(task_download.clone()),
            upload: Some(task_upload.clone()),
            file_browser: Some(file_entry.clone()),
            credentials: vec![credential.clone()],
            artifacts: vec![artifact.clone()],
            processes: vec![process.clone()],
            commands: vec![cmd.clone()],
            keylogs: vec![keylog.clone()],
            tokens: vec![token.clone()],
            callback_tokens: vec![cb_token.clone()],
            removed_files: vec![removed.clone()],
            alerts: vec![AlertMessage {
                source: Some("a".into()),
                level: Some("info".into()),
                alert: Some("note".into()),
                send_webhook: Some(false),
                webhook_alert: Some(serde_json::json!({"x": 1})),
            }],
            edges: vec![EdgeMessage {
                source: "src".into(),
                destination: "dst".into(),
                action: "add".into(),
                c2_profile: "http".into(),
                metadata: Some("meta".into()),
            }],
            socks: vec![SocksMessage {
                server_id: 1,
                exit: false,
                data: Some("d".into()),
            }],
            rpfwd: vec![ReversePortForwardMessage {
                server_id: 2,
                exit: true,
                data: None,
                port: None,
            }],
            interactive: vec![InteractiveMessage {
                task_id: uuid,
                data: "stdin".into(),
                message_type: 7,
            }],
        };
        assert_eq!(
            serde_json::from_str::<TaskResponse>(&serde_json::to_string(&full_response).unwrap())
                .unwrap(),
            full_response
        );
    }
}
