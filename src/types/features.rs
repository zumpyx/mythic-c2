//! Nested types used by hooking features.

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "json")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "json")]
use serde_json::Value;

/// P2P delegate message.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct Delegate {
    pub message: String,
    pub c2_profile: String,
    pub uuid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_uuid: Option<String>,
}

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
    pub action: String,
    pub c2_profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct CommandUpdate {
    pub action: String,
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
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub token_id: u32,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct Download {
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
    pub level: String,
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
