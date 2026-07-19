use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Upload {
    pub file_id: String,
    pub chunk_size: u32,
    /// 1-based chunk number the agent is requesting.
    pub chunk_num: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_path: Option<String>,
}

impl Upload {
    pub fn new(file_id: impl Into<String>, chunk_size: u32, chunk_num: u32) -> Self {
        Self {
            file_id: file_id.into(),
            chunk_size,
            chunk_num,
            host: None,
            full_path: None,
        }
    }

    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    pub fn with_full_path(mut self, full_path: impl Into<String>) -> Self {
        self.full_path = Some(full_path.into());
        self
    }
}

impl Default for Upload {
    fn default() -> Self {
        Self {
            file_id: String::new(),
            chunk_size: 512000,
            chunk_num: 1,
            host: None,
            full_path: None,
        }
    }
}
