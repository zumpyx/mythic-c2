use serde::{Deserialize, Serialize};

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

impl ProcessEntry {
    pub fn new(process_id: i64, name: impl Into<String>, host: impl Into<String>) -> Self {
        Self {
            process_id,
            name: name.into(),
            host: host.into(),
            ..Default::default()
        }
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}
