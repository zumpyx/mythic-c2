use serde::{Deserialize, Serialize};
use serde_json::Value;

/// File-browser entry for a directory or file.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct FileBrowser {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub is_file: bool,
    /// Platform-specific permission object. Kept as [`Value`] so agents can
    /// send arbitrary permission structures (Windows ACLs, Unix octals, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Value>,
    pub name: String,
    pub parent_path: String,
    pub success: bool,
    pub access_time: i64,
    pub modify_time: i64,
    pub size: i64,
    pub update_deleted: bool,
    pub files: Vec<File>,
}

impl FileBrowser {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        is_file: bool,
        permissions: Option<Value>,
        name: String,
        parent_path: String,
        success: bool,
        access_time: i64,
        modify_time: i64,
        size: i64,
        update_deleted: bool,
        files: Vec<File>,
    ) -> Self {
        Self {
            host: None,
            is_file,
            permissions,
            name,
            parent_path,
            success,
            access_time,
            modify_time,
            size,
            update_deleted,
            files,
        }
    }

    /// Attach a permission map, e.g. `{"read": true, "write": false}`.
    pub fn with_permissions(mut self, permissions: Value) -> Self {
        self.permissions = Some(permissions);
        self
    }
}

/// Child file/directory entry inside a [`FileBrowser`].
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct File {
    pub is_file: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Value>,
    pub name: String,
    pub access_time: i64,
    pub modify_time: i64,
    pub size: i64,
}

impl File {
    pub fn new(
        is_file: bool,
        permissions: Option<Value>,
        name: impl Into<String>,
        access_time: i64,
        modify_time: i64,
        size: i64,
    ) -> Self {
        Self {
            is_file,
            permissions,
            name: name.into(),
            access_time,
            modify_time,
            size,
        }
    }

    pub fn with_permissions(mut self, permissions: Value) -> Self {
        self.permissions = Some(permissions);
        self
    }
}

/// A file that was removed by a task.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct RemovedFile {
    pub host: String,
    pub path: String,
}

impl RemovedFile {
    pub fn new(host: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            path: path.into(),
        }
    }
}
