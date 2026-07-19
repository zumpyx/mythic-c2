use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct TokenEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileges: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logon_sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_level_sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restricted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_dacl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_container_sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_container_number: Option<i64>,
}

impl TokenEntry {
    pub fn new(token_id: i64, user: impl Into<String>) -> Self {
        Self {
            token_id: Some(token_id),
            user: Some(user.into()),
            ..Default::default()
        }
    }

    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    pub fn with_groups(mut self, groups: impl Into<String>) -> Self {
        self.groups = Some(groups.into());
        self
    }

    pub fn with_privileges(mut self, privileges: impl Into<String>) -> Self {
        self.privileges = Some(privileges.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct CallbackToken {
    pub action: String,
    pub host: String,
    pub token_id: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<TokenEntry>,
}

impl CallbackToken {
    pub fn new(
        action: impl Into<String>,
        host: impl Into<String>,
        token_id: i64,
    ) -> Self {
        Self {
            action: action.into(),
            host: host.into(),
            token_id,
            token: None,
        }
    }

    pub fn with_token(mut self, token: TokenEntry) -> Self {
        self.token = Some(token);
        self
    }
}
