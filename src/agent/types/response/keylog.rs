use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct KeylogEntry {
    pub keystrokes: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_title: Option<String>,
}

impl KeylogEntry {
    pub fn new(keystrokes: impl Into<String>) -> Self {
        Self {
            keystrokes: keystrokes.into(),
            user: None,
            window_title: None,
        }
    }

    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    pub fn with_window_title(mut self, window_title: impl Into<String>) -> Self {
        self.window_title = Some(window_title.into());
        self
    }
}
