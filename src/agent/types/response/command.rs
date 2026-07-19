use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CommandAction {
    pub action: String,
    pub cmd: String,
}

impl CommandAction {
    pub fn new(action: impl Into<String>, cmd: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            cmd: cmd.into(),
        }
    }
}
