use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Artifact {
    pub base_artifact: String,
    pub artifact: String,
    #[serde(default)]
    pub needs_cleanup: bool,
    #[serde(default)]
    pub resolved: bool,
}

impl Artifact {
    pub fn new(
        base_artifact: impl Into<String>,
        artifact: impl Into<String>,
    ) -> Self {
        Self {
            base_artifact: base_artifact.into(),
            artifact: artifact.into(),
            needs_cleanup: false,
            resolved: false,
        }
    }
}
