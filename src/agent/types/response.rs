//! Per-task response payload used inside `get_tasking` / `post_response` messages.
//!
//! A [`Response`] is the unit of task output an agent sends back to Mythic.
//! It can carry plain text output, file-transfer metadata, hooking-feature
//! data (credentials, processes, keystrokes, etc.), and P2P/proxy traffic.
//! For complex responses use [`ResponseBuilder`].

mod artifact;
mod command;
mod cred;
mod download;
mod file;
mod keylog;
mod process;
mod token;
mod upload;

pub use artifact::Artifact;
pub use command::CommandAction;
pub use cred::Credential;
pub use download::Download;
pub use file::{File, FileBrowser, RemovedFile};
pub use keylog::KeylogEntry;
pub use process::ProcessEntry;
pub use token::{CallbackToken, TokenEntry};
pub use upload::Upload;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::peer::{AlertMessage, EdgeMessage, InteractiveMessage, RpfwdMessage, SocksMessage};

/// Task output sent by the agent. All hooking-feature fields are optional so
/// an agent can send back only what it needs.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Response {
    pub task_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_output: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    // ── Hooking features ───────────────────────
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_browser: Option<FileBrowser>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_files: Vec<RemovedFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<Credential>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<Artifact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub processes: Vec<ProcessEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<CommandAction>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keylogs: Vec<KeylogEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tokens: Vec<TokenEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callback_tokens: Vec<CallbackToken>,

    // ── File transfer ──────────────────────────
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download: Option<Download>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload: Option<Upload>,

    // ── P2P / proxy / custom ───────────────────
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alerts: Vec<AlertMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edges: Vec<EdgeMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub socks: Vec<SocksMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rpfwd: Vec<RpfwdMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interactive: Vec<InteractiveMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_response: Option<Value>,
}

impl Response {
    pub fn new(task_id: impl Into<String>) -> Self {
        Self {
            task_id: task_id.into(),
            ..Default::default()
        }
    }

    pub fn completed(task_id: impl Into<String>, user_output: &str) -> Self {
        Self {
            task_id: task_id.into(),
            completed: Some(true),
            status: Some("success".into()),
            user_output: Some(user_output.into()),
            ..Default::default()
        }
    }

    pub fn failed(task_id: impl Into<String>, error: &str) -> Self {
        Self {
            task_id: task_id.into(),
            completed: Some(true),
            status: Some("error".into()),
            user_output: Some(error.into()),
            ..Default::default()
        }
    }

    /// Returns `true` if the agent marked this task as completed.
    pub fn is_completed(&self) -> bool {
        self.completed.unwrap_or(false)
    }

    /// Returns `true` when [`status`](Self::status) is `"success"`.
    pub fn is_success(&self) -> bool {
        self.status.as_deref() == Some("success")
    }

    /// Returns `true` when [`status`](Self::status) is `"error"`.
    pub fn is_error(&self) -> bool {
        self.status.as_deref() == Some("error")
    }
}

/// Fluent builder for complex [`Response`] objects.
///
/// # Example
///
/// ```rust
/// use mythic::protocol::types::{ResponseBuilder, Credential, ProcessEntry};
///
/// let resp = ResponseBuilder::new("task-uuid")
///     .user_output("done")
///     .completed()
///     .credential(Credential::new("plaintext", "admin", "pass123"))
///     .process(ProcessEntry::new(1234, "evil.exe", "host"))
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ResponseBuilder {
    response: Response,
}

impl ResponseBuilder {
    pub fn new(task_id: impl Into<String>) -> Self {
        Self {
            response: Response::new(task_id),
        }
    }

    pub fn user_output(mut self, output: impl Into<String>) -> Self {
        self.response.user_output = Some(output.into());
        self
    }

    /// Mark the task as completed with status `"success"`.
    pub fn completed(mut self) -> Self {
        self.response.completed = Some(true);
        self.response.status = Some("success".into());
        self
    }

    /// Mark the task as completed with status `"error"`.
    pub fn failed(mut self) -> Self {
        self.response.completed = Some(true);
        self.response.status = Some("error".into());
        self
    }

    pub fn status(mut self, status: impl Into<String>) -> Self {
        self.response.status = Some(status.into());
        self
    }

    pub fn file_browser(mut self, file_browser: FileBrowser) -> Self {
        self.response.file_browser = Some(file_browser);
        self
    }

    pub fn removed_file(mut self, removed_file: RemovedFile) -> Self {
        self.response.removed_files.push(removed_file);
        self
    }

    pub fn credential(mut self, credential: Credential) -> Self {
        self.response.credentials.push(credential);
        self
    }

    pub fn artifact(mut self, artifact: Artifact) -> Self {
        self.response.artifacts.push(artifact);
        self
    }

    pub fn process(mut self, process: ProcessEntry) -> Self {
        self.response.processes.push(process);
        self
    }

    pub fn command(mut self, command: CommandAction) -> Self {
        self.response.commands.push(command);
        self
    }

    pub fn keylog(mut self, keylog: KeylogEntry) -> Self {
        self.response.keylogs.push(keylog);
        self
    }

    pub fn token(mut self, token: TokenEntry) -> Self {
        self.response.tokens.push(token);
        self
    }

    pub fn callback_token(mut self, callback_token: CallbackToken) -> Self {
        self.response.callback_tokens.push(callback_token);
        self
    }

    pub fn download(mut self, download: Download) -> Self {
        self.response.download = Some(download);
        self
    }

    pub fn upload(mut self, upload: Upload) -> Self {
        self.response.upload = Some(upload);
        self
    }

    pub fn alert(mut self, alert: AlertMessage) -> Self {
        self.response.alerts.push(alert);
        self
    }

    pub fn edge(mut self, edge: EdgeMessage) -> Self {
        self.response.edges.push(edge);
        self
    }

    pub fn socks(mut self, socks: SocksMessage) -> Self {
        self.response.socks.push(socks);
        self
    }

    pub fn rpfwd(mut self, rpfwd: RpfwdMessage) -> Self {
        self.response.rpfwd.push(rpfwd);
        self
    }

    pub fn interactive(mut self, interactive: InteractiveMessage) -> Self {
        self.response.interactive.push(interactive);
        self
    }

    pub fn process_response(mut self, process_response: Value) -> Self {
        self.response.process_response = Some(process_response);
        self
    }

    pub fn build(self) -> Response {
        self.response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    #[test]
    fn response_default_is_empty() {
        let resp = Response::default();
        assert!(resp.user_output.is_none());
        assert!(resp.download.is_none());
        assert!(resp.upload.is_none());
        assert!(resp.file_browser.is_none());
        assert!(resp.credentials.is_empty());
        assert!(resp.artifacts.is_empty());
        assert!(resp.processes.is_empty());
        assert!(resp.commands.is_empty());
        assert!(resp.keylogs.is_empty());
        assert!(resp.tokens.is_empty());
        assert!(resp.callback_tokens.is_empty());
        assert!(resp.removed_files.is_empty());
        assert!(resp.alerts.is_empty());
        assert!(resp.edges.is_empty());
    }

    #[test]
    fn response_helpers() {
        let ok = Response::completed("t", "ok");
        assert!(ok.is_completed());
        assert!(ok.is_success());
        assert!(!ok.is_error());

        let err = Response::failed("t", "fail");
        assert!(err.is_completed());
        assert!(err.is_error());
        assert!(!err.is_success());

        let pending = Response::new("t");
        assert!(!pending.is_completed());
        assert!(!pending.is_success());
        assert!(!pending.is_error());
    }

    #[test]
    fn response_builder_roundtrip() {
        let resp = ResponseBuilder::new("task-uuid")
            .user_output("done")
            .completed()
            .credential(Credential::new("plaintext", "admin", "pass123"))
            .process(ProcessEntry::new(1234, "evil.exe", "host"))
            .build();

        let json = serde_json::to_string(&resp).unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, resp);
        assert!(parsed.is_success());
        assert_eq!(parsed.credentials.len(), 1);
        assert_eq!(parsed.processes.len(), 1);
    }

    #[test]
    fn subtypes_roundtrip() {
        let task_download = Download {
            total_chunks: Some(2),
            chunk_size: Some(64),
            filename: Some("out.txt".to_string()),
            full_path: Some("/tmp/out.txt".to_string()),
            host: Some("host-a".to_string()),
            is_screenshot: false,
            file_id: None,
            chunk_num: None,
            chunk_data: None,
        };
        assert_eq!(
            serde_json::from_str::<Download>(&serde_json::to_string(&task_download).unwrap())
                .unwrap(),
            task_download
        );

        let task_upload = Upload {
            file_id: "file-id".into(),
            chunk_size: 512000,
            chunk_num: 1,
            full_path: Some("/tmp/target".into()),
            host: Some("host-a".into()),
        };
        assert_eq!(
            serde_json::from_str::<Upload>(&serde_json::to_string(&task_upload).unwrap()).unwrap(),
            task_upload
        );

        let file_entry = FileBrowser {
            is_file: false,
            name: "dir".into(),
            host: None,
            parent_path: "/".into(),
            success: true,
            permissions: Some(serde_json::json!({"x": "1"})),
            files: vec![File {
                is_file: true,
                name: "f.txt".into(),
                size: 100,
                permissions: None,
                access_time: 0,
                modify_time: 0,
            }],
            access_time: 0,
            modify_time: 0,
            size: 0,
            update_deleted: false,
        };
        assert_eq!(
            serde_json::from_str::<FileBrowser>(&serde_json::to_string(&file_entry).unwrap())
                .unwrap(),
            file_entry
        );

        let credential = Credential {
            credential_type: "plaintext".into(),
            credential: "pass123".into(),
            account: "admin".into(),
            realm: Some("DOMAIN".into()),
            comment: None,
            metadata: None,
        };
        assert_eq!(
            serde_json::from_str::<Credential>(&serde_json::to_string(&credential).unwrap())
                .unwrap(),
            credential
        );

        let artifact = Artifact {
            base_artifact: "Process Create".into(),
            artifact: "sh -c whoami".into(),
            needs_cleanup: false,
            resolved: false,
        };
        assert_eq!(
            serde_json::from_str::<Artifact>(&serde_json::to_string(&artifact).unwrap()).unwrap(),
            artifact
        );

        let process = ProcessEntry {
            process_id: 12345,
            name: "evil.exe".into(),
            host: "a.b.com".into(),
            parent_process_id: Some(1234),
            architecture: Some("x64".into()),
            user: Some("bob".into()),
            ..Default::default()
        };
        assert_eq!(
            serde_json::from_str::<ProcessEntry>(&serde_json::to_string(&process).unwrap())
                .unwrap(),
            process
        );

        let cmd = CommandAction {
            action: "add".into(),
            cmd: "shell".into(),
        };
        assert_eq!(
            serde_json::from_str::<CommandAction>(&serde_json::to_string(&cmd).unwrap()).unwrap(),
            cmd
        );

        let keylog = KeylogEntry {
            keystrokes: "password123".into(),
            user: Some("alice".into()),
            window_title: Some("Notepad".into()),
        };
        assert_eq!(
            serde_json::from_str::<KeylogEntry>(&serde_json::to_string(&keylog).unwrap()).unwrap(),
            keylog
        );

        let token = TokenEntry {
            token_id: Some(18947),
            host: Some("bob.com".into()),
            user: Some("bob".into()),
            process_id: Some(2345),
            ..Default::default()
        };
        assert_eq!(
            serde_json::from_str::<TokenEntry>(&serde_json::to_string(&token).unwrap()).unwrap(),
            token
        );

        let cb_token = CallbackToken {
            action: "add".into(),
            host: "a.b.com".into(),
            token_id: 12345,
            token: Some(token.clone()),
        };
        assert_eq!(
            serde_json::from_str::<CallbackToken>(&serde_json::to_string(&cb_token).unwrap())
                .unwrap(),
            cb_token
        );

        let removed = RemovedFile {
            host: "h".into(),
            path: "/tmp/f".into(),
        };
        assert_eq!(
            serde_json::from_str::<RemovedFile>(&serde_json::to_string(&removed).unwrap()).unwrap(),
            removed
        );
    }
}
