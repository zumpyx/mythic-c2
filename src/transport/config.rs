//! Transport configuration deserialization.
//!
//! Supports the Mythic payload builder output format:
//!
//! ```json
//! {
//!   "c2_profiles": [
//!     { "http": { "callback_host": "...", ... } }
//!   ]
//! }
//! ```

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{C2Transport, MythicError, MythicResult};

#[cfg(feature = "http")]
pub use crate::transport::http::{HttpConfig, HttpTransport};

#[cfg(feature = "websocket")]
pub use crate::transport::websocket::{WebsocketConfig, WebsocketTransport};

#[cfg(feature = "dns")]
pub use crate::transport::dns::{DnsConfig, DnsTransport};

#[cfg(feature = "github")]
pub use crate::transport::github::{GithubConfig, GithubTransport};

/// A single C2 profile entry of the form `{ "http": { ... } }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "HashMap<String, Value>", into = "HashMap<String, Value>")]
pub enum C2Profile {
    #[cfg(feature = "http")]
    Http(HttpConfig),
    #[cfg(feature = "httpx")]
    Httpx(HttpConfig),
    #[cfg(feature = "dns")]
    Dns(DnsConfig),
    #[cfg(feature = "websocket")]
    Websocket(WebsocketConfig),
    #[cfg(feature = "github")]
    Github(GithubConfig),
}

/// The `c2_profiles` array.
pub type C2Profiles = Vec<C2Profile>;

impl C2Profile {
    /// Build a concrete transport from this profile configuration.
    pub fn build(self) -> MythicResult<Box<dyn C2Transport>> {
        match self {
            #[cfg(feature = "http")]
            C2Profile::Http(cfg) => Ok(Box::new(HttpTransport::new(cfg)?)),
            #[cfg(feature = "httpx")]
            C2Profile::Httpx(cfg) => Ok(Box::new(HttpTransport::new(cfg)?)),
            #[cfg(feature = "dns")]
            C2Profile::Dns(cfg) => Ok(Box::new(DnsTransport::new(cfg)?)),
            #[cfg(feature = "websocket")]
            C2Profile::Websocket(cfg) => Ok(Box::new(WebsocketTransport::new(cfg)?)),
            #[cfg(feature = "github")]
            C2Profile::Github(cfg) => Ok(Box::new(GithubTransport::new(cfg)?)),
            #[allow(unreachable_patterns)]
            _ => Err(MythicError::InvalidTransport),
        }
    }

    /// Transport name as a static string.
    pub fn name(&self) -> &'static str {
        match self {
            #[cfg(feature = "http")]
            C2Profile::Http(_) => "http",
            #[cfg(feature = "httpx")]
            C2Profile::Httpx(_) => "httpx",
            #[cfg(feature = "dns")]
            C2Profile::Dns(_) => "dns",
            #[cfg(feature = "websocket")]
            C2Profile::Websocket(_) => "websocket",
            #[cfg(feature = "github")]
            C2Profile::Github(_) => "github",
            #[allow(unreachable_patterns)]
            _ => "unknown",
        }
    }
}

impl From<HashMap<String, Value>> for C2Profile {
    fn from(map: HashMap<String, Value>) -> Self {
        let mut iter = map.into_iter();
        if let Some((k, v)) = iter.next() {
            match k.as_str() {
                #[cfg(feature = "http")]
                "http" => match serde_json::from_value::<HttpConfig>(v) {
                    Ok(cfg) => Self::Http(cfg),
                    Err(_) => Self::Http(HttpConfig::default()),
                },
                #[cfg(feature = "httpx")]
                "httpx" => match serde_json::from_value::<HttpConfig>(v) {
                    Ok(cfg) => Self::Httpx(cfg),
                    Err(_) => Self::Httpx(HttpConfig::default()),
                },
                #[cfg(feature = "dns")]
                "dns" => match serde_json::from_value::<DnsConfig>(v) {
                    Ok(cfg) => Self::Dns(cfg),
                    Err(_) => Self::Dns(DnsConfig::default()),
                },
                #[cfg(feature = "websocket")]
                "websocket" => match serde_json::from_value::<WebsocketConfig>(v) {
                    Ok(cfg) => Self::Websocket(cfg),
                    Err(_) => Self::Websocket(WebsocketConfig::default()),
                },
                #[cfg(feature = "github")]
                "github" => match serde_json::from_value::<GithubConfig>(v) {
                    Ok(cfg) => Self::Github(cfg),
                    Err(_) => Self::Github(GithubConfig::default()),
                },
                _ => {
                    #[cfg(feature = "http")]
                    {
                        Self::Http(HttpConfig::default())
                    }
                    #[cfg(not(feature = "http"))]
                    {
                        let mut map = HashMap::new();
                        map.insert(k, v);
                        Self::from(map)
                    }
                }
            }
        } else {
            #[cfg(feature = "http")]
            return Self::Http(HttpConfig::default());
            #[cfg(not(feature = "http"))]
            {
                let mut map = HashMap::new();
                map.insert("unknown".to_string(), Value::Null);
                Self::from(map)
            }
        }
    }
}

impl From<C2Profile> for HashMap<String, Value> {
    fn from(profile: C2Profile) -> Self {
        let mut map = HashMap::new();
        match profile {
            #[cfg(feature = "http")]
            C2Profile::Http(v) => {
                map.insert(
                    "http".to_string(),
                    serde_json::to_value(v).unwrap_or(Value::Null),
                );
            }
            #[cfg(feature = "httpx")]
            C2Profile::Httpx(v) => {
                map.insert(
                    "httpx".to_string(),
                    serde_json::to_value(v).unwrap_or(Value::Null),
                );
            }
            #[cfg(feature = "dns")]
            C2Profile::Dns(v) => {
                map.insert(
                    "dns".to_string(),
                    serde_json::to_value(v).unwrap_or(Value::Null),
                );
            }
            #[cfg(feature = "websocket")]
            C2Profile::Websocket(v) => {
                map.insert(
                    "websocket".to_string(),
                    serde_json::to_value(v).unwrap_or(Value::Null),
                );
            }
            #[cfg(feature = "github")]
            C2Profile::Github(v) => {
                map.insert(
                    "github".to_string(),
                    serde_json::to_value(v).unwrap_or(Value::Null),
                );
            }
        }
        map
    }
}
