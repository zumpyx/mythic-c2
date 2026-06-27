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

use crate::{C2Transport, MythicResult};

#[cfg(feature = "http")]
pub use crate::transport::http::{HttpConfig, HttpTransport};

/// A single C2 profile entry of the form `{ "http": { ... } }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "HashMap<String, Value>", into = "HashMap<String, Value>")]
pub enum C2Profile {
    #[cfg(feature = "http")]
    Http(HttpConfig),
    #[cfg(feature = "httpx")]
    Httpx(HttpConfig),
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
        }
    }

    /// Transport name as a static string.
    pub fn name(&self) -> &'static str {
        match self {
            #[cfg(feature = "http")]
            C2Profile::Http(_) => "http",
            #[cfg(feature = "httpx")]
            C2Profile::Httpx(_) => "httpx",
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
        }
        map
    }
}
