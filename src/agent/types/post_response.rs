use serde::{Deserialize, Serialize};

use super::{peer::Delegate, response::Response};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ReqPostResponse {
    pub action: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub responses: Vec<Response>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegates: Vec<Delegate>,
}

impl ReqPostResponse {
    pub fn new(responses: Vec<Response>, delegates: Vec<Delegate>) -> Self {
        Self {
            action: obfstring!("post_response"),
            responses,
            delegates,
        }
    }

    pub fn with_responses(responses: Vec<Response>) -> Self {
        Self {
            action: obfstring!("post_response"),
            responses,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RespPostResponse {
    pub action: String,
    #[serde(default)]
    pub responses: Vec<Response>,
    #[serde(default)]
    pub delegates: Vec<Delegate>,
}

impl RespPostResponse {
    pub fn new(responses: Vec<Response>, delegates: Vec<Delegate>) -> Self {
        Self {
            action: obfstring!("post_response"),
            responses,
            delegates,
        }
    }
}
