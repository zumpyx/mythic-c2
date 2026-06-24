//! Protocol layer — message types, wire codec, and AES-256-CBC-HMAC crypto.
//!
//! This module provides the low-level building blocks:
//!
//! | Module | Purpose |
//! |---|---|
//! | [`codec`] | Wire format + `MythicCrypto` trait + `Aes256HmacCrypto` |
//! | [`checkin`] | Checkin message types (plaintext / static-key) + staging data types |
//! | [`get_tasking`] | `ReqGetTasking` / `RespGetTasking`, `TaskMessage`, `TaskResponse`, hooking types |
//! | [`post_response`] | `ReqPostResponse` / `RespPostResponse`, `ResponseReceipt` |
//! | [`peer`] | P2P, SOCKS, reverse port forward, interactive, alerts, edges |

pub mod checkin;
pub mod codec;
#[cfg(feature = "rsa-staging")]
pub mod crypto;
pub mod get_tasking;
pub mod peer;
pub mod post_response;

pub use checkin::{
    DirectResult, ReqCheckin, ReqStagingRSA, ReqStagingTranslation, ReqTranslationStaging,
    RespCheckin, RespStagingRSA, RespStagingTranslation, RespTranslationStaging, direct_checkin,
};
pub use codec::{
    AES256_HMAC_LEN, AES256_IV_LEN, AES256_KEY_LEN, Aes256HmacCrypto, MYTHIC_UUID_LEN,
    MythicCrypto, decode_message, decode_message_plain, encode_message, encode_message_plain,
};
pub use get_tasking::{
    AgentExtras, AgentMessageExtras, AgentResponseExtras, Artifact, CallbackToken, CommandAction,
    Credential, FileBrowserEntry, KeylogEntry, ProcessEntry, RemovedFileInfo, ReqGetTasking,
    RespGetTasking, TaskDownload, TaskMessage, TaskResponse, TaskUpload, TokenEntry,
};
pub use peer::{
    AlertMessage, DelegateMessage, EdgeMessage, InteractiveMessage, P2PMessage,
    ReversePortForwardMessage, RpfwdMessage, SocksMessage,
};
pub use post_response::{ReqPostResponse, RespPostResponse, ResponseReceipt};

pub const ACTION_CHECKIN: &str = "checkin";
pub const ACTION_STAGING_RSA: &str = "staging_rsa";
pub const ACTION_STAGING_TRANSLATION: &str = "staging_translation";
pub const ACTION_TRANSLATION_STAGING: &str = "translation_staging";
pub const ACTION_GET_TASKING: &str = "get_tasking";
pub const ACTION_POST_RESPONSE: &str = "post_response";
