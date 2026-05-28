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
pub mod get_tasking;
pub mod peer;
pub mod post_response;

pub use checkin::{
    DirectResult, ReqCheckin, ReqStagingRSA, ReqStagingTranslation, ReqTranslationStaging,
    RespCheckin, RespStagingRSA, RespStagingTranslation, RespTranslationStaging,
    direct_checkin,
};
pub use codec::{
    AES256_HMAC_LEN, AES256_IV_LEN, AES256_KEY_LEN, Aes256HmacCrypto, MYTHIC_UUID_LEN,
    MythicCrypto, decode_message, decode_message_plain,
    encode_message, encode_message_plain,
};
pub use peer::{
    AlertMessage, DelegateMessage, EdgeMessage, InteractiveMessage, P2PMessage,
    ReversePortForwardMessage, RpfwdMessage, SocksMessage,
};
pub use get_tasking::{
    AgentExtras, AgentMessageExtras, AgentResponseExtras, Artifact, CallbackToken,
    CommandAction, Credential, FileBrowserEntry, KeylogEntry, ProcessEntry, ReqGetTasking,
    RemovedFileInfo, RespGetTasking, TaskDownload, TaskMessage, TaskResponse, TaskUpload,
    TokenEntry,
};
pub use post_response::{ReqPostResponse, RespPostResponse, ResponseReceipt};

pub const ACTION_CHECKIN: &str = "checkin";
pub const ACTION_STAGING_RSA: &str = "staging_rsa";
pub const ACTION_STAGING_TRANSLATION: &str = "staging_translation";
pub const ACTION_TRANSLATION_STAGING: &str = "translation_staging";
pub const ACTION_GET_TASKING: &str = "get_tasking";
pub const ACTION_POST_RESPONSE: &str = "post_response";
pub const ACTION_DELEGATE: &str = "delegate";
pub const ACTION_P2P: &str = "p2p";
pub const ACTION_TASK: &str = "task";
pub const ACTION_TASK_RESPONSE: &str = "task_response";
pub const ACTION_DOWNLOAD: &str = "download";
pub const ACTION_SOCKS: &str = "socks";
pub const ACTION_RPFWD: &str = "rpfwd";
pub const ACTION_INTERACTIVE: &str = "interactive";
pub const ACTION_ALERT: &str = "alert";
pub const ACTION_EDGE: &str = "edge";
