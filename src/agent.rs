//! High-level agent facade — build, send, and parse Mythic protocol messages.

use alloc::vec::Vec;
use uuid::Uuid;

use crate::MythicResult;
use crate::error::MythicError;
use crate::protocol::checkin::{self, DirectResult};
use crate::protocol::codec::{
    Aes256HmacCrypto, decode_message, decode_message_plain, encode_message, encode_message_plain,
};
use crate::protocol::{
    AgentExtras, AgentMessageExtras, ReqCheckin, ReqGetTasking, ReqPostResponse, RespGetTasking,
    RespPostResponse,
};
use crate::transport::C2Transport;

/// Post-checkin phase — holds the callback UUID and optional crypto session.
///
/// # Examples
///
/// ```no_run
/// use mythic::{C2Transport, MythicAgent};
/// use uuid::Uuid;
///
/// # struct HttpC2;
/// # impl C2Transport for HttpC2 {
/// #     type Error = &'static str;
/// #     fn random_iv(&self) -> Result<[u8; 16], Self::Error> { Ok([0u8; 16]) }
/// #     fn checkin(&self, p: &str) -> Result<String, Self::Error> { Ok(String::new()) }
/// #     fn get_tasking(&self, p: &str) -> Result<String, Self::Error> { Ok(String::new()) }
/// #     fn post_response(&self, p: &str) -> Result<String, Self::Error> { Ok(String::new()) }
/// # }
/// let c2 = HttpC2;
/// let payload_uuid = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
///
/// let agent = MythicAgent::new(payload_uuid)
///     .checkin(&c2, vec!["10.0.0.1".into()], "linux", "root", "web01", 1337, "x86_64")
///     .unwrap();
/// println!("callback UUID: {}", agent.callback_uuid());
/// ```
#[derive(Debug)]
pub struct MythicAgent {
    pub callback_uuid: Uuid,
    crypto: Option<Aes256HmacCrypto>,
}

impl MythicAgent {
    pub fn new(callback_uuid: Uuid) -> Self {
        Self {
            callback_uuid,
            crypto: None,
        }
    }

    pub fn callback_uuid(&self) -> Uuid {
        self.callback_uuid
    }

    // ── Core message flow ──────────────────────────────────────

    /// Simple checkin — only the fields Mythic needs for callback creation.
    ///
    /// Builds a [`ReqCheckin`] internally.  Use [`checkin_with_req`](Self::checkin_with_req)
    /// if you need the full set of checkin fields (domain, integrity_level,
    /// encryption_key, etc.).
    #[allow(clippy::too_many_arguments)]
    pub fn checkin<C: C2Transport>(
        self,
        c2: &C,
        ips: Vec<alloc::string::String>,
        os: &str,
        user: &str,
        host: &str,
        pid: u32,
        architecture: &str,
    ) -> MythicResult<Self> {
        let req = ReqCheckin::new(
            self.callback_uuid,
            ips,
            Some(os.into()),
            Some(user.into()),
            Some(host.into()),
            Some(pid),
            Some(architecture.into()),
            None, None, None, None, None, None,
        );
        self.checkin_with_req(req, c2)
    }

    /// Full checkin with a pre-built [`ReqCheckin`].
    ///
    /// The mode is determined automatically from the transport
    /// via [`C2Transport::aes_psk`].  `req.uuid` must be the payload UUID;
    /// it is used both in the JSON body and the wire framing.
    pub fn checkin_with_req<C: C2Transport>(mut self, req: ReqCheckin, c2: &C) -> MythicResult<Self> {
        let payload_uuid = req.uuid;

        let needs_crypto = c2.aes_psk().is_some();
        let iv = if needs_crypto {
            c2.random_iv().map_err(MythicError::transport)?
        } else {
            [0u8; 16]
        };

        let DirectResult {
            callback_uuid,
            crypto,
            ..
        } = checkin::direct_checkin(c2, &req, payload_uuid, &iv)?;

        self.callback_uuid = callback_uuid;
        self.crypto = crypto;

        Ok(self)
    }

    /// Poll for new tasks from the Mythic server (no extras).
    pub fn get_tasking<C: C2Transport>(
        &mut self,
        tasking_size: u32,
        c2: &C,
    ) -> MythicResult<RespGetTasking> {
        self.get_tasking_with(tasking_size, c2, AgentMessageExtras::default())
    }

    /// Poll for new tasks, carrying delegates, SOCKS, RPFWD, interactive data,
    /// edges, alerts, and/or responses alongside the request.
    pub fn get_tasking_with<C: C2Transport>(
        &mut self,
        tasking_size: u32,
        c2: &C,
        extras: AgentMessageExtras,
    ) -> MythicResult<RespGetTasking> {
        let req = ReqGetTasking::with_extras(tasking_size, extras);

        if let Some(ref crypto) = self.crypto {
            let iv = c2.random_iv().map_err(MythicError::transport)?;
            let packed = encode_message(&req, self.callback_uuid, crypto, &iv)?;
            let response = c2.get_tasking(&packed).map_err(MythicError::transport)?;
            decode_message(&response, Some(self.callback_uuid), crypto).map(|(_, r)| r)
        } else {
            let packed = encode_message_plain(&req, self.callback_uuid)?;
            let response = c2.get_tasking(&packed).map_err(MythicError::transport)?;
            decode_message_plain(&response, Some(self.callback_uuid)).map(|(_, r)| r)
        }
    }

    /// Send task responses back to the Mythic server (no extras).
    ///
    /// The `responses` vector contains the output of completed (or in-progress)
    /// tasks.  Use [`crate::protocol::TaskResponse`] builders like
    /// [`crate::protocol::TaskResponse::completed`] or construct custom
    /// responses with hooking-feature data (file browser entries, credentials,
    /// keylogs, etc.).
    pub fn post_response<C: C2Transport>(
        &mut self,
        responses: Vec<crate::protocol::TaskResponse>,
        c2: &C,
    ) -> MythicResult<RespPostResponse> {
        self.post_response_with(responses, c2, AgentExtras::default())
    }

    /// Send task responses, carrying delegates, SOCKS, RPFWD, interactive data,
    /// edges, and/or alerts alongside the response.
    ///
    /// `shared` is the [`AgentExtras`] portion — it does **not** contain
    /// `responses` (those are the first argument).  Use
    /// [`AgentExtras::default()`] if you only need the responses.
    pub fn post_response_with<C: C2Transport>(
        &mut self,
        responses: Vec<crate::protocol::TaskResponse>,
        c2: &C,
        shared: AgentExtras,
    ) -> MythicResult<RespPostResponse> {
        let extras = AgentMessageExtras { responses, shared };
        let req = ReqPostResponse::from_extras(extras);

        if let Some(ref crypto) = self.crypto {
            let iv = c2.random_iv().map_err(MythicError::transport)?;
            let packed = encode_message(&req, self.callback_uuid, crypto, &iv)?;
            let response = c2.post_response(&packed).map_err(MythicError::transport)?;
            decode_message(&response, Some(self.callback_uuid), crypto).map(|(_, r)| r)
        } else {
            let packed = encode_message_plain(&req, self.callback_uuid)?;
            let response = c2.post_response(&packed).map_err(MythicError::transport)?;
            decode_message_plain(&response, Some(self.callback_uuid)).map(|(_, r)| r)
        }
    }
}
