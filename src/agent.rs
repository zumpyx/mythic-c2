use crate::{MythicC2, protocol::ReqCheckin};

// #[derive(Debug)]
// pub struct MythicAgent {
//     pub session: MythicSession,
//     pub c2_list: Vec<MythicC2>,
// }

// impl MythicAgent {
// }
//     // ── Core message flow ──────────────────────────────────────

//     /// One-shot checkin — create an agent and check it in, no `new()` needed.
//     ///
//     /// For full control use [`checkin`](Self::checkin) with a pre-built
//     /// [`ReqCheckin`].
//     // #[allow(clippy::too_many_arguments)]
//     // pub fn easy_checkin<C: C2Transport>(
//     //     payload_uuid: u128,
//     //     c2: &mut C,
//     //     ips: Vec<String>,
//     //     os: Option<String>,
//     //     user: Option<String>,
//     //     host: Option<String>,
//     //     pid: Option<u32>,
//     //     architecture: Option<String>,
//     //     domain: Option<String>,
//     //     integrity_level: Option<u32>,
//     //     external_ip: Option<String>,
//     //     encryption_key: Option<String>,
//     //     decryption_key: Option<String>,
//     //     process_name: Option<String>,
//     // ) -> MythicResult<Self> {
//     //     let req = ReqCheckin::new(
//     //         payload_uuid,
//     //         ips,
//     //         os,
//     //         user,
//     //         host,
//     //         pid,
//     //         architecture,
//     //         domain,
//     //         integrity_level,
//     //         external_ip,
//     //         encryption_key,
//     //         decryption_key,
//     //         process_name,
//     //     );
//     //     Self::new(payload_uuid).checkin(req, c2)
//     }

//     /// Perform a direct checkin (plaintext or static-key PSK).
//     ///
//     /// The mode is determined automatically from the transport
//     /// via [`C2Transport::get_aes_psk`].  `req.uuid` must be the payload
//     /// UUID; it is used both in the JSON body and the wire framing.
//     ///
//     /// This method takes `&mut C` because RSA/translation staging may
//     /// negotiate a new session key that must be stored back into the transport.
//     // pub fn checkin<C: C2Transport>(mut self, req: ReqCheckin, c2: &mut C) -> MythicResult<Self> {
//     //     let payload_uuid = req.uuid;

//     //     if c2.encrypted_exchange_check() {
//     //         #[cfg(feature = "rsa-staging")]
//     //         return self.rsa_checkin(req, c2);
//     //         #[cfg(not(feature = "rsa-staging"))]
//     //         return Err(MythicError::KeyExchangeFailed);
//     //     }

//     //     let needs_crypto = c2.get_aes_psk().is_some();
//     //     let iv = if needs_crypto {
//     //         c2.random_iv()?
//     //     } else {
//     //         [0u8; 16]
//     //     };

//     //     // let DirectResult { callback_uuid, .. } =
//     //     //     checkin::direct_checkin(c2, &req, payload_uuid, &iv)?;

//     //     self.callback_uuid = callback_uuid;

//     //     Ok(self)
//     // }

//     /// Perform an RSA encrypted key exchange checkin.
//     ///
//     /// This is used when the transport reports
//     /// [`C2Transport::encrypted_exchange_check`] as `true`. It executes the
//     /// full `staging_rsa` → temp key → normal checkin flow.
//     #[cfg(feature = "rsa-staging")]
//     pub fn rsa_checkin<C: C2Transport>(
//         mut self,
//         req: ReqCheckin,
//         c2: &mut C,
//     ) -> MythicResult<Self> {
//         use crate::protocol::checkin::{RsaStagingResult, rsa_staging_checkin};
//         use crate::protocol::codec::encode_message;
//         use crate::protocol::crypto::random_iv;

//         let payload_uuid = req.uuid;
//         let RsaStagingResult {
//             temp_uuid, crypto, ..
//         } = rsa_staging_checkin(&*c2, payload_uuid)?;

//         // Persist the negotiated session key back into the transport so that
//         // subsequent get_tasking/post_response calls use it.
//         c2.set_aes_psk(&crypto.key_b64());

//         let iv = random_iv()?;
//         let packed = encode_message(&req, temp_uuid, &crypto, &iv)?;
//         let response = c2.checkin(&packed)?;
//         let (_, resp): (Uuid, RespCheckin) =
//             crate::protocol::codec::decode_message(&response, Some(temp_uuid), &crypto)?;

//         if resp.status != "success" {
//             return Err(MythicError::protocol(format!(
//                 "checkin rejected after RSA staging: status={}",
//                 resp.status
//             )));
//         }

//         self.callback_uuid = resp.id;
//         Ok(self)
//     }

//     /// Poll for new tasks from the Mythic server (no extras).
//     ///
//     /// `tasking_size` of `-1` asks Mythic for all available tasks.
//     pub fn get_tasking<C: C2Transport>(
//         &self,
//         tasking_size: i32,
//         c2: &C,
//     ) -> MythicResult<RespGetTasking> {
//         self.get_tasking_with(tasking_size, c2, AgentMessageExtras::default())
//     }

//     /// Poll for new tasks, carrying delegates, SOCKS, RPFWD, interactive data,
//     /// edges, alerts, and/or responses alongside the request.
//     pub fn get_tasking_with<C: C2Transport>(
//         &self,
//         tasking_size: i32,
//         c2: &C,
//         extras: AgentMessageExtras,
//     ) -> MythicResult<RespGetTasking> {
//         let req = ReqGetTasking::with_extras(tasking_size, extras);

//         if let Some(key_b64) = c2.get_aes_psk() {
//             let crypto = Aes256HmacCrypto::from_base64_key(&key_b64)?;
//             let iv = c2.random_iv()?;
//             let packed = encode_message(&req, self.callback_uuid, &crypto, &iv)?;
//             let response = c2.get_tasking(&packed)?;
//             decode_message(&response, Some(self.callback_uuid), &crypto).map(|(_, r)| r)
//         } else {
//             let packed = encode_message_plain(&req, self.callback_uuid)?;
//             let response = c2.get_tasking(&packed)?;
//             decode_message_plain(&response, Some(self.callback_uuid)).map(|(_, r)| r)
//         }
//     }

//     /// Send task responses back to the Mythic server (no extras).
//     ///
//     /// The `responses` vector contains the output of completed (or in-progress)
//     /// tasks.  Use [`crate::protocol::TaskResponse`] builders like
//     /// [`crate::protocol::TaskResponse::completed`] or construct custom
//     /// responses with hooking-feature data.
//     pub fn post_response<C: C2Transport>(
//         &self,
//         responses: Vec<crate::protocol::TaskResponse>,
//         c2: &C,
//     ) -> MythicResult<RespPostResponse> {
//         self.post_response_with(responses, c2, AgentExtras::default())
//     }

//     /// Send task responses, carrying delegates, SOCKS, RPFWD, interactive data,
//     /// edges, and/or alerts alongside the response.
//     ///
//     /// `shared` is the [`AgentExtras`] portion — it does **not** contain
//     /// `responses` (those are the first argument).
//     pub fn post_response_with<C: C2Transport>(
//         &self,
//         responses: Vec<crate::protocol::TaskResponse>,
//         c2: &C,
//         shared: AgentExtras,
//     ) -> MythicResult<RespPostResponse> {
//         let extras = AgentMessageExtras { responses, shared };
//         let req = ReqPostResponse::from_extras(extras);

//         if let Some(key_b64) = c2.get_aes_psk() {
//             let crypto = Aes256HmacCrypto::from_base64_key(&key_b64)?;
//             let iv = c2.random_iv()?;
//             let packed = encode_message(&req, self.callback_uuid, &crypto, &iv)?;
//             let response = c2.post_response(&packed)?;
//             decode_message(&response, Some(self.callback_uuid), &crypto).map(|(_, r)| r)
//         } else {
//             let packed = encode_message_plain(&req, self.callback_uuid)?;
//             let response = c2.post_response(&packed)?;
//             decode_message_plain(&response, Some(self.callback_uuid)).map(|(_, r)| r)
//         }
//     }
// }
