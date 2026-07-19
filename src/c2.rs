use serde::{Deserialize, Serialize};

use crate::MythicResult;

pub mod http;

#[derive(Debug, Serialize, Deserialize)]
pub enum MythicC2 {
    #[serde(rename = "http")]
    Http(http::Http),
}

pub trait C2Trait {
    /// Return the current AES-256 pre-shared key.
    ///
    /// # Errors
    ///
    /// Returns [`MythicError::Base64`] if the stored key is not valid base64, or
    /// [`MythicError::Crypto`] if it does not decode to exactly 32 bytes.
    fn get_aes_psk(&self) -> MythicResult<[u8; 32]>;
    fn set_aes_psk(&mut self, psk: String);
    fn encrypted_exchange_check(&self) -> bool;
    fn checkin(&self, packed: &str) -> MythicResult<String>;
    fn get_tasking(&self, packed: &str) -> MythicResult<String>;
    fn post_response(&self, packed: &str) -> MythicResult<String>;
}

impl C2Trait for MythicC2 {
    fn get_aes_psk(&self) -> MythicResult<[u8; 32]> {
        match self {
            Self::Http(inner) => inner.get_aes_psk(),
        }
    }

    fn set_aes_psk(&mut self, psk: String) {
        match self {
            Self::Http(inner) => inner.set_aes_psk(psk),
        }
    }

    fn encrypted_exchange_check(&self) -> bool {
        match self {
            Self::Http(inner) => inner.encrypted_exchange_check(),
        }
    }

    fn checkin(&self, packed: &str) -> MythicResult<String> {
        match self {
            Self::Http(inner) => inner.checkin(packed),
        }
    }

    fn get_tasking(&self, packed: &str) -> MythicResult<String> {
        match self {
            Self::Http(inner) => inner.get_tasking(packed),
        }
    }

    fn post_response(&self, packed: &str) -> MythicResult<String> {
        match self {
            Self::Http(inner) => inner.post_response(packed),
        }
    }
}

#[cfg(test)]
pub mod mock {
    use std::cell::RefCell;

    use super::C2Trait;
    use crate::agent::{aes256_packed, aes256_unpack};
    use crate::common::{base64_decode, base64_encode};
    use crate::{MythicError, MythicResult};

    /// A test-only C2 transport that records requests and returns pre-set
    /// JSON responses, automatically handling AES encryption/decryption.
    #[derive(Debug, Default)]
    pub struct MockC2 {
        pub callback_uuid: String,
        pub aes_psk_b64: String,
        pub encrypted_exchange_check: bool,
        pub checkin_response: RefCell<Option<String>>,
        pub get_tasking_response: RefCell<Option<String>>,
        pub post_response_response: RefCell<Option<String>>,
        pub calls: RefCell<Vec<(Call, String)>>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Call {
        Checkin,
        GetTasking,
        PostResponse,
    }

    impl MockC2 {
        pub fn new(callback_uuid: impl Into<String>, aes_psk: [u8; 32]) -> Self {
            Self {
                callback_uuid: callback_uuid.into(),
                aes_psk_b64: base64_encode(aes_psk),
                ..Default::default()
            }
        }

        pub fn with_checkin_response(self, json: impl Into<String>) -> Self {
            *self.checkin_response.borrow_mut() = Some(json.into());
            self
        }

        pub fn with_get_tasking_response(self, json: impl Into<String>) -> Self {
            *self.get_tasking_response.borrow_mut() = Some(json.into());
            self
        }

        pub fn with_post_response_response(self, json: impl Into<String>) -> Self {
            *self.post_response_response.borrow_mut() = Some(json.into());
            self
        }

        fn dispatch(
            &self,
            call: Call,
            packed: &str,
            response: &RefCell<Option<String>>,
        ) -> MythicResult<String> {
            let aes_psk = self.get_aes_psk()?;
            let decrypted = aes256_unpack(&self.callback_uuid, &aes_psk, packed)?;
            self.calls
                .borrow_mut()
                .push((call, String::from_utf8_lossy(&decrypted).into()));
            let resp = response
                .borrow()
                .clone()
                .ok_or(MythicError::ServerRejected)?;
            aes256_packed(&self.callback_uuid, &aes_psk, resp)
        }
    }

    impl C2Trait for MockC2 {
        fn get_aes_psk(&self) -> MythicResult<[u8; 32]> {
            let bytes = base64_decode(&self.aes_psk_b64)?;
            bytes.try_into().map_err(|_| MythicError::KeyDerivation)
        }

        fn set_aes_psk(&mut self, psk: String) {
            self.aes_psk_b64 = psk.to_string();
        }

        fn encrypted_exchange_check(&self) -> bool {
            self.encrypted_exchange_check
        }

        fn checkin(&self, packed: &str) -> MythicResult<String> {
            self.dispatch(Call::Checkin, packed, &self.checkin_response)
        }

        fn get_tasking(&self, packed: &str) -> MythicResult<String> {
            self.dispatch(Call::GetTasking, packed, &self.get_tasking_response)
        }

        fn post_response(&self, packed: &str) -> MythicResult<String> {
            self.dispatch(Call::PostResponse, packed, &self.post_response_response)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::http::Http;
    use super::{C2Trait, MythicC2};

    #[test]
    fn mythic_c2_http_dispatch() {
        let http = Http {
            callback_host: "http://127.0.0.1".to_string(),
            callback_port: 8080,
            ..Default::default()
        };
        let c2 = MythicC2::Http(http);
        assert!(c2.get_aes_psk().is_err());
        assert!(!c2.encrypted_exchange_check());
    }
}
