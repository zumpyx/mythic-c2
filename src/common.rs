use crate::{MythicError, MythicResult};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

pub fn base64_encode(data: impl AsRef<[u8]>) -> String {
    STANDARD.encode(data)
}

pub fn base64_decode(data: impl AsRef<[u8]>) -> MythicResult<Vec<u8>> {
    STANDARD.decode(data).map_err(|_| MythicError::Base64)
}
