/// Errors that can occur during message encoding or decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MythicMessageError {
    Serialize,
    Deserialize,
    Base64Decode,
    Utf8,
    InvalidPacket,
    InvalidUuid,
    UuidMismatch,
    Crypto,
}

impl core::fmt::Display for MythicMessageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Serialize => "failed to serialize Mythic message",
            Self::Deserialize => "failed to deserialize Mythic message",
            Self::Base64Decode => "failed to decode Mythic packet from base64",
            Self::Utf8 => "failed to decode Mythic UUID as UTF-8",
            Self::InvalidPacket => "invalid Mythic packet",
            Self::InvalidUuid => "invalid Mythic UUID",
            Self::UuidMismatch => "Mythic UUID mismatch",
            Self::Crypto => "Mythic crypto operation failed",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn error_display_covers_all_variants() {
        let errors = [
            MythicMessageError::Serialize,
            MythicMessageError::Deserialize,
            MythicMessageError::Base64Decode,
            MythicMessageError::Utf8,
            MythicMessageError::InvalidPacket,
            MythicMessageError::InvalidUuid,
            MythicMessageError::UuidMismatch,
            MythicMessageError::Crypto,
        ];

        for error in errors {
            assert!(!error.to_string().is_empty());
        }
    }
}
