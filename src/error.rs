use std::fmt;

/// Library error. Display implementation emits descriptive text only under
/// `debug_assertions`; release builds report a generic error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Base64,
    Utf8,
    Json,
    InvalidFormat,
    Uuid,
    #[cfg(debug_assertions)]
    Message(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(debug_assertions)]
        {
            match self {
                Error::Base64 => write!(f, "base64 decode failed"),
                Error::Utf8 => write!(f, "invalid utf-8"),
                Error::Json => write!(f, "json (de)serialization failed"),
                Error::InvalidFormat => write!(f, "message too short or malformed"),
                Error::Uuid => write!(f, "invalid uuid"),
                Error::Message(m) => write!(f, "{}", m),
            }
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = self;
            write!(f, "error")
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
