use core::fmt;

/// Library error.
///
/// The `Display` implementation emits descriptive text only under
/// `debug_assertions`. Release builds report a generic error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Json,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(debug_assertions)]
        {
            match self {
                Error::Json => write!(f, "json (de)serialization failed"),
            }
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = self;
            write!(f, "error")
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;
