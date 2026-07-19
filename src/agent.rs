pub mod checkin;
pub mod common;
pub mod dispatch;
pub mod get_tasking;
pub mod post_response;
pub mod types;
pub use common::*;
pub use types::*;

#[derive(Debug)]
pub struct MythicAgent {
    pub callback_uuid: String,
}

impl MythicAgent {
    pub fn new(callback_uuid: String) -> Self {
        Self {
            callback_uuid: callback_uuid.into(),
        }
    }
}
