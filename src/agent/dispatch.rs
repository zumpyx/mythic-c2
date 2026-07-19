use super::types::task::TaskMessage;
use crate::common::hash::hash_blake2b;
use crate::{MythicError, MythicResult};
use core::error::Error;
use heapless::index_map::FnvIndexMap;
use spin::Mutex;

use super::types::response::Response;

pub type CommandFn = fn(&TaskMessage) -> MythicResult<Response>;

const MAX_COMMANDS: usize = 128;
static REGISTRY: Mutex<FnvIndexMap<u64, CommandFn, MAX_COMMANDS>> = Mutex::new(FnvIndexMap::new());

pub fn hash_to_key(name: &str) -> u64 {
    let hash: [u8; 64] = hash_blake2b(name.as_bytes());
    let key1 = u64::from_le_bytes(hash[..8].try_into().unwrap());
    let key2 = u64::from_le_bytes(hash[8..16].try_into().unwrap());
    let key3 = u64::from_le_bytes(hash[16..24].try_into().unwrap());
    let key4 = u64::from_le_bytes(hash[24..32].try_into().unwrap());
    let key5 = u64::from_le_bytes(hash[32..40].try_into().unwrap());
    let key6 = u64::from_le_bytes(hash[40..48].try_into().unwrap());
    let key7 = u64::from_le_bytes(hash[48..56].try_into().unwrap());
    let key8 = u64::from_le_bytes(hash[56..64].try_into().unwrap());
    key1 ^ key2 ^ key3 ^ key4 ^ key5 ^ key6 ^ key7 ^ key8
}

pub fn register_command(name: &str, func: CommandFn) {
    let mut registry = REGISTRY.lock();
    let key = hash_to_key(name);
    registry.insert(key, func).unwrap();
}

impl TaskMessage {
    pub fn run(&self) -> MythicResult<Response> {
        let func = REGISTRY.lock().get(&hash_to_key(&self.command)).copied();
        match func {
            Some(f) => f(self),
            None => Err(MythicError::CommandNotFound),
        }
    }
}
