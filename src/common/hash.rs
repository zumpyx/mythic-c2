use blake2::{Blake2b, Digest};

pub fn hash_blake2b(data: &[u8]) -> [u8; 64] {
    let mut hasher = Blake2b::new();
    hasher.update(data);
    hasher.finalize().into()
}
