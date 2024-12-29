use sha2::{Sha256, Digest};
use sha3::Sha3_256;
use rand::RngCore;
use prost_types::Timestamp;
use std::time::{SystemTime, UNIX_EPOCH};

/// Computes the SHA-256 hash of the given data.
pub fn compute_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Computes the SHA3-256 hash of the given data.
pub fn compute_sha3256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Generates a UUID as a vector of bytes based on RFC 4122.
pub fn generate_bytes_uuid() -> Vec<u8> {
    let mut uuid = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut uuid);

    // Variant bits (see section 4.1.1)
    uuid[8] = (uuid[8] & 0x3f) | 0x80;

    // Version 4 (pseudo-random, see section 4.1.3)
    uuid[6] = (uuid[6] & 0x0f) | 0x40;

    uuid.to_vec()
}

/// Generates a UUID as a string based on RFC 4122.
pub fn generate_uuid() -> String {
    id_bytes_to_str(&generate_bytes_uuid())
}

/// Converts the given UUID bytes into a string format.
fn id_bytes_to_str(id: &[u8]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7],
        id[8], id[9], id[10], id[11], id[12], id[13], id[14], id[15]
    )
}

/// Creates a UTC timestamp using the `prost_types::Timestamp` type.
pub fn create_utc_timestamp() -> Timestamp {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    Timestamp {
        seconds: now.as_secs() as i64,
        nanos: now.subsec_nanos() as i32,
    }
}

/// Converts a list of strings into a vector of byte slices.
pub fn to_chaincode_args(args: &[&str]) -> Vec<Vec<u8>> {
    args.iter().map(|&arg| arg.as_bytes().to_vec()).collect()
}

/// Concatenates multiple byte slices into a single byte vector.
pub fn concatenate_bytes(data: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = data.iter().map(|slice| slice.len()).sum();
    let mut result = Vec::with_capacity(total_len);
    for slice in data {
        result.extend_from_slice(slice);
    }
    result
}
