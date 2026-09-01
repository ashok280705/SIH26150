//! # Cryptographic Hash Types
//!
//! `Hash` and `HashAlgorithm` — the platform's representation of a cryptographic hash
//! value. SHA-256 is required (Req 5.1); the `algorithm` field allows future algorithms
//! without a schema change.

use serde::{Deserialize, Serialize};

/// The hash algorithm used. SHA-256 is required; the enum is extensible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithm {
    /// SHA-256 (required by the platform).
    Sha256,
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sha256 => write!(f, "SHA-256"),
        }
    }
}

/// A cryptographic hash value with its algorithm tag.
///
/// The `value` field stores raw bytes; use [`Hash::hex`] for the hex-encoded string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash {
    /// Which algorithm produced this hash.
    pub algorithm: HashAlgorithm,
    /// Raw hash bytes (e.g. 32 bytes for SHA-256).
    #[serde(with = "hex_serde")]
    pub value: Vec<u8>,
}

impl Hash {
    /// Create a SHA-256 hash from raw bytes.
    ///
    /// # Panics
    /// Panics in debug mode if `bytes.len() != 32`. In release mode, the value is stored
    /// as-is (a caller that creates a wrong-length SHA-256 hash will be caught by
    /// downstream verification, not by this constructor).
    pub fn sha256(bytes: Vec<u8>) -> Self {
        debug_assert_eq!(bytes.len(), 32, "SHA-256 hash must be 32 bytes");
        Self {
            algorithm: HashAlgorithm::Sha256,
            value: bytes,
        }
    }

    /// Hex-encoded hash value.
    pub fn hex(&self) -> String {
        hex::encode(&self.value)
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.hex())
    }
}

/// Custom serde module for Vec<u8> ↔ hex string.
mod hex_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_serde_roundtrip() {
        let hash = Hash::sha256(vec![0xab; 32]);
        let json = serde_json::to_string(&hash).unwrap();
        let back: Hash = serde_json::from_str(&json).unwrap();
        assert_eq!(hash, back);
    }

    #[test]
    fn hex_display() {
        let hash = Hash::sha256(vec![0x00; 32]);
        assert_eq!(
            hash.hex(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn display_includes_algorithm() {
        let hash = Hash::sha256(vec![0xff; 32]);
        let s = hash.to_string();
        assert!(s.starts_with("SHA-256:"), "got: {s}");
    }

    #[test]
    fn json_format_uses_hex_string() {
        let mut bytes = vec![0xde, 0xad, 0xbe, 0xef];
        bytes.resize(32, 0x00);
        let hash = Hash::sha256(bytes);
        let json = serde_json::to_string(&hash).unwrap();
        // The value field should be a hex string, not an array of integers
        assert!(
            !json.contains('['),
            "value should be hex string, not array: {json}"
        );
    }
}
