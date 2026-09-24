//! # Hashing Service
//!
//! The `HashingService` and `HashRecord`: streaming SHA-256 computed over an
//! `EvidenceReader` in bounded windows, linked to provenance for exports and reports (Req 5.1, 5.6, 5.7).
//!
//! Key invariants:
//! - Hashing never loads a whole image into memory (Req 5.7).
//! - Every record captures algorithm, status, duration, and bytes hashed.
//! - SHA-256 is required; the `algo` field leaves room for additional algorithms.

#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;

use evidence_reader::{
    CancellationToken, EvidenceReader, ProgressCallback, RegionScanner, ScanOptions,
};
use forensic_core::{ArtifactId, ForensicError, Hash, HashAlgorithm, Region, ValidationState};

/// Detailed record of a computed cryptographic hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashRecord {
    /// Optional associated artifact identifier.
    pub artifact_id: Option<ArtifactId>,
    /// Cryptographic algorithm used.
    pub algo: HashAlgorithm,
    /// The computed hash value.
    pub value: Hash,
    /// When the computation completed.
    pub computed_at: DateTime<Utc>,
    /// Verification/validation outcome of the hash operation.
    pub status: ValidationState,
    /// Total duration of the hashing run in milliseconds.
    pub duration_ms: u64,
    /// Total number of evidence bytes hashed.
    pub bytes_hashed: u64,
}

/// Streaming hashing service that processes evidence in bounded windows.
pub struct HashingService;

impl HashingService {
    /// Compute the SHA-256 hash over an entire `EvidenceReader` stream in bounded windows.
    pub fn hash_reader(
        reader: &dyn EvidenceReader,
        window_size: usize,
        cancellation: Option<&CancellationToken>,
        progress: Option<ProgressCallback>,
    ) -> Result<HashRecord, ForensicError> {
        let region = Region::new(0, reader.len())?;
        Self::hash_region(reader, region, window_size, cancellation, progress)
    }

    /// Compute the SHA-256 hash over a bounded region of evidence.
    pub fn hash_region(
        reader: &dyn EvidenceReader,
        region: Region,
        window_size: usize,
        cancellation: Option<&CancellationToken>,
        progress: Option<ProgressCallback>,
    ) -> Result<HashRecord, ForensicError> {
        let start_time = Instant::now();
        let mut hasher = Sha256::new();

        let options = ScanOptions {
            window_size: window_size.max(4096),
            alignment: 1,
            max_scan_bytes: None,
        };

        let scanner = RegionScanner::new(reader, region, options)?;

        let report = scanner.scan(cancellation, progress, |_offset, chunk| {
            hasher.update(chunk);
            Ok(true)
        })?;

        let duration_ms = start_time.elapsed().as_millis() as u64;
        let computed_at = Utc::now();

        if !report.is_complete() {
            let val_state = ValidationState::review(
                format!(
                    "hashing terminated prematurely: {}",
                    report.termination_reason
                ),
                "streaming_sha256",
                reader.source_path(),
            )
            .map_err(|e| ForensicError::corrupt("hash_region", format!("{e}")))?;

            return Ok(HashRecord {
                artifact_id: None,
                algo: HashAlgorithm::Sha256,
                value: Hash::sha256(hasher.finalize().to_vec()),
                computed_at,
                status: val_state,
                duration_ms,
                bytes_hashed: report.searched_bytes,
            });
        }

        let hash_bytes = hasher.finalize().to_vec();
        let hash = Hash::sha256(hash_bytes);

        let val_state = ValidationState::pass(
            format!(
                "streaming SHA-256 completed ({} bytes)",
                report.searched_bytes
            ),
            "streaming_sha256",
            reader.source_path(),
        )
        .map_err(|e| ForensicError::corrupt("hash_region", format!("{e}")))?;

        Ok(HashRecord {
            artifact_id: None,
            algo: HashAlgorithm::Sha256,
            value: hash,
            computed_at,
            status: val_state,
            duration_ms,
            bytes_hashed: report.searched_bytes,
        })
    }

    /// Compute SHA-256 directly from an in-memory byte slice (for small artifacts).
    pub fn hash_bytes(bytes: &[u8], subject_name: &str) -> Result<HashRecord, ForensicError> {
        let start_time = Instant::now();
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let hash_bytes = hasher.finalize().to_vec();
        let duration_ms = start_time.elapsed().as_millis() as u64;

        let status = ValidationState::pass(
            format!(
                "SHA-256 computed for in-memory buffer ({} bytes)",
                bytes.len()
            ),
            "hash_bytes",
            subject_name,
        )
        .map_err(|e| ForensicError::corrupt("hash_bytes", format!("{e}")))?;

        Ok(HashRecord {
            artifact_id: None,
            algo: HashAlgorithm::Sha256,
            value: Hash::sha256(hash_bytes),
            computed_at: Utc::now(),
            status,
            duration_ms,
            bytes_hashed: bytes.len() as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockReader {
        data: Vec<u8>,
    }

    impl EvidenceReader for MockReader {
        fn len(&self) -> u64 {
            self.data.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
            if offset >= self.len() {
                return Err(ForensicError::out_of_bounds(
                    "test",
                    offset,
                    buf.len() as u64,
                    self.len(),
                ));
            }
            let start = offset as usize;
            let available = (self.data.len() - start).min(buf.len());
            buf[..available].copy_from_slice(&self.data[start..start + available]);
            Ok(available)
        }
        fn source_kind(&self) -> evidence_reader::SourceKind {
            evidence_reader::SourceKind::Raw
        }
        fn source_path(&self) -> &str {
            "mock://test_image.raw"
        }
    }

    #[test]
    fn known_vector_sha256() {
        // "abc" -> ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let data = b"abc".to_vec();
        let reader = MockReader { data };

        let record = HashingService::hash_reader(&reader, 1024, None, None).unwrap();
        assert_eq!(
            record.value.hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(record.bytes_hashed, 3);
        assert!(record.status.is_pass());
    }

    #[test]
    fn known_vector_empty_sha256() {
        // "" -> e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let data = b"".to_vec();
        let reader = MockReader { data };

        let record = HashingService::hash_reader(&reader, 1024, None, None).unwrap();
        assert_eq!(
            record.value.hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(record.bytes_hashed, 0);
    }

    #[test]
    fn same_file_same_hash_across_window_sizes() {
        let data = (0..65536).map(|i| (i % 256) as u8).collect::<Vec<u8>>();
        let reader = MockReader { data: data.clone() };

        // Test varying window sizes from 4KB to 64KB
        let windows = [4096, 8192, 16384, 32768, 65536];
        let base_record = HashingService::hash_reader(&reader, windows[0], None, None).unwrap();
        let in_mem_record = HashingService::hash_bytes(&data, "mem_test").unwrap();

        assert_eq!(
            base_record.value, in_mem_record.value,
            "Streaming and in-memory must match exactly"
        );

        for &w in &windows[1..] {
            let record = HashingService::hash_reader(&reader, w, None, None).unwrap();
            assert_eq!(
                record.value, base_record.value,
                "Hash must be strictly identical regardless of streaming window size (window: {w})"
            );
            assert_eq!(record.bytes_hashed, data.len() as u64);
        }
    }

    #[test]
    fn different_files_produce_different_hashes() {
        let file_a = vec![0x42u8; 1024];
        let mut file_b = vec![0x42u8; 1024];
        // Flip a single bit in the last byte
        file_b[1023] ^= 0x01;

        let mut file_c = vec![0x42u8; 1024];
        // Flip a single bit in the first byte
        file_c[0] ^= 0x01;

        // Truncated version
        let file_d = vec![0x42u8; 1023];

        let hash_a = HashingService::hash_bytes(&file_a, "file_a").unwrap().value;
        let hash_b = HashingService::hash_bytes(&file_b, "file_b").unwrap().value;
        let hash_c = HashingService::hash_bytes(&file_c, "file_c").unwrap().value;
        let hash_d = HashingService::hash_bytes(&file_d, "file_d").unwrap().value;

        assert_ne!(
            hash_a, hash_b,
            "Flipping a single bit at the end must produce a different hash"
        );
        assert_ne!(
            hash_a, hash_c,
            "Flipping a single bit at the start must produce a different hash"
        );
        assert_ne!(
            hash_b, hash_c,
            "Different bit modifications must produce distinct hashes"
        );
        assert_ne!(
            hash_a, hash_d,
            "Different length files must produce distinct hashes"
        );
    }

    #[test]
    fn bounded_streaming_hash_large_fixture() {
        let data = vec![0xAA; 65536];
        let reader = MockReader { data: data.clone() };

        // Hash in tiny 512 byte windows
        let record = HashingService::hash_reader(&reader, 512, None, None).unwrap();

        // Compare against single in-memory hash
        let mem_record = HashingService::hash_bytes(&data, "mem").unwrap();
        assert_eq!(record.value, mem_record.value);
        assert_eq!(record.bytes_hashed, 65536);
    }
}
