//! Digests over bytes that were actually read.
//!
//! Three distinct artifacts are hashed by this pipeline and they must never be conflated:
//!
//! | digest | covers |
//! |---|---|
//! | source hash | the evidence bytes as read from the image (computed upstream) |
//! | media artifact hash | the derived container/elementary-stream file on disk |
//! | frame hash | the decoded pixel buffer of one frame |
//!
//! They cover different byte sequences, so they differ, and a report that shows them as equal
//! is showing a bug. Each [`ContentHash`] records its algorithm and the number of bytes fed in,
//! so it can be audited rather than merely trusted.
//!
//! A hash is only ever produced from a successful read. There is no path here that returns a
//! zero-filled or placeholder digest: a read failure is an error, and the caller must surface
//! it.

use crate::artifact::ContentHash;
use crate::error::{MediaError, MediaErrorKind, MediaResult};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

/// The algorithm label recorded on every hash this module produces.
pub const ALGORITHM: &str = "SHA-256";

/// The all-zero SHA-256 spelling, recognised so it can be rejected — never produced.
const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Hashes an in-memory buffer, e.g. one decoded frame.
pub fn hash_bytes(bytes: &[u8]) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    ContentHash {
        algorithm: ALGORITHM.to_string(),
        hex: hex::encode(hasher.finalize()),
        bytes_hashed: bytes.len() as u64,
    }
}

/// Hashes a file in bounded 64 KiB chunks.
///
/// Memory use is constant regardless of file size, so a multi-gigabyte derived artifact hashes
/// without ever being resident. A read error propagates; it does not degrade into a partial or
/// placeholder digest.
pub fn hash_file(path: &Path) -> MediaResult<ContentHash> {
    let mut file = std::fs::File::open(path).map_err(|e| {
        let kind = if e.kind() == std::io::ErrorKind::NotFound {
            MediaErrorKind::MediaNotFound
        } else {
            MediaErrorKind::MediaUnreadable
        };
        MediaError::new(
            kind,
            "hash_file",
            format!("opening '{}' for hashing: {e}", path.display()),
        )
    })?;

    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = file.read(&mut buffer).map_err(|e| {
            MediaError::new(
                MediaErrorKind::MediaUnreadable,
                "hash_file",
                format!("reading '{}' for hashing: {e}", path.display()),
            )
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        total += n as u64;
    }

    if total == 0 {
        // Hashing nothing would still yield the well-known SHA-256 of the empty string, which
        // looks like a real digest in a report. An empty artifact is a failure, not a hash.
        return Err(MediaError::new(
            MediaErrorKind::MediaEmpty,
            "hash_file",
            format!(
                "'{}' holds zero bytes; no digest is produced",
                path.display()
            ),
        ));
    }

    Ok(ContentHash {
        algorithm: ALGORITHM.to_string(),
        hex: hex::encode(hasher.finalize()),
        bytes_hashed: total,
    })
}

/// Recomputes a file's digest and compares it with a previously recorded one.
///
/// A recorded digest of all zeroes is rejected outright: it is a placeholder, not a hash, and
/// treating it as comparable would let a fabricated value pass verification.
pub fn verify_file(path: &Path, expected: &ContentHash) -> MediaResult<VerificationOutcome> {
    if expected.hex.eq_ignore_ascii_case(ZERO_SHA256) {
        return Err(MediaError::new(
            MediaErrorKind::InvalidConfiguration,
            "verify_file",
            "the recorded digest is all zeroes, which is a placeholder rather than a hash",
        ));
    }
    let computed = hash_file(path)?;
    let matches = computed.hex.eq_ignore_ascii_case(&expected.hex)
        && computed.algorithm == expected.algorithm;
    Ok(VerificationOutcome {
        expected: expected.clone(),
        computed,
        matches,
    })
}

/// The result of re-hashing an artifact against its recorded digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationOutcome {
    pub expected: ContentHash,
    pub computed: ContentHash,
    pub matches: bool,
}

impl VerificationOutcome {
    pub fn label(&self) -> &'static str {
        if self.matches {
            "MATCH"
        } else {
            "MISMATCH"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_file(name: &str, contents: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(contents).unwrap();
        (dir, p)
    }

    #[test]
    fn hashing_is_deterministic_and_records_the_byte_count() {
        let a = hash_bytes(b"FORENSIC");
        let b = hash_bytes(b"FORENSIC");
        assert_eq!(a, b);
        assert_eq!(a.algorithm, "SHA-256");
        assert_eq!(a.hex.len(), 64);
        assert_eq!(a.bytes_hashed, 8);
    }

    #[test]
    fn the_known_sha256_vector_is_reproduced() {
        // SHA-256("abc"), the canonical FIPS 180-4 test vector.
        assert_eq!(
            hash_bytes(b"abc").hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn a_file_hash_matches_the_hash_of_the_same_bytes_in_memory() {
        let (_d, p) = temp_file("a.bin", b"derived media bytes");
        let from_file = hash_file(&p).unwrap();
        let from_mem = hash_bytes(b"derived media bytes");
        assert_eq!(from_file.hex, from_mem.hex);
        assert_eq!(from_file.bytes_hashed, from_mem.bytes_hashed);
    }

    #[test]
    fn chunking_does_not_change_the_digest_for_files_larger_than_the_buffer() {
        let big: Vec<u8> = (0..(300 * 1024u32)).map(|i| (i % 251) as u8).collect();
        let (_d, p) = temp_file("big.bin", &big);
        assert_eq!(hash_file(&p).unwrap().hex, hash_bytes(&big).hex);
    }

    #[test]
    fn an_empty_file_yields_media_empty_rather_than_a_digest() {
        let (_d, p) = temp_file("empty.bin", b"");
        let err = hash_file(&p).unwrap_err();
        assert_eq!(err.kind, MediaErrorKind::MediaEmpty);
    }

    #[test]
    fn a_missing_file_yields_media_not_found_rather_than_a_digest() {
        let err = hash_file(Path::new("does/not/exist/anywhere.mp4")).unwrap_err();
        assert_eq!(err.kind, MediaErrorKind::MediaNotFound);
    }

    #[test]
    fn a_zero_filled_digest_is_rejected_rather_than_compared() {
        let (_d, p) = temp_file("a.bin", b"x");
        let placeholder = ContentHash {
            algorithm: ALGORITHM.into(),
            hex: ZERO_SHA256.into(),
            bytes_hashed: 0,
        };
        let err = verify_file(&p, &placeholder).unwrap_err();
        assert_eq!(err.kind, MediaErrorKind::InvalidConfiguration);
    }

    #[test]
    fn verification_reports_match_and_mismatch_distinctly() {
        let (_d, p) = temp_file("a.bin", b"payload");
        let good = hash_file(&p).unwrap();
        assert!(verify_file(&p, &good).unwrap().matches);

        let wrong = hash_bytes(b"different payload");
        let outcome = verify_file(&p, &wrong).unwrap();
        assert!(!outcome.matches);
        assert_eq!(outcome.label(), "MISMATCH");
    }

    #[test]
    fn the_source_digest_and_the_derived_digest_cover_different_bytes() {
        // A remux prepends container boxes, so the derived file cannot hash to the source.
        let source = hash_bytes(b"\x00\x00\x00\x01\x67elementary-stream");
        let derived = hash_bytes(b"ftypisom\x00\x00\x00\x01\x67elementary-stream");
        assert_ne!(source.hex, derived.hex);
    }
}
