//! # In-memory evidence reader for exercising the Dahua structure readers
//!
//! A [`MemReader`] presents a `Vec<u8>` through the read-only [`EvidenceReader`] trait so
//! the DHFS 4.1 structure readers can be driven over exact byte layouts without touching
//! the filesystem.
//!
//! It is compiled unconditionally (not behind `#[cfg(test)]`) so this crate's integration
//! tests under `tests/` can use it too. It exposes no write path to real evidence: it owns
//! its own buffer and implements the same read-only trait every production reader does.

use evidence_reader::{EvidenceReader, SourceKind};
use forensic_core::ForensicError;

/// An owned byte buffer presented as read-only evidence.
#[derive(Debug, Clone)]
pub struct MemReader {
    data: Vec<u8>,
    path: String,
}

impl MemReader {
    /// Wrap a byte buffer.
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            path: "mem://dahua-structure-test".to_string(),
        }
    }

    /// Wrap a byte buffer with a specific reported source path.
    pub fn with_path(data: Vec<u8>, path: impl Into<String>) -> Self {
        Self {
            data,
            path: path.into(),
        }
    }

    /// The underlying bytes, for a test that needs to assert on what it built.
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }
}

impl EvidenceReader for MemReader {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
        // Out-of-bounds is an error, not a zero-fill, so a reader bug cannot masquerade as
        // a region of zeros — which a parser could then misread as an empty structure.
        if offset >= self.len() {
            return Err(ForensicError::out_of_bounds(
                "MemReader::read_at",
                offset,
                buf.len() as u64,
                self.len(),
            ));
        }
        let start = offset as usize;
        let n = (self.data.len() - start).min(buf.len());
        buf[..n].copy_from_slice(&self.data[start..start + n]);
        Ok(n)
    }

    fn source_kind(&self) -> SourceKind {
        SourceKind::Raw
    }

    fn source_path(&self) -> &str {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_reads_are_reported_as_short_not_padded() {
        let r = MemReader::new(vec![1, 2, 3, 4]);
        let mut buf = [0u8; 8];
        assert_eq!(r.read_at(2, &mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], &[3, 4]);
    }

    #[test]
    fn reading_past_the_end_is_an_error_not_zeros() {
        let r = MemReader::new(vec![1, 2, 3, 4]);
        let mut buf = [0u8; 4];
        assert!(r.read_at(4, &mut buf).is_err());
        assert!(r.read_at(u64::MAX, &mut buf).is_err());
    }

    #[test]
    fn read_exact_at_refuses_a_short_read() {
        let r = MemReader::new(vec![1, 2, 3, 4]);
        assert!(r.read_exact_at(0, 4).is_ok());
        assert!(r.read_exact_at(2, 4).is_err());
    }
}
