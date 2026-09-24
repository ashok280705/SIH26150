//! # Bounded Reader Abstraction (Req 8.1, 13.1, 24.1)
//!
//! Restricts read operations to a strictly bounded sub-window of an underlying `EvidenceReader`.
//! Automatically rejects any out-of-bounds reads beyond the bounded region and maps
//! local window offsets back to absolute evidence offsets to preserve forensic provenance.

use crate::reader::{EvidenceReader, SourceKind};
use forensic_core::ForensicError;

/// A bounded window into an underlying `EvidenceReader`.
pub struct BoundedReader<'a> {
    inner: &'a dyn EvidenceReader,
    start_offset: u64,
    length: u64,
}

impl<'a> BoundedReader<'a> {
    /// Creates a new `BoundedReader` restricted to `[start_offset, start_offset + length)`.
    /// Returns `Err(OutOfBounds)` if the bounded region exceeds the underlying reader's length.
    pub fn new(
        inner: &'a dyn EvidenceReader,
        start_offset: u64,
        length: u64,
    ) -> Result<Self, ForensicError> {
        let total_len = inner.len();
        let end_offset = start_offset.checked_add(length).ok_or_else(|| {
            ForensicError::overflow("start_offset + length overflowed u64 in BoundedReader")
        })?;

        if end_offset > total_len {
            return Err(ForensicError::out_of_bounds(
                "BoundedReader creation beyond source",
                start_offset,
                length,
                total_len,
            ));
        }

        Ok(Self {
            inner,
            start_offset,
            length,
        })
    }

    /// Converts a local relative offset within the bounded window to an absolute evidence offset.
    pub fn to_absolute_offset(&self, local_offset: u64) -> Result<u64, ForensicError> {
        if local_offset > self.length {
            return Err(ForensicError::out_of_bounds(
                "Local offset exceeds BoundedReader length",
                local_offset,
                0,
                self.length,
            ));
        }
        self.start_offset.checked_add(local_offset).ok_or_else(|| {
            ForensicError::overflow("to_absolute_offset overflowed u64 in BoundedReader")
        })
    }

    /// Returns the absolute start offset of this bounded region on the evidence source.
    pub fn start_offset(&self) -> u64 {
        self.start_offset
    }
}

impl<'a> EvidenceReader for BoundedReader<'a> {
    fn len(&self) -> u64 {
        self.length
    }

    fn read_at(&self, local_offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
        if local_offset >= self.length {
            return Err(ForensicError::out_of_bounds(
                "BoundedReader read_at past window end",
                local_offset,
                buf.len() as u64,
                self.length,
            ));
        }

        let abs_offset = self.start_offset.checked_add(local_offset).ok_or_else(|| {
            ForensicError::overflow("abs_offset overflowed u64 in BoundedReader::read_at")
        })?;

        // Clamp read length to not exceed bounded window
        let max_readable = (self.length - local_offset) as usize;
        let read_len = buf.len().min(max_readable);

        self.inner.read_at(abs_offset, &mut buf[..read_len])
    }

    fn source_kind(&self) -> SourceKind {
        self.inner.source_kind()
    }

    fn source_path(&self) -> &str {
        self.inner.source_path()
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
                    "MockReader read past end",
                    offset,
                    buf.len() as u64,
                    self.len(),
                ));
            }
            let avail = (self.len() - offset) as usize;
            let to_read = buf.len().min(avail);
            buf[..to_read].copy_from_slice(&self.data[offset as usize..offset as usize + to_read]);
            Ok(to_read)
        }
        fn source_kind(&self) -> SourceKind {
            SourceKind::Raw
        }
        fn source_path(&self) -> &str {
            "mock://test"
        }
    }

    #[test]
    fn test_bounded_reader_isolates_region() {
        let payload = b"0123456789ABCDEF".to_vec();
        let reader = MockReader { data: payload };

        // Window of 6 bytes starting at offset 4 -> "456789"
        let bounded = BoundedReader::new(&reader, 4, 6).unwrap();
        assert_eq!(bounded.len(), 6);

        let data = bounded.read_exact_at(0, 6).unwrap();
        assert_eq!(data, b"456789");

        // Out of bounds in local window
        assert!(bounded.read_exact_at(4, 4).is_err());

        // Absolute offset mapping
        assert_eq!(bounded.to_absolute_offset(2).unwrap(), 6);
    }
}
