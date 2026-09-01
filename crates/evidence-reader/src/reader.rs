//! # EvidenceReader Trait
//!
//! The read-only trait for accessing evidence. Exposes NO write method at the type level.
//! `Send + Sync` for parallel detection (Req 1.1, 8.1, 8.7, 8.9).

use forensic_core::{ForensicError, Region};

/// The kind of evidence source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Raw binary image (.raw).
    Raw,
    /// dd image (.dd).
    Dd,
    /// Disk image (.img).
    Img,
    /// Physical block device.
    PhysicalDisk,
    // E01 is reserved but NOT implemented (gated by OPEN-1).
}

impl std::fmt::Display for SourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Raw => write!(f, "raw"),
            Self::Dd => write!(f, "dd"),
            Self::Img => write!(f, "img"),
            Self::PhysicalDisk => write!(f, "physical_disk"),
        }
    }
}

/// Read-only trait for accessing evidence sources.
///
/// **No write method exists at the type level.** This is the primary read-only guarantee
/// (Req 1.1). The trait is `Send + Sync` for parallel detection.
///
/// Implementations:
/// - [`crate::raw::RawReader`] — `.raw`, `.dd`, `.img`, and physical disk backend.
pub trait EvidenceReader: Send + Sync {
    /// Total length of the evidence source in bytes.
    fn len(&self) -> u64;

    /// Whether the source is empty (zero bytes).
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read bytes at a positioned offset into `buf`.
    ///
    /// Returns the number of bytes actually read. Returns `OutOfBounds` if `offset`
    /// is beyond the source length. Returns fewer bytes than `buf.len()` only at
    /// end-of-source or in sparse regions.
    ///
    /// All offset arithmetic inside the implementation MUST use the checked helpers
    /// from `forensic_core::checked`.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError>;

    /// The kind of evidence source.
    fn source_kind(&self) -> SourceKind;

    /// The path or identifier of the evidence source (for logging/display only).
    fn source_path(&self) -> &str;

    /// Read exactly `length` bytes starting at `offset`. Returns an error if fewer bytes
    /// are available (unlike `read_at` which returns a short read).
    fn read_exact_at(&self, offset: u64, length: usize) -> Result<Vec<u8>, ForensicError> {
        let mut buf = vec![0u8; length];
        let bytes_read = self.read_at(offset, &mut buf)?;
        if bytes_read < length {
            return Err(ForensicError::out_of_bounds(
                "short read",
                offset,
                length as u64,
                self.len(),
            ));
        }
        Ok(buf)
    }

    /// Read all bytes in a region. Validates bounds first.
    fn read_region(&self, region: &Region) -> Result<Vec<u8>, ForensicError> {
        forensic_core::checked::validate_region_bounds(region, self.len())?;
        // Safe because length was validated to fit in source.
        let length = region.length as usize;
        self.read_exact_at(region.offset, length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time test: verify that EvidenceReader has no write method.
    /// This test exists to document the invariant — if a write method is added, this
    /// comment should be updated/removed, which is the point: it's a review gate.
    #[test]
    fn no_write_method_exists() {
        // The trait has: len, is_empty, read_at, source_kind, source_path,
        // read_exact_at, read_region. None of these write.
        // This test is a documentation assertion — the real enforcement is the trait
        // definition itself having no write method.
    }

    /// Compile-time test: EvidenceReader is Send + Sync.
    #[test]
    fn reader_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        // This checks that the trait object is Send + Sync.
        assert_send_sync::<Box<dyn EvidenceReader>>();
    }
}
