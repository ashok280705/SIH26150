//! # Region — Byte range in evidence
//!
//! A `Region` represents a contiguous byte range `[offset, offset+length)` within an
//! evidence source. Used throughout the platform for source regions, scan extents,
//! searched/skipped accounting, and provenance.

use serde::{Deserialize, Serialize};

use crate::error::ForensicError;

/// A contiguous byte range `[offset, offset+length)` in evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Region {
    /// Start offset in bytes from the beginning of the evidence source.
    pub offset: u64,
    /// Length in bytes.
    pub length: u64,
}

impl Region {
    /// Create a new region. Returns an error if `offset + length` overflows.
    pub fn new(offset: u64, length: u64) -> Result<Self, ForensicError> {
        offset.checked_add(length).ok_or_else(|| {
            ForensicError::overflow(format!(
                "Region::new: offset ({offset}) + length ({length}) overflows u64"
            ))
        })?;
        Ok(Self { offset, length })
    }

    /// Create a zero-length region at an offset (a position marker).
    pub fn point(offset: u64) -> Self {
        Self { offset, length: 0 }
    }

    /// Exclusive end offset. Returns `None` if the computation overflows.
    pub fn end(&self) -> Option<u64> {
        self.offset.checked_add(self.length)
    }

    /// Whether this region is zero-length.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Whether `byte_offset` falls within `[offset, offset+length)`.
    pub fn contains(&self, byte_offset: u64) -> bool {
        if self.length == 0 {
            return false;
        }
        match self.end() {
            Some(end) => byte_offset >= self.offset && byte_offset < end,
            None => byte_offset >= self.offset, // overflow implies extends to u64::MAX
        }
    }

    /// Whether this region overlaps with `other`.
    pub fn overlaps(&self, other: &Region) -> bool {
        if self.is_empty() || other.is_empty() {
            return false;
        }
        let self_end = self.end().unwrap_or(u64::MAX);
        let other_end = other.end().unwrap_or(u64::MAX);
        self.offset < other_end && other.offset < self_end
    }

    /// Compute the intersection of two regions. Returns `None` if they don't overlap.
    pub fn intersection(&self, other: &Region) -> Option<Region> {
        if !self.overlaps(other) {
            return None;
        }
        let start = self.offset.max(other.offset);
        let self_end = self.end().unwrap_or(u64::MAX);
        let other_end = other.end().unwrap_or(u64::MAX);
        let end = self_end.min(other_end);
        // end >= start is guaranteed by the overlaps check
        Some(Region {
            offset: start,
            length: end - start,
        })
    }
}

impl std::fmt::Display for Region {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.end() {
            Some(end) => write!(
                f,
                "[0x{:X}..0x{:X}) ({} bytes)",
                self.offset, end, self.length
            ),
            None => write!(f, "[0x{:X}..overflow) ({} bytes)", self.offset, self.length),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_serde_roundtrip() {
        let r = Region::new(1024, 512).unwrap();
        let json = serde_json::to_string(&r).unwrap();
        let back: Region = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn end_offset() {
        let r = Region::new(100, 50).unwrap();
        assert_eq!(r.end(), Some(150));
    }

    #[test]
    fn contains_byte() {
        let r = Region::new(100, 50).unwrap();
        assert!(r.contains(100));
        assert!(r.contains(149));
        assert!(!r.contains(150));
        assert!(!r.contains(99));
    }

    #[test]
    fn empty_region_contains_nothing() {
        let r = Region::point(100);
        assert!(!r.contains(100));
        assert!(r.is_empty());
    }

    #[test]
    fn overlap_detection() {
        let a = Region::new(100, 50).unwrap(); // [100, 150)
        let b = Region::new(120, 50).unwrap(); // [120, 170)
        let c = Region::new(150, 50).unwrap(); // [150, 200) — adjacent, not overlapping
        let d = Region::new(0, 100).unwrap(); // [0, 100) — adjacent, not overlapping

        assert!(a.overlaps(&b));
        assert!(b.overlaps(&a));
        assert!(!a.overlaps(&c));
        assert!(!a.overlaps(&d));
    }

    #[test]
    fn intersection_computation() {
        let a = Region::new(100, 50).unwrap(); // [100, 150)
        let b = Region::new(120, 50).unwrap(); // [120, 170)

        let inter = a.intersection(&b).unwrap();
        assert_eq!(inter.offset, 120);
        assert_eq!(inter.length, 30); // [120, 150)
    }

    #[test]
    fn no_intersection_for_non_overlapping() {
        let a = Region::new(0, 100).unwrap();
        let b = Region::new(200, 100).unwrap();
        assert!(a.intersection(&b).is_none());
    }

    #[test]
    fn overflow_rejected() {
        let result = Region::new(u64::MAX, 1);
        assert!(result.is_err());
    }

    #[test]
    fn display_format() {
        let r = Region::new(0x1000, 0x200).unwrap();
        let s = r.to_string();
        assert!(s.contains("0x1000"), "got: {s}");
        assert!(s.contains("512 bytes"), "got: {s}");
    }
}
