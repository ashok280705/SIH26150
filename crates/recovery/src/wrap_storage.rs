//! Circular/wrap storage handling (Req 14.8, 13.11, 15.6).
//!
//! Detects wrap boundaries from profile-described structures, reconstructs across the
//! wrap point where evidence supports it. Physical order is NEVER automatically treated
//! as chronological (Req 14.7, 15.6). A wrap does not by itself prove overwrite (Req 13.11).

use forensic_core::{Region, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};

/// Describes a detected wrap boundary in circular storage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WrapBoundary {
    /// The physical offset where the wrap occurs.
    pub wrap_offset: u64,
    /// The region before the wrap point (tail of the circular buffer).
    pub pre_wrap_region: Region,
    /// The region after the wrap point (head of the circular buffer).
    pub post_wrap_region: Region,
    /// Whether there is physical evidence of overwrite at this boundary.
    pub has_overwrite_evidence: bool,
    /// Validation state of the wrap detection.
    pub validation: ValidationState,
}

/// Detects a wrap boundary given physical evidence.
/// A wrap alone NEVER sets DataState = Overwritten; only confirmed physical evidence does.
pub fn detect_wrap_boundary(
    total_region: &Region,
    wrap_offset: u64,
    has_overwrite_evidence: bool,
) -> Option<WrapBoundary> {
    if wrap_offset <= total_region.offset
        || wrap_offset >= total_region.offset + total_region.length
    {
        return None; // Wrap point is outside the region
    }

    let pre_wrap = Region {
        offset: total_region.offset,
        length: wrap_offset - total_region.offset,
    };
    let post_wrap = Region {
        offset: wrap_offset,
        length: (total_region.offset + total_region.length) - wrap_offset,
    };

    let validation = if has_overwrite_evidence {
        ValidationState::new(
            ValidationStateKind::Review,
            "detect_wrap_boundary",
            "Wrap boundary detected with physical overwrite evidence",
            "WrapStorage",
        )
        .unwrap()
    } else {
        ValidationState::new(
            ValidationStateKind::Pass,
            "detect_wrap_boundary",
            "Wrap boundary detected; no overwrite evidence at boundary",
            "WrapStorage",
        )
        .unwrap()
    };

    Some(WrapBoundary {
        wrap_offset,
        pre_wrap_region: pre_wrap,
        post_wrap_region: post_wrap,
        has_overwrite_evidence,
        validation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_without_overwrite_evidence() {
        let region = Region {
            offset: 0,
            length: 1000,
        };
        let boundary = detect_wrap_boundary(&region, 600, false).unwrap();
        assert!(!boundary.has_overwrite_evidence);
        assert_eq!(boundary.validation.state, ValidationStateKind::Pass);
        assert_eq!(boundary.pre_wrap_region.length, 600);
        assert_eq!(boundary.post_wrap_region.length, 400);
    }

    #[test]
    fn test_wrap_with_overwrite_evidence() {
        let region = Region {
            offset: 0,
            length: 1000,
        };
        let boundary = detect_wrap_boundary(&region, 600, true).unwrap();
        assert!(boundary.has_overwrite_evidence);
        assert_eq!(boundary.validation.state, ValidationStateKind::Review);
    }

    #[test]
    fn test_wrap_outside_region_returns_none() {
        let region = Region {
            offset: 100,
            length: 500,
        };
        assert!(detect_wrap_boundary(&region, 50, false).is_none());
        assert!(detect_wrap_boundary(&region, 700, false).is_none());
    }
}
