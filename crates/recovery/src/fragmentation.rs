//! Two-Dimensional Fragmented Recording Model (Req 19.6, 14.3, 14.7, 15.6, 24.2).
//!
//! Separates logical frame/sequence continuity from physical disk continuity:
//! - Logical continuity: sequence index / timestamp gaps (missing frames).
//! - Physical continuity: contiguous, non-contiguous scatter-gather, or circular buffer wrap.
//!
//! Physical non-contiguity is NEVER treated as frame loss or automatic corruption (Req 14.7).
//! Logical gaps are explicitly marked and NEVER synthesized with fill content (Property 9).

use forensic_core::{Region, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};

/// Physical storage layout continuity state between fragments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PhysicalContinuity {
    /// Fragments are physically adjacent on disk.
    Contiguous,
    /// Fragments are stored at non-adjacent physical offsets on disk (scatter-gather / unit allocation).
    Fragmented { physical_distance: u64 },
    /// Physical offset decreased, indicating circular storage ring buffer wrap.
    CircularWrap { wrap_offset: u64 },
    /// Physical continuity cannot be established.
    Unknown,
}

/// A single fragment of a video recording with its source region and sequence position.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fragment {
    pub region: Region,
    pub sequence_index: u32,
    pub is_valid: bool,
}

/// A detected logical frame gap in the video sequence (missing frames).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogicalGap {
    pub previous_sequence: u32,
    pub current_sequence: u32,
    pub missing_count: u32,
    pub reason: String,
}

/// A physical storage discontinuity between two fragments.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhysicalDiscontinuity {
    pub previous_region: Region,
    pub current_region: Region,
    pub continuity: PhysicalContinuity,
}

/// Comprehensive two-dimensional reassembly report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReassemblyResult {
    pub ordered_fragments: Vec<Fragment>,
    pub logical_gaps: Vec<LogicalGap>,
    pub physical_discontinuities: Vec<PhysicalDiscontinuity>,
    pub is_physically_contiguous: bool,
    pub truncated: bool,
    pub validation: ValidationState,
}

/// Reassembles fragments by logical sequence index while independently tracking physical layout.
/// Never synthesizes fill content for missing frames (Property 9).
pub fn reassemble_fragments(mut fragments: Vec<Fragment>, max_fragments: u32) -> ReassemblyResult {
    let truncated = fragments.len() > max_fragments as usize;
    if truncated {
        fragments.truncate(max_fragments as usize);
    }

    // 1. Sort by logical sequence index
    fragments.sort_by_key(|f| f.sequence_index);

    let mut logical_gaps = Vec::new();
    let mut physical_discontinuities = Vec::new();
    let mut is_physically_contiguous = true;

    // 2. Evaluate consecutive fragment pairs in two dimensions
    for window in fragments.windows(2) {
        let prev = &window[0];
        let curr = &window[1];

        // Dimension A: Logical sequence continuity
        if curr.sequence_index > prev.sequence_index + 1 {
            let missing_count = curr.sequence_index - prev.sequence_index - 1;
            logical_gaps.push(LogicalGap {
                previous_sequence: prev.sequence_index,
                current_sequence: curr.sequence_index,
                missing_count,
                reason: format!(
                    "Sequence jump from #{} to #{} ({} missing frames)",
                    prev.sequence_index, curr.sequence_index, missing_count
                ),
            });
        }

        // Dimension B: Physical storage continuity
        let prev_end = prev.region.offset.saturating_add(prev.region.length);
        let curr_start = curr.region.offset;

        if curr_start == prev_end {
            // Contiguous physical layout
        } else if curr_start < prev.region.offset {
            // Circular buffer wrap (offset went backwards)
            is_physically_contiguous = false;
            physical_discontinuities.push(PhysicalDiscontinuity {
                previous_region: prev.region,
                current_region: curr.region,
                continuity: PhysicalContinuity::CircularWrap {
                    wrap_offset: curr_start,
                },
            });
        } else {
            // Non-contiguous physical gap on disk (scatter-gather allocation)
            is_physically_contiguous = false;
            let distance = curr_start.saturating_sub(prev_end);
            physical_discontinuities.push(PhysicalDiscontinuity {
                previous_region: prev.region,
                current_region: curr.region,
                continuity: PhysicalContinuity::Fragmented {
                    physical_distance: distance,
                },
            });
        }
    }

    // 3. Construct defensible validation state with explicit technical explanations
    let validation = if truncated {
        ValidationState::new(
            ValidationStateKind::Review,
            "Pathological fragmentation: fragment count bounded to maximum limit",
            "reassemble_fragments",
            "Fragments",
        )
        .unwrap()
    } else if !logical_gaps.is_empty() {
        let total_missing: u32 = logical_gaps.iter().map(|g| g.missing_count).sum();
        ValidationState::new(
            ValidationStateKind::Review,
            format!(
                "{} logical gap(s) detected with {} total missing frame(s)",
                logical_gaps.len(),
                total_missing
            ),
            "reassemble_fragments",
            "Fragments",
        )
        .unwrap()
    } else if !is_physically_contiguous {
        ValidationState::new(
            ValidationStateKind::Pass,
            "Stream is logically complete; physical non-contiguity detected and recorded",
            "reassemble_fragments",
            "Fragments",
        )
        .unwrap()
    } else {
        ValidationState::new(
            ValidationStateKind::Pass,
            "All fragments logically complete and physically contiguous",
            "reassemble_fragments",
            "Fragments",
        )
        .unwrap()
    };

    ReassemblyResult {
        ordered_fragments: fragments,
        logical_gaps,
        physical_discontinuities,
        is_physically_contiguous,
        truncated,
        validation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logical_gap_with_physical_contiguity() {
        // Frames are physically adjacent (0..100, 100..200), but sequence skips from 0 to 5
        let fragments = vec![
            Fragment {
                region: Region {
                    offset: 0,
                    length: 100,
                },
                sequence_index: 0,
                is_valid: true,
            },
            Fragment {
                region: Region {
                    offset: 100,
                    length: 100,
                },
                sequence_index: 5,
                is_valid: true,
            },
        ];
        let result = reassemble_fragments(fragments, 100);

        assert_eq!(result.logical_gaps.len(), 1);
        assert_eq!(result.logical_gaps[0].missing_count, 4);
        assert!(result.is_physically_contiguous);
        assert_eq!(result.validation.state, ValidationStateKind::Review);
    }

    #[test]
    fn test_logical_contiguity_with_physical_fragmentation() {
        // Frames are consecutive (0, 1), but stored in non-adjacent clusters (0..100, 5000..5100)
        let fragments = vec![
            Fragment {
                region: Region {
                    offset: 0,
                    length: 100,
                },
                sequence_index: 0,
                is_valid: true,
            },
            Fragment {
                region: Region {
                    offset: 5000,
                    length: 100,
                },
                sequence_index: 1,
                is_valid: true,
            },
        ];
        let result = reassemble_fragments(fragments, 100);

        assert!(
            result.logical_gaps.is_empty(),
            "Consecutive sequences must have NO logical gap"
        );
        assert!(!result.is_physically_contiguous);
        assert_eq!(result.physical_discontinuities.len(), 1);
        assert_eq!(
            result.validation.state,
            ValidationStateKind::Pass,
            "Logically complete streams must PASS even if physically fragmented"
        );
    }

    #[test]
    fn test_circular_wrap_detection() {
        // Sequence 0 is at offset 9000, Sequence 1 wraps around to offset 500
        let fragments = vec![
            Fragment {
                region: Region {
                    offset: 9000,
                    length: 100,
                },
                sequence_index: 0,
                is_valid: true,
            },
            Fragment {
                region: Region {
                    offset: 500,
                    length: 100,
                },
                sequence_index: 1,
                is_valid: true,
            },
        ];
        let result = reassemble_fragments(fragments, 100);

        assert!(result.logical_gaps.is_empty());
        assert_eq!(result.physical_discontinuities.len(), 1);
        match result.physical_discontinuities[0].continuity {
            PhysicalContinuity::CircularWrap { wrap_offset } => assert_eq!(wrap_offset, 500),
            _ => panic!("Expected CircularWrap"),
        }
    }
}
