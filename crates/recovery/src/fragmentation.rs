//! Fragmented recording handling (Req 19.6, 14.3, 24.2).
//!
//! Reassembles validated fragments or marks gaps; never fabricates continuity.
//! Pathological fragmentation is bounded and reported (Req 24.2).

use forensic_core::{Region, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};

/// A fragment of a recording with its source location and validation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fragment {
    pub region: Region,
    pub sequence_index: u32,
    pub is_valid: bool,
}

/// A gap between fragments — never synthesized, always marked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Gap {
    pub expected_region: Region,
    pub reason: String,
}

/// Result of fragment reassembly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReassemblyResult {
    pub ordered_fragments: Vec<Fragment>,
    pub gaps: Vec<Gap>,
    pub truncated: bool,
    pub validation: ValidationState,
}

/// Reassemble fragments into order, marking gaps. Never synthesizes fill content (Property 9).
/// Pathological fragmentation (exceeding max_fragments) is bounded and reported (Req 24.2).
pub fn reassemble_fragments(
    mut fragments: Vec<Fragment>,
    max_fragments: u32,
) -> ReassemblyResult {
    let truncated = fragments.len() > max_fragments as usize;
    if truncated {
        fragments.truncate(max_fragments as usize);
    }

    // Sort by sequence index
    fragments.sort_by_key(|f| f.sequence_index);

    // Detect gaps between consecutive fragments
    let mut gaps = Vec::new();
    for window in fragments.windows(2) {
        let end_of_prev = window[0].region.offset + window[0].region.length;
        let start_of_next = window[1].region.offset;
        if start_of_next > end_of_prev {
            gaps.push(Gap {
                expected_region: Region { offset: end_of_prev, length: start_of_next - end_of_prev },
                reason: "Missing frames between consecutive fragments".to_string(),
            });
        }
    }

    let validation = if truncated {
        ValidationState::new(ValidationStateKind::Review, "reassemble_fragments",
            "Pathological fragmentation: fragment count bounded", "Fragments").unwrap()
    } else if !gaps.is_empty() {
        ValidationState::new(ValidationStateKind::Review, "reassemble_fragments",
            &format!("{} gap(s) detected in fragment sequence", gaps.len()), "Fragments").unwrap()
    } else {
        ValidationState::new(ValidationStateKind::Pass, "reassemble_fragments",
            "All fragments reassembled without gaps", "Fragments").unwrap()
    };

    ReassemblyResult {
        ordered_fragments: fragments,
        gaps,
        truncated,
        validation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gap_detection() {
        let fragments = vec![
            Fragment { region: Region { offset: 0, length: 100 }, sequence_index: 0, is_valid: true },
            Fragment { region: Region { offset: 200, length: 100 }, sequence_index: 1, is_valid: true },
        ];
        let result = reassemble_fragments(fragments, 100);
        assert_eq!(result.gaps.len(), 1);
        assert_eq!(result.gaps[0].expected_region.offset, 100);
        assert_eq!(result.gaps[0].expected_region.length, 100);
    }

    #[test]
    fn test_pathological_fragmentation_bounded() {
        let fragments: Vec<Fragment> = (0..100).map(|i| Fragment {
            region: Region { offset: i * 100, length: 50 },
            sequence_index: i as u32,
            is_valid: true,
        }).collect();
        let result = reassemble_fragments(fragments, 10);
        assert!(result.truncated);
        assert_eq!(result.ordered_fragments.len(), 10);
        assert_eq!(result.validation.state, ValidationStateKind::Review);
    }
}
