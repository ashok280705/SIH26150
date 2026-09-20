use forensic_core::{
    ForensicError, OemProfile, RecoveryBounds, RecoveryCandidate,
    RecoveryRun, Region, ValidationState, ValidationStateKind,
};
use evidence_reader::EvidenceReader;
use parsers_core::parser::Parser;
use std::time::Instant;

/// Core engine orchestrating bounded recovery across multiple OEMs and recovery levels.
pub struct RecoveryEngine;

impl RecoveryEngine {
    pub fn new() -> Self {
        Self
    }

    /// Executes a bounded recovery scan using the provided parser and profile.
    pub fn execute_recovery(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
        parser: &dyn Parser,
        bounds: &RecoveryBounds,
        start_offset: u64,
        end_offset: u64,
    ) -> Result<(Vec<RecoveryCandidate>, RecoveryRun), ForensicError> {
        let mut run = RecoveryRun {
            searched_regions: vec![],
            searched_bytes: 0,
            skipped_ranges: vec![],
            candidate_count: 0,
            rejected: 0,
            accepted: 0,
            hypothesis_count: 0,
            truncated: false,
            cancelled: false,
            validation_state: ValidationState::new(ValidationStateKind::Unknown, "RecoveryEngine", "Initial state", "Search").unwrap(),
            reason: String::new(),
        };

        let mut candidates = Vec::new();
        let start_time = Instant::now();

        // Bounded chunked scan. Each chunk is escalated through the recovery levels
        // in order (L1 indexed -> L2 orphan/slack -> L3 raw carving); the first level
        // that yields a candidate for a chunk wins, so a region is never double-counted
        // across levels. A chunk that overflows or reads out of bounds is recorded as
        // skipped rather than aborting the whole run (Req 24).
        let mut current_offset = start_offset;
        let chunk_size = 1024u64 * 1024; // 1 MiB chunks

        while current_offset < end_offset {
            // 1. Cancellation is honored promptly and downgrades the run to REVIEW.
            if bounds.cancel.is_cancelled() {
                run.cancelled = true;
                break;
            }

            // 2. Wall-clock bound.
            if let Some(limit) = bounds.time_limit {
                if start_time.elapsed() > limit {
                    run.truncated = true;
                    break;
                }
            }

            // 3. Byte bound: stop before exceeding the configured scan budget.
            if run.searched_bytes + chunk_size > bounds.max_scan_bytes {
                run.truncated = true;
                break;
            }

            // 4. Candidate bound.
            if run.candidate_count >= bounds.max_candidates {
                run.truncated = true;
                break;
            }

            let search_region = Region {
                offset: current_offset,
                length: chunk_size.min(end_offset - current_offset),
            };

            run.searched_regions.push(search_region.clone());
            run.searched_bytes += search_region.length;

            // Escalating cascade: stop at the first level that recovers something.
            let level_result = crate::levels::recover_l1_indexed(reader, profile, parser, &search_region)
                .and_then(|c| {
                    if c.is_empty() {
                        crate::levels::recover_l2_orphan(reader, profile, parser, &search_region)
                    } else {
                        Ok(c)
                    }
                })
                .and_then(|c| {
                    if c.is_empty() {
                        crate::levels::recover_l3_carve(reader, profile, parser, &search_region)
                    } else {
                        Ok(c)
                    }
                });

            match level_result {
                Ok(found) => {
                    for cand in found {
                        run.candidate_count += 1;
                        // A candidate whose structure validated is accepted; otherwise
                        // it is surfaced for review, never silently dropped.
                        if matches!(cand.validation.structure.state, ValidationStateKind::Pass) {
                            run.accepted += 1;
                        } else {
                            run.rejected += 1;
                        }
                        candidates.push(cand);
                        if run.candidate_count >= bounds.max_candidates {
                            break;
                        }
                    }
                }
                Err(_) => {
                    // Hostile/unreadable chunk: record as skipped, keep scanning.
                    run.skipped_ranges.push(search_region.clone());
                }
            }

            current_offset += search_region.length;
        }

        // Finalize the run to enforce Req 13.10
        if !run.cancelled && !run.truncated {
            run.validation_state = ValidationState::new(ValidationStateKind::Pass, "RecoveryEngine", "Full search space explored", "Search").unwrap();
            run.reason = "Complete".to_string();
        }
        run.finalize();

        Ok((candidates, run))
    }
}
