//! # Recovery observability
//!
//! Structured, serializable counters for one recovery run, plus a `tracing` emission
//! helper. These exist so a forensic engineer can answer "what did the engine compare,
//! and what did it conclude?" without re-running the scan.
//!
//! Raw evidence bytes are never logged — only offsets, lengths, counts and states.

use forensic_core::DataState;
use serde::{Deserialize, Serialize};

/// Counters describing one index-aware recovery run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryMetrics {
    /// OEM key the run executed under.
    pub oem_key: String,
    /// Profile id applied.
    pub profile_id: String,
    /// Whether the OEM parser supplied storage geometry from evidence.
    pub geometry_available: bool,
    /// The OEM-declared video payload region, as `offset:length`, if established.
    pub video_region: Option<String>,
    /// The OEM-declared index region, as `offset:length`, if established.
    pub index_region: Option<String>,
    /// Declared block size, if established.
    pub block_size: Option<u64>,
    /// Whether an authoritative recording index was established.
    pub authoritative_index: bool,
    /// Entries the index declared in its header, if it declares a count.
    pub index_declared_entries: Option<usize>,
    /// Index entries that parsed cleanly and produced claims.
    pub index_entry_count: usize,
    /// Canonical claimed range count (after merging).
    pub claimed_range_count: usize,
    /// Total bytes claimed by the index.
    pub claimed_bytes: u64,
    /// Canonical unclaimed range count.
    pub unclaimed_region_count: usize,
    /// Total bytes no index entry claims.
    pub unclaimed_bytes: u64,
    /// Ranges described by surviving OEM metadata the recorder no longer reaches — the
    /// *available* set. These are orphan findings backed by the recorder's own metadata, which
    /// is stronger evidence than an unreferenced gap.
    pub available_claim_count: usize,
    pub available_bytes: u64,
    /// Candidates produced from an available-metadata probe.
    pub available_candidate_count: usize,
    /// Candidates whose physical bounds came from an OEM container record rather than from a
    /// scan window. The ratio of this to `candidate_count` is how much of a run was structural
    /// recovery versus window classification.
    pub container_record_candidate_count: usize,
    /// Unclaimed regions inside the authoritative index scope (orphan-eligible space).
    pub orphan_eligible_region_count: usize,
    pub orphan_eligible_bytes: u64,
    /// Regions actually handed to the scanner (claimed probes plus unclaimed chunks).
    pub scan_region_count: usize,
    /// Bytes actually read and examined.
    pub scanned_bytes: u64,
    /// Bytes the planner skipped because no index-derived target covered them. This is
    /// the measurable benefit of index-aware planning over a whole-disk sweep.
    pub bytes_avoided_vs_full_scan: u64,
    /// Total candidates produced.
    pub candidate_count: usize,
    pub active_count: usize,
    pub orphaned_count: usize,
    pub unindexed_count: usize,
    pub deleted_count: usize,
    pub corrupted_count: usize,
    pub overwritten_count: usize,
    /// Candidates whose structural validation did not pass.
    pub validation_failures: usize,
    /// Ranges that could not be read and were recorded as skipped.
    pub skipped_range_count: usize,
    /// Whether the run hit a bound or was cancelled.
    pub truncated: bool,
    pub cancelled: bool,
}

impl RecoveryMetrics {
    /// Fold one candidate's state into the per-state counters.
    pub fn record_state(&mut self, state: DataState) {
        self.candidate_count += 1;
        match state {
            DataState::Active => self.active_count += 1,
            DataState::Orphaned => self.orphaned_count += 1,
            DataState::Unindexed => self.unindexed_count += 1,
            DataState::Deleted => self.deleted_count += 1,
            DataState::Corrupted => self.corrupted_count += 1,
            DataState::Overwritten => self.overwritten_count += 1,
        }
    }

    /// Emit the run summary as a single structured `tracing` event.
    ///
    /// Deliberately one event with named fields rather than a prose log line, so it can
    /// be filtered and machine-read in a forensic engineering session.
    pub fn emit(&self) {
        tracing::info!(
            target: "recovery::pipeline",
            oem_key = %self.oem_key,
            profile_id = %self.profile_id,
            geometry_available = self.geometry_available,
            video_region = self.video_region.as_deref().unwrap_or("unknown"),
            index_region = self.index_region.as_deref().unwrap_or("unknown"),
            block_size = self.block_size.unwrap_or(0),
            authoritative_index = self.authoritative_index,
            index_declared_entries = self.index_declared_entries.unwrap_or(0),
            index_entry_count = self.index_entry_count,
            claimed_range_count = self.claimed_range_count,
            claimed_bytes = self.claimed_bytes,
            unclaimed_region_count = self.unclaimed_region_count,
            unclaimed_bytes = self.unclaimed_bytes,
            available_claim_count = self.available_claim_count,
            available_bytes = self.available_bytes,
            available_candidates = self.available_candidate_count,
            container_record_candidates = self.container_record_candidate_count,
            orphan_eligible_region_count = self.orphan_eligible_region_count,
            orphan_eligible_bytes = self.orphan_eligible_bytes,
            scan_region_count = self.scan_region_count,
            scanned_bytes = self.scanned_bytes,
            bytes_avoided_vs_full_scan = self.bytes_avoided_vs_full_scan,
            candidate_count = self.candidate_count,
            active = self.active_count,
            orphaned = self.orphaned_count,
            unindexed = self.unindexed_count,
            deleted = self.deleted_count,
            corrupted = self.corrupted_count,
            overwritten = self.overwritten_count,
            validation_failures = self.validation_failures,
            skipped_ranges = self.skipped_range_count,
            truncated = self.truncated,
            cancelled = self.cancelled,
            "index-aware recovery run complete"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_counters_are_independent() {
        let mut m = RecoveryMetrics::default();
        m.record_state(DataState::Active);
        m.record_state(DataState::Orphaned);
        m.record_state(DataState::Orphaned);
        m.record_state(DataState::Unindexed);
        assert_eq!(m.candidate_count, 4);
        assert_eq!(m.active_count, 1);
        assert_eq!(m.orphaned_count, 2);
        assert_eq!(m.unindexed_count, 1);
        assert_eq!(m.deleted_count, 0);
    }

    #[test]
    fn metrics_serialize_for_api_transport() {
        let m = RecoveryMetrics {
            oem_key: "dahua".into(),
            ..Default::default()
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"oem_key\":\"dahua\""));
        assert!(json.contains("unindexed_count"));
    }
}
