//! # Recovery planning
//!
//! Turns OEM storage evidence into an explicit list of physical ranges to read.
//!
//! ```text
//!   StorageGeometry + RecordingIndex
//!            │
//!            ▼
//!        ClaimMap  (claimed / unclaimed, via RangeSet)
//!            │
//!            ▼
//!   Vec<ScanTarget>   ← exact physical offsets, each tagged with its claim
//! ```
//!
//! ## Why this is not a whole-disk sweep
//!
//! With an authoritative index the planner does two different things:
//!
//! * **Claimed ranges** get one bounded *probe* each, capped at
//!   [`CLAIM_PROBE_BYTES`]. Confirming that an indexed recording's video is present
//!   needs its header, not its whole payload — a 40 MB recording costs one 256 KiB read
//!   instead of forty 1 MiB reads.
//! * **Unclaimed ranges** get a chunked sweep, because that is where unknown video may
//!   be and its position is not declared anywhere.
//!
//! When the parser supplies no index the planner falls back to a whole-window sweep, and
//! every target carries `NoIndexEvidence` so no `Active`/`Orphaned` conclusion is reachable.
//!
//! Every target keeps absolute physical offsets. Nothing is rebased to zero, and no
//! target is converted into an anonymous buffer.

use forensic_core::{ForensicError, Region};
use parsers_core::storage::{RecordingIndex, StorageGeometry};
use serde::{Deserialize, Serialize};

use crate::claims::{build_claim_map, empty_claim_map, ClaimMap, UnclaimedKind};
use crate::classification::RegionClaim;
use crate::fragment::DiscoveryMethod;

/// Bytes read to confirm video presence inside an index-claimed range.
///
/// An indexed recording's codec evidence lives in its leading parameter sets, so a
/// bounded head probe is sufficient to establish presence and validity. Reading the
/// whole claimed payload would be a full-disk scan by another name.
pub const CLAIM_PROBE_BYTES: u64 = 256 * 1024;

/// Chunk size used when sweeping unclaimed space.
pub const UNCLAIMED_CHUNK_BYTES: u64 = 1024 * 1024;

/// One bounded read the scanner will perform, with the claim that governs it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanTarget {
    /// The exact physical bytes to read. Absolute offsets in the evidence.
    pub region: Region,
    /// The larger planner region this target was carved from — a claimed range or an
    /// unclaimed range. Preserved for fragment provenance.
    pub originating_region: Region,
    /// The elementary-stream payload sub-range of `originating_region`, when the OEM
    /// parser separated container framing from payload. `None` for unclaimed space,
    /// where no framing is established.
    pub payload_region: Option<Region>,
    /// What the index says about these bytes. The scanner never computes this itself.
    pub claim: RegionClaim,
    /// How a fragment found here was discovered.
    pub discovery_method: DiscoveryMethod,
}

/// The full plan for one recovery run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveryPlan {
    /// The address space planned over.
    pub universe: Region,
    /// Storage geometry, when the OEM parser established it.
    pub geometry: Option<StorageGeometry>,
    /// Recording index, when the OEM parser read one.
    pub index: Option<RecordingIndex>,
    /// Claimed vs unclaimed comparison.
    pub claim_map: ClaimMap,
    /// Ordered, bounded scan targets.
    pub targets: Vec<ScanTarget>,
    /// Bytes the planner will actually read.
    pub planned_bytes: u64,
    /// Human-readable account of how the plan was derived.
    pub rationale: String,
}

impl RecoveryPlan {
    /// Bytes a naive whole-window sweep would have read.
    pub fn full_scan_bytes(&self) -> u64 {
        self.universe.length
    }

    /// Bytes avoided relative to a whole-window sweep (saturating at zero).
    pub fn bytes_avoided(&self) -> u64 {
        self.full_scan_bytes().saturating_sub(self.planned_bytes)
    }
}

/// Split a region into chunks of at most `chunk` bytes, preserving absolute offsets.
fn chunk_region(region: Region, chunk: u64) -> Vec<Region> {
    if region.is_empty() || chunk == 0 {
        return Vec::new();
    }
    let end = region.end().unwrap_or(u64::MAX);
    let mut out = Vec::new();
    let mut cursor = region.offset;
    while cursor < end {
        let len = chunk.min(end - cursor);
        if let Ok(r) = Region::new(cursor, len) {
            out.push(r);
        }
        cursor = cursor.saturating_add(len);
    }
    out
}

/// Build a recovery plan from OEM storage evidence.
///
/// `geometry` and `index` are whatever the OEM parser could establish; either may be
/// `None`, and the plan degrades honestly rather than inventing structure.
pub fn plan_recovery(
    universe: Region,
    geometry: Option<StorageGeometry>,
    index: Option<RecordingIndex>,
) -> Result<RecoveryPlan, ForensicError> {
    // Build the claim map. Without an index there is nothing claimed, and the whole
    // universe is unclaimed-but-ungoverned.
    let claim_map = match index.as_ref() {
        Some(ix) => build_claim_map(ix, geometry.as_ref(), universe)?,
        None => empty_claim_map(universe)?,
    };

    let mut targets: Vec<ScanTarget> = Vec::new();

    // 1. Probe each index-claimed range to confirm what the recorder says is there.
    //    Bounded: a claim's head is what establishes presence.
    for claim in &claim_map.claims {
        let probe_len = claim.region.length.min(CLAIM_PROBE_BYTES);
        if probe_len == 0 {
            continue;
        }
        let probe = Region::new(claim.region.offset, probe_len)?;
        targets.push(ScanTarget {
            region: probe,
            originating_region: claim.region,
            payload_region: claim.payload_region,
            claim: RegionClaim::from_claim(claim),
            discovery_method: DiscoveryMethod::IndexClaimedProbe,
        });
    }

    // 2. Sweep unclaimed space. This is where non-Active candidates come from.
    let has_index = claim_map.has_authoritative_index() || index.is_some();
    for unclaimed in &claim_map.unclaimed_regions {
        let (claim, method) = match unclaimed.kind {
            UnclaimedKind::WithinAuthoritativeIndexScope => (
                RegionClaim::UnclaimedWithinIndexScope {
                    index_entry_count: claim_map.claims.len(),
                },
                DiscoveryMethod::UnclaimedScanInIndexScope,
            ),
            UnclaimedKind::OutsideIndexScope if claim_map.has_authoritative_index() => (
                RegionClaim::OutsideIndexScope {
                    reason: format!(
                        "outside the region the authoritative index governs ({})",
                        claim_map
                            .authoritative_scope
                            .map(|r| r.to_string())
                            .unwrap_or_else(|| "none".into())
                    ),
                },
                DiscoveryMethod::UnclaimedScanOutsideIndexScope,
            ),
            UnclaimedKind::OutsideIndexScope => (
                RegionClaim::NoIndexEvidence {
                    reason: match index.as_ref() {
                        Some(ix) => format!(
                            "the recording index is not authoritative: {}",
                            match &ix.authority {
                                parsers_core::storage::IndexAuthority::Partial { reason } => {
                                    reason.clone()
                                }
                                parsers_core::storage::IndexAuthority::NotFound { reason } => {
                                    reason.clone()
                                }
                                parsers_core::storage::IndexAuthority::Authoritative { .. } =>
                                    "authoritative".to_string(),
                            }
                        ),
                        None => {
                            "this OEM path supplied no recording index reader".to_string()
                        }
                    },
                },
                if has_index {
                    DiscoveryMethod::UnclaimedScanOutsideIndexScope
                } else {
                    DiscoveryMethod::WholeImageScanWithoutIndex
                },
            ),
        };

        for chunk in chunk_region(unclaimed.region, UNCLAIMED_CHUNK_BYTES) {
            targets.push(ScanTarget {
                region: chunk,
                originating_region: unclaimed.region,
                // Unclaimed space has no established container framing, so no payload
                // boundary may be claimed for it.
                payload_region: None,
                claim: claim.clone(),
                discovery_method: method,
            });
        }
    }

    // Deterministic order: ascending physical offset, so two runs over the same evidence
    // produce byte-identical plans and candidate ordering.
    targets.sort_by_key(|t| (t.region.offset, t.region.length));

    let planned_bytes = targets
        .iter()
        .fold(0u64, |acc, t| acc.saturating_add(t.region.length));

    let rationale = if claim_map.has_authoritative_index() {
        format!(
            "Authoritative index supplied {claims} claim(s) covering {claimed} byte(s); \
             {unclaimed_n} unclaimed region(s) totalling {unclaimed} byte(s) remain, of which \
             {orphan_n} region(s) / {orphan} byte(s) fall inside the governed scope and are \
             orphan-eligible. Claimed ranges are probed at up to {probe} bytes each instead of \
             swept, so the plan reads {planned} of {total} byte(s).",
            claims = claim_map.claims.len(),
            claimed = claim_map.claimed_bytes(),
            unclaimed_n = claim_map.unclaimed.count(),
            unclaimed = claim_map.unclaimed_bytes(),
            orphan_n = claim_map
                .unclaimed_regions
                .iter()
                .filter(|u| u.kind == UnclaimedKind::WithinAuthoritativeIndexScope)
                .count(),
            orphan = claim_map
                .unclaimed_regions
                .iter()
                .filter(|u| u.kind == UnclaimedKind::WithinAuthoritativeIndexScope)
                .fold(0u64, |a, u| a.saturating_add(u.region.length)),
            probe = CLAIM_PROBE_BYTES,
            planned = planned_bytes,
            total = universe.length,
        )
    } else {
        format!(
            "No authoritative recording index was established, so nothing is claimed and no \
             region is orphan-eligible. The full {total}-byte window is swept in {chunk}-byte \
             chunks and any video found can only be reported as unindexed.",
            total = universe.length,
            chunk = UNCLAIMED_CHUNK_BYTES,
        )
    };

    Ok(RecoveryPlan {
        universe,
        geometry,
        index,
        claim_map,
        targets,
        planned_bytes,
        rationale,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_core::{ValidationState, ValidationStateKind};
    use parsers_core::storage::{
        AllocationEvidence, CircularBufferEvidence, IndexAuthority, IndexedRecording,
    };
    use std::collections::BTreeMap;

    fn r(offset: u64, length: u64) -> Region {
        Region::new(offset, length).unwrap()
    }

    fn state() -> ValidationState {
        ValidationState::new(ValidationStateKind::Pass, "t", "t", "t").unwrap()
    }

    fn entry(id: &str, region: Region) -> IndexedRecording {
        IndexedRecording {
            recording_id: id.into(),
            channel: Some(2),
            start_time_unix: Some(1_700_000_000),
            end_time_unix: None,
            physical_regions: vec![region],
            payload_regions: vec![],
            codec_hint: None,
            allocation: AllocationEvidence::Unknown,
            oem_metadata: BTreeMap::new(),
            evidence: state(),
        }
    }

    fn geometry(video: Region, index: Region, size: u64) -> StorageGeometry {
        StorageGeometry {
            physical_size: size,
            video_region: Some(video),
            index_region: Some(index),
            metadata_region: Some(r(0, 512)),
            block_size: Some(65536),
            sector_size: Some(512),
            circular_buffer: CircularBufferEvidence::Unknown,
            oem_fields: BTreeMap::new(),
            evidence: state(),
        }
    }

    #[test]
    fn chunking_preserves_absolute_offsets_and_total_length() {
        let chunks = chunk_region(r(1_000_000, 2_500_000), 1_000_000);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0], r(1_000_000, 1_000_000));
        assert_eq!(chunks[1], r(2_000_000, 1_000_000));
        assert_eq!(chunks[2], r(3_000_000, 500_000));
        assert_eq!(chunks.iter().map(|c| c.length).sum::<u64>(), 2_500_000);
    }

    #[test]
    fn chunking_an_empty_region_yields_nothing() {
        assert!(chunk_region(Region::point(42), 1024).is_empty());
    }

    #[test]
    fn indexed_claims_are_probed_not_swept() {
        // One 8 MiB claim: a sweep would be 8 chunks, a probe is one 256 KiB read.
        let claim = r(1 << 20, 8 << 20);
        let index = RecordingIndex {
            authority: IndexAuthority::Authoritative {
                governs: r(1 << 20, 16 << 20),
            },
            recordings: vec![entry("didx#0", claim)],
            declared_entry_count: Some(1),
            index_region: None,
            evidence: state(),
        };
        let plan = plan_recovery(r(0, 32 << 20), None, Some(index)).unwrap();

        let probes: Vec<&ScanTarget> = plan
            .targets
            .iter()
            .filter(|t| t.discovery_method == DiscoveryMethod::IndexClaimedProbe)
            .collect();
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].region, r(1 << 20, CLAIM_PROBE_BYTES));
        assert_eq!(probes[0].originating_region, claim);
        assert!(matches!(probes[0].claim, RegionClaim::Indexed { .. }));
        // The plan reads strictly less than the whole window.
        assert!(plan.planned_bytes < plan.full_scan_bytes());
        assert!(plan.bytes_avoided() > 0);
    }

    #[test]
    fn unclaimed_space_inside_the_index_scope_is_orphan_eligible_and_swept() {
        // Video region [1 MiB, 5 MiB); the index claims only the first MiB of it.
        let video = r(1 << 20, 4 << 20);
        let index = RecordingIndex {
            authority: IndexAuthority::Authoritative { governs: video },
            recordings: vec![entry("didx#0", r(1 << 20, 1 << 20))],
            declared_entry_count: Some(1),
            index_region: None,
            evidence: state(),
        };
        let geo = geometry(video, r(5 << 20, 4096), 8 << 20);
        let plan = plan_recovery(r(0, 8 << 20), Some(geo), Some(index)).unwrap();

        let orphan_targets: Vec<&ScanTarget> = plan
            .targets
            .iter()
            .filter(|t| t.discovery_method == DiscoveryMethod::UnclaimedScanInIndexScope)
            .collect();
        // [2 MiB, 5 MiB) unclaimed inside scope -> 3 one-MiB chunks.
        assert_eq!(orphan_targets.len(), 3);
        assert_eq!(orphan_targets[0].region, r(2 << 20, 1 << 20));
        assert!(orphan_targets
            .iter()
            .all(|t| matches!(t.claim, RegionClaim::UnclaimedWithinIndexScope { .. })));

        // Space before and after the video region is outside the index's statement.
        let outside: Vec<&ScanTarget> = plan
            .targets
            .iter()
            .filter(|t| t.discovery_method == DiscoveryMethod::UnclaimedScanOutsideIndexScope)
            .collect();
        assert!(!outside.is_empty());
        assert!(outside
            .iter()
            .all(|t| matches!(t.claim, RegionClaim::OutsideIndexScope { .. })));
    }

    #[test]
    fn without_an_index_every_target_is_ungoverned() {
        let plan = plan_recovery(r(0, 3 << 20), None, None).unwrap();

        assert_eq!(plan.targets.len(), 3);
        assert!(plan
            .targets
            .iter()
            .all(|t| matches!(t.claim, RegionClaim::NoIndexEvidence { .. })));
        assert!(plan
            .targets
            .iter()
            .all(|t| t.discovery_method == DiscoveryMethod::WholeImageScanWithoutIndex));
        // A fallback sweep reads everything; nothing is avoided, and that is reported.
        assert_eq!(plan.planned_bytes, plan.full_scan_bytes());
        assert_eq!(plan.bytes_avoided(), 0);
        assert!(plan.rationale.contains("unindexed"));
    }

    #[test]
    fn a_partial_index_still_narrows_reads_but_grants_no_orphan_space() {
        let index = RecordingIndex {
            authority: IndexAuthority::Partial {
                reason: "2 of 3 entries parsed".into(),
            },
            recordings: vec![entry("didx#0", r(1 << 20, 1 << 20))],
            declared_entry_count: Some(3),
            index_region: None,
            evidence: state(),
        };
        let plan = plan_recovery(r(0, 4 << 20), None, Some(index)).unwrap();

        assert!(!plan.claim_map.has_authoritative_index());
        assert!(plan
            .targets
            .iter()
            .all(|t| !matches!(t.claim, RegionClaim::UnclaimedWithinIndexScope { .. })));
        // The partial index's own claim is still probed rather than swept.
        assert!(plan
            .targets
            .iter()
            .any(|t| t.discovery_method == DiscoveryMethod::IndexClaimedProbe));
    }

    #[test]
    fn targets_are_ordered_by_physical_offset_for_determinism() {
        let video = r(512, (4 << 20) - 512);
        let index = RecordingIndex {
            authority: IndexAuthority::Authoritative { governs: video },
            recordings: vec![
                entry("didx#1", r(2 << 20, 4096)),
                entry("didx#0", r(512, 4096)),
            ],
            declared_entry_count: Some(2),
            index_region: None,
            evidence: state(),
        };
        let plan = plan_recovery(r(0, 4 << 20), None, Some(index)).unwrap();

        let offsets: Vec<u64> = plan.targets.iter().map(|t| t.region.offset).collect();
        let mut sorted = offsets.clone();
        sorted.sort_unstable();
        assert_eq!(offsets, sorted);
    }

    #[test]
    fn an_empty_universe_plans_no_reads() {
        let plan = plan_recovery(Region::point(0), None, None).unwrap();
        assert!(plan.targets.is_empty());
        assert_eq!(plan.planned_bytes, 0);
    }
}
