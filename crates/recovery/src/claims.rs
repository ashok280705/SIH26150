//! # Claimed vs unclaimed physical space
//!
//! This module performs the central comparison of the whole recovery path:
//!
//! ```text
//!   what the DVR's index says exists   ──►  ClaimedRanges
//!   the physical address space         ──►  universe
//!   universe − ClaimedRanges           ──►  UnclaimedRegions
//! ```
//!
//! It is deliberately OEM-agnostic: it consumes [`RecordingIndex`] — plain [`Region`]s
//! plus optional metadata — and never interprets an OEM index format. The single
//! canonical [`RangeSet`] from `forensic-core` does all the range algebra; this module
//! introduces no competing range abstraction.
//!
//! ## Why unclaimed regions are classified into two kinds
//!
//! Absence from an index only supports an *orphan* conclusion where that index is an
//! authoritative, complete statement. So each unclaimed region records whether it falls
//! inside the region the index actually governs:
//!
//! * inside  → the index positively does not reference these bytes → orphan-eligible
//! * outside → the index makes no statement here → unindexed only
//!
//! That distinction is what keeps "not in the index" from silently becoming "deleted".

use forensic_core::{ForensicError, RangeSet, Region};
use parsers_core::storage::{
    AllocationEvidence, IndexAuthority, IndexedRecording, RecordingIndex, StorageGeometry,
};
use serde::{Deserialize, Serialize};

/// One physical range an OEM index claims, with enough back-reference to trace the
/// claim to the index entry that made it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimedRegion {
    /// Exact physical byte range, as the index declared it (clipped to the universe).
    pub region: Region,
    /// The elementary-stream payload sub-range inside `region`, when the OEM parser
    /// could separate container framing from payload.
    pub payload_region: Option<Region>,
    /// Identifier of the index entry that made this claim (e.g. "didx#3").
    pub recording_id: String,
    /// Channel, only if the index recorded one.
    pub channel: Option<u32>,
    /// Start time as unix seconds, only if the index recorded one.
    pub start_time_unix: Option<i64>,
    /// Allocation state of the claiming entry per the OEM structures.
    pub allocation: AllocationEvidence,
}

/// Why an unclaimed region is unclaimed, and therefore what may be concluded about
/// valid video found inside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnclaimedKind {
    /// Inside the region an authoritative index governs, and unreferenced by it. Valid
    /// video here is physically present and positively not referenced by the recorder's
    /// current index — the evidentiary basis for an orphan finding.
    WithinAuthoritativeIndexScope,
    /// Outside the scope of any authoritative index, or the governing index was only
    /// partial. The index makes no statement here, so no orphan conclusion is licensed.
    OutsideIndexScope,
}

/// A physical range no index entry claims, tagged with the strength of that fact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnclaimedRegion {
    /// Exact physical byte range. Offsets are absolute in the evidence, never rebased.
    pub region: Region,
    /// What kind of "unclaimed" this is.
    pub kind: UnclaimedKind,
}

/// The result of comparing an OEM index against the physical address space.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimMap {
    /// The address space the comparison was performed over.
    pub universe: Region,
    /// The region an authoritative index governs, if any. `None` means no authoritative
    /// index applies, in which case every unclaimed region is `OutsideIndexScope`.
    pub authoritative_scope: Option<Region>,
    /// Canonical set of claimed ranges (merged, sorted, disjoint).
    pub claimed: RangeSet,
    /// Canonical complement of `claimed` within `universe`.
    pub unclaimed: RangeSet,
    /// Per-entry claims, preserving the index → range provenance the canonical
    /// `RangeSet` necessarily loses when it merges adjacent ranges.
    pub claims: Vec<ClaimedRegion>,
    /// Unclaimed ranges, each tagged with what may be concluded there.
    pub unclaimed_regions: Vec<UnclaimedRegion>,
    /// Claims the index declared that fell wholly outside the universe and were
    /// therefore excluded, recorded so the exclusion is auditable rather than silent.
    pub out_of_universe_claims: Vec<String>,
}

impl ClaimMap {
    /// Total bytes claimed by the index within the universe.
    pub fn claimed_bytes(&self) -> u64 {
        self.claimed.total_length()
    }

    /// Total bytes in the universe that no index entry claims.
    pub fn unclaimed_bytes(&self) -> u64 {
        self.unclaimed.total_length()
    }

    /// Whether any authoritative index governs this evidence.
    pub fn has_authoritative_index(&self) -> bool {
        self.authoritative_scope.is_some()
    }

    /// The claim covering `offset`, if any. Used to attribute a discovered fragment
    /// back to the index entry whose bytes it sits in.
    pub fn claim_at(&self, offset: u64) -> Option<&ClaimedRegion> {
        self.claims.iter().find(|c| c.region.contains(offset))
    }

    /// How an offset relates to the index, for the classifier.
    pub fn kind_at(&self, offset: u64) -> Option<UnclaimedKind> {
        self.unclaimed_regions
            .iter()
            .find(|u| u.region.contains(offset))
            .map(|u| u.kind)
    }
}

/// Build a claim map with **no** index evidence: nothing is claimed, and the entire
/// universe is unclaimed but outside any index scope.
///
/// This is the honest representation for an OEM path with no index reader. Because every
/// region is `OutsideIndexScope`, discovered video can only reach the conservative
/// unindexed state — never `Active`, never `Orphaned`.
pub fn empty_claim_map(universe: Region) -> Result<ClaimMap, ForensicError> {
    let claimed = RangeSet::new();
    let unclaimed = claimed.complement_within(universe)?;
    let unclaimed_regions = unclaimed
        .iter()
        .map(|r| UnclaimedRegion {
            region: *r,
            kind: UnclaimedKind::OutsideIndexScope,
        })
        .collect();
    Ok(ClaimMap {
        universe,
        authoritative_scope: None,
        claimed,
        unclaimed,
        claims: Vec::new(),
        unclaimed_regions,
        out_of_universe_claims: Vec::new(),
    })
}

/// Clip an index-declared region to the universe.
///
/// Returns `None` when the claim lies wholly outside. Clipping (rather than dropping a
/// partially-overlapping claim) keeps the claimed set faithful to the recorder's
/// statement about the bytes we actually hold.
fn clip(region: Region, universe: Region) -> Option<Region> {
    region.intersection(&universe).filter(|r| !r.is_empty())
}

/// Turn one index entry into its claimed regions within `universe`.
fn claims_from_entry(
    entry: &IndexedRecording,
    universe: Region,
    excluded: &mut Vec<String>,
) -> Vec<ClaimedRegion> {
    let mut out = Vec::new();
    for (i, declared) in entry.physical_regions.iter().enumerate() {
        match clip(*declared, universe) {
            Some(clipped) => {
                // Pair the payload sub-range with its parent region only when it is
                // genuinely inside the clipped span; a payload range that survived
                // clipping differently would misdescribe the claim.
                let payload_region = entry
                    .payload_regions
                    .get(i)
                    .and_then(|p| clip(*p, clipped));
                out.push(ClaimedRegion {
                    region: clipped,
                    payload_region,
                    recording_id: entry.recording_id.clone(),
                    channel: entry.channel,
                    start_time_unix: entry.start_time_unix,
                    allocation: entry.allocation,
                });
            }
            None => excluded.push(format!(
                "{}: declared {} lies outside the scanned address space {}",
                entry.recording_id, declared, universe
            )),
        }
    }
    out
}

/// Compare an OEM recording index against a physical address space.
///
/// `universe` is the address space being reasoned about — normally the whole evidence,
/// or the caller's explicit scan window. Claims are clipped to it; the complement within
/// it becomes the unclaimed set.
///
/// `geometry` is optional and only refines the reported region kinds; the claim algebra
/// itself depends solely on the index.
pub fn build_claim_map(
    index: &RecordingIndex,
    geometry: Option<&StorageGeometry>,
    universe: Region,
) -> Result<ClaimMap, ForensicError> {
    if universe.is_empty() {
        return empty_claim_map(universe);
    }

    let mut out_of_universe_claims = Vec::new();
    let mut claims: Vec<ClaimedRegion> = Vec::new();
    for entry in &index.recordings {
        claims.extend(claims_from_entry(entry, universe, &mut out_of_universe_claims));
    }

    // Canonical merge via the platform's single range implementation.
    let claimed = RangeSet::from_regions(claims.iter().map(|c| c.region))?;
    let unclaimed = claimed.complement_within(universe)?;

    // An authoritative index only governs the region it says it governs, intersected
    // with what we are actually looking at. A partial or missing index governs nothing.
    let authoritative_scope = match &index.authority {
        IndexAuthority::Authoritative { governs } => {
            // Prefer the geometry's video region when the index defers to it; both are
            // evidence-derived, and the narrower of the two is the safer scope.
            let scope = match geometry.and_then(|g| g.video_region) {
                Some(video) => video.intersection(governs).unwrap_or(*governs),
                None => *governs,
            };
            clip(scope, universe)
        }
        IndexAuthority::Partial { .. } | IndexAuthority::NotFound { .. } => None,
    };

    let unclaimed_regions = unclaimed
        .iter()
        .flat_map(|r| split_by_scope(*r, authoritative_scope))
        .collect();

    Ok(ClaimMap {
        universe,
        authoritative_scope,
        claimed,
        unclaimed,
        claims,
        unclaimed_regions,
        out_of_universe_claims,
    })
}

/// Split an unclaimed range at the boundaries of the authoritative scope so each piece
/// carries exactly one conclusion strength.
///
/// A range straddling the scope boundary must not be labelled wholesale: the bytes
/// inside the scope are orphan-eligible and the bytes outside are not.
fn split_by_scope(region: Region, scope: Option<Region>) -> Vec<UnclaimedRegion> {
    let scope = match scope {
        Some(s) if !s.is_empty() => s,
        _ => {
            return vec![UnclaimedRegion {
                region,
                kind: UnclaimedKind::OutsideIndexScope,
            }]
        }
    };

    let inside = region.intersection(&scope).filter(|r| !r.is_empty());
    let Some(inside) = inside else {
        return vec![UnclaimedRegion {
            region,
            kind: UnclaimedKind::OutsideIndexScope,
        }];
    };

    let r_start = region.offset;
    let r_end = region.end().unwrap_or(u64::MAX);
    let i_start = inside.offset;
    let i_end = inside.end().unwrap_or(u64::MAX);

    let mut out = Vec::new();
    if i_start > r_start {
        if let Ok(left) = Region::new(r_start, i_start - r_start) {
            out.push(UnclaimedRegion {
                region: left,
                kind: UnclaimedKind::OutsideIndexScope,
            });
        }
    }
    out.push(UnclaimedRegion {
        region: inside,
        kind: UnclaimedKind::WithinAuthoritativeIndexScope,
    });
    if r_end > i_end {
        if let Ok(right) = Region::new(i_end, r_end - i_end) {
            out.push(UnclaimedRegion {
                region: right,
                kind: UnclaimedKind::OutsideIndexScope,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_core::{ValidationState, ValidationStateKind};
    use std::collections::BTreeMap;

    fn r(offset: u64, length: u64) -> Region {
        Region::new(offset, length).unwrap()
    }

    fn state() -> ValidationState {
        ValidationState::new(ValidationStateKind::Pass, "test", "test", "test").unwrap()
    }

    fn entry(id: &str, regions: Vec<Region>) -> IndexedRecording {
        IndexedRecording {
            recording_id: id.to_string(),
            channel: Some(1),
            start_time_unix: Some(1_700_000_000),
            end_time_unix: None,
            physical_regions: regions,
            payload_regions: Vec::new(),
            codec_hint: None,
            allocation: AllocationEvidence::Unknown,
            oem_metadata: BTreeMap::new(),
            evidence: state(),
        }
    }

    fn authoritative(entries: Vec<IndexedRecording>, governs: Region) -> RecordingIndex {
        let n = entries.len();
        RecordingIndex {
            authority: IndexAuthority::Authoritative { governs },
            recordings: entries,
            declared_entry_count: Some(n),
            index_region: None,
            evidence: state(),
        }
    }

    fn partial(entries: Vec<IndexedRecording>) -> RecordingIndex {
        let n = entries.len();
        RecordingIndex {
            authority: IndexAuthority::Partial {
                reason: "truncated".into(),
            },
            recordings: entries,
            declared_entry_count: Some(n + 1),
            index_region: None,
            evidence: state(),
        }
    }

    // ── Claimed range construction ──────────────────────────────────────────

    #[test]
    fn claimed_ranges_preserve_exact_physical_offsets() {
        let index = authoritative(
            vec![
                entry("a", vec![r(100 << 20, 50 << 20)]),
                entry("b", vec![r(300 << 20, 40 << 20)]),
            ],
            r(0, 1000 << 20),
        );
        let map = build_claim_map(&index, None, r(0, 1000 << 20)).unwrap();

        assert_eq!(map.claimed.count(), 2);
        assert_eq!(map.claimed.ranges()[0], r(100 << 20, 50 << 20));
        assert_eq!(map.claimed.ranges()[1], r(300 << 20, 40 << 20));
        assert_eq!(map.claimed_bytes(), (50 + 40) << 20);
        // The per-entry provenance survives the canonical merge.
        assert_eq!(map.claims.len(), 2);
        assert_eq!(map.claims[0].recording_id, "a");
        assert_eq!(map.claims[0].region.offset, 100 << 20);
    }

    #[test]
    fn range_subtraction_produces_the_exact_complement() {
        // Disk [0,1000); claimed [100,200) [400,500) [700,800).
        let index = authoritative(
            vec![
                entry("a", vec![r(100, 100)]),
                entry("b", vec![r(400, 100)]),
                entry("c", vec![r(700, 100)]),
            ],
            r(0, 1000),
        );
        let map = build_claim_map(&index, None, r(0, 1000)).unwrap();

        let got: Vec<Region> = map.unclaimed.ranges().to_vec();
        assert_eq!(
            got,
            vec![r(0, 100), r(200, 200), r(500, 200), r(800, 200)],
            "unclaimed must be the exact complement"
        );
        assert_eq!(map.claimed_bytes() + map.unclaimed_bytes(), 1000);
    }

    #[test]
    fn overlapping_claims_merge_without_double_counting() {
        let index = authoritative(
            vec![
                entry("a", vec![r(100, 150)]), // [100,250)
                entry("b", vec![r(200, 100)]), // [200,300)
            ],
            r(0, 1000),
        );
        let map = build_claim_map(&index, None, r(0, 1000)).unwrap();

        assert_eq!(map.claimed.count(), 1);
        assert_eq!(map.claimed.ranges()[0], r(100, 200)); // [100,300)
        assert_eq!(map.claimed_bytes(), 200, "overlap counted once");
        // Both entries still traceable.
        assert_eq!(map.claims.len(), 2);
    }

    #[test]
    fn adjacent_claims_merge_and_leave_no_phantom_gap() {
        let index = authoritative(
            vec![
                entry("a", vec![r(100, 100)]), // [100,200)
                entry("b", vec![r(200, 100)]), // [200,300)
            ],
            r(0, 1000),
        );
        let map = build_claim_map(&index, None, r(0, 1000)).unwrap();

        assert_eq!(map.claimed.count(), 1);
        assert_eq!(map.claimed.ranges()[0], r(100, 200));
        assert_eq!(map.unclaimed.ranges(), &[r(0, 100), r(300, 700)]);
    }

    #[test]
    fn empty_index_leaves_the_whole_universe_unclaimed() {
        let index = authoritative(vec![], r(0, 1000));
        let map = build_claim_map(&index, None, r(0, 1000)).unwrap();

        assert!(map.claimed.is_empty());
        assert_eq!(map.unclaimed.ranges(), &[r(0, 1000)]);
        assert_eq!(map.unclaimed_bytes(), 1000);
    }

    #[test]
    fn empty_universe_yields_empty_sets() {
        let index = authoritative(vec![entry("a", vec![r(100, 100)])], r(0, 1000));
        let map = build_claim_map(&index, None, Region::point(500)).unwrap();

        assert!(map.claimed.is_empty());
        assert!(map.unclaimed.is_empty());
    }

    #[test]
    fn zero_length_claims_are_never_stored() {
        let index = authoritative(vec![entry("a", vec![Region::point(400)])], r(0, 1000));
        let map = build_claim_map(&index, None, r(0, 1000)).unwrap();

        assert!(map.claimed.is_empty(), "a zero-length claim claims nothing");
        assert_eq!(map.unclaimed.ranges(), &[r(0, 1000)]);
    }

    #[test]
    fn out_of_bounds_claim_is_excluded_and_recorded() {
        let index = authoritative(
            vec![
                entry("inside", vec![r(100, 100)]),
                entry("beyond", vec![r(5000, 100)]),
            ],
            r(0, 1000),
        );
        let map = build_claim_map(&index, None, r(0, 1000)).unwrap();

        assert_eq!(map.claimed.ranges(), &[r(100, 100)]);
        assert_eq!(map.out_of_universe_claims.len(), 1);
        assert!(map.out_of_universe_claims[0].contains("beyond"));
    }

    #[test]
    fn straddling_claim_is_clipped_to_the_universe() {
        let index = authoritative(vec![entry("a", vec![r(900, 500)])], r(0, 1000));
        let map = build_claim_map(&index, None, r(0, 1000)).unwrap();

        assert_eq!(map.claimed.ranges(), &[r(900, 100)], "clipped at the boundary");
        assert_eq!(map.unclaimed.ranges(), &[r(0, 900)]);
    }

    #[test]
    fn claim_covering_the_whole_universe_leaves_nothing_unclaimed() {
        let index = authoritative(vec![entry("a", vec![r(0, 1000)])], r(0, 1000));
        let map = build_claim_map(&index, None, r(0, 1000)).unwrap();

        assert_eq!(map.claimed.ranges(), &[r(0, 1000)]);
        assert!(map.unclaimed.is_empty());
    }

    #[test]
    fn scan_window_universe_preserves_absolute_offsets() {
        // Scanning only [2000,3000) must not rebase offsets to zero.
        let index = authoritative(vec![entry("a", vec![r(2100, 100)])], r(0, 10_000));
        let map = build_claim_map(&index, None, r(2000, 1000)).unwrap();

        assert_eq!(map.claimed.ranges(), &[r(2100, 100)]);
        assert_eq!(map.unclaimed.ranges(), &[r(2000, 100), r(2200, 800)]);
    }

    // ── Conclusion scope ────────────────────────────────────────────────────

    #[test]
    fn unclaimed_inside_authoritative_scope_is_orphan_eligible() {
        // Index governs the video region [500,900) only.
        let index = authoritative(vec![entry("a", vec![r(500, 100)])], r(500, 400));
        let map = build_claim_map(&index, None, r(0, 1000)).unwrap();

        assert_eq!(map.authoritative_scope, Some(r(500, 400)));
        // [0,500) outside, [600,900) inside, [900,1000) outside.
        assert_eq!(
            map.unclaimed_regions,
            vec![
                UnclaimedRegion { region: r(0, 500), kind: UnclaimedKind::OutsideIndexScope },
                UnclaimedRegion {
                    region: r(600, 300),
                    kind: UnclaimedKind::WithinAuthoritativeIndexScope
                },
                UnclaimedRegion { region: r(900, 100), kind: UnclaimedKind::OutsideIndexScope },
            ]
        );
        assert_eq!(
            map.kind_at(700),
            Some(UnclaimedKind::WithinAuthoritativeIndexScope)
        );
        assert_eq!(map.kind_at(50), Some(UnclaimedKind::OutsideIndexScope));
    }

    #[test]
    fn a_partial_index_grants_no_authoritative_scope() {
        // Same geometry, but the index could not be fully parsed: absence proves nothing,
        // so no region may be called orphaned.
        let index = partial(vec![entry("a", vec![r(500, 100)])]);
        let map = build_claim_map(&index, None, r(0, 1000)).unwrap();

        assert_eq!(map.authoritative_scope, None);
        assert!(!map.has_authoritative_index());
        assert!(map
            .unclaimed_regions
            .iter()
            .all(|u| u.kind == UnclaimedKind::OutsideIndexScope));
        // The claim itself is still honoured — a partial index still tells us what it
        // did manage to reference.
        assert_eq!(map.claimed.ranges(), &[r(500, 100)]);
    }

    #[test]
    fn geometry_narrows_the_authoritative_scope() {
        let geometry = StorageGeometry {
            physical_size: 1000,
            video_region: Some(r(500, 200)), // narrower than the index's own claim
            index_region: None,
            metadata_region: None,
            block_size: None,
            sector_size: None,
            circular_buffer: parsers_core::storage::CircularBufferEvidence::Unknown,
            oem_fields: BTreeMap::new(),
            evidence: state(),
        };
        let index = authoritative(vec![entry("a", vec![r(500, 100)])], r(500, 400));
        let map = build_claim_map(&index, Some(&geometry), r(0, 1000)).unwrap();

        assert_eq!(map.authoritative_scope, Some(r(500, 200)));
        assert_eq!(
            map.kind_at(650),
            Some(UnclaimedKind::WithinAuthoritativeIndexScope)
        );
        // Past the video region the index says nothing.
        assert_eq!(map.kind_at(800), Some(UnclaimedKind::OutsideIndexScope));
    }

    #[test]
    fn no_index_evidence_means_no_orphan_eligible_space() {
        let map = empty_claim_map(r(0, 1000)).unwrap();
        assert!(!map.has_authoritative_index());
        assert_eq!(map.unclaimed.ranges(), &[r(0, 1000)]);
        assert_eq!(map.kind_at(500), Some(UnclaimedKind::OutsideIndexScope));
    }

    #[test]
    fn claim_lookup_resolves_the_originating_entry() {
        let index = authoritative(
            vec![
                entry("didx#0", vec![r(1000, 500)]),
                entry("didx#1", vec![r(2000, 500)]),
            ],
            r(0, 10_000),
        );
        let map = build_claim_map(&index, None, r(0, 10_000)).unwrap();

        assert_eq!(map.claim_at(1200).map(|c| c.recording_id.as_str()), Some("didx#0"));
        assert_eq!(map.claim_at(2400).map(|c| c.recording_id.as_str()), Some("didx#1"));
        assert!(map.claim_at(1800).is_none());
    }
}
