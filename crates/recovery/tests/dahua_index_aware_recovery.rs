//! # Production integration test: Dahua DHFS deletion-recovery path
//!
//! This test drives the **real production recovery entry point**
//! (`RecoveryEngine::execute_recovery`) with the **real Dahua parser** and the **real
//! versioned profile loaded from `profiles/`**. Nothing is mocked:
//!
//! ```text
//!   DHFS evidence image (deterministic fixture, real structures)
//!        ↓  DahuaParser::storage_geometry      — DHFS superblock read from bytes
//!        ↓  DahuaParser::recording_index       — DIDX table read from bytes
//!        ↓  claims::build_claim_map            — RangeSet claimed ranges
//!        ↓  RangeSet::complement_within        — unclaimed regions
//!        ↓  plan::plan_recovery               — bounded scan targets
//!        ↓  levels::scan_target               — bounded reads, exact offsets
//!        ↓  classification::classify_region_state
//!        ↓  Active / Orphaned / Unindexed
//! ```
//!
//! ## What the fixture represents
//!
//! A DHFS volume with four DHAV recordings physically present, but a DIDX index that
//! references only three of them. The fourth is real, decodable H.264 sitting inside the
//! recorder's declared video region with no index entry pointing at it — the actual
//! forensic situation of a recording the DVR has stopped listing. A fifth H.264 blob is
//! placed past the index region, outside anything the index governs.
//!
//! The fixture is built from the same DHFS/DHAV/DIDX field layout as
//! `generate_dahua_raw.py` and the platform's Dahua corpus, and every offset the test
//! asserts on is computed from that layout — it is not a "parser success" stub, because
//! a stub could not produce the claimed/unclaimed split the assertions check.

mod common;

use common::{
    bounds, build_fixture, dahua_profile, open_fixture, profiles_dir, BASE_UNIX, BLOCK_SIZE, SECTOR,
};
use evidence_reader::RawReader;
use forensic_core::{
    DataState, EvidenceId, ProfileRegistry, RecoveryBounds, RecoveryLevel, Region,
    ValidationStateKind,
};
use parser_dahua::DahuaParser;
use recovery::{RecoveryEngine, RecoveryRequest};
// ═══════════════════════════════════════════════════════════════════════════
// 1. OEM storage interpretation comes from evidence
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn dhfs_storage_geometry_is_read_from_the_superblock() {
    let fx = build_fixture();
    let (_dir, reader) = open_fixture(&fx);
    let registry = ProfileRegistry::load_from_dir(&profiles_dir()).unwrap();
    let profile = dahua_profile(&registry);
    let parser = DahuaParser::default();

    let geo = parsers_core::Parser::storage_geometry(&parser, &reader, profile)
        .unwrap()
        .expect("DHFS geometry must be established from the superblock");

    assert_eq!(geo.physical_size, fx.disk_size);
    assert_eq!(geo.sector_size, Some(SECTOR));
    assert_eq!(geo.block_size, Some(BLOCK_SIZE as u64));
    // The video region runs from the declared dhav_start up to the verified index.
    assert_eq!(
        geo.video_region,
        Some(Region::new(fx.video_start, fx.index_offset - fx.video_start).unwrap())
    );
    assert_eq!(
        geo.index_region,
        Some(Region::new(fx.index_offset, fx.index_len).unwrap())
    );
    assert_eq!(geo.evidence.state, ValidationStateKind::Pass);
    assert_eq!(geo.oem_fields.get("model").map(|s| s.as_str()), Some("DHI-XVR5216AN"));
    // DHFS carries no wrap pointer, so circular-buffer state must stay Unknown.
    assert_eq!(
        geo.circular_buffer,
        parsers_core::storage::CircularBufferEvidence::Unknown
    );
}

#[test]
fn didx_index_entries_are_read_from_evidence_and_are_authoritative() {
    let fx = build_fixture();
    let (_dir, reader) = open_fixture(&fx);
    let registry = ProfileRegistry::load_from_dir(&profiles_dir()).unwrap();
    let profile = dahua_profile(&registry);
    let parser = DahuaParser::default();

    let index = parsers_core::Parser::recording_index(&parser, &reader, profile)
        .unwrap()
        .expect("DIDX index must be located via the superblock index_offset");

    assert_eq!(index.declared_entry_count, Some(3));
    assert_eq!(index.recordings.len(), 3, "three of four segments are indexed");
    assert!(
        index.authority.is_authoritative(),
        "a fully parsed index is authoritative: {:?}",
        index.authority
    );

    // Each entry's physical claim matches the packet it describes, exactly.
    let expected: Vec<Region> = (0..fx.segments.len())
        .filter(|i| fx.segment(*i).indexed)
        .map(|i| fx.packet_region(i))
        .collect();
    assert_eq!(index.claimed_regions(), expected);

    // Real metadata where the structure records it, explicit unknown where it does not.
    let first = &index.recordings[0];
    assert_eq!(first.channel, Some(1), "channel reported 1-based");
    assert_eq!(first.start_time_unix, Some(BASE_UNIX as i64));
    assert_eq!(first.end_time_unix, None, "DIDX records no end time; must stay unknown");
    assert_eq!(first.codec_hint, None, "the index entry carries no codec label");
    assert_eq!(
        first.allocation,
        parsers_core::storage::AllocationEvidence::Unknown,
        "DHFS has no per-entry allocation field; must not be invented"
    );
}

#[test]
fn oem_detection_does_not_imply_an_index() {
    // A DHFS volume whose index region was wiped: the OEM is still recognisable, the
    // geometry is still partly readable, but no authoritative index exists — so no region
    // may be called Active or Orphaned.
    let mut fx = build_fixture();
    let ix = fx.index_offset as usize;
    for b in fx.bytes[ix..ix + fx.index_len as usize].iter_mut() {
        *b = 0;
    }
    let (_dir, reader) = open_fixture(&fx);
    let registry = ProfileRegistry::load_from_dir(&profiles_dir()).unwrap();
    let profile = dahua_profile(&registry);
    let parser = DahuaParser::default();

    // Detection-level recognition still succeeds: DHFS magic is intact.
    assert_eq!(&fx.bytes[0..4], b"DHFS");

    let index = parsers_core::Parser::recording_index(&parser, &reader, profile)
        .unwrap()
        .expect("a DHFS volume still reports an index outcome");
    assert!(!index.authority.is_authoritative());

    let outcome = RecoveryEngine::new()
        .execute_recovery(RecoveryRequest {
            evidence_id: EvidenceId::new(),
            reader: &reader,
            profile,
            oem_key: "dahua",
            parser: &parser,
            bounds: &bounds(),
            scan_window: None,
        })
        .unwrap();

    assert_eq!(outcome.metrics.active_count, 0, "recognising DHFS is not an index");
    assert_eq!(outcome.metrics.orphaned_count, 0, "a wiped index cannot support orphan findings");
    assert!(outcome.metrics.unindexed_count > 0, "the video is still found, conservatively");
    for c in &outcome.candidates {
        assert_eq!(c.data_state, DataState::Unindexed);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Claimed ranges, range subtraction, and the production recovery run
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn claimed_ranges_and_unclaimed_complement_are_exact() {
    let fx = build_fixture();
    let (_dir, reader) = open_fixture(&fx);
    let registry = ProfileRegistry::load_from_dir(&profiles_dir()).unwrap();
    let profile = dahua_profile(&registry);
    let parser = DahuaParser::default();

    let outcome = RecoveryEngine::new()
        .execute_recovery(RecoveryRequest {
            evidence_id: EvidenceId::new(),
            reader: &reader,
            profile,
            oem_key: "dahua",
            parser: &parser,
            bounds: &bounds(),
            scan_window: None,
        })
        .unwrap();

    let map = &outcome.plan.claim_map;

    // Claimed == exactly the three indexed DHAV packets, at their exact offsets.
    let expected_claims: Vec<Region> = (0..fx.segments.len())
        .filter(|i| fx.segment(*i).indexed)
        .map(|i| fx.packet_region(i))
        .collect();
    assert_eq!(map.claimed.ranges(), expected_claims.as_slice());
    assert_eq!(
        map.claimed_bytes(),
        expected_claims.iter().map(|r| r.length).sum::<u64>()
    );

    // Claimed + unclaimed partitions the whole disk with no overlap and no loss.
    assert_eq!(
        map.claimed_bytes() + map.unclaimed_bytes(),
        fx.disk_size,
        "the complement must account for every byte"
    );
    assert!(map.unclaimed.iter().all(|u| expected_claims
        .iter()
        .all(|c| !u.overlaps(c))));

    // The orphan segment's bytes are unclaimed and inside the authoritative scope.
    let orphan = fx.packet_region(2);
    assert!(!map.claimed.contains(orphan.offset));
    assert_eq!(
        map.kind_at(orphan.offset),
        Some(recovery::UnclaimedKind::WithinAuthoritativeIndexScope),
        "the orphan sits inside the region the index governs"
    );

    // The trailing blob is unclaimed but outside the governed scope.
    assert_eq!(
        map.kind_at(fx.trailing_video_offset),
        Some(recovery::UnclaimedKind::OutsideIndexScope)
    );
}

#[test]
fn production_recovery_reaches_a_non_active_state_from_real_index_evidence() {
    // THE core assertion of this phase: the real production entry point, on real OEM
    // structures, produces a non-Active candidate at the orphan's exact physical offset.
    let fx = build_fixture();
    let (_dir, reader) = open_fixture(&fx);
    let registry = ProfileRegistry::load_from_dir(&profiles_dir()).unwrap();
    let profile = dahua_profile(&registry);
    let parser = DahuaParser::default();
    let evidence_id = EvidenceId::new();

    let outcome = RecoveryEngine::new()
        .execute_recovery(RecoveryRequest {
            evidence_id,
            reader: &reader,
            profile,
            oem_key: "dahua",
            parser: &parser,
            bounds: &bounds(),
            scan_window: None,
        })
        .unwrap();

    // ── Active: the indexed recordings ──────────────────────────────────────
    let active: Vec<&forensic_core::RecoveryCandidate> =
        outcome.in_state(DataState::Active).collect();
    assert_eq!(
        active.len(),
        3,
        "each indexed recording with valid video is Active; got {:?}",
        outcome
            .candidates
            .iter()
            .map(|c| (c.data_state, c.source_offsets[0].offset))
            .collect::<Vec<_>>()
    );
    for i in (0..fx.segments.len()).filter(|i| fx.segment(*i).indexed) {
        let at = fx.segment(i).offset;
        assert!(
            active.iter().any(|c| c.source_offsets[0].offset == at),
            "expected an Active candidate at the indexed packet offset 0x{at:X}"
        );
    }
    assert!(active.iter().all(|c| c.recovery_level == RecoveryLevel::L1));

    // ── Orphaned: physically present, governed by the index, unreferenced ────
    let orphaned: Vec<&forensic_core::RecoveryCandidate> =
        outcome.in_state(DataState::Orphaned).collect();
    assert!(
        !orphaned.is_empty(),
        "DataState::Orphaned must be reachable through the production path"
    );
    let orphan_region = fx.packet_region(2);
    let hit = orphaned
        .iter()
        .find(|c| {
            let r = c.source_offsets[0];
            r.offset <= orphan_region.offset
                && r.end().unwrap_or(0) > orphan_region.offset
        })
        .expect("an Orphaned candidate must cover the unindexed recording's bytes");
    assert_eq!(hit.recovery_level, RecoveryLevel::L2);
    assert_eq!(
        hit.recovery_status,
        forensic_core::RecoveryStatus::Recoverable
    );
    // The finding must be explainable to an examiner.
    let reason = &hit.provenance.validation_state.reason;
    assert!(
        reason.contains("no longer indexed"),
        "the orphan finding must state why: {reason}"
    );

    // ── Unindexed: video the index makes no statement about ─────────────────
    let unindexed: Vec<&forensic_core::RecoveryCandidate> =
        outcome.in_state(DataState::Unindexed).collect();
    assert!(
        !unindexed.is_empty(),
        "the trailing video outside the governed region must be Unindexed"
    );
    assert!(
        unindexed.iter().any(|c| {
            let r = c.source_offsets[0];
            r.offset <= fx.trailing_video_offset
                && r.end().unwrap_or(0) >= fx.trailing_video_offset + fx.trailing_video_len
        }),
        "expected an Unindexed candidate covering 0x{:X}",
        fx.trailing_video_offset
    );
    assert!(unindexed.iter().all(|c| c.recovery_level == RecoveryLevel::L3));

    // ── Unindexed is never reported as Deleted ──────────────────────────────
    assert_eq!(
        outcome.metrics.deleted_count, 0,
        "no DHFS evidence supports a deletion finding, so none may be reported"
    );
    assert_eq!(outcome.metrics.overwritten_count, 0);

    // ── Observability ───────────────────────────────────────────────────────
    let m = &outcome.metrics;
    assert_eq!(m.oem_key, "dahua");
    assert_eq!(m.profile_id, profile.profile_id);
    assert!(m.geometry_available);
    assert!(m.authoritative_index);
    assert_eq!(m.index_declared_entries, Some(3));
    assert_eq!(m.index_entry_count, 3);
    assert_eq!(m.claimed_range_count, 3);
    assert!(m.claimed_bytes > 0);
    assert!(m.unclaimed_bytes > 0);
    assert!(m.orphan_eligible_region_count > 0);
    assert!(m.scan_region_count > 0);
    assert_eq!(m.active_count, 3);
    assert!(m.orphaned_count >= 1);
    assert!(m.unindexed_count >= 1);
    assert_eq!(
        m.candidate_count,
        outcome.candidates.len(),
        "metrics must account for every candidate"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Provenance
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn evidence_id_and_physical_offsets_survive_the_whole_pipeline() {
    let fx = build_fixture();
    let (_dir, reader) = open_fixture(&fx);
    let registry = ProfileRegistry::load_from_dir(&profiles_dir()).unwrap();
    let profile = dahua_profile(&registry);
    let parser = DahuaParser::default();
    let evidence_id = EvidenceId::new();

    let outcome = RecoveryEngine::new()
        .execute_recovery(RecoveryRequest {
            evidence_id,
            reader: &reader,
            profile,
            oem_key: "dahua",
            parser: &parser,
            bounds: &bounds(),
            scan_window: None,
        })
        .unwrap();

    assert!(!outcome.candidates.is_empty());
    assert_eq!(outcome.candidates.len(), outcome.fragments.len());

    for (c, f) in outcome.candidates.iter().zip(outcome.fragments.iter()) {
        // EvidenceId stability.
        assert_eq!(c.provenance.source_evidence_id, evidence_id);
        assert_eq!(f.evidence_id, evidence_id);
        for sr in &c.provenance.source_regions {
            assert_eq!(sr.evidence_id, evidence_id);
        }

        // Physical offsets intact and inside the evidence.
        let r = c.source_offsets[0];
        assert!(r.length > 0);
        assert!(r.end().unwrap() <= fx.disk_size, "offsets must stay in-bounds");
        assert_eq!(f.physical_region, r);
        // The candidate's region lies inside the planner region it came from.
        assert!(
            f.originating_region.offset <= r.offset
                && f.originating_region.end().unwrap() >= r.end().unwrap()
        );

        // Provenance completeness and OEM context.
        assert!(c.provenance.is_complete());
        assert_eq!(c.provenance.profile_version.as_deref(), Some(profile.profile_version.as_str()));
        assert_eq!(c.provenance.profile_hash, profile.profile_hash);
        assert!(c.provenance.parser_version.as_deref().unwrap().contains("dahua"));
        assert!(!c.provenance.transformation_history.is_empty());
        assert_eq!(f.oem_key, "dahua");
        assert_eq!(f.profile_id, profile.profile_id);
    }
}

#[test]
fn recorder_metadata_is_known_only_where_the_index_supplied_it() {
    let fx = build_fixture();
    let (_dir, reader) = open_fixture(&fx);
    let registry = ProfileRegistry::load_from_dir(&profiles_dir()).unwrap();
    let profile = dahua_profile(&registry);
    let parser = DahuaParser::default();

    let outcome = RecoveryEngine::new()
        .execute_recovery(RecoveryRequest {
            evidence_id: EvidenceId::new(),
            reader: &reader,
            profile,
            oem_key: "dahua",
            parser: &parser,
            bounds: &bounds(),
            scan_window: None,
        })
        .unwrap();

    for (c, f) in outcome.candidates.iter().zip(outcome.fragments.iter()) {
        match c.data_state {
            DataState::Active => {
                assert!(
                    f.camera_id.is_known() && f.timestamp_unix.is_known(),
                    "an indexed recording's channel and timestamp come from the index"
                );
                assert_eq!(c.validation.channel.state, ValidationStateKind::Pass);
                assert_eq!(c.validation.timestamps.state, ValidationStateKind::Pass);
            }
            DataState::Orphaned | DataState::Unindexed => {
                assert!(
                    !f.camera_id.is_known(),
                    "carved video has no camera; it must not be reported as camera 0"
                );
                assert!(!f.timestamp_unix.is_known(), "carved video has no recorder clock");
                assert!(!f.sequence_number.is_known());
                assert_eq!(c.validation.channel.state, ValidationStateKind::Unknown);
                assert_eq!(c.validation.timestamps.state, ValidationStateKind::Unknown);
            }
            other => panic!("unexpected state {other:?} for this fixture"),
        }
        // Continuity is never assessed by a single-region scan.
        assert_eq!(c.validation.continuity.state, ValidationStateKind::Unknown);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Bounded, non-full-disk reads and forensic integrity
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn index_evidence_narrows_the_scan_instead_of_sweeping_the_disk() {
    let fx = build_fixture();
    let (_dir, reader) = open_fixture(&fx);
    let registry = ProfileRegistry::load_from_dir(&profiles_dir()).unwrap();
    let profile = dahua_profile(&registry);
    let parser = DahuaParser::default();

    let outcome = RecoveryEngine::new()
        .execute_recovery(RecoveryRequest {
            evidence_id: EvidenceId::new(),
            reader: &reader,
            profile,
            oem_key: "dahua",
            parser: &parser,
            bounds: &bounds(),
            scan_window: None,
        })
        .unwrap();

    assert!(
        outcome.run.searched_bytes < fx.disk_size,
        "with an index available the engine must not read the whole disk: read {} of {}",
        outcome.run.searched_bytes,
        fx.disk_size
    );
    assert!(outcome.metrics.bytes_avoided_vs_full_scan > 0);
    // Claimed ranges are probed, not swept: each indexed packet costs one bounded read.
    let probes = outcome
        .plan
        .targets
        .iter()
        .filter(|t| t.discovery_method == recovery::DiscoveryMethod::IndexClaimedProbe)
        .count();
    assert_eq!(probes, 3);
    // Every scanned region stays inside the evidence.
    for r in &outcome.run.searched_regions {
        assert!(r.end().unwrap() <= fx.disk_size);
    }
}

#[test]
fn truncated_runs_are_review_never_pass() {
    let fx = build_fixture();
    let (_dir, reader) = open_fixture(&fx);
    let registry = ProfileRegistry::load_from_dir(&profiles_dir()).unwrap();
    let profile = dahua_profile(&registry);
    let parser = DahuaParser::default();

    let tight = RecoveryBounds {
        max_scan_bytes: 4096,
        ..bounds()
    };
    let outcome = RecoveryEngine::new()
        .execute_recovery(RecoveryRequest {
            evidence_id: EvidenceId::new(),
            reader: &reader,
            profile,
            oem_key: "dahua",
            parser: &parser,
            bounds: &tight,
            scan_window: None,
        })
        .unwrap();

    assert!(outcome.run.truncated);
    assert_eq!(outcome.run.validation_state.state, ValidationStateKind::Review);
    assert!(outcome.metrics.truncated);
}

#[test]
fn recovery_does_not_modify_the_evidence_image() {
    let fx = build_fixture();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("readonly_check.raw");
    std::fs::write(&path, &fx.bytes).unwrap();
    let before = std::fs::read(&path).unwrap();

    let reader = RawReader::open(path.to_str().unwrap()).unwrap();
    let registry = ProfileRegistry::load_from_dir(&profiles_dir()).unwrap();
    let profile = dahua_profile(&registry);
    let parser = DahuaParser::default();

    RecoveryEngine::new()
        .execute_recovery(RecoveryRequest {
            evidence_id: EvidenceId::new(),
            reader: &reader,
            profile,
            oem_key: "dahua",
            parser: &parser,
            bounds: &bounds(),
            scan_window: None,
        })
        .unwrap();
    drop(reader);

    let after = std::fs::read(&path).unwrap();
    assert_eq!(before, after, "evidence must be byte-identical after recovery");
}

#[test]
fn two_runs_over_the_same_evidence_produce_identical_findings() {
    let fx = build_fixture();
    let (_dir, reader) = open_fixture(&fx);
    let registry = ProfileRegistry::load_from_dir(&profiles_dir()).unwrap();
    let profile = dahua_profile(&registry);
    let parser = DahuaParser::default();
    let evidence_id = EvidenceId::new();

    let run_once = || {
        RecoveryEngine::new()
            .execute_recovery(RecoveryRequest {
                evidence_id,
                reader: &reader,
                profile,
                oem_key: "dahua",
                parser: &parser,
                bounds: &bounds(),
                scan_window: None,
            })
            .unwrap()
    };

    let a = run_once();
    let b = run_once();

    let key = |o: &recovery::RecoveryOutcome| -> Vec<(u64, u64, DataState, RecoveryLevel)> {
        o.candidates
            .iter()
            .map(|c| {
                (
                    c.source_offsets[0].offset,
                    c.source_offsets[0].length,
                    c.data_state,
                    c.recovery_level,
                )
            })
            .collect()
    };
    assert_eq!(key(&a), key(&b), "recovery must be deterministic");
    assert_eq!(a.plan.targets, b.plan.targets);
    assert_eq!(a.metrics, b.metrics);
}

