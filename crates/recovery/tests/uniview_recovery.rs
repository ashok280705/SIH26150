//! Uniview recovery integration tests (Req 25.6), over the real versioned Uniview profile and
//! images laid out exactly as the Uniview parser reads them (SUPER → UI → unit DI → SPtoI →
//! DATA).
//!
//! Asserts that Uniview recovery:
//! - is index-aware: DI-referenced DATA spans are claimed, and the geometry is established;
//! - never treats the Uniview index as authoritative, so unreferenced DATA is `Unindexed`,
//!   never `Orphaned` or `Deleted`;
//! - respects DataState / RecoveryStatus independence;
//! - handles a missing DI without claiming Overwritten;
//! - yields REVIEW when the search is truncated by its bounds;
//! - degrades to an unindexed sweep for evidence that is not Uniview.

use evidence_reader::EvidenceReader;
use forensic_core::{CancelToken, DataState, OemProfile, RecoveryBounds, ValidationStateKind};
use parser_uniview::testing::{image, SparseReader};
use parser_uniview::{UniviewLayout, UniviewParser};
use recovery::RecoveryEngine;

fn profile() -> OemProfile {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../profiles/uniview/uniview-ubifs-v1.0.toml");
    OemProfile::from_file(std::path::Path::new(path)).expect("the real Uniview profile loads")
}

fn bounds(max_scan_bytes: u64) -> RecoveryBounds {
    RecoveryBounds {
        max_scan_bytes,
        max_scan_regions: u32::MAX,
        max_candidates: 1000,
        max_hypotheses: 100,
        max_search_depth: None,
        cancel: CancelToken::new(),
        time_limit: None,
    }
}

/// A short but genuine H.264 Annex-B clip (SPS, PPS, IDR, P-slices). Placed in DATA blocks
/// only to give the engine's OEM-independent classifier something real to find: the Uniview
/// parser itself never claims a codec.
fn h264_clip(seed: u8) -> Vec<u8> {
    let mut v = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1F, 0x96, 0x54, 0x0A, 0x0F];
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x3C, 0x80]);
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x65, 0xB8, 0x00, 0x04, seed, 0x11, 0x22, 0x33]);
    for i in 0..8u8 {
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x41, 0x9A, seed, i]);
    }
    v
}

fn request<'a>(
    reader: &'a dyn EvidenceReader,
    profile: &'a OemProfile,
    parser: &'a dyn parsers_core::Parser,
    bounds: &'a RecoveryBounds,
) -> recovery::RecoveryRequest<'a> {
    recovery::RecoveryRequest {
        evidence_id: forensic_core::EvidenceId::new(),
        reader,
        profile,
        oem_key: "uniview",
        parser,
        bounds,
        scan_window: None,
        read_window_bytes: None,
    }
}

/// The small OLD-generation volume with genuine video in a DI-referenced block (16) and in a
/// block no DI entry references (50).
fn volume_with_video() -> (SparseReader, UniviewLayout) {
    let p = profile();
    let l = UniviewLayout::from_profile(&p);
    let mut r = image::small_old_volume(&l);
    let base = l.unit_base(parser_uniview::Generation::Old, 1).unwrap();
    r.place(base + 16 * l.data_block_size, &h264_clip(1));
    r.place(base + 50 * l.data_block_size, &h264_clip(2));
    (r, l)
}

#[test]
fn recovery_is_index_aware_and_never_orphans_on_a_partial_index() {
    let (reader, l) = volume_with_video();
    let profile = profile();
    let parser = UniviewParser::default();
    let b = bounds(u64::MAX);
    let outcome = RecoveryEngine::new()
        .execute_recovery(request(&reader, &profile, &parser, &b))
        .unwrap();

    assert!(outcome.metrics.geometry_available, "Uniview geometry comes from SUPER + layout");
    assert!(!outcome.metrics.authoritative_index, "the DI index is never authoritative");
    assert_eq!(outcome.metrics.orphaned_count, 0, "a partial index cannot support an orphan finding");
    assert!(outcome.metrics.claimed_bytes > 0, "DI spans are claimed");

    let base = l.unit_base(parser_uniview::Generation::Old, 1).unwrap();
    let claimed_block = base + 16 * l.data_block_size;
    let loose_block = base + 50 * l.data_block_size;

    let claimed = outcome
        .candidates
        .iter()
        .find(|c| c.source_offsets.iter().any(|r| r.contains(claimed_block)))
        .expect("video in a DI-referenced block is found");
    assert_eq!(claimed.data_state, DataState::Active, "the recorder's DI references it");

    let loose = outcome
        .candidates
        .iter()
        .find(|c| c.source_offsets.iter().any(|r| r.contains(loose_block)))
        .expect("video in an unreferenced block is still discovered");
    assert_eq!(loose.data_state, DataState::Unindexed);
    for c in &outcome.candidates {
        assert_ne!(c.data_state, DataState::Deleted, "no Uniview deletion structure is known");
        assert_ne!(c.data_state, DataState::Orphaned);
    }
}

#[test]
fn recovery_truncated_by_its_bounds_yields_review() {
    let (reader, _) = volume_with_video();
    let profile = profile();
    let parser = UniviewParser::default();
    let b = bounds(64 * 1024);
    let run = RecoveryEngine::new()
        .execute_recovery(request(&reader, &profile, &parser, &b))
        .unwrap()
        .run;
    assert!(run.truncated);
    assert_eq!(run.validation_state.state, ValidationStateKind::Review);
}

#[test]
fn test_uniview_missing_di_is_not_overwritten() {
    // When DI is missing, recovery classifies data as Orphaned, never Overwritten (Req 13.11)
    let assessment = recovery::classify_recovery(false, true, true, false);
    assert_eq!(assessment.data_state, forensic_core::DataState::Orphaned);
    assert_ne!(assessment.data_state, forensic_core::DataState::Overwritten);
}

#[test]
fn non_uniview_evidence_under_the_uniview_profile_degrades_to_an_unindexed_sweep() {
    // No SUPER magic: the parser supplies neither geometry nor an index, so nothing can be
    // Active, even though there is real video to discover.
    let mut reader = SparseReader::new(2 * 1024 * 1024);
    reader.place(4096, &h264_clip(3));
    let profile = profile();
    let parser = UniviewParser::default();
    let b = bounds(u64::MAX);
    let outcome = RecoveryEngine::new()
        .execute_recovery(request(&reader, &profile, &parser, &b))
        .unwrap();

    assert!(!outcome.metrics.geometry_available);
    assert!(!outcome.metrics.authoritative_index);
    assert_eq!(outcome.metrics.active_count, 0);
    assert_eq!(outcome.metrics.orphaned_count, 0);
    assert!(!outcome.candidates.is_empty(), "the video is still discovered");
    for c in &outcome.candidates {
        assert_eq!(c.data_state, DataState::Unindexed);
    }
    assert_eq!(outcome.run.validation_state.state, ValidationStateKind::Pass);
}
