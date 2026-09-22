//! # Full production chain: OEM detection → index parsing → orphan discovery
//!
//! The companion test in `crates/recovery/tests/dahua_index_aware_recovery.rs` proves the
//! recovery engine's behaviour. This one proves the **whole production chain** in front of
//! it, using the same orchestrators the API handler uses:
//!
//! ```text
//!   RawReader (read-only)
//!      ↓ DetectionOrchestrator::run          — real detectors, real profiles
//!      ↓ ConfidenceEngine::classify          — real attribution
//!      ↓ ProfileRegistry::find_applicable    — real versioned profile from profiles/
//!      ↓ ParsingOrchestrator::parser_for     — the real registered Dahua parser
//!      ↓ RecoveryEngine::execute_recovery    — the production recovery entry point
//!      ↓ DataState::Orphaned                 — reached from index evidence
//! ```
//!
//! The load-bearing assertion is the separation the phase exists to establish:
//! detection saying "this is Dahua" does **not** make any region `Active`, and the only
//! thing that produces `Orphaned` is an authoritative index that governs bytes it does not
//! reference.

use confidence::config::ConfidenceConfig;
use confidence::engine::ConfidenceEngine;
use detection::orchestrator::DetectionOrchestrator;
use evidence_reader::RawReader;
use forensic_core::{
    CancelToken, DataState, EvidenceId, ProfileRegistry, RecoveryBounds, RecoveryLevel, Region,
};
use parsing::orchestrator::ParsingOrchestrator;
use recovery::{RecoveryEngine, RecoveryRequest};
use std::path::{Path, PathBuf};

const SECTOR: u64 = 512;
const DHAV_HEADER: u64 = 64;
const DHAV_FOOTER: u64 = 4;
const BLOCK_SIZE: u32 = 65536;
const BASE_UNIX: u64 = 1_790_500_000;
const SLOT: u64 = 1024 * 1024;

/// A genuine H.264 Annex-B clip (SPS + PPS + IDR + P-slices).
///
/// Real parameter sets are required: the codec classifier only reports PASS on actual
/// SPS/PPS NAL headers, and only validated video can reach `Active` or `Orphaned`. The
/// test therefore cannot pass on a fabricated byte pattern.
fn h264_clip(seed: u8) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1F, 0x96, 0x54, 0x0A, 0x0F]);
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x3C, 0x80]);
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x65, 0xB8, 0x00, 0x04, seed, 0x11, 0x22, 0x33]);
    for i in 0..8u8 {
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x41, 0x9A, seed, i]);
    }
    v
}

fn align_up(v: u64, a: u64) -> u64 {
    ((v + a - 1) / a) * a
}

fn put_u32(b: &mut [u8], at: u64, v: u32) {
    b[at as usize..at as usize + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(b: &mut [u8], at: u64, v: u64) {
    b[at as usize..at as usize + 8].copy_from_slice(&v.to_le_bytes());
}

struct Layout {
    bytes: Vec<u8>,
    /// Physical regions of the DHAV packets the DIDX index references.
    indexed_packets: Vec<Region>,
    /// Physical region of the DHAV packet that is present but NOT referenced.
    orphan_packet: Region,
    index_offset: u64,
    disk_size: u64,
}

/// Build a DHFS image with three recordings, two of which the DIDX index references.
///
/// Byte layout matches the DHFS superblock / DHAV packet / DIDX entry structures the
/// `profiles/dahua/dahua-dhfs-v1.0.toml` `[layout]` table declares, which is the same
/// layout `generate_dahua_raw.py` writes. Nothing here bypasses the parser: the parser has
/// to read the superblock and walk the index for the test to see any claims at all.
fn build_dhfs_image() -> Layout {
    // (channel0, timestamp, payload, indexed)
    let segments: Vec<(u8, u64, Vec<u8>, bool)> = vec![
        (0, BASE_UNIX, h264_clip(0x51), true),
        // Physically present, deliberately absent from the index.
        (1, BASE_UNIX + 300, h264_clip(0x62), false),
        (0, BASE_UNIX + 600, h264_clip(0x73), true),
    ];

    let video_start = SECTOR;
    let offsets: Vec<u64> = (0..segments.len())
        .map(|i| align_up(video_start + (i as u64) * SLOT, SECTOR))
        .collect();
    let totals: Vec<u64> = segments
        .iter()
        .map(|(_, _, p, _)| DHAV_HEADER + p.len() as u64 + DHAV_FOOTER)
        .collect();

    let indexed_count = segments.iter().filter(|s| s.3).count() as u64;
    let last_end = offsets[segments.len() - 1] + totals[segments.len() - 1];
    let index_offset = align_up(last_end + SLOT, SECTOR);
    let index_len = 16 + indexed_count * 32;
    let disk_size = align_up(index_offset + index_len + SECTOR, SLOT);

    let mut b = vec![0u8; disk_size as usize];

    // DHFS superblock.
    b[0..4].copy_from_slice(b"DHFS");
    put_u32(&mut b, 4, 0x0001_0000);
    put_u32(&mut b, 8, SECTOR as u32);
    put_u32(&mut b, 12, BLOCK_SIZE);
    put_u64(&mut b, 16, disk_size / BLOCK_SIZE as u64);
    put_u64(&mut b, 24, video_start);
    put_u64(&mut b, 32, index_offset);
    put_u64(&mut b, 40, BASE_UNIX);
    b[48..48 + 13].copy_from_slice(b"DHI-XVR5216AN");
    b[96..96 + 12].copy_from_slice(b"DVR_REC_VOL0");

    // DHAV packets.
    for (i, (ch0, ts, payload, _)) in segments.iter().enumerate() {
        let at = offsets[i];
        let a = at as usize;
        b[a..a + 4].copy_from_slice(b"DHAV");
        b[a + 4] = 0xFD;
        b[a + 5] = *ch0;
        put_u32(&mut b, at + 8, i as u32 + 1);
        put_u32(&mut b, at + 12, totals[i] as u32);
        put_u64(&mut b, at + 16, *ts);
        b[a + 28..a + 30].copy_from_slice(&1280u16.to_le_bytes());
        b[a + 30..a + 32].copy_from_slice(&720u16.to_le_bytes());
        b[a + 32..a + 41].copy_from_slice(b"H.264/AVC");
        let name = format!("CH{:02}", ch0 + 1).into_bytes();
        b[a + 48..a + 48 + name.len()].copy_from_slice(&name);
        let p = a + DHAV_HEADER as usize;
        b[p..p + payload.len()].copy_from_slice(payload);
        b[p + payload.len()..p + payload.len() + 4].copy_from_slice(b"dhav");
    }

    // DIDX index: only the indexed segments.
    b[index_offset as usize..index_offset as usize + 4].copy_from_slice(b"DIDX");
    put_u32(&mut b, index_offset + 4, indexed_count as u32);
    let mut e = index_offset + 16;
    for (i, (ch0, ts, _, indexed)) in segments.iter().enumerate() {
        if !*indexed {
            continue;
        }
        b[e as usize] = *ch0;
        b[e as usize + 1] = 0xFD;
        put_u64(&mut b, e + 4, offsets[i]);
        put_u64(&mut b, e + 12, totals[i]);
        put_u64(&mut b, e + 20, *ts);
        put_u32(&mut b, e + 28, 0x1A2B_3C4D);
        e += 32;
    }

    let indexed_packets = segments
        .iter()
        .enumerate()
        .filter(|(_, s)| s.3)
        .map(|(i, _)| Region::new(offsets[i], totals[i]).unwrap())
        .collect();
    let orphan_idx = segments.iter().position(|s| !s.3).unwrap();
    let orphan_packet = Region::new(offsets[orphan_idx], totals[orphan_idx]).unwrap();

    Layout {
        bytes: b,
        indexed_packets,
        orphan_packet,
        index_offset,
        disk_size,
    }
}

fn profiles_dir() -> PathBuf {
    for p in ["profiles", "../profiles", "../../profiles"] {
        if Path::new(p).exists() {
            return PathBuf::from(p);
        }
    }
    panic!("could not locate profiles/");
}

fn bounds() -> RecoveryBounds {
    RecoveryBounds {
        max_scan_bytes: u64::MAX,
        max_scan_regions: u32::MAX,
        max_candidates: u32::MAX,
        max_hypotheses: 1024,
        max_search_depth: None,
        cancel: CancelToken::new(),
        time_limit: None,
    }
}

#[test]
fn full_chain_detection_to_orphan_discovery() {
    let layout = build_dhfs_image();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dahua_dhfs_production_chain.raw");
    std::fs::write(&path, &layout.bytes).unwrap();
    let reader = RawReader::open(path.to_str().unwrap()).expect("evidence opens read-only");

    let registry = ProfileRegistry::load_from_dir(&profiles_dir()).expect("profiles load");

    // ── 1. OEM detection ────────────────────────────────────────────────────
    let detector_outputs = DetectionOrchestrator::new()
        .run(&reader, &registry)
        .expect("detection runs");
    let dahua = detector_outputs
        .iter()
        .find(|o| o.oem_key == "dahua")
        .expect("a Dahua detector output");
    assert_eq!(
        dahua.status,
        detection::DetectionStatus::Confirmed,
        "DHFS magic at 0 plus a DHAV tag in the header window is Confirmed"
    );

    let classified = ConfidenceEngine::classify(
        &detector_outputs,
        &registry,
        &ConfidenceConfig::provisional_default(),
    )
    .expect("confidence classifies");
    assert_eq!(classified.detector_output.oem_key, "dahua");
    let oem_key = classified.detector_output.oem_key.clone();

    // ── 2. Profile + parser, exactly as the API handler resolves them ───────
    let profile = registry
        .find_applicable(&oem_key, None, None, None)
        .expect("the versioned Dahua profile");
    let orchestrator = ParsingOrchestrator::new();
    let parser = orchestrator
        .parser_for(&oem_key)
        .expect("the registered Dahua parser");

    // ── 3. Production recovery entry point ──────────────────────────────────
    let evidence_id = EvidenceId::new();
    let outcome = RecoveryEngine::new()
        .execute_recovery(RecoveryRequest {
            evidence_id,
            reader: &reader,
            profile,
            oem_key: &oem_key,
            parser,
            bounds: &bounds(),
            scan_window: None,
        })
        .expect("recovery runs");

    eprintln!("plan: {}", outcome.plan.rationale);
    for c in &outcome.candidates {
        eprintln!(
            "  candidate 0x{:X} len {} -> {:?}/{:?} {:?}",
            c.source_offsets[0].offset,
            c.source_offsets[0].length,
            c.data_state,
            c.recovery_status,
            c.recovery_level
        );
    }

    // ── 4. Storage geometry and index came from evidence ────────────────────
    let geometry = outcome.plan.geometry.as_ref().expect("geometry established");
    assert_eq!(geometry.physical_size, layout.disk_size);
    assert_eq!(geometry.block_size, Some(BLOCK_SIZE as u64));
    assert_eq!(
        geometry.video_region.map(|r| r.offset),
        Some(SECTOR),
        "video region start comes from the superblock's dhav_start"
    );
    assert_eq!(
        geometry.index_region.map(|r| r.offset),
        Some(layout.index_offset),
        "index region located via the superblock's index_offset"
    );

    let index = outcome.plan.index.as_ref().expect("index read");
    assert!(index.authority.is_authoritative());
    assert_eq!(index.recordings.len(), 2);

    // ── 5. Claimed ranges are exactly the indexed packets ───────────────────
    assert_eq!(
        outcome.plan.claim_map.claimed.ranges(),
        layout.indexed_packets.as_slice(),
        "claimed ranges must match the index entries byte for byte"
    );

    // ── 6. The orphan is unclaimed, inside scope, and classified Orphaned ───
    assert!(!outcome
        .plan
        .claim_map
        .claimed
        .contains(layout.orphan_packet.offset));
    assert_eq!(
        outcome.plan.claim_map.kind_at(layout.orphan_packet.offset),
        Some(recovery::UnclaimedKind::WithinAuthoritativeIndexScope)
    );

    let orphan = outcome
        .candidates
        .iter()
        .find(|c| {
            c.data_state == DataState::Orphaned
                && c.source_offsets[0].offset <= layout.orphan_packet.offset
                && c.source_offsets[0].end().unwrap_or(0) > layout.orphan_packet.offset
        })
        .unwrap_or_else(|| {
            panic!(
                "no Orphaned candidate covers the unindexed recording at 0x{:X}",
                layout.orphan_packet.offset
            )
        });
    assert_eq!(orphan.recovery_level, RecoveryLevel::L2);
    assert_eq!(
        orphan.provenance.source_evidence_id, evidence_id,
        "provenance points back at the registered evidence item"
    );

    // ── 7. The indexed recordings are Active, and only they ─────────────────
    let active_offsets: Vec<u64> = outcome
        .candidates
        .iter()
        .filter(|c| c.data_state == DataState::Active)
        .map(|c| c.source_offsets[0].offset)
        .collect();
    let mut expected: Vec<u64> = layout.indexed_packets.iter().map(|r| r.offset).collect();
    expected.sort_unstable();
    let mut got = active_offsets.clone();
    got.sort_unstable();
    assert_eq!(got, expected, "only index-claimed regions may be Active");

    // ── 8. Nothing is called Deleted without deletion evidence ──────────────
    assert_eq!(
        outcome.metrics.deleted_count, 0,
        "unindexed data must never be reported as deleted"
    );
    assert_eq!(outcome.metrics.overwritten_count, 0);
    assert!(outcome.metrics.orphaned_count >= 1);
}

#[test]
fn parsing_stages_still_pass_on_an_indexed_dhfs_volume() {
    // Guard that making `recognize_candidate` real and rewiring `parse_metadata` through
    // the index reader did not regress the existing five-stage parsing contract.
    let layout = build_dhfs_image();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dahua_parse_contract.raw");
    std::fs::write(&path, &layout.bytes).unwrap();
    let reader = RawReader::open(path.to_str().unwrap()).unwrap();

    let registry = ProfileRegistry::load_from_dir(&profiles_dir()).unwrap();
    let profile = registry.find_applicable("dahua", None, None, None).unwrap();
    let result = ParsingOrchestrator::new()
        .run_parsing("dahua", &reader, profile)
        .expect("parsing runs");

    assert_eq!(result.parser_runs.len(), 5, "all five stages still run");
    for run in &result.parser_runs {
        eprintln!(
            "stage {} -> {:?} ({})",
            run.operation_name, run.validation_state.state, run.validation_state.reason
        );
        assert_eq!(
            run.validation_state.state,
            forensic_core::ValidationStateKind::Pass,
            "stage {} must still pass on a well-formed DHFS volume",
            run.operation_name
        );
    }
    // All three DHAV packets are still extracted by the container walk, indexed or not —
    // the walk reports what is physically there; the index decides what it means.
    assert_eq!(result.recordings.len(), 3);
    assert_eq!(result.timeline_events.len(), 3);
}

#[test]
fn recognize_candidate_is_format_recognition_not_an_index_lookup() {
    // The defect this phase fixes: `recognize_candidate` returned `Ok(true)` for any bytes,
    // which the engine then treated as proof of indexation. It must now answer a pure
    // format question, and answer it honestly.
    let layout = build_dhfs_image();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dahua_recognize.raw");
    std::fs::write(&path, &layout.bytes).unwrap();
    let reader = RawReader::open(path.to_str().unwrap()).unwrap();

    let registry = ProfileRegistry::load_from_dir(&profiles_dir()).unwrap();
    let profile = registry.find_applicable("dahua", None, None, None).unwrap();
    let parser = parser_dahua::DahuaParser::default();

    // A window over a DHAV packet: framing present.
    let at_packet = evidence_reader::BoundedReader::new(
        &reader,
        layout.orphan_packet.offset,
        layout.orphan_packet.length,
    )
    .unwrap();
    assert!(
        parsers_core::Parser::recognize_candidate(&parser, &at_packet, profile).unwrap(),
        "DHAV framing is present in this window"
    );

    // A window over zeroed slack: no framing. Under the old implementation this also
    // returned true, which is what suppressed every orphan and unindexed finding.
    let slack_offset = layout.orphan_packet.end().unwrap() + 4096;
    let at_slack = evidence_reader::BoundedReader::new(&reader, slack_offset, 65536).unwrap();
    assert!(
        !parsers_core::Parser::recognize_candidate(&parser, &at_slack, profile).unwrap(),
        "zeroed slack carries no DHAV framing and must not be recognised"
    );
}
