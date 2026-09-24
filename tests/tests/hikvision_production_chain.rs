//! # Full production chain over a synthetic Hikvision volume
//!
//! Every stage is the real one, driven through the same orchestrators the API handler uses:
//!
//! ```text
//!   RawReader (read-only)
//!      ↓ DetectionOrchestrator::run            — real detectors, real profiles
//!      ↓ ConfidenceEngine::classify            — real attribution
//!      ↓ ProfileRegistry::find_applicable      — the versioned profile from profiles/
//!      ↓ ParsingOrchestrator::run_parsing      — the registered Hikvision parser, all five stages
//!      ↓ RecoveryEngine::execute_recovery      — the production recovery entry point
//!      ↓ DataState::{Active, Orphaned, Unindexed}
//!      ↓ parser_hikvision::reconstruct_recording — clip → MPEG-PS parts → payload ranges
//!      ↓ exportable payload with preserved provenance
//! ```
//!
//! The load-bearing assertions are the separations the design enforces: detection saying "this is
//! Hikvision" does not by itself make any region `Active`; a block the B-tree does not reference is
//! `Orphaned` and never `Deleted`; and an engine-discovered fragment can be reconstructed into an
//! exportable stream that traces back to the exact physical bytes and the same clip id the index
//! assigned.

use confidence::config::ConfidenceConfig;
use confidence::engine::ConfidenceEngine;
use detection::orchestrator::DetectionOrchestrator;
use evidence_reader::{EvidenceReader, RawReader};
use forensic_core::{
    CancelToken, DataState, EvidenceId, ProfileRegistry, RecoveryBounds, Region,
    ValidationStateKind,
};
use forensic_tests::hikvision_fixtures::{
    build_hikvision_image, realistic_dvr_volume, FooterMode, HikBlockSpec, HikClipSpec,
    HikEntrySpec, HikTreeSpec, HikvisionImage, HikvisionImageSpec, LooseClipSpec,
};
use parser_hikvision::HikCodec;
use parsing::orchestrator::ParsingOrchestrator;
use recovery::{RecoveryEngine, RecoveryRequest};
use std::path::{Path, PathBuf};

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

struct Chain {
    image: HikvisionImage,
    reader: RawReader,
    registry: ProfileRegistry,
    _dir: tempfile::TempDir,
}

fn open(image: HikvisionImage) -> Chain {
    let dir = tempfile::tempdir().unwrap();
    let path = image
        .write_to_dir(dir.path(), "hikvision_production.raw")
        .unwrap();
    let reader = RawReader::open(path.to_str().unwrap()).expect("evidence opens read-only");
    let registry = ProfileRegistry::load_from_dir(&profiles_dir()).expect("profiles load");
    Chain {
        image,
        reader,
        registry,
        _dir: dir,
    }
}

#[test]
fn detection_confirms_hikvision_from_the_identifier_and_the_tree_pointer() {
    let c = open(realistic_dvr_volume());

    let detector_outputs = DetectionOrchestrator::new()
        .run(&c.reader, &c.registry)
        .expect("detection runs");
    let hik = detector_outputs
        .iter()
        .find(|o| o.oem_key == "hikvision")
        .expect("a Hikvision detector output");
    assert_eq!(
        hik.status,
        detection::DetectionStatus::Confirmed,
        "the filesystem identifier plus a HIKBTREE reached through the boot pointer is Confirmed: {:?}",
        hik.warnings
    );

    // The confidence engine attributes it to Hikvision, and no other OEM outscores it.
    let classified = ConfidenceEngine::classify(
        &detector_outputs,
        &c.registry,
        &ConfidenceConfig::provisional_default(),
    )
    .expect("confidence classifies");
    assert_eq!(classified.detector_output.oem_key, "hikvision");
}

#[test]
fn a_random_image_is_not_attributed_to_hikvision() {
    // The false-positive guard: bytes that are not a Hikvision volume must not be Confirmed.
    let bytes: Vec<u8> = (0..(1u32 << 18))
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
        .collect();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("random.raw");
    std::fs::write(&path, &bytes).unwrap();
    let reader = RawReader::open(path.to_str().unwrap()).unwrap();
    let registry = ProfileRegistry::load_from_dir(&profiles_dir()).unwrap();

    let outputs = DetectionOrchestrator::new()
        .run(&reader, &registry)
        .unwrap();
    let hik = outputs.iter().find(|o| o.oem_key == "hikvision").unwrap();
    assert_ne!(
        hik.status,
        detection::DetectionStatus::Confirmed,
        "random bytes must not be confirmed as Hikvision"
    );
}

#[test]
fn full_chain_detection_to_orphan_and_active_separation() {
    let c = open(realistic_dvr_volume());

    // ── Detection → confidence → profile → parser, as the API resolves them ──
    let detector_outputs = DetectionOrchestrator::new()
        .run(&c.reader, &c.registry)
        .unwrap();
    let classified = ConfidenceEngine::classify(
        &detector_outputs,
        &c.registry,
        &ConfidenceConfig::provisional_default(),
    )
    .unwrap();
    let oem_key = classified.detector_output.oem_key.clone();
    assert_eq!(oem_key, "hikvision");

    let profile = c
        .registry
        .find_applicable(&oem_key, None, None, None)
        .expect("the versioned Hikvision profile");
    let orchestrator = ParsingOrchestrator::new();
    let parser = orchestrator
        .parser_for(&oem_key)
        .expect("the registered Hikvision parser");

    // ── Production recovery entry point ──────────────────────────────────────
    let evidence_id = EvidenceId::new();
    let outcome = RecoveryEngine::new()
        .execute_recovery(RecoveryRequest {
            evidence_id,
            reader: &c.reader,
            profile,
            oem_key: &oem_key,
            parser,
            bounds: &bounds(),
            scan_window: None,
            read_window_bytes: None,
        })
        .expect("recovery runs");

    // ── Geometry and index came from evidence ────────────────────────────────
    let geometry = outcome
        .plan
        .geometry
        .as_ref()
        .expect("geometry established");
    assert_eq!(geometry.physical_size, c.reader.len());
    assert_eq!(geometry.block_size, Some(c.image.block_size));
    assert_eq!(
        geometry.video_region.map(|r| r.offset),
        Some(c.image.video_start)
    );

    let index = outcome.plan.index.as_ref().expect("index read");
    assert!(
        index.authority.is_authoritative(),
        "a fully traversed tree over complete geometry is authoritative: {:?}",
        index.authority
    );
    // Block 0's two clips are accessible; block 1's clip is available (unreferenced).
    assert_eq!(index.recordings.len(), 2, "two accessible clips");
    assert_eq!(index.unreferenced_recordings.len(), 1, "one available clip");

    // ── The unreferenced block is orphaned, never deleted ────────────────────
    let block1 = c.image.block(1).unwrap();
    // The available clip's real physical offset (its footer slot described it, but block 1 is
    // not referenced by the tree, so it lands in the available set).
    // Several regions are legitimately Orphaned: block 1's available clip, and any unindexed
    // clip that falls inside the authoritative index's governed scope (the loose and slack
    // clips). The load-bearing fact is that the unreferenced block's own video data is among
    // them — not that it is the only one.
    let orphan_in_block1 = outcome.candidates.iter().find(|cand| {
        cand.data_state == DataState::Orphaned
            && cand.source_offsets[0].offset >= block1.offset
            && cand.source_offsets[0].offset < block1.footer_offset
    });
    assert!(
        orphan_in_block1.is_some(),
        "the unreferenced block's video data must be orphaned; orphans found at: {:?}",
        outcome
            .candidates
            .iter()
            .filter(|c| c.data_state == DataState::Orphaned)
            .map(|c| c.source_offsets[0].offset)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        orphan_in_block1.unwrap().provenance.source_evidence_id,
        evidence_id,
        "provenance points back at the registered evidence item"
    );

    // ── Nothing is Deleted without an allocation/free marker (there is none) ──
    assert_eq!(
        outcome.metrics.deleted_count, 0,
        "the Hikvision structures carry no free marker, so Deleted is unreachable"
    );
    assert!(
        outcome.metrics.orphaned_count >= 1,
        "the unreferenced block is orphaned"
    );

    // ── At least one accessible clip is Active, in block 0 ───────────────────
    let block0 = c.image.block(0).unwrap();
    let active_in_block0 = outcome.candidates.iter().any(|cand| {
        cand.data_state == DataState::Active
            && cand.source_offsets[0].offset >= block0.offset
            && cand.source_offsets[0].offset < block0.footer_offset
    });
    assert!(
        active_in_block0,
        "the referenced block's clips must be able to reach Active"
    );
}

#[test]
fn an_engine_discovered_clip_reconstructs_into_an_exportable_stream_with_provenance() {
    let c = open(realistic_dvr_volume());
    let profile = c
        .registry
        .find_applicable("hikvision", None, None, None)
        .unwrap();

    // Read the volume the way the export handler does, then reconstruct the first clip by the
    // id the index assigned it — the same id the engine reports on a fragment.
    let volume = parser_hikvision::volume::read_volume(&c.reader, profile).unwrap();
    let (_, clip) = c.image.first_clip().expect("a clip in the fixture");

    let reconstruction = parser_hikvision::reconstruct_recording(
        &c.reader,
        profile,
        &volume,
        &clip.expected_clip_id,
    )
    .unwrap()
    .expect("the recording behind the clip id");

    // The reconstruction is exportable: it has ordered payload ranges and a real codec.
    assert!(reconstruction.is_exportable());
    assert_ne!(reconstruction.codec.codec, HikCodec::Unknown);
    assert!(reconstruction.payload_bytes() > 0);

    // Concatenating the payload ranges reads real bytes from the evidence, in order, and every
    // range lies inside the clip it came from — never rebased, never past the end.
    let mut assembled = Vec::new();
    for r in &reconstruction.payload_regions {
        assert!(
            r.offset + r.length <= c.reader.len(),
            "no range past the evidence"
        );
        assembled.extend_from_slice(&c.reader.read_exact_at(r.offset, r.length as usize).unwrap());
    }
    assert_eq!(assembled.len() as u64, reconstruction.payload_bytes());

    // The recording id is the clip id, not a freshly minted one.
    assert_eq!(reconstruction.recording_id, clip.expected_clip_id);
    // The metadata carries the physical clip regions, so the export traces back to the bytes.
    let meta = reconstruction.oem_metadata();
    assert!(meta.contains_key("hikvision_clip_physical_regions"));
    assert!(meta.contains_key("hikvision_codec_evidence"));
}

#[test]
fn a_reconstructed_hikvision_recording_exports_as_artifacts_with_real_digests() {
    let c = open(realistic_dvr_volume());
    let profile = c
        .registry
        .find_applicable("hikvision", None, None, None)
        .unwrap();
    let volume = parser_hikvision::volume::read_volume(&c.reader, profile).unwrap();
    let (_, clip) = c.image.first_clip().unwrap();
    let rec = parser_hikvision::reconstruct_recording(
        &c.reader,
        profile,
        &volume,
        &clip.expected_clip_id,
    )
    .unwrap()
    .unwrap();

    // ── The stream: exactly the normalized export ranges, all evidence bytes ──
    let mut stream = Vec::new();
    for r in rec.export_regions() {
        assert!(r.offset + r.length <= c.reader.len());
        stream.extend_from_slice(&c.reader.read_exact_at(r.offset, r.length as usize).unwrap());
    }
    // PES framing was stripped: the stream is Annex-B H.264, not MPEG-PS.
    assert_ne!(
        &stream[..4],
        &[0x00, 0x00, 0x01, 0xBA],
        "no pack header in the export"
    );
    let codec_evidence = recovery::VideoReconstructor::classify_codec(&stream);
    assert_eq!(codec_evidence.codec, recovery::VideoCodec::H264);
    assert_eq!(codec_evidence.validation.state, ValidationStateKind::Pass);

    // ── Export: native + derived artifacts with real digests ────────────────
    let evidence_id = EvidenceId::new();
    let native_region = Region::new(rec.export_regions()[0].offset, stream.len() as u64).unwrap();
    let out = recovery::VideoReconstructor::reconstruct(
        evidence_id,
        native_region,
        stream.clone(),
        false,
        false,
    );
    assert_eq!(out.native_artifact.evidence_id, evidence_id);
    assert_ne!(
        out.native_artifact.hash,
        forensic_core::Hash::sha256(vec![0; 32]),
        "the native artifact must carry a real digest of the recovered bytes"
    );
    for d in &out.derived_artifacts {
        assert_eq!(d.provenance.source_evidence_id, evidence_id);
    }
    // A decode test that did not run is Unknown, never Pass.
    assert_eq!(out.validation_state.state, ValidationStateKind::Unknown);
}

#[test]
fn an_engine_discovered_orphan_exports_by_the_id_the_engine_reported() {
    // The production export path for an engine discovery: recovery reports a fragment with a
    // parent recording id; that id — not a freshly minted one — is what reconstruction resolves.
    let c = open(realistic_dvr_volume());
    let profile = c
        .registry
        .find_applicable("hikvision", None, None, None)
        .unwrap();
    let orchestrator = ParsingOrchestrator::new();
    let parser = orchestrator.parser_for("hikvision").unwrap();
    let evidence_id = EvidenceId::new();
    let outcome = RecoveryEngine::new()
        .execute_recovery(RecoveryRequest {
            evidence_id,
            reader: &c.reader,
            profile,
            oem_key: "hikvision",
            parser,
            bounds: &bounds(),
            scan_window: None,
            read_window_bytes: None,
        })
        .unwrap();

    let block1 = c.image.block(1).unwrap();
    let expected_parent = &block1.clips[0].expected_clip_id;
    let (cand, frag) = outcome
        .candidates
        .iter()
        .zip(outcome.fragments.iter())
        .find(|(cand, _)| {
            cand.data_state == DataState::Orphaned
                && cand.source_offsets[0].offset >= block1.offset
                && cand.source_offsets[0].offset < block1.footer_offset
        })
        .expect("the unreferenced block's video data is an orphan candidate");

    // Provenance and identity survive from engine to export.
    assert_eq!(frag.evidence_id, evidence_id);
    assert!(frag.id_is_consistent());
    assert_eq!(cand.provenance.source_evidence_id, evidence_id);
    let parent = frag
        .parent_recording
        .value()
        .expect("a fragment inside a described clip knows its recording");
    assert_eq!(parent, expected_parent);

    let volume = parser_hikvision::volume::read_volume(&c.reader, profile).unwrap();
    let rec = parser_hikvision::reconstruct_recording(&c.reader, profile, &volume, parent)
        .unwrap()
        .expect("the engine's parent id resolves");
    assert_eq!(
        &rec.recording_id, parent,
        "the id is used as given, never regenerated"
    );
    assert!(
        !rec.fully_accessible,
        "an orphan is not presented as a live recording"
    );
    assert!(rec.is_exportable());
    // The fragment's bytes lie inside the reconstructed recording's clips.
    let frag_start = cand.source_offsets[0].offset;
    assert!(rec
        .clip_regions
        .iter()
        .any(|r| frag_start >= r.offset && frag_start < r.offset + r.length));
}

#[test]
fn the_audited_pipeline_runs_end_to_end_on_a_hikvision_volume() {
    let c = open(realistic_dvr_volume());
    let evidence_id = EvidenceId::new();
    let run = pipeline::run_pipeline(
        evidence_id,
        &c.reader,
        &c.registry,
        &ConfidenceConfig::provisional_default(),
        &pipeline::PipelineOptions::default(),
    )
    .expect("the pipeline runs");

    for stage in &run.stages {
        eprintln!("{:?} {:?}: {}", stage.stage, stage.status, stage.detail);
    }

    assert_eq!(
        run.oem_key_used.as_deref(),
        Some("hikvision"),
        "the Hikvision parser was used, not the unified fallback"
    );
    assert!(!run.used_unified_fallback);
    assert_eq!(
        run.attribution.as_ref().expect("attribution").oem_key,
        "hikvision"
    );
    assert_eq!(run.parsing.as_ref().expect("parsing").recordings.len(), 3);

    if let Some(recovery_summary) = &run.recovery {
        assert_eq!(
            recovery_summary.metrics.deleted_count, 0,
            "Hikvision structures carry no free marker, so no deletion finding is possible"
        );
        for (cand, frag) in recovery_summary
            .candidates
            .iter()
            .zip(recovery_summary.fragments.iter())
        {
            assert_eq!(cand.provenance.source_evidence_id, evidence_id);
            assert_eq!(frag.evidence_id, evidence_id);
            assert!(frag.id_is_consistent());
        }
    }
}

#[test]
fn parsing_stages_pass_and_report_real_structures() {
    let c = open(realistic_dvr_volume());
    let profile = c
        .registry
        .find_applicable("hikvision", None, None, None)
        .unwrap();
    let result = ParsingOrchestrator::new()
        .run_parsing("hikvision", &c.reader, profile)
        .expect("parsing runs");

    assert_eq!(result.parser_runs.len(), 5, "all five stages run");

    // Filesystem stage recognises the volume; the reason never mentions the fictional tags.
    let fs = result
        .parser_runs
        .iter()
        .find(|r| r.operation_name == "parse_filesystem")
        .unwrap();
    assert!(matches!(
        fs.validation_state.state,
        ValidationStateKind::Pass | ValidationStateKind::Review
    ));
    for run in &result.parser_runs {
        assert!(!run.validation_state.reason.contains("HIK_"));
        assert!(!run.validation_state.reason.contains("HKSEG"));
        assert!(!run.validation_state.reason.contains("Mock"));
    }

    // Three clips → three recordings (two accessible in block 0, one available in block 1).
    assert_eq!(result.recordings.len(), 3);
    let available = result.recordings.iter().filter(|r| {
        r.integrity.iter().any(|f| match f {
            forensic_core::IntegrityFlag::Custom(s) => {
                s.contains("unreferenced") || s.contains("available")
            }
            _ => false,
        })
    });
    assert_eq!(
        available.count(),
        1,
        "the unreferenced block's recording must be flagged, not presented as active"
    );

    // Timeline events carry decoded instants and no assumed timezone.
    assert!(!result.timeline_events.is_empty());
    for ev in &result.timeline_events {
        assert_eq!(ev.time.timezone, forensic_core::TimeZoneState::Unknown);
    }
}

#[test]
fn a_multi_block_recording_reconstructs_across_the_block_boundary() {
    let c = open(forensic_tests::hikvision_fixtures::multi_block_recording_volume());
    let profile = c
        .registry
        .find_applicable("hikvision", None, None, None)
        .unwrap();
    let volume = parser_hikvision::volume::read_volume(&c.reader, profile).unwrap();
    let (_, seed) = c
        .image
        .block(0)
        .unwrap()
        .clips
        .first()
        .map(|clip| (0u32, clip))
        .unwrap();

    let reconstruction = parser_hikvision::reconstruct_recording(
        &c.reader,
        profile,
        &volume,
        &seed.expected_clip_id,
    )
    .unwrap()
    .expect("a recording");
    assert_eq!(
        reconstruction.blocks.len(),
        2,
        "a recording that continues into the next block must reconstruct as one: {:?}",
        reconstruction.blocks
    );
}

#[test]
fn a_corrupt_footer_block_yields_carved_candidates_not_index_claims() {
    // A block whose footer index is unusable but whose video data holds real clips: the only
    // path to its bytes is structural carving, and carving may not claim they were indexed.
    let spec = HikvisionImageSpec {
        blocks: vec![HikBlockSpec {
            clips: vec![HikClipSpec::default()],
            loose_clips: vec![LooseClipSpec::default(), LooseClipSpec::default()],
            footer: FooterMode::Corrupt,
        }],
        // A tree that references nothing in this block, so recovery must fall to carving.
        primary_tree: Some(HikTreeSpec::single_leaf(vec![HikEntrySpec::blank()])),
        ..Default::default()
    };
    let c = open(build_hikvision_image(&spec));
    let profile = c
        .registry
        .find_applicable("hikvision", None, None, None)
        .unwrap();
    let parser = ParsingOrchestrator::new();
    let parser = parser.parser_for("hikvision").unwrap();

    let block = c.image.block(0).unwrap();
    let region = Region::new(block.offset, block.footer_offset - block.offset).unwrap();
    let records = parser
        .scan_region_for_candidates(&c.reader, profile, region)
        .unwrap();
    assert!(
        records.len() >= 2,
        "the carver must find the block's video clips: {}",
        records.len()
    );
    for rec in &records {
        assert!(rec
            .oem_metadata
            .get("hikvision_carve_index_statement")
            .unwrap()
            .contains("cannot support an Active or Deleted conclusion"));
    }
}
