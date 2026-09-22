//! # Full production chain over a Dahua DHFS 4.1 volume
//!
//! Every stage is the real one, driven through the same orchestrators the API handler uses:
//!
//! ```text
//!   RawReader (read-only)
//!      ↓ DetectionOrchestrator::run            — real detectors, real profiles
//!      ↓ ConfidenceEngine::classify            — real attribution
//!      ↓ ProfileRegistry::find_applicable      — the versioned profile from profiles/
//!      ↓ ParsingOrchestrator::run_parsing      — the registered Dahua parser, all five stages
//!      ↓ RecoveryEngine::execute_recovery      — the production recovery entry point
//!      ↓ DataState::{Active, Orphaned, Unindexed}
//!      ↓ parser_dahua::reconstruct_recording   — chain → ordered blocks → DHII → DHAV frames
//!      ↓ VideoReconstructor::reconstruct       — native + derived artifacts, real digests
//!      ↓ exportable evidence artifact
//!   run_pipeline(...)                          — the audited end-to-end flow
//! ```
//!
//! The load-bearing assertions are the separations the design exists to enforce: detection saying
//! "this is Dahua" does not make any region `Active`; an unreachable chain is `Orphaned` and never
//! `Deleted`; and an exported artifact traces back to the exact physical bytes and the same
//! identifiers the engine assigned.

use confidence::config::ConfidenceConfig;
use confidence::engine::ConfidenceEngine;
use detection::orchestrator::DetectionOrchestrator;
use evidence_reader::{EvidenceReader, RawReader};
use forensic_core::{
    CancelToken, DataState, EvidenceId, ProfileRegistry, RecoveryBounds, RecoveryLevel, Region,
    ValidationStateKind,
};
use forensic_tests::dahua_fixtures::{self as fx, realistic};
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
    image: fx::DhfsImage,
    reader: RawReader,
    registry: ProfileRegistry,
    _dir: tempfile::TempDir,
}

fn open() -> Chain {
    let image = fx::realistic_xvr_volume();
    let dir = tempfile::tempdir().unwrap();
    let path = image
        .write_to_dir(dir.path(), "dahua_dhfs41_production.raw")
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
fn full_chain_detection_to_orphan_discovery() {
    let c = open();
    let p = c.image.partition(0).expect("partition 0");

    // ── 1. OEM detection ────────────────────────────────────────────────────
    let detector_outputs = DetectionOrchestrator::new()
        .run(&c.reader, &c.registry)
        .expect("detection runs");
    let dahua = detector_outputs
        .iter()
        .find(|o| o.oem_key == "dahua")
        .expect("a Dahua detector output");
    assert_eq!(
        dahua.status,
        detection::DetectionStatus::Confirmed,
        "the DHFS 4.1 signature plus a verified partition table identifier is Confirmed: {:?}",
        dahua.warnings
    );

    let classified = ConfidenceEngine::classify(
        &detector_outputs,
        &c.registry,
        &ConfidenceConfig::provisional_default(),
    )
    .expect("confidence classifies");
    assert_eq!(classified.detector_output.oem_key, "dahua");
    let oem_key = classified.detector_output.oem_key.clone();

    // ── 2. Profile + parser, exactly as the API handler resolves them ───────
    let profile = c
        .registry
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
            reader: &c.reader,
            profile,
            oem_key: &oem_key,
            parser,
            bounds: &bounds(),
            scan_window: None,
            read_window_bytes: None,
        })
        .expect("recovery runs");

    eprintln!("plan: {}", outcome.plan.rationale);
    for (cand, frag) in outcome.candidates.iter().zip(outcome.fragments.iter()) {
        eprintln!(
            "  {} 0x{:X} len {} -> {:?}/{:?} {:?} via {}",
            frag.fragment_id,
            cand.source_offsets[0].offset,
            cand.source_offsets[0].length,
            cand.data_state,
            cand.recovery_status,
            cand.recovery_level,
            frag.discovery_method.label()
        );
    }

    // ── 4. Geometry and the recording index came from evidence ──────────────
    let geometry = outcome
        .plan
        .geometry
        .as_ref()
        .expect("geometry established");
    assert_eq!(geometry.physical_size, c.reader.len());
    assert_eq!(geometry.block_size, Some(fx::VIDEO_BLOCK));
    assert_eq!(
        geometry.video_region.map(|r| r.offset),
        Some(p.video_base),
        "the video region comes from the partition's VideoStartSector"
    );
    assert_eq!(
        geometry.index_region.map(|r| r.offset),
        Some(p.block_table_offset),
        "the block table comes from the partition's IndexStartSector"
    );

    let index = outcome.plan.index.as_ref().expect("index read");
    assert!(index.authority.is_authoritative());
    assert_eq!(index.recordings.len(), 2, "two accessible chains");
    assert_eq!(
        index.unreferenced_recordings.len(),
        1,
        "one available chain"
    );

    // ── 5. The available chain is orphaned, never deleted ───────────────────
    let available_frame = p.block(realistic::AVAILABLE_BLOCK).unwrap().frame_offsets[0];
    let orphan = outcome
        .candidates
        .iter()
        .find(|cand| {
            cand.data_state == DataState::Orphaned
                && cand.source_offsets[0].offset == available_frame
        })
        .unwrap_or_else(|| {
            panic!("no Orphaned candidate at the available recording's frame 0x{available_frame:X}")
        });
    assert_eq!(orphan.recovery_level, RecoveryLevel::L2);
    assert_eq!(
        orphan.provenance.source_evidence_id, evidence_id,
        "provenance points back at the registered evidence item"
    );
    assert!(orphan
        .provenance
        .validation_state
        .reason
        .contains("not evidence of deletion"));

    // ── 6. Only the accessible chains' bytes are Active ─────────────────────
    let mut expected_active: Vec<u64> = Vec::new();
    for b in [
        realistic::CH1_HEAD_BLOCK,
        realistic::CH1_TAIL_BLOCK,
        realistic::CH2_BLOCK,
    ] {
        expected_active.extend(p.block(b).unwrap().frame_offsets.iter().copied());
    }
    expected_active.sort_unstable();
    let mut active: Vec<u64> = outcome
        .candidates
        .iter()
        .filter(|cand| cand.data_state == DataState::Active)
        .map(|cand| cand.source_offsets[0].offset)
        .collect();
    active.sort_unstable();
    assert_eq!(
        active, expected_active,
        "only bytes the accessible recording set claims may be Active"
    );

    // ── 7. Nothing is called Deleted or Overwritten without evidence ────────
    assert_eq!(outcome.metrics.deleted_count, 0);
    assert_eq!(outcome.metrics.overwritten_count, 0);
    assert!(outcome.metrics.orphaned_count >= 1);
    assert!(
        outcome.metrics.unindexed_count >= 1,
        "slack video is unindexed"
    );
}

#[test]
fn parsing_stages_pass_on_a_dhfs41_volume_and_report_real_structures() {
    let c = open();
    let profile = c
        .registry
        .find_applicable("dahua", None, None, None)
        .unwrap();
    let result = ParsingOrchestrator::new()
        .run_parsing("dahua", &c.reader, profile)
        .expect("parsing runs");

    assert_eq!(result.parser_runs.len(), 5, "all five stages still run");
    for run in &result.parser_runs {
        eprintln!(
            "stage {} -> {:?} ({})",
            run.operation_name, run.validation_state.state, run.validation_state.reason
        );
    }

    // The filesystem stage recognises DHFS 4.1 and reads its partition table.
    let fs_stage = result
        .parser_runs
        .iter()
        .find(|r| r.operation_name == "parse_filesystem")
        .unwrap();
    assert_eq!(fs_stage.validation_state.state, ValidationStateKind::Pass);
    assert!(fs_stage.validation_state.reason.contains("DHFS 4.1"));

    // One recording per chain: two accessible, one available.
    assert_eq!(result.recordings.len(), 3);
    let mut channels: Vec<u32> = result.recordings.iter().map(|r| r.channel).collect();
    channels.sort_unstable();
    assert_eq!(channels, vec![1, 2, 3]);

    // The available recording is flagged as such on the recording itself.
    let available = result
        .recordings
        .iter()
        .find(|r| r.channel == 3)
        .expect("the channel-3 recording");
    assert!(
        available.integrity.iter().any(|f| match f {
            forensic_core::IntegrityFlag::Custom(s) => s.contains("available"),
            _ => false,
        }),
        "an available recording must be flagged, not silently presented as active: {:?}",
        available.integrity
    );

    // A multi-block recording keeps every block, in chain order.
    let ch1 = result.recordings.iter().find(|r| r.channel == 1).unwrap();
    assert_eq!(ch1.source_offsets.len(), 2);
    assert!(ch1.source_offsets[0].offset < ch1.source_offsets[1].offset);

    // Timeline events exist for every chain that carried a decodable clock.
    assert_eq!(result.timeline_events.len(), 3);
}

#[test]
fn no_parser_output_claims_a_timezone_the_evidence_did_not_state() {
    let c = open();
    let profile = c
        .registry
        .find_applicable("dahua", None, None, None)
        .unwrap();
    let result = ParsingOrchestrator::new()
        .run_parsing("dahua", &c.reader, profile)
        .unwrap();

    for rec in &result.recordings {
        assert_eq!(
            rec.time.timezone,
            forensic_core::TimeZoneState::Unknown,
            "no recorder timezone offset is established by parsing, so none may be claimed"
        );
        // The recorder's own digits are reported with no zone suffix.
        let native = rec
            .time
            .recorder_native
            .as_ref()
            .expect("a decoded wall clock")
            .iso_8601
            .clone();
        assert!(!native.contains('+'), "no offset may be appended: {native}");
        assert!(
            !native.ends_with('Z'),
            "and no zone may be asserted: {native}"
        );
        // The normalization method states explicitly that no offset was applied.
        let method = rec.time.normalized.as_ref().unwrap().method.clone();
        assert!(method.contains("no recorder timezone offset"), "{method}");
        // The raw packed field is retained so the decoding is re-derivable.
        assert_eq!(rec.time.raw.format, "DAHUA_PACKED_BASE2000_LE");
        assert_ne!(rec.time.raw.value, 0);
    }
    for ev in &result.timeline_events {
        assert_eq!(ev.time.timezone, forensic_core::TimeZoneState::Unknown);
    }
}

#[test]
fn recognize_candidate_is_format_recognition_not_an_index_lookup() {
    // The defect this guards: `recognize_candidate` once returned `Ok(true)` for any bytes, which
    // the engine then treated as proof of indexation. It must answer a pure format question, and
    // answer it honestly.
    let c = open();
    let profile = c
        .registry
        .find_applicable("dahua", None, None, None)
        .unwrap();
    let parser = parser_dahua::DahuaParser::default();
    let p = c.image.partition(0).unwrap();

    // A window over a block that holds frames: framing present.
    let frame_block = p.block(realistic::CH1_HEAD_BLOCK).unwrap();
    let at_frames =
        evidence_reader::BoundedReader::new(&c.reader, frame_block.offset, fx::VIDEO_BLOCK)
            .unwrap();
    assert!(
        parsers_core::Parser::recognize_candidate(&parser, &at_frames, profile).unwrap(),
        "DHAV framing is present in this block"
    );

    // A window over an empty block: no framing. Under the old implementation this also returned
    // true, which is what suppressed every orphan and unindexed finding.
    let empty_block = p.block(realistic::EMPTY_BLOCK).unwrap();
    let at_empty =
        evidence_reader::BoundedReader::new(&c.reader, empty_block.offset, fx::VIDEO_BLOCK)
            .unwrap();
    assert!(
        !parsers_core::Parser::recognize_candidate(&parser, &at_empty, profile).unwrap(),
        "an unused block carries no DHAV framing and must not be recognised"
    );
}

// ── Recording and stream reconstruction, through to an exportable artifact ─────

#[test]
fn a_multi_block_recording_reconstructs_into_an_ordered_exportable_stream() {
    let c = open();
    let profile = c
        .registry
        .find_applicable("dahua", None, None, None)
        .unwrap();
    let volume = parser_dahua::volume::read_volume(&c.reader, profile).unwrap();

    let classified =
        parser_dahua::find_chain(&volume, realistic::CH1_CHAIN_ID).expect("the channel-1 chain");
    assert_eq!(classified.chain.blocks.len(), 2, "a two-block recording");

    let rec = parser_dahua::reconstruct_recording(&c.reader, profile, &classified.chain).unwrap();
    let p = c.image.partition(0).unwrap();

    // Blocks in chain order, frames in block-chain then container order.
    assert_eq!(
        rec.block_regions
            .iter()
            .map(|r| r.offset)
            .collect::<Vec<_>>(),
        vec![
            p.block(realistic::CH1_HEAD_BLOCK).unwrap().offset,
            p.block(realistic::CH1_TAIL_BLOCK).unwrap().offset
        ]
    );
    let mut expected_frames: Vec<u64> = Vec::new();
    expected_frames.extend(
        p.block(realistic::CH1_HEAD_BLOCK)
            .unwrap()
            .frame_offsets
            .iter(),
    );
    expected_frames.extend(
        p.block(realistic::CH1_TAIL_BLOCK)
            .unwrap()
            .frame_offsets
            .iter(),
    );
    assert_eq!(
        rec.frames
            .iter()
            .map(|f| f.frame.physical_offset)
            .collect::<Vec<_>>(),
        expected_frames,
        "frames are ordered by the block chain first"
    );
    // Dense sequence numbers and the recorder's own frame numbers agree.
    assert_eq!(
        rec.frames.iter().map(|f| f.sequence).collect::<Vec<_>>(),
        (0..rec.frames.len()).collect::<Vec<_>>()
    );
    assert_eq!(
        rec.frames
            .iter()
            .map(|f| f.frame.frame_number)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(rec.codec().as_deref(), Some("H.264"));
    assert!(
        rec.notes.is_empty(),
        "no gaps in this recording: {:?}",
        rec.notes
    );
    assert_eq!(rec.evidence.state, ValidationStateKind::Pass);

    // ── The stream: concatenating exactly those payload ranges ──────────────
    assert_eq!(rec.payload_regions.len(), 3);
    let mut stream = Vec::with_capacity(rec.payload_bytes() as usize);
    for region in &rec.payload_regions {
        stream.extend_from_slice(
            &c.reader
                .read_exact_at(region.offset, region.length as usize)
                .expect("payload bytes are present"),
        );
    }
    assert_eq!(stream.len() as u64, rec.payload_bytes());
    // The assembled stream is decodable H.264 — the payload boundaries were right.
    let codec_evidence = recovery::VideoReconstructor::classify_codec(&stream);
    assert_eq!(codec_evidence.codec, recovery::VideoCodec::H264);
    assert_eq!(codec_evidence.validation.state, ValidationStateKind::Pass);

    // ── Export: native + derived artifacts with real digests ────────────────
    let evidence_id = EvidenceId::new();
    let native_region = Region::new(rec.payload_regions[0].offset, rec.payload_bytes()).unwrap();
    let out = recovery::VideoReconstructor::reconstruct(
        evidence_id,
        native_region,
        stream.clone(),
        false,
        false,
    );
    assert_eq!(out.native_artifact.evidence_id, evidence_id);
    assert_eq!(out.native_artifact.region, native_region);
    assert_ne!(
        out.native_artifact.hash,
        forensic_core::Hash::sha256(vec![0; 32]),
        "the native artifact must carry a real digest of the recovered bytes"
    );
    assert!(!out.derived_artifacts.is_empty());
    for d in &out.derived_artifacts {
        assert_eq!(d.provenance.source_evidence_id, evidence_id);
        assert!(d
            .provenance
            .source_regions
            .iter()
            .all(|sr| sr.evidence_id == evidence_id));
    }
    // A decode test that did not run is Unknown, never Pass.
    assert_eq!(out.validation_state.state, ValidationStateKind::Unknown);
}

#[test]
fn a_dhii_indexed_recording_is_ordered_by_its_frame_index() {
    let c = open();
    let profile = c
        .registry
        .find_applicable("dahua", None, None, None)
        .unwrap();
    let volume = parser_dahua::volume::read_volume(&c.reader, profile).unwrap();
    let classified =
        parser_dahua::find_chain(&volume, realistic::CH2_CHAIN_ID).expect("the channel-2 chain");
    let rec = parser_dahua::reconstruct_recording(&c.reader, profile, &classified.chain).unwrap();

    assert_eq!(
        rec.ordering,
        parser_dahua::ReconstructionOrdering::BlockChainThenDhii,
        "this block carries a DHII index, so it decides the frame order"
    );
    assert_eq!(rec.dhii_indexes.len(), 1);
    assert!(rec
        .frames
        .iter()
        .all(|f| f.source == parser_dahua::FrameSource::DhiiReferenceIndex));
    let p = c.image.partition(0).unwrap();
    assert_eq!(
        rec.frames
            .iter()
            .map(|f| f.frame.physical_offset)
            .collect::<Vec<_>>(),
        p.block(realistic::CH2_BLOCK).unwrap().frame_offsets
    );
}

#[test]
fn an_available_recording_is_exportable_and_keeps_its_chain_identity() {
    // An available recording is real recoverable video. It must be exportable, and the export must
    // stay tied to the chain the filesystem metadata named.
    let c = open();
    let profile = c
        .registry
        .find_applicable("dahua", None, None, None)
        .unwrap();
    let volume = parser_dahua::volume::read_volume(&c.reader, profile).unwrap();

    let classified = parser_dahua::find_chain(&volume, realistic::AVAILABLE_CHAIN_ID)
        .expect("the available chain");
    assert!(
        !classified.accessibility.is_accessible(),
        "this chain is available, not accessible"
    );

    let rec = parser_dahua::reconstruct_recording(&c.reader, profile, &classified.chain).unwrap();
    assert_eq!(rec.chain_id, realistic::AVAILABLE_CHAIN_ID);
    assert_eq!(rec.channel.normalized, 3);
    assert_eq!(rec.payload_regions.len(), 1);

    let mut stream = Vec::new();
    for region in &rec.payload_regions {
        stream.extend_from_slice(
            &c.reader
                .read_exact_at(region.offset, region.length as usize)
                .unwrap(),
        );
    }
    assert_eq!(
        recovery::VideoReconstructor::classify_codec(&stream).codec,
        recovery::VideoCodec::H264,
        "an orphaned recording's bytes are as exportable as an active one's"
    );
}

// ── The audited pipeline ───────────────────────────────────────────────────────

#[test]
fn the_audited_pipeline_runs_end_to_end_on_a_dhfs41_volume() {
    let c = open();
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
        Some("dahua"),
        "the Dahua parser was used, not the unified fallback"
    );
    assert!(!run.used_unified_fallback);
    assert!(
        !run.requires_analyst,
        "a clean DHFS 4.1 volume should not need analyst intervention: {:?}",
        run.analyst_reasons
    );
    let attribution = run.attribution.as_ref().expect("attribution recorded");
    assert_eq!(attribution.oem_key, "dahua");

    let parsing = run.parsing.as_ref().expect("parsing recorded");
    assert_eq!(parsing.recordings.len(), 3);

    // Any recovery the pipeline ran must not have invented a deletion finding, and every
    // candidate must trace back to this evidence item.
    if let Some(recovery_summary) = &run.recovery {
        assert_eq!(recovery_summary.metrics.deleted_count, 0);
        assert_eq!(recovery_summary.metrics.overwritten_count, 0);
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

    // Timeline events carry real digests, not zero-filled placeholders.
    if let Some(timeline) = &run.final_timeline {
        for ev in &timeline.events {
            assert_ne!(
                ev.profile_hash,
                forensic_core::Hash::sha256(vec![0; 32]),
                "a placeholder digest would read as a verified hash in a report"
            );
        }
    }
}
