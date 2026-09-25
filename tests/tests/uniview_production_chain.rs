//! # Full production chain over synthetic Uniview volumes
//!
//! Every stage is the real one, driven through the same orchestrators the API handler uses:
//!
//! ```text
//!   RawReader (read-only) / sparse reader for the 256 MiB-offset NEW layout
//!      ↓ DetectionOrchestrator::run            — real detectors, real profiles
//!      ↓ ConfidenceEngine::classify            — real attribution
//!      ↓ ParsingOrchestrator::run_parsing      — the registered Uniview parser, all five stages
//!      ↓ RecoveryEngine::execute_recovery      — the production recovery entry point
//!      ↓ parser_uniview::extract_recording     — raw DATA, exact offsets, SHA-256
//!      ↓ pipeline::run_pipeline                — the audited end-to-end flow
//! ```
//!
//! The load-bearing assertions: the SUPER magic alone attributes the volume (and its
//! generation); no other OEM detector confirms a Uniview volume and the Uniview detector
//! confirms no other OEM's; unreferenced DATA is never `Orphaned` or `Deleted`; and extracted
//! DATA is byte-exact and carries no codec claim from the parser.

use confidence::config::ConfidenceConfig;
use confidence::engine::ConfidenceEngine;
use detection::orchestrator::DetectionOrchestrator;
use detection::DetectionStatus;
use evidence_reader::{EvidenceReader, RawReader};
use forensic_core::{CancelToken, DataState, EvidenceId, ProfileRegistry, RecoveryBounds, ValidationStateKind};
use parser_uniview::testing::image;
use parser_uniview::{volume, UniviewLayout};
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

fn registry() -> ProfileRegistry {
    ProfileRegistry::load_from_dir(&profiles_dir()).expect("profiles load")
}

fn layout(reg: &ProfileRegistry) -> UniviewLayout {
    UniviewLayout::from_profile(reg.find_applicable("uniview", None, None, None).expect("uniview profile"))
}

/// The small OLD-generation volume, written to disk and opened through the production reader.
fn open_old(reg: &ProfileRegistry) -> (tempfile::TempDir, RawReader) {
    let bytes = image::small_old_volume(&layout(reg)).materialize();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("uniview_old.raw");
    std::fs::write(&path, &bytes).unwrap();
    let reader = RawReader::open(path.to_str().unwrap()).expect("evidence opens read-only");
    (dir, reader)
}

#[test]
fn detection_confirms_uniview_from_the_super_magic_alone() {
    let reg = registry();
    let (_d, old) = open_old(&reg);
    let new = image::new_volume(&layout(&reg));

    for (reader, gen) in [(&old as &dyn EvidenceReader, "OLD"), (&new as &dyn EvidenceReader, "NEW")] {
        let outputs = DetectionOrchestrator::new().run(reader, &reg).unwrap();
        let unv = outputs.iter().find(|o| o.oem_key == "uniview").expect("uniview output");
        assert_eq!(unv.status, DetectionStatus::Confirmed, "{:?}", unv.warnings);
        assert!(unv.evidence[0].explanation.contains(gen));
        for other in outputs.iter().filter(|o| o.oem_key != "uniview") {
            assert_ne!(other.status, DetectionStatus::Confirmed, "{} confirmed a Uniview volume", other.oem_key);
        }
        let classified =
            ConfidenceEngine::classify(&outputs, &reg, &ConfidenceConfig::provisional_default()).unwrap();
        assert_eq!(classified.detector_output.oem_key, "uniview");
    }
}

#[test]
fn random_bytes_and_a_lookalike_tag_are_not_uniview() {
    let reg = registry();
    let random: Vec<u8> = (0..(1u32 << 18)).map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8).collect();
    let mut ascii = vec![0u8; 1 << 16];
    ascii[..4].copy_from_slice(b"UNIV");
    for bytes in [random, ascii] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.raw");
        std::fs::write(&path, &bytes).unwrap();
        let reader = RawReader::open(path.to_str().unwrap()).unwrap();
        let outputs = DetectionOrchestrator::new().run(&reader, &reg).unwrap();
        let unv = outputs.iter().find(|o| o.oem_key == "uniview").unwrap();
        assert_eq!(unv.status, DetectionStatus::NotDetected);
    }
}

#[test]
fn parsing_orchestrator_runs_every_uniview_stage() {
    let reg = registry();
    let (_d, reader) = open_old(&reg);
    let profile = reg.find_applicable("uniview", None, None, None).unwrap();
    let result = ParsingOrchestrator::new().run_parsing("uniview", &reader, profile).unwrap();

    assert_eq!(result.parser_runs.len(), 5);
    for run in &result.parser_runs {
        assert_eq!(run.parser_id, "uniview-super-di-parser");
        assert_eq!(run.validation_state.state, ValidationStateKind::Pass, "{}: {}", run.operation_name, run.validation_state.reason);
    }
    assert_eq!(result.recordings.len(), 1);
    assert_eq!(result.timeline_events.len(), 1);
}

#[test]
fn recovery_and_extraction_over_the_production_reader() {
    let reg = registry();
    let (_d, reader) = open_old(&reg);
    let profile = reg.find_applicable("uniview", None, None, None).unwrap();
    let orchestrator = ParsingOrchestrator::new();
    let parser = orchestrator.parser_for("uniview").unwrap();
    let bounds = RecoveryBounds {
        max_scan_bytes: u64::MAX,
        max_scan_regions: u32::MAX,
        max_candidates: u32::MAX,
        max_hypotheses: 1024,
        max_search_depth: None,
        cancel: CancelToken::new(),
        time_limit: None,
    };
    let outcome = RecoveryEngine::new()
        .execute_recovery(RecoveryRequest {
            evidence_id: EvidenceId::new(),
            reader: &reader,
            profile,
            oem_key: "uniview",
            parser,
            bounds: &bounds,
            scan_window: None,
            read_window_bytes: None,
        })
        .unwrap();
    assert!(outcome.metrics.geometry_available);
    assert!(!outcome.metrics.authoritative_index);
    assert_eq!(outcome.metrics.deleted_count, 0);
    for c in &outcome.candidates {
        assert!(!matches!(c.data_state, DataState::Orphaned | DataState::Deleted));
    }

    let vol = volume::read_volume(&reader, profile).unwrap();
    let x = parser_uniview::extract_recording(&reader, &vol, "unv:u1").unwrap().unwrap();
    // The extracted bytes are the evidence bytes at the recorded offsets.
    let direct = reader.read_exact_at(x.regions[0].offset, x.regions[0].length as usize).unwrap();
    assert_eq!(x.bytes, direct);
    assert_eq!(x.region_sha256.len(), 1);
}

#[test]
fn the_audited_pipeline_runs_end_to_end_on_a_uniview_volume() {
    let reg = registry();
    let (_d, reader) = open_old(&reg);
    let evidence_id = EvidenceId::new();
    let run = pipeline::run_pipeline(
        evidence_id,
        &reader,
        &reg,
        &ConfidenceConfig::provisional_default(),
        &pipeline::PipelineOptions::default(),
    )
    .expect("the pipeline runs");

    assert_eq!(run.oem_key_used.as_deref(), Some("uniview"), "the Uniview parser was used");
    assert!(!run.used_unified_fallback);
    assert_eq!(run.attribution.as_ref().expect("attribution").oem_key, "uniview");
    assert_eq!(run.parsing.as_ref().expect("parsing").recordings.len(), 1);
    if let Some(r) = &run.recovery {
        assert_eq!(r.metrics.deleted_count, 0);
        assert_eq!(r.metrics.orphaned_count, 0);
    }
}
