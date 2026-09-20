use evidence_reader::{EvidenceReader, RawReader};
use forensic_core::{ProfileRegistry, ValidationStateKind};
use detection::orchestrator::DetectionOrchestrator;
use confidence::config::ConfidenceConfig;
use confidence::engine::ConfidenceEngine;
use parsing::orchestrator::ParsingOrchestrator;
use std::path::Path;

/// End-to-end check against the synthetic Dahua DHFS image produced by
/// `generate_dahua_raw.py` (dahua_dhfs_sample.raw).
///
/// Exercises the same pipeline the TP-Link sample test uses:
///   topology -> profile load -> detection -> confidence -> parsing.
///
/// Expectations reflect what the current Dahua detector/parser actually emit:
///   * Detector: DetectionStatus::Confirmed (DHFS magic @0 + DHAV tag in window)
///   * Confidence: positive score
///   * Parser: all five stages run without error
#[test]
fn test_dahua_sample_raw_detection_and_parsing() {
    let raw_path = if Path::new("dahua_dhfs_sample.raw").exists() {
        Path::new("dahua_dhfs_sample.raw").to_path_buf()
    } else {
        Path::new("../dahua_dhfs_sample.raw").to_path_buf()
    };
    // `*.raw` fixtures are gitignored, so a clean checkout (and CI) will not have
    // this image until `generate_dahua_raw.py` is run. Skip rather than fail, so a
    // missing generated fixture is not reported as a broken parser.
    if !raw_path.exists() {
        eprintln!(
            "skipping: {raw_path:?} not present — run `python3 generate_dahua_raw.py` to create it"
        );
        return;
    }

    let reader = RawReader::open(raw_path.to_str().unwrap()).expect("Failed to open raw reader");
    assert_eq!(reader.len(), 4 * 1024 * 1024);

    // 1. Load Profiles
    let profiles_dir = if Path::new("profiles").exists() {
        Path::new("profiles").to_path_buf()
    } else {
        Path::new("../profiles").to_path_buf()
    };
    let registry = ProfileRegistry::load_from_dir(&profiles_dir).expect("Failed to load profiles");
    let dahua_profile = registry
        .find_applicable("dahua", None, None, None)
        .expect("Dahua profile not found");

    // 2. Verify Detection -> Confirmed
    let det_orchestrator = DetectionOrchestrator::new();
    let detector_outputs = det_orchestrator.run(&reader, &registry).expect("Detection failed");
    let dahua_output = detector_outputs
        .iter()
        .find(|o| o.oem_key == "dahua")
        .expect("Dahua output missing");
    eprintln!(
        "Dahua detection: status={:?}, evidence_items={}",
        dahua_output.status,
        dahua_output.evidence.len()
    );
    assert_eq!(
        dahua_output.status,
        detection::DetectionStatus::Confirmed,
        "DHFS magic @0 + DHAV tag should yield Confirmed"
    );

    // 3. Verify Confidence Classification
    let config = ConfidenceConfig::provisional_default();
    let classified = ConfidenceEngine::classify(&detector_outputs, &registry, &config)
        .expect("Classification failed");
    eprintln!(
        "Classified: oem={}, status={:?}, confidence={}, raw_score={}",
        classified.detector_output.oem_key,
        classified.attribution_status,
        classified.confidence,
        classified.raw_score
    );
    assert!(classified.confidence > 0.0, "Expected positive confidence score");

    // 4. Verify Parsing Orchestrator runs all stages without error
    let parsing_orchestrator = ParsingOrchestrator::new();
    let parse_result = parsing_orchestrator
        .run_parsing("dahua", &reader, dahua_profile)
        .expect("Parsing failed");

    assert_eq!(parse_result.parser_runs.len(), 5, "Expected 5 parser stages");
    for run in &parse_result.parser_runs {
        eprintln!(
            "Stage {} -> {:?} ({})",
            run.operation_name, run.validation_state.state, run.validation_state.reason
        );
        assert_eq!(
            run.validation_state.state,
            ValidationStateKind::Pass,
            "Stage {} should PASS on the synthetic Dahua image",
            run.operation_name
        );
    }

    // 5. Real extraction: two DHAV packets were written into the image.
    eprintln!(
        "Extracted {} recordings, {} timeline events",
        parse_result.recordings.len(),
        parse_result.timeline_events.len()
    );
    assert_eq!(
        parse_result.recordings.len(),
        2,
        "Should extract both DHAV recordings (CH01, CH02)"
    );
    assert_eq!(
        parse_result.timeline_events.len(),
        2,
        "Should extract a timeline event per DHAV packet"
    );
}
