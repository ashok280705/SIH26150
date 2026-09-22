//! End-to-end check against the DHFS 4.1 image produced by `generate_dahua_raw.py`
//! (`dahua_dhfs_sample.raw`).
//!
//! This is the one Dahua test driven by an image built **outside** the Rust test suite, by an
//! independent implementation of the same structure definitions. That independence is the point:
//! the Rust fixture builders and the parser could agree on a shared misreading, whereas a
//! separately written generator agreeing with the parser is a real cross-check of the format
//! facts — signature, partition table identifier and offsets, partition information fields, the
//! 32-byte block-table entry, the packed timestamp encoding, and DHAV framing.
//!
//! It exercises the same pipeline the TP-Link sample test uses:
//!   detection -> confidence -> profile -> parsing.
//!
//! The image is still synthetic. Agreement between two implementations of the documented
//! structures is not evidence of compatibility with any particular Dahua firmware.

use confidence::config::ConfidenceConfig;
use confidence::engine::ConfidenceEngine;
use detection::orchestrator::DetectionOrchestrator;
use evidence_reader::{EvidenceReader, RawReader};
use forensic_core::{ProfileRegistry, TimeZoneState, ValidationStateKind};
use parsing::orchestrator::ParsingOrchestrator;
use std::path::Path;

#[test]
fn test_dahua_sample_raw_detection_and_parsing() {
    let raw_path = if Path::new("dahua_dhfs_sample.raw").exists() {
        Path::new("dahua_dhfs_sample.raw").to_path_buf()
    } else {
        Path::new("../dahua_dhfs_sample.raw").to_path_buf()
    };
    // `*.raw` fixtures are gitignored, so a clean checkout (and CI) will not have this image
    // until `generate_dahua_raw.py` is run. Skip rather than fail, so a missing generated
    // fixture is not reported as a broken parser.
    if !raw_path.exists() {
        eprintln!(
            "skipping: {raw_path:?} not present — run `python3 generate_dahua_raw.py` to create it"
        );
        return;
    }

    let reader = RawReader::open(raw_path.to_str().unwrap()).expect("Failed to open raw reader");
    // The image is sized from the structures it holds, so no fixed length is asserted. What
    // matters is that it carries a whole DHFS 4.1 structure set.
    assert!(
        reader.len() > 2 * 1024 * 1024,
        "a DHFS 4.1 image holds at least one 2 MiB video block"
    );
    assert_eq!(
        reader.read_exact_at(0, 8).expect("read the signature"),
        b"DHFS4.1\0",
        "the generator must write the DHFS 4.1 volume signature"
    );

    // 1. Load profiles
    let profiles_dir = if Path::new("profiles").exists() {
        Path::new("profiles").to_path_buf()
    } else {
        Path::new("../profiles").to_path_buf()
    };
    let registry = ProfileRegistry::load_from_dir(&profiles_dir).expect("Failed to load profiles");
    let dahua_profile = registry
        .find_applicable("dahua", None, None, None)
        .expect("Dahua profile not found");

    // 2. Detection is Confirmed — corroborated by the partition table, which is at a known
    //    offset, not by a frame tag that a real DHFS 4.1 layout does not put near the start.
    let detector_outputs = DetectionOrchestrator::new()
        .run(&reader, &registry)
        .expect("Detection failed");
    let dahua_output = detector_outputs
        .iter()
        .find(|o| o.oem_key == "dahua")
        .expect("Dahua output missing");
    eprintln!(
        "Dahua detection: status={:?}, evidence_items={}, warnings={:?}",
        dahua_output.status,
        dahua_output.evidence.len(),
        dahua_output.warnings
    );
    assert_eq!(
        dahua_output.status,
        detection::DetectionStatus::Confirmed,
        "the DHFS 4.1 signature plus a verified partition table identifier is Confirmed"
    );
    assert!(
        dahua_output
            .evidence
            .iter()
            .any(|e| e.kind == "partition_table_identifier"),
        "the generator's partition table must be recognised at its declared offset"
    );

    // 3. Confidence classification
    let classified = ConfidenceEngine::classify(
        &detector_outputs,
        &registry,
        &ConfidenceConfig::provisional_default(),
    )
    .expect("Classification failed");
    eprintln!(
        "Classified: oem={}, status={:?}, confidence={}, raw_score={}",
        classified.detector_output.oem_key,
        classified.attribution_status,
        classified.confidence,
        classified.raw_score
    );
    assert!(
        classified.confidence > 0.0,
        "Expected positive confidence score"
    );

    // 4. All five parsing stages run
    let parse_result = ParsingOrchestrator::new()
        .run_parsing("dahua", &reader, dahua_profile)
        .expect("Parsing failed");

    assert_eq!(
        parse_result.parser_runs.len(),
        5,
        "Expected 5 parser stages"
    );
    for run in &parse_result.parser_runs {
        eprintln!(
            "Stage {} -> {:?} ({})",
            run.operation_name, run.validation_state.state, run.validation_state.reason
        );
    }
    let fs_stage = parse_result
        .parser_runs
        .iter()
        .find(|r| r.operation_name == "parse_filesystem")
        .expect("the filesystem stage ran");
    assert_eq!(
        fs_stage.validation_state.state,
        ValidationStateKind::Pass,
        "the generator's DHFS 4.1 structures must read cleanly: {}",
        fs_stage.validation_state.reason
    );
    assert!(
        fs_stage.validation_state.reason.contains("DHFS 4.1"),
        "the stage must name the structural model it used: {}",
        fs_stage.validation_state.reason
    );

    // 5. Real extraction: one recording per block chain the generator wrote.
    eprintln!(
        "Extracted {} recording(s), {} timeline event(s)",
        parse_result.recordings.len(),
        parse_result.timeline_events.len()
    );
    assert!(
        !parse_result.recordings.is_empty(),
        "the generator writes one block chain per recorded segment"
    );
    // Both channels the generator records are present.
    let channels: std::collections::BTreeSet<u32> =
        parse_result.recordings.iter().map(|r| r.channel).collect();
    assert!(
        channels.contains(&1) && channels.contains(&2),
        "both recorded channels should be decoded from the block table, got {channels:?}"
    );

    // 6. The two implementations agree on the packed timestamp encoding, and neither invents a
    //    timezone.
    for rec in &parse_result.recordings {
        assert_eq!(rec.time.raw.format, "DAHUA_PACKED_BASE2000_LE");
        assert_ne!(
            rec.time.raw.value, 0,
            "the packed field was read from the entry"
        );
        let native = rec
            .time
            .recorder_native
            .as_ref()
            .expect("the generator's packed timestamp must decode")
            .iso_8601
            .clone();
        assert!(
            native.starts_with("20"),
            "the base-2000 year must decode into this century: {native}"
        );
        assert_eq!(
            rec.time.timezone,
            TimeZoneState::Unknown,
            "the recorder records no timezone, so none may be claimed"
        );
    }
}
