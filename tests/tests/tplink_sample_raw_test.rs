use evidence_reader::{EvidenceReader, RawReader};
use forensic_core::{ProfileRegistry, ValidationStateKind};
use detection::orchestrator::DetectionOrchestrator;
use detection::topology::{StorageTopologyProfiler, TopologyType};
use confidence::config::ConfidenceConfig;
use confidence::engine::ConfidenceEngine;
use confidence::result::AttributionStatus;
use parsing::orchestrator::ParsingOrchestrator;
use std::path::Path;

#[test]
fn test_tplink_sample_raw_detection_and_parsing() {
    let raw_path = if Path::new("tplink_vigi_nvr_sample.raw").exists() {
        Path::new("tplink_vigi_nvr_sample.raw").to_path_buf()
    } else {
        Path::new("../tplink_vigi_nvr_sample.raw").to_path_buf()
    };
    assert!(raw_path.exists(), "Sample raw file should exist at {:?}", raw_path);

    let reader = RawReader::open(raw_path.to_str().unwrap()).expect("Failed to open raw reader");
    assert_eq!(reader.len(), 4 * 1024 * 1024);

    // 1. Verify Topology Profiler
    let topology = StorageTopologyProfiler::profile(&reader, None).expect("Topology profiling failed");
    assert_eq!(topology.topology_type, TopologyType::Mbr);
    assert_eq!(topology.partitions.len(), 2, "Expected 2 partitions in MBR");
    assert_eq!(topology.partitions[0].partition_type, "0x82"); // Swap
    assert_eq!(topology.partitions[1].partition_type, "0x83"); // Ext4

    // 2. Load Profiles
    let profiles_dir = if Path::new("profiles").exists() {
        Path::new("profiles").to_path_buf()
    } else {
        Path::new("../profiles").to_path_buf()
    };
    let registry = ProfileRegistry::load_from_dir(&profiles_dir).expect("Failed to load profiles");
    let tplink_profile = registry.find_applicable("tplink", None, None, None).expect("TP-Link profile not found");

    // 3. Verify Detection
    let det_orchestrator = DetectionOrchestrator::new();
    let detector_outputs = det_orchestrator.run(&reader, &registry).expect("Detection failed");
    let tplink_output = detector_outputs.iter().find(|o| o.oem_key == "tplink").expect("Tplink output missing");
    assert_eq!(tplink_output.status, detection::DetectionStatus::Confirmed);

    // 4. Verify Confidence Classification
    let config = ConfidenceConfig::provisional_default();
    let classified = ConfidenceEngine::classify(&detector_outputs, &registry, &config).expect("Classification failed");
    eprintln!("Classified: oem={}, status={:?}, confidence={}, raw_score={}",
        classified.detector_output.oem_key, classified.attribution_status, classified.confidence, classified.raw_score);
    assert!(classified.confidence >= 0.50, "Expected positive confidence score");

    // 5. Verify Parsing Orchestrator
    let parsing_orchestrator = ParsingOrchestrator::new();
    let parse_result = parsing_orchestrator.run_parsing("tplink", &reader, tplink_profile).expect("Parsing failed");
    
    assert_eq!(parse_result.parser_runs.len(), 5, "Expected 5 parser stages");
    for run in &parse_result.parser_runs {
        assert_eq!(run.validation_state.state, ValidationStateKind::Pass, "Stage {} should PASS", run.operation_name);
    }

    assert!(!parse_result.recordings.is_empty(), "Should extract recordings");
    assert!(!parse_result.timeline_events.is_empty(), "Should extract timeline events");
}
