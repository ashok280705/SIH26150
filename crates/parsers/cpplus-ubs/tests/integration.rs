use forensic_core::{
    Hash, OemProfile, SignatureRule, OffsetConstraint, EvidenceStatus, ConfidenceWeights, ValidationStateKind
};
use parser_cpplus_ubs::CpPlusUbsParser;
use parsers_core::Parser;
use forensic_tests::fixtures::{generate_fixture, OemShape, FixtureShape};
use evidence_reader::raw::RawReader;
use std::io::Write;
use tempfile::NamedTempFile;
use std::collections::HashMap;

fn mock_cpplus_profile() -> OemProfile {
    let mut layout = HashMap::new();
    layout.insert("superblock_size".to_string(), 512);
    layout.insert("cpplus_marker_start".to_string(), 512);

    OemProfile {
        profile_id: "cpplus-ubs-v1.0".to_string(),
        profile_version: "1.0.0".to_string(),
        schema_version: "1.0".to_string(),
        oem: "cpplus_ubs".to_string(),
        storage_family: "CPPLUS_UBS".to_string(),
        applicability: forensic_core::Applicability {
            models: vec!["CP-UVR".to_string()],
            firmwares: vec![],
            storage_variants: vec!["single_disk".to_string()],
            reference: Some("CP Plus test".to_string()),
        },
        signatures: vec![
            SignatureRule {
                name: "ubs_partition_marker".to_string(),
                pattern_hex: "55 42 53 5F".to_string(), // UBS_
                evidence_status: EvidenceStatus::Provisional,
                weight: 0.70,
                is_exclusive: false,
                explanation: "UBS magic".to_string(),
                offset_constraints: vec![OffsetConstraint::Exact { offset: 0 }],
            }
        ],
        validation_rules: vec![],
        layout,
        confidence_weights: ConfidenceWeights {
            max_possible_score: 1.20,
            min_threshold: 0.60,
        },
        profile_hash: Some(Hash::sha256(vec![0; 32])),
    }
}

fn fixture_reader(shape: FixtureShape) -> (RawReader, NamedTempFile) {
    let fixture = generate_fixture(OemShape::CpPlusUbs, shape, 42);
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(&fixture.bytes).unwrap();
    let reader = RawReader::open(file.path()).unwrap();
    (reader, file)
}

#[test]
fn test_cpplus_parser_normal_fixture() {
    let parser = CpPlusUbsParser::default();
    let (reader, _file) = fixture_reader(FixtureShape::Normal);
    let profile = mock_cpplus_profile();
    
    // Parse filesystem
    let runs = parser.parse_filesystem(&reader, &profile).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].operation_name, "parse_filesystem");
    
    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Pass);
    assert!(runs[0].validation_state.reason.contains("UBS_ Superblock Found"));
    
    // Parse metadata
    let metadata_runs = parser.parse_metadata(&reader, &profile).unwrap();
    assert_eq!(metadata_runs.len(), 1);
    assert_eq!(metadata_runs[0].validation_state.state, ValidationStateKind::Unknown); // Handled gracefully
    
    // Parse recordings
    let (_recordings, rec_runs) = parser.parse_recordings(&reader, &profile).unwrap();
    assert_eq!(rec_runs.len(), 1);
    
    assert_eq!(rec_runs[0].validation_state.state, ValidationStateKind::Review);
    assert!(rec_runs[0].validation_state.reason.contains("Mock CPPLUS segment parse complete"));
}

#[test]
fn test_cpplus_parser_adversarial_wrong_offset() {
    let parser = CpPlusUbsParser::default();
    let (reader, _file) = fixture_reader(FixtureShape::WrongOffset);
    let profile = mock_cpplus_profile();
    
    let runs = parser.parse_filesystem(&reader, &profile).unwrap();
    assert_eq!(runs.len(), 1);
    
    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Review);
    assert!(runs[0].validation_state.reason.contains("Magic mismatch"));
}
