use evidence_reader::raw::RawReader;
use forensic_core::{
    ConfidenceWeights, EvidenceStatus, Hash, OemProfile, OffsetConstraint, SignatureRule,
    ValidationStateKind,
};
use forensic_tests::fixtures::{generate_fixture, FixtureShape, OemShape};
use parser_honeywell::HoneywellParser;
use parsers_core::Parser;
use std::collections::HashMap;
use std::io::Write;
use tempfile::NamedTempFile;

fn mock_honeywell_profile() -> OemProfile {
    let mut layout = HashMap::new();
    layout.insert("sector_size".to_string(), 512);
    layout.insert("mpro_start".to_string(), 512);

    OemProfile {
        profile_id: "honeywell-maxpro-v1.0".to_string(),
        profile_version: "1.0.0".to_string(),
        schema_version: "1.0".to_string(),
        oem: "honeywell".to_string(),
        storage_family: "MAXPRO_NVR".to_string(),
        applicability: forensic_core::Applicability {
            models: vec!["MAXPRO".to_string()],
            firmwares: vec![],
            storage_variants: vec!["partitioned".to_string()],
            reference: Some("Honeywell test".to_string()),
        },
        signatures: vec![SignatureRule {
            name: "honeywell_header_magic".to_string(),
            pattern_hex: "48 4F 4E 45 59 57 45 4C 4C".to_string(), // HONEYWELL
            evidence_status: EvidenceStatus::Validated,
            weight: 0.90,
            is_exclusive: true,
            explanation: "Superblock magic".to_string(),
            offset_constraints: vec![OffsetConstraint::Exact { offset: 0 }],
        }],
        validation_rules: vec![],
        layout,
        confidence_weights: ConfidenceWeights {
            max_possible_score: 1.30,
            min_threshold: 0.70,
        },
        profile_hash: Some(Hash::sha256(vec![0; 32])),
    }
}

fn fixture_reader(shape: FixtureShape) -> (RawReader, NamedTempFile) {
    let fixture = generate_fixture(OemShape::Honeywell, shape, 42);
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(&fixture.bytes).unwrap();
    let reader = RawReader::open(file.path()).unwrap();
    (reader, file)
}

#[test]
fn test_honeywell_parser_normal_fixture() {
    let parser = HoneywellParser::default();
    let (reader, _file) = fixture_reader(FixtureShape::Normal);
    let profile = mock_honeywell_profile();

    // Parse filesystem
    let runs = parser.parse_filesystem(&reader, &profile).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].operation_name, "parse_filesystem");

    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Pass);
    assert!(runs[0]
        .validation_state
        .reason
        .contains("HONEYWELL Superblock Found"));

    // Parse metadata
    let metadata_runs = parser.parse_metadata(&reader, &profile).unwrap();
    assert_eq!(metadata_runs.len(), 1);
    assert_eq!(
        metadata_runs[0].validation_state.state,
        ValidationStateKind::Unknown
    ); // Missing in fixtures

    // Parse recordings
    let (_recordings, rec_runs) = parser.parse_recordings(&reader, &profile).unwrap();
    assert_eq!(rec_runs.len(), 1);

    assert_eq!(
        rec_runs[0].validation_state.state,
        ValidationStateKind::Review
    );
    assert!(rec_runs[0]
        .validation_state
        .reason
        .contains("Mock MPRO segment parse complete"));
}

#[test]
fn test_honeywell_parser_adversarial_wrong_offset() {
    let parser = HoneywellParser::default();
    let (reader, _file) = fixture_reader(FixtureShape::WrongOffset);
    let profile = mock_honeywell_profile();

    let runs = parser.parse_filesystem(&reader, &profile).unwrap();
    assert_eq!(runs.len(), 1);

    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Review);
    assert!(runs[0].validation_state.reason.contains("Magic mismatch"));
}
