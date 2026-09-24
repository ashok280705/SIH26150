use evidence_reader::raw::RawReader;
use forensic_core::{
    ConfidenceWeights, EvidenceStatus, Hash, OemProfile, OffsetConstraint, SignatureRule,
    ValidationStateKind,
};
use forensic_tests::fixtures::{generate_fixture, FixtureShape, OemShape};
use parser_uniview::UniviewParser;
use parsers_core::Parser;
use std::collections::HashMap;
use std::io::Write;
use tempfile::NamedTempFile;

fn mock_uniview_profile() -> OemProfile {
    let mut layout = HashMap::new();
    layout.insert("superblock_size".to_string(), 512);
    layout.insert("ec1001_start".to_string(), 512);

    OemProfile {
        profile_id: "uniview-ubifs-v1.0".to_string(),
        profile_version: "1.0.0".to_string(),
        schema_version: "1.0".to_string(),
        oem: "uniview".to_string(),
        storage_family: "UNIVIEW_UBIFS".to_string(),
        applicability: forensic_core::Applicability {
            models: vec!["UNV-NVR".to_string()],
            firmwares: vec![],
            storage_variants: vec!["single_disk".to_string()],
            reference: Some("Uniview test".to_string()),
        },
        signatures: vec![SignatureRule {
            name: "uniview_super_magic".to_string(),
            pattern_hex: "55 4E 49 56".to_string(), // UNIV
            evidence_status: EvidenceStatus::Validated,
            weight: 0.85,
            is_exclusive: true,
            explanation: "Superblock magic".to_string(),
            offset_constraints: vec![OffsetConstraint::Exact { offset: 0 }],
        }],
        validation_rules: vec![],
        layout,
        confidence_weights: ConfidenceWeights {
            max_possible_score: 1.20,
            min_threshold: 0.65,
        },
        profile_hash: Some(Hash::sha256(vec![0; 32])),
    }
}

fn fixture_reader(shape: FixtureShape) -> (RawReader, NamedTempFile) {
    let fixture = generate_fixture(OemShape::Uniview, shape, 42);
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(&fixture.bytes).unwrap();
    let reader = RawReader::open(file.path()).unwrap();
    (reader, file)
}

#[test]
fn test_uniview_parser_normal_fixture() {
    let parser = UniviewParser::default();
    let (reader, _file) = fixture_reader(FixtureShape::Normal);
    let profile = mock_uniview_profile();

    // Parse filesystem
    let runs = parser.parse_filesystem(&reader, &profile).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Pass);
    assert!(runs[0]
        .validation_state
        .reason
        .contains("UNIV Superblock Found"));
}

#[test]
fn test_uniview_parser_adversarial_suite() {
    let parser = UniviewParser::default();
    let profile = mock_uniview_profile();

    let mut success = 0;

    for &shape in FixtureShape::all() {
        let (reader, _file) = fixture_reader(shape);

        // Property: Parse filesystem NEVER panics!
        let runs = parser.parse_filesystem(&reader, &profile).unwrap();
        let fs_state = runs[0].validation_state.state;

        // Property: Parse recordings NEVER panics!
        // It might yield an OutOfBounds io error, which is valid (and handled gracefully upstream)
        let rec_res = parser.parse_recordings(&reader, &profile);

        let mut any_review_or_error = false;
        let mut any_unknown = false;

        if fs_state == ValidationStateKind::Review {
            any_review_or_error = true;
        }
        if fs_state == ValidationStateKind::Unknown {
            any_unknown = true;
        }

        let meta_runs = parser.parse_metadata(&reader, &profile).unwrap();
        if meta_runs[0].validation_state.state == ValidationStateKind::Review {
            any_review_or_error = true;
        }

        if let Err(_) = rec_res {
            any_review_or_error = true; // e.g. OutOfBounds error
        } else if let Ok((_, runs)) = rec_res {
            if runs[0].validation_state.state == ValidationStateKind::Review {
                any_review_or_error = true;
            }
            if runs[0].validation_state.state == ValidationStateKind::Unknown {
                any_unknown = true;
            }
        }

        match shape {
            FixtureShape::Normal => {
                assert_eq!(fs_state, ValidationStateKind::Pass);
                // Normal might have review in our mock since it lacks real structures, which is fine
            }
            FixtureShape::UnknownModel | FixtureShape::UnknownFirmware => {
                assert!(any_unknown, "Expected Unknown state for {:?}", shape);
            }
            FixtureShape::LoneMagic
            | FixtureShape::FalsePositive
            | FixtureShape::KnownNegative
            | FixtureShape::Orphaned => {
                assert!(
                    any_review_or_error || any_unknown,
                    "Expected Review or Unknown for {:?}",
                    shape
                );
            }
            _ => {
                // All other corrupted, partial, truncated etc.
                assert!(
                    any_review_or_error,
                    "Expected Review or Error for {:?}",
                    shape
                );
            }
        }
        success += 1;
    }

    assert_eq!(success, FixtureShape::all().len());
}
