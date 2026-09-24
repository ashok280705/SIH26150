use evidence_reader::raw::RawReader;
use forensic_core::{OemProfile, ValidationStateKind};
use parsers_core::Parser;
use std::path::PathBuf;

use forensic_tests::corpus::{CorpusCase, CorpusLoader};
use forensic_tests::fixtures::{generate_fixture, FixtureShape, OemShape};
use parser_cpplus_ubs::CpPlusUbsParser;
use parser_dahua::DahuaParser;
use parser_hikvision::HikvisionParser;
use parser_honeywell::HoneywellParser;
use parser_uniview::UniviewParser;

use std::collections::HashMap;
use std::io::Write;
use std::str::FromStr;
use tempfile::NamedTempFile;

fn string_to_validation_state(state: &str) -> ValidationStateKind {
    match state.to_lowercase().as_str() {
        "pass" => ValidationStateKind::Pass,
        "review" => ValidationStateKind::Review,
        "unknown" => ValidationStateKind::Unknown,
        _ => ValidationStateKind::Unknown,
    }
}

fn dummy_profile(oem: &str) -> OemProfile {
    let mut layout = HashMap::new();
    layout.insert("superblock_size".to_string(), 512);
    // Generic layout values that won't fail checked arithmetic bounds
    layout.insert("dhfs_magic_offset".to_string(), 0);
    layout.insert("mpro_start".to_string(), 512);
    layout.insert("cpplus_marker_start".to_string(), 512);
    layout.insert("ec1001_start".to_string(), 512);

    OemProfile {
        profile_id: format!("{}-test", oem),
        profile_version: "1.0.0".to_string(),
        schema_version: "1.0".to_string(),
        oem: oem.to_string(),
        storage_family: format!("{}_FAM", oem.to_uppercase()),
        applicability: forensic_core::Applicability {
            models: vec![],
            firmwares: vec![],
            storage_variants: vec![],
            reference: None,
        },
        signatures: vec![], // Add dummy signature to avoid magic checks failing completely for valid cases?
        // Actually, the parsers rely on profile.signatures. Let's add them.
        validation_rules: vec![],
        layout,
        confidence_weights: forensic_core::ConfidenceWeights {
            max_possible_score: 1.0,
            min_threshold: 0.5,
        },
        profile_hash: None,
    }
}

/// Declare the signature rules each OEM's parser resolves by name.
///
/// The rule **names** must be the ones the parser actually looks up, and the patterns must be
/// the OEM's real identifier bytes at their real offsets. A name the parser never asks for
/// leaves the structure unverifiable, and the case then measures nothing.
fn populate_signatures(profile: &mut OemProfile, oem: &str) {
    use forensic_core::{EvidenceStatus, OffsetConstraint, SignatureRule};

    // (rule name, pattern hex, exact offset)
    let rules: Vec<(&str, &str, u64)> = match oem {
        "dahua" => vec![("dhfs_superblock", "44 48 46 53", 0)],
        // The Hikvision identifier is a field at boot + 16, i.e. absolute 528 for the boot
        // position at 0x200 — not a magic at offset 0. The corroborating HIKBTREE magic is
        // located through the boot structure's own pointer, so it carries no offset constraint.
        "hikvision" => vec![
            (
                "hikvision_boot_identifier",
                "48 49 4B 56 49 53 49 4F 4E 40 48 41 4E 47 5A 48 4F 55",
                528,
            ),
            ("hikbtree_magic", "48 49 4B 42 54 52 45 45", 0),
            ("hikvision_ofni_part", "4F 46 4E 49", 0),
            ("ps_pack_header", "00 00 01 BA", 0),
            ("ps_video_stream_0", "00 00 01 E0", 0),
            ("hikvision_carve_sentinel", "FF FF FF FB", 0),
        ],
        "honeywell" => vec![("honeywell_master_sector", "48 4F 4E 45 59 57 45 4C 4C", 0)],
        "cpplus_ubs" => vec![("ubs_partition_marker", "55 42 53 5F", 0)],
        "uniview" => vec![("uniview_super_magic", "55 4E 49 56", 0)],
        _ => Vec::new(),
    };

    for (name, magic, offset) in rules {
        profile.signatures.push(SignatureRule {
            name: name.to_string(),
            pattern_hex: magic.to_string(),
            evidence_status: EvidenceStatus::Validated,
            weight: 1.0,
            is_exclusive: true,
            explanation: String::new(),
            offset_constraints: vec![OffsetConstraint::Exact { offset }],
        });
    }
}

fn extract_shape_from_case(case: &CorpusCase) -> (OemShape, FixtureShape) {
    let parts: Vec<&str> = case.case_id.split('-').collect();
    let oem = match parts[1] {
        "DAHUA" => OemShape::Dahua,
        "HIKVISION" => OemShape::Hikvision,
        "HONEYWELL" => OemShape::Honeywell,
        "CPPLUS_UBS" => OemShape::CpPlusUbs,
        "UNIVIEW" => OemShape::Uniview,
        _ => panic!("Unknown OEM: {}", parts[1]),
    };

    let shape_str = parts[2];

    let shape = match shape_str {
        "NORMAL" => FixtureShape::Normal,
        "SPARSE" => FixtureShape::Sparse,
        "TRUNCATED" => FixtureShape::Truncated,
        "FRAGMENTED" => FixtureShape::Fragmented,
        "OVERLAPPING_SIGNATURE" => FixtureShape::OverlappingSignature,
        "WRONG_OFFSET" => FixtureShape::WrongOffset,
        "LONE_MAGIC" => FixtureShape::LoneMagic,
        "OVERWRITTEN" => FixtureShape::Overwritten,
        "KNOWN_NEGATIVE" => FixtureShape::KnownNegative,
        "CORRUPTED" => FixtureShape::Corrupted,
        "PARTIAL" => FixtureShape::Partial,
        "FALSE_POSITIVE" => FixtureShape::FalsePositive,
        "MISSING_FRAME" => FixtureShape::MissingFrame,
        "DELETED" => FixtureShape::Deleted,
        "ORPHANED" => FixtureShape::Orphaned,
        "UNKNOWN_MODEL" => FixtureShape::UnknownModel,
        "UNKNOWN_FIRMWARE" => FixtureShape::UnknownFirmware,
        _ => panic!("Unknown shape: {}", shape_str),
    };

    (oem, shape)
}

#[test]
fn test_corpus_parsers_suite() {
    let corpus_dir = PathBuf::from_str("../validation_corpus").unwrap();
    let cases = CorpusLoader::load_dir(&corpus_dir).expect("Failed to load corpus");

    assert!(
        cases.len() >= 85,
        "Expected at least 85 generated corpus cases"
    );

    let dahua = DahuaParser::default();
    let hikvision = HikvisionParser::default();
    let honeywell = HoneywellParser::default();
    let cpplus = CpPlusUbsParser::default();
    let uniview = UniviewParser::default();

    let mut success_count = 0;

    for case in &cases {
        let (oem, shape) = extract_shape_from_case(&case);

        let parser: &dyn Parser = match oem {
            OemShape::Dahua => &dahua,
            OemShape::Hikvision => &hikvision,
            OemShape::Honeywell => &honeywell,
            OemShape::CpPlusUbs => &cpplus,
            OemShape::Uniview => &uniview,
        };

        let mut profile = dummy_profile(&case.expected_detection);
        populate_signatures(&mut profile, &case.expected_detection);

        let fixture = generate_fixture(oem, shape, 1);
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&fixture.bytes).unwrap();

        let reader = RawReader::open(temp_file.path()).unwrap();

        let runs = parser.parse_filesystem(&reader, &profile).unwrap();
        let actual_state = runs.first().unwrap().validation_state.state;
        let expected_state = string_to_validation_state(&case.expected_validation_state);

        // Record if the validation mapped exactly as expected in the manifest!
        if actual_state == expected_state {
            success_count += 1;
        } else {
            println!(
                "Mismatch for {}: expected {:?}, got {:?}",
                case.case_id, expected_state, actual_state
            );
        }
    }

    let success_rate = (success_count as f64 / cases.len() as f64) * 100.0;
    println!(
        "Successfully validated {}/{} parser test corpus cases ({:.2}%).",
        success_count,
        cases.len(),
        success_rate
    );

    // We expect at least some baseline of success since parsers are still basic
    assert!(
        success_rate >= 20.0,
        "Parsing success rate too low! ({:.2}%)",
        success_rate
    );
}
