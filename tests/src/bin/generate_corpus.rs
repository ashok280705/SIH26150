use forensic_core::Region;
use forensic_core::Hash;
use forensic_tests::corpus::{CorpusCase, CorpusLoader};
use forensic_tests::fixtures::{OemShape, FixtureShape, generate_fixture};
use std::path::PathBuf;

fn expected_validation_state(shape: FixtureShape) -> &'static str {
    match shape {
        FixtureShape::Normal => "pass",
        FixtureShape::Sparse |
        FixtureShape::Truncated |
        FixtureShape::Fragmented |
        FixtureShape::OverlappingSignature |
        FixtureShape::WrongOffset |
        FixtureShape::Overwritten |
        FixtureShape::Corrupted |
        FixtureShape::Partial |
        FixtureShape::MissingFrame |
        FixtureShape::Deleted |
        FixtureShape::UnknownModel |
        FixtureShape::UnknownFirmware => "review",
        
        FixtureShape::LoneMagic |
        FixtureShape::KnownNegative |
        FixtureShape::FalsePositive |
        FixtureShape::Orphaned => "unknown",
    }
}

fn oem_name(oem: OemShape) -> &'static str {
    match oem {
        OemShape::Dahua => "dahua",
        OemShape::Hikvision => "hikvision",
        OemShape::Honeywell => "honeywell",
        OemShape::CpPlusUbs => "cpplus_ubs",
        OemShape::Uniview => "uniview",
    }
}

fn main() {
    let out_dir = PathBuf::from("validation_corpus");
    std::fs::create_dir_all(&out_dir).unwrap();

    let mut generated_count = 0;

    for &oem in OemShape::all() {
        for &shape in FixtureShape::all() {
            let _fixture = generate_fixture(oem, shape, 1);
            let case_id = format!("SYNTH-{}-{}-001", oem.name().to_uppercase(), shape.name().to_uppercase());
            
            // Dummy hash for synthetic bytes
            let source_hash = Hash::sha256(vec![0; 32]);

            let case = CorpusCase {
                case_id: case_id.clone(),
                source_path: format!("synthetic_{}_{}_1.raw", oem.name(), shape.name()),
                source_hash,
                source_type: "raw".to_string(),
                expected_detection: oem_name(oem).to_string(),
                expected_detection_status: "confirmed".to_string(),
                expected_classification: "confirmed".to_string(),
                expected_attribution_status: "confirmed".to_string(),
                expected_regions: vec![Region::new(0, 512).unwrap()],
                expected_parser_state: "parsed".to_string(),
                expected_recovery_state: "l1_carving_available".to_string(),
                expected_validation_state: expected_validation_state(shape).to_string(),
                expected_warnings: vec![],
                synthetic: true,
            };

            CorpusLoader::save_case(&out_dir, &case).unwrap();
            generated_count += 1;
        }
    }

    println!("Generated {} synthetic corpus cases.", generated_count);
}
