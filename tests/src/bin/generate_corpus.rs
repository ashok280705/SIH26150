//! Regenerates the synthetic validation-corpus manifests under `validation_corpus/`.
//!
//! Expectations are per **(OEM, shape)**, not per shape alone. They used to be shape-only, which
//! worked while every parser was a magic-byte comparison at offset 0: every OEM then behaved
//! identically on a given adversarial shape. It stops being true as soon as a parser reads a real
//! structure set, because what an 8 KiB adversarial fixture *contains* differs per format — a
//! Hikvision identifier lives at boot+16 inside a boot structure with live pointers, and a small
//! fixture cannot carry a coherent one.
//!
//! So the Hikvision rows below record the honest outcome of the real parser, and the note on each
//! case says why. Cases that exercise the whole Hikvision production path live in
//! `tests/tests/hikvision_production_chain.rs` against
//! [`forensic_tests::hikvision_fixtures`], which builds a complete volume.

use forensic_core::Hash;
use forensic_core::Region;
use forensic_tests::corpus::{CorpusCase, CorpusLoader};
use forensic_tests::fixtures::{generate_fixture, FixtureShape, OemShape};
use std::path::PathBuf;

/// What the whole corpus expects of a parser whose recognition is a magic comparison.
fn default_validation_state(shape: FixtureShape) -> &'static str {
    match shape {
        FixtureShape::Normal => "pass",
        FixtureShape::Sparse
        | FixtureShape::Truncated
        | FixtureShape::Fragmented
        | FixtureShape::OverlappingSignature
        | FixtureShape::WrongOffset
        | FixtureShape::Overwritten
        | FixtureShape::Corrupted
        | FixtureShape::Partial
        | FixtureShape::MissingFrame
        | FixtureShape::Deleted
        | FixtureShape::UnknownModel
        | FixtureShape::UnknownFirmware => "review",

        FixtureShape::LoneMagic
        | FixtureShape::KnownNegative
        | FixtureShape::FalsePositive
        | FixtureShape::Orphaned => "unknown",
    }
}

/// The expectation for one case: validation state, detection status, and why.
struct Expectation {
    validation: &'static str,
    detection_status: &'static str,
    classification: &'static str,
    attribution: &'static str,
    /// Region the detector should nominate, if any.
    regions: Vec<Region>,
    note: Option<&'static str>,
}

fn expectation(oem: OemShape, shape: FixtureShape) -> Expectation {
    // The Hikvision parser reads a real boot structure, HIKBTREE and block footers. Any shape
    // that damages or displaces the identifier field at boot+16 means the structure set does not
    // apply, which is `unknown` rather than `review`: "this is not a Hikvision volume" is a
    // different finding from "this is a damaged Hikvision volume".
    if oem == OemShape::Hikvision {
        let boot_region = vec![Region::new(512, 512).unwrap()];
        return match shape {
            FixtureShape::Normal => Expectation {
                validation: "review",
                detection_status: "insufficient",
                classification: "insufficient",
                attribution: "insufficient",
                regions: boot_region,
                note: Some(
                    "the filesystem identifier is present at boot+16 but this 8 KiB detection \
                     fixture carries no coherent boot geometry or HIKBTREE, so the identifier \
                     stands alone",
                ),
            },
            FixtureShape::LoneMagic => Expectation {
                validation: "review",
                detection_status: "insufficient",
                classification: "insufficient",
                attribution: "insufficient",
                regions: boot_region,
                note: Some(
                    "a lone identifier: present, but no tree pointer and no video start could be \
                     established, so the boot structure is reported malformed and detection is \
                     Insufficient rather than Confirmed",
                ),
            },
            FixtureShape::Corrupted => Expectation {
                validation: "unknown",
                detection_status: "not_detected",
                classification: "unresolved",
                attribution: "unresolved",
                regions: Vec::new(),
                note: Some(
                    "the scrambled index area overwrites the identifier field at boot+16, so the \
                     Hikvision structure set does not apply",
                ),
            },
            FixtureShape::Deleted => Expectation {
                validation: "unknown",
                detection_status: "not_detected",
                classification: "unresolved",
                attribution: "unresolved",
                regions: Vec::new(),
                note: Some("the deleted marker overwrites the first byte of the identifier field"),
            },
            FixtureShape::Overwritten => Expectation {
                validation: "unknown",
                detection_status: "not_detected",
                classification: "unresolved",
                attribution: "unresolved",
                regions: Vec::new(),
                note: Some("the overwritten structure area covers the identifier field"),
            },
            FixtureShape::WrongOffset => Expectation {
                validation: "unknown",
                detection_status: "not_detected",
                classification: "unresolved",
                attribution: "unresolved",
                regions: Vec::new(),
                note: Some(
                    "the identifier sits at 777, which is not a declared boot position plus the \
                     identifier offset; an identifier at the wrong offset is not a Hikvision volume",
                ),
            },
            other => Expectation {
                validation: default_validation_state(other),
                detection_status: "confirmed",
                classification: "confirmed",
                attribution: "confirmed",
                regions: boot_region,
                note: None,
            },
        };
    }

    Expectation {
        validation: default_validation_state(shape),
        detection_status: "confirmed",
        classification: "confirmed",
        attribution: "confirmed",
        regions: vec![Region::new(0, 512).unwrap()],
        note: None,
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
            let case_id = format!(
                "SYNTH-{}-{}-001",
                oem.name().to_uppercase(),
                shape.name().to_uppercase()
            );
            let e = expectation(oem, shape);

            // Dummy hash for synthetic bytes.
            let source_hash = Hash::sha256(vec![0; 32]);

            let case = CorpusCase {
                case_id: case_id.clone(),
                source_path: format!("synthetic_{}_{}_1.raw", oem.name(), shape.name()),
                source_hash,
                source_type: "raw".to_string(),
                expected_detection: oem_name(oem).to_string(),
                expected_detection_status: e.detection_status.to_string(),
                expected_classification: e.classification.to_string(),
                expected_attribution_status: e.attribution.to_string(),
                expected_regions: e.regions,
                expected_parser_state: "parsed".to_string(),
                expected_recovery_state: "l1_carving_available".to_string(),
                expected_validation_state: e.validation.to_string(),
                expected_warnings: e.note.map(|n| vec![n.to_string()]).unwrap_or_default(),
                synthetic: true,
            };

            CorpusLoader::save_case(&out_dir, &case).unwrap();
            generated_count += 1;
        }
    }

    println!("Generated {generated_count} synthetic corpus cases.");
}
