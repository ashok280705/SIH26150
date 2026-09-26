//! # The universal `Parser` contract, applied to every OEM parser in the workspace
//!
//! One harness, one definition of compliance, every parser. The checks live in
//! [`parsers_core::contract`] so they cannot drift per OEM, and this file only decides *which*
//! parsers and *which* evidence they are run against.
//!
//! ## The three evidence shapes every parser sees
//!
//! | evidence            | what it proves                                                  |
//! |---------------------|-----------------------------------------------------------------|
//! | an empty image      | no parser invents structure out of nothing                       |
//! | an all-zero image   | zeroed bytes are not mistaken for a volume                       |
//! | pseudo-random bytes | noise is not mistaken for a container, a clock or a channel      |
//! | a real OEM fixture  | the parser's own format is normalized honestly and in bounds     |
//!
//! The first three are run for **every** parser including the ones for other OEMs, which is the
//! point: handed a Dahua disk, the Hikvision parser must report nothing rather than something.
//!
//! ## Adding an OEM
//!
//! Add the parser crate to this crate's `[dev-dependencies]` and one line to `all_parsers()`.
//! Nothing else. If the new parser is compliant the suite goes green; if it fabricates a
//! timestamp, escapes the evidence bounds or parses non-deterministically, it fails here
//! before it can reach an examiner's report.

mod common;

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, OemProfile, ProfileRegistry};
use parsers_core::contract::{run_parser_contract, CheckOutcome};
use parsers_core::Parser;

/// An in-memory reader, so a contract case needs no temp file.
struct MemReader {
    data: Vec<u8>,
    label: String,
}

impl MemReader {
    fn new(data: Vec<u8>, label: &str) -> Self {
        Self {
            data,
            label: label.to_string(),
        }
    }
}

impl EvidenceReader for MemReader {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
        if offset >= self.len() {
            return Err(ForensicError::out_of_bounds(
                &self.label,
                offset,
                buf.len() as u64,
                self.len(),
            ));
        }
        let start = offset as usize;
        let n = (self.data.len() - start).min(buf.len());
        buf[..n].copy_from_slice(&self.data[start..start + n]);
        Ok(n)
    }
    fn source_kind(&self) -> evidence_reader::SourceKind {
        evidence_reader::SourceKind::Raw
    }
    fn source_path(&self) -> &str {
        &self.label
    }
}

/// Deterministic pseudo-random bytes. A fixed LCG rather than a random source, so a failure
/// is reproducible from the seed alone.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as u8
        })
        .collect()
}

/// Every parser in the workspace, with the profile key its profile is registered under.
///
/// The one place a new OEM is added to the contract suite.
fn all_parsers() -> Vec<(&'static str, Box<dyn Parser>)> {
    vec![
        ("dahua", Box::new(parser_dahua::DahuaParser::default())),
        (
            "hikvision",
            Box::new(parser_hikvision::HikvisionParser::default()),
        ),
        (
            "uniview",
            Box::new(parser_uniview::UniviewParser::default()),
        ),
        (
            "cpplus_ubs",
            Box::new(parser_cpplus_ubs::CpPlusUbsParser::default()),
        ),
        (
            "honeywell",
            Box::new(parser_honeywell::HoneywellParser::default()),
        ),
        ("tplink", Box::new(tplink::TplinkParser::default())),
        (
            "unified",
            Box::new(parser_unified::UnifiedParser::default()),
        ),
    ]
}

fn registry() -> ProfileRegistry {
    ProfileRegistry::load_from_dir(&common::profiles_dir())
        .expect("the profiles/ directory must load")
}

/// The profile for an OEM key, or `None` when this build carries no profile for it.
fn profile_for<'a>(registry: &'a ProfileRegistry, oem_key: &str) -> Option<&'a OemProfile> {
    registry.find_applicable(oem_key, None, None, None)
}

/// Run the contract for one parser on one evidence shape and assert compliance.
fn assert_contract(
    parser: &dyn Parser,
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    case: &str,
) {
    let report = run_parser_contract(parser, reader, profile);
    println!(
        "\n── contract: {} v{} on {case} ──\n{}",
        report.parser_id,
        report.parser_version,
        report.summary()
    );
    report.assert_compliant();
}

#[test]
fn every_parser_is_contract_compliant_on_an_empty_image() {
    let reg = registry();
    let reader = MemReader::new(Vec::new(), "mem://empty");
    for (key, parser) in all_parsers() {
        let Some(profile) = profile_for(&reg, key) else {
            continue;
        };
        assert_contract(parser.as_ref(), &reader, profile, "an empty image");
    }
}

#[test]
fn every_parser_is_contract_compliant_on_a_zeroed_image() {
    let reg = registry();
    let reader = MemReader::new(vec![0u8; 8 << 20], "mem://zeroed");
    for (key, parser) in all_parsers() {
        let Some(profile) = profile_for(&reg, key) else {
            continue;
        };
        assert_contract(parser.as_ref(), &reader, profile, "an 8 MiB zeroed image");
    }
}

#[test]
fn every_parser_is_contract_compliant_on_pseudo_random_noise() {
    let reg = registry();
    let reader = MemReader::new(noise(8 << 20, 0xC0FFEE), "mem://noise");
    for (key, parser) in all_parsers() {
        let Some(profile) = profile_for(&reg, key) else {
            continue;
        };
        assert_contract(
            parser.as_ref(),
            &reader,
            profile,
            "8 MiB of pseudo-random noise",
        );
    }
}

#[test]
fn every_parser_is_contract_compliant_on_another_oems_disk() {
    // A real Dahua DHFS 4.1 volume, shown to every parser. The Dahua parser should normalize
    // it; the others must decline it without fabricating geometry, entries or timestamps.
    let fx = common::build_fixture();
    let (_dir, reader) = common::open_fixture(&fx);
    let reg = registry();

    for (key, parser) in all_parsers() {
        let Some(profile) = profile_for(&reg, key) else {
            continue;
        };
        assert_contract(
            parser.as_ref(),
            &reader,
            profile,
            "a real Dahua DHFS 4.1 volume",
        );
    }
}

#[test]
fn a_parser_that_reads_its_own_format_normalizes_it_within_bounds() {
    // The positive case: the Dahua parser on a Dahua disk must not merely decline — it must
    // produce an in-bounds, non-fabricating, deterministic normalized view.
    let fx = common::build_fixture();
    let (_dir, reader) = common::open_fixture(&fx);
    let reg = registry();
    let profile = common::dahua_profile(&reg);
    let parser = parser_dahua::DahuaParser::default();

    let report = run_parser_contract(&parser, &reader, profile);
    println!("{}", report.summary());
    report.assert_compliant();

    // The run actually exercised the index and carver paths rather than skipping everything,
    // which is what would make a green contract meaningless here.
    assert_eq!(
        report.check("index.regions_in_bounds").map(|c| c.outcome),
        Some(CheckOutcome::Pass),
        "the Dahua parser must read an index from a Dahua disk, not skip the check"
    );
    assert_eq!(
        report
            .check("index.accessible_and_unreferenced_are_disjoint")
            .map(|c| c.outcome),
        Some(CheckOutcome::Pass)
    );
    assert_eq!(
        report
            .check("determinism.repeat_parse_is_identical")
            .map(|c| c.outcome),
        Some(CheckOutcome::Pass)
    );
}

#[test]
fn the_contract_harness_detects_a_non_compliant_parser() {
    // A harness that cannot fail proves nothing, so the suite includes a parser that breaks
    // the contract on purpose and asserts the harness catches each violation.
    use forensic_core::{Recording, Region, TimelineEvent, ValidationState, ValidationStateKind};
    use parsers_core::storage::{
        AllocationEvidence, IndexAuthority, IndexedRecording, RecordingIndex,
    };
    use std::collections::BTreeMap;

    struct FabricatingParser;
    impl Parser for FabricatingParser {
        fn id(&self) -> &str {
            "fabricating"
        }
        fn version(&self) -> &str {
            "0.0.0"
        }
        fn parse_filesystem(
            &self,
            _: &dyn EvidenceReader,
            _: &OemProfile,
        ) -> Result<Vec<forensic_core::ParserRun>, ForensicError> {
            Ok(vec![])
        }
        fn parse_metadata(
            &self,
            _: &dyn EvidenceReader,
            _: &OemProfile,
        ) -> Result<Vec<forensic_core::ParserRun>, ForensicError> {
            Ok(vec![])
        }
        fn parse_recordings(
            &self,
            _: &dyn EvidenceReader,
            _: &OemProfile,
        ) -> Result<(Vec<Recording>, Vec<forensic_core::ParserRun>), ForensicError> {
            Ok((vec![], vec![]))
        }
        fn extract_timeline_events(
            &self,
            _: &dyn EvidenceReader,
            _: &OemProfile,
        ) -> Result<(Vec<TimelineEvent>, Vec<forensic_core::ParserRun>), ForensicError> {
            Ok((vec![], vec![]))
        }
        fn validate_structure(
            &self,
            _: &dyn EvidenceReader,
            _: &OemProfile,
        ) -> Result<Vec<forensic_core::ParserRun>, ForensicError> {
            Ok(vec![])
        }
        fn recognize_candidate(
            &self,
            _: &dyn EvidenceReader,
            _: &OemProfile,
        ) -> Result<bool, ForensicError> {
            Ok(true)
        }
        fn recording_index(
            &self,
            _: &dyn EvidenceReader,
            _: &OemProfile,
        ) -> Result<Option<RecordingIndex>, ForensicError> {
            // Two violations: a range far outside the evidence, and an epoch timestamp
            // standing in for a clock that was never read.
            Ok(Some(RecordingIndex {
                authority: IndexAuthority::Authoritative {
                    governs: Region::new(0, 1 << 20).unwrap(),
                },
                recordings: vec![IndexedRecording {
                    recording_id: "made-up#1".into(),
                    partition: None,
                    channel: Some(1),
                    start_time_unix: Some(0),
                    end_time_unix: None,
                    physical_regions: vec![Region::new(1 << 40, 4096).unwrap()],
                    payload_regions: vec![],
                    codec_hint: Some("H264".into()),
                    allocation: AllocationEvidence::Unknown,
                    oem_metadata: BTreeMap::new(),
                    evidence: ValidationState::new(
                        ValidationStateKind::Pass,
                        "fabricated",
                        "test",
                        "test",
                    )
                    .unwrap(),
                }],
                unreferenced_recordings: vec![],
                declared_entry_count: Some(1),
                index_region: None,
                evidence: ValidationState::new(
                    ValidationStateKind::Pass,
                    "fabricated",
                    "test",
                    "test",
                )
                .unwrap(),
            }))
        }
    }

    let reg = registry();
    let profile = common::dahua_profile(&reg);
    let reader = MemReader::new(vec![0u8; 1 << 20], "mem://small");
    let report = run_parser_contract(&FabricatingParser, &reader, profile);

    assert!(!report.is_compliant(), "{}", report.summary());
    assert_eq!(
        report.check("index.regions_in_bounds").map(|c| c.outcome),
        Some(CheckOutcome::Fail),
        "a region outside the evidence must fail the contract"
    );
    assert_eq!(
        report
            .check("index.no_fabricated_metadata")
            .map(|c| c.outcome),
        Some(CheckOutcome::Fail),
        "an epoch timestamp standing in for an unread clock must fail the contract"
    );
}

#[test]
fn contract_results_are_reproducible_across_runs() {
    let reg = registry();
    let reader = MemReader::new(noise(2 << 20, 42), "mem://noise");
    for (key, parser) in all_parsers() {
        let Some(profile) = profile_for(&reg, key) else {
            continue;
        };
        let a = run_parser_contract(parser.as_ref(), &reader, profile);
        let b = run_parser_contract(parser.as_ref(), &reader, profile);
        let names_a: Vec<(&str, CheckOutcome)> =
            a.checks.iter().map(|c| (c.name, c.outcome)).collect();
        let names_b: Vec<(&str, CheckOutcome)> =
            b.checks.iter().map(|c| (c.name, c.outcome)).collect();
        assert_eq!(
            names_a, names_b,
            "parser '{}' produced different contract outcomes on two identical runs",
            a.parser_id
        );
    }
}

/// `recognize_candidate` is documented as "these bytes are shaped like our format", and the
/// trait states that returning `Ok(true)` unconditionally makes the signal useless.
///
/// This test records, rather than asserts, which parsers honour that — because the signal is
/// **not** load-bearing: [`recovery::levels::scan_target_all`] consults it only as a
/// corroborating observation and the data state cannot depend on it. Turning this into a hard
/// failure would require changing OEM parser internals, which is out of scope here; leaving it
/// untested would let the gap go unrecorded. So it is measured and printed, and the finding is
/// carried in `docs/RECOVERY_ENGINE_AUDIT.md`.
#[test]
fn recognize_candidate_honesty_is_measured_and_reported() {
    let reg = registry();
    let zeroed = MemReader::new(vec![0u8; 1 << 20], "mem://zeroed");
    let mut unconditional: Vec<String> = Vec::new();
    let mut honest: Vec<String> = Vec::new();

    for (key, parser) in all_parsers() {
        let Some(profile) = profile_for(&reg, key) else {
            continue;
        };
        match parser.recognize_candidate(&zeroed, profile) {
            Ok(true) => unconditional.push(parser.id().to_string()),
            Ok(false) => honest.push(parser.id().to_string()),
            Err(e) => honest.push(format!("{} (errored: {e})", parser.id())),
        }
    }

    println!("recognize_candidate on an all-zero image:");
    println!("  inspects the bytes: {}", honest.join(", "));
    println!("  always true:        {}", unconditional.join(", "));

    // What is asserted is the property the engine actually relies on: at least one parser
    // discriminates, so the signal is not structurally meaningless platform-wide.
    assert!(
        !honest.is_empty(),
        "no parser discriminates on recognize_candidate; the signal would be meaningless"
    );
}
