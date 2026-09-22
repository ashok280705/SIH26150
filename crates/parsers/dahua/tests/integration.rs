//! # DahuaParser integration tests over DHFS 4.1 structures
//!
//! These drive the `Parser` trait against format-accurate images built by the shared fixture
//! builders in `forensic_tests::dahua_fixtures`, plus the adversarial shapes from the generic
//! synthetic fixture generator.
//!
//! The profile used is the **real** versioned one from `profiles/dahua/`, so a profile that
//! drifts from the parser fails here rather than passing against a private copy of the offsets.

use evidence_reader::raw::RawReader;
use forensic_core::{OemProfile, ValidationStateKind};
use forensic_tests::dahua_fixtures::{self as fx, realistic};
use forensic_tests::fixtures::{generate_fixture, FixtureShape, OemShape};
use parser_dahua::DahuaParser;
use parsers_core::Parser;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

fn profile_path() -> PathBuf {
    let mut dir: PathBuf = env!("CARGO_MANIFEST_DIR").into();
    loop {
        let candidate = dir.join("profiles/dahua/dahua-dhfs-v1.0.toml");
        if candidate.is_file() {
            return candidate;
        }
        assert!(
            dir.pop(),
            "could not locate profiles/dahua/dahua-dhfs-v1.0.toml"
        );
    }
}

/// The real, versioned Dahua profile.
fn dahua_profile() -> OemProfile {
    OemProfile::from_file(Path::new(&profile_path())).expect("the shipped Dahua profile loads")
}

fn reader_for(bytes: &[u8]) -> (RawReader, NamedTempFile) {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(bytes).unwrap();
    file.flush().unwrap();
    let reader = RawReader::open(file.path()).unwrap();
    (reader, file)
}

fn fixture_reader(shape: FixtureShape) -> (RawReader, NamedTempFile) {
    let fixture = generate_fixture(OemShape::Dahua, shape, 42);
    reader_for(&fixture.bytes)
}

// ── A well-formed DHFS 4.1 volume ──────────────────────────────────────────────

#[test]
fn every_stage_reads_the_dhfs41_structure_set() {
    let image = fx::realistic_xvr_volume();
    let (reader, _f) = reader_for(&image.bytes);
    let profile = dahua_profile();
    let parser = DahuaParser::default();

    let runs = parser.parse_filesystem(&reader, &profile).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].operation_name, "parse_filesystem");
    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Pass);
    assert!(runs[0].validation_state.reason.contains("DHFS 4.1"));

    let runs = parser.parse_metadata(&reader, &profile).unwrap();
    assert!(
        runs[0].validation_state.reason.contains("block table"),
        "metadata comes from the block tables: {}",
        runs[0].validation_state.reason
    );

    let (recordings, runs) = parser.parse_recordings(&reader, &profile).unwrap();
    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Pass);
    assert_eq!(
        recordings.len(),
        3,
        "two accessible chains plus one available"
    );

    let (events, runs) = parser.extract_timeline_events(&reader, &profile).unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Pass);
    assert!(events
        .iter()
        .all(|e| e.description.contains("DHFS 4.1 partition")));

    let runs = parser.validate_structure(&reader, &profile).unwrap();
    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Pass);
    let reason = &runs[0].validation_state.reason;
    assert!(
        reason.contains("DHFS 4.1 structures consistent"),
        "{reason}"
    );
    assert!(
        reason.contains("0 malformed block entries")
            && reason.contains("0 chain(s) with damaged links"),
        "a well-formed volume has no damaged structures: {reason}"
    );
    assert!(
        reason.contains("1 chain(s) recovered from blocks no first-block traversal reached"),
        "the available chain is reported as availability, not as damage: {reason}"
    );
}

#[test]
fn a_multi_block_recording_keeps_every_block_in_chain_order() {
    let image = fx::realistic_xvr_volume();
    let (reader, _f) = reader_for(&image.bytes);
    let profile = dahua_profile();
    let (recordings, _) = DahuaParser::default()
        .parse_recordings(&reader, &profile)
        .unwrap();

    let p = image.partition(0).unwrap();
    let ch1 = recordings
        .iter()
        .find(|r| r.channel == 1)
        .expect("channel 1");
    assert_eq!(ch1.source_offsets.len(), 2, "a two-block recording");
    assert_eq!(
        ch1.source_offsets[0].offset,
        p.block(realistic::CH1_HEAD_BLOCK).unwrap().offset
    );
    assert_eq!(
        ch1.source_offsets[1].offset,
        p.block(realistic::CH1_TAIL_BLOCK).unwrap().offset
    );
    assert_eq!(
        ch1.source_offsets[1].length,
        p.block(realistic::CH1_TAIL_BLOCK)
            .unwrap()
            .claimed_length
            .unwrap(),
        "the last block's length is sectorCount * 512, not a whole block"
    );
}

#[test]
fn an_extended_channel_recorder_is_decoded_without_an_off_by_one() {
    // A 32-channel recorder uses the extended channel field, which is NOT incremented.
    let ts = fx::pack_timestamp(2026, 9, 22, 8, 0, 0);
    let blocks = vec![
        fx::BlockSpec::empty(),
        fx::BlockSpec::new(
            fx::BlockEntrySpec::occupied(1)
                .extended_channel(21)
                .span(ts, ts + 60)
                .links(1, 0, 0)
                .sector_count(64),
            fx::BlockContent::Frames(vec![fx::DhavFrameSpec::video_key(
                21, 2026, 9, 22, 8, 0, 0, 0x55,
            )
            .with_codec(fx::CODEC_H264, 15)]),
        ),
    ];
    let spec = fx::DhfsImageSpec {
        partitions: vec![fx::PartitionSpec::new(128, blocks)],
        ..Default::default()
    };
    let image = fx::build_dhfs41_image(&spec);
    let (reader, _f) = reader_for(&image.bytes);
    let profile = dahua_profile();

    let (recordings, _) = DahuaParser::default()
        .parse_recordings(&reader, &profile)
        .unwrap();
    assert_eq!(recordings.len(), 1);
    assert_eq!(
        recordings[0].channel, 21,
        "the extended channel field is used verbatim, not offset by one"
    );
}

#[test]
fn scan_region_for_candidates_reports_every_frame_at_absolute_offsets() {
    let image = fx::realistic_xvr_volume();
    let (reader, _f) = reader_for(&image.bytes);
    let profile = dahua_profile();
    let parser = DahuaParser::default();

    let whole = forensic_core::Region::new(0, image.len()).unwrap();
    let records = parser
        .scan_region_for_candidates(&reader, &profile, whole)
        .unwrap();

    let mut expected: Vec<u64> = Vec::new();
    for b in &image.partition(0).unwrap().blocks {
        expected.extend(b.frame_offsets.iter().copied());
    }
    expected.extend(image.loose_frame_offsets.iter().copied());
    expected.sort_unstable();

    let got: Vec<u64> = records.iter().map(|r| r.physical_region.offset).collect();
    assert_eq!(
        got, expected,
        "one carve of the whole image must report every frame, at absolute offsets"
    );
    assert!(records.iter().all(|r| r.payload_region.is_some()));
    assert!(records.iter().all(|r| r.channel.is_some()));
    assert!(records.iter().all(|r| r.start_time_unix.is_some()));
    assert!(records
        .iter()
        .all(|r| r.evidence.state == ValidationStateKind::Pass));
}

// ── Version-aware recognition ──────────────────────────────────────────────────

#[test]
fn an_unsupported_dhfs_variant_is_reviewed_not_parsed_as_dhfs41() {
    let mut image = fx::realistic_xvr_volume();
    image.bytes[..8].copy_from_slice(b"DHFS9.9\0");
    let (reader, _f) = reader_for(&image.bytes);
    let profile = dahua_profile();
    let parser = DahuaParser::default();

    let runs = parser.parse_filesystem(&reader, &profile).unwrap();
    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Review);
    assert!(runs[0].validation_state.reason.contains("'9.9'"));

    let (recordings, _) = parser.parse_recordings(&reader, &profile).unwrap();
    assert!(
        recordings.is_empty(),
        "no recording may be produced from a version whose layout is not established"
    );
    assert!(parser
        .storage_geometry(&reader, &profile)
        .unwrap()
        .is_none());
}

#[test]
fn a_malformed_volume_header_is_reviewed_and_nothing_behind_it_is_interpreted() {
    let mut image = fx::realistic_xvr_volume();
    // Binary garbage where the version suffix belongs.
    image.bytes[4..8].copy_from_slice(&[0x01, 0xFF, 0x7F, 0x03]);
    let (reader, _f) = reader_for(&image.bytes);
    let profile = dahua_profile();
    let parser = DahuaParser::default();

    let runs = parser.parse_filesystem(&reader, &profile).unwrap();
    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Review);
    assert!(runs[0].validation_state.reason.contains("malformed"));
    let (recordings, _) = parser.parse_recordings(&reader, &profile).unwrap();
    assert!(recordings.is_empty());
}

#[test]
fn a_volume_with_no_partition_table_is_reviewed_and_claims_nothing() {
    let mut image = fx::realistic_xvr_volume();
    let at = fx::PARTITION_TABLE_PRIMARY as usize + fx::PARTITION_TABLE_IDENTIFIER_OFFSET as usize;
    image.bytes[at..at + 8].copy_from_slice(&[0u8; 8]);
    let (reader, _f) = reader_for(&image.bytes);
    let profile = dahua_profile();
    let parser = DahuaParser::default();

    let runs = parser.validate_structure(&reader, &profile).unwrap();
    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Review);
    assert!(runs[0]
        .validation_state
        .reason
        .contains("no block table could be read"));

    let index = parser.recording_index(&reader, &profile).unwrap().unwrap();
    assert!(
        !index.authority.is_authoritative(),
        "with no block table read, absence proves nothing"
    );
    assert!(index.recordings.is_empty());
    assert!(index.unreferenced_recordings.is_empty());
}

// ── Adversarial shapes from the generic fixture generator ──────────────────────

#[test]
fn a_non_dahua_volume_is_unknown_never_a_failure_of_this_parser() {
    let (reader, _f) = fixture_reader(FixtureShape::KnownNegative);
    let profile = dahua_profile();
    let parser = DahuaParser::default();

    let runs = parser.parse_filesystem(&reader, &profile).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(
        runs[0].validation_state.state,
        ValidationStateKind::Unknown,
        "not applicable is Unknown, never Pass and never Fail"
    );
    assert!(parser
        .storage_geometry(&reader, &profile)
        .unwrap()
        .is_none());
    assert!(!parser.recognize_candidate(&reader, &profile).unwrap());
}

#[test]
fn a_magic_at_the_wrong_offset_is_not_a_dahua_volume() {
    let (reader, _f) = fixture_reader(FixtureShape::WrongOffset);
    let profile = dahua_profile();
    let runs = DahuaParser::default()
        .parse_filesystem(&reader, &profile)
        .unwrap();
    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Unknown);
    assert!(runs[0]
        .validation_state
        .reason
        .contains("no DHFS volume signature at offset 0"));
}

#[test]
fn a_lone_magic_yields_no_geometry_and_no_recordings() {
    let (reader, _f) = fixture_reader(FixtureShape::LoneMagic);
    let profile = dahua_profile();
    let parser = DahuaParser::default();
    // "DHFS" followed by zeros: family magic present, no readable version.
    let runs = parser.parse_filesystem(&reader, &profile).unwrap();
    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Review);
    let (recordings, _) = parser.parse_recordings(&reader, &profile).unwrap();
    assert!(recordings.is_empty());
}

#[test]
fn a_truncated_volume_never_panics_and_claims_nothing() {
    let image = fx::realistic_xvr_volume();
    let profile = dahua_profile();
    let parser = DahuaParser::default();
    // Every truncation point from "nothing" to "past the partition table".
    for cut in [0usize, 4, 8, 512, 0x3C00, 0x3C00 + 300, 0x3E00, 0x10000] {
        let cut = cut.min(image.bytes.len());
        let (reader, _f) = reader_for(&image.bytes[..cut]);
        // None of these may panic, and none may claim a recording.
        let _ = parser.parse_filesystem(&reader, &profile);
        let _ = parser.validate_structure(&reader, &profile);
        let (recordings, _) = parser
            .parse_recordings(&reader, &profile)
            .unwrap_or_default();
        assert!(
            recordings.is_empty(),
            "a volume truncated at {cut} bytes cannot support a recording claim"
        );
        let _ = parser.recognize_candidate(&reader, &profile);
    }
}

#[test]
fn an_empty_volume_is_handled_without_error() {
    let (reader, _f) = reader_for(&[]);
    let profile = dahua_profile();
    let parser = DahuaParser::default();
    let runs = parser.parse_filesystem(&reader, &profile).unwrap();
    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Unknown);
    assert!(parser.recording_index(&reader, &profile).unwrap().is_some());
}
