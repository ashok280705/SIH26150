//! # Hikvision parser integration tests
//!
//! These drive the parser over **format-accurate** synthetic volumes built from the documented
//! on-disk layout, through a real `RawReader` on a temp file, using the **real shipped profile**
//! rather than a hand-written stub. Loading the shipped profile is deliberate: it means a profile
//! that drifts from the parser fails here instead of passing against a private copy of the
//! offsets.
//!
//! The mock this file replaces asserted on the strings "HIK_ Superblock Found" and
//! "Mock HKSEG index parse complete". Neither the strings nor the structures behind them existed
//! in any real Hikvision volume.

use std::io::Write;
use std::path::{Path, PathBuf};

use evidence_reader::raw::RawReader;
use forensic_core::{OemProfile, ValidationStateKind};
use forensic_tests::hikvision_fixtures::{
    build_hikvision_image, minimal_volume, multi_block_recording_volume, no_index_volume,
    realistic_dvr_volume, FixtureCodec, FooterMode, HikBlockSpec, HikClipSpec, HikEntrySpec,
    HikPageSpec, HikTreeSpec, HikvisionImage, HikvisionImageSpec, LooseClipSpec,
};
use parser_hikvision::{HikCodec, HikvisionParser, TreeIntegrity};
use parsers_core::storage::{AllocationEvidence, IndexAuthority};
use parsers_core::Parser;
use tempfile::NamedTempFile;

/// Load the real shipped Hikvision profile by walking up from the crate directory.
fn shipped_profile() -> OemProfile {
    let mut dir: PathBuf = env!("CARGO_MANIFEST_DIR").into();
    loop {
        let candidate = dir.join("profiles/hikvision/hikvision-hik-v1.0.toml");
        if candidate.is_file() {
            return OemProfile::from_file(Path::new(&candidate))
                .expect("the shipped Hikvision profile must load");
        }
        assert!(dir.pop(), "could not locate the shipped Hikvision profile");
    }
}

/// Write an image to a temp file and open it through the production `RawReader`.
fn reader_for(image: &HikvisionImage) -> (RawReader, NamedTempFile) {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(&image.bytes).unwrap();
    file.flush().unwrap();
    let reader = RawReader::open(file.path()).unwrap();
    (reader, file)
}

// ── Filesystem recognition ───────────────────────────────────────────────────────

#[test]
fn a_real_hikvision_volume_is_recognised_by_parse_filesystem() {
    let parser = HikvisionParser::default();
    let profile = shipped_profile();
    let image = minimal_volume();
    let (reader, _f) = reader_for(&image);

    let runs = parser.parse_filesystem(&reader, &profile).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].operation_name, "parse_filesystem");
    // A clean minimal volume passes; the reason names the real structures, never "HIK_".
    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Pass);
    let reason = &runs[0].validation_state.reason;
    assert!(
        !reason.contains("HIK_"),
        "the fictional tag must be gone: {reason}"
    );
    assert!(
        !reason.contains("HKSEG"),
        "the fictional segment must be gone: {reason}"
    );
}

#[test]
fn a_non_hikvision_image_is_not_recognised() {
    let parser = HikvisionParser::default();
    let profile = shipped_profile();
    // Random non-Hikvision bytes through a real reader.
    let bytes: Vec<u8> = (0..(1u32 << 16))
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(&bytes).unwrap();
    file.flush().unwrap();
    let reader = RawReader::open(file.path()).unwrap();

    let runs = parser.parse_filesystem(&reader, &profile).unwrap();
    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Unknown);
    // And no recording, geometry or index may be conjured from it.
    let (recordings, _) = parser.parse_recordings(&reader, &profile).unwrap();
    assert!(recordings.is_empty());
    assert!(parser
        .storage_geometry(&reader, &profile)
        .unwrap()
        .is_none());
    assert!(parser.recording_index(&reader, &profile).unwrap().is_none());
    assert!(!parser.recognize_candidate(&reader, &profile).unwrap());
}

// ── Recordings ─────────────────────────────────────────────────────────────────

#[test]
fn recordings_are_reconstructed_one_per_clip_with_real_offsets() {
    let parser = HikvisionParser::default();
    let profile = shipped_profile();
    let image = realistic_dvr_volume();
    let (reader, _f) = reader_for(&image);

    let (recordings, runs) = parser.parse_recordings(&reader, &profile).unwrap();
    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Pass);

    // Every footer-described clip becomes exactly one recording, at its own physical offset.
    let expected: Vec<(u64, u64)> = image.described_clip_regions();
    assert_eq!(
        recordings.len(),
        expected.len(),
        "one recording per validated clip"
    );
    for rec in &recordings {
        assert_eq!(rec.source_offsets.len(), 1);
        let r = rec.source_offsets[0];
        assert!(
            expected.contains(&(r.offset, r.length)),
            "recording range {r} must match a clip the fixture actually produced"
        );
    }
}

#[test]
fn a_recording_carries_the_channel_and_timestamp_the_clip_declared() {
    let parser = HikvisionParser::default();
    let profile = shipped_profile();
    let image = minimal_volume();
    let (reader, _f) = reader_for(&image);
    let (_, clip) = image.first_clip().unwrap();

    let (recordings, _) = parser.parse_recordings(&reader, &profile).unwrap();
    let rec = recordings
        .iter()
        .find(|r| r.source_offsets.first().map(|s| s.offset) == Some(clip.clip_offset))
        .expect("the recording for the built clip");

    assert_eq!(rec.channel, clip.channel);
    // Unix seconds read as UTC, with no timezone applied at parse time.
    let normalized = rec.time.normalized.as_ref().expect("a decoded instant");
    assert!(normalized.method.contains("no timezone offset"));
    assert!(!normalized.iso_8601.contains("+05:30"));
    assert_eq!(rec.time.raw.value, clip.start_time as u64);
}

// ── Geometry and index authority ─────────────────────────────────────────────────

#[test]
fn storage_geometry_reports_the_real_video_region_and_block_size() {
    let parser = HikvisionParser::default();
    let profile = shipped_profile();
    let image = realistic_dvr_volume();
    let (reader, _f) = reader_for(&image);

    let geometry = parser
        .storage_geometry(&reader, &profile)
        .unwrap()
        .expect("a Hikvision volume must yield geometry");
    assert_eq!(geometry.block_size, Some(image.block_size));
    let video = geometry.video_region.expect("a video region");
    assert_eq!(video.offset, image.video_start);
    // These structures carry no allocation state, so the geometry must say so.
    assert!(geometry
        .oem_fields
        .get("hikvision_allocation_evidence")
        .unwrap()
        .contains("no deletion finding is available"));
}

#[test]
fn a_complete_tree_over_clean_geometry_is_authoritative() {
    let parser = HikvisionParser::default();
    let profile = shipped_profile();
    let image = minimal_volume();
    let (reader, _f) = reader_for(&image);

    let index = parser
        .recording_index(&reader, &profile)
        .unwrap()
        .expect("a Hikvision volume must yield an index");
    assert!(
        matches!(index.authority, IndexAuthority::Authoritative { .. }),
        "a fully traversed tree over complete geometry must be authoritative: {:?}",
        index.authority
    );
    // Every entry reports Unknown allocation — the only route to Deleted is closed.
    for rec in index
        .recordings
        .iter()
        .chain(index.unreferenced_recordings.iter())
    {
        assert_eq!(rec.allocation, AllocationEvidence::Unknown);
    }
}

#[test]
fn an_unreferenced_block_becomes_available_not_deleted() {
    let parser = HikvisionParser::default();
    let profile = shipped_profile();
    let image = realistic_dvr_volume();
    let (reader, _f) = reader_for(&image);

    let index = parser
        .recording_index(&reader, &profile)
        .unwrap()
        .expect("an index");

    // Block 1's clip is unreferenced by the tree, so it is available, not accessible.
    assert!(
        !index.unreferenced_recordings.is_empty(),
        "the unreferenced block's clip must land in the available set"
    );
    for rec in &index.unreferenced_recordings {
        // Never Deleted, and the reason must say why.
        assert_eq!(rec.allocation, AllocationEvidence::Unknown);
        let reason = rec
            .oem_metadata
            .get("availability_reason")
            .expect("a reason");
        assert!(reason.contains("not evidence of deletion"), "{reason}");
    }
}

#[test]
fn no_index_tree_yields_a_not_found_authority_not_a_silent_orphan() {
    let parser = HikvisionParser::default();
    let profile = shipped_profile();
    let image = no_index_volume();
    let (reader, _f) = reader_for(&image);

    let index = parser
        .recording_index(&reader, &profile)
        .unwrap()
        .expect("even without a tree the volume yields an index shell");
    assert!(
        matches!(index.authority, IndexAuthority::NotFound { .. }),
        "no tree means NotFound authority, so absence proves nothing: {:?}",
        index.authority
    );
}

// ── Backup tree ──────────────────────────────────────────────────────────────────

#[test]
fn a_backup_tree_substitutes_for_a_missing_primary() {
    let parser = HikvisionParser::default();
    let profile = shipped_profile();
    // Primary tree magic corrupted; backup intact.
    let spec = HikvisionImageSpec {
        blocks: vec![HikBlockSpec::default()],
        primary_tree: Some(HikTreeSpec {
            magic: Some(b"NOTATREE".to_vec()),
            ..HikTreeSpec::single_leaf(vec![HikEntrySpec::at(0, 0, 0)])
        }),
        backup_tree: Some(HikTreeSpec::single_leaf(vec![HikEntrySpec::at(0, 0, 0)])),
        ..Default::default()
    };
    let image = build_hikvision_image(&spec);
    let (reader, _f) = reader_for(&image);

    let geometry = parser.storage_geometry(&reader, &profile).unwrap().unwrap();
    assert_eq!(
        geometry
            .oem_fields
            .get("hikvision_index_authority_tree")
            .map(String::as_str),
        Some("backup"),
        "the backup must take authority when the primary is unusable"
    );
    assert_eq!(
        geometry
            .oem_fields
            .get("hikvision_index_authority_substituted")
            .map(String::as_str),
        Some("true")
    );
}

#[test]
fn disagreeing_trees_are_preserved_not_merged() {
    let parser = HikvisionParser::default();
    let profile = shipped_profile();
    let spec = HikvisionImageSpec {
        blocks: vec![
            HikBlockSpec::default(),
            HikBlockSpec {
                clips: vec![HikClipSpec {
                    channel_raw: 1,
                    ..Default::default()
                }],
                ..Default::default()
            },
        ],
        // Primary references block 0; backup references block 1. They disagree.
        primary_tree: Some(HikTreeSpec::single_leaf(vec![HikEntrySpec::at(0, 0, 0)])),
        backup_tree: Some(HikTreeSpec::single_leaf(vec![HikEntrySpec::at(1, 0, 1)])),
        ..Default::default()
    };
    let image = build_hikvision_image(&spec);
    let (reader, _f) = reader_for(&image);

    let geometry = parser.storage_geometry(&reader, &profile).unwrap().unwrap();
    assert_eq!(
        geometry
            .oem_fields
            .get("hikvision_tree_agreement")
            .map(String::as_str),
        Some("disagree"),
        "a disagreement between the trees must be recorded, not merged away"
    );
}

// ── B-tree structural edge cases through the whole parser ─────────────────────────

#[test]
fn a_page_cycle_downgrades_authority_below_authoritative() {
    let parser = HikvisionParser::default();
    let profile = shipped_profile();
    // Two leaves that point at each other: a cycle.
    let spec = HikvisionImageSpec {
        blocks: vec![HikBlockSpec::default()],
        primary_tree: Some(HikTreeSpec {
            pages: vec![
                HikPageSpec::Leaf {
                    entries: vec![HikEntrySpec::at(0, 0, 0)],
                    next_page_index: Some(2),
                    declared_entry_count: None,
                },
                HikPageSpec::Leaf {
                    entries: vec![HikEntrySpec::blank()],
                    next_page_index: Some(1), // back to page 1 -> cycle
                    declared_entry_count: None,
                },
            ],
            first_leaf_page_index: Some(1),
            ..Default::default()
        }),
        ..Default::default()
    };
    let image = build_hikvision_image(&spec);
    let (reader, _f) = reader_for(&image);

    let index = parser.recording_index(&reader, &profile).unwrap().unwrap();
    assert!(
        matches!(index.authority, IndexAuthority::Partial { .. }),
        "a tree containing a cycle cannot be authoritative: {:?}",
        index.authority
    );
}

#[test]
fn a_malformed_entry_is_surfaced_by_validate_structure() {
    let parser = HikvisionParser::default();
    let profile = shipped_profile();
    let spec = HikvisionImageSpec {
        blocks: vec![HikBlockSpec::default()],
        primary_tree: Some(HikTreeSpec::single_leaf(vec![
            HikEntrySpec::at(0, 0, 0),
            HikEntrySpec::malformed(),
        ])),
        ..Default::default()
    };
    let image = build_hikvision_image(&spec);
    let (reader, _f) = reader_for(&image);

    let runs = parser.validate_structure(&reader, &profile).unwrap();
    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Review);
    assert!(
        runs[0]
            .validation_state
            .reason
            .contains("neither blank nor populated"),
        "the malformed sentinel must be reported: {}",
        runs[0].validation_state.reason
    );
}

// ── Clip / codec / timeline ──────────────────────────────────────────────────────

#[test]
fn the_codec_is_taken_from_video_payload_h264_and_h265() {
    let profile = shipped_profile();

    for codec in [FixtureCodec::H264, FixtureCodec::H265] {
        let spec = HikvisionImageSpec {
            blocks: vec![HikBlockSpec {
                clips: vec![HikClipSpec {
                    codec,
                    ..Default::default()
                }],
                ..Default::default()
            }],
            primary_tree: Some(HikTreeSpec::single_leaf(vec![HikEntrySpec::at(0, 0, 0)])),
            ..Default::default()
        };
        let image = build_hikvision_image(&spec);
        let (reader, _f) = reader_for(&image);
        let volume = parser_hikvision::volume::read_volume(&reader, &profile).unwrap();
        let (_, clip) = image.first_clip().unwrap();
        let reconstruction = parser_hikvision::reconstruct_recording(
            &reader,
            &profile,
            &volume,
            &clip.expected_clip_id,
        )
        .unwrap()
        .expect("the recording");
        let expected = match codec {
            FixtureCodec::H264 => HikCodec::H264,
            FixtureCodec::H265 => HikCodec::H265,
            FixtureCodec::Indeterminate => HikCodec::Unknown,
        };
        assert_eq!(reconstruction.codec.codec, expected);
        assert!(reconstruction.is_exportable());
    }
}

#[test]
fn an_indeterminate_payload_yields_unknown_codec_not_a_guess() {
    let profile = shipped_profile();
    let spec = HikvisionImageSpec {
        blocks: vec![HikBlockSpec {
            clips: vec![HikClipSpec {
                codec: FixtureCodec::Indeterminate,
                ..Default::default()
            }],
            ..Default::default()
        }],
        primary_tree: Some(HikTreeSpec::single_leaf(vec![HikEntrySpec::at(0, 0, 0)])),
        ..Default::default()
    };
    let image = build_hikvision_image(&spec);
    let (reader, _f) = reader_for(&image);
    let volume = parser_hikvision::volume::read_volume(&reader, &profile).unwrap();
    let (_, clip) = image.first_clip().unwrap();
    let reconstruction =
        parser_hikvision::reconstruct_recording(&reader, &profile, &volume, &clip.expected_clip_id)
            .unwrap()
            .unwrap();
    assert_eq!(reconstruction.codec.codec, HikCodec::Unknown);
}

#[test]
fn timeline_events_come_only_from_clips_with_a_decodable_clock() {
    let parser = HikvisionParser::default();
    let profile = shipped_profile();
    let image = realistic_dvr_volume();
    let (reader, _f) = reader_for(&image);

    let (events, runs) = parser.extract_timeline_events(&reader, &profile).unwrap();
    assert!(!events.is_empty());
    assert!(matches!(
        runs[0].validation_state.state,
        ValidationStateKind::Pass | ValidationStateKind::Review
    ));
    for e in &events {
        // Every event carries a decoded instant and no assumed timezone.
        assert!(e.time.normalized.is_some());
        assert_eq!(e.time.timezone, forensic_core::TimeZoneState::Unknown);
    }
}

// ── Multi-block reconstruction ───────────────────────────────────────────────────

#[test]
fn a_recording_spanning_two_blocks_is_reconstructed_as_one() {
    let profile = shipped_profile();
    let image = multi_block_recording_volume();
    let (reader, _f) = reader_for(&image);
    let volume = parser_hikvision::volume::read_volume(&reader, &profile).unwrap();

    // Seed from block 0's clip; the continuation in block 1 must join it.
    let (_, seed) = image
        .block(0)
        .unwrap()
        .clips
        .first()
        .map(|c| (0u32, c))
        .unwrap();
    let reconstruction =
        parser_hikvision::reconstruct_recording(&reader, &profile, &volume, &seed.expected_clip_id)
            .unwrap()
            .expect("a recording");
    assert_eq!(
        reconstruction.blocks.len(),
        2,
        "the recording must span both blocks: {:?}",
        reconstruction.blocks
    );
    assert!(reconstruction.clips.len() >= 2);
    assert!(reconstruction.payload_bytes() > 0);
}

// ── Raw carving through the parser's scan interface ──────────────────────────────

#[test]
fn scan_region_reports_unindexed_clips_as_carved_candidates() {
    let parser = HikvisionParser::default();
    let profile = shipped_profile();
    // A block whose footer is corrupt, so its clips are only recoverable by carving.
    let spec = HikvisionImageSpec {
        blocks: vec![HikBlockSpec {
            clips: vec![HikClipSpec::default()],
            loose_clips: vec![LooseClipSpec::default(), LooseClipSpec::default()],
            footer: FooterMode::Corrupt,
        }],
        primary_tree: None,
        ..Default::default()
    };
    let image = build_hikvision_image(&spec);
    let (reader, _f) = reader_for(&image);

    let block = image.block(0).unwrap();
    let region =
        forensic_core::Region::new(block.offset, block.footer_offset - block.offset).unwrap();
    let records = parser
        .scan_region_for_candidates(&reader, &profile, region)
        .unwrap();
    assert!(
        records.len() >= 2,
        "the carver must find the unindexed clips, at absolute offsets: {}",
        records.len()
    );
    for rec in &records {
        assert!(rec.physical_region.offset >= block.offset);
        assert!(rec.physical_region.offset < block.footer_offset);
        // Carving establishes no index claim.
        assert!(rec
            .oem_metadata
            .get("hikvision_carve_index_statement")
            .unwrap()
            .contains("cannot support an Active or Deleted conclusion"));
    }
}

// ── Every stage is well-behaved on a damaged but recognised volume ───────────────

#[test]
fn a_volume_with_only_carveable_video_still_runs_every_stage() {
    let parser = HikvisionParser::default();
    let profile = shipped_profile();
    let image = no_index_volume();
    let (reader, _f) = reader_for(&image);

    // None of these may panic or error; each returns a run with a reason.
    assert!(parser.parse_filesystem(&reader, &profile).is_ok());
    assert!(parser.parse_metadata(&reader, &profile).is_ok());
    assert!(parser.parse_recordings(&reader, &profile).is_ok());
    assert!(parser.extract_timeline_events(&reader, &profile).is_ok());
    assert!(parser.validate_structure(&reader, &profile).is_ok());
}

// ── Multi-clip reconstruction and Annex-B normalization ───────────────────────────

#[test]
fn consecutive_clips_in_one_block_join_into_one_recording_in_slot_order() {
    let profile = shipped_profile();
    let first = HikClipSpec::default();
    let second = HikClipSpec {
        start_time: first.end_time,
        end_time: first.end_time + 600,
        time_a: first.end_time,
        ..Default::default()
    };
    let spec = HikvisionImageSpec {
        blocks: vec![HikBlockSpec {
            clips: vec![first, second],
            ..Default::default()
        }],
        primary_tree: Some(HikTreeSpec::single_leaf(vec![HikEntrySpec::at(0, 0, 0)])),
        ..Default::default()
    };
    let image = build_hikvision_image(&spec);
    let (reader, _f) = reader_for(&image);
    let volume = parser_hikvision::volume::read_volume(&reader, &profile).unwrap();
    let built = &image.block(0).unwrap().clips;
    assert_eq!(built.len(), 2);

    // Seeding from the *second* clip must still yield both, in footer slot order.
    let reconstruction = parser_hikvision::reconstruct_recording(
        &reader,
        &profile,
        &volume,
        &built[1].expected_clip_id,
    )
    .unwrap()
    .expect("a recording");
    assert_eq!(reconstruction.clips.len(), 2, "{:?}", reconstruction.notes);
    assert_eq!(reconstruction.clip_regions[0].offset, built[0].clip_offset);
    assert_eq!(reconstruction.clip_regions[1].offset, built[1].clip_offset);
    assert_eq!(reconstruction.blocks, vec![0]);
    // The seed id is the recording id; it is never regenerated.
    assert_eq!(reconstruction.recording_id, built[1].expected_clip_id);

    // Payload ranges lie inside the clips and exclude the MPEG-PS framing.
    for r in &reconstruction.payload_regions {
        assert!(reconstruction
            .clip_regions
            .iter()
            .any(|c| r.offset >= c.offset && r.offset + r.length <= c.offset + c.length));
    }
    assert!(reconstruction.payload_bytes() < reconstruction.clip_bytes());
}

#[test]
fn a_clean_stream_is_normalized_without_changing_its_layout() {
    let profile = shipped_profile();
    let image = minimal_volume();
    let (reader, _f) = reader_for(&image);
    let volume = parser_hikvision::volume::read_volume(&reader, &profile).unwrap();
    let (_, clip) = image.first_clip().unwrap();
    let reconstruction =
        parser_hikvision::reconstruct_recording(&reader, &profile, &volume, &clip.expected_clip_id)
            .unwrap()
            .unwrap();

    let n = &reconstruction.normalization;
    assert_eq!(
        n.evidence.state,
        ValidationStateKind::Pass,
        "{}",
        n.evidence.reason
    );
    assert!(!n.changed_layout(), "{}", n.summary());
    assert_eq!(
        reconstruction.export_regions(),
        &reconstruction.payload_regions[..]
    );

    // The exported bytes open on an Annex-B start code followed by a parameter set.
    let first = reconstruction.export_regions()[0];
    let head = evidence_reader::EvidenceReader::read_exact_at(&reader, first.offset, 5).unwrap();
    assert_eq!(&head[..4], &[0x00, 0x00, 0x00, 0x01]);
    assert_eq!(head[4] & 0x1F, 7, "an H.264 SPS leads the stream");
    assert!(reconstruction
        .oem_metadata()
        .contains_key("hikvision_annexb_normalization"));
}

// ── Partially captured acquisitions ──────────────────────────────────────────────

#[test]
fn a_block_cut_off_by_the_end_of_the_image_is_out_of_scope_not_malformed() {
    let parser = HikvisionParser::default();
    let profile = shipped_profile();
    let spec = HikvisionImageSpec {
        blocks: vec![HikBlockSpec::default(), HikBlockSpec::default()],
        primary_tree: Some(HikTreeSpec::single_leaf(vec![HikEntrySpec::at(0, 0, 0)])),
        ..Default::default()
    };
    let mut image = build_hikvision_image(&spec);
    // Cut the acquisition inside block 1's video data: its footer was never captured.
    let block1 = image.block(1).unwrap().clone();
    image.bytes.truncate((block1.offset + 64 * 1024) as usize);
    let (reader, _f) = reader_for(&image);

    let volume = parser_hikvision::volume::read_volume(&reader, &profile).unwrap();
    let classified = volume
        .blocks
        .iter()
        .find(|b| b.block_number() == 1)
        .expect("the partially captured block is still enumerated");
    assert_eq!(
        classified.classification.label(),
        "out-of-scope",
        "{:?}",
        classified.classification
    );
    assert_eq!(
        volume.malformed_blocks().count(),
        0,
        "nothing is known to be damaged"
    );
    // Its captured bytes are still offered to the carver.
    assert!(classified.is_carving_candidate());

    // And an index over a domain that was not wholly captured is not a complete statement.
    let index = parser.recording_index(&reader, &profile).unwrap().unwrap();
    assert!(
        matches!(index.authority, IndexAuthority::Partial { .. }),
        "{:?}",
        index.authority
    );
}

#[test]
fn the_tree_integrity_reexport_is_usable_from_outside_the_crate() {
    // A compile-level check that the public surface a consumer needs is actually exported.
    let _ = TreeIntegrity::CompleteTraversal.is_complete();
}
