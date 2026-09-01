//! Comprehensive Forensic Hardening & Regression Test Suite.
//!
//! Validates the 8 architectural corrections and forensic invariants:
//! 1. Codec start-code disambiguation (H.265 vs H.264 multi-signal classification)
//! 2. Two-dimensional fragmentation (logical sequence continuity vs physical storage layout)
//! 3. Uniview deleted superblock structural validation
//! 4. Deterministic canonical tie-breaking for simultaneous timeline events
//! 5. Timestamp parsing with unknown timezone preservation
//! 6. Bounded reader isolation and absolute offset translation

use evidence_reader::{BoundedReader, EvidenceReader, SourceKind};
use forensic_core::{
    ForensicError, Hash, NormalizedTime, OemProfile, ProfileId, Provenance, RawTimestamp,
    RecorderNativeTime, Region, TimelineEvent, TimeZoneState, ValidationState, ValidationStateKind,
};
use parser_uniview::UniviewParser;
use parsers_core::Parser;
use recovery::fragmentation::{reassemble_fragments, Fragment, PhysicalContinuity};
use recovery::reconstructor::{VideoCodec, VideoReconstructor};
use timeline::correlation::CrossCameraCorrelator;
use timeline::engine::{TimelineEngine, TimelineOrdering};

// Mock in-memory EvidenceReader for regression tests
struct MockEvidence {
    data: Vec<u8>,
}

impl EvidenceReader for MockEvidence {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
        if offset >= self.len() {
            return Err(ForensicError::out_of_bounds("MockEvidence EOF", offset, buf.len() as u64, self.len()));
        }
        let avail = (self.len() - offset) as usize;
        let to_read = buf.len().min(avail);
        buf[..to_read].copy_from_slice(&self.data[offset as usize..offset as usize + to_read]);
        Ok(to_read)
    }
    fn source_kind(&self) -> SourceKind {
        SourceKind::Raw
    }
    fn source_path(&self) -> &str {
        "mock://regression"
    }
}

// -----------------------------------------------------------------------------
// 1. Codec Multi-Signal Classification Tests
// -----------------------------------------------------------------------------

#[test]
fn test_regression_codec_h264_4byte_start_code() {
    let stream = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x01, 0x68];
    let evidence = VideoReconstructor::classify_codec(&stream);
    assert_eq!(evidence.codec, VideoCodec::H264);
    assert_eq!(evidence.validation.state, ValidationStateKind::Pass);
}

#[test]
fn test_regression_codec_h265_4byte_start_code_not_shadowed() {
    // 00 00 00 01 40 (HEVC VPS) followed by 00 00 00 01 42 (HEVC SPS)
    let stream = vec![0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x0C, 0x01, 0x00, 0x00, 0x00, 0x01, 0x42, 0x01];
    let evidence = VideoReconstructor::classify_codec(&stream);
    assert_eq!(evidence.codec, VideoCodec::H265, "H.265 VPS starting with 4-byte start code must NEVER be misclassified as H.264");
    assert_eq!(evidence.validation.state, ValidationStateKind::Pass);
}

#[test]
fn test_regression_codec_h265_3byte_start_code() {
    let stream = vec![0x00, 0x00, 0x01, 0x40, 0x01, 0x0C, 0x00, 0x00, 0x01, 0x42, 0x01];
    let evidence = VideoReconstructor::classify_codec(&stream);
    assert_eq!(evidence.codec, VideoCodec::H265);
}

// -----------------------------------------------------------------------------
// 2. Two-Dimensional Fragmentation Tests
// -----------------------------------------------------------------------------

#[test]
fn test_regression_logical_gap_physical_contiguous() {
    // Physical layout is contiguous, but sequence jumps from 0 to 5 (4 missing frames)
    let fragments = vec![
        Fragment { region: Region { offset: 0, length: 100 }, sequence_index: 0, is_valid: true },
        Fragment { region: Region { offset: 100, length: 100 }, sequence_index: 5, is_valid: true },
    ];
    let result = reassemble_fragments(fragments, 100);

    assert_eq!(result.logical_gaps.len(), 1);
    assert_eq!(result.logical_gaps[0].missing_count, 4);
    assert!(result.is_physically_contiguous);
    assert_eq!(result.validation.state, ValidationStateKind::Review);
}

#[test]
fn test_regression_logical_contiguous_physical_fragmented() {
    // Sequence is contiguous (0, 1), but stored in non-adjacent clusters
    let fragments = vec![
        Fragment { region: Region { offset: 0, length: 100 }, sequence_index: 0, is_valid: true },
        Fragment { region: Region { offset: 5000, length: 100 }, sequence_index: 1, is_valid: true },
    ];
    let result = reassemble_fragments(fragments, 100);

    assert!(result.logical_gaps.is_empty(), "Consecutive frames must have 0 logical gaps");
    assert!(!result.is_physically_contiguous);
    assert_eq!(result.physical_discontinuities.len(), 1);
    assert_eq!(result.validation.state, ValidationStateKind::Pass);
}

#[test]
fn test_regression_circular_buffer_wrap() {
    let fragments = vec![
        Fragment { region: Region { offset: 9000, length: 100 }, sequence_index: 0, is_valid: true },
        Fragment { region: Region { offset: 500, length: 100 }, sequence_index: 1, is_valid: true },
    ];
    let result = reassemble_fragments(fragments, 100);

    assert!(result.logical_gaps.is_empty());
    assert_eq!(result.physical_discontinuities.len(), 1);
    match result.physical_discontinuities[0].continuity {
        PhysicalContinuity::CircularWrap { wrap_offset } => assert_eq!(wrap_offset, 500),
        _ => panic!("Expected CircularWrap"),
    }
}

// -----------------------------------------------------------------------------
// 3. Uniview Deleted Marker Structural Validation Tests
// -----------------------------------------------------------------------------

#[test]
fn test_regression_uniview_deleted_superblock_marker() {
    let parser = UniviewParser::default();
    let mut data = vec![0u8; 1024];
    // Deleted marker: 0xE5 followed by "NIV" and valid cluster size
    data[0] = 0xE5;
    data[1] = b'N';
    data[2] = b'I';
    data[3] = b'V';
    data[4] = 0x01; // Non-zero cluster hint

    let reader = MockEvidence { data };
    let profile_toml = r#"
        profile_id = "uniview-ubifs-v1.0"
        profile_version = "1.0.0"
        schema_version = "1.0"
        oem = "uniview"
        storage_family = "UNIVIEW_UBIFS"

        [applicability]
        models = ["UNV-NVR"]
        firmwares = []
        storage_variants = ["single_disk"]
        reference = "Uniview"

        [layout]
        superblock_size = 512

        [[signatures]]
        name = "uniview_super_magic"
        pattern_hex = "55 4E 49 56"
        evidence_status = "validated"
        weight = 0.85
        is_exclusive = true
        explanation = "Superblock"

        [confidence_weights]
        max_possible_score = 1.0
        min_threshold = 0.6
    "#;
    let profile = OemProfile::from_toml_str(profile_toml).unwrap();

    let runs = parser.parse_filesystem(&reader, &profile).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Review);
    assert!(runs[0].validation_state.reason.contains("Deleted marker candidate"));
}

// -----------------------------------------------------------------------------
// 4. Timeline Deterministic Canonical Tie-Breaking Tests
// -----------------------------------------------------------------------------

#[test]
fn test_regression_simultaneous_timeline_events_deterministic() {
    let raw_prov = Provenance::new(
        forensic_core::EvidenceId::new(),
        Hash::sha256(vec![0; 32]),
        vec![],
        "TestParser",
        "1.0.0",
        Hash::sha256(vec![0; 32]),
        ValidationState::pass("raw", "valid", "raw").unwrap(),
    );

    let e1 = TimelineEvent {
        channel: 1,
        time: forensic_core::TimeEvidence {
            raw: RawTimestamp { value: 100, format: "HEX".into(), source: raw_prov.clone() },
            recorder_native: Some(RecorderNativeTime { iso_8601: "2026-09-01T12:00:00Z".into() }),
            normalized: Some(NormalizedTime { iso_8601: "2026-09-01T12:00:00Z".into(), method: "UTC".into() }),
            reference: None,
            timezone: TimeZoneState::Known("UTC".into()),
            correction: None,
        },
        description: "Motion Cam 1".into(),
        source_offsets: vec![Region { offset: 1000, length: 100 }],
        parser_id: "test".into(),
        parser_version: "1.0.0".into(),
        profile_id: ProfileId("prof".into()),
        profile_hash: Hash::sha256(vec![0; 32]),
    };

    let e2 = TimelineEvent {
        channel: 2,
        time: forensic_core::TimeEvidence {
            raw: RawTimestamp { value: 200, format: "HEX".into(), source: raw_prov },
            recorder_native: Some(RecorderNativeTime { iso_8601: "2026-09-01T12:00:00Z".into() }),
            normalized: Some(NormalizedTime { iso_8601: "2026-09-01T12:00:00Z".into(), method: "UTC".into() }),
            reference: None,
            timezone: TimeZoneState::Known("UTC".into()),
            correction: None,
        },
        description: "Motion Cam 2".into(),
        source_offsets: vec![Region { offset: 2000, length: 100 }],
        parser_id: "test".into(),
        parser_version: "1.0.0".into(),
        profile_id: ProfileId("prof".into()),
        profile_hash: Hash::sha256(vec![0; 32]),
    };

    // Run 1: Input [e1, e2]
    let t1 = TimelineEngine::build_timeline(vec![e1.clone(), e2.clone()], TimelineOrdering::Normalized);
    // Run 2: Input [e2, e1]
    let t2 = TimelineEngine::build_timeline(vec![e2, e1], TimelineOrdering::Normalized);

    assert_eq!(t1.events[0].channel, t2.events[0].channel, "Canonical tie-breaker must produce identical event order regardless of arrival permutation");
    assert_eq!(t1.events[1].channel, t2.events[1].channel);
}

// -----------------------------------------------------------------------------
// 5. Timestamp Uncertainty Preservation Tests
// -----------------------------------------------------------------------------

#[test]
fn test_regression_unknown_timezone_preserved_never_coerced_to_utc() {
    let raw_prov = Provenance::new(
        forensic_core::EvidenceId::new(),
        Hash::sha256(vec![0; 32]),
        vec![],
        "TestParser",
        "1.0.0",
        Hash::sha256(vec![0; 32]),
        ValidationState::pass("raw", "valid", "raw").unwrap(),
    );

    let e1 = TimelineEvent {
        channel: 1,
        time: forensic_core::TimeEvidence {
            raw: RawTimestamp { value: 100, format: "HEX".into(), source: raw_prov.clone() },
            recorder_native: Some(RecorderNativeTime { iso_8601: "2026-09-01 12:00:00".into() }),
            normalized: Some(NormalizedTime { iso_8601: "2026-09-01 12:00:00".into(), method: "None".into() }),
            reference: None,
            timezone: TimeZoneState::Unknown,
            correction: None,
        },
        description: "Cam 1 Event".into(),
        source_offsets: vec![Region { offset: 1000, length: 100 }],
        parser_id: "test".into(),
        parser_version: "1.0.0".into(),
        profile_id: ProfileId("prof".into()),
        profile_hash: Hash::sha256(vec![0; 32]),
    };

    let e2 = TimelineEvent {
        channel: 2,
        time: forensic_core::TimeEvidence {
            raw: RawTimestamp { value: 200, format: "HEX".into(), source: raw_prov },
            recorder_native: Some(RecorderNativeTime { iso_8601: "2026-09-01 12:00:05".into() }),
            normalized: Some(NormalizedTime { iso_8601: "2026-09-01 12:00:05".into(), method: "None".into() }),
            reference: None,
            timezone: TimeZoneState::Unknown,
            correction: None,
        },
        description: "Cam 2 Event".into(),
        source_offsets: vec![Region { offset: 2000, length: 100 }],
        parser_id: "test".into(),
        parser_version: "1.0.0".into(),
        profile_id: ProfileId("prof".into()),
        profile_hash: Hash::sha256(vec![0; 32]),
    };

    let groups = CrossCameraCorrelator::correlate_events(&[e1, e2], 30);
    assert_eq!(groups.len(), 1);
    assert!(groups[0].has_timezone_uncertainty, "Correlation across unknown timezone events must flag uncertainty");
    assert_eq!(groups[0].validation.state, ValidationStateKind::Review);
}

// -----------------------------------------------------------------------------
// 6. Bounded Reader Abstraction Tests
// -----------------------------------------------------------------------------

#[test]
fn test_regression_bounded_reader_isolates_and_translates_offsets() {
    let mock = MockEvidence { data: b"0123456789ABCDEF".to_vec() };
    let bounded = BoundedReader::new(&mock, 5, 5).unwrap();

    assert_eq!(bounded.len(), 5);
    let bytes = bounded.read_exact_at(0, 5).unwrap();
    assert_eq!(bytes, b"56789");

    // Reading outside bounded window must fail
    assert!(bounded.read_exact_at(4, 2).is_err());

    // Local to absolute offset mapping
    assert_eq!(bounded.to_absolute_offset(3).unwrap(), 8);
}
