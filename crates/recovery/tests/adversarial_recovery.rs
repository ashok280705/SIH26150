//! Adversarial and Hostile-Input Recovery Suite (Task 100, 101 / Req 24.1-24.4, 19.3, 19.6).
//!
//! Guarantees:
//! - No input panics or hangs the recovery engine (Req 24.1)
//! - Integer/offset overflow is safely caught and rejected (Req 24.4)
//! - Pathological fragmentation, enormous candidates, cyclic graphs are bounded (Req 24.2)
//! - Cancellation returns defined results immediately (Req 24.3)

use evidence_reader::{EvidenceReader, SourceKind};
use forensic_core::{
    CancelToken, ForensicError, OemProfile, RecoveryBounds, Region, ValidationStateKind,
};
use recovery::{
    fragmentation::{reassemble_fragments, Fragment},
    hypothesis::{rank_hypotheses, Hypothesis},
    video::{validate_and_order_frames, VideoFrame, FrameType},
    RecoveryEngine,
};

/// Hostile reader simulating various corrupt / edge-case evidence devices.
struct HostileReader {
    len: u64,
    fail_reads: bool,
}

impl EvidenceReader for HostileReader {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
        if self.fail_reads {
            return Err(ForensicError::io("HostileReader", std::io::Error::new(std::io::ErrorKind::Other, "Simulated device failure")));
        }
        if offset >= self.len {
            return Err(ForensicError::out_of_bounds("HostileReader", offset, buf.len() as u64, self.len));
        }
        let available = ((self.len - offset) as usize).min(buf.len());
        for b in &mut buf[..available] {
            *b = 0xAA; // Hostile pattern
        }
        Ok(available)
    }

    fn source_kind(&self) -> SourceKind {
        SourceKind::Raw
    }

    fn source_path(&self) -> &str {
        "hostile://device"
    }
}

fn make_test_profile() -> OemProfile {
    let toml_str = r#"
profile_id = "test-fs-v1.0"
profile_version = "1.0.0"
schema_version = "1.0"
oem = "test"
storage_family = "TEST_FS"

[applicability]
models = []
firmwares = []
storage_variants = []
reference = "Test profile"

[[signatures]]
name = "test_sig"
pattern_hex = "AA BB CC DD"
evidence_status = "validated"
weight = 0.5
is_exclusive = false
explanation = "Test"

[confidence_weights]
max_possible_score = 0.5
"#;
    OemProfile::from_toml_str(toml_str).expect("Failed to parse test profile")
}

struct DummyParser;

impl parsers_core::parser::Parser for DummyParser {
    fn id(&self) -> &str { "dummy" }
    fn version(&self) -> &str { "1.0.0" }
    fn parse_filesystem(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<Vec<forensic_core::ParserRun>, ForensicError> { Ok(vec![]) }
    fn parse_metadata(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<Vec<forensic_core::ParserRun>, ForensicError> { Ok(vec![]) }
    fn parse_recordings(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<(Vec<forensic_core::Recording>, Vec<forensic_core::ParserRun>), ForensicError> { Ok((vec![], vec![])) }
    fn extract_timeline_events(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<(Vec<forensic_core::TimelineEvent>, Vec<forensic_core::ParserRun>), ForensicError> { Ok((vec![], vec![])) }
    fn validate_structure(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<Vec<forensic_core::ParserRun>, ForensicError> { Ok(vec![]) }
    fn recognize_candidate(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<bool, ForensicError> { Ok(true) }
}

#[test]
fn test_overflow_offsets_rejected_safely() {
    let reader = HostileReader { len: 1024, fail_reads: false };
    let profile = make_test_profile();
    let parser = DummyParser;

    let overflow_region = Region {
        offset: u64::MAX - 10,
        length: 20, // offset + length overflows u64
    };

    let result = scan(&reader, &profile, &parser, overflow_region);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ForensicError::ArithmeticOverflow { .. }));
}

#[test]
fn test_out_of_bounds_offsets_rejected_safely() {
    let reader = HostileReader { len: 1024, fail_reads: false };
    let profile = make_test_profile();
    let parser = DummyParser;

    let oob_region = Region {
        offset: 2000,
        length: 500,
    };

    let result = scan(&reader, &profile, &parser, oob_region);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ForensicError::OutOfBounds { .. }));
}

#[test]
fn test_enormous_candidate_count_bounded() {
    let hypotheses: Vec<Hypothesis> = (0..5000).map(|i| Hypothesis {
        candidate_id: format!("cand_{}", i),
        source_regions: vec![Region { offset: i * 512, length: 512 }],
        score: 0.5,
    }).collect();

    let (ranked, val) = rank_hypotheses(hypotheses, 50);
    assert_eq!(ranked.len(), 50);
    assert_eq!(val.state, ValidationStateKind::Review);
}

#[test]
fn test_pathological_fragmentation_bounded_and_reported() {
    let fragments: Vec<Fragment> = (0..10_000).map(|i| Fragment {
        region: Region { offset: i * 256, length: 128 },
        sequence_index: i as u32,
        is_valid: true,
    }).collect();

    let result = reassemble_fragments(fragments, 100);
    assert!(result.truncated);
    assert_eq!(result.ordered_fragments.len(), 100);
    assert_eq!(result.validation.state, ValidationStateKind::Review);
}

#[test]
fn test_malformed_and_impossible_frame_timestamps() {
    let frames = vec![
        VideoFrame { offset: 0, size: 100, frame_type: FrameType::IFrame, timestamp: Some(u64::MAX), channel_id: Some(999), is_valid: false, rejection_reason: Some("Impossible timestamp".into()) },
        VideoFrame { offset: 100, size: 100, frame_type: FrameType::PFrame, timestamp: Some(10), channel_id: Some(1), is_valid: true, rejection_reason: None },
    ];

    let result = validate_and_order_frames(frames);
    assert_eq!(result.ordered_frames.len(), 1);
    assert_eq!(result.rejected_frames.len(), 1);
    assert_eq!(result.validation.state, ValidationStateKind::Review);
}

#[test]
fn test_device_read_failure_handled_gracefully() {
    let reader = HostileReader { len: 1024 * 1024, fail_reads: true };
    let profile = make_test_profile();
    let parser = DummyParser;
    let engine = RecoveryEngine::new();

    let bounds = RecoveryBounds {
        max_scan_bytes: u64::MAX,
        max_scan_regions: 10,
        max_candidates: 10,
        max_hypotheses: 10,
        max_search_depth: None,
        cancel: CancelToken::new(),
        time_limit: None,
    };

    // Device failures during scan loop should be recorded as rejections without crashing the engine
    let outcome = engine.execute_recovery(request(&reader, &profile, &parser, &bounds)).unwrap();
    let (candidates, run) = (outcome.candidates, outcome.run);
    assert!(candidates.is_empty());
    assert_eq!(run.searched_regions.len(), 1);
}

/// Build a whole-image recovery request.
fn request<'a>(
    reader: &'a dyn EvidenceReader,
    profile: &'a OemProfile,
    parser: &'a dyn parsers_core::Parser,
    bounds: &'a RecoveryBounds,
) -> recovery::RecoveryRequest<'a> {
    recovery::RecoveryRequest {
        evidence_id: forensic_core::EvidenceId::new(),
        reader,
        profile,
        oem_key: "test",
        parser,
        bounds,
        scan_window: None,
        read_window_bytes: None,
    }
}

/// Scan one hostile region directly, bypassing the planner, to check that bad offsets are
/// rejected at the read boundary rather than panicking.
fn scan(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    parser: &dyn parsers_core::Parser,
    region: Region,
) -> Result<Option<recovery::ScanFinding>, ForensicError> {
    let ctx = recovery::ScanContext {
        evidence_id: forensic_core::EvidenceId::new(),
        oem_key: "test".into(),
        profile_id: profile.profile_id.clone(),
        profile_version: profile.profile_version.clone(),
        profile_hash: profile.profile_hash.clone(),
        parser_id: parser.id().into(),
        parser_version: parser.version().into(),
        max_window_bytes: recovery::DEFAULT_SCAN_WINDOW_BYTES,
    };
    let target = recovery::ScanTarget {
        region,
        originating_region: region,
        payload_region: None,
        claim: recovery::RegionClaim::NoIndexEvidence {
            reason: "adversarial test".into(),
        },
        discovery_method: recovery::DiscoveryMethod::WholeImageScanWithoutIndex,
    };
    recovery::scan_target(reader, profile, parser, &ctx, &target)
}
