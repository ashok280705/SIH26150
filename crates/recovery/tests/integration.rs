use forensic_core::{
    CancelToken, ForensicError, OemProfile, ParserRun, RecoveryBounds, Recording,
    TimelineEvent, ValidationStateKind,
};
use evidence_reader::{EvidenceReader, SourceKind};
use parsers_core::parser::Parser;
use recovery::RecoveryEngine;

/// Mock EvidenceReader that returns a fixed length.
struct MockReader {
    len: u64,
}

impl EvidenceReader for MockReader {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
        if offset >= self.len {
            return Err(ForensicError::out_of_bounds("MockReader", offset, buf.len() as u64, self.len));
        }
        let available = ((self.len - offset) as usize).min(buf.len());
        for b in &mut buf[..available] { *b = 0; }
        Ok(available)
    }

    fn source_kind(&self) -> SourceKind {
        SourceKind::Raw
    }

    fn source_path(&self) -> &str {
        "mock://test"
    }
}

/// EvidenceReader that fills every read with a repeating H.264 Annex-B pattern
/// (SPS/PPS/IDR start codes), so the recovery levels find genuine codec evidence.
struct CodecReader {
    len: u64,
}

impl EvidenceReader for CodecReader {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
        if offset >= self.len {
            return Err(ForensicError::out_of_bounds("CodecReader", offset, buf.len() as u64, self.len));
        }
        // A small, real H.264 Annex-B fragment repeated to fill the window.
        const PATTERN: [u8; 24] = [
            0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1F, // SPS
            0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x3C, 0x80, // PPS
            0x00, 0x00, 0x00, 0x01, 0x65, 0xB8, 0x00, 0x04, // IDR
        ];
        let available = ((self.len - offset) as usize).min(buf.len());
        for (i, b) in buf[..available].iter_mut().enumerate() {
            *b = PATTERN[(offset as usize + i) % PATTERN.len()];
        }
        Ok(available)
    }

    fn source_kind(&self) -> SourceKind {
        SourceKind::Raw
    }

    fn source_path(&self) -> &str {
        "codec://test"
    }
}

/// Mock Parser that always recognizes a candidate.
struct AlwaysRecognizeParser;

impl Parser for AlwaysRecognizeParser {
    fn id(&self) -> &str { "mock-always" }
    fn version(&self) -> &str { "1.0.0" }
    fn parse_filesystem(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<Vec<ParserRun>, ForensicError> {
        Ok(vec![])
    }
    fn parse_metadata(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<Vec<ParserRun>, ForensicError> {
        Ok(vec![])
    }
    fn parse_recordings(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<(Vec<Recording>, Vec<ParserRun>), ForensicError> {
        Ok((vec![], vec![]))
    }
    fn extract_timeline_events(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<(Vec<TimelineEvent>, Vec<ParserRun>), ForensicError> {
        Ok((vec![], vec![]))
    }
    fn validate_structure(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<Vec<ParserRun>, ForensicError> {
        Ok(vec![])
    }
    fn recognize_candidate(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<bool, ForensicError> {
        Ok(true)
    }
}

/// Mock Parser that never recognizes a candidate.
struct NeverRecognizeParser;

impl Parser for NeverRecognizeParser {
    fn id(&self) -> &str { "mock-never" }
    fn version(&self) -> &str { "1.0.0" }
    fn parse_filesystem(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<Vec<ParserRun>, ForensicError> {
        Ok(vec![])
    }
    fn parse_metadata(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<Vec<ParserRun>, ForensicError> {
        Ok(vec![])
    }
    fn parse_recordings(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<(Vec<Recording>, Vec<ParserRun>), ForensicError> {
        Ok((vec![], vec![]))
    }
    fn extract_timeline_events(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<(Vec<TimelineEvent>, Vec<ParserRun>), ForensicError> {
        Ok((vec![], vec![]))
    }
    fn validate_structure(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<Vec<ParserRun>, ForensicError> {
        Ok(vec![])
    }
    fn recognize_candidate(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<bool, ForensicError> {
        Ok(false)
    }
}

fn make_mock_profile() -> OemProfile {
    let toml_str = r#"
profile_id = "mock-fs-v1.0"
profile_version = "1.0.0"
schema_version = "1.0"
oem = "MOCK"
storage_family = "MOCK_FS"

[applicability]
models = []
firmwares = []
storage_variants = []
reference = "Mock profile for testing"

[[signatures]]
name = "mock_sig"
pattern_hex = "4D 4F 43 4B"
evidence_status = "validated"
weight = 0.5
is_exclusive = false
explanation = "Mock signature for testing"

[confidence_weights]
max_possible_score = 0.5
"#;
    OemProfile::from_toml_str(toml_str).expect("Failed to parse mock profile")
}

#[test]
fn test_engine_truncation_on_byte_limit() {
    let engine = RecoveryEngine::new();
    let reader = MockReader { len: 10 * 1024 * 1024 }; // 10 MB
    let profile = make_mock_profile();
    let parser = NeverRecognizeParser;

    let bounds = RecoveryBounds {
        max_scan_bytes: 2 * 1024 * 1024, // 2 MB limit
        max_scan_regions: 100,
        max_candidates: 100,
        max_hypotheses: 100,
        max_search_depth: None,
        cancel: CancelToken::new(),
        time_limit: None,
    };

    let run = engine.execute_recovery(request(&reader, &profile, &parser, &bounds)).unwrap().run;
    
    assert!(run.truncated, "Run should be truncated when byte limit is reached");
    assert_eq!(run.validation_state.state, ValidationStateKind::Review, "Truncated run must be REVIEW");
}

#[test]
fn test_engine_truncation_on_candidate_limit() {
    let engine = RecoveryEngine::new();
    // Real codec bytes so each indexed chunk yields a recovery candidate.
    let reader = CodecReader { len: 10 * 1024 * 1024 };
    let profile = make_mock_profile();
    let parser = AlwaysRecognizeParser; // every chunk is indexed and holds codec data

    let bounds = RecoveryBounds {
        max_scan_bytes: u64::MAX,
        max_scan_regions: 100,
        max_candidates: 2, // only 2 candidates allowed
        max_hypotheses: 100,
        max_search_depth: None,
        cancel: CancelToken::new(),
        time_limit: None,
    };

    let run = engine.execute_recovery(request(&reader, &profile, &parser, &bounds)).unwrap().run;
    
    assert!(run.truncated, "Run should be truncated when candidate limit is reached");
    assert_eq!(run.validation_state.state, ValidationStateKind::Review);
}

#[test]
fn test_engine_cancellation_yields_review() {
    let engine = RecoveryEngine::new();
    let reader = MockReader { len: 10 * 1024 * 1024 };
    let profile = make_mock_profile();
    let parser = NeverRecognizeParser;
    let cancel = CancelToken::new();
    cancel.cancel(); // pre-cancelled

    let bounds = RecoveryBounds {
        max_scan_bytes: u64::MAX,
        max_scan_regions: 100,
        max_candidates: 100,
        max_hypotheses: 100,
        max_search_depth: None,
        cancel,
        time_limit: None,
    };

    let run = engine.execute_recovery(request(&reader, &profile, &parser, &bounds)).unwrap().run;
    
    assert!(run.cancelled, "Run should be cancelled");
    assert_eq!(run.validation_state.state, ValidationStateKind::Review);
}

#[test]
fn test_engine_full_scan_pass() {
    let engine = RecoveryEngine::new();
    let reader = MockReader { len: 1024 * 1024 }; // 1 MB -- small enough to complete
    let profile = make_mock_profile();
    let parser = NeverRecognizeParser;

    let bounds = RecoveryBounds {
        max_scan_bytes: u64::MAX,
        max_scan_regions: 100,
        max_candidates: 100,
        max_hypotheses: 100,
        max_search_depth: None,
        cancel: CancelToken::new(),
        time_limit: None,
    };

    let run = engine.execute_recovery(request(&reader, &profile, &parser, &bounds)).unwrap().run;
    
    assert!(!run.truncated, "Run should NOT be truncated");
    assert!(!run.cancelled, "Run should NOT be cancelled");
    assert_eq!(run.validation_state.state, ValidationStateKind::Pass, "Complete run should be PASS");
}

#[test]
fn test_engine_parser_never_drives_level_selection() {
    // This test asserts that the engine, not the parser, decides the scanning loop.
    let engine = RecoveryEngine::new();
    let reader = CodecReader { len: 3 * 1024 * 1024 };
    let profile = make_mock_profile();
    let parser = AlwaysRecognizeParser;

    let bounds = RecoveryBounds {
        max_scan_bytes: u64::MAX,
        max_scan_regions: 100,
        max_candidates: 100,
        max_hypotheses: 100,
        max_search_depth: None,
        cancel: CancelToken::new(),
        time_limit: None,
    };

    let run = engine.execute_recovery(request(&reader, &profile, &parser, &bounds)).unwrap().run;
    
    // The engine drove all 3 chunks (3 MB / 1 MB chunk = 3 regions)
    assert_eq!(run.searched_regions.len(), 3, "Engine should have driven 3 scan regions");
    assert_eq!(run.candidate_count, 3, "All 3 regions should have produced candidates");
}

/// Build a whole-image recovery request.
///
/// These mock parsers supply no `storage_geometry`/`recording_index`, so every run here
/// exercises the engine's no-index-evidence fallback: a full-window sweep whose
/// candidates can only reach `DataState::Unindexed`.
fn request<'a>(
    reader: &'a dyn EvidenceReader,
    profile: &'a OemProfile,
    parser: &'a dyn Parser,
    bounds: &'a RecoveryBounds,
) -> recovery::RecoveryRequest<'a> {
    recovery::RecoveryRequest {
        evidence_id: forensic_core::EvidenceId::new(),
        reader,
        profile,
        oem_key: "mock",
        parser,
        bounds,
        scan_window: None,
        read_window_bytes: None,
    }
}

#[test]
fn test_without_index_evidence_no_candidate_is_active() {
    // Regression guard for the original defect. `AlwaysRecognizeParser` returns
    // `Ok(true)` from `recognize_candidate` for every window — exactly what every OEM
    // parser used to do. That must no longer be able to produce `Active`, because it is
    // not index evidence.
    let engine = RecoveryEngine::new();
    let reader = CodecReader { len: 3 * 1024 * 1024 };
    let profile = make_mock_profile();
    let parser = AlwaysRecognizeParser;

    let bounds = RecoveryBounds {
        max_scan_bytes: u64::MAX,
        max_scan_regions: u32::MAX,
        max_candidates: 100,
        max_hypotheses: 100,
        max_search_depth: None,
        cancel: CancelToken::new(),
        time_limit: None,
    };

    let outcome = engine
        .execute_recovery(request(&reader, &profile, &parser, &bounds))
        .unwrap();

    assert!(!outcome.candidates.is_empty(), "codec bytes should be discovered");
    for c in &outcome.candidates {
        assert_eq!(
            c.data_state,
            forensic_core::DataState::Unindexed,
            "no index evidence exists, so nothing may be Active/Orphaned/Deleted"
        );
        assert_eq!(c.recovery_level, forensic_core::RecoveryLevel::L3);
    }
    assert_eq!(outcome.metrics.active_count, 0);
    assert_eq!(outcome.metrics.orphaned_count, 0);
    assert_eq!(outcome.metrics.deleted_count, 0);
    assert_eq!(outcome.metrics.unindexed_count, outcome.candidates.len());
    assert!(!outcome.metrics.authoritative_index);
}

#[test]
fn test_evidence_id_is_stable_across_every_candidate() {
    let engine = RecoveryEngine::new();
    let reader = CodecReader { len: 3 * 1024 * 1024 };
    let profile = make_mock_profile();
    let parser = AlwaysRecognizeParser;
    let evidence_id = forensic_core::EvidenceId::new();

    let bounds = RecoveryBounds {
        max_scan_bytes: u64::MAX,
        max_scan_regions: u32::MAX,
        max_candidates: 100,
        max_hypotheses: 100,
        max_search_depth: None,
        cancel: CancelToken::new(),
        time_limit: None,
    };

    let outcome = engine
        .execute_recovery(recovery::RecoveryRequest {
            evidence_id,
            reader: &reader,
            profile: &profile,
            oem_key: "mock",
            parser: &parser,
            bounds: &bounds,
            scan_window: None,
            read_window_bytes: None,
        })
        .unwrap();

    assert!(!outcome.candidates.is_empty());
    for c in &outcome.candidates {
        assert_eq!(
            c.provenance.source_evidence_id, evidence_id,
            "the engine must propagate the caller's EvidenceId, never mint one"
        );
        for sr in &c.provenance.source_regions {
            assert_eq!(sr.evidence_id, evidence_id);
        }
    }
    for f in &outcome.fragments {
        assert_eq!(f.evidence_id, evidence_id);
    }
}

#[test]
fn test_scan_window_preserves_absolute_physical_offsets() {
    let engine = RecoveryEngine::new();
    let reader = CodecReader { len: 4 * 1024 * 1024 };
    let profile = make_mock_profile();
    let parser = AlwaysRecognizeParser;

    let bounds = RecoveryBounds {
        max_scan_bytes: u64::MAX,
        max_scan_regions: u32::MAX,
        max_candidates: 100,
        max_hypotheses: 100,
        max_search_depth: None,
        cancel: CancelToken::new(),
        time_limit: None,
    };

    let window = forensic_core::Region::new(2 * 1024 * 1024, 1024 * 1024).unwrap();
    let outcome = engine
        .execute_recovery(recovery::RecoveryRequest {
            evidence_id: forensic_core::EvidenceId::new(),
            reader: &reader,
            profile: &profile,
            oem_key: "mock",
            parser: &parser,
            bounds: &bounds,
            scan_window: Some(window),
            read_window_bytes: None,
        })
        .unwrap();

    assert_eq!(outcome.run.searched_regions, vec![window]);
    assert_eq!(outcome.candidates.len(), 1);
    assert_eq!(
        outcome.candidates[0].source_offsets,
        vec![window],
        "offsets must stay absolute, never rebased to the window start"
    );
    assert_eq!(outcome.fragments[0].physical_region.offset, 2 * 1024 * 1024);
}
