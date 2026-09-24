//! Uniview L1/L2/L3 recovery integration tests (Task 98 / Req 25.6).
//!
//! Asserts that Uniview recovery:
//! - Functions with the RecoveryEngine across L1/L2/L3
//! - Respects DataState / RecoveryStatus independence
//! - Handles missing DI / orphan DATA without claiming Overwritten
//! - Bounded search truncation yields REVIEW

use evidence_reader::{EvidenceReader, SourceKind};
use forensic_core::{CancelToken, ForensicError, OemProfile, RecoveryBounds, ValidationStateKind};
use parser_uniview::UniviewParser;
use recovery::RecoveryEngine;

struct UniviewMockReader {
    data: Vec<u8>,
}

impl EvidenceReader for UniviewMockReader {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
        if offset >= self.data.len() as u64 {
            return Err(ForensicError::out_of_bounds(
                "UniviewMockReader",
                offset,
                buf.len() as u64,
                self.data.len() as u64,
            ));
        }
        let available = ((self.data.len() as u64 - offset) as usize).min(buf.len());
        buf[..available].copy_from_slice(&self.data[offset as usize..offset as usize + available]);
        Ok(available)
    }

    fn source_kind(&self) -> SourceKind {
        SourceKind::Raw
    }

    fn source_path(&self) -> &str {
        "uniview://mock"
    }
}

fn make_uniview_profile() -> OemProfile {
    let toml_str = r#"
profile_id = "uniview-ubifs-v1.0"
profile_version = "1.0.0"
schema_version = "1.0"
oem = "uniview"
storage_family = "UBIFS"

[applicability]
models = ["NVR301", "NVR302", "NVR304", "NVR308"]
firmwares = []
storage_variants = ["ubifs_raw", "single_disk"]
reference = "Uniview NVR UBIFS Specification & Field Research 2024"

[[signatures]]
name = "ubifs_node_magic"
pattern_hex = "31 18 10 06"
evidence_status = "validated"
weight = 0.85
is_exclusive = true
explanation = "UBIFS node magic number at beginning of LEB node"

[confidence_weights]
max_possible_score = 1.0

[layout]
ec1001_start = 512
"#;
    OemProfile::from_toml_str(toml_str).expect("Failed to parse Uniview profile")
}

#[test]
fn test_uniview_recovery_full_scan() {
    let mut data = vec![0u8; 2 * 1024 * 1024]; // 2 MB
                                               // Set UBIFS magic at offset 0
    data[0..4].copy_from_slice(&[0x31, 0x18, 0x10, 0x06]);
    // Set Uniview marker at 512
    data[512] = b'U';

    let reader = UniviewMockReader { data };
    let profile = make_uniview_profile();
    let parser = UniviewParser::default();
    let engine = RecoveryEngine::new();

    let bounds = RecoveryBounds {
        max_scan_bytes: u64::MAX,
        max_scan_regions: 100,
        max_candidates: 100,
        max_hypotheses: 100,
        max_search_depth: None,
        cancel: CancelToken::new(),
        time_limit: None,
    };

    let run = engine
        .execute_recovery(request(&reader, &profile, &parser, &bounds))
        .unwrap()
        .run;
    assert_eq!(run.validation_state.state, ValidationStateKind::Pass);
    assert_eq!(run.searched_regions.len(), 2);
}

#[test]
fn test_uniview_recovery_truncated_yields_review() {
    let data = vec![0u8; 5 * 1024 * 1024]; // 5 MB
    let reader = UniviewMockReader { data };
    let profile = make_uniview_profile();
    let parser = UniviewParser::default();
    let engine = RecoveryEngine::new();

    let bounds = RecoveryBounds {
        max_scan_bytes: 2 * 1024 * 1024, // 2 MB cap
        max_scan_regions: 100,
        max_candidates: 100,
        max_hypotheses: 100,
        max_search_depth: None,
        cancel: CancelToken::new(),
        time_limit: None,
    };

    let run = engine
        .execute_recovery(request(&reader, &profile, &parser, &bounds))
        .unwrap()
        .run;
    assert!(run.truncated);
    assert_eq!(run.validation_state.state, ValidationStateKind::Review);
}

#[test]
fn test_uniview_missing_di_is_not_overwritten() {
    // When DI is missing, recovery classifies data as Orphaned, never Overwritten (Req 13.11)
    let assessment = recovery::classify_recovery(false, true, true, false);
    assert_eq!(assessment.data_state, forensic_core::DataState::Orphaned);
    assert_ne!(assessment.data_state, forensic_core::DataState::Overwritten);
}

/// Build a whole-image recovery request.
///
/// The Uniview parser supplies no storage geometry and no recording index, so these runs
/// exercise the engine's conservative fallback path.
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
        oem_key: "uniview",
        parser,
        bounds,
        scan_window: None,
        read_window_bytes: None,
    }
}

#[test]
fn test_uniview_has_no_index_reader_so_nothing_can_be_active() {
    // Uniview's parser has no index reader, so the engine must not be able to conclude
    // that any region is an active recording. Recognising a Uniview disk is not evidence
    // about any particular video region.
    let mut data = vec![0u8; 2 * 1024 * 1024];
    data[0..4].copy_from_slice(&[0x31, 0x18, 0x10, 0x06]);
    // A real H.264 Annex-B fragment so there is genuine video to discover.
    let h264: [u8; 24] = [
        0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1F, 0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x3C,
        0x80, 0x00, 0x00, 0x00, 0x01, 0x65, 0xB8, 0x00, 0x04,
    ];
    data[4096..4096 + h264.len()].copy_from_slice(&h264);

    let reader = UniviewMockReader { data };
    let profile = make_uniview_profile();
    let parser = UniviewParser::default();
    let engine = RecoveryEngine::new();

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

    assert!(!outcome.metrics.geometry_available);
    assert!(!outcome.metrics.authoritative_index);
    assert_eq!(outcome.metrics.active_count, 0);
    assert_eq!(outcome.metrics.orphaned_count, 0);
    for c in &outcome.candidates {
        assert_eq!(c.data_state, forensic_core::DataState::Unindexed);
    }
}
