//! # Phase 1 Foundational Test Suite
//!
//! Enforces release gates and correctness properties (P1–P4) for Phase 1 (Req 1.1, 1.4, 1.10, 8.2, 8.3, 8.6, 8.10, 8.11, 19.6, 20.1, 24.1, 24.2, 24.3, 24.4):
//! - Property 1: Read-only enforcement (WriteGuard rejection + logged CustodyEvent, source hash unchanged)
//! - Property 2: Bounded memory scanning
//! - Property 3: Read fidelity (concatenated chunked reads equal direct reads)
//! - Property 4: Determinism repeat check
//! - Hostile input contract: no panic on extreme offsets or malformed inputs

use std::fs;

use evidence_reader::{
    inspect_source, EvidenceReader, RawReader, RegionScanner, SafetyDecision, ScanOptions,
};
use forensic_core::case::SourceState;
use forensic_core::chain_of_custody::{CustodyAction, CustodyLog};
use forensic_core::checked::{checked_add, checked_mul, checked_sub, validate_bounds};
use forensic_core::determinism::{
    compare_forensic_results, ComparisonResult, ComponentVersions, DeterminismKey, ForensicResult,
    ResultMetadata,
};
use forensic_core::write_guard::WriteGuard;
use forensic_core::{CaseId, ExaminerId, Hash, Region};
use forensic_tests::fixtures::{generate_fixture, FixtureShape, OemShape};
use hashing::HashingService;

/// Property 1: Read-only enforcement & WriteGuard rejection with audit logging.
#[test]
fn property_1_read_only_enforcement_and_audit() {
    let temp_dir = std::env::temp_dir().join(format!("p1_prop1_{}", uuid::Uuid::new_v4()));
    let evidence_dir = temp_dir.join("evidence");
    let artifacts_dir = temp_dir.join("artifacts");
    fs::create_dir_all(&evidence_dir).unwrap();
    fs::create_dir_all(&artifacts_dir).unwrap();

    let fixture = generate_fixture(OemShape::Dahua, FixtureShape::Normal, 100);
    let evidence_file = evidence_dir.join("evidence.raw");
    fs::write(&evidence_file, &fixture.bytes).unwrap();

    let reader = RawReader::open(&evidence_file).unwrap();
    let initial_hash = HashingService::hash_reader(&reader, 4096, None, None).unwrap();

    let guard = WriteGuard::new(&evidence_dir, &artifacts_dir);
    let mut log = CustodyLog::new();
    let case_id = CaseId::new();
    let examiner = ExaminerId::new("examiner-p1");

    // Attempted write inside evidence dir MUST be rejected
    let target = evidence_dir.join("malicious.txt");
    let write_res = guard.guard_write(&target, case_id, examiner, &mut log, |_| Ok(()));

    assert!(write_res.is_err());
    assert_eq!(log.len(), 1);
    assert_eq!(log.events()[0].action, CustodyAction::WriteDenied);

    // Verify evidence file remains bit-for-bit unchanged
    let after_hash = HashingService::hash_reader(&reader, 4096, None, None).unwrap();
    assert_eq!(initial_hash.value, after_hash.value);

    let _ = fs::remove_dir_all(&temp_dir);
}

/// Property 2: Bounded memory scanning over large sparse fixture.
#[test]
fn property_2_bounded_memory_scanning() {
    let fixture = generate_fixture(OemShape::Uniview, FixtureShape::Sparse, 200);
    let temp_dir = std::env::temp_dir().join(format!("p1_prop2_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();
    let path = temp_dir.join("sparse.raw");
    fs::write(&path, &fixture.bytes).unwrap();

    let reader = RawReader::open(&path).unwrap();
    let target_region = Region::new(0, reader.len()).unwrap();

    // Use bounded 512-byte window
    let options = ScanOptions {
        window_size: 512,
        alignment: 1,
        max_scan_bytes: None,
    };
    let scanner = RegionScanner::new(&reader, target_region, options).unwrap();

    let mut scanned_chunks = 0;
    let report = scanner
        .scan(None, None, |_offset, _chunk| {
            scanned_chunks += 1;
            Ok(true)
        })
        .unwrap();

    assert!(report.is_complete());
    assert_eq!(report.searched_bytes, reader.len());
    assert!(scanned_chunks > 10); // Proves windowed chunking occurred

    let _ = fs::remove_dir_all(&temp_dir);
}

/// Property 3: Read fidelity (windowed concatenation equals direct read).
#[test]
fn property_3_read_fidelity_and_concatenation() {
    let fixture = generate_fixture(OemShape::Hikvision, FixtureShape::Normal, 300);
    let temp_dir = std::env::temp_dir().join(format!("p1_prop3_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();
    let path = temp_dir.join("normal.raw");
    fs::write(&path, &fixture.bytes).unwrap();

    let reader = RawReader::open(&path).unwrap();
    let direct_bytes = reader.read_exact_at(100, 2048).unwrap();

    let target_region = Region::new(100, 2048).unwrap();
    let options = ScanOptions {
        window_size: 256,
        alignment: 1,
        max_scan_bytes: None,
    };
    let scanner = RegionScanner::new(&reader, target_region, options).unwrap();

    let mut windowed_bytes = Vec::new();
    let report = scanner
        .scan(None, None, |_offset, chunk| {
            windowed_bytes.extend_from_slice(chunk);
            Ok(true)
        })
        .unwrap();

    assert_eq!(report.searched_bytes, 2048);
    assert_eq!(direct_bytes, windowed_bytes);

    let _ = fs::remove_dir_all(&temp_dir);
}

/// Property 4: Determinism repeat check.
#[test]
fn property_4_determinism_repeat_check() {
    let key = DeterminismKey {
        evidence_hash: Hash::sha256(vec![0x42; 32]),
        profile_version: "dahua-v1.0".into(),
        profile_hash: Hash::sha256(vec![0x43; 32]),
        config_version: "conf-1.0".into(),
        config_hash: Hash::sha256(vec![0x44; 32]),
        recovery_config: None,
        component_versions: ComponentVersions {
            detector_version: "0.1.0".into(),
            parser_version: "0.1.0".into(),
            confidence_engine_version: "0.1.0".into(),
            recovery_engine_version: "0.1.0".into(),
        },
    };

    let result_1 = ForensicResult {
        key: key.clone(),
        forensic_fields: serde_json::json!({
            "status": "confirmed",
            "extracted_count": 42
        }),
        metadata: ResultMetadata {
            execution_timestamp: Some("2026-09-01T12:00:00Z".into()),
            db_ids: vec!["db-01".into()],
            temp_paths: vec!["/tmp/a".into()],
            durations_ms: vec![120],
        },
    };

    let result_2 = ForensicResult {
        key,
        forensic_fields: serde_json::json!({
            "status": "confirmed",
            "extracted_count": 42
        }),
        metadata: ResultMetadata {
            execution_timestamp: Some("2026-09-01T12:05:00Z".into()), // Changed metadata!
            db_ids: vec!["db-99".into()],
            temp_paths: vec!["/tmp/b".into()],
            durations_ms: vec![999],
        },
    };

    assert_eq!(
        compare_forensic_results(&result_1, &result_2),
        ComparisonResult::Equal
    );
}

/// Adversarial: Source safety rejection on write-enabled device.
#[test]
fn adversarial_source_safety_rejection() {
    let report_rw = inspect_source(SourceState::ReadWrite);
    assert_eq!(report_rw.decision, SafetyDecision::Rejected);

    let report_unknown = inspect_source(SourceState::Unknown);
    assert_eq!(report_unknown.decision, SafetyDecision::Accepted);
    assert_eq!(report_unknown.source_state, SourceState::Unknown); // Never fabricated as ReadOnly
}

/// Adversarial: Checked arithmetic rejects overflow without panic.
#[test]
fn adversarial_checked_arithmetic_overflow() {
    assert!(checked_add(u64::MAX, 1).is_err());
    assert!(checked_mul(u64::MAX, 2).is_err());
    assert!(checked_sub(10, 20).is_err());
    assert!(validate_bounds(u64::MAX - 10, 20, 100).is_err());
}
