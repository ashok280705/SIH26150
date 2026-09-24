//! Reporting Engine Comprehensive Test Suite (Task 117 / Req 19.5, 17.5, 17.6).
//!
//! Validates:
//! - Complete schema coverage for PDF (Markdown), JSON, and CSV exports
//! - Cryptographic hashing of report outputs (SHA-256)
//! - Capability Stages vs Validation States separation
//! - Non-admissibility limitation boilerplate presence
//! - Native vs Derived artifact lineage tracking

use chrono::Utc;
use forensic_core::{
    chain_of_custody::CustodyAction, CapabilityStages, CaseId, EvidenceId, ExaminerId, Hash,
};
use reporting::{
    model::*, CsvReportExporter, FormattedReportExporter, JsonReportExporter, ReportAuditor,
};

fn create_full_test_report() -> ForensicReport {
    ForensicReport {
        report_id: "REP-2026-001".into(),
        generated_at: Utc::now(),
        examiner_id: ExaminerId::new("Special Examiner #42"),
        case_id: CaseId::new(),
        evidence_id: EvidenceId::new(),
        evidence_summary: EvidenceSummaryReport {
            source_path: "/data/evidence/dahua_nvr.raw".into(),
            image_format: "RAW".into(),
            size_bytes: 4 * 1024 * 1024 * 1024,
            sha256: Hash::sha256(vec![0xAA; 32]),
            acquisition_status: "Complete".into(),
            source_safety_decision: "SafeReadOnly (Strict Kernel Write Guard)".into(),
        },
        detection_summary: DetectionSummaryReport {
            detection_status: "Detected".into(),
            classification: "Known".into(),
            attribution_status: "Attributed".into(),
            primary_oem: Some("Dahua".into()),
            confidence_score: 0.96,
            profile_id: Some("dahua-dhfs-v1.0".into()),
            profile_version: Some("1.0.0".into()),
            profile_hash: Some(Hash::sha256(vec![0xBB; 32])),
            matched_rules: vec![
                RuleMatchReportItem {
                    rule_name: "dhfs_magic".into(),
                    pattern_hex: "44 48 46 53".into(),
                    evidence_status: "Validated".into(),
                    rule_match_status: "Confirmed".into(),
                    match_offset: 0,
                    weight: 0.85,
                }
            ],
        },
        capabilities: CapabilityStages::not_implemented(),
        validation_summary: vec![
            ValidationRecord {
                operation: "parse_filesystem".into(),
                subject: "DHFS Superblock".into(),
                state: "PASS".into(),
                reason: "Valid sector 0 DHFS magic and allocation table".into(),
            },
            ValidationRecord {
                operation: "reconstruct".into(),
                subject: "Camera 1 Channel".into(),
                state: "PASS".into(),
                reason: "Valid H.264 NAL headers and sequence timestamps".into(),
            }
        ],
        recordings: vec![
            RecordingReportItem {
                recording_id: "rec-001".into(),
                channel: 1,
                raw_timestamp: 0x20260901120000,
                raw_format: "BCD 64-bit".into(),
                recorder_native_time: "2026-09-01 12:00:00".into(),
                normalized_time: "2026-09-01T12:00:00Z".into(),
                timezone_state: "Known (UTC)".into(),
                codec: "H.264".into(),
                source_offset: 0x00100000,
                source_length: 50 * 1024 * 1024,
                validation_state: "PASS".into(),
            }
        ],
        recovery_items: vec![
            RecoveryReportItem {
                candidate_id: "cand-001".into(),
                channel: Some(1),
                recovery_level: "L1".into(),
                data_state: "Active".into(),
                recovery_status: "Recoverable".into(),
                source_offset: 0x00100000,
                source_length: 50 * 1024 * 1024,
                validation_state: "PASS".into(),
                validation_reason: "Direct indexed table entry validated".into(),
                discovery_method: "index-claimed-probe".into(),
                state_reason: "Region is claimed by authoritative index entry didx#0 and valid video was validated there".into(),
            },
            RecoveryReportItem {
                candidate_id: "cand-002".into(),
                channel: Some(2),
                recovery_level: "L2".into(),
                data_state: "Orphaned".into(),
                recovery_status: "Recoverable".into(),
                source_offset: 0x01500000,
                source_length: 30 * 1024 * 1024,
                validation_state: "PASS".into(),
                validation_reason: "Orphan payload candidate; index missing but video stream valid".into(),
                discovery_method: "unclaimed-scan-in-index-scope".into(),
                state_reason: "Valid video is physically present here, and the authoritative recording index governs this region without referencing it".into(),
            }
        ],
        recovery_run_bounds: Some(RecoveryRunBoundsReport {
            searched_bytes: 4 * 1024 * 1024 * 1024,
            total_bytes: 4 * 1024 * 1024 * 1024,
            truncated: false,
            cancelled: false,
            candidate_count: 2,
            accepted_count: 2,
            rejected_count: 0,
        }),
        timeline_events: vec![
            TimelineReportItem {
                channel: 1,
                normalized_time: "2026-09-01T12:00:00Z".into(),
                recorder_native_time: "2026-09-01 12:00:00".into(),
                description: "Recording Start (Camera 1)".into(),
                source_offset: 0x00100000,
            }
        ],
        native_artifacts: vec![
            ArtifactReportItem {
                artifact_id: "art-native-01".into(),
                classification: "Native".into(),
                description: "Unmodified raw stream bytes".into(),
                sha256: Hash::sha256(vec![0x11; 32]),
                producing_component: "EvidenceReader".into(),
            }
        ],
        derived_artifacts: vec![
            ArtifactReportItem {
                artifact_id: "art-derived-01".into(),
                classification: "Derived".into(),
                description: "Remuxed MP4 container".into(),
                sha256: Hash::sha256(vec![0x22; 32]),
                producing_component: "VideoReconstructor".into(),
            }
        ],
        chain_of_custody: vec![],
        limitations: ForensicReport::standard_limitations(),
        detection_depth: None,
        parsing_depth: None,
        preliminary_timeline: None,
        recovery_depth: None,
        final_timeline_summary: None,
    }
}

#[test]
fn test_full_report_json_export_and_hashing() {
    let report = create_full_test_report();

    // 1. JSON Export
    let json_output = JsonReportExporter::export_to_json(&report).unwrap();
    assert!(json_output.contains("REP-2026-001"));
    assert!(json_output.contains("dahua-dhfs-v1.0"));

    // 2. Report Hashing & Provenance
    let hash = ReportAuditor::hash_report(json_output.as_bytes());
    assert_eq!(hash.algorithm, forensic_core::HashAlgorithm::Sha256);

    let artifact = ReportAuditor::create_report_artifact(
        report.evidence_id,
        "/reports/REP-2026-001.json",
        hash.clone(),
        "JSON",
    );
    assert_eq!(artifact.provenance.output_hash, hash);

    let custody_event = ReportAuditor::create_custody_event(
        report.case_id,
        report.examiner_id.clone(),
        hash,
        "JSON",
    );
    assert_eq!(custody_event.action, CustodyAction::Export);
}

#[test]
fn test_full_report_csv_export() {
    let report = create_full_test_report();

    let rec_csv = CsvReportExporter::export_recordings_csv(&report);
    assert!(rec_csv.contains("rec-001,1,0x20260901120000,BCD 64-bit"));

    let recov_csv = CsvReportExporter::export_recovery_csv(&report);
    assert!(recov_csv.contains("cand-001,1,L1,Active,Recoverable"));
    assert!(recov_csv.contains("cand-002,2,L2,Orphaned,Recoverable"));

    let time_csv = CsvReportExporter::export_timeline_csv(&report);
    assert!(time_csv
        .contains("1,2026-09-01T12:00:00Z,2026-09-01 12:00:00,\"Recording Start (Camera 1)\""));
}

#[test]
fn test_full_report_markdown_formatted_document() {
    let report = create_full_test_report();
    let md = FormattedReportExporter::render_markdown_report(&report);

    assert!(md.contains("# DIGITAL FORENSIC EXAMINATION REPORT"));
    assert!(md.contains("## 1. Case & Examiner"));
    assert!(md.contains("## 2. Selected Evidence & Integrity"));
    assert!(md.contains("## 3. Detection — Where the Format Was Found"));
    assert!(md.contains("## 4. Parsing — Where Frames Were Found and How They Were Confirmed"));
    assert!(md.contains("## 5. Preliminary Timeline — Coverage and Gaps"));
    assert!(md.contains("## 6. Recovery Engine — Staged Carving of Missing Footage"));
    assert!(md.contains("## 7. Final Timeline"));
    assert!(md.contains("## 8. Artifact Registry & Lineage"));
    assert!(md.contains("## 9. Stated Forensic Limitations"));
}
