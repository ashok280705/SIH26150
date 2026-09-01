//! JSON Report Exporter (Req 17.1, 17.2, 20.1).
//!
//! Produces deterministic JSON exports with stable key ordering.

use crate::model::ForensicReport;
use forensic_core::ForensicError;

pub struct JsonReportExporter;

impl JsonReportExporter {
    /// Export report as formatted, deterministic JSON string.
    pub fn export_to_json(report: &ForensicReport) -> Result<String, ForensicError> {
        serde_json::to_string_pretty(report).map_err(|e| {
            ForensicError::io("export_to_json", std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use chrono::Utc;
    use forensic_core::{CapabilityStages, CaseId, EvidenceId, ExaminerId, Hash};

    fn dummy_report() -> ForensicReport {
        ForensicReport {
            report_id: "REP-001".into(),
            generated_at: Utc::now(),
            examiner_id: ExaminerId::new("Examiner 1"),
            case_id: CaseId::new(),
            evidence_id: EvidenceId::new(),
            evidence_summary: EvidenceSummaryReport {
                source_path: "/data/evidence.dd".into(),
                image_format: "RAW".into(),
                size_bytes: 1024 * 1024,
                sha256: Hash::sha256(vec![0; 32]),
                acquisition_status: "Complete".into(),
                source_safety_decision: "SafeReadOnly".into(),
            },
            detection_summary: DetectionSummaryReport {
                detection_status: "Detected".into(),
                classification: "Known".into(),
                attribution_status: "Attributed".into(),
                primary_oem: Some("Dahua".into()),
                confidence_score: 0.95,
                profile_id: Some("dahua-dhfs-v1.0".into()),
                profile_version: Some("1.0.0".into()),
                profile_hash: Some(Hash::sha256(vec![0; 32])),
                matched_rules: vec![],
            },
            capabilities: CapabilityStages::not_implemented(),
            validation_summary: vec![],
            recordings: vec![],
            recovery_items: vec![],
            recovery_run_bounds: None,
            timeline_events: vec![],
            native_artifacts: vec![],
            derived_artifacts: vec![],
            chain_of_custody: vec![],
            limitations: ForensicReport::standard_limitations(),
        }
    }

    #[test]
    fn test_json_export_roundtrip() {
        let report = dummy_report();
        let json_str = JsonReportExporter::export_to_json(&report).unwrap();
        assert!(json_str.contains("\"report_id\": \"REP-001\""));
        assert!(json_str.contains("\"primary_oem\": \"Dahua\""));

        let deserialized: ForensicReport = serde_json::from_str(&json_str).unwrap();
        assert_eq!(report.report_id, deserialized.report_id);
    }
}
