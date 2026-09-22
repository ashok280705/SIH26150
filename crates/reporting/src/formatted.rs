//! Formatted Forensic Report Document Exporter (Req 17.1, 17.2, 17.5).
//!
//! Generates a structured court-admissible forensic examination document
//! (in markdown / text format suitable for PDF conversion).
//!
//! Enforces:
//! - Clear separation of Capability Stages vs Validation States
//! - Defensible language: NEVER claims legal admissibility
//! - Strict Attribution Status labeling (e.g. "PROVISIONAL", "ATTRIBUTED", "UNRESOLVED")

use crate::model::ForensicReport;

pub struct FormattedReportExporter;

impl FormattedReportExporter {
    /// Renders a full forensic examination report in structured Markdown format.
    pub fn render_markdown_report(report: &ForensicReport) -> String {
        let mut doc = String::new();

        doc.push_str("# DIGITAL FORENSIC EXAMINATION REPORT\n\n");
        doc.push_str("## 1. Case & Examiner Information\n");
        doc.push_str(&format!("* **Report ID**: {}\n", report.report_id));
        doc.push_str(&format!("* **Generated At**: {}\n", report.generated_at.to_rfc3339()));
        doc.push_str(&format!("* **Examiner ID**: {}\n", report.examiner_id));
        doc.push_str(&format!("* **Case ID**: {}\n", report.case_id));
        doc.push_str(&format!("* **Evidence ID**: {}\n\n", report.evidence_id));

        doc.push_str("## 2. Evidence Target & Integrity\n");
        doc.push_str(&format!("* **Source Path**: {}\n", report.evidence_summary.source_path));
        doc.push_str(&format!("* **Image Format**: {}\n", report.evidence_summary.image_format));
        doc.push_str(&format!("* **Size**: {} bytes\n", report.evidence_summary.size_bytes));
        doc.push_str(&format!("* **SHA-256 Hash**: `{}`\n", report.evidence_summary.sha256));
        doc.push_str(&format!("* **Acquisition Status**: {}\n", report.evidence_summary.acquisition_status));
        doc.push_str(&format!("* **Source Safety**: {}\n\n", report.evidence_summary.source_safety_decision));

        doc.push_str("## 3. OEM Detection & Attribution\n");
        doc.push_str(&format!("* **Detection Status**: {}\n", report.detection_summary.detection_status));
        doc.push_str(&format!("* **Attribution Status**: {}\n", report.detection_summary.attribution_status));
        doc.push_str(&format!("* **Identified OEM**: {}\n", report.detection_summary.primary_oem.as_deref().unwrap_or("None")));
        doc.push_str(&format!("* **Confidence Score**: {:.2}\n", report.detection_summary.confidence_score));
        if let Some(prof) = &report.detection_summary.profile_id {
            doc.push_str(&format!("* **Applied Profile**: {} (v{})\n", prof, report.detection_summary.profile_version.as_deref().unwrap_or("1.0")));
        }
        doc.push_str("\n");

        doc.push_str("## 4. Recovered Video & Candidate Summary\n");
        doc.push_str("| Candidate ID | Channel | Level | DataState | RecoveryStatus | Source Offset | Validation | Why this state |\n");
        doc.push_str("|---|---|---|---|---|---|---|---|\n");
        for item in &report.recovery_items {
            // A candidate with no index-supplied channel is reported as "CH Unknown".
            // Printing "CH 0" would assert a channel the evidence never established.
            let channel = item
                .channel
                .map(|c| format!("CH {c}"))
                .unwrap_or_else(|| "CH Unknown".to_string());
            doc.push_str(&format!(
                "| {} | {} | {} | {} | {} | `0x{:x}` | {} ({}) | {} |\n",
                item.candidate_id,
                channel,
                item.recovery_level,
                item.data_state,
                item.recovery_status,
                item.source_offset,
                item.validation_state,
                item.validation_reason,
                if item.state_reason.is_empty() { "—" } else { &item.state_reason }
            ));
        }
        doc.push_str("\n");

        doc.push_str("## 5. Artifact Registry & Lineage\n");
        doc.push_str("### Native Original Artifacts\n");
        for a in &report.native_artifacts {
            doc.push_str(&format!("* **{}**: {} | SHA-256: `{}`\n", a.artifact_id, a.description, a.sha256));
        }
        doc.push_str("\n### Derived Transform Artifacts\n");
        for a in &report.derived_artifacts {
            doc.push_str(&format!("* **{}**: {} | SHA-256: `{}` (Produced by: {})\n", a.artifact_id, a.description, a.sha256, a.producing_component));
        }
        doc.push_str("\n");

        doc.push_str("## 6. Stated Forensic Limitations\n");
        for lim in &report.limitations {
            doc.push_str(&format!("{}\n", lim));
        }

        doc
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use chrono::Utc;
    use forensic_core::{CapabilityStages, CaseId, EvidenceId, ExaminerId, Hash};

    #[test]
    fn test_markdown_report_renders_defensible_structure() {
        let report = ForensicReport {
            report_id: "REP-001".into(),
            generated_at: Utc::now(),
            examiner_id: ExaminerId::new("Examiner 1"),
            case_id: CaseId::new(),
            evidence_id: EvidenceId::new(),
            evidence_summary: EvidenceSummaryReport {
                source_path: "/evidence/disk.dd".into(),
                image_format: "RAW".into(),
                size_bytes: 1024,
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
        };

        let md = FormattedReportExporter::render_markdown_report(&report);
        assert!(md.contains("DIGITAL FORENSIC EXAMINATION REPORT"));
        assert!(md.contains("Attribution Status"));
        assert!(md.contains("Stated Forensic Limitations"));
        assert!(md.contains("does not constitute a legal admissibility ruling"));
    }
}
