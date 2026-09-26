//! CSV Report Exporters (Req 17.1, 17.2).
//!
//! Generates tabular CSV exports for recordings, recovery candidates, timeline events,
//! and validation matrices. Both state dimensions (DataState & RecoveryStatus) are
//! rendered in separate columns and never merged.

use crate::model::ForensicReport;

pub struct CsvReportExporter;

impl CsvReportExporter {
    /// Export recovered items to CSV string.
    pub fn export_recovery_csv(report: &ForensicReport) -> String {
        let mut out = String::from("candidate_id,channel,recovery_level,data_state,recovery_status,source_offset,source_length,validation_state,validation_reason,discovery_method,state_reason\n");
        for item in &report.recovery_items {
            // An absent channel is rendered "Unknown", never 0 — a CSV cell reading "0"
            // would be indistinguishable from a real channel 0.
            let channel = item
                .channel
                .map(|c| c.to_string())
                .unwrap_or_else(|| "Unknown".to_string());
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},\"{}\",{},\"{}\"\n",
                item.candidate_id,
                channel,
                item.recovery_level,
                item.data_state,
                item.recovery_status,
                item.source_offset,
                item.source_length,
                item.validation_state,
                item.validation_reason.replace('\"', "\"\""),
                item.discovery_method,
                item.state_reason.replace('\"', "\"\"")
            ));
        }
        out
    }

    /// Export recordings to CSV string.
    pub fn export_recordings_csv(report: &ForensicReport) -> String {
        let mut out = String::from("recording_id,channel,raw_timestamp,raw_format,recorder_native_time,normalized_time,timezone_state,codec,source_offset,source_length,validation_state\n");
        for rec in &report.recordings {
            out.push_str(&format!(
                "{},{},0x{:x},{},{},{},{},{},{},{},{}\n",
                rec.recording_id,
                rec.channel,
                rec.raw_timestamp,
                rec.raw_format,
                rec.recorder_native_time,
                rec.normalized_time,
                rec.timezone_state,
                rec.codec,
                rec.source_offset,
                rec.source_length,
                rec.validation_state
            ));
        }
        out
    }

    /// Export timeline events to CSV string.
    pub fn export_timeline_csv(report: &ForensicReport) -> String {
        let mut out = String::from(
            "channel,normalized_time,recorder_native_time,description,source_offset\n",
        );
        for evt in &report.timeline_events {
            out.push_str(&format!(
                "{},{},{},\"{}\",{}\n",
                evt.channel,
                evt.normalized_time,
                evt.recorder_native_time,
                evt.description.replace('\"', "\"\""),
                evt.source_offset
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use chrono::Utc;
    use forensic_core::{CapabilityStages, CaseId, EvidenceId, ExaminerId, Hash};

    fn test_report() -> ForensicReport {
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
                examiner_timezone: None,
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
            recovery_items: vec![RecoveryReportItem {
                candidate_id: "cand-1".into(),
                channel: Some(1),
                recovery_level: "L2".into(),
                data_state: "Orphaned".into(),
                recovery_status: "Recoverable".into(),
                source_offset: 1024,
                source_length: 512,
                validation_state: "PASS".into(),
                validation_reason: "Valid GOP".into(),
                discovery_method: "unclaimed-scan-in-index-scope".into(),
                state_reason: "authoritative index governs this region without referencing it"
                    .into(),
            }],
            recovery_run_bounds: None,
            timeline_events: vec![],
            native_artifacts: vec![],
            derived_artifacts: vec![],
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
    fn test_csv_recovery_columns_independent() {
        let report = test_report();
        let csv = CsvReportExporter::export_recovery_csv(&report);
        // Header contains separate columns for both dimensions
        assert!(csv.contains("data_state,recovery_status"));
        // Row contains Orphaned,Recoverable in separate columns
        assert!(csv.contains("cand-1,1,L2,Orphaned,Recoverable,1024,512,PASS,\"Valid GOP\""));
    }
}
