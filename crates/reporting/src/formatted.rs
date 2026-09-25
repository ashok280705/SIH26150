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
    /// Renders the full stage-by-stage forensic examination report in Markdown:
    /// Case → Evidence → Detection → Parsing → Preliminary Timeline → Recovery →
    /// Final Timeline → Artifacts → Limitations.
    pub fn render_markdown_report(report: &ForensicReport) -> String {
        let mut doc = String::new();

        doc.push_str("# DIGITAL FORENSIC EXAMINATION REPORT\n\n");

        // ── 1. Case & Examiner ───────────────────────────────────────────────
        doc.push_str("## 1. Case & Examiner\n");
        doc.push_str(&format!("* **Report ID**: {}\n", report.report_id));
        doc.push_str(&format!(
            "* **Generated At**: {}\n",
            report.generated_at.to_rfc3339()
        ));
        doc.push_str(&format!("* **Examiner ID**: {}\n", report.examiner_id));
        doc.push_str(&format!("* **Case ID**: {}\n", report.case_id));
        doc.push_str(&format!("* **Evidence ID**: {}\n\n", report.evidence_id));

        // ── 2. Selected evidence & integrity ─────────────────────────────────
        doc.push_str("## 2. Selected Evidence & Integrity\n");
        doc.push_str(&format!(
            "* **Source Path**: {}\n",
            report.evidence_summary.source_path
        ));
        doc.push_str(&format!(
            "* **Image Format**: {}\n",
            report.evidence_summary.image_format
        ));
        doc.push_str(&format!(
            "* **Size**: {} bytes\n",
            report.evidence_summary.size_bytes
        ));
        doc.push_str(&format!(
            "* **SHA-256**: `{}`\n",
            report.evidence_summary.sha256
        ));
        doc.push_str(&format!(
            "* **Acquisition**: {}\n",
            report.evidence_summary.acquisition_status
        ));
        doc.push_str(&format!(
            "* **Source Safety**: {}\n\n",
            report.evidence_summary.source_safety_decision
        ));

        // ── 3. Detection — where the format was found ────────────────────────
        doc.push_str("## 3. Detection — Where the Format Was Found\n");
        doc.push_str(&format!(
            "* **Detection Status**: {}\n",
            report.detection_summary.detection_status
        ));
        doc.push_str(&format!(
            "* **Identified OEM**: {}\n",
            report
                .detection_summary
                .primary_oem
                .as_deref()
                .unwrap_or("None")
        ));
        doc.push_str(&format!(
            "* **Attribution Status**: {}\n",
            report.detection_summary.attribution_status
        ));
        doc.push_str(&format!(
            "* **Confidence**: {:.1}%\n",
            report.detection_summary.confidence_score * 100.0
        ));
        if let Some(dd) = &report.detection_depth {
            doc.push_str(&format!("* **Storage Family**: {}\n", dd.storage_family));
            let runner = dd
                .runner_up
                .as_ref()
                .map(|r| format!(" (vs {r})"))
                .unwrap_or_default();
            doc.push_str(&format!(
                "* **Margin over runner-up**: {:.3}{}\n",
                dd.margin, runner
            ));
            doc.push_str(&format!(
                "* **Evidence Quality**: {:.2}\n",
                dd.evidence_quality
            ));
            doc.push_str(&format!(
                "* **Search reach**: probed up to offset `0x{:X}` within a {}-byte image; {} bytes structurally examined.\n",
                dd.highest_offset_examined, dd.image_size_bytes, dd.bytes_examined
            ));
            doc.push_str(&format!("* **Method**: {}\n\n", dd.method));
            if !dd.matched_indicators.is_empty() {
                doc.push_str("**Signature indicators (where each was found):**\n\n");
                doc.push_str(
                    "| Indicator | Offset | Len | Matched | Status | Weight | Exclusive |\n",
                );
                doc.push_str("|---|---|---|---|---|---|---|\n");
                for m in &dd.matched_indicators {
                    doc.push_str(&format!(
                        "| {} | `0x{:X}` | {} | {} | {} | {:.2} | {} |\n",
                        m.kind,
                        m.offset,
                        m.length,
                        if m.matched { "yes" } else { "no" },
                        m.evidence_status,
                        m.weight,
                        if m.exclusive { "yes" } else { "no" }
                    ));
                }
                doc.push('\n');
            }
            if !dd.candidate_regions.is_empty() {
                let regions: Vec<String> = dd
                    .candidate_regions
                    .iter()
                    .map(|r| {
                        format!(
                            "`0x{:X}..0x{:X}`",
                            r.offset,
                            r.offset.saturating_add(r.length)
                        )
                    })
                    .collect();
                doc.push_str(&format!(
                    "**Candidate storage regions considered:** {}\n\n",
                    regions.join(", ")
                ));
            }
        } else {
            doc.push('\n');
        }

        // ── 4. Parsing — where frames were found & how confirmed ─────────────
        doc.push_str("## 4. Parsing — Where Frames Were Found and How They Were Confirmed\n");
        if let Some(pd) = &report.parsing_depth {
            doc.push_str(&format!("* **Parser**: {}\n", pd.parser_id));
            doc.push_str(&format!(
                "* **Recordings located**: {}\n\n",
                pd.total_recordings
            ));
            if !pd.stages.is_empty() {
                doc.push_str("**Parser stages:**\n\n");
                doc.push_str("| Stage | Subject | Outcome | Reason |\n|---|---|---|---|\n");
                for s in &pd.stages {
                    doc.push_str(&format!(
                        "| {} | {} | {} | {} |\n",
                        s.operation, s.subject, s.state, s.reason
                    ));
                }
                doc.push('\n');
            }
            if !pd.frames.is_empty() {
                doc.push_str("**Located recordings (offset + confirmation):**\n\n");
                doc.push_str("| Ch | Native Time | Offset | Length | Codec | NAL Units | Confirmed | Integrity |\n");
                doc.push_str("|---|---|---|---|---|---|---|---|\n");
                for f in &pd.frames {
                    let integ = if f.integrity_flags.is_empty() {
                        "clean".to_string()
                    } else {
                        f.integrity_flags.join(", ")
                    };
                    doc.push_str(&format!(
                        "| {} | {} | `0x{:X}` | {} | {} | {} | {} | {} |\n",
                        f.channel,
                        f.recorder_native_time,
                        f.source_offset,
                        f.source_length,
                        f.codec,
                        f.nal_unit_count,
                        if f.confirmed { "yes" } else { "review" },
                        integ
                    ));
                }
                doc.push('\n');
            }
        } else {
            doc.push_str("_No parsing stage output available._\n\n");
        }

        // ── 5. Preliminary timeline — coverage & gaps ────────────────────────
        doc.push_str("## 5. Preliminary Timeline — Coverage and Gaps\n");
        if let Some(pt) = &report.preliminary_timeline {
            doc.push_str(&format!(
                "* **{} recording(s)** across **{} channel(s)**, {} segment(s); **{}s** of footage missing.\n",
                pt.total_recordings, pt.channel_count, pt.total_segments, pt.total_missing_seconds
            ));
            doc.push_str(&format!(
                "* **Image attribution**: {:.1}% ({} of {} bytes attributed to recordings; {} bytes unallocated).\n\n",
                pt.coverage_ratio * 100.0, pt.accounted_bytes, pt.total_bytes, pt.unaccounted_bytes
            ));
            for s in &pt.sessions {
                doc.push_str(&format!(
                    "* **Channel {}** {} → {} ({}): {:.1}% covered · {}s recorded · {}s missing\n",
                    s.channel,
                    s.start,
                    s.end,
                    s.timezone,
                    s.coverage_ratio * 100.0,
                    s.covered_seconds,
                    s.missing_seconds
                ));
                for g in &s.gaps {
                    doc.push_str(&format!(
                        "    * gap {} → {}: {}s missing, bytes `0x{:X}..0x{:X}`\n",
                        g.starts_after,
                        g.ends_before,
                        g.missing_seconds,
                        g.previous_offset,
                        g.next_offset
                    ));
                }
            }
            doc.push('\n');
        } else {
            doc.push_str("_No preliminary timeline available._\n\n");
        }

        // ── 6. Recovery — staged carving ─────────────────────────────────────
        doc.push_str("## 6. Recovery Engine — Staged Carving of Missing Footage\n");
        if let Some(rd) = &report.recovery_depth {
            doc.push_str(&format!("* **Algorithm**: {}\n", rd.algorithm));
            doc.push_str(&format!("* **Gaps processed**: {}\n", rd.gaps_processed));
            doc.push_str(&format!(
                "* **Bytes searched**: {} of {}\n",
                rd.searched_bytes, rd.total_bytes
            ));
            doc.push_str(&format!(
                "* **Recovered**: {}s · **Not recovered**: {}s\n\n",
                rd.total_recovered_seconds, rd.total_unrecovered_seconds
            ));
            doc.push_str("| Ch | Byte Region | Attempts | Recovered | Missing | Decision |\n");
            doc.push_str("|---|---|---|---|---|---|\n");
            for gap in &rd.per_gap {
                doc.push_str(&format!(
                    "| {} | `0x{:X}..0x{:X}` | {} | {}s | {}s | {} |\n",
                    gap.channel,
                    gap.scan_start,
                    gap.scan_end,
                    gap.attempts,
                    gap.recovered_seconds,
                    gap.unrecovered_seconds,
                    gap.decision
                ));
            }
            doc.push('\n');
        } else {
            doc.push_str("_No recovery was required (no in-recording gaps), or no gap produced a recoverable region._\n\n");
        }

        // ── 7. Final timeline ────────────────────────────────────────────────
        doc.push_str("## 7. Final Timeline\n");
        if let Some(ft) = &report.final_timeline_summary {
            doc.push_str(&format!(
                "* **{} event(s)** total: {} recorded + {} recovered folded in.\n\n",
                ft.total_events, ft.recorded_events, ft.recovered_events
            ));
        } else {
            doc.push_str("_No final timeline available._\n\n");
        }

        // ── 8. Artifact registry ─────────────────────────────────────────────
        doc.push_str("## 8. Artifact Registry & Lineage\n");
        doc.push_str("### Native Original Artifacts\n");
        if report.native_artifacts.is_empty() {
            doc.push_str("_None._\n");
        }
        for a in &report.native_artifacts {
            doc.push_str(&format!(
                "* **{}**: {} | SHA-256: `{}`\n",
                a.artifact_id, a.description, a.sha256
            ));
        }
        doc.push_str("\n### Derived Transform Artifacts\n");
        if report.derived_artifacts.is_empty() {
            doc.push_str("_None._\n");
        }
        for a in &report.derived_artifacts {
            doc.push_str(&format!(
                "* **{}**: {} | SHA-256: `{}` (Produced by: {})\n",
                a.artifact_id, a.description, a.sha256, a.producing_component
            ));
        }
        doc.push('\n');

        // ── 9. Limitations ───────────────────────────────────────────────────
        doc.push_str("## 9. Stated Forensic Limitations\n");
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
            detection_depth: None,
            parsing_depth: None,
            preliminary_timeline: None,
            recovery_depth: None,
            final_timeline_summary: None,
        };

        let md = FormattedReportExporter::render_markdown_report(&report);
        assert!(md.contains("DIGITAL FORENSIC EXAMINATION REPORT"));
        assert!(md.contains("Attribution Status"));
        assert!(md.contains("Stated Forensic Limitations"));
        assert!(md.contains("does not constitute a legal admissibility ruling"));
    }
}
