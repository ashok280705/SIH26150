//! Forensic Report Model (Req 17.1, 17.2, 17.5).
//!
//! Aggregates the complete forensic evaluation for a case/evidence:
//! - Case & Evidence Metadata + SHA-256 Hashes
//! - Source Safety & Acquisition Status
//! - OEM Detection (Attribution status, supporting evidence with both status axes)
//! - Capability Stages (reported independently of Validation States)
//! - Validation States with mandatory reasons (no unearned PASS)
//! - Two-dimensional Recovery results (DataState + RecoveryStatus)
//! - Unified Timeline with raw/native timestamp preservation
//! - Native vs Derived Artifact registry with complete Provenance
//! - Chain of Custody log
//! - Defensible limitations (Req 17.5 — never claims legal admissibility)

use chrono::{DateTime, Utc};
use forensic_core::{
    chain_of_custody::CustodyEvent,
    CapabilityStages, CaseId, EvidenceId, ExaminerId, Hash,
};
use serde::{Deserialize, Serialize};

/// Comprehensive forensic report aggregating all analysis stages.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForensicReport {
    pub report_id: String,
    pub generated_at: DateTime<Utc>,
    pub examiner_id: ExaminerId,
    pub case_id: CaseId,
    pub evidence_id: EvidenceId,

    // 1. Evidence & Integrity Section
    pub evidence_summary: EvidenceSummaryReport,

    // 2. OEM Detection & Attribution Section
    pub detection_summary: DetectionSummaryReport,

    // 3. Capabilities & Validation Section (Maturity vs Outcome separated)
    pub capabilities: CapabilityStages,
    pub validation_summary: Vec<ValidationRecord>,

    // 4. Recordings & Recovery Section (Two-dimensional state maintained)
    pub recordings: Vec<RecordingReportItem>,
    pub recovery_items: Vec<RecoveryReportItem>,
    pub recovery_run_bounds: Option<RecoveryRunBoundsReport>,

    // 5. Timeline & Cross-Camera Section
    pub timeline_events: Vec<TimelineReportItem>,

    // 6. Artifact Registry (Native vs Derived separated)
    pub native_artifacts: Vec<ArtifactReportItem>,
    pub derived_artifacts: Vec<ArtifactReportItem>,

    // 7. Chain of Custody History
    pub chain_of_custody: Vec<CustodyEvent>,

    // 8. Stated Forensic Limitations (Req 17.5)
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceSummaryReport {
    pub source_path: String,
    pub image_format: String,
    pub size_bytes: u64,
    pub sha256: Hash,
    pub acquisition_status: String,
    pub source_safety_decision: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionSummaryReport {
    pub detection_status: String,
    pub classification: String,
    pub attribution_status: String,
    pub primary_oem: Option<String>,
    pub confidence_score: f64,
    pub profile_id: Option<String>,
    pub profile_version: Option<String>,
    pub profile_hash: Option<Hash>,
    pub matched_rules: Vec<RuleMatchReportItem>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleMatchReportItem {
    pub rule_name: String,
    pub pattern_hex: String,
    pub evidence_status: String,
    pub rule_match_status: String,
    pub match_offset: u64,
    pub weight: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationRecord {
    pub operation: String,
    pub subject: String,
    pub state: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordingReportItem {
    pub recording_id: String,
    pub channel: u32,
    pub raw_timestamp: u64,
    pub raw_format: String,
    pub recorder_native_time: String,
    pub normalized_time: String,
    pub timezone_state: String,
    pub codec: String,
    pub source_offset: u64,
    pub source_length: u64,
    pub validation_state: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveryReportItem {
    pub candidate_id: String,
    /// `None` when no index entry supplied a channel. Video carved from unclaimed space
    /// has no channel, and a report must say "unknown" rather than print channel 0.
    pub channel: Option<u32>,
    pub recovery_level: String, // 'L1', 'L2', 'L3'
    /// `'Active' | 'Deleted' | 'Orphaned' | 'Unindexed' | 'Corrupted' | 'Overwritten'`.
    ///
    /// `Orphaned` and `Unindexed` are distinct findings and must be reported as such:
    /// `Orphaned` means an authoritative index governs those bytes without referencing
    /// them, while `Unindexed` records that no index statement covers them at all.
    /// Neither is a deletion finding.
    pub data_state: String,
    pub recovery_status: String,// 'Recoverable', 'PartiallyRecoverable', 'Unrecoverable'
    pub source_offset: u64,
    pub source_length: u64,
    pub validation_state: String,
    pub validation_reason: String,
    /// How this candidate was found: an index-claimed probe, or a scan of unclaimed space.
    #[serde(default)]
    pub discovery_method: String,
    /// Why this candidate received its `data_state`, in examiner-readable prose. Present
    /// so an `Orphaned` or `Unindexed` finding in a report is never unexplained.
    #[serde(default)]
    pub state_reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveryRunBoundsReport {
    pub searched_bytes: u64,
    pub total_bytes: u64,
    pub truncated: bool,
    pub cancelled: bool,
    pub candidate_count: u32,
    pub accepted_count: u32,
    pub rejected_count: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineReportItem {
    pub channel: u32,
    pub normalized_time: String,
    pub recorder_native_time: String,
    pub description: String,
    pub source_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactReportItem {
    pub artifact_id: String,
    pub classification: String, // 'Native' or 'Derived'
    pub description: String,
    pub sha256: Hash,
    pub producing_component: String,
}

impl ForensicReport {
    /// Default standard forensic limitations boilerplate (Req 17.5).
    pub fn standard_limitations() -> Vec<String> {
        vec![
            "1. This forensic examination was conducted using read-only analysis tools.".into(),
            "2. Attribution is based on probabilistic signature matching and storage layout profiles.".into(),
            "3. Overwritten data regions are physically irrecoverable; no replaced content was synthesized.".into(),
            "4. Timestamps with 'Unknown' timezone status reflect uncalibrated native DVR clocks.".into(),
            "5. This technical report details scientific findings and does not constitute a legal admissibility ruling.".into(),
        ]
    }
}
