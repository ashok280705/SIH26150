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
    chain_of_custody::CustodyEvent, CapabilityStages, CaseId, EvidenceId, ExaminerId, Hash,
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

    // ── Deep, stage-by-stage narrative sections (populated from the live run) ──
    // Each is optional so a run that halts early (or a unit test) can omit it.
    #[serde(default)]
    pub detection_depth: Option<DetectionDepthReport>,
    #[serde(default)]
    pub parsing_depth: Option<ParsingDepthReport>,
    #[serde(default)]
    pub preliminary_timeline: Option<PreliminaryTimelineReport>,
    #[serde(default)]
    pub recovery_depth: Option<RecoveryDepthReport>,
    #[serde(default)]
    pub final_timeline_summary: Option<FinalTimelineReport>,
}

/// A byte range `[offset, offset+length)` as reported to the reader.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegionReport {
    pub offset: u64,
    pub length: u64,
}

// ── Detection depth ───────────────────────────────────────────────────────

/// One structural indicator the detector probed, with where it was found.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchedIndicatorReport {
    /// Indicator kind (e.g. "dhfs_magic", "stream_packet_tag").
    pub kind: String,
    /// Byte offset in the image where the indicator was probed.
    pub offset: u64,
    /// Length of the probed indicator in bytes.
    pub length: u64,
    /// Whether the observed bytes matched the expected pattern.
    pub matched: bool,
    /// Profile maturity of the rule ("Validated", "Provisional", ...).
    pub evidence_status: String,
    /// Whether this indicator is exclusive evidence for the OEM.
    pub exclusive: bool,
    /// Score weight contributed by this indicator.
    pub weight: f64,
    /// Human-readable explanation of the indicator.
    pub explanation: String,
}

/// How the evidence's OEM/format was detected, and where.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionDepthReport {
    /// Total image size — the space detection operated within.
    pub image_size_bytes: u64,
    /// Description of the detection method (structural probes, not a full scan).
    pub method: String,
    pub storage_family: String,
    pub detector_status: String,
    pub confidence: f64,
    pub margin: f64,
    pub evidence_quality: f64,
    /// The runner-up OEM candidate, if any (drives the margin).
    pub runner_up: Option<String>,
    /// Every indicator the detector probed, with offsets.
    pub matched_indicators: Vec<MatchedIndicatorReport>,
    /// Candidate storage regions the detector considered (partitions/segments).
    pub candidate_regions: Vec<RegionReport>,
    /// Total bytes structurally examined across all probed indicators.
    pub bytes_examined: u64,
    /// Highest byte offset any indicator was probed at (the search reach).
    pub highest_offset_examined: u64,
}

// ── Parsing depth ─────────────────────────────────────────────────────────

/// One parsed recording/frame: where it was found and how it was confirmed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParsedFrameReport {
    pub channel: u32,
    pub recorder_native_time: String,
    pub normalized_time: String,
    /// Primary byte offset of the recording's stream payload.
    pub source_offset: u64,
    pub source_length: u64,
    /// Number of distinct byte regions attributed to this recording.
    pub region_count: usize,
    /// Codec classified from the actual stream bytes at the offset.
    pub codec: String,
    /// Number of Annex-B NAL units observed (how the frame was confirmed).
    pub nal_unit_count: usize,
    /// True when the codec classifier confirmed a decodable stream (SPS/PPS present).
    pub confirmed: bool,
    /// How the frame was confirmed (classifier reason).
    pub confirmation: String,
    /// Integrity anomalies the parser flagged for this recording, if any.
    pub integrity_flags: Vec<String>,
}

/// How recordings/frames were located and confirmed by the parser.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParsingDepthReport {
    pub parser_id: String,
    /// The parser stages that ran, with their validation outcome.
    pub stages: Vec<ValidationRecord>,
    pub total_recordings: usize,
    pub frames: Vec<ParsedFrameReport>,
}

// ── Preliminary timeline depth ──────────────────────────────────────────────

/// A missing window inside a recording, with the recoverable byte region.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionGapReport {
    pub starts_after: String,
    pub ends_before: String,
    pub missing_seconds: i64,
    pub previous_offset: u64,
    pub next_offset: u64,
}

/// One per-camera recording session with its coverage and gaps.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionReport {
    pub channel: u32,
    pub start: String,
    pub end: String,
    pub timezone: String,
    pub span_seconds: i64,
    pub covered_seconds: i64,
    pub missing_seconds: i64,
    pub coverage_ratio: f64,
    pub segment_count: usize,
    pub gaps: Vec<SessionGapReport>,
}

/// The preliminary timeline: which footage exists and where the gaps are.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PreliminaryTimelineReport {
    pub channel_count: usize,
    pub total_segments: usize,
    pub total_recordings: usize,
    pub total_missing_seconds: i64,
    /// Physical image attribution (bytes attributed to recordings / total).
    pub coverage_ratio: f64,
    pub accounted_bytes: u64,
    pub unaccounted_bytes: u64,
    pub total_bytes: u64,
    pub sessions: Vec<SessionReport>,
}

// ── Recovery depth ──────────────────────────────────────────────────────────

/// One recovery sub-slot probed inside a gap.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoverySlotReport {
    pub index: usize,
    /// "L1" | "L2" | "L3", or `None` when nothing could be carved.
    pub level: Option<String>,
    pub recovered: bool,
    pub start_offset_sec: i64,
    pub end_offset_sec: i64,
    pub offset: u64,
    pub length: u64,
    pub codec: String,
    pub nal_unit_count: usize,
    pub reason: String,
}

/// Recovery of one gap: the staged cascade result over its byte region.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GapRecoveryReport {
    pub channel: u32,
    pub scan_start: u64,
    pub scan_end: u64,
    /// Number of sub-slot probes attempted over this gap (each runs the L1→L2→L3 cascade).
    pub attempts: usize,
    pub total_seconds: i64,
    pub recovered_seconds: i64,
    pub unrecovered_seconds: i64,
    pub decision: String,
    pub slots: Vec<RecoverySlotReport>,
}

/// The recovery engine's staged results across all detected gaps.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveryDepthReport {
    /// Description of the staged recovery algorithm used.
    pub algorithm: String,
    pub searched_bytes: u64,
    pub total_bytes: u64,
    pub gaps_processed: usize,
    pub total_recovered_seconds: i64,
    pub total_unrecovered_seconds: i64,
    pub per_gap: Vec<GapRecoveryReport>,
}

// ── Final timeline summary ────────────────────────────────────────────────

/// The final timeline after folding in recovered footage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FinalTimelineReport {
    pub total_events: usize,
    pub recorded_events: usize,
    pub recovered_events: usize,
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
    pub recovery_status: String, // 'Recoverable', 'PartiallyRecoverable', 'Unrecoverable'
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
