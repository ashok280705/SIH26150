//! # pipeline
//!
//! The forensic pipeline orchestrator. This crate is the single place that runs the
//! stages of the investigation flow **in order** and records the outcome of every
//! decision gate, so the path taken through the flow is fully auditable.
//!
//! The flow implemented here mirrors the platform's pipeline diagram:
//!
//! ```text
//! Intake ─▶ Parallel OEM Detection ─▶ Evidence-based Extraction ─▶ Confidence Engine
//!        │
//!        ▼   ┌── Score > Threshold? ──┐
//!        │   YES                       NO
//!        ▼                             ▼
//!   OEM confirmed                 Ambiguous ─▶ Analyst Review
//!   OEM parser & extraction       Unresolved ─▶ Unified parser
//!        │                             │
//!        └────────── IS PARSED? ───────┘
//!             YES │            │ NO ─▶ revert to Analyst
//!                 ▼
//!   Preliminary Timeline (normalize, correlate, detect gaps, estimate coverage)
//!                 │
//!            ┌─ Gaps? ─┐
//!            YES        NO
//!            ▼           ▼
//!   Recovery Engine   Final Timeline
//!   (L1 / L2 / L3)
//!            │
//!       ┌ Recovery? ┐
//!  Completely/Partially   Not Recovered ─▶ revert to Analyst
//!            ▼
//!   Final Timeline ─▶ (reconstruction, correlation, report handled by the API layer)
//! ```
//!
//! Design constraints:
//! * **Pure orchestration.** No database, no network, no filesystem writes. It composes
//!   the stage engines over an `EvidenceReader` + `ProfileRegistry` and returns a
//!   `PipelineRun`. Persistence, FFmpeg reconstruction, and AI analytics are the API's job.
//! * **Every gate is recorded** with a machine value and a human reason. An unrun stage
//!   is `Skipped` with a reason, never silently treated as passed.
//! * **No attribution is invented.** The confidence engine's classification is honored; a
//!   below-threshold or ambiguous result routes to analyst review or the unified fallback
//!   rather than proceeding on a guessed OEM.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

use confidence::config::ConfidenceConfig;
use confidence::engine::ConfidenceEngine;
use confidence::result::{AttributionStatus, Classification};
use detection::orchestrator::DetectionOrchestrator;
use evidence_reader::EvidenceReader;
use forensic_core::{
    OemProfile, ProfileRegistry, RecoveryCandidate, RecoveryRun, Region, TimelineEvent,
    ValidationStateKind,
};
use parsing::orchestrator::{ParsingResult, UNIFIED_OEM_KEY};
use parsing::ParsingOrchestrator;
use timeline::gaps::{self, GapAnalysis};
use timeline::{
    build_recording_timeline_with_examiner_tz, CorrelatedEventGroup, CrossCameraCorrelator,
    RecordingTimeline, TimelineEngine, TimelineOrdering, UnifiedTimeline,
};

/// A node in the pipeline flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStage {
    Intake,
    Detection,
    Confidence,
    ThresholdGate,
    OemExtraction,
    UnifiedExtraction,
    AnalystReview,
    ParsedGate,
    PreliminaryTimeline,
    GapGate,
    Recovery,
    RecoveryGate,
    FinalTimeline,
}

/// Whether a stage ran, was skipped, or halted the flow pending an analyst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageStatus {
    Completed,
    Skipped,
    RequiresAnalyst,
}

/// A record of one stage's execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StageRecord {
    pub stage: PipelineStage,
    pub status: StageStatus,
    pub detail: String,
}

/// The decision taken at the "Score > Threshold?" gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdDecision {
    /// Attributed to a supported OEM above threshold and margin.
    OemConfirmed,
    /// Multiple candidates within the margin — routed to analyst review.
    Ambiguous,
    /// No candidate reached threshold — routed to the unified fallback parser.
    Unresolved,
}

/// The decision at the "IS PARSED?" gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseDecision {
    Parsed,
    NotParsed,
}

/// The decision at the "Gaps?" gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapDecision {
    GapsPresent,
    NoGaps,
}

/// The decision at the "Recovery?" gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryDecision {
    CompletelyRecovered,
    PartiallyRecovered,
    NotRecovered,
}

/// A recorded gate decision with its justification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "gate", rename_all = "snake_case")]
pub enum GateRecord {
    Threshold {
        decision: ThresholdDecision,
        confidence: f64,
        min_confidence: f64,
        margin: f64,
        min_margin: f64,
        reason: String,
    },
    Parsed {
        decision: ParseDecision,
        reason: String,
    },
    Gaps {
        decision: GapDecision,
        reason: String,
    },
    Recovery {
        decision: RecoveryDecision,
        reason: String,
    },
}

/// Compact attribution summary carried on the run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttributionSummary {
    pub oem_key: String,
    pub classification: Classification,
    pub attribution_status: AttributionStatus,
    pub confidence: f64,
    pub margin: f64,
    pub evidence_quality: f64,
    pub explanation: String,
}

/// Recovery stage output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoverySummary {
    pub candidates: Vec<RecoveryCandidate>,
    /// Fragment record per candidate, index-aligned with `candidates`.
    ///
    /// Carries each candidate's physical location, discovery method, and the recorder
    /// metadata that was — or explicitly was not — established. Reporting reads channel
    /// and timestamp from here rather than substituting zero.
    pub fragments: Vec<recovery::DiscoveredFragment>,
    /// The fragments grouped into recordings by the correlation stage, with the evidence for
    /// every grouping and ordering decision.
    ///
    /// This is the answer to "how many recordings were recovered?", which `candidates` is not:
    /// a carved recording of four hundred container records is four hundred candidates and one
    /// recording. A group whose order could not be established from evidence says so
    /// explicitly rather than presenting physical order as a timeline.
    #[serde(default)]
    pub recordings: Vec<recovery::CorrelatedRecording>,
    /// What the OEM parser actually established about this evidence item, capability by
    /// capability — runtime evidence, distinct from the declared `CapabilityStages` maturity.
    pub capabilities: recovery::RecoveryCapabilities,
    /// Which recovery strategies those capabilities licensed, and the recorded reason for
    /// each strategy that was not applied.
    pub strategies: recovery::StrategySelection,
    pub run: RecoveryRun,
    /// Observability counters: geometry, index entry count, claimed/unclaimed byte
    /// totals, and the per-state candidate breakdown.
    pub metrics: recovery::RecoveryMetrics,
    pub decision: RecoveryDecision,
}

/// The terminal disposition of a pipeline run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineOutcome {
    /// Parsed cleanly, no gaps, final timeline built.
    CompletedNoGaps,
    /// Gaps were found and recovery filled them enough to finalize.
    CompletedAfterRecovery,
    /// Gaps remained after a partial recovery; final timeline built with caveats.
    CompletedPartialRecovery,
    /// The flow halted pending human analyst review.
    RequiresAnalyst,
}

/// Knobs for a pipeline run. Defaults match the platform's provisional policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineOptions {
    /// Continuity threshold, in seconds, above which a per-channel gap is reported.
    pub max_gap_seconds: i64,
    /// Smallest unaccounted byte span reported as a coverage hole.
    pub min_unaccounted_bytes: u64,
    /// Time-window, in seconds, for cross-camera correlation.
    pub correlation_window_seconds: i64,
    /// Timeline ordering mode for the preliminary and final timelines.
    pub ordering: TimelineOrdering,
    /// Cap on bytes the recovery engine will scan.
    pub max_recovery_scan_bytes: Option<u64>,
    /// Smallest shortfall (relative to a channel's measured cadence) reported as an
    /// in-recording gap. Below this, a spacing is treated as normal jitter.
    pub min_recording_gap_seconds: i64,
    /// A per-channel silence at least this long begins a new recording session rather
    /// than being reported as an in-recording gap.
    pub session_split_seconds: i64,
    /// Optional examiner-established timezone (external evidence, not inferred from disk).
    #[serde(default)]
    pub examiner_timezone: Option<forensic_core::ExaminerTimezone>,
}

impl Default for PipelineOptions {
    fn default() -> Self {
        Self {
            max_gap_seconds: 120,
            min_unaccounted_bytes: 64 * 1024,
            correlation_window_seconds: 5,
            ordering: TimelineOrdering::Normalized,
            max_recovery_scan_bytes: None,
            min_recording_gap_seconds: 30,
            session_split_seconds: 3600,
            examiner_timezone: None,
        }
    }
}

/// The full, auditable result of a pipeline run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineRun {
    pub stages: Vec<StageRecord>,
    pub gates: Vec<GateRecord>,
    pub attribution: Option<AttributionSummary>,
    /// The parser key actually used (an OEM key, or the unified fallback).
    pub oem_key_used: Option<String>,
    pub used_unified_fallback: bool,
    pub parsing: Option<ParsingResult>,
    pub preliminary_timeline: Option<UnifiedTimeline>,
    /// Per-camera recording sessions: start/end, in-recording gaps, and coverage,
    /// derived from the parser's recordings and sorted chronologically by date.
    pub recordings_timeline: Option<RecordingTimeline>,
    pub gap_analysis: Option<GapAnalysis>,
    pub recovery: Option<RecoverySummary>,
    pub final_timeline: Option<UnifiedTimeline>,
    pub correlation_groups: Vec<CorrelatedEventGroup>,
    pub outcome: PipelineOutcome,
    pub requires_analyst: bool,
    pub analyst_reasons: Vec<String>,
}

impl PipelineRun {
    fn record_stage(
        &mut self,
        stage: PipelineStage,
        status: StageStatus,
        detail: impl Into<String>,
    ) {
        self.stages.push(StageRecord {
            stage,
            status,
            detail: detail.into(),
        });
    }
}

/// A minimal, OEM-neutral profile for the unified fallback parser.
///
/// This is generic pipeline configuration, not OEM factual knowledge, so embedding it
/// here does not violate the "OEM facts live in profiles/" rule.
fn unified_profile() -> OemProfile {
    OemProfile::from_toml_str(
        r#"
profile_id = "unified-fallback-v1.0"
profile_version = "1.0.0"
schema_version = "1.0"
oem = "unified"
storage_family = "GENERIC"
[applicability]
models = []
firmwares = []
storage_variants = []
[[signatures]]
name = "annexb_startcode"
pattern_hex = "00 00 01"
evidence_status = "provisional"
weight = 0.1
is_exclusive = false
explanation = "Annex-B NAL start code, used by the generic carving fallback"
[confidence_weights]
max_possible_score = 1.0
"#,
    )
    .expect("embedded unified fallback profile must parse")
}

/// Does the parser output represent a real parse?
///
/// Parsed = at least one recording was produced, OR at least one parser stage
/// affirmatively passed. A run of only `not_run`/`review` with no recordings is treated
/// as NotParsed so it routes back to the analyst rather than being reported as success.
fn is_parsed(result: &ParsingResult) -> bool {
    if !result.recordings.is_empty() {
        return true;
    }
    result
        .parser_runs
        .iter()
        .any(|r| r.validation_state.state == ValidationStateKind::Pass)
}

/// Collect the byte regions attributed to recordings, for coverage estimation.
fn recording_regions(result: &ParsingResult) -> Vec<Region> {
    result
        .recordings
        .iter()
        .flat_map(|r| r.source_offsets.iter().cloned())
        .collect()
}

/// Turn recovered candidates into timeline events so the final timeline reflects them.
///
/// # Only candidates with real recorder metadata are placed on the timeline
///
/// `TimelineEvent` requires a concrete channel and a concrete raw timestamp; the type has
/// no representation for "channel unknown" or "time unknown". Previously every recovered
/// candidate was inserted as channel 0 at timestamp 0, which puts fabricated metadata on
/// the examiner's timeline.
///
/// So a candidate is only converted when its fragment carries a channel **and** a
/// timestamp that came from index evidence. Candidates carved out of unclaimed space — the
/// orphaned and unindexed findings — are deliberately withheld from the timeline and
/// reported through `PipelineRun::recovery` instead, where their unknowns stay unknown.
/// Placing them on the timeline is a task for the later temporal-reconstruction phase,
/// once the timeline model can express an unknown camera and clock.
///
/// Returns the events plus the number of candidates withheld for lack of metadata.
fn candidates_to_events(
    candidates: &[RecoveryCandidate],
    fragments: &[recovery::DiscoveredFragment],
) -> (Vec<TimelineEvent>, usize) {
    use forensic_core::identifiers::ProfileId;
    use forensic_core::{RawTimestamp, TimeEvidence, TimeZoneState};

    let mut events = Vec::new();
    let mut withheld = 0usize;

    for (c, f) in candidates.iter().zip(fragments.iter()) {
        let region = c.source_offsets.first().cloned().unwrap_or(Region {
            offset: 0,
            length: 0,
        });

        let (Some(channel), Some(ts)) = (f.camera_id.value(), f.timestamp_unix.value()) else {
            withheld += 1;
            continue;
        };
        let Ok(raw_value) = u64::try_from(*ts) else {
            withheld += 1;
            continue;
        };

        // The candidate's own provenance is reused verbatim rather than a fresh one being
        // built: it already carries the real evidence id, the real source regions, the real
        // content hashes computed by the scanner, and the recovery level. Rebuilding it here
        // with placeholder digests is what previously broke the chain between a timeline event
        // and the bytes behind it.
        let prov = c.provenance.clone();
        let content_hash = prov.output_hash.clone();
        let event_profile_hash = prov.profile_hash.clone().unwrap_or(content_hash);
        let time = TimeEvidence {
            raw: RawTimestamp {
                value: raw_value,
                format: "UNIX_LE".into(),
                source: prov,
            },
            recorder_native: None,
            normalized: None,
            reference: None,
            // The recorder's zone is not established by recovery, so it stays Unknown.
            timezone: TimeZoneState::Unknown,
            correction: None,
        };
        events.push(TimelineEvent::new(
            *channel,
            time,
            format!(
                "Recovered {:?} candidate {} ({:?}/{:?}) at 0x{:X}, {} via {}",
                c.recovery_level,
                f.fragment_id,
                c.data_state,
                c.recovery_status,
                region.offset,
                f.codec,
                f.discovery_method.label()
            ),
            vec![region],
            "recovery-engine".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
            ProfileId(f.profile_id.clone()),
            // The profile hash the scanner actually applied, when it recorded one. Falling back
            // to the candidate's content digest keeps the field a real digest rather than a
            // zero-filled placeholder that would read as a verified hash in a report.
            event_profile_hash,
        ));
    }

    (events, withheld)
}

/// Run the full pipeline over one piece of evidence.
///
/// Returns a `PipelineRun` capturing every stage and gate. Errors only on
/// unrecoverable I/O; forensic "negative" outcomes (unresolved, not parsed, not
/// recovered) are represented in the run, not as errors.
/// `evidence_id` identifies the evidence item being processed and is propagated into
/// every recovery candidate's provenance. It is a required parameter rather than something
/// the pipeline mints, so a recovered candidate is always traceable back to the registered
/// evidence item it came from.
pub fn run_pipeline(
    evidence_id: forensic_core::EvidenceId,
    reader: &dyn EvidenceReader,
    registry: &ProfileRegistry,
    config: &ConfidenceConfig,
    options: &PipelineOptions,
) -> Result<PipelineRun, forensic_core::ForensicError> {
    let mut run = PipelineRun {
        stages: Vec::new(),
        gates: Vec::new(),
        attribution: None,
        oem_key_used: None,
        used_unified_fallback: false,
        parsing: None,
        preliminary_timeline: None,
        recordings_timeline: None,
        gap_analysis: None,
        recovery: None,
        final_timeline: None,
        correlation_groups: Vec::new(),
        outcome: PipelineOutcome::RequiresAnalyst,
        requires_analyst: false,
        analyst_reasons: Vec::new(),
    };

    // ── Stage: Intake ───────────────────────────────────────────────────────
    run.record_stage(
        PipelineStage::Intake,
        StageStatus::Completed,
        format!("Evidence opened read-only, {} bytes", reader.len()),
    );

    // ── Stage: Detection + Confidence ───────────────────────────────────────
    let detector_outputs = DetectionOrchestrator::new().run(reader, registry)?;
    run.record_stage(
        PipelineStage::Detection,
        StageStatus::Completed,
        format!(
            "{} detector(s) evaluated in parallel",
            detector_outputs.len()
        ),
    );

    let classified = ConfidenceEngine::classify_all(&detector_outputs, registry, config)?;
    let top = classified.first().cloned();
    run.record_stage(
        PipelineStage::Confidence,
        StageStatus::Completed,
        match &top {
            Some(t) => format!(
                "Top candidate '{}' scored {:.3} ({})",
                t.detector_output.oem_key, t.confidence, t.classification
            ),
            None => "No detector produced a candidate".to_string(),
        },
    );

    // ── Gate: Score > Threshold? ────────────────────────────────────────────
    let (threshold_decision, oem_key) = match &top {
        Some(t) => {
            run.attribution = Some(AttributionSummary {
                oem_key: t.detector_output.oem_key.clone(),
                classification: t.classification,
                attribution_status: t.attribution_status,
                confidence: t.confidence,
                margin: t.margin,
                evidence_quality: t.evidence_quality,
                explanation: t.explanation.clone(),
            });
            match t.classification {
                Classification::Confirmed | Classification::CompatibleCandidate => (
                    ThresholdDecision::OemConfirmed,
                    Some(t.detector_output.oem_key.clone()),
                ),
                Classification::Ambiguous => (ThresholdDecision::Ambiguous, None),
                Classification::Unknown | Classification::Insufficient => {
                    (ThresholdDecision::Unresolved, None)
                }
            }
        }
        None => (ThresholdDecision::Unresolved, None),
    };

    let (conf, margin) = top
        .as_ref()
        .map(|t| (t.confidence, t.margin))
        .unwrap_or((0.0, 0.0));
    run.gates.push(GateRecord::Threshold {
        decision: threshold_decision,
        confidence: conf,
        min_confidence: config.min_confidence,
        margin,
        min_margin: config.min_margin,
        reason: match threshold_decision {
            ThresholdDecision::OemConfirmed => format!(
                "Confidence {:.3} ≥ threshold {:.3} with margin {:.3} ≥ {:.3}: OEM attribution accepted",
                conf, config.min_confidence, margin, config.min_margin
            ),
            ThresholdDecision::Ambiguous => format!(
                "Candidates within the {:.3} margin (top {:.3}): routed to analyst review",
                config.min_margin, conf
            ),
            ThresholdDecision::Unresolved => format!(
                "No candidate reached threshold {:.3} (top {:.3}): routed to the unified fallback parser",
                config.min_confidence, conf
            ),
        },
    });
    run.record_stage(
        PipelineStage::ThresholdGate,
        StageStatus::Completed,
        format!("{threshold_decision:?}"),
    );

    // ── Stage: Extraction (OEM, Unified, or halt for Analyst) ───────────────
    let orchestrator = ParsingOrchestrator::new();
    let parsing_result: ParsingResult = match threshold_decision {
        ThresholdDecision::OemConfirmed => {
            let key = oem_key.clone().unwrap();
            let profile = registry
                .find_applicable(&key, None, None, None)
                .ok_or_else(|| {
                    forensic_core::ForensicError::corrupt(
                        "pipeline",
                        format!("attributed OEM '{key}' has no applicable profile"),
                    )
                })?;
            let result = orchestrator.run_parsing(&key, reader, profile)?;
            run.oem_key_used = Some(key.clone());
            run.record_stage(
                PipelineStage::OemExtraction,
                StageStatus::Completed,
                format!(
                    "OEM parser '{}' extracted {} recording(s)",
                    key,
                    result.recordings.len()
                ),
            );
            result
        }
        ThresholdDecision::Ambiguous => {
            // Analyst review is required; the flow halts here with everything gathered
            // so far. This is a real terminal outcome, not an error.
            run.record_stage(
                PipelineStage::AnalystReview,
                StageStatus::RequiresAnalyst,
                "Ambiguous attribution: analyst must confirm OEM or dispatch the unified parser",
            );
            run.requires_analyst = true;
            run.analyst_reasons.push(
                "Confidence engine returned Ambiguous — multiple OEM candidates scored within the margin".to_string(),
            );
            run.outcome = PipelineOutcome::RequiresAnalyst;
            return Ok(run);
        }
        ThresholdDecision::Unresolved => {
            // Unresolved -> Unified parser branch.
            let profile = unified_profile();
            let result = orchestrator.run_parsing(UNIFIED_OEM_KEY, reader, &profile)?;
            run.oem_key_used = Some(UNIFIED_OEM_KEY.to_string());
            run.used_unified_fallback = true;
            run.record_stage(
                PipelineStage::UnifiedExtraction,
                StageStatus::Completed,
                format!(
                    "Unified fallback carved {} region(s)",
                    result.recordings.len()
                ),
            );
            result
        }
    };

    // ── Gate: IS PARSED? ────────────────────────────────────────────────────
    let parsed = is_parsed(&parsing_result);
    run.gates.push(GateRecord::Parsed {
        decision: if parsed {
            ParseDecision::Parsed
        } else {
            ParseDecision::NotParsed
        },
        reason: if parsed {
            format!(
                "{} recording(s) and {} passing stage(s): evidence parsed",
                parsing_result.recordings.len(),
                parsing_result
                    .parser_runs
                    .iter()
                    .filter(|r| r.validation_state.state == ValidationStateKind::Pass)
                    .count()
            )
        } else {
            "No recordings and no passing parser stage: not parsed".to_string()
        },
    });

    if !parsed {
        run.record_stage(
            PipelineStage::ParsedGate,
            StageStatus::RequiresAnalyst,
            "Parser produced nothing usable; reverting to analyst",
        );
        run.parsing = Some(parsing_result);
        run.requires_analyst = true;
        run.analyst_reasons
            .push("Selected parser produced no recordings and no passing validation".to_string());
        run.outcome = PipelineOutcome::RequiresAnalyst;
        return Ok(run);
    }
    run.record_stage(PipelineStage::ParsedGate, StageStatus::Completed, "Parsed");

    // ── Per-recording sessions (start/end, in-recording gaps, coverage) ─────
    // Built from the parser's own recordings and sorted by date, this is the
    // investigator-facing "which recordings exist and what is missing inside them"
    // view that complements the event-level unified timeline.
    let recordings_timeline = build_recording_timeline_with_examiner_tz(
        &parsing_result.recordings,
        options.min_recording_gap_seconds,
        options.session_split_seconds,
        options.examiner_timezone.as_ref(),
    );
    let tz_info = if let Some(ex) = &options.examiner_timezone {
        format!(
            "; normalized to UTC using examiner-established timezone '{}' (basis: '{}')",
            ex.timezone, ex.source
        )
    } else {
        String::new()
    };
    run.record_stage(
        PipelineStage::PreliminaryTimeline,
        StageStatus::Completed,
        format!(
            "Grouped {} recording segment(s) into {} recording(s) across {} channel(s); {}s missing{}",
            recordings_timeline.total_segments,
            recordings_timeline.total_recordings,
            recordings_timeline.channel_count,
            recordings_timeline.total_missing_seconds,
            tz_info
        ),
    );
    run.recordings_timeline = Some(recordings_timeline);

    // ── Stage: Preliminary Timeline (normalize, correlate, detect gaps) ─────
    let preliminary =
        TimelineEngine::build_timeline(parsing_result.timeline_events.clone(), options.ordering);
    run.correlation_groups = CrossCameraCorrelator::correlate_events(
        &preliminary.events,
        options.correlation_window_seconds,
    );
    run.record_stage(
        PipelineStage::PreliminaryTimeline,
        StageStatus::Completed,
        format!(
            "Built preliminary timeline of {} event(s); {} cross-camera group(s)",
            preliminary.events.len(),
            run.correlation_groups.len()
        ),
    );

    let gap_analysis = gaps::analyze(
        &preliminary.events,
        recording_regions(&parsing_result),
        reader.len(),
        options.max_gap_seconds,
        options.min_unaccounted_bytes,
    );

    // ── Gate: Gaps? ─────────────────────────────────────────────────────────
    let gaps_present = gap_analysis.gaps_present;
    run.gates.push(GateRecord::Gaps {
        decision: if gaps_present {
            GapDecision::GapsPresent
        } else {
            GapDecision::NoGaps
        },
        reason: gap_analysis.validation.reason.clone(),
    });
    run.record_stage(
        PipelineStage::GapGate,
        StageStatus::Completed,
        if gaps_present {
            "Gaps present -> recovery"
        } else {
            "No gaps -> final timeline"
        },
    );

    // ── Stage: Recovery (only when gaps are present) ────────────────────────
    let mut final_events = preliminary.events.clone();
    if gaps_present {
        let scan_cap = options.max_recovery_scan_bytes.unwrap_or(reader.len());
        let bounds = forensic_core::RecoveryBounds {
            max_scan_bytes: scan_cap,
            max_scan_regions: u32::MAX,
            max_candidates: u32::MAX,
            max_hypotheses: 1024,
            max_search_depth: None,
            cancel: forensic_core::CancelToken::new(),
            time_limit: None,
        };
        // The recovery engine needs a parser + profile to vet candidates. Reuse the
        // same one the extraction stage used (OEM or unified fallback).
        let key = run
            .oem_key_used
            .clone()
            .unwrap_or_else(|| UNIFIED_OEM_KEY.to_string());
        let unified = unified_profile();
        let profile = registry
            .find_applicable(&key, None, None, None)
            .unwrap_or(&unified);
        let parser = orchestrator.parser_for(&key);

        if let Some(parser) = parser {
            let engine = recovery::RecoveryEngine::new();
            // Index-aware recovery: the parser's storage geometry and recording index (if
            // it has them) decide which physical ranges are claimed, and the complement
            // becomes the search space. A parser without an index reader falls back to a
            // whole-image sweep whose candidates can only be reported as unindexed.
            let outcome = engine.execute_recovery(recovery::RecoveryRequest {
                evidence_id,
                reader,
                profile,
                oem_key: &key,
                parser,
                bounds: &bounds,
                scan_window: None,
                read_window_bytes: None,
            })?;
            let recovery::RecoveryOutcome {
                candidates,
                fragments,
                recordings,
                capabilities,
                strategies,
                run: rec_run,
                metrics,
                ..
            } = outcome;

            let accepted = candidates
                .iter()
                .filter(|c| {
                    !matches!(
                        c.recovery_status,
                        forensic_core::RecoveryStatus::Unrecoverable
                    )
                })
                .count();
            let any_partial = candidates.iter().any(|c| {
                matches!(
                    c.recovery_status,
                    forensic_core::RecoveryStatus::PartiallyRecoverable
                )
            });

            let decision = if accepted == 0 {
                RecoveryDecision::NotRecovered
            } else if rec_run.truncated || any_partial {
                RecoveryDecision::PartiallyRecovered
            } else {
                RecoveryDecision::CompletelyRecovered
            };

            // State breakdown, so the gate reason distinguishes confirming active
            // recordings from discovering video the index no longer references.
            let breakdown = format!(
                "{} active, {} orphaned, {} unindexed, {} corrupted",
                metrics.active_count,
                metrics.orphaned_count,
                metrics.unindexed_count,
                metrics.corrupted_count
            );
            let index_note = if metrics.authoritative_index {
                format!(
                    "authoritative index claimed {} byte(s) in {} range(s); {} byte(s) unclaimed",
                    metrics.claimed_bytes, metrics.claimed_range_count, metrics.unclaimed_bytes
                )
            } else {
                "no authoritative recording index was established, so no orphan conclusion is available".to_string()
            };

            run.gates.push(GateRecord::Recovery {
                decision,
                reason: match decision {
                    RecoveryDecision::CompletelyRecovered => format!(
                        "{accepted} candidate(s) recovered ({breakdown}), scan complete: gaps addressed. {index_note}"
                    ),
                    RecoveryDecision::PartiallyRecovered => format!(
                        "{accepted} candidate(s) recovered ({breakdown}) but scan was truncated or partial: gaps only partly addressed. {index_note}"
                    ),
                    RecoveryDecision::NotRecovered => {
                        format!("No recoverable candidates found in the gap regions. {index_note}")
                    }
                },
            });

            // Fold recovered candidates into the final timeline. Candidates with no
            // recorder metadata are withheld rather than placed at channel 0 / time 0.
            let (recovered_events, withheld) = candidates_to_events(&candidates, &fragments);
            if withheld > 0 {
                run.analyst_reasons.push(format!(
                    "{withheld} recovered candidate(s) carry no recorder channel or timestamp and \
                     were not placed on the timeline; they are reported under recovery with their \
                     exact physical offsets and unknown metadata preserved"
                ));
            }
            final_events.extend(recovered_events);

            match decision {
                RecoveryDecision::NotRecovered => {
                    run.record_stage(
                        PipelineStage::Recovery,
                        StageStatus::Completed,
                        "Recovery scan found no usable candidates",
                    );
                    run.record_stage(
                        PipelineStage::RecoveryGate,
                        StageStatus::RequiresAnalyst,
                        "Not recovered: reverting to analyst",
                    );
                    run.requires_analyst = true;
                    run.analyst_reasons.push(
                        "Gaps were detected but recovery produced no usable candidates".to_string(),
                    );
                    run.outcome = PipelineOutcome::RequiresAnalyst;
                }
                RecoveryDecision::PartiallyRecovered => {
                    run.record_stage(
                        PipelineStage::Recovery,
                        StageStatus::Completed,
                        format!("{accepted} candidate(s) partially recovered"),
                    );
                    run.record_stage(
                        PipelineStage::RecoveryGate,
                        StageStatus::Completed,
                        "Partially recovered",
                    );
                    run.outcome = PipelineOutcome::CompletedPartialRecovery;
                }
                RecoveryDecision::CompletelyRecovered => {
                    run.record_stage(
                        PipelineStage::Recovery,
                        StageStatus::Completed,
                        format!("{accepted} candidate(s) recovered"),
                    );
                    run.record_stage(
                        PipelineStage::RecoveryGate,
                        StageStatus::Completed,
                        "Recovered",
                    );
                    run.outcome = PipelineOutcome::CompletedAfterRecovery;
                }
            }

            run.recovery = Some(RecoverySummary {
                candidates,
                fragments,
                recordings,
                capabilities,
                strategies,
                run: rec_run,
                metrics,
                decision,
            });
        } else {
            run.record_stage(
                PipelineStage::Recovery,
                StageStatus::Skipped,
                format!("No parser registered for '{key}'; recovery skipped"),
            );
        }
    } else {
        run.record_stage(
            PipelineStage::Recovery,
            StageStatus::Skipped,
            "No gaps; recovery not required",
        );
        run.outcome = PipelineOutcome::CompletedNoGaps;
    }

    // ── Stage: Final Timeline ───────────────────────────────────────────────
    // Rebuilt including any recovered events, re-ordered canonically.
    let final_timeline = TimelineEngine::build_timeline(final_events, options.ordering);
    run.record_stage(
        PipelineStage::FinalTimeline,
        // Built either way; whether an analyst is needed is recorded on the run itself.
        StageStatus::Completed,
        format!(
            "Final timeline built with {} event(s)",
            final_timeline.events.len()
        ),
    );

    run.parsing = Some(parsing_result);
    run.preliminary_timeline = Some(preliminary);
    run.gap_analysis = Some(gap_analysis);
    run.final_timeline = Some(final_timeline);

    Ok(run)
}
