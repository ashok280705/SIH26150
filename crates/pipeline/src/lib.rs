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
use timeline::{CrossCameraCorrelator, CorrelatedEventGroup, TimelineEngine, TimelineOrdering, UnifiedTimeline};

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
    pub run: RecoveryRun,
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
}

impl Default for PipelineOptions {
    fn default() -> Self {
        Self {
            max_gap_seconds: 120,
            min_unaccounted_bytes: 64 * 1024,
            correlation_window_seconds: 5,
            ordering: TimelineOrdering::Normalized,
            max_recovery_scan_bytes: None,
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
    pub gap_analysis: Option<GapAnalysis>,
    pub recovery: Option<RecoverySummary>,
    pub final_timeline: Option<UnifiedTimeline>,
    pub correlation_groups: Vec<CorrelatedEventGroup>,
    pub outcome: PipelineOutcome,
    pub requires_analyst: bool,
    pub analyst_reasons: Vec<String>,
}

impl PipelineRun {
    fn record_stage(&mut self, stage: PipelineStage, status: StageStatus, detail: impl Into<String>) {
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
/// Carved candidates carry no recorder clock, so the events they produce keep the
/// `TimeEvidence` from the candidate's provenance region with an Unknown timezone — the
/// final timeline never invents a time for recovered data.
fn candidates_to_events(candidates: &[RecoveryCandidate]) -> Vec<TimelineEvent> {
    use forensic_core::identifiers::ProfileId;
    use forensic_core::{Hash, Provenance, RawTimestamp, TimeEvidence, TimeZoneState};

    candidates
        .iter()
        .map(|c| {
            let region = c
                .source_offsets
                .first()
                .cloned()
                .unwrap_or(Region { offset: 0, length: 0 });
            let prov = Provenance::new(
                forensic_core::EvidenceId::new(),
                Hash::sha256(vec![0; 32]),
                vec![],
                "recovery-engine",
                "1.0.0",
                Hash::sha256(vec![0; 32]),
                c.validation.structure.clone(),
            );
            let time = TimeEvidence {
                raw: RawTimestamp {
                    value: 0,
                    format: "none".into(),
                    source: prov,
                },
                recorder_native: None,
                normalized: None,
                reference: None,
                timezone: TimeZoneState::Unknown,
                correction: None,
            };
            TimelineEvent::new(
                0,
                time,
                format!(
                    "Recovered {:?} candidate ({:?}/{:?}) at 0x{:X}",
                    c.recovery_level, c.data_state, c.recovery_status, region.offset
                ),
                vec![region],
                "recovery-engine".to_string(),
                "1.0.0".to_string(),
                ProfileId("recovery".into()),
                Hash::sha256(vec![0; 32]),
            )
        })
        .collect()
}

/// Run the full pipeline over one piece of evidence.
///
/// Returns a `PipelineRun` capturing every stage and gate. Errors only on
/// unrecoverable I/O; forensic "negative" outcomes (unresolved, not parsed, not
/// recovered) are represented in the run, not as errors.
pub fn run_pipeline(
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
        format!("{} detector(s) evaluated in parallel", detector_outputs.len()),
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
                Classification::Confirmed | Classification::CompatibleCandidate => {
                    (ThresholdDecision::OemConfirmed, Some(t.detector_output.oem_key.clone()))
                }
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
            let profile = registry.find_applicable(&key, None, None, None).ok_or_else(|| {
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
        decision: if parsed { ParseDecision::Parsed } else { ParseDecision::NotParsed },
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
        decision: if gaps_present { GapDecision::GapsPresent } else { GapDecision::NoGaps },
        reason: gap_analysis.validation.reason.clone(),
    });
    run.record_stage(
        PipelineStage::GapGate,
        StageStatus::Completed,
        if gaps_present { "Gaps present -> recovery" } else { "No gaps -> final timeline" },
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
        let key = run.oem_key_used.clone().unwrap_or_else(|| UNIFIED_OEM_KEY.to_string());
        let unified = unified_profile();
        let profile = registry
            .find_applicable(&key, None, None, None)
            .unwrap_or(&unified);
        let parser = orchestrator.parser_for(&key);

        if let Some(parser) = parser {
            let engine = recovery::RecoveryEngine::new();
            let (candidates, rec_run) =
                engine.execute_recovery(reader, profile, parser, &bounds, 0, reader.len())?;

            let accepted = candidates
                .iter()
                .filter(|c| {
                    !matches!(c.recovery_status, forensic_core::RecoveryStatus::Unrecoverable)
                })
                .count();
            let any_partial = candidates
                .iter()
                .any(|c| matches!(c.recovery_status, forensic_core::RecoveryStatus::PartiallyRecoverable));

            let decision = if accepted == 0 {
                RecoveryDecision::NotRecovered
            } else if rec_run.truncated || any_partial {
                RecoveryDecision::PartiallyRecovered
            } else {
                RecoveryDecision::CompletelyRecovered
            };

            run.gates.push(GateRecord::Recovery {
                decision,
                reason: match decision {
                    RecoveryDecision::CompletelyRecovered => format!(
                        "{accepted} candidate(s) recovered, scan complete: gaps addressed"
                    ),
                    RecoveryDecision::PartiallyRecovered => format!(
                        "{accepted} candidate(s) recovered but scan was truncated or partial: gaps only partly addressed"
                    ),
                    RecoveryDecision::NotRecovered => {
                        "No recoverable candidates found in the gap regions".to_string()
                    }
                },
            });

            // Fold recovered candidates into the final timeline (Unknown timezone).
            final_events.extend(candidates_to_events(&candidates));

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
                    run.record_stage(PipelineStage::RecoveryGate, StageStatus::Completed, "Partially recovered");
                    run.outcome = PipelineOutcome::CompletedPartialRecovery;
                }
                RecoveryDecision::CompletelyRecovered => {
                    run.record_stage(
                        PipelineStage::Recovery,
                        StageStatus::Completed,
                        format!("{accepted} candidate(s) recovered"),
                    );
                    run.record_stage(PipelineStage::RecoveryGate, StageStatus::Completed, "Recovered");
                    run.outcome = PipelineOutcome::CompletedAfterRecovery;
                }
            }

            run.recovery = Some(RecoverySummary {
                candidates,
                run: rec_run,
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
        run.record_stage(PipelineStage::Recovery, StageStatus::Skipped, "No gaps; recovery not required");
        run.outcome = PipelineOutcome::CompletedNoGaps;
    }

    // ── Stage: Final Timeline ───────────────────────────────────────────────
    // Rebuilt including any recovered events, re-ordered canonically.
    let final_timeline = TimelineEngine::build_timeline(final_events, options.ordering);
    run.record_stage(
        PipelineStage::FinalTimeline,
        if run.requires_analyst { StageStatus::Completed } else { StageStatus::Completed },
        format!("Final timeline built with {} event(s)", final_timeline.events.len()),
    );

    run.parsing = Some(parsing_result);
    run.preliminary_timeline = Some(preliminary);
    run.gap_analysis = Some(gap_analysis);
    run.final_timeline = Some(final_timeline);

    Ok(run)
}
