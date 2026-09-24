//! # Index-aware bounded recovery engine
//!
//! The single production entry point for recovery. It compares what the DVR's own index
//! says exists against what is physically present, and classifies each discovery from
//! that comparison.
//!
//! ```text
//!   RecoveryRequest { evidence_id, reader, profile, parser, bounds, scan_window }
//!        │
//!        ├─ parser.storage_geometry()   ── OEM storage interpretation
//!        ├─ parser.recording_index()    ── OEM index/metadata reading
//!        │
//!        ├─ plan::plan_recovery()       ── claimed ranges, RangeSet complement,
//!        │                                 unclaimed regions, bounded scan targets
//!        │
//!        ├─ levels::scan_target() ×N    ── bounded reads at exact physical offsets
//!        │
//!        └─ RecoveryOutcome { candidates, fragments, run, plan, metrics }
//! ```
//!
//! ## Separation of concerns
//!
//! The engine performs **no** OEM interpretation. It never reads a magic value, never
//! knows a structure offset, and never decides that a region is indexed. Those are
//! parser responsibilities, surfaced as `StorageGeometry`/`RecordingIndex`. The engine
//! does range algebra, bounded reads, budget enforcement and accounting.
//!
//! Detecting the OEM is likewise not this engine's job and is not treated as evidence of
//! anything: the caller passes the parser and profile in. A parser that cannot supply an
//! index degrades the run to a whole-window sweep whose candidates can only reach the
//! conservative unindexed state.

use std::time::Instant;

use evidence_reader::EvidenceReader;
use forensic_core::{
    EvidenceId, ForensicError, OemProfile, RecoveryBounds, RecoveryCandidate, RecoveryRun, Region,
    ValidationState, ValidationStateKind,
};
use parsers_core::parser::Parser;
use parsers_core::storage::IndexAuthority;

use crate::claims::UnclaimedKind;
use crate::fragment::DiscoveredFragment;
use crate::levels::{scan_target_all, ScanContext, DEFAULT_SCAN_WINDOW_BYTES};
use crate::metrics::RecoveryMetrics;
use crate::plan::{plan_recovery, RecoveryPlan};

/// Everything one recovery run needs.
///
/// `evidence_id` is mandatory and is the reason this is a struct rather than a growing
/// positional argument list: the engine must never mint an evidence id, so the caller
/// that owns the evidence item has to supply it explicitly.
pub struct RecoveryRequest<'a> {
    /// The evidence item being recovered from. Propagated verbatim to every candidate,
    /// fragment and provenance record.
    pub evidence_id: EvidenceId,
    /// Read-only evidence access.
    pub reader: &'a dyn EvidenceReader,
    /// The OEM profile in force.
    pub profile: &'a OemProfile,
    /// OEM key the run executes under, for reporting and fragment context.
    pub oem_key: &'a str,
    /// The OEM parser supplying storage interpretation.
    pub parser: &'a dyn Parser,
    /// Budget and cancellation.
    pub bounds: &'a RecoveryBounds,
    /// Address space to reason over. `None` means the whole evidence item.
    ///
    /// A window here narrows *reasoning*, not just reading: claims are clipped to it and
    /// the complement is computed within it, so absolute physical offsets are preserved.
    pub scan_window: Option<Region>,
    /// Largest number of bytes one classification read pulls into memory.
    ///
    /// A memory/throughput knob, never a semantic limit: an OEM container record longer than
    /// this is still described in full from its own declared length. `None` uses
    /// [`DEFAULT_SCAN_WINDOW_BYTES`].
    pub read_window_bytes: Option<u64>,
}

impl<'a> RecoveryRequest<'a> {
    /// A request over the whole evidence item with the default read window.
    pub fn new(
        evidence_id: EvidenceId,
        reader: &'a dyn EvidenceReader,
        profile: &'a OemProfile,
        oem_key: &'a str,
        parser: &'a dyn Parser,
        bounds: &'a RecoveryBounds,
    ) -> Self {
        Self {
            evidence_id,
            reader,
            profile,
            oem_key,
            parser,
            bounds,
            scan_window: None,
            read_window_bytes: None,
        }
    }
}

/// The full result of a recovery run.
pub struct RecoveryOutcome {
    /// Candidates, in ascending physical offset order.
    pub candidates: Vec<RecoveryCandidate>,
    /// The fragment record for each candidate, index-aligned with `candidates`.
    pub fragments: Vec<DiscoveredFragment>,
    /// Bounded-search accounting.
    pub run: RecoveryRun,
    /// The plan that was executed: geometry, index, claim map and scan targets.
    pub plan: RecoveryPlan,
    /// Observability counters for this run.
    pub metrics: RecoveryMetrics,
}

impl RecoveryOutcome {
    /// Candidates in a given data state.
    pub fn in_state(
        &self,
        state: forensic_core::DataState,
    ) -> impl Iterator<Item = &RecoveryCandidate> {
        self.candidates
            .iter()
            .filter(move |c| c.data_state == state)
    }
}

/// Core engine orchestrating bounded, index-aware recovery.
pub struct RecoveryEngine;

impl Default for RecoveryEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RecoveryEngine {
    pub fn new() -> Self {
        Self
    }

    /// Execute a bounded, index-aware recovery run.
    ///
    /// Never modifies evidence: the only access is through the read-only
    /// [`EvidenceReader`] trait, which exposes no write path at the type level.
    ///
    /// Read errors on individual targets are recorded in `run.skipped_ranges` and the run
    /// continues — one unreadable sector must not discard the rest of the analysis.
    pub fn execute_recovery(
        &self,
        request: RecoveryRequest<'_>,
    ) -> Result<RecoveryOutcome, ForensicError> {
        let RecoveryRequest {
            evidence_id,
            reader,
            profile,
            oem_key,
            parser,
            bounds,
            scan_window,
            read_window_bytes: scan_window_bytes,
        } = request;

        let disk = Region::new(0, reader.len())?;
        // Clip the caller's window to the evidence so a request can never describe bytes
        // we do not hold.
        let universe = match scan_window {
            Some(w) => w.intersection(&disk).unwrap_or(Region::point(w.offset)),
            None => disk,
        };

        // ── OEM storage interpretation ──────────────────────────────────────
        // A parser failure here is not fatal: we fall back to "no evidence", which is
        // strictly more conservative than guessing, and record why.
        let geometry = match parser.storage_geometry(reader, profile) {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!(
                    target: "recovery::pipeline",
                    oem_key = %oem_key,
                    error = %e,
                    "storage geometry could not be read; recovery degrades to an unindexed sweep"
                );
                None
            }
        };
        let index = match parser.recording_index(reader, profile) {
            Ok(i) => i,
            Err(e) => {
                tracing::warn!(
                    target: "recovery::pipeline",
                    oem_key = %oem_key,
                    error = %e,
                    "recording index could not be read; recovery degrades to an unindexed sweep"
                );
                None
            }
        };

        if let Some(g) = geometry.as_ref() {
            tracing::debug!(
                target: "recovery::pipeline",
                oem_key = %oem_key,
                physical_size = g.physical_size,
                video_region = %g.video_region.map(|r| r.to_string()).unwrap_or_else(|| "unknown".into()),
                index_region = %g.index_region.map(|r| r.to_string()).unwrap_or_else(|| "unknown".into()),
                block_size = g.block_size.unwrap_or(0),
                sector_size = g.sector_size.unwrap_or(0),
                evidence = %g.evidence.reason,
                "OEM storage geometry established"
            );
        }
        if let Some(i) = index.as_ref() {
            tracing::debug!(
                target: "recovery::pipeline",
                oem_key = %oem_key,
                authority = ?std::mem::discriminant(&i.authority),
                authoritative = i.authority.is_authoritative(),
                declared_entries = i.declared_entry_count.unwrap_or(0),
                parsed_entries = i.recordings.len(),
                evidence = %i.evidence.reason,
                "OEM recording index read"
            );
        }

        // ── Claimed vs unclaimed, then scan planning ────────────────────────
        let plan = plan_recovery(universe, geometry, index)?;

        tracing::debug!(
            target: "recovery::pipeline",
            oem_key = %oem_key,
            claimed_ranges = plan.claim_map.claimed.count(),
            claimed_bytes = plan.claim_map.claimed_bytes(),
            unclaimed_regions = plan.claim_map.unclaimed.count(),
            unclaimed_bytes = plan.claim_map.unclaimed_bytes(),
            scan_targets = plan.targets.len(),
            planned_bytes = plan.planned_bytes,
            "recovery plan built: {}",
            plan.rationale
        );

        let ctx = ScanContext {
            evidence_id,
            oem_key: oem_key.to_string(),
            profile_id: profile.profile_id.clone(),
            profile_version: profile.profile_version.clone(),
            profile_hash: profile.profile_hash.clone(),
            parser_id: parser.id().to_string(),
            parser_version: parser.version().to_string(),
            max_window_bytes: scan_window_bytes.unwrap_or(DEFAULT_SCAN_WINDOW_BYTES),
        };

        let mut run = RecoveryRun {
            searched_regions: vec![],
            searched_bytes: 0,
            skipped_ranges: vec![],
            candidate_count: 0,
            rejected: 0,
            accepted: 0,
            hypothesis_count: 0,
            truncated: false,
            cancelled: false,
            validation_state: ValidationState::new(
                ValidationStateKind::Unknown,
                "Initial state",
                "RecoveryEngine",
                "Search",
            )
            .expect("static reason is non-empty"),
            reason: String::new(),
        };

        let mut candidates: Vec<RecoveryCandidate> = Vec::new();
        let mut fragments: Vec<DiscoveredFragment> = Vec::new();
        let mut metrics = build_metrics(&plan, oem_key, profile);
        let start_time = Instant::now();

        // ── Bounded execution of the plan ───────────────────────────────────
        for target in &plan.targets {
            // Cancellation is honoured promptly and downgrades the run to REVIEW.
            if bounds.cancel.is_cancelled() {
                run.cancelled = true;
                break;
            }
            if let Some(limit) = bounds.time_limit {
                if start_time.elapsed() > limit {
                    run.truncated = true;
                    break;
                }
            }
            // Byte budget: stop before exceeding it rather than after.
            if run.searched_bytes.saturating_add(target.region.length) > bounds.max_scan_bytes {
                run.truncated = true;
                break;
            }
            if run.candidate_count >= bounds.max_candidates {
                run.truncated = true;
                break;
            }
            if run.searched_regions.len() as u64 >= bounds.max_scan_regions as u64 {
                run.truncated = true;
                break;
            }

            run.searched_regions.push(target.region);
            run.searched_bytes = run.searched_bytes.saturating_add(target.region.length);

            // One target can hold many records. `scan_target_all` reports every one of them,
            // so a sweep chunk is no longer forced to stand for exactly one recording.
            match scan_target_all(reader, profile, parser, &ctx, target) {
                Ok(findings) => {
                    for finding in findings {
                        if run.candidate_count >= bounds.max_candidates {
                            run.truncated = true;
                            break;
                        }
                        let state = finding.candidate.data_state;
                        metrics.record_state(state);
                        run.candidate_count += 1;
                        let structurally_valid = matches!(
                            finding.candidate.validation.structure.state,
                            ValidationStateKind::Pass
                        );
                        if structurally_valid {
                            run.accepted += 1;
                        } else {
                            // Surfaced for review, never silently dropped.
                            run.rejected += 1;
                            metrics.validation_failures += 1;
                        }
                        if finding.fragment.discovery_method
                            == crate::fragment::DiscoveryMethod::AvailableMetadataProbe
                        {
                            metrics.available_candidate_count += 1;
                        }
                        if matches!(
                            finding.fragment.framing,
                            crate::fragment::FragmentFraming::OemContainerRecord
                        ) {
                            metrics.container_record_candidate_count += 1;
                        }
                        tracing::debug!(
                            target: "recovery::candidate",
                            scanned_offset = target.region.offset,
                            scanned_length = target.region.length,
                            fragment_offset = finding.fragment.physical_region.offset,
                            fragment_length = finding.fragment.physical_region.length,
                            fragment_id = %finding.fragment.fragment_id,
                            claim = target.claim.label(),
                            discovery = target.discovery_method.label(),
                            framing = finding.fragment.framing.label(),
                            data_state = ?state,
                            recovery_status = ?finding.candidate.recovery_status,
                            level = ?finding.candidate.recovery_level,
                            codec = %finding.fragment.codec,
                            oem_format_recognised = finding.oem_format_recognised,
                            reason = %finding.candidate.provenance.validation_state.reason,
                            "recovery candidate produced"
                        );
                        candidates.push(finding.candidate);
                        fragments.push(finding.fragment);
                    }
                }
                Err(e) => {
                    // Hostile/unreadable region: record and keep going.
                    tracing::debug!(
                        target: "recovery::pipeline",
                        offset = target.region.offset,
                        length = target.region.length,
                        error = %e,
                        "scan target unreadable; recorded as skipped"
                    );
                    run.skipped_ranges.push(target.region);
                }
            }
        }

        metrics.scanned_bytes = run.searched_bytes;
        metrics.scan_region_count = run.searched_regions.len();
        metrics.skipped_range_count = run.skipped_ranges.len();
        metrics.truncated = run.truncated;
        metrics.cancelled = run.cancelled;

        // A bounded search that completed the whole plan is PASS; anything truncated or
        // cancelled is downgraded to REVIEW by `finalize`, because a bounded search can
        // never guarantee a global optimum.
        if !run.cancelled && !run.truncated {
            run.validation_state = ValidationState::new(
                ValidationStateKind::Pass,
                format!(
                    "Full recovery plan executed: {} target(s), {} byte(s) examined",
                    run.searched_regions.len(),
                    run.searched_bytes
                ),
                "RecoveryEngine",
                "Search",
            )
            .expect("formatted reason is non-empty");
            run.reason = "Complete".to_string();
        }
        run.finalize();

        metrics.emit();

        Ok(RecoveryOutcome {
            candidates,
            fragments,
            run,
            plan,
            metrics,
        })
    }
}

/// Seed the metrics from the plan, before any scanning happens.
fn build_metrics(plan: &RecoveryPlan, oem_key: &str, profile: &OemProfile) -> RecoveryMetrics {
    let orphan_regions: Vec<&crate::claims::UnclaimedRegion> = plan
        .claim_map
        .unclaimed_regions
        .iter()
        .filter(|u| u.kind == UnclaimedKind::WithinAuthoritativeIndexScope)
        .collect();

    RecoveryMetrics {
        oem_key: oem_key.to_string(),
        profile_id: profile.profile_id.clone(),
        geometry_available: plan.geometry.is_some(),
        video_region: plan
            .geometry
            .as_ref()
            .and_then(|g| g.video_region)
            .map(|r| format!("{}:{}", r.offset, r.length)),
        index_region: plan
            .geometry
            .as_ref()
            .and_then(|g| g.index_region)
            .or_else(|| plan.index.as_ref().and_then(|i| i.index_region))
            .map(|r| format!("{}:{}", r.offset, r.length)),
        block_size: plan.geometry.as_ref().and_then(|g| g.block_size),
        authoritative_index: plan
            .index
            .as_ref()
            .map(|i| matches!(i.authority, IndexAuthority::Authoritative { .. }))
            .unwrap_or(false),
        index_declared_entries: plan.index.as_ref().and_then(|i| i.declared_entry_count),
        index_entry_count: plan.claim_map.claims.len(),
        claimed_range_count: plan.claim_map.claimed.count(),
        claimed_bytes: plan.claim_map.claimed_bytes(),
        available_claim_count: plan.claim_map.available_claims.len(),
        available_bytes: plan.claim_map.available_bytes(),
        unclaimed_region_count: plan.claim_map.unclaimed.count(),
        unclaimed_bytes: plan.claim_map.unclaimed_bytes(),
        orphan_eligible_region_count: orphan_regions.len(),
        orphan_eligible_bytes: orphan_regions
            .iter()
            .fold(0u64, |a, u| a.saturating_add(u.region.length)),
        bytes_avoided_vs_full_scan: plan.bytes_avoided(),
        ..Default::default()
    }
}
