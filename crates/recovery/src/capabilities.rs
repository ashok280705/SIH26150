//! # Runtime recovery capabilities and strategy selection
//!
//! This module answers one question, for one run, from evidence only:
//!
//! ```text
//!   given what the OEM parser was actually able to establish about THIS evidence item,
//!   which recovery strategies are licensed, and which are not — and why?
//! ```
//!
//! ## Why this is not [`forensic_core::CapabilityStages`]
//!
//! [`forensic_core::CapabilityStages`] is *implementation maturity*: "is Uniview parsing
//! implemented in this build?". It is a property of the codebase, declared ahead of time.
//!
//! [`RecoveryCapabilities`] is *runtime evidence*: "did the parser return a recording index
//! for this disk?". The same parser yields different capabilities on a healthy image and on
//! one whose index region is destroyed. The two models are deliberately separate types with
//! no conversion between them, exactly as `CapabilityStage` and `ValidationState` are.
//!
//! ## Why strategy selection lives here rather than in `if oem == ...`
//!
//! Nothing in this module names an OEM. A capability is present because the parser returned
//! a populated structure, and a strategy is licensed because the capabilities it needs are
//! present. Adding an OEM therefore adds no branch here: a new parser that returns a
//! [`RecordingIndex`](parsers_core::storage::RecordingIndex) gets indexed recovery for free,
//! and one that cannot gets the honest degraded path without anybody writing its name.
//!
//! ## Absence is recorded, never silently dropped
//!
//! Every capability and every strategy appears in the output whether or not it is available,
//! each with the reason it is or is not. A report can therefore state "structural recovery
//! was not performed because no authoritative index governs any of these bytes" instead of
//! leaving the examiner to infer it from a missing section.

use serde::{Deserialize, Serialize};

use crate::claims::UnclaimedKind;
use crate::plan::RecoveryPlan;

/// One thing the recovery engine may or may not have, established from parser output.
///
/// Ordered so a serialized [`RecoveryCapabilities`] is byte-identical across runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryCapability {
    /// The parser read physical storage geometry from the recorder's own structures.
    StorageGeometry,
    /// The parser read a recording index of any authority.
    RecordingIndex,
    /// The index is authoritative over a known region, so absence from it is evidence.
    AuthoritativeIndexScope,
    /// At least one index entry carries an explicit allocation/deallocation marker.
    DeletionMetadata,
    /// The parser reported surviving metadata for recordings the recorder no longer reaches.
    UnreferencedMetadata,
    /// At least one described recording carries a recorder timestamp.
    RecorderTimestamps,
    /// At least one described recording carries a channel.
    ChannelAttribution,
    /// The parser separated container framing from elementary-stream payload.
    PayloadBoundaries,
    /// At least one described recording carries an OEM-declared codec label.
    CodecMetadata,
    /// The parser's structural carver reported container records during this run.
    ContainerCarving,
}

impl RecoveryCapability {
    /// Every capability, in the fixed order used for output.
    pub const ALL: [RecoveryCapability; 10] = [
        Self::StorageGeometry,
        Self::RecordingIndex,
        Self::AuthoritativeIndexScope,
        Self::DeletionMetadata,
        Self::UnreferencedMetadata,
        Self::RecorderTimestamps,
        Self::ChannelAttribution,
        Self::PayloadBoundaries,
        Self::CodecMetadata,
        Self::ContainerCarving,
    ];

    /// Stable label for logs, reports and provenance strings.
    pub fn label(&self) -> &'static str {
        match self {
            Self::StorageGeometry => "storage-geometry",
            Self::RecordingIndex => "recording-index",
            Self::AuthoritativeIndexScope => "authoritative-index-scope",
            Self::DeletionMetadata => "deletion-metadata",
            Self::UnreferencedMetadata => "unreferenced-metadata",
            Self::RecorderTimestamps => "recorder-timestamps",
            Self::ChannelAttribution => "channel-attribution",
            Self::PayloadBoundaries => "payload-boundaries",
            Self::CodecMetadata => "codec-metadata",
            Self::ContainerCarving => "container-carving",
        }
    }
}

/// Whether one capability was established for this run, and on what basis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityFinding {
    pub capability: RecoveryCapability,
    /// True only when parser output positively established it.
    pub available: bool,
    /// Why it is or is not available, phrased for an examiner.
    pub reason: String,
}

/// What this run established about the evidence, capability by capability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveryCapabilities {
    /// One entry per [`RecoveryCapability::ALL`], in that fixed order.
    pub findings: Vec<CapabilityFinding>,
}

impl RecoveryCapabilities {
    /// Whether a capability was established.
    pub fn has(&self, capability: RecoveryCapability) -> bool {
        self.findings
            .iter()
            .any(|f| f.capability == capability && f.available)
    }

    /// The recorded reason for a capability, if it is tracked.
    pub fn reason(&self, capability: RecoveryCapability) -> Option<&str> {
        self.findings
            .iter()
            .find(|f| f.capability == capability)
            .map(|f| f.reason.as_str())
    }

    /// The capabilities that were established, in fixed order.
    pub fn available(&self) -> Vec<RecoveryCapability> {
        self.findings
            .iter()
            .filter(|f| f.available)
            .map(|f| f.capability)
            .collect()
    }
}

/// A recovery strategy the universal engine can apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStrategy {
    /// Probe the ranges the accessible recording set claims.
    IndexedRecovery,
    /// Probe the ranges surviving-but-unreachable metadata describes.
    AvailableMetadataRecovery,
    /// Sweep space an authoritative index governs but does not claim.
    StructuralOrphanRecovery,
    /// Sweep space no authoritative index makes any statement about.
    RawRecovery,
    /// Group discovered fragments into recordings from recorder metadata.
    FragmentCorrelation,
    /// Order the fragments of a recording from sequence or clock evidence.
    TemporalCorrelation,
}

impl RecoveryStrategy {
    pub const ALL: [RecoveryStrategy; 6] = [
        Self::IndexedRecovery,
        Self::AvailableMetadataRecovery,
        Self::StructuralOrphanRecovery,
        Self::RawRecovery,
        Self::FragmentCorrelation,
        Self::TemporalCorrelation,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Self::IndexedRecovery => "indexed-recovery",
            Self::AvailableMetadataRecovery => "available-metadata-recovery",
            Self::StructuralOrphanRecovery => "structural-orphan-recovery",
            Self::RawRecovery => "raw-recovery",
            Self::FragmentCorrelation => "fragment-correlation",
            Self::TemporalCorrelation => "temporal-correlation",
        }
    }
}

/// Whether one strategy was licensed by the run's capabilities, and why.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StrategyDecision {
    pub strategy: RecoveryStrategy,
    /// True when the evidence supports applying this strategy on this evidence item.
    pub licensed: bool,
    /// The capabilities the decision rests on.
    pub basis: Vec<RecoveryCapability>,
    /// Why the strategy is or is not licensed.
    pub reason: String,
}

/// The full strategy plan for one run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StrategySelection {
    /// One decision per [`RecoveryStrategy::ALL`], in that fixed order.
    pub decisions: Vec<StrategyDecision>,
}

impl StrategySelection {
    pub fn is_licensed(&self, strategy: RecoveryStrategy) -> bool {
        self.decisions
            .iter()
            .any(|d| d.strategy == strategy && d.licensed)
    }

    pub fn reason(&self, strategy: RecoveryStrategy) -> Option<&str> {
        self.decisions
            .iter()
            .find(|d| d.strategy == strategy)
            .map(|d| d.reason.as_str())
    }

    pub fn licensed(&self) -> Vec<RecoveryStrategy> {
        self.decisions
            .iter()
            .filter(|d| d.licensed)
            .map(|d| d.strategy)
            .collect()
    }
}

/// What the scan itself observed, which the plan alone cannot say.
///
/// Kept as an explicit input rather than read out of the candidate list so the assessment
/// stays a pure function of named observations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanObservations {
    /// Fragments whose bounds came from an OEM container record.
    pub container_record_fragments: usize,
    /// Fragments carrying an evidence-established parent recording.
    pub fragments_with_parent_recording: usize,
    /// Fragments carrying an evidence-established channel.
    pub fragments_with_channel: usize,
    /// Fragments carrying an evidence-established recorder timestamp.
    pub fragments_with_timestamp: usize,
    /// Fragments carrying an evidence-established on-disk sequence number.
    pub fragments_with_sequence: usize,
}

/// Assess what this run established, from the plan and what the scan observed.
///
/// Pure and total: identical inputs always produce an identical assessment, and nothing here
/// reads the clock, the filesystem or an OEM name.
pub fn assess_capabilities(
    plan: &RecoveryPlan,
    observations: ScanObservations,
) -> RecoveryCapabilities {
    let index = plan.index.as_ref();
    let described: Vec<&parsers_core::storage::IndexedRecording> = index
        .map(|i| {
            i.recordings
                .iter()
                .chain(i.unreferenced_recordings.iter())
                .collect()
        })
        .unwrap_or_default();

    let mut findings = Vec::with_capacity(RecoveryCapability::ALL.len());
    let mut push = |capability, available, reason: String| {
        findings.push(CapabilityFinding {
            capability,
            available,
            reason,
        })
    };

    match plan.geometry.as_ref() {
        Some(g) => push(
            RecoveryCapability::StorageGeometry,
            true,
            format!(
                "the parser read geometry from the recorder's structures: {} byte(s), video region {}, index region {}",
                g.physical_size,
                g.video_region.map(|r| r.to_string()).unwrap_or_else(|| "unknown".into()),
                g.index_region.map(|r| r.to_string()).unwrap_or_else(|| "unknown".into()),
            ),
        ),
        None => push(
            RecoveryCapability::StorageGeometry,
            false,
            "this OEM path established no storage geometry from the evidence; recovery reasons over the whole window".to_string(),
        ),
    }

    // A parser that looked for an index and did not find one returns
    // `Some(RecordingIndex { authority: NotFound, .. })`, which is an honest answer and not a
    // located index. The capability is about what was found, so `NotFound` is not available.
    match index {
        Some(i) if !matches!(i.authority, parsers_core::storage::IndexAuthority::NotFound { .. }) => {
            push(
                RecoveryCapability::RecordingIndex,
                true,
                format!(
                    "the parser located a recording index: {} accessible and {} unreferenced entr(ies), declared count {}",
                    i.recordings.len(),
                    i.unreferenced_recordings.len(),
                    i.declared_entry_count
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "not declared".into()),
                ),
            )
        }
        Some(i) => {
            let reason = match &i.authority {
                parsers_core::storage::IndexAuthority::NotFound { reason } => reason.clone(),
                _ => unreachable!("the previous arm matched everything else"),
            };
            push(
                RecoveryCapability::RecordingIndex,
                false,
                format!(
                    "the parser looked for a recording index and located none ({reason}), so no region can be shown to be referenced or unreferenced"
                ),
            )
        }
        None => push(
            RecoveryCapability::RecordingIndex,
            false,
            "this OEM path supplied no recording index reader, so no region can be shown to be referenced or unreferenced".to_string(),
        ),
    }

    match plan.claim_map.authoritative_scope {
        Some(scope) => push(
            RecoveryCapability::AuthoritativeIndexScope,
            true,
            format!("the index is authoritative over {scope}, so absence from it is evidence within that region"),
        ),
        None => push(
            RecoveryCapability::AuthoritativeIndexScope,
            false,
            "no index is authoritative over any part of this address space, so absence from an index proves nothing here".to_string(),
        ),
    }

    let allocation_markers = described
        .iter()
        .filter(|e| e.allocation != parsers_core::storage::AllocationEvidence::Unknown)
        .count();
    push(
        RecoveryCapability::DeletionMetadata,
        allocation_markers > 0,
        if allocation_markers > 0 {
            format!("{allocation_markers} described recording(s) carry an explicit allocation marker, which is the only basis for a deletion finding")
        } else {
            "no described recording carries an allocation marker, so no deletion finding is reachable on this evidence".to_string()
        },
    );

    let unreferenced = index.map(|i| i.unreferenced_recordings.len()).unwrap_or(0);
    push(
        RecoveryCapability::UnreferencedMetadata,
        unreferenced > 0,
        if unreferenced > 0 {
            format!("{unreferenced} recording(s) are described by surviving metadata the recorder no longer reaches")
        } else {
            "the parser reported no surviving metadata for unreachable recordings".to_string()
        },
    );

    let with_time = described
        .iter()
        .filter(|e| e.start_time_unix.is_some())
        .count();
    push(
        RecoveryCapability::RecorderTimestamps,
        with_time > 0 || observations.fragments_with_timestamp > 0,
        format!(
            "{with_time} described recording(s) and {} discovered fragment(s) carry a recorder timestamp",
            observations.fragments_with_timestamp
        ),
    );

    let with_channel = described.iter().filter(|e| e.channel.is_some()).count();
    push(
        RecoveryCapability::ChannelAttribution,
        with_channel > 0 || observations.fragments_with_channel > 0,
        format!(
            "{with_channel} described recording(s) and {} discovered fragment(s) carry a channel",
            observations.fragments_with_channel
        ),
    );

    let with_payload = described
        .iter()
        .filter(|e| !e.payload_regions.is_empty())
        .count();
    push(
        RecoveryCapability::PayloadBoundaries,
        with_payload > 0,
        if with_payload > 0 {
            format!("{with_payload} described recording(s) separate elementary-stream payload from container framing")
        } else {
            "no described recording separates payload from framing; remux must treat the whole range as opaque".to_string()
        },
    );

    let with_codec = described.iter().filter(|e| e.codec_hint.is_some()).count();
    push(
        RecoveryCapability::CodecMetadata,
        with_codec > 0,
        if with_codec > 0 {
            format!("{with_codec} described recording(s) carry an OEM-declared codec label")
        } else {
            "no described recording carries an OEM-declared codec; codec identity can only come from the stream bytes".to_string()
        },
    );

    push(
        RecoveryCapability::ContainerCarving,
        observations.container_record_fragments > 0,
        if observations.container_record_fragments > 0 {
            format!(
                "the parser's structural carver bounded {} fragment(s) by their own declared record lengths",
                observations.container_record_fragments
            )
        } else {
            "no container record was carved in this run; fragments are bounded by the scan window instead".to_string()
        },
    );

    RecoveryCapabilities { findings }
}

/// Decide which strategies this run's capabilities license.
///
/// This is the whole of strategy selection. It reads capabilities and plan counts — never an
/// OEM key, never a parser id.
pub fn select_strategies(
    capabilities: &RecoveryCapabilities,
    plan: &RecoveryPlan,
    observations: ScanObservations,
) -> StrategySelection {
    let accessible_claims = plan.claim_map.claims.len();
    let available_claims = plan.claim_map.available_claims.len();
    let orphan_regions = plan
        .claim_map
        .unclaimed_regions
        .iter()
        .filter(|u| u.kind == UnclaimedKind::WithinAuthoritativeIndexScope)
        .count();
    let ungoverned_regions = plan
        .claim_map
        .unclaimed_regions
        .iter()
        .filter(|u| u.kind == UnclaimedKind::OutsideIndexScope)
        .count();

    let mut decisions = Vec::with_capacity(RecoveryStrategy::ALL.len());
    let mut push = |strategy, licensed, basis: Vec<RecoveryCapability>, reason: String| {
        decisions.push(StrategyDecision {
            strategy,
            licensed,
            basis,
            reason,
        })
    };

    push(
        RecoveryStrategy::IndexedRecovery,
        capabilities.has(RecoveryCapability::RecordingIndex) && accessible_claims > 0,
        vec![RecoveryCapability::RecordingIndex],
        if accessible_claims > 0 {
            format!("{accessible_claims} accessible index claim(s) give exact physical ranges to confirm")
        } else {
            "no accessible index claim describes any range in this address space".to_string()
        },
    );

    push(
        RecoveryStrategy::AvailableMetadataRecovery,
        capabilities.has(RecoveryCapability::UnreferencedMetadata) && available_claims > 0,
        vec![RecoveryCapability::UnreferencedMetadata],
        if available_claims > 0 {
            format!("{available_claims} range(s) are described by metadata that survives but is not reachable from the recorder's current structures")
        } else {
            "no surviving metadata describes an unreachable recording".to_string()
        },
    );

    push(
        RecoveryStrategy::StructuralOrphanRecovery,
        capabilities.has(RecoveryCapability::AuthoritativeIndexScope) && orphan_regions > 0,
        vec![RecoveryCapability::AuthoritativeIndexScope],
        if !capabilities.has(RecoveryCapability::AuthoritativeIndexScope) {
            "an orphan finding needs an authoritative index to be absent from, and none governs these bytes".to_string()
        } else if orphan_regions > 0 {
            format!("{orphan_regions} region(s) lie inside the authoritative scope and are claimed by no entry, which is positive evidence of non-reference")
        } else {
            "the authoritative index claims every byte it governs, so no region is orphan-eligible"
                .to_string()
        },
    );

    push(
        RecoveryStrategy::RawRecovery,
        ungoverned_regions > 0,
        vec![],
        if ungoverned_regions > 0 {
            format!("{ungoverned_regions} region(s) carry no authoritative index statement; anything found there can only be reported as unindexed")
        } else {
            "every byte in this address space is governed by an authoritative index, so no blind sweep is needed".to_string()
        },
    );

    // Correlation needs recorder-supplied grouping evidence. Physical adjacency is
    // deliberately not in this basis: two fragments being next to each other on disk is not
    // evidence that they belong to the same recording.
    let groupable =
        observations.fragments_with_parent_recording > 0 || observations.fragments_with_channel > 0;
    push(
        RecoveryStrategy::FragmentCorrelation,
        groupable,
        vec![RecoveryCapability::ChannelAttribution],
        if groupable {
            format!(
                "{} fragment(s) carry a parent recording and {} carry a channel, which is recorder-supplied grouping evidence",
                observations.fragments_with_parent_recording, observations.fragments_with_channel
            )
        } else {
            "no fragment carries recorder-supplied grouping evidence, so every fragment stands alone; physical adjacency is not used to group".to_string()
        },
    );

    let orderable =
        observations.fragments_with_sequence > 1 || observations.fragments_with_timestamp > 1;
    push(
        RecoveryStrategy::TemporalCorrelation,
        orderable,
        vec![RecoveryCapability::RecorderTimestamps],
        if orderable {
            format!(
                "{} fragment(s) carry an on-disk sequence number and {} carry a recorder timestamp, so an ordering can be established from evidence",
                observations.fragments_with_sequence, observations.fragments_with_timestamp
            )
        } else {
            "fewer than two fragments carry a sequence number or a recorder clock, so no ordering can be established and ordering stays UNKNOWN".to_string()
        },
    );

    StrategySelection { decisions }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::plan_recovery;
    use forensic_core::{Region, ValidationState, ValidationStateKind};
    use parsers_core::storage::{
        AllocationEvidence, IndexAuthority, IndexedRecording, RecordingIndex,
    };
    use std::collections::BTreeMap;

    fn r(offset: u64, length: u64) -> Region {
        Region::new(offset, length).unwrap()
    }

    fn state() -> ValidationState {
        ValidationState::new(ValidationStateKind::Pass, "t", "t", "t").unwrap()
    }

    fn entry(id: &str, region: Region) -> IndexedRecording {
        IndexedRecording {
            recording_id: id.into(),
            partition: None,
            channel: Some(1),
            start_time_unix: Some(1_700_000_000),
            end_time_unix: None,
            physical_regions: vec![region],
            payload_regions: vec![],
            codec_hint: None,
            allocation: AllocationEvidence::Unknown,
            oem_metadata: BTreeMap::new(),
            evidence: state(),
        }
    }

    #[test]
    fn a_parser_with_no_index_licenses_only_the_raw_sweep() {
        let plan = plan_recovery(r(0, 4 << 20), None, None).unwrap();
        let caps = assess_capabilities(&plan, ScanObservations::default());
        let sel = select_strategies(&caps, &plan, ScanObservations::default());

        assert!(!caps.has(RecoveryCapability::RecordingIndex));
        assert!(!caps.has(RecoveryCapability::AuthoritativeIndexScope));
        assert!(sel.is_licensed(RecoveryStrategy::RawRecovery));
        assert!(!sel.is_licensed(RecoveryStrategy::IndexedRecovery));
        assert!(!sel.is_licensed(RecoveryStrategy::StructuralOrphanRecovery));
        // The refusal is explained, not merely absent.
        assert!(sel
            .reason(RecoveryStrategy::StructuralOrphanRecovery)
            .unwrap()
            .contains("authoritative index"));
    }

    #[test]
    fn an_authoritative_index_with_a_gap_licenses_orphan_recovery() {
        let video = r(1 << 20, 4 << 20);
        let index = RecordingIndex {
            authority: IndexAuthority::Authoritative { governs: video },
            recordings: vec![entry("e0", r(1 << 20, 1 << 20))],
            unreferenced_recordings: Vec::new(),
            declared_entry_count: Some(1),
            index_region: None,
            evidence: state(),
        };
        let plan = plan_recovery(r(0, 8 << 20), None, Some(index)).unwrap();
        let caps = assess_capabilities(&plan, ScanObservations::default());
        let sel = select_strategies(&caps, &plan, ScanObservations::default());

        assert!(caps.has(RecoveryCapability::AuthoritativeIndexScope));
        assert!(sel.is_licensed(RecoveryStrategy::IndexedRecovery));
        assert!(sel.is_licensed(RecoveryStrategy::StructuralOrphanRecovery));
    }

    #[test]
    fn a_partial_index_never_licenses_orphan_recovery() {
        let index = RecordingIndex {
            authority: IndexAuthority::Partial {
                reason: "2 of 5 entries parsed".into(),
            },
            recordings: vec![entry("e0", r(1 << 20, 1 << 20))],
            unreferenced_recordings: Vec::new(),
            declared_entry_count: Some(5),
            index_region: None,
            evidence: state(),
        };
        let plan = plan_recovery(r(0, 4 << 20), None, Some(index)).unwrap();
        let caps = assess_capabilities(&plan, ScanObservations::default());
        let sel = select_strategies(&caps, &plan, ScanObservations::default());

        assert!(caps.has(RecoveryCapability::RecordingIndex));
        assert!(!caps.has(RecoveryCapability::AuthoritativeIndexScope));
        assert!(sel.is_licensed(RecoveryStrategy::IndexedRecovery));
        assert!(!sel.is_licensed(RecoveryStrategy::StructuralOrphanRecovery));
    }

    #[test]
    fn correlation_is_not_licensed_by_physical_adjacency_alone() {
        let plan = plan_recovery(r(0, 4 << 20), None, None).unwrap();
        let caps = assess_capabilities(&plan, ScanObservations::default());
        // Many fragments, none carrying recorder metadata.
        let obs = ScanObservations {
            container_record_fragments: 50,
            ..Default::default()
        };
        let sel = select_strategies(&caps, &plan, obs);
        assert!(!sel.is_licensed(RecoveryStrategy::FragmentCorrelation));
        assert!(!sel.is_licensed(RecoveryStrategy::TemporalCorrelation));
        assert!(sel
            .reason(RecoveryStrategy::FragmentCorrelation)
            .unwrap()
            .contains("physical adjacency"));
    }

    #[test]
    fn every_capability_and_strategy_is_reported_either_way() {
        let plan = plan_recovery(r(0, 1 << 20), None, None).unwrap();
        let caps = assess_capabilities(&plan, ScanObservations::default());
        let sel = select_strategies(&caps, &plan, ScanObservations::default());

        assert_eq!(caps.findings.len(), RecoveryCapability::ALL.len());
        assert_eq!(sel.decisions.len(), RecoveryStrategy::ALL.len());
        assert!(caps.findings.iter().all(|f| !f.reason.trim().is_empty()));
        assert!(sel.decisions.iter().all(|d| !d.reason.trim().is_empty()));
    }

    #[test]
    fn the_assessment_is_deterministic_and_ordered() {
        let plan = plan_recovery(r(0, 2 << 20), None, None).unwrap();
        let a = assess_capabilities(&plan, ScanObservations::default());
        let b = assess_capabilities(&plan, ScanObservations::default());
        assert_eq!(a, b);
        let order: Vec<RecoveryCapability> = a.findings.iter().map(|f| f.capability).collect();
        assert_eq!(order, RecoveryCapability::ALL.to_vec());
    }
}
