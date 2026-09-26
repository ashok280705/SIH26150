//! # Fragment and temporal correlation
//!
//! The stage between "N pieces of video were found" and "these pieces are one recording".
//!
//! ```text
//!   Vec<DiscoveredFragment>
//!        │
//!        ├─ grouping    ── recorder-supplied evidence only
//!        │                 (parent recording id, then channel within one described region)
//!        │
//!        ├─ ordering    ── on-disk sequence numbers, else recorder clock, else UNKNOWN
//!        │
//!        └─ Vec<CorrelatedRecording>   with the evidence for every decision attached
//! ```
//!
//! ## The rule this module exists to enforce
//!
//! **Physical adjacency is never evidence of temporal continuity, and never evidence of
//! common identity.** Two container records sitting next to each other on a disk may be two
//! halves of one recording, or two unrelated recordings from different cameras months apart
//! that happen to share a cluster boundary. Nothing here groups or orders on adjacency.
//!
//! Where the evidence cannot establish an ordering, the result is
//! [`TemporalOrdering::Unknown`] with the reason attached. That is the correct answer, not a
//! failure, and it is strictly preferable to a fabricated sequence. Members of an unordered
//! group are still listed — in physical offset order, labelled as such — so an examiner can
//! see what was found without being told it is a timeline.
//!
//! ## Why the grouping tiers are what they are
//!
//! | tier | basis                                            | strength |
//! |------|--------------------------------------------------|----------|
//! | A    | the recorder's own metadata names a parent recording | strong |
//! | B    | same channel inside one OEM-described region      | medium   |
//! | C    | nothing the recorder supplied                     | — the fragment stands alone |
//!
//! Tier B is bounded by `originating_region` — the claimed or unclaimed range the *planner*
//! derived from OEM structures — rather than by a distance threshold. A threshold would be a
//! tuned constant standing in for evidence; the originating region is evidence.

use std::collections::BTreeMap;

use forensic_core::{DataState, RecoveryCandidate, Region, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};

use crate::fragment::DiscoveredFragment;
use crate::fragmentation::{reassemble_fragments, Fragment, ReassemblyResult};

/// How strongly one correlation observation supports its conclusion.
///
/// This is an ordinal **label on a named observation**, not a score. It is never summed,
/// averaged or converted to a number, and it never replaces the observation it labels — a
/// consumer reads both. The platform's numeric scoring lives in the `confidence` crate and
/// concerns OEM attribution; this does not compete with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStrength {
    /// The recorder's own structures state it.
    Strong,
    /// Derived from several recorder-supplied fields that agree.
    Medium,
    /// A structural observation that is consistent with, but does not establish, the claim.
    Weak,
}

/// One named observation behind a correlation decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorrelationEvidence {
    /// Stable kind label, e.g. `parent-recording-id`, `sequence-numbers`, `region-overlap`.
    pub kind: String,
    pub strength: EvidenceStrength,
    /// What was observed, phrased for an examiner.
    pub detail: String,
}

impl CorrelationEvidence {
    fn new(kind: &str, strength: EvidenceStrength, detail: impl Into<String>) -> Self {
        Self {
            kind: kind.to_string(),
            strength,
            detail: detail.into(),
        }
    }
}

/// What put a set of fragments into one group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupingBasis {
    /// The recorder's metadata names the same parent recording for every member.
    ParentRecording { recording_id: String },
    /// Every member carries the same channel and was found inside the same OEM-described
    /// region. Weaker than a named parent, and labelled as such.
    ChannelWithinDescribedRegion {
        channel: u32,
        partition: Option<u32>,
        region: Region,
    },
    /// The recorder supplied nothing that associates this fragment with any other.
    Ungrouped { reason: String },
}

impl GroupingBasis {
    pub fn label(&self) -> &'static str {
        match self {
            Self::ParentRecording { .. } => "parent-recording",
            Self::ChannelWithinDescribedRegion { .. } => "channel-within-described-region",
            Self::Ungrouped { .. } => "ungrouped",
        }
    }

    fn strength(&self) -> EvidenceStrength {
        match self {
            Self::ParentRecording { .. } => EvidenceStrength::Strong,
            Self::ChannelWithinDescribedRegion { .. } => EvidenceStrength::Medium,
            Self::Ungrouped { .. } => EvidenceStrength::Weak,
        }
    }
}

/// What established the order of a group's members — or that nothing did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TemporalOrdering {
    /// Ordered from on-disk sequence numbers the recorder wrote.
    BySequenceNumber,
    /// Ordered from recorder timestamps.
    ByRecorderTimestamp,
    /// A single member: there is nothing to order, and that is not an ordering claim.
    SingleFragment,
    /// No evidence establishes an order. Members are listed in physical offset order, which
    /// is a statement about the disk and **not** about time.
    Unknown { reason: String },
}

impl TemporalOrdering {
    pub fn label(&self) -> &'static str {
        match self {
            Self::BySequenceNumber => "by-sequence-number",
            Self::ByRecorderTimestamp => "by-recorder-timestamp",
            Self::SingleFragment => "single-fragment",
            Self::Unknown { .. } => "unknown",
        }
    }

    /// Whether the member order is a temporal claim at all.
    pub fn is_established(&self) -> bool {
        matches!(self, Self::BySequenceNumber | Self::ByRecorderTimestamp)
    }
}

/// One recording as reconstructed from correlated fragments.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorrelatedRecording {
    /// Deterministic identifier for this group, derived from its basis and lowest offset.
    pub recording_key: String,
    pub grouping: GroupingBasis,
    /// Member fragment ids, in `regions` order.
    pub fragment_ids: Vec<String>,
    /// Member physical ranges, in the order `ordering` describes.
    pub regions: Vec<Region>,
    pub ordering: TemporalOrdering,
    /// Channel, only when every member agrees and the value came from evidence.
    pub channel: Option<u32>,
    /// Partition, only when every member agrees and the value came from evidence.
    pub partition: Option<u32>,
    /// Earliest recorder timestamp across members, when any member carries one.
    pub start_time_unix: Option<i64>,
    /// Latest recorder end timestamp across members, when any member carries one.
    pub end_time_unix: Option<i64>,
    /// The data state, only when every member was classified the same way. `None` when the
    /// members disagree — collapsing that would assert something no member states.
    pub data_state: Option<DataState>,
    /// Every member's state, in member order, so a mixed group is still fully readable.
    pub member_states: Vec<DataState>,
    /// The observations behind the grouping and the ordering.
    pub evidence: Vec<CorrelationEvidence>,
    /// The two-dimensional logical/physical report, when sequence numbers made one possible.
    pub reassembly: Option<ReassemblyResult>,
    /// PASS only for a group whose ordering is established and whose members are consistent.
    pub validation: ValidationState,
}

impl CorrelatedRecording {
    /// Total bytes the group's members cover (saturating; overlapping members are counted
    /// once each, which is why `regions` is also published verbatim).
    pub fn total_bytes(&self) -> u64 {
        self.regions
            .iter()
            .fold(0u64, |a, r| a.saturating_add(r.length))
    }
}

/// Limits on the correlation stage.
///
/// Correlation is the one stage whose cost is combinatorial in the number of fragments, so it
/// is bounded explicitly rather than trusting the candidate cap to contain it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorrelationBounds {
    /// Largest number of groups evaluated. Each group is one reconstruction hypothesis, so
    /// this is where [`forensic_core::RecoveryBounds::max_hypotheses`] is actually enforced.
    pub max_groups: usize,
    /// Largest number of members considered in one group.
    pub max_fragments_per_group: usize,
}

impl CorrelationBounds {
    /// Derive the correlation budget from the run's recovery bounds.
    pub fn from_recovery_bounds(bounds: &forensic_core::RecoveryBounds) -> Self {
        Self {
            max_groups: bounds.max_hypotheses as usize,
            // One group can never hold more members than the run is allowed candidates.
            max_fragments_per_group: bounds.max_candidates as usize,
        }
    }
}

impl Default for CorrelationBounds {
    fn default() -> Self {
        Self {
            max_groups: 1024,
            max_fragments_per_group: 4096,
        }
    }
}

/// The outcome of correlating one run's fragments.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorrelationOutcome {
    /// Groups in deterministic order: lowest physical offset first.
    pub recordings: Vec<CorrelatedRecording>,
    /// Groups formed before bounding. Each is one hypothesis, and this is what the run
    /// reports as `hypothesis_count`.
    pub groups_considered: usize,
    /// True when the group or member budget stopped the stage short.
    pub truncated: bool,
    /// PASS for a complete, consistent correlation; REVIEW when bounded or ambiguous.
    pub validation: ValidationState,
}

/// Total `ValidationState` constructor; the static fallback reason is non-empty.
fn vs(kind: ValidationStateKind, reason: impl Into<String>, subject: &str) -> ValidationState {
    let reason = reason.into();
    ValidationState::new(kind, reason, "correlate_fragments", subject).unwrap_or_else(|_| {
        ValidationState::new(kind, "reason unavailable", "correlate_fragments", subject)
            .expect("static fallback reason is non-empty")
    })
}

/// The key a fragment is grouped under, or `None` when the recorder supplied nothing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum GroupKey {
    Parent(String),
    ChannelInRegion {
        partition: Option<u32>,
        channel: u32,
        region_offset: u64,
        region_length: u64,
    },
}

fn group_key(fragment: &DiscoveredFragment) -> Option<GroupKey> {
    if let Some(parent) = fragment.parent_recording.value() {
        return Some(GroupKey::Parent(parent.clone()));
    }
    // Tier B. The channel must have come from evidence, and the originating region is the
    // OEM-derived range the planner targeted — not a distance heuristic.
    fragment
        .camera_id
        .value()
        .map(|channel| GroupKey::ChannelInRegion {
            partition: fragment.partition.value().copied(),
            channel: *channel,
            region_offset: fragment.originating_region.offset,
            region_length: fragment.originating_region.length,
        })
}

/// Correlate one run's fragments into recordings.
///
/// `candidates` is index-aligned with `fragments`, exactly as the engine holds them. Every
/// fragment appears in exactly one group; nothing is dropped, and a fragment the recorder
/// said nothing about becomes its own single-member group rather than disappearing.
pub fn correlate_fragments(
    candidates: &[RecoveryCandidate],
    fragments: &[DiscoveredFragment],
    bounds: CorrelationBounds,
) -> CorrelationOutcome {
    // BTreeMap, not HashMap: group order must not depend on hash iteration order.
    let mut grouped: BTreeMap<GroupKey, Vec<usize>> = BTreeMap::new();
    let mut ungrouped: Vec<usize> = Vec::new();

    for (i, fragment) in fragments.iter().enumerate() {
        match group_key(fragment) {
            Some(key) => grouped.entry(key).or_default().push(i),
            None => ungrouped.push(i),
        }
    }

    let groups_considered = grouped.len() + ungrouped.len();
    let mut truncated = false;
    let mut member_truncated = 0usize;

    let mut recordings: Vec<CorrelatedRecording> = Vec::new();

    for (key, mut members) in grouped {
        // Deterministic member order before any bounding, so truncation keeps the same
        // members every run rather than whichever the scan happened to reach first.
        members.sort_by_key(|&i| {
            (
                fragments[i].physical_region.offset,
                fragments[i].physical_region.length,
            )
        });
        if members.len() > bounds.max_fragments_per_group {
            members.truncate(bounds.max_fragments_per_group);
            truncated = true;
            member_truncated += 1;
        }
        recordings.push(build_group(
            &key,
            &members,
            candidates,
            fragments,
            member_truncated > 0,
        ));
    }

    for i in ungrouped {
        recordings.push(build_ungrouped(i, candidates, fragments));
    }

    // Deterministic group order: lowest member offset, then the key itself via the
    // recording_key string, which is itself derived deterministically.
    recordings.sort_by(|a, b| {
        let a_off = a.regions.iter().map(|r| r.offset).min().unwrap_or(u64::MAX);
        let b_off = b.regions.iter().map(|r| r.offset).min().unwrap_or(u64::MAX);
        a_off
            .cmp(&b_off)
            .then_with(|| a.recording_key.cmp(&b.recording_key))
    });

    if recordings.len() > bounds.max_groups {
        recordings.truncate(bounds.max_groups);
        truncated = true;
    }

    let ambiguous = recordings
        .iter()
        .filter(|r| matches!(r.ordering, TemporalOrdering::Unknown { .. }))
        .count();

    let validation = if truncated {
        vs(
            ValidationStateKind::Review,
            format!(
                "correlation was bounded: {groups_considered} group(s) were formed and at most \
                 {} are reported, with {member_truncated} group(s) whose membership was capped at \
                 {}. A bounded correlation cannot claim a global reconstruction",
                bounds.max_groups, bounds.max_fragments_per_group
            ),
            "CorrelationOutcome",
        )
    } else if ambiguous > 0 {
        vs(
            ValidationStateKind::Review,
            format!(
                "{ambiguous} of {} correlated recording(s) have no evidence-established \
                 ordering and are reported in physical offset order, which is not a timeline",
                recordings.len()
            ),
            "CorrelationOutcome",
        )
    } else if recordings.is_empty() {
        vs(
            ValidationStateKind::Unknown,
            "no fragments were available to correlate",
            "CorrelationOutcome",
        )
    } else {
        vs(
            ValidationStateKind::Pass,
            format!(
                "{} recording(s) correlated, each with an evidence-established ordering",
                recordings.len()
            ),
            "CorrelationOutcome",
        )
    };

    CorrelationOutcome {
        recordings,
        groups_considered,
        truncated,
        validation,
    }
}

/// Derive a stable key for a group from its basis and its lowest member offset.
fn derive_key(basis: &GroupingBasis, lowest_offset: u64) -> String {
    match basis {
        GroupingBasis::ParentRecording { recording_id } => {
            format!("rec:parent:{recording_id}")
        }
        GroupingBasis::ChannelWithinDescribedRegion {
            channel,
            partition,
            region,
        } => format!(
            "rec:chan:{}:{}:{}:{}",
            partition
                .map(|p| p.to_string())
                .unwrap_or_else(|| "none".into()),
            channel,
            region.offset,
            region.length
        ),
        GroupingBasis::Ungrouped { .. } => format!("rec:solo:{lowest_offset:#x}"),
    }
}

fn build_group(
    key: &GroupKey,
    members: &[usize],
    candidates: &[RecoveryCandidate],
    fragments: &[DiscoveredFragment],
    member_capped: bool,
) -> CorrelatedRecording {
    let basis = match key {
        GroupKey::Parent(id) => GroupingBasis::ParentRecording {
            recording_id: id.clone(),
        },
        GroupKey::ChannelInRegion {
            partition,
            channel,
            region_offset,
            region_length,
        } => GroupingBasis::ChannelWithinDescribedRegion {
            channel: *channel,
            partition: *partition,
            region: Region::new(*region_offset, *region_length)
                .unwrap_or_else(|_| Region::point(*region_offset)),
        },
    };

    let mut evidence = vec![CorrelationEvidence::new(
        match &basis {
            GroupingBasis::ParentRecording { .. } => "parent-recording-id",
            _ => "channel-within-described-region",
        },
        basis.strength(),
        match &basis {
            GroupingBasis::ParentRecording { recording_id } => format!(
                "{} fragment(s) carry the recorder's own parent recording id {recording_id}",
                members.len()
            ),
            GroupingBasis::ChannelWithinDescribedRegion {
                channel, region, ..
            } => format!(
                "{} fragment(s) carry channel {channel} and were found inside the single \
                 OEM-described region {region}; grouped on that, not on physical adjacency",
                members.len()
            ),
            GroupingBasis::Ungrouped { .. } => unreachable!("grouped members have a key"),
        },
    )];

    if member_capped {
        evidence.push(CorrelationEvidence::new(
            "membership-bounded",
            EvidenceStrength::Weak,
            "the group's membership was capped by the run's correlation bounds, so it may be \
             incomplete",
        ));
    }

    finish_group(basis, members, candidates, fragments, evidence)
}

fn build_ungrouped(
    i: usize,
    candidates: &[RecoveryCandidate],
    fragments: &[DiscoveredFragment],
) -> CorrelatedRecording {
    let f = &fragments[i];
    let reason = format!(
        "the recorder supplied neither a parent recording nor a channel for these bytes \
         ({}); it is reported alone rather than attached to a neighbour",
        f.discovery_method.label()
    );
    let basis = GroupingBasis::Ungrouped {
        reason: reason.clone(),
    };
    let evidence = vec![CorrelationEvidence::new(
        "no-grouping-evidence",
        EvidenceStrength::Weak,
        reason,
    )];
    finish_group(basis, &[i], candidates, fragments, evidence)
}

/// Establish ordering, roll up agreed metadata, and validate — the half of group
/// construction that is identical for every basis.
fn finish_group(
    basis: GroupingBasis,
    members: &[usize],
    candidates: &[RecoveryCandidate],
    fragments: &[DiscoveredFragment],
    mut evidence: Vec<CorrelationEvidence>,
) -> CorrelatedRecording {
    // Physical order is the starting point and the fallback. It is never presented as time.
    let mut order: Vec<usize> = members.to_vec();
    order.sort_by_key(|&i| {
        (
            fragments[i].physical_region.offset,
            fragments[i].physical_region.length,
        )
    });

    let ordering = if order.len() == 1 {
        TemporalOrdering::SingleFragment
    } else {
        establish_ordering(&mut order, fragments, &mut evidence)
    };

    // A reassembly report needs sequence numbers; without them there is no logical dimension
    // to report and fabricating one would be exactly the error this module prevents.
    let reassembly = if matches!(ordering, TemporalOrdering::BySequenceNumber) {
        let frags: Vec<Fragment> = order
            .iter()
            .filter_map(|&i| {
                fragments[i].sequence_number.value().map(|seq| Fragment {
                    region: fragments[i].physical_region,
                    sequence_index: (*seq).min(u32::MAX as u64) as u32,
                    is_valid: fragments[i].validation.state == ValidationStateKind::Pass,
                })
            })
            .collect();
        let count = frags.len() as u32;
        Some(reassemble_fragments(frags, count.max(1)))
    } else {
        None
    };

    if let Some(report) = reassembly.as_ref() {
        if !report.logical_gaps.is_empty() {
            let missing: u32 = report.logical_gaps.iter().map(|g| g.missing_count).sum();
            evidence.push(CorrelationEvidence::new(
                "logical-gap",
                EvidenceStrength::Strong,
                format!(
                    "{} sequence gap(s) totalling {missing} missing frame(s); the gaps are \
                     recorded and never filled",
                    report.logical_gaps.len()
                ),
            ));
        }
        if !report.is_physically_contiguous {
            evidence.push(CorrelationEvidence::new(
                "physical-discontinuity",
                EvidenceStrength::Weak,
                format!(
                    "{} physical discontinuit(ies) between members; non-contiguity on disk is \
                     not frame loss",
                    report.physical_discontinuities.len()
                ),
            ));
        }
    }

    // Overlapping member ranges mean at least one of them is misdescribed. Recorded, and the
    // group is downgraded rather than silently merged.
    let mut overlaps = 0usize;
    for w in order.windows(2) {
        if fragments[w[0]]
            .physical_region
            .overlaps(&fragments[w[1]].physical_region)
        {
            overlaps += 1;
        }
    }
    if overlaps > 0 {
        evidence.push(CorrelationEvidence::new(
            "region-overlap",
            EvidenceStrength::Strong,
            format!(
                "{overlaps} pair(s) of members describe overlapping physical ranges, so at \
                 least one member's bounds are wrong"
            ),
        ));
    }

    let regions: Vec<Region> = order
        .iter()
        .map(|&i| fragments[i].physical_region)
        .collect();
    let fragment_ids: Vec<String> = order
        .iter()
        .map(|&i| fragments[i].fragment_id.clone())
        .collect();
    let member_states: Vec<DataState> = order.iter().map(|&i| candidates[i].data_state).collect();

    // Only an unanimous state is reported. Disagreement stays visible.
    let data_state = member_states
        .first()
        .filter(|first| member_states.iter().all(|s| s == *first))
        .copied();
    if data_state.is_none() && member_states.len() > 1 {
        evidence.push(CorrelationEvidence::new(
            "mixed-member-states",
            EvidenceStrength::Strong,
            "members of this group were classified differently, so no single data state is \
             reported for the group",
        ));
    }

    let channel = unanimous(&order, fragments, |f| f.camera_id.value().copied());
    let partition = unanimous(&order, fragments, |f| f.partition.value().copied());
    let start_time_unix = order
        .iter()
        .filter_map(|&i| fragments[i].timestamp_unix.value().copied())
        .min();
    let end_time_unix = order
        .iter()
        .filter_map(|&i| {
            fragments[i]
                .end_timestamp_unix
                .value()
                .copied()
                .or_else(|| fragments[i].timestamp_unix.value().copied())
        })
        .max();

    let lowest_offset = regions.iter().map(|r| r.offset).min().unwrap_or(0);
    let recording_key = derive_key(&basis, lowest_offset);

    let validation = if overlaps > 0 {
        vs(
            ValidationStateKind::Review,
            format!("{overlaps} overlapping member range(s) in this group"),
            "CorrelatedRecording",
        )
    } else {
        match &ordering {
            TemporalOrdering::Unknown { reason } => vs(
                ValidationStateKind::Review,
                format!("member order is physical, not temporal: {reason}"),
                "CorrelatedRecording",
            ),
            TemporalOrdering::SingleFragment => vs(
                ValidationStateKind::Pass,
                "a single fragment; there is nothing to order",
                "CorrelatedRecording",
            ),
            established => vs(
                ValidationStateKind::Pass,
                format!(
                    "{} member(s) ordered {}",
                    regions.len(),
                    established.label()
                ),
                "CorrelatedRecording",
            ),
        }
    };

    CorrelatedRecording {
        recording_key,
        grouping: basis,
        fragment_ids,
        regions,
        ordering,
        channel,
        partition,
        start_time_unix,
        end_time_unix,
        data_state,
        member_states,
        evidence,
        reassembly,
        validation,
    }
}

/// Order `order` in place from evidence, or leave it in physical order and say so.
fn establish_ordering(
    order: &mut [usize],
    fragments: &[DiscoveredFragment],
    evidence: &mut Vec<CorrelationEvidence>,
) -> TemporalOrdering {
    // Sequence numbers first: they are the recorder's own statement of order.
    let seqs: Vec<Option<u64>> = order
        .iter()
        .map(|&i| fragments[i].sequence_number.value().copied())
        .collect();
    if seqs.iter().all(|s| s.is_some()) {
        let mut values: Vec<u64> = seqs.iter().map(|s| s.expect("checked")).collect();
        values.sort_unstable();
        let has_duplicates = values.windows(2).any(|w| w[0] == w[1]);
        if !has_duplicates {
            order.sort_by_key(|&i| {
                (
                    fragments[i].sequence_number.value().copied().unwrap_or(0),
                    fragments[i].physical_region.offset,
                )
            });
            evidence.push(CorrelationEvidence::new(
                "sequence-numbers",
                EvidenceStrength::Strong,
                format!(
                    "every member carries a distinct on-disk sequence number ({}..={})",
                    values.first().copied().unwrap_or(0),
                    values.last().copied().unwrap_or(0)
                ),
            ));
            return TemporalOrdering::BySequenceNumber;
        }
        evidence.push(CorrelationEvidence::new(
            "sequence-conflict",
            EvidenceStrength::Strong,
            "two or more members carry the same on-disk sequence number, so the recorder's own \
             ordering evidence is contradictory and cannot be used",
        ));
        return TemporalOrdering::Unknown {
            reason: "duplicate sequence numbers among the members".to_string(),
        };
    }

    // Then the recorder's clock.
    let times: Vec<Option<i64>> = order
        .iter()
        .map(|&i| fragments[i].timestamp_unix.value().copied())
        .collect();
    if times.iter().all(|t| t.is_some()) {
        let mut values: Vec<i64> = times.iter().map(|t| t.expect("checked")).collect();
        values.sort_unstable();
        let has_duplicates = values.windows(2).any(|w| w[0] == w[1]);
        if !has_duplicates {
            order.sort_by_key(|&i| {
                (
                    fragments[i].timestamp_unix.value().copied().unwrap_or(0),
                    fragments[i].physical_region.offset,
                )
            });
            evidence.push(CorrelationEvidence::new(
                "recorder-timestamps",
                EvidenceStrength::Medium,
                format!(
                    "every member carries a distinct recorder timestamp ({}..={})",
                    values.first().copied().unwrap_or(0),
                    values.last().copied().unwrap_or(0)
                ),
            ));
            return TemporalOrdering::ByRecorderTimestamp;
        }
        evidence.push(CorrelationEvidence::new(
            "timestamp-collision",
            EvidenceStrength::Medium,
            "two or more members carry the same recorder timestamp, which cannot order them",
        ));
        return TemporalOrdering::Unknown {
            reason: "identical recorder timestamps among the members".to_string(),
        };
    }

    let missing_seq = seqs.iter().filter(|s| s.is_none()).count();
    let missing_time = times.iter().filter(|t| t.is_none()).count();
    let reason = format!(
        "{missing_seq} of {} member(s) carry no sequence number and {missing_time} carry no \
         recorder timestamp; physical adjacency is not used as a substitute",
        order.len()
    );
    evidence.push(CorrelationEvidence::new(
        "no-ordering-evidence",
        EvidenceStrength::Weak,
        reason.clone(),
    ));
    TemporalOrdering::Unknown { reason }
}

/// The value every member agrees on, or `None` if any member disagrees or lacks it.
fn unanimous<T: PartialEq + Copy>(
    order: &[usize],
    fragments: &[DiscoveredFragment],
    get: impl Fn(&DiscoveredFragment) -> Option<T>,
) -> Option<T> {
    let mut iter = order.iter().map(|&i| get(&fragments[i]));
    let first = iter.next().flatten()?;
    if order.iter().all(|&i| get(&fragments[i]) == Some(first)) {
        Some(first)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fragment::{DiscoveryMethod, FieldEvidence, FragmentFraming};
    use forensic_core::{
        EvidenceId, FrameValidationReport, Hash, Provenance, RecoveryLevel, RecoveryStatus,
        SourceRegion,
    };

    fn r(offset: u64, length: u64) -> Region {
        Region::new(offset, length).unwrap()
    }

    fn state() -> ValidationState {
        ValidationState::new(ValidationStateKind::Pass, "t", "t", "t").unwrap()
    }

    fn provenance(ev: EvidenceId, region: Region) -> Provenance {
        Provenance::new(
            ev,
            Hash::sha256(vec![1; 32]),
            vec![SourceRegion::new(ev, region)],
            "test",
            "0",
            Hash::sha256(vec![2; 32]),
            state(),
        )
    }

    struct FragBuilder {
        ev: EvidenceId,
        region: Region,
        originating: Region,
        parent: Option<String>,
        channel: Option<u32>,
        seq: Option<u64>,
        time: Option<i64>,
    }

    impl FragBuilder {
        fn new(ev: EvidenceId, offset: u64, length: u64) -> Self {
            Self {
                ev,
                region: r(offset, length),
                originating: r(0, 1 << 20),
                parent: None,
                channel: None,
                seq: None,
                time: None,
            }
        }
        fn parent(mut self, p: &str) -> Self {
            self.parent = Some(p.into());
            self
        }
        fn channel(mut self, c: u32) -> Self {
            self.channel = Some(c);
            self
        }
        fn originating(mut self, offset: u64, length: u64) -> Self {
            self.originating = r(offset, length);
            self
        }
        fn seq(mut self, s: u64) -> Self {
            self.seq = Some(s);
            self
        }
        fn time(mut self, t: i64) -> Self {
            self.time = Some(t);
            self
        }
        fn build(self) -> DiscoveredFragment {
            DiscoveredFragment {
                evidence_id: self.ev,
                fragment_id: DiscoveredFragment::derive_id(self.ev, self.region),
                physical_region: self.region,
                payload_region: None,
                framing: FragmentFraming::OemContainerRecord,
                originating_region: self.originating,
                oem_key: "test".into(),
                profile_id: "test-v1".into(),
                discovery_method: DiscoveryMethod::IndexClaimedProbe,
                codec: "H264".into(),
                partition: FieldEvidence::unknown("no partition"),
                camera_id: match self.channel {
                    Some(c) => FieldEvidence::known(c, "index"),
                    None => FieldEvidence::unknown("no channel"),
                },
                timestamp_unix: match self.time {
                    Some(t) => FieldEvidence::known(t, "index"),
                    None => FieldEvidence::unknown("no timestamp"),
                },
                end_timestamp_unix: FieldEvidence::unknown("no end"),
                sequence_number: match self.seq {
                    Some(s) => FieldEvidence::known(s, "container header"),
                    None => FieldEvidence::unknown("no sequence"),
                },
                frame_type: FieldEvidence::unknown("no frame type"),
                parent_recording: match self.parent {
                    Some(p) => FieldEvidence::known(p, "index"),
                    None => FieldEvidence::unknown("no parent"),
                },
                oem_metadata: BTreeMap::new(),
                validation: state(),
                confidence: FieldEvidence::known(0.5, "test"),
                provenance: provenance(self.ev, self.region),
            }
        }
    }

    fn candidate(region: Region, ev: EvidenceId, data_state: DataState) -> RecoveryCandidate {
        RecoveryCandidate {
            recovery_level: RecoveryLevel::L1,
            data_state,
            recovery_status: RecoveryStatus::Recoverable,
            source_offsets: vec![region],
            validation: FrameValidationReport {
                signatures: state(),
                structure: state(),
                timestamps: state(),
                channel: state(),
                continuity: state(),
            },
            provenance: provenance(ev, region),
        }
    }

    fn run(frags: Vec<DiscoveredFragment>, states: Vec<DataState>) -> CorrelationOutcome {
        let cands: Vec<RecoveryCandidate> = frags
            .iter()
            .zip(states)
            .map(|(f, s)| candidate(f.physical_region, f.evidence_id, s))
            .collect();
        correlate_fragments(&cands, &frags, CorrelationBounds::default())
    }

    #[test]
    fn fragments_sharing_a_parent_recording_become_one_recording() {
        let ev = EvidenceId::new();
        let frags = vec![
            FragBuilder::new(ev, 0x2000, 0x400)
                .parent("didx#3")
                .seq(2)
                .build(),
            FragBuilder::new(ev, 0x1000, 0x400)
                .parent("didx#3")
                .seq(1)
                .build(),
            FragBuilder::new(ev, 0x9000, 0x400)
                .parent("didx#7")
                .seq(1)
                .build(),
        ];
        let out = run(frags, vec![DataState::Active; 3]);

        assert_eq!(out.recordings.len(), 2, "two parents, two recordings");
        let first = &out.recordings[0];
        assert_eq!(first.fragment_ids.len(), 2);
        assert_eq!(first.ordering, TemporalOrdering::BySequenceNumber);
        // Ordered by sequence, which here agrees with offsets.
        assert_eq!(first.regions[0], r(0x1000, 0x400));
        assert_eq!(first.regions[1], r(0x2000, 0x400));
        assert!(matches!(
            first.grouping,
            GroupingBasis::ParentRecording { .. }
        ));
        assert_eq!(out.groups_considered, 2);
    }

    #[test]
    fn physical_adjacency_alone_never_groups_or_orders() {
        let ev = EvidenceId::new();
        // Back-to-back on disk, but the recorder said nothing about either.
        let frags = vec![
            FragBuilder::new(ev, 0x1000, 0x1000).build(),
            FragBuilder::new(ev, 0x2000, 0x1000).build(),
        ];
        let out = run(frags, vec![DataState::Unindexed; 2]);

        assert_eq!(
            out.recordings.len(),
            2,
            "adjacent fragments with no recorder evidence stay separate"
        );
        assert!(out
            .recordings
            .iter()
            .all(|r| matches!(r.grouping, GroupingBasis::Ungrouped { .. })));
        assert!(out
            .recordings
            .iter()
            .all(|r| r.ordering == TemporalOrdering::SingleFragment));
    }

    #[test]
    fn a_group_without_ordering_evidence_is_unknown_not_invented() {
        let ev = EvidenceId::new();
        let frags = vec![
            FragBuilder::new(ev, 0x1000, 0x400).parent("r1").build(),
            FragBuilder::new(ev, 0x2000, 0x400).parent("r1").build(),
        ];
        let out = run(frags, vec![DataState::Orphaned; 2]);

        assert_eq!(out.recordings.len(), 1);
        let rec = &out.recordings[0];
        match &rec.ordering {
            TemporalOrdering::Unknown { reason } => {
                assert!(
                    reason.contains("physical adjacency is not used"),
                    "{reason}"
                );
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
        assert_eq!(rec.validation.state, ValidationStateKind::Review);
        assert_eq!(out.validation.state, ValidationStateKind::Review);
    }

    #[test]
    fn duplicate_sequence_numbers_make_the_ordering_unknown() {
        let ev = EvidenceId::new();
        let frags = vec![
            FragBuilder::new(ev, 0x1000, 0x400)
                .parent("r1")
                .seq(5)
                .build(),
            FragBuilder::new(ev, 0x2000, 0x400)
                .parent("r1")
                .seq(5)
                .build(),
        ];
        let out = run(frags, vec![DataState::Active; 2]);

        let rec = &out.recordings[0];
        assert!(matches!(rec.ordering, TemporalOrdering::Unknown { .. }));
        assert!(rec.evidence.iter().any(|e| e.kind == "sequence-conflict"));
        assert!(rec.reassembly.is_none(), "no report without a usable order");
    }

    #[test]
    fn timestamps_order_a_group_when_sequence_numbers_are_absent() {
        let ev = EvidenceId::new();
        let frags = vec![
            FragBuilder::new(ev, 0x9000, 0x400)
                .parent("r1")
                .time(200)
                .build(),
            FragBuilder::new(ev, 0x1000, 0x400)
                .parent("r1")
                .time(100)
                .build(),
        ];
        let out = run(frags, vec![DataState::Active; 2]);

        let rec = &out.recordings[0];
        assert_eq!(rec.ordering, TemporalOrdering::ByRecorderTimestamp);
        assert_eq!(rec.regions[0], r(0x1000, 0x400));
        assert_eq!(rec.start_time_unix, Some(100));
        assert_eq!(rec.end_time_unix, Some(200));
    }

    #[test]
    fn channel_grouping_is_confined_to_one_described_region() {
        let ev = EvidenceId::new();
        let frags = vec![
            FragBuilder::new(ev, 0x1000, 0x400)
                .channel(2)
                .originating(0x1000, 0x8000)
                .seq(1)
                .build(),
            FragBuilder::new(ev, 0x2000, 0x400)
                .channel(2)
                .originating(0x1000, 0x8000)
                .seq(2)
                .build(),
            // Same channel, different described region — a different recording.
            FragBuilder::new(ev, 0x40000, 0x400)
                .channel(2)
                .originating(0x40000, 0x8000)
                .seq(1)
                .build(),
        ];
        let out = run(frags, vec![DataState::Orphaned; 3]);

        assert_eq!(out.recordings.len(), 2);
        assert_eq!(out.recordings[0].fragment_ids.len(), 2);
        assert_eq!(out.recordings[1].fragment_ids.len(), 1);
        assert!(matches!(
            out.recordings[0].grouping,
            GroupingBasis::ChannelWithinDescribedRegion { channel: 2, .. }
        ));
    }

    #[test]
    fn a_mixed_state_group_reports_no_single_state() {
        let ev = EvidenceId::new();
        let frags = vec![
            FragBuilder::new(ev, 0x1000, 0x400)
                .parent("r1")
                .seq(1)
                .build(),
            FragBuilder::new(ev, 0x2000, 0x400)
                .parent("r1")
                .seq(2)
                .build(),
        ];
        let out = run(frags, vec![DataState::Active, DataState::Corrupted]);

        let rec = &out.recordings[0];
        assert_eq!(rec.data_state, None);
        assert_eq!(rec.member_states.len(), 2);
        assert!(rec.evidence.iter().any(|e| e.kind == "mixed-member-states"));
    }

    #[test]
    fn correlation_is_deterministic_regardless_of_discovery_order() {
        let ev = EvidenceId::new();
        let mk = || {
            vec![
                FragBuilder::new(ev, 0x3000, 0x400)
                    .parent("b")
                    .seq(1)
                    .build(),
                FragBuilder::new(ev, 0x1000, 0x400)
                    .parent("a")
                    .seq(2)
                    .build(),
                FragBuilder::new(ev, 0x2000, 0x400)
                    .parent("a")
                    .seq(1)
                    .build(),
            ]
        };
        let forward = run(mk(), vec![DataState::Active; 3]);
        let mut reversed = mk();
        reversed.reverse();
        let backward = run(reversed, vec![DataState::Active; 3]);

        let keys_f: Vec<&str> = forward
            .recordings
            .iter()
            .map(|r| r.recording_key.as_str())
            .collect();
        let keys_b: Vec<&str> = backward
            .recordings
            .iter()
            .map(|r| r.recording_key.as_str())
            .collect();
        assert_eq!(keys_f, keys_b);
        assert_eq!(
            forward.recordings[0].regions,
            backward.recordings[0].regions
        );
    }

    #[test]
    fn the_group_budget_is_enforced_and_reported() {
        let ev = EvidenceId::new();
        let frags: Vec<DiscoveredFragment> = (0..50)
            .map(|i| {
                FragBuilder::new(ev, 0x1000 + i * 0x1000, 0x400)
                    .parent(&format!("r{i}"))
                    .build()
            })
            .collect();
        let states = vec![DataState::Active; 50];
        let cands: Vec<RecoveryCandidate> = frags
            .iter()
            .zip(states)
            .map(|(f, s)| candidate(f.physical_region, f.evidence_id, s))
            .collect();

        let out = correlate_fragments(
            &cands,
            &frags,
            CorrelationBounds {
                max_groups: 5,
                max_fragments_per_group: 10,
            },
        );

        assert_eq!(out.recordings.len(), 5);
        assert_eq!(
            out.groups_considered, 50,
            "what was formed is still reported"
        );
        assert!(out.truncated);
        assert_eq!(out.validation.state, ValidationStateKind::Review);
        assert!(out.validation.reason.contains("bounded"));
    }

    #[test]
    fn the_member_budget_is_enforced_per_group() {
        let ev = EvidenceId::new();
        let frags: Vec<DiscoveredFragment> = (0..20)
            .map(|i| {
                FragBuilder::new(ev, 0x1000 + i * 0x1000, 0x400)
                    .parent("one-recording")
                    .seq(i)
                    .build()
            })
            .collect();
        let cands: Vec<RecoveryCandidate> = frags
            .iter()
            .map(|f| candidate(f.physical_region, f.evidence_id, DataState::Active))
            .collect();

        let out = correlate_fragments(
            &cands,
            &frags,
            CorrelationBounds {
                max_groups: 64,
                max_fragments_per_group: 4,
            },
        );

        assert_eq!(out.recordings.len(), 1);
        assert_eq!(out.recordings[0].fragment_ids.len(), 4);
        assert!(out.truncated);
        assert!(out.recordings[0]
            .evidence
            .iter()
            .any(|e| e.kind == "membership-bounded"));
    }

    #[test]
    fn every_fragment_appears_in_exactly_one_group() {
        let ev = EvidenceId::new();
        let frags = vec![
            FragBuilder::new(ev, 0x1000, 0x400)
                .parent("r1")
                .seq(1)
                .build(),
            FragBuilder::new(ev, 0x2000, 0x400)
                .parent("r1")
                .seq(2)
                .build(),
            FragBuilder::new(ev, 0x5000, 0x400).channel(4).build(),
            FragBuilder::new(ev, 0x8000, 0x400).build(),
        ];
        let ids: Vec<String> = frags.iter().map(|f| f.fragment_id.clone()).collect();
        let out = run(frags, vec![DataState::Active; 4]);

        let mut seen: Vec<String> = out
            .recordings
            .iter()
            .flat_map(|r| r.fragment_ids.iter().cloned())
            .collect();
        seen.sort();
        let mut expected = ids;
        expected.sort();
        assert_eq!(seen, expected);
    }

    #[test]
    fn overlapping_members_are_reported_not_merged() {
        let ev = EvidenceId::new();
        let frags = vec![
            FragBuilder::new(ev, 0x1000, 0x800)
                .parent("r1")
                .seq(1)
                .build(),
            FragBuilder::new(ev, 0x1400, 0x800)
                .parent("r1")
                .seq(2)
                .build(),
        ];
        let out = run(frags, vec![DataState::Active; 2]);

        let rec = &out.recordings[0];
        assert_eq!(
            rec.regions.len(),
            2,
            "overlapping members are kept distinct"
        );
        assert!(rec.evidence.iter().any(|e| e.kind == "region-overlap"));
        assert_eq!(rec.validation.state, ValidationStateKind::Review);
    }

    #[test]
    fn a_sequence_gap_is_recorded_and_never_filled() {
        let ev = EvidenceId::new();
        let frags = vec![
            FragBuilder::new(ev, 0x1000, 0x400)
                .parent("r1")
                .seq(1)
                .build(),
            FragBuilder::new(ev, 0x2000, 0x400)
                .parent("r1")
                .seq(6)
                .build(),
        ];
        let out = run(frags, vec![DataState::Active; 2]);

        let rec = &out.recordings[0];
        assert_eq!(rec.ordering, TemporalOrdering::BySequenceNumber);
        let report = rec
            .reassembly
            .as_ref()
            .expect("sequence numbers give a report");
        assert_eq!(report.logical_gaps.len(), 1);
        assert_eq!(report.logical_gaps[0].missing_count, 4);
        assert_eq!(
            rec.regions.len(),
            2,
            "the gap is recorded, not filled with a synthesized member"
        );
        assert!(rec.evidence.iter().any(|e| e.kind == "logical-gap"));
    }

    #[test]
    fn correlating_nothing_is_unknown_not_pass() {
        let out = correlate_fragments(&[], &[], CorrelationBounds::default());
        assert!(out.recordings.is_empty());
        assert_eq!(out.validation.state, ValidationStateKind::Unknown);
        assert_eq!(out.groups_considered, 0);
    }
}
