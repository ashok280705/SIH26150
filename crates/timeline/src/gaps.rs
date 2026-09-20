//! # Timeline gap detection and coverage estimation
//!
//! Implements the "Detect Gaps" and "Estimate Coverage" responsibilities of the
//! preliminary-timeline stage, and produces the evidence the `Gaps?` decision gate
//! branches on.
//!
//! Forensic constraints upheld here:
//!
//! * Gaps are **reported, never filled**. No event, frame, or timestamp is synthesized.
//! * Two independent dimensions are assessed and never collapsed into one number:
//!   **temporal** gaps (missing time between events on a channel) and **physical**
//!   coverage (bytes of the image not accounted for by any parsed recording).
//! * A dimension that cannot be assessed reports `Unknown` rather than a default
//!   "complete" result. An unmeasured gap check is never reported as "no gaps".
//! * Events whose timezone is `Unknown` are excluded from temporal gap maths (their
//!   instants are not comparable) and counted separately, never silently treated as UTC.

use forensic_core::{Region, TimeEvidence, TimelineEvent, TimeZoneState, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};

/// A detected gap in temporal coverage on a single channel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineGap {
    pub channel: u32,
    /// Normalized instant the gap opens (end of the earlier event).
    pub starts_after_iso: String,
    /// Normalized instant the gap closes (start of the later event).
    pub ends_before_iso: String,
    /// Duration of the unobserved window, in seconds.
    pub gap_seconds: i64,
    /// Byte offset of the earlier event, for navigation back to the evidence.
    pub previous_offset: u64,
    /// Byte offset of the later event.
    pub next_offset: u64,
    pub reason: String,
}

/// A contiguous span of the image not accounted for by any parsed recording.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnaccountedRegion {
    pub region: Region,
    pub reason: String,
}

/// Physical coverage of the evidence image by parsed recordings.
///
/// `coverage_ratio` is a measured quantity: merged accounted bytes over total bytes.
/// It is never an estimate of "how much video was recovered" — only of how much of
/// the image the parser could attribute to a recording.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoverageEstimate {
    pub total_bytes: u64,
    pub accounted_bytes: u64,
    pub unaccounted_bytes: u64,
    /// 0.0 ..= 1.0
    pub coverage_ratio: f64,
    pub largest_unaccounted: Option<UnaccountedRegion>,
    pub unaccounted_regions: Vec<UnaccountedRegion>,
    /// How the figure was derived, recorded so a reader can reproduce it.
    pub method: String,
}

/// Combined two-dimensional gap assessment driving the `Gaps?` gate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GapAnalysis {
    pub temporal_gaps: Vec<TimelineGap>,
    pub coverage: CoverageEstimate,
    /// Events excluded from temporal maths because their timezone is `Unknown`.
    pub events_with_unknown_timezone: usize,
    /// Events carrying no normalized instant at all.
    pub events_without_normalized_time: usize,
    /// True when either dimension shows a shortfall worth sending to recovery.
    pub gaps_present: bool,
    pub validation: ValidationState,
}

impl GapAnalysis {
    /// Total seconds of unobserved time across all channels.
    pub fn total_gap_seconds(&self) -> i64 {
        self.temporal_gaps.iter().map(|g| g.gap_seconds).sum()
    }
}

/// Parse a normalized ISO-8601 instant into a UTC datetime.
fn parse_instant(iso: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(iso) {
        return Some(dt.with_timezone(&chrono::Utc));
    }
    for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(iso, fmt) {
            return Some(naive.and_utc());
        }
    }
    None
}

/// A comparable instant for an event, or `None` when it must be excluded.
fn comparable_instant(time: &TimeEvidence) -> Option<chrono::DateTime<chrono::Utc>> {
    // An Unknown timezone means the instant is not comparable across channels.
    if time.timezone == TimeZoneState::Unknown {
        return None;
    }
    time.normalized
        .as_ref()
        .and_then(|n| parse_instant(&n.iso_8601))
}

/// Merge overlapping/adjacent regions into a canonical ascending set.
fn merge_regions(mut regions: Vec<Region>) -> Vec<Region> {
    regions.sort_by_key(|r| (r.offset, r.length));
    let mut merged: Vec<Region> = Vec::new();
    for r in regions {
        if r.length == 0 {
            continue;
        }
        match merged.last_mut() {
            Some(last) => {
                let last_end = last.offset.saturating_add(last.length);
                if r.offset <= last_end {
                    // Overlapping or touching: extend.
                    let new_end = last_end.max(r.offset.saturating_add(r.length));
                    last.length = new_end.saturating_sub(last.offset);
                } else {
                    merged.push(r);
                }
            }
            None => merged.push(r),
        }
    }
    merged
}

/// Measure how much of the image the parsed recordings account for.
///
/// `min_unaccounted_bytes` suppresses trivially small holes (sector padding and
/// container framing) so the result highlights spans worth carving.
pub fn estimate_coverage(
    recording_regions: Vec<Region>,
    total_bytes: u64,
    min_unaccounted_bytes: u64,
) -> CoverageEstimate {
    let merged = merge_regions(recording_regions);
    let accounted_bytes: u64 = merged.iter().map(|r| r.length).sum();
    let accounted_bytes = accounted_bytes.min(total_bytes);

    let mut unaccounted_regions = Vec::new();
    let mut cursor = 0u64;
    for r in &merged {
        if r.offset > cursor {
            let length = r.offset - cursor;
            if length >= min_unaccounted_bytes {
                unaccounted_regions.push(UnaccountedRegion {
                    region: Region { offset: cursor, length },
                    reason: format!(
                        "{length} bytes between accounted recordings are not referenced by any parsed recording"
                    ),
                });
            }
        }
        cursor = cursor.max(r.offset.saturating_add(r.length));
    }
    if cursor < total_bytes {
        let length = total_bytes - cursor;
        if length >= min_unaccounted_bytes {
            unaccounted_regions.push(UnaccountedRegion {
                region: Region { offset: cursor, length },
                reason: format!(
                    "{length} trailing bytes after the last accounted recording are unreferenced"
                ),
            });
        }
    }

    let largest_unaccounted = unaccounted_regions
        .iter()
        .max_by_key(|u| u.region.length)
        .cloned();

    let coverage_ratio = if total_bytes == 0 {
        0.0
    } else {
        accounted_bytes as f64 / total_bytes as f64
    };

    CoverageEstimate {
        total_bytes,
        accounted_bytes,
        unaccounted_bytes: total_bytes.saturating_sub(accounted_bytes),
        coverage_ratio,
        largest_unaccounted,
        unaccounted_regions,
        method: format!(
            "Merged parsed recording regions over total image size; holes smaller than {min_unaccounted_bytes} bytes suppressed"
        ),
    }
}

/// Detect temporal gaps per channel in the supplied events.
///
/// A gap is reported when consecutive events on the same channel are separated by
/// more than `max_gap_seconds` of normalized time.
pub fn detect_timeline_gaps(events: &[TimelineEvent], max_gap_seconds: i64) -> Vec<TimelineGap> {
    use std::collections::BTreeMap;

    let mut per_channel: BTreeMap<u32, Vec<(chrono::DateTime<chrono::Utc>, u64)>> = BTreeMap::new();
    for e in events {
        if let Some(instant) = comparable_instant(&e.time) {
            let offset = e.source_offsets.iter().map(|r| r.offset).min().unwrap_or(0);
            per_channel.entry(e.channel).or_default().push((instant, offset));
        }
    }

    let mut gaps = Vec::new();
    for (channel, mut points) in per_channel {
        points.sort_by_key(|(instant, offset)| (*instant, *offset));
        for window in points.windows(2) {
            let (prev, prev_off) = window[0];
            let (next, next_off) = window[1];
            let delta = (next - prev).num_seconds();
            if delta > max_gap_seconds {
                gaps.push(TimelineGap {
                    channel,
                    starts_after_iso: prev.to_rfc3339(),
                    ends_before_iso: next.to_rfc3339(),
                    gap_seconds: delta,
                    previous_offset: prev_off,
                    next_offset: next_off,
                    reason: format!(
                        "No observed activity on channel {channel} for {delta}s, exceeding the {max_gap_seconds}s continuity threshold"
                    ),
                });
            }
        }
    }
    gaps
}

/// Run both gap dimensions and produce the gate input.
///
/// `gaps_present` is true when there is a temporal gap OR an unaccounted span large
/// enough to be worth a recovery pass. When neither dimension could be measured the
/// validation state is `Unknown` and `gaps_present` is left false, but the reason
/// records that the check did not run — an unrun check is never reported as a pass.
pub fn analyze(
    events: &[TimelineEvent],
    recording_regions: Vec<Region>,
    total_bytes: u64,
    max_gap_seconds: i64,
    min_unaccounted_bytes: u64,
) -> GapAnalysis {
    let temporal_gaps = detect_timeline_gaps(events, max_gap_seconds);
    let coverage = estimate_coverage(recording_regions, total_bytes, min_unaccounted_bytes);

    let events_with_unknown_timezone = events
        .iter()
        .filter(|e| e.time.timezone == TimeZoneState::Unknown)
        .count();
    let events_without_normalized_time =
        events.iter().filter(|e| e.time.normalized.is_none()).count();

    let comparable_events = events.len()
        - events
            .iter()
            .filter(|e| comparable_instant(&e.time).is_none())
            .count();

    let has_temporal_gaps = !temporal_gaps.is_empty();
    let has_unaccounted = !coverage.unaccounted_regions.is_empty();
    let gaps_present = has_temporal_gaps || has_unaccounted;

    // Temporal continuity needs at least two comparable events to say anything.
    let temporal_measurable = comparable_events >= 2;

    let validation = if gaps_present {
        let mut parts = Vec::new();
        if has_temporal_gaps {
            let total: i64 = temporal_gaps.iter().map(|g| g.gap_seconds).sum();
            parts.push(format!(
                "{} temporal gap(s) totalling {}s",
                temporal_gaps.len(),
                total
            ));
        }
        if has_unaccounted {
            parts.push(format!(
                "{} unaccounted region(s) totalling {} bytes ({:.1}% of the image is attributed)",
                coverage.unaccounted_regions.len(),
                coverage.unaccounted_bytes,
                coverage.coverage_ratio * 100.0
            ));
        }
        ValidationState::new(
            ValidationStateKind::Review,
            format!("Coverage shortfall detected: {}", parts.join("; ")),
            "analyze_gaps",
            "PreliminaryTimeline",
        )
        .unwrap()
    } else if !temporal_measurable && total_bytes == 0 {
        ValidationState::new(
            ValidationStateKind::Unknown,
            "Gap analysis did not run: no comparable timestamps and no image extent available",
            "analyze_gaps",
            "PreliminaryTimeline",
        )
        .unwrap()
    } else if !temporal_measurable {
        ValidationState::new(
            ValidationStateKind::Review,
            format!(
                "Physical coverage is complete ({:.1}%), but temporal continuity could not be assessed: fewer than two events carry a comparable normalized instant ({} with unknown timezone, {} with no normalized time)",
                coverage.coverage_ratio * 100.0,
                events_with_unknown_timezone,
                events_without_normalized_time
            ),
            "analyze_gaps",
            "PreliminaryTimeline",
        )
        .unwrap()
    } else {
        ValidationState::new(
            ValidationStateKind::Pass,
            format!(
                "No temporal gaps beyond {}s across {} comparable event(s); {:.1}% of the image is attributed to parsed recordings",
                max_gap_seconds,
                comparable_events,
                coverage.coverage_ratio * 100.0
            ),
            "analyze_gaps",
            "PreliminaryTimeline",
        )
        .unwrap()
    };

    GapAnalysis {
        temporal_gaps,
        coverage,
        events_with_unknown_timezone,
        events_without_normalized_time,
        gaps_present,
        validation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_core::{
        Hash, NormalizedTime, ProfileId, Provenance, RawTimestamp, RecorderNativeTime, TimeEvidence,
    };

    fn event(channel: u32, offset: u64, norm: Option<&str>, tz: TimeZoneState) -> TimelineEvent {
        let prov = Provenance::new(
            forensic_core::EvidenceId::new(),
            Hash::sha256(vec![0; 32]),
            vec![],
            "test",
            "1.0",
            Hash::sha256(vec![0; 32]),
            ValidationState::pass("raw", "valid", "raw").unwrap(),
        );
        TimelineEvent {
            channel,
            time: TimeEvidence {
                raw: RawTimestamp { value: 0, format: "UNIX".into(), source: prov },
                recorder_native: Some(RecorderNativeTime { iso_8601: "2024-01-01T00:00:00".into() }),
                normalized: norm.map(|n| NormalizedTime {
                    iso_8601: n.to_string(),
                    method: "test".into(),
                }),
                reference: None,
                timezone: tz,
                correction: None,
            },
            description: "e".into(),
            source_offsets: vec![Region { offset, length: 100 }],
            parser_id: "p".into(),
            parser_version: "1".into(),
            profile_id: ProfileId("prof".into()),
            profile_hash: Hash::sha256(vec![0; 32]),
        }
    }

    #[test]
    fn detects_temporal_gap_beyond_threshold() {
        let events = vec![
            event(1, 0, Some("2024-01-01T00:00:00Z"), TimeZoneState::Known("UTC".into())),
            event(1, 500, Some("2024-01-01T01:00:00Z"), TimeZoneState::Known("UTC".into())),
        ];
        let gaps = detect_timeline_gaps(&events, 60);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].gap_seconds, 3600);
        assert_eq!(gaps[0].channel, 1);
    }

    #[test]
    fn no_gap_within_threshold() {
        let events = vec![
            event(1, 0, Some("2024-01-01T00:00:00Z"), TimeZoneState::Known("UTC".into())),
            event(1, 500, Some("2024-01-01T00:00:30Z"), TimeZoneState::Known("UTC".into())),
        ];
        assert!(detect_timeline_gaps(&events, 60).is_empty());
    }

    #[test]
    fn unknown_timezone_events_are_excluded_not_assumed_utc() {
        // Two events an hour apart, but timezone Unknown: they are not comparable,
        // so no gap may be asserted from them.
        let events = vec![
            event(1, 0, Some("2024-01-01T00:00:00Z"), TimeZoneState::Unknown),
            event(1, 500, Some("2024-01-01T01:00:00Z"), TimeZoneState::Unknown),
        ];
        assert!(detect_timeline_gaps(&events, 60).is_empty());

        let analysis = analyze(&events, vec![Region { offset: 0, length: 100 }], 100, 60, 4096);
        assert_eq!(analysis.events_with_unknown_timezone, 2);
        // Cannot claim PASS when continuity was not assessable.
        assert_ne!(analysis.validation.state, ValidationStateKind::Pass);
    }

    #[test]
    fn gaps_are_reported_per_channel_independently() {
        let events = vec![
            event(1, 0, Some("2024-01-01T00:00:00Z"), TimeZoneState::Known("UTC".into())),
            event(2, 100, Some("2024-01-01T05:00:00Z"), TimeZoneState::Known("UTC".into())),
        ];
        // One event per channel: no intra-channel pair, so no gap.
        assert!(detect_timeline_gaps(&events, 60).is_empty());
    }

    #[test]
    fn coverage_merges_overlapping_regions() {
        let cov = estimate_coverage(
            vec![
                Region { offset: 0, length: 100 },
                Region { offset: 50, length: 100 },
            ],
            200,
            1,
        );
        assert_eq!(cov.accounted_bytes, 150);
        assert_eq!(cov.unaccounted_bytes, 50);
        assert_eq!(cov.unaccounted_regions.len(), 1);
        assert_eq!(cov.unaccounted_regions[0].region.offset, 150);
    }

    #[test]
    fn coverage_suppresses_small_holes() {
        let cov = estimate_coverage(
            vec![
                Region { offset: 0, length: 100 },
                Region { offset: 200, length: 100 },
            ],
            300,
            4096,
        );
        // The 100-byte hole is below the threshold and is not reported.
        assert!(cov.unaccounted_regions.is_empty());
        assert_eq!(cov.accounted_bytes, 200);
    }

    #[test]
    fn full_coverage_and_continuity_passes() {
        let events = vec![
            event(1, 0, Some("2024-01-01T00:00:00Z"), TimeZoneState::Known("UTC".into())),
            event(1, 100, Some("2024-01-01T00:00:10Z"), TimeZoneState::Known("UTC".into())),
        ];
        let analysis = analyze(&events, vec![Region { offset: 0, length: 1000 }], 1000, 60, 4096);
        assert!(!analysis.gaps_present);
        assert_eq!(analysis.validation.state, ValidationStateKind::Pass);
        assert_eq!(analysis.coverage.coverage_ratio, 1.0);
    }

    #[test]
    fn gaps_are_never_filled() {
        let events = vec![
            event(1, 0, Some("2024-01-01T00:00:00Z"), TimeZoneState::Known("UTC".into())),
            event(1, 500, Some("2024-01-01T02:00:00Z"), TimeZoneState::Known("UTC".into())),
        ];
        let analysis = analyze(&events, vec![Region { offset: 0, length: 600 }], 1000, 60, 100);
        // The gap is recorded; the event count is unchanged — nothing synthesized.
        assert_eq!(events.len(), 2);
        assert_eq!(analysis.temporal_gaps.len(), 1);
        assert!(analysis.gaps_present);
        assert_eq!(analysis.validation.state, ValidationStateKind::Review);
    }
}
