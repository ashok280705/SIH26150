//! Timeline Engine (Req 15.1–15.6, 4.3, 4.5, 4.6, 14.7).
//!
//! Owns unified timeline construction from Parser candidate events across all cameras.
//! Supports three distinguishable orderings:
//! - Physical (by lowest source offset)
//! - RecorderNative (by native timestamp)
//! - Normalized (by normalized UTC time)
//!
//! Guarantees:
//! - Raw and recorder-native timestamps are NEVER mutated or overwritten (Property 8, Req 4.5)
//! - Unknown timezone states are preserved and flagged, NEVER assumed to be UTC (Req 4.6)
//! - Physical storage order is NEVER equated with chronological order (Req 15.6, 14.7)

use forensic_core::{
    TimelineEvent, TimeZoneState, ValidationState, ValidationStateKind,
};
use serde::{Deserialize, Serialize};

/// The three distinguishable ordering modes for timeline events (Req 15.6, 14.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimelineOrdering {
    /// Ordered by physical disk offset (lowest starting byte offset first).
    Physical,
    /// Ordered by recorder-native timestamp string.
    RecorderNative,
    /// Ordered by normalized UTC timestamp string.
    Normalized,
}

/// A unified timeline constructed from multi-camera candidate events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnifiedTimeline {
    pub events: Vec<TimelineEvent>,
    pub ordering: TimelineOrdering,
    pub has_unknown_timezones: bool,
    pub validation: ValidationState,
}

pub struct TimelineEngine;

impl TimelineEngine {
    /// Builds a unified cross-camera timeline from candidate events.
    /// The parser only emits candidates; the engine owns construction (Req 15.1, 15.5).
    pub fn build_timeline(
        candidates: Vec<TimelineEvent>,
        ordering: TimelineOrdering,
    ) -> UnifiedTimeline {
        let mut events = candidates;
        let mut has_unknown_timezones = false;

        for event in &events {
            if event.time.timezone == TimeZoneState::Unknown {
                has_unknown_timezones = true;
            }
        }

        // Canonical deterministic sorting based on selected ordering mode (Req 20.1)
        match ordering {
            TimelineOrdering::Physical => {
                events.sort_by(|a, b| {
                    let a_off = a.source_offsets.iter().map(|r| r.offset).min().unwrap_or(u64::MAX);
                    let b_off = b.source_offsets.iter().map(|r| r.offset).min().unwrap_or(u64::MAX);
                    a_off.cmp(&b_off)
                        .then_with(|| a.channel.cmp(&b.channel))
                        .then_with(|| {
                            let an = a.time.recorder_native.as_ref().map(|t| &t.iso_8601);
                            let bn = b.time.recorder_native.as_ref().map(|t| &t.iso_8601);
                            an.cmp(&bn)
                        })
                        .then_with(|| {
                            let an = a.time.normalized.as_ref().map(|t| &t.iso_8601);
                            let bn = b.time.normalized.as_ref().map(|t| &t.iso_8601);
                            an.cmp(&bn)
                        })
                        .then_with(|| a.description.cmp(&b.description))
                        .then_with(|| a.parser_id.cmp(&b.parser_id))
                        .then_with(|| a.profile_id.0.cmp(&b.profile_id.0))
                });
            }
            TimelineOrdering::RecorderNative => {
                events.sort_by(|a, b| {
                    let a_native = a.time.recorder_native.as_ref().map(|t| &t.iso_8601);
                    let b_native = b.time.recorder_native.as_ref().map(|t| &t.iso_8601);
                    a_native.cmp(&b_native)
                        .then_with(|| a.channel.cmp(&b.channel))
                        .then_with(|| {
                            let a_off = a.source_offsets.iter().map(|r| r.offset).min().unwrap_or(u64::MAX);
                            let b_off = b.source_offsets.iter().map(|r| r.offset).min().unwrap_or(u64::MAX);
                            a_off.cmp(&b_off)
                        })
                        .then_with(|| a.description.cmp(&b.description))
                        .then_with(|| a.time.raw.value.cmp(&b.time.raw.value))
                        .then_with(|| a.parser_id.cmp(&b.parser_id))
                        .then_with(|| a.profile_id.0.cmp(&b.profile_id.0))
                });
            }
            TimelineOrdering::Normalized => {
                events.sort_by(|a, b| {
                    let a_norm = a.time.normalized.as_ref().map(|t| &t.iso_8601);
                    let b_norm = b.time.normalized.as_ref().map(|t| &t.iso_8601);
                    a_norm.cmp(&b_norm)
                        .then_with(|| a.channel.cmp(&b.channel))
                        .then_with(|| {
                            let an = a.time.recorder_native.as_ref().map(|t| &t.iso_8601);
                            let bn = b.time.recorder_native.as_ref().map(|t| &t.iso_8601);
                            an.cmp(&bn)
                        })
                        .then_with(|| {
                            let a_off = a.source_offsets.iter().map(|r| r.offset).min().unwrap_or(u64::MAX);
                            let b_off = b.source_offsets.iter().map(|r| r.offset).min().unwrap_or(u64::MAX);
                            a_off.cmp(&b_off)
                        })
                        .then_with(|| a.description.cmp(&b.description))
                        .then_with(|| a.time.raw.value.cmp(&b.time.raw.value))
                        .then_with(|| a.parser_id.cmp(&b.parser_id))
                        .then_with(|| a.profile_id.0.cmp(&b.profile_id.0))
                });
            }
        }

        let validation = if events.is_empty() {
            ValidationState::new(
                ValidationStateKind::Unknown,
                "No candidate timeline events provided",
                "build_timeline",
                "Timeline",
            ).unwrap()
        } else if has_unknown_timezones && ordering == TimelineOrdering::Normalized {
            ValidationState::new(
                ValidationStateKind::Review,
                "Timeline contains events with Unknown timezone; review required",
                "build_timeline",
                "Timeline",
            ).unwrap()
        } else {
            ValidationState::new(
                ValidationStateKind::Pass,
                "Unified timeline successfully constructed and deterministically ordered",
                "build_timeline",
                "Timeline",
            ).unwrap()
        };

        UnifiedTimeline {
            events,
            ordering,
            has_unknown_timezones,
            validation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_core::{Hash, ProfileId, RawTimestamp, RecorderNativeTime, NormalizedTime, Provenance, Region, TimeEvidence};

    fn make_test_event(channel: u32, offset: u64, native_time: &str, norm_time: &str, tz: TimeZoneState) -> TimelineEvent {
        let raw_prov = Provenance::new(
            forensic_core::EvidenceId::new(),
            Hash::sha256(vec![0; 32]),
            vec![],
            "TestParser",
            "1.0.0",
            Hash::sha256(vec![0; 32]),
            ValidationState::pass("raw", "valid", "raw").unwrap(),
        );

        let time = TimeEvidence {
            raw: RawTimestamp { value: 123456, format: "BCD".into(), source: raw_prov },
            recorder_native: Some(RecorderNativeTime { iso_8601: native_time.into() }),
            normalized: Some(NormalizedTime { iso_8601: norm_time.into(), method: "UTC offset".into() }),
            reference: None,
            timezone: tz,
            correction: None,
        };

        TimelineEvent {
            channel,
            time,
            description: format!("Event on CH {}", channel),
            source_offsets: vec![Region { offset, length: 1024 }],
            parser_id: "test_parser".into(),
            parser_version: "1.0.0".into(),
            profile_id: ProfileId("test-prof".into()),
            profile_hash: Hash::sha256(vec![0; 32]),
        }
    }

    #[test]
    fn test_three_orderings_are_distinguishable() {
        // Event 1: physically at offset 1000, but chronologically later (2026-09-01 14:00)
        let e1 = make_test_event(1, 1000, "2026-09-01T14:00:00", "2026-09-01T14:00:00Z", TimeZoneState::Known("UTC".into()));
        // Event 2: physically at offset 5000, but chronologically earlier (2026-09-01 10:00)
        let e2 = make_test_event(2, 5000, "2026-09-01T10:00:00", "2026-09-01T10:00:00Z", TimeZoneState::Known("UTC".into()));

        let candidates = vec![e1.clone(), e2.clone()];

        // 1. Physical ordering: e1 (offset 1000) then e2 (offset 5000)
        let physical = TimelineEngine::build_timeline(candidates.clone(), TimelineOrdering::Physical);
        assert_eq!(physical.events[0].channel, 1);
        assert_eq!(physical.events[1].channel, 2);

        // 2. Normalized chronological ordering: e2 (10:00) then e1 (14:00)
        let normalized = TimelineEngine::build_timeline(candidates.clone(), TimelineOrdering::Normalized);
        assert_eq!(normalized.events[0].channel, 2);
        assert_eq!(normalized.events[1].channel, 1);
    }

    #[test]
    fn test_property_8_raw_and_native_timestamps_preserved_under_ordering() {
        let e1 = make_test_event(1, 1000, "2026-09-01T14:00:00", "2026-09-01T14:00:00Z", TimeZoneState::Known("UTC".into()));
        let e2 = make_test_event(2, 5000, "2026-09-01T10:00:00", "2026-09-01T10:00:00Z", TimeZoneState::Known("UTC".into()));

        let timeline = TimelineEngine::build_timeline(vec![e1, e2], TimelineOrdering::Normalized);

        // Raw timestamp values and formats remain identical after sorting
        assert_eq!(timeline.events[0].time.raw.value, 123456);
        assert_eq!(timeline.events[0].time.raw.format, "BCD");
        assert_eq!(timeline.events[0].time.recorder_native.as_ref().unwrap().iso_8601, "2026-09-01T10:00:00");
    }

    #[test]
    fn test_unknown_timezone_flags_review_under_normalized_ordering() {
        let e1 = make_test_event(1, 1000, "2026-09-01T14:00:00", "2026-09-01T14:00:00Z", TimeZoneState::Unknown);
        let timeline = TimelineEngine::build_timeline(vec![e1], TimelineOrdering::Normalized);

        assert!(timeline.has_unknown_timezones);
        assert_eq!(timeline.validation.state, ValidationStateKind::Review);
    }
}
