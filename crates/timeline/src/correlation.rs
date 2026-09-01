//! Cross-Camera Event Correlation (Req 15.4).
//!
//! Correlates events across cameras within configurable time windows.
//! Guarantees:
//! - Correlation is a deterministic linkage, NEVER a claim of causation
//! - Underlying events are NEVER merged or modified
//! - Events with Unknown timezone are correlated only with an explicit uncertainty flag

use chrono::{DateTime, Utc};
use forensic_core::{TimelineEvent, TimeZoneState, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};

/// A correlated cluster of events across multiple cameras occurring in close temporal proximity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorrelatedEventGroup {
    pub group_id: String,
    pub window_start: String,
    pub window_end: String,
    pub camera_channels: Vec<u32>,
    pub events: Vec<TimelineEvent>,
    pub has_timezone_uncertainty: bool,
    pub validation: ValidationState,
}

pub struct CrossCameraCorrelator;

impl CrossCameraCorrelator {
    /// Correlates events across different camera channels within a given window (in seconds).
    pub fn correlate_events(
        events: &[TimelineEvent],
        window_seconds: i64,
    ) -> Vec<CorrelatedEventGroup> {
        if events.is_empty() {
            return vec![];
        }

        // 1. Sort a copy of candidate events by normalized time
        let mut sorted_events: Vec<TimelineEvent> = events.to_vec();
        sorted_events.sort_by(|a, b| {
            let a_norm = a.time.normalized.as_ref().map(|t| &t.iso_8601);
            let b_norm = b.time.normalized.as_ref().map(|t| &t.iso_8601);
            a_norm.cmp(&b_norm)
        });

        let mut groups = Vec::new();
        let mut current_group_events: Vec<TimelineEvent> = Vec::new();
        let mut current_group_channels: Vec<u32> = Vec::new();
        let mut current_window_start: Option<DateTime<Utc>> = None;
        let mut current_has_uncertainty = false;

        for event in sorted_events {
            let event_dt = event.time.normalized.as_ref()
                .and_then(|n| DateTime::parse_from_rfc3339(&n.iso_8601).ok())
                .map(|dt| dt.with_timezone(&Utc));

            let is_unknown_tz = event.time.timezone == TimeZoneState::Unknown;

            match (current_window_start, event_dt) {
                (Some(start), Some(dt)) => {
                    let diff = (dt - start).num_seconds();
                    if diff <= window_seconds {
                        // Add to current cluster
                        if !current_group_channels.contains(&event.channel) {
                            current_group_channels.push(event.channel);
                        }
                        if is_unknown_tz {
                            current_has_uncertainty = true;
                        }
                        current_group_events.push(event);
                    } else {
                        // Close current group and start new one
                        if current_group_channels.len() > 1 {
                            groups.push(Self::finalize_group(
                                groups.len() + 1,
                                current_window_start.unwrap(),
                                start + chrono::Duration::seconds(window_seconds),
                                current_group_channels.clone(),
                                current_group_events.clone(),
                                current_has_uncertainty,
                            ));
                        }
                        current_group_events = vec![event.clone()];
                        current_group_channels = vec![event.channel];
                        current_window_start = Some(dt);
                        current_has_uncertainty = is_unknown_tz;
                    }
                }
                (None, Some(dt)) => {
                    current_window_start = Some(dt);
                    current_group_events = vec![event.clone()];
                    current_group_channels = vec![event.channel];
                    current_has_uncertainty = is_unknown_tz;
                }
                _ => {
                    // Event has no parseable normalized time
                }
            }
        }

        // Final group
        if current_group_channels.len() > 1 && current_window_start.is_some() {
            groups.push(Self::finalize_group(
                groups.len() + 1,
                current_window_start.unwrap(),
                current_window_start.unwrap() + chrono::Duration::seconds(window_seconds),
                current_group_channels,
                current_group_events,
                current_has_uncertainty,
            ));
        }

        groups
    }

    fn finalize_group(
        index: usize,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        channels: Vec<u32>,
        events: Vec<TimelineEvent>,
        has_uncertainty: bool,
    ) -> CorrelatedEventGroup {
        let validation = if has_uncertainty {
            ValidationState::new(
                ValidationStateKind::Review,
                "correlate_events",
                "Correlation includes events with Unknown timezone; temporal alignment uncertain",
                "CrossCameraCorrelation",
            ).unwrap()
        } else {
            ValidationState::new(
                ValidationStateKind::Pass,
                "correlate_events",
                "Multi-camera correlation window verified",
                "CrossCameraCorrelation",
            ).unwrap()
        };

        CorrelatedEventGroup {
            group_id: format!("corr-grp-{:03}", index),
            window_start: start.to_rfc3339(),
            window_end: end.to_rfc3339(),
            camera_channels: channels,
            events,
            has_timezone_uncertainty: has_uncertainty,
            validation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_core::{Hash, ProfileId, RawTimestamp, RecorderNativeTime, NormalizedTime, Provenance, Region, TimeEvidence};

    fn make_event(channel: u32, norm_time: &str, tz: TimeZoneState) -> TimelineEvent {
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
            recorder_native: Some(RecorderNativeTime { iso_8601: norm_time.into() }),
            normalized: Some(NormalizedTime { iso_8601: norm_time.into(), method: "UTC offset".into() }),
            reference: None,
            timezone: tz,
            correction: None,
        };

        TimelineEvent {
            channel,
            time,
            description: format!("Motion on CH {}", channel),
            source_offsets: vec![Region { offset: 1024, length: 512 }],
            parser_id: "test_parser".into(),
            parser_version: "1.0.0".into(),
            profile_id: ProfileId("test-prof".into()),
            profile_hash: Hash::sha256(vec![0; 32]),
        }
    }

    #[test]
    fn test_cross_camera_correlation_links_multi_channel_events() {
        let e1 = make_event(1, "2026-09-01T14:00:00Z", TimeZoneState::Known("UTC".into()));
        let e2 = make_event(2, "2026-09-01T14:00:15Z", TimeZoneState::Known("UTC".into())); // 15s later
        let e3 = make_event(3, "2026-09-01T16:00:00Z", TimeZoneState::Known("UTC".into())); // 2h later

        let groups = CrossCameraCorrelator::correlate_events(&[e1, e2, e3], 30); // 30s window

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].camera_channels, vec![1, 2]);
        assert_eq!(groups[0].events.len(), 2);
        assert!(!groups[0].has_timezone_uncertainty);
        assert_eq!(groups[0].validation.state, ValidationStateKind::Pass);
    }

    #[test]
    fn test_unknown_timezone_flags_correlation_uncertainty() {
        let e1 = make_event(1, "2026-09-01T14:00:00Z", TimeZoneState::Known("UTC".into()));
        let e2 = make_event(2, "2026-09-01T14:00:10Z", TimeZoneState::Unknown); // Unknown tz

        let groups = CrossCameraCorrelator::correlate_events(&[e1, e2], 30);

        assert_eq!(groups.len(), 1);
        assert!(groups[0].has_timezone_uncertainty);
        assert_eq!(groups[0].validation.state, ValidationStateKind::Review);
    }
}
