//! Cross-Camera Event Correlation (Req 15.4, 4.6, 20.1).
//!
//! Correlates events across cameras within configurable time windows.
//! Guarantees:
//! - Correlation is a deterministic linkage, NEVER a claim of causation (Req 15.4)
//! - Underlying events are NEVER merged or modified
//! - Events with Unknown timezone are correlated only with an explicit uncertainty flag (Req 4.6)
//! - Multi-format timestamps are parsed without silently assuming UTC when timezone is unknown (Req 4.6)
//! - Deterministic canonical tie-breaking prevents arrival-order variance (Req 20.1)

use chrono::{DateTime, NaiveDateTime, Utc};
use forensic_core::{TimeZoneState, TimelineEvent, ValidationState, ValidationStateKind};
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
    /// Attempts to parse an ISO 8601 / RFC 3339 string into a DateTime<Utc>.
    /// Returns (DateTime<Utc>, bool_has_explicit_timezone).
    pub fn parse_timestamp_flexible(s: &str) -> Option<(DateTime<Utc>, bool)> {
        // 1. Strict RFC 3339 with timezone offset
        if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
            return Some((dt.with_timezone(&Utc), true));
        }

        // 2. ISO 8601 without offset ("2026-09-01T12:00:00")
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
            return Some((ndt.and_utc(), false));
        }

        // 3. Space-delimited ("2026-09-01 12:00:00")
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
            return Some((ndt.and_utc(), false));
        }

        None
    }

    /// Correlates events across different camera channels within a given window (in seconds).
    pub fn correlate_events(
        events: &[TimelineEvent],
        window_seconds: i64,
    ) -> Vec<CorrelatedEventGroup> {
        if events.is_empty() {
            return vec![];
        }

        // 1. Sort a copy of candidate events using canonical deterministic key
        let mut sorted_events: Vec<TimelineEvent> = events.to_vec();
        sorted_events.sort_by(|a, b| {
            let a_norm = a.time.normalized.as_ref().map(|t| &t.iso_8601);
            let b_norm = b.time.normalized.as_ref().map(|t| &t.iso_8601);
            a_norm
                .cmp(&b_norm)
                .then_with(|| a.channel.cmp(&b.channel))
                .then_with(|| {
                    let a_off = a.source_offsets.first().map(|r| r.offset);
                    let b_off = b.source_offsets.first().map(|r| r.offset);
                    a_off.cmp(&b_off)
                })
                .then_with(|| a.description.cmp(&b.description))
        });

        let mut groups = Vec::new();
        let mut current_group_events: Vec<TimelineEvent> = Vec::new();
        let mut current_group_channels: Vec<u32> = Vec::new();
        let mut current_window_start: Option<DateTime<Utc>> = None;
        let mut current_has_uncertainty = false;

        for event in sorted_events {
            let parsed_time = event
                .time
                .normalized
                .as_ref()
                .and_then(|n| Self::parse_timestamp_flexible(&n.iso_8601))
                .or_else(|| {
                    event
                        .time
                        .recorder_native
                        .as_ref()
                        .and_then(|n| Self::parse_timestamp_flexible(&n.iso_8601))
                });

            let (event_dt, has_explicit_tz) = match parsed_time {
                Some((dt, explicit)) => (Some(dt), explicit),
                None => (None, false),
            };

            let is_unknown_tz = event.time.timezone == TimeZoneState::Unknown || !has_explicit_tz;

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
                    // Event has no parseable timestamp
                }
            }
        }

        // Final group
        if current_group_channels.len() > 1 && current_window_start.is_some() {
            let start = current_window_start.unwrap();
            groups.push(Self::finalize_group(
                groups.len() + 1,
                start,
                start + chrono::Duration::seconds(window_seconds),
                current_group_channels,
                current_group_events,
                current_has_uncertainty,
            ));
        }

        groups
    }

    fn finalize_group(
        group_idx: usize,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        channels: Vec<u32>,
        events: Vec<TimelineEvent>,
        has_uncertainty: bool,
    ) -> CorrelatedEventGroup {
        let val_state = if has_uncertainty {
            ValidationState::new(
                ValidationStateKind::Review,
                "Cross-camera correlation contains events with unconfirmed timezone state (Req 4.6)",
                "cross_camera_correlation",
                format!("Group-{}", group_idx),
            ).unwrap()
        } else {
            ValidationState::new(
                ValidationStateKind::Pass,
                format!(
                    "Multi-camera correlation confirmed across {} channels",
                    channels.len()
                ),
                "cross_camera_correlation",
                format!("Group-{}", group_idx),
            )
            .unwrap()
        };

        CorrelatedEventGroup {
            group_id: format!("CORR-{:04}", group_idx),
            window_start: start.to_rfc3339(),
            window_end: end.to_rfc3339(),
            camera_channels: channels,
            events,
            has_timezone_uncertainty: has_uncertainty,
            validation: val_state,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_core::{
        Hash, NormalizedTime, ProfileId, Provenance, RawTimestamp, RecorderNativeTime, Region,
    };

    fn make_test_event(
        channel: u32,
        native_time: &str,
        norm_time: &str,
        tz: TimeZoneState,
    ) -> TimelineEvent {
        let raw_prov = Provenance::new(
            forensic_core::EvidenceId::new(),
            Hash::sha256(vec![0; 32]),
            vec![],
            "TestParser",
            "1.0.0",
            Hash::sha256(vec![0; 32]),
            ValidationState::pass("raw", "valid", "raw").unwrap(),
        );

        let time = forensic_core::TimeEvidence {
            raw: RawTimestamp {
                value: 123,
                format: "BCD".into(),
                source: raw_prov,
            },
            recorder_native: Some(RecorderNativeTime {
                iso_8601: native_time.into(),
            }),
            normalized: Some(NormalizedTime {
                iso_8601: norm_time.into(),
                method: "UTC offset".into(),
            }),
            reference: None,
            timezone: tz,
            correction: None,
        };

        TimelineEvent {
            channel,
            time,
            description: format!("Motion on Camera {}", channel),
            source_offsets: vec![Region {
                offset: 1024 * channel as u64,
                length: 512,
            }],
            parser_id: "test_parser".into(),
            parser_version: "1.0.0".into(),
            profile_id: ProfileId("test-prof".into()),
            profile_hash: Hash::sha256(vec![0; 32]),
        }
    }

    #[test]
    fn test_cross_camera_correlation_links_multi_channel_events() {
        let e1 = make_test_event(
            1,
            "2026-09-01T12:00:00Z",
            "2026-09-01T12:00:00Z",
            TimeZoneState::Known("UTC".into()),
        );
        let e2 = make_test_event(
            2,
            "2026-09-01T12:00:15Z",
            "2026-09-01T12:00:15Z",
            TimeZoneState::Known("UTC".into()),
        );

        let groups = CrossCameraCorrelator::correlate_events(&[e1, e2], 30);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].camera_channels, vec![1, 2]);
        assert_eq!(groups[0].validation.state, ValidationStateKind::Pass);
        assert!(!groups[0].has_timezone_uncertainty);
    }

    #[test]
    fn test_unknown_timezone_flags_correlation_uncertainty() {
        let e1 = make_test_event(
            1,
            "2026-09-01T12:00:00Z",
            "2026-09-01T12:00:00Z",
            TimeZoneState::Known("UTC".into()),
        );
        let e2 = make_test_event(
            2,
            "2026-09-01T12:00:10",
            "2026-09-01T12:00:10",
            TimeZoneState::Unknown,
        );

        let groups = CrossCameraCorrelator::correlate_events(&[e1, e2], 30);
        assert_eq!(groups.len(), 1);
        assert!(groups[0].has_timezone_uncertainty);
        assert_eq!(groups[0].validation.state, ValidationStateKind::Review);
    }

    #[test]
    fn test_space_delimited_timestamp_parsed_without_panic() {
        let (dt, explicit) =
            CrossCameraCorrelator::parse_timestamp_flexible("2026-09-01 12:00:00").unwrap();
        assert_eq!(
            dt.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2026-09-01 12:00:00"
        );
        assert!(!explicit, "Space-delimited timestamp lacks explicit offset");
    }
}
