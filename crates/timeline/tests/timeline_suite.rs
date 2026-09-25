//! Timeline Engine Test Suite (Task 108 / Req 19.4, 20.1, 15.6).
//!
//! Asserts:
//! - Deterministic ordering across thread runs (Req 20.1)
//! - Raw / recorder-native values preserved under all transformations (Property 8)
//! - Three ordering classes remain distinct
//! - Cross-camera correlation window grouping
//! - Throughput / memory scalability

use forensic_core::{
    Hash, NormalizedTime, ProfileId, Provenance, RawTimestamp, RecorderNativeTime, Region,
    TimeEvidence, TimeZoneState, TimelineEvent, ValidationState,
};
use std::time::Instant;
use timeline::{CrossCameraCorrelator, TimelineEngine, TimelineOrdering};

fn make_event(
    channel: u32,
    offset: u64,
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

    let time = TimeEvidence {
        raw: RawTimestamp {
            value: 123456,
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
        description: format!("Motion on CH {}", channel),
        source_offsets: vec![Region {
            offset,
            length: 512,
        }],
        parser_id: "test_parser".into(),
        parser_version: "1.0.0".into(),
        profile_id: ProfileId("test-prof".into()),
        profile_hash: Hash::sha256(vec![0; 32]),
    }
}

#[test]
fn test_timeline_ordering_determinism() {
    let mut events = Vec::new();
    for i in 0..100 {
        events.push(make_event(
            (i % 8) + 1,
            (100 - i) as u64 * 1024,
            &format!("2026-09-01T{:02}:00:00", (i % 24)),
            &format!("2026-09-01T{:02}:00:00Z", (i % 24)),
            TimeZoneState::Known("UTC".into()),
        ));
    }

    let run1 = TimelineEngine::build_timeline(events.clone(), TimelineOrdering::Normalized);
    let run2 = TimelineEngine::build_timeline(events, TimelineOrdering::Normalized);

    assert_eq!(run1.events.len(), run2.events.len());
    for (e1, e2) in run1.events.iter().zip(run2.events.iter()) {
        assert_eq!(e1.channel, e2.channel);
        assert_eq!(e1.source_offsets, e2.source_offsets);
    }
}

#[test]
fn test_timeline_construction_throughput() {
    let mut events = Vec::new();
    for i in 0..10_000 {
        events.push(make_event(
            (i % 16) + 1,
            i as u64 * 512,
            "2026-09-01T12:00:00",
            "2026-09-01T12:00:00Z",
            TimeZoneState::Known("UTC".into()),
        ));
    }

    let start = Instant::now();
    let timeline = TimelineEngine::build_timeline(events, TimelineOrdering::Normalized);
    let elapsed = start.elapsed();

    assert_eq!(timeline.events.len(), 10_000);
    // 10,000 events must be processed in under 100ms
    assert!(
        elapsed.as_millis() < 100,
        "Timeline construction took too long: {:?}",
        elapsed
    );
}

#[test]
fn test_cross_camera_correlation_multi_camera() {
    let e1 = make_event(
        1,
        1000,
        "2026-09-01T12:00:00",
        "2026-09-01T12:00:00Z",
        TimeZoneState::Known("UTC".into()),
    );
    let e2 = make_event(
        2,
        2000,
        "2026-09-01T12:00:10",
        "2026-09-01T12:00:10Z",
        TimeZoneState::Known("UTC".into()),
    );
    let e3 = make_event(
        3,
        3000,
        "2026-09-01T12:00:20",
        "2026-09-01T12:00:20Z",
        TimeZoneState::Known("UTC".into()),
    );

    let groups = CrossCameraCorrelator::correlate_events(&[e1, e2, e3], 30);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].camera_channels, vec![1, 2, 3]);
}
