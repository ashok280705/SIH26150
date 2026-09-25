//! # Recording sessions
//!
//! The unified timeline answers "what happened, in order, across all cameras". This
//! module answers a different, investigator-facing question: **"per camera, which
//! continuous recordings exist, from when to when, and what is missing inside them?"**
//!
//! A parser emits one [`Recording`] per stored stream packet. Each carries a channel,
//! a `TimeEvidence` (the recorder's own wall-clock plus a normalized UTC instant), and
//! the byte region the stream occupies. This module groups those packets, per channel,
//! into **recording sessions**: a contiguous block of footage a camera produced. Within
//! a session it reports the **gaps** — windows where the camera should have been
//! recording but no packet exists — and how much of the session's span is actually
//! accounted for by recovered footage.
//!
//! Design rules this module upholds, consistent with the rest of the timeline crate:
//!
//! * **Nothing is invented.** A gap is reported, never filled. A missing window is a
//!   stated absence, not a synthesized recording.
//! * **The recorder clock is preserved.** `start_native`/`end_native` are the camera's
//!   own local wall-clock strings (what an investigator reads off the DVR), shown
//!   verbatim. All arithmetic is done on the normalized UTC instant so cross-day and
//!   cross-timezone maths stay correct.
//! * **Unknown timezones are excluded from temporal maths.** A packet whose timezone is
//!   `Unknown` cannot be placed on a comparable timeline, so it is counted but does not
//!   contribute a start/end or a gap.
//! * **The cadence is measured, not assumed.** DVRs segment footage at a fixed nominal
//!   interval that differs by vendor and configuration. Rather than hard-code a value,
//!   the nominal interval is derived from the observed spacing of the channel's own
//!   packets, so the same code reports honest gaps regardless of vendor cadence.

use serde::{Deserialize, Serialize};

use forensic_core::{Recording, TimeEvidence, TimeZoneState};

/// One stored stream packet, projected onto the recording-session view.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordingSegment {
    /// 1-based camera channel this segment belongs to.
    pub channel: u32,
    /// Recorder-native wall-clock string, shown verbatim (e.g. `2026-09-20T10:00:00`).
    pub start_native: Option<String>,
    /// Normalized UTC instant used for ordering and gap maths.
    pub start_normalized: Option<String>,
    /// Byte offset of the segment's stream payload in the evidence image.
    pub source_offset: u64,
    /// Length in bytes of the segment's stream payload.
    pub source_length: u64,
}

/// A window inside a recording where footage is absent.
///
/// The window is bounded by the two packets that straddle it. `missing_seconds` is the
/// unobserved span in excess of the channel's nominal segment cadence — i.e. how much
/// footage the camera should have produced but did not.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionGap {
    /// Recorder-native wall clock the gap opens at (end of the earlier segment).
    pub starts_after_native: Option<String>,
    /// Recorder-native wall clock the gap closes at (start of the later segment).
    pub ends_before_native: Option<String>,
    /// Normalized UTC instant the gap opens at.
    pub starts_after_normalized: String,
    /// Normalized UTC instant the gap closes at.
    pub ends_before_normalized: String,
    /// Seconds of footage missing from this window.
    pub missing_seconds: i64,
    /// Byte offset of the segment before the gap, for navigation back to the image.
    pub previous_offset: u64,
    /// Byte length of the segment before the gap. The recoverable byte region of the
    /// gap is `[previous_offset + previous_length, next_offset]` — i.e. the physical
    /// space between the two straddling segments, where deleted footage would reside.
    pub previous_length: u64,
    /// Byte offset of the segment after the gap.
    pub next_offset: u64,
    /// Human-readable statement of what is missing.
    pub reason: String,
}

/// A contiguous recording produced by a single camera.
///
/// "Contiguous" means the packets are close enough in time to be one recording block;
/// a silence longer than the session-split threshold starts a new session rather than
/// being reported as an in-session gap.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordingSession {
    /// Stable identifier: `ch{channel}-{start_normalized}`.
    pub id: String,
    /// 1-based camera channel.
    pub channel: u32,
    /// Recorder-native wall clock the recording starts at.
    pub start_native: Option<String>,
    /// Recorder-native wall clock the recording ends at (last segment + one cadence).
    pub end_native: Option<String>,
    /// Normalized UTC instant the recording starts at.
    pub start_normalized: String,
    /// Normalized UTC instant the recording ends at.
    pub end_normalized: String,
    /// Timezone label carried by the segments (e.g. `UTC+05:30`) or `Unknown`.
    pub timezone: String,
    /// Number of stored segments found for this recording.
    pub segment_count: usize,
    /// Wall-clock span of the recording, in seconds (`end - start`).
    pub span_seconds: i64,
    /// Seconds of footage actually accounted for by recovered segments.
    pub covered_seconds: i64,
    /// Seconds of footage missing across all in-session gaps.
    pub missing_seconds: i64,
    /// `covered_seconds / span_seconds`, clamped to `0.0 ..= 1.0`.
    pub coverage_ratio: f64,
    /// Measured nominal cadence between segments, in seconds.
    pub nominal_segment_seconds: i64,
    /// Missing windows inside this recording, in chronological order.
    pub gaps: Vec<SessionGap>,
    /// The segments that make up this recording, in chronological order.
    pub segments: Vec<RecordingSegment>,
}

/// The full per-recording view for one evidence image.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordingTimeline {
    /// Recording sessions, sorted by start instant ascending (earliest first).
    pub sessions: Vec<RecordingSession>,
    /// Distinct camera channels that produced at least one recording.
    pub channel_count: usize,
    /// Total stored segments across every recording.
    pub total_segments: usize,
    /// Total recordings (sessions) found.
    pub total_recordings: usize,
    /// Total missing footage across every recording, in seconds.
    pub total_missing_seconds: i64,
    /// Recordings that were skipped because their timezone is `Unknown` and therefore
    /// could not be placed on a comparable timeline.
    pub recordings_without_time: usize,
    /// How the figures were derived, recorded so a reader can reproduce them.
    pub method: String,
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

/// The comparable normalized instant for a recording, or `None` when it cannot be placed.
fn comparable_instant(time: &TimeEvidence) -> Option<chrono::DateTime<chrono::Utc>> {
    if time.timezone == TimeZoneState::Unknown {
        return None;
    }
    time.normalized
        .as_ref()
        .and_then(|n| parse_instant(&n.iso_8601))
}

/// Add `seconds` to a recorder-native wall-clock string, preserving its format.
///
/// The native string carries no timezone, so it is treated as a naive local clock and
/// advanced directly — exactly how a reader would add time on the DVR's own display.
fn native_plus(native: &str, seconds: i64) -> Option<String> {
    for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(native, fmt) {
            let shifted = naive + chrono::Duration::seconds(seconds);
            return Some(shifted.format(fmt).to_string());
        }
    }
    None
}

/// The median of a set of positive second-deltas, used as the nominal cadence.
fn median_delta(deltas: &[i64]) -> Option<i64> {
    let mut positive: Vec<i64> = deltas.iter().copied().filter(|d| *d > 0).collect();
    if positive.is_empty() {
        return None;
    }
    positive.sort_unstable();
    Some(positive[positive.len() / 2])
}

/// Internal working record for one packet with a comparable instant.
struct Point {
    instant: chrono::DateTime<chrono::Utc>,
    native: Option<String>,
    offset: u64,
    length: u64,
}

/// Build the per-recording timeline from parser-emitted recordings.
///
/// * `min_gap_seconds` — a shortfall smaller than this (relative to the measured
///   cadence) is treated as normal jitter, not a reportable gap.
/// * `session_split_seconds` — a silence at least this long ends the current recording
///   and begins a new one, rather than being reported as an in-session gap.
///
/// Sessions are returned sorted by start instant ascending, so the UI can present
/// recordings in chronological (date) order without further work.
pub fn build_recording_timeline(
    recordings: &[Recording],
    min_gap_seconds: i64,
    session_split_seconds: i64,
) -> RecordingTimeline {
    use std::collections::BTreeMap;

    // Group comparable packets per channel; count the ones we cannot place.
    let mut per_channel: BTreeMap<u32, (Vec<Point>, String)> = BTreeMap::new();
    let mut recordings_without_time = 0usize;

    for rec in recordings {
        let instant = match comparable_instant(&rec.time) {
            Some(i) => i,
            None => {
                recordings_without_time += 1;
                continue;
            }
        };
        let native = rec
            .time
            .recorder_native
            .as_ref()
            .map(|n| n.iso_8601.clone());
        let offset = rec
            .source_offsets
            .iter()
            .map(|r| r.offset)
            .min()
            .unwrap_or(0);
        let length: u64 = rec.source_offsets.iter().map(|r| r.length).sum();
        let tz = match &rec.time.timezone {
            TimeZoneState::Known(label) => label.clone(),
            TimeZoneState::Unknown => "Unknown".to_string(),
        };
        let entry = per_channel
            .entry(rec.channel)
            .or_insert_with(|| (Vec::new(), tz));
        entry.0.push(Point {
            instant,
            native,
            offset,
            length,
        });
    }

    let mut sessions: Vec<RecordingSession> = Vec::new();

    for (channel, (mut points, timezone)) in per_channel {
        points.sort_by(|a, b| a.instant.cmp(&b.instant).then(a.offset.cmp(&b.offset)));

        // Measure the channel's own nominal cadence from consecutive spacings.
        let deltas: Vec<i64> = points
            .windows(2)
            .map(|w| (w[1].instant - w[0].instant).num_seconds())
            .collect();
        let nominal = median_delta(&deltas).unwrap_or(0).max(1);

        // Walk the packets, cutting a new session whenever the silence is long enough
        // to be a separate recording rather than an in-recording gap.
        let mut current: Vec<&Point> = Vec::new();
        for point in &points {
            if let Some(prev) = current.last() {
                let delta = (point.instant - prev.instant).num_seconds();
                if delta >= session_split_seconds {
                    if let Some(session) =
                        build_session(channel, &timezone, &current, nominal, min_gap_seconds)
                    {
                        sessions.push(session);
                    }
                    current.clear();
                }
            }
            current.push(point);
        }
        if let Some(session) = build_session(channel, &timezone, &current, nominal, min_gap_seconds)
        {
            sessions.push(session);
        }
    }

    // Chronological (date) ordering across all channels.
    sessions.sort_by(|a, b| {
        a.start_normalized
            .cmp(&b.start_normalized)
            .then(a.channel.cmp(&b.channel))
    });

    let channels: std::collections::BTreeSet<u32> = sessions.iter().map(|s| s.channel).collect();
    let total_segments: usize = sessions.iter().map(|s| s.segment_count).sum();
    let total_missing_seconds: i64 = sessions.iter().map(|s| s.missing_seconds).sum();

    RecordingTimeline {
        channel_count: channels.len(),
        total_segments,
        total_recordings: sessions.len(),
        total_missing_seconds,
        recordings_without_time,
        method: format!(
            "Grouped parser recordings per channel; nominal cadence measured per channel from segment spacing; \
             in-recording gaps reported when a silence exceeds the cadence by at least {min_gap_seconds}s; \
             a silence of at least {session_split_seconds}s starts a new recording"
        ),
        sessions,
    }
}

/// Build one session from a chronologically ordered, non-empty group of packets.
fn build_session(
    channel: u32,
    timezone: &str,
    group: &[&Point],
    nominal: i64,
    min_gap_seconds: i64,
) -> Option<RecordingSession> {
    let first = group.first()?;
    let last = group.last()?;

    let start_instant = first.instant;
    // The last segment still contributes one cadence of footage after its start.
    let end_instant = last.instant + chrono::Duration::seconds(nominal);
    let span_seconds = (end_instant - start_instant).num_seconds().max(0);

    // Detect in-recording gaps: a spacing longer than the cadence by a meaningful margin.
    let mut gaps: Vec<SessionGap> = Vec::new();
    for w in group.windows(2) {
        let prev = w[0];
        let next = w[1];
        let delta = (next.instant - prev.instant).num_seconds();
        let missing = delta - nominal;
        if missing >= min_gap_seconds {
            // The gap opens one cadence after the earlier segment started (i.e. when its
            // footage runs out) and closes when the later segment begins.
            let gap_open = prev.instant + chrono::Duration::seconds(nominal);
            let gap_open_native = prev.native.as_ref().and_then(|n| native_plus(n, nominal));
            gaps.push(SessionGap {
                starts_after_native: gap_open_native,
                ends_before_native: next.native.clone(),
                starts_after_normalized: gap_open.to_rfc3339(),
                ends_before_normalized: next.instant.to_rfc3339(),
                missing_seconds: missing,
                previous_offset: prev.offset,
                previous_length: prev.length,
                next_offset: next.offset,
                reason: format!(
                    "No footage on channel {channel} for {missing}s between segments \
                     (nominal segment cadence {nominal}s)"
                ),
            });
        }
    }

    let missing_seconds: i64 = gaps.iter().map(|g| g.missing_seconds).sum();
    let covered_seconds = (span_seconds - missing_seconds).max(0);
    let coverage_ratio = if span_seconds == 0 {
        1.0
    } else {
        (covered_seconds as f64 / span_seconds as f64).clamp(0.0, 1.0)
    };

    let end_native = last.native.as_ref().and_then(|n| native_plus(n, nominal));

    let segments = group
        .iter()
        .map(|p| RecordingSegment {
            channel,
            start_native: p.native.clone(),
            start_normalized: Some(p.instant.to_rfc3339()),
            source_offset: p.offset,
            source_length: p.length,
        })
        .collect();

    Some(RecordingSession {
        id: format!("ch{}-{}", channel, start_instant.to_rfc3339()),
        channel,
        start_native: first.native.clone(),
        end_native,
        start_normalized: start_instant.to_rfc3339(),
        end_normalized: end_instant.to_rfc3339(),
        timezone: timezone.to_string(),
        segment_count: group.len(),
        span_seconds,
        covered_seconds,
        missing_seconds,
        coverage_ratio,
        nominal_segment_seconds: nominal,
        gaps,
        segments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_core::{
        Hash, NormalizedTime, ProfileId, Provenance, RawTimestamp, RecorderNativeTime, Region,
    };

    fn recording(
        channel: u32,
        offset: u64,
        native: &str,
        norm: &str,
        tz: TimeZoneState,
    ) -> Recording {
        let prov = Provenance::new(
            forensic_core::EvidenceId::new(),
            Hash::sha256(vec![0; 32]),
            vec![],
            "test",
            "1.0",
            Hash::sha256(vec![0; 32]),
            forensic_core::ValidationState::pass("raw", "valid", "raw").unwrap(),
        );
        Recording {
            channel,
            time: TimeEvidence {
                raw: RawTimestamp {
                    value: 0,
                    format: "UNIX".into(),
                    source: prov,
                },
                recorder_native: Some(RecorderNativeTime {
                    iso_8601: native.into(),
                }),
                normalized: Some(NormalizedTime {
                    iso_8601: norm.into(),
                    method: "test".into(),
                }),
                reference: None,
                timezone: tz,
                correction: None,
            },
            source_image: "img.raw".into(),
            source_offsets: vec![Region {
                offset,
                length: 1000,
            }],
            parser_id: "p".into(),
            parser_version: "1".into(),
            profile_id: ProfileId("prof".into()),
            profile_hash: Hash::sha256(vec![0; 32]),
            integrity: vec![],
            exported_video_path: None,
        }
    }

    fn ist(channel: u32, offset: u64, native: &str, norm: &str) -> Recording {
        recording(
            channel,
            offset,
            native,
            norm,
            TimeZoneState::Known("UTC+05:30".into()),
        )
    }

    #[test]
    fn continuous_segments_have_no_gaps_and_full_coverage() {
        // Three segments 300s apart -> nominal 300s -> continuous.
        let recs = vec![
            ist(1, 0, "2026-09-20T10:00:00", "2026-09-20T04:30:00Z"),
            ist(1, 1000, "2026-09-20T10:05:00", "2026-09-20T04:35:00Z"),
            ist(1, 2000, "2026-09-20T10:10:00", "2026-09-20T04:40:00Z"),
        ];
        let tl = build_recording_timeline(&recs, 30, 3600);
        assert_eq!(tl.total_recordings, 1);
        let s = &tl.sessions[0];
        assert_eq!(s.segment_count, 3);
        assert!(s.gaps.is_empty());
        assert_eq!(s.missing_seconds, 0);
        assert!((s.coverage_ratio - 1.0).abs() < 1e-9);
        assert_eq!(s.nominal_segment_seconds, 300);
    }

    #[test]
    fn skipped_slot_is_reported_as_an_in_recording_gap() {
        // 10:00, 10:05, [10:10 missing], 10:15, 10:20 -> one 300s gap.
        let recs = vec![
            ist(1, 0, "2026-09-20T10:00:00", "2026-09-20T04:30:00Z"),
            ist(1, 1000, "2026-09-20T10:05:00", "2026-09-20T04:35:00Z"),
            ist(1, 2000, "2026-09-20T10:15:00", "2026-09-20T04:45:00Z"),
            ist(1, 3000, "2026-09-20T10:20:00", "2026-09-20T04:50:00Z"),
        ];
        let tl = build_recording_timeline(&recs, 30, 3600);
        let s = &tl.sessions[0];
        assert_eq!(s.gaps.len(), 1);
        assert_eq!(s.gaps[0].missing_seconds, 300);
        assert_eq!(
            s.gaps[0].starts_after_native.as_deref(),
            Some("2026-09-20T10:10:00")
        );
        assert_eq!(
            s.gaps[0].ends_before_native.as_deref(),
            Some("2026-09-20T10:15:00")
        );
        assert_eq!(s.missing_seconds, 300);
        assert!(s.coverage_ratio < 1.0);
    }

    #[test]
    fn long_silence_splits_into_separate_recordings() {
        let recs = vec![
            ist(1, 0, "2026-09-20T10:00:00", "2026-09-20T04:30:00Z"),
            ist(1, 1000, "2026-09-20T10:05:00", "2026-09-20T04:35:00Z"),
            // Two hours later: a distinct recording, not a gap.
            ist(1, 2000, "2026-09-20T12:05:00", "2026-09-20T06:35:00Z"),
            ist(1, 3000, "2026-09-20T12:10:00", "2026-09-20T06:40:00Z"),
        ];
        let tl = build_recording_timeline(&recs, 30, 3600);
        assert_eq!(tl.total_recordings, 2);
    }

    #[test]
    fn sessions_are_sorted_by_date_across_channels() {
        let recs = vec![
            ist(2, 5000, "2026-09-20T11:00:00", "2026-09-20T05:30:00Z"),
            ist(1, 0, "2026-09-20T10:00:00", "2026-09-20T04:30:00Z"),
        ];
        let tl = build_recording_timeline(&recs, 30, 3600);
        assert_eq!(tl.sessions[0].channel, 1);
        assert_eq!(tl.sessions[1].channel, 2);
    }

    #[test]
    fn unknown_timezone_recordings_are_counted_but_excluded() {
        let recs = vec![recording(
            1,
            0,
            "2026-09-20T10:00:00",
            "2026-09-20T04:30:00Z",
            TimeZoneState::Unknown,
        )];
        let tl = build_recording_timeline(&recs, 30, 3600);
        assert_eq!(tl.recordings_without_time, 1);
        assert_eq!(tl.total_recordings, 0);
    }
}
