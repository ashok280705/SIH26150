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

use forensic_core::{ExaminerTimezone, Recording, TimeEvidence, TimeZoneState};

/// The temporal basis of a recording session or segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalBasis {
    /// Absolute instant in UTC, derived from a timestamp with an established timezone offset.
    AbsoluteUtc,
    /// Recorder-local wall-clock time with Unknown timezone. Valid for intra-device sequencing
    /// only; not comparable with UTC or other devices without an examiner-established timezone.
    DeviceLocal,
}

fn default_temporal_basis() -> TemporalBasis {
    TemporalBasis::AbsoluteUtc
}

/// One stored stream packet, projected onto the recording-session view.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordingSegment {
    /// 1-based camera channel this segment belongs to.
    pub channel: u32,
    /// Recorder-native wall-clock string, shown verbatim (e.g. `2026-09-20T10:00:00`).
    pub start_native: Option<String>,
    /// Normalized instant used for ordering and gap maths (RFC3339 UTC or naive ISO-8601).
    pub start_normalized: Option<String>,
    /// Byte offset of the segment's stream payload in the evidence image.
    pub source_offset: u64,
    /// Length in bytes of the segment's stream payload.
    pub source_length: u64,
    /// Absolute UTC instant if established (either via known filesystem timezone or examiner assertion).
    #[serde(default)]
    pub absolute_utc: Option<String>,
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
    /// Normalized instant the gap opens at.
    pub starts_after_normalized: String,
    /// Normalized instant the gap closes at.
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
    /// Stable identifier: `ch{channel}-{start_normalized}` or `ch{channel}-local-{start_normalized}`.
    pub id: String,
    /// 1-based camera channel.
    pub channel: u32,
    /// Recorder-native wall clock the recording starts at.
    pub start_native: Option<String>,
    /// Recorder-native wall clock the recording ends at (last segment + one cadence).
    pub end_native: Option<String>,
    /// Normalized instant the recording starts at (RFC3339 UTC or naive ISO-8601).
    pub start_normalized: String,
    /// Normalized instant the recording ends at.
    pub end_normalized: String,
    /// Timezone label carried by the segments (e.g. `UTC+05:30`) or `Unknown`.
    pub timezone: String,
    /// Temporal basis: AbsoluteUtc (known timezone) or DeviceLocal (unknown timezone).
    #[serde(default = "default_temporal_basis")]
    pub temporal_basis: TemporalBasis,
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
    /// Filesystem-derived timezone label (e.g. "Unknown" or "UTC+08:00").
    #[serde(default)]
    pub filesystem_timezone: Option<String>,
    /// Examiner-established timezone metadata, if established externally.
    #[serde(default)]
    pub examiner_timezone: Option<ExaminerTimezone>,
    /// Whether there is an evidentiary conflict between filesystem timezone and examiner assertion.
    #[serde(default)]
    pub timezone_conflict: Option<String>,
}

/// The full per-recording view for one evidence image.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordingTimeline {
    /// Recording sessions, sorted by temporal basis, then start instant ascending.
    pub sessions: Vec<RecordingSession>,
    /// Distinct camera channels that produced at least one recording.
    pub channel_count: usize,
    /// Total stored segments across every recording.
    pub total_segments: usize,
    /// Total recordings (sessions) found.
    pub total_recordings: usize,
    /// Total missing footage across every recording, in seconds.
    pub total_missing_seconds: i64,
    /// Recordings that were skipped because they carry no usable temporal evidence at all
    /// (neither absolute instant nor valid recorder-native wall clock).
    pub recordings_without_time: usize,
    /// Recordings that carry valid recorder-native timestamps but have an `Unknown` timezone.
    /// These are ordered per-device in their native temporal domain and displayed as Device Local Time.
    #[serde(default)]
    pub recordings_with_unknown_timezone: usize,
    /// Examiner-established timezone assertion applied to this timeline, if any.
    #[serde(default)]
    pub examiner_timezone: Option<ExaminerTimezone>,
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

/// Parse a naive datetime from an ISO string (no timezone shift or assumption).
fn parse_naive(s: &str) -> Option<chrono::NaiveDateTime> {
    for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, fmt) {
            return Some(naive);
        }
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(dt.naive_local());
    }
    None
}

/// The comparable normalized instant for a recording, or `None` when it cannot be placed.
///
/// FORENSIC INVARIANT: If timezone is `Unknown`, `comparable_instant` strictly returns `None`.
/// It is never weakened to assume UTC.
pub fn comparable_instant(time: &TimeEvidence) -> Option<chrono::DateTime<chrono::Utc>> {
    if time.timezone == TimeZoneState::Unknown {
        return None;
    }
    time.normalized
        .as_ref()
        .and_then(|n| parse_instant(&n.iso_8601))
}

/// Temporal domain grouping key to prevent intermingling cross-device or cross-basis timestamps.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum TemporalDomain {
    Absolute(String), // label, e.g. "UTC+05:30"
    DeviceLocal,
}

/// Strongly-typed ordering key separating Absolute UTC instants from Device-Local wall-clocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemporalOrderingKey {
    Absolute(chrono::DateTime<chrono::Utc>),
    DeviceLocal(chrono::NaiveDateTime),
}

impl TemporalOrderingKey {
    /// Delta in seconds between two keys.
    ///
    /// FORENSIC CROSS-DEVICE SAFETY: Returns `None` if keys belong to different temporal bases.
    /// Device-local time is NEVER silently subtracted from or compared with UTC.
    pub fn delta_seconds(&self, other: &Self) -> Option<i64> {
        match (self, other) {
            (TemporalOrderingKey::Absolute(a), TemporalOrderingKey::Absolute(b)) => {
                Some((*b - *a).num_seconds())
            }
            (TemporalOrderingKey::DeviceLocal(a), TemporalOrderingKey::DeviceLocal(b)) => {
                Some((*b - *a).num_seconds())
            }
            _ => None,
        }
    }

    pub fn add_seconds(&self, secs: i64) -> Self {
        match self {
            TemporalOrderingKey::Absolute(dt) => {
                TemporalOrderingKey::Absolute(*dt + chrono::Duration::seconds(secs))
            }
            TemporalOrderingKey::DeviceLocal(naive) => {
                TemporalOrderingKey::DeviceLocal(*naive + chrono::Duration::seconds(secs))
            }
        }
    }

    pub fn format_iso(&self) -> String {
        match self {
            TemporalOrderingKey::Absolute(dt) => dt.to_rfc3339(),
            TemporalOrderingKey::DeviceLocal(naive) => {
                naive.format("%Y-%m-%dT%H:%M:%S").to_string()
            }
        }
    }

    pub fn temporal_basis(&self) -> TemporalBasis {
        match self {
            TemporalOrderingKey::Absolute(_) => TemporalBasis::AbsoluteUtc,
            TemporalOrderingKey::DeviceLocal(_) => TemporalBasis::DeviceLocal,
        }
    }
}

fn find_iana_tz(s: &str) -> Option<chrono_tz::Tz> {
    if let Ok(tz) = s.parse::<chrono_tz::Tz>() {
        return Some(tz);
    }
    let with_underscore = s.replace(' ', "_");
    if let Ok(tz) = with_underscore.parse::<chrono_tz::Tz>() {
        return Some(tz);
    }
    // Case-insensitive lookup against full IANA Olson database variants
    chrono_tz::TZ_VARIANTS
        .iter()
        .find(|tz| {
            tz.name().eq_ignore_ascii_case(s)
                || tz.name().eq_ignore_ascii_case(&with_underscore)
        })
        .copied()
}

/// Resolve a timezone identifier or UTC offset string against an optional naive recording instant.
///
/// If an IANA named timezone (e.g. "America/New_York", "Europe/London", "Asia/Kolkata") is provided,
/// the offset is resolved dynamically using genuine IANA rules at that specific calendar date/time,
/// accurately applying Daylight Saving Time (DST) transitions.
///
/// If a numeric offset (e.g. "+05:30", "UTC-04:00", "Z") is provided, it is parsed directly.
///
/// FORENSIC INTEGRITY: System, local machine, and browser timezones are NEVER checked or inferred.
/// Only the explicit string passed in is evaluated. If invalid or unrecognized, returns `None`.
pub fn resolve_timezone_offset(
    tz_str: &str,
    naive: Option<chrono::NaiveDateTime>,
) -> Option<chrono::FixedOffset> {
    use chrono::{Offset, TimeZone};

    let trimmed = tz_str.trim();
    if trimmed.is_empty() {
        return None;
    }

    // 1. Check genuine IANA Olson database timezone
    if let Some(tz) = find_iana_tz(trimmed) {
        let dt = naive.unwrap_or_else(|| {
            // Reference date (mid-winter) if no specific instant is available
            chrono::NaiveDate::from_ymd_opt(2026, 1, 15)
                .unwrap()
                .and_hms_opt(12, 0, 0)
                .unwrap()
        });

        return match tz.from_local_datetime(&dt) {
            chrono::LocalResult::Single(local_dt) => Some(local_dt.offset().fix()),
            chrono::LocalResult::Ambiguous(earlier, _) => Some(earlier.offset().fix()),
            chrono::LocalResult::None => {
                // In spring-forward gap, sample 1 hour later
                match tz.from_local_datetime(&(dt + chrono::Duration::hours(1))) {
                    chrono::LocalResult::Single(local_dt) => Some(local_dt.offset().fix()),
                    chrono::LocalResult::Ambiguous(earlier, _) => Some(earlier.offset().fix()),
                    chrono::LocalResult::None => Some(chrono::FixedOffset::east_opt(0).unwrap()),
                }
            }
        };
    }

    // 2. Named abbreviation aliases
    let lower = trimmed.to_lowercase();
    match lower.as_str() {
        "utc" | "etc/utc" | "z" | "gmt" | "wet" => {
            return chrono::FixedOffset::east_opt(0);
        }
        "ist" => {
            return chrono::FixedOffset::east_opt(5 * 3600 + 30 * 60); // +05:30
        }
        "wib" => {
            return chrono::FixedOffset::east_opt(7 * 3600); // +07:00
        }
        "jst" | "kst" => {
            return chrono::FixedOffset::east_opt(9 * 3600); // +09:00
        }
        "aest" => {
            return chrono::FixedOffset::east_opt(10 * 3600); // +10:00
        }
        "aedt" => {
            return chrono::FixedOffset::east_opt(11 * 3600); // +11:00
        }
        "nzst" => {
            return chrono::FixedOffset::east_opt(12 * 3600); // +12:00
        }
        "gst" => {
            return chrono::FixedOffset::east_opt(4 * 3600); // +04:00
        }
        "cet" => {
            return chrono::FixedOffset::east_opt(3600); // +01:00
        }
        "cest" => {
            return chrono::FixedOffset::east_opt(2 * 3600); // +02:00
        }
        "eet" => {
            return chrono::FixedOffset::east_opt(2 * 3600); // +02:00
        }
        "eest" => {
            return chrono::FixedOffset::east_opt(3 * 3600); // +03:00
        }
        "msk" => {
            return chrono::FixedOffset::east_opt(3 * 3600); // +03:00
        }
        "est" => {
            return chrono::FixedOffset::west_opt(5 * 3600); // -05:00
        }
        "edt" => {
            return chrono::FixedOffset::west_opt(4 * 3600); // -04:00
        }
        "cst" => {
            return chrono::FixedOffset::west_opt(6 * 3600); // -06:00
        }
        "cdt" => {
            return chrono::FixedOffset::west_opt(5 * 3600); // -05:00
        }
        "mst" => {
            return chrono::FixedOffset::west_opt(7 * 3600); // -07:00
        }
        "mdt" => {
            return chrono::FixedOffset::west_opt(6 * 3600); // -06:00
        }
        "pst" => {
            return chrono::FixedOffset::west_opt(8 * 3600); // -08:00
        }
        "pdt" => {
            return chrono::FixedOffset::west_opt(7 * 3600); // -07:00
        }
        "akst" => {
            return chrono::FixedOffset::west_opt(9 * 3600); // -09:00
        }
        "hst" => {
            return chrono::FixedOffset::west_opt(10 * 3600); // -10:00
        }
        "brt" => {
            return chrono::FixedOffset::west_opt(3 * 3600); // -03:00
        }
        _ => {}
    }

    // 3. Strip prefixes like "UTC", "GMT"
    let s = trimmed
        .strip_prefix("UTC")
        .or_else(|| trimmed.strip_prefix("utc"))
        .or_else(|| trimmed.strip_prefix("GMT"))
        .or_else(|| trimmed.strip_prefix("gmt"))
        .unwrap_or(trimmed)
        .trim();

    if s.is_empty() || s == "Z" || s == "z" {
        return chrono::FixedOffset::east_opt(0);
    }

    // Parse sign
    let (sign, rest) = if let Some(r) = s.strip_prefix('+') {
        (1i32, r.trim())
    } else if let Some(r) = s.strip_prefix('-') {
        (-1i32, r.trim())
    } else if s.chars().next().map_or(false, |c| c.is_ascii_digit()) {
        (1i32, s)
    } else {
        return None;
    };

    // Parse hours and minutes
    let (hours, minutes) = if let Some((h_str, m_str)) = rest.split_once(':') {
        let h: i32 = h_str.trim().parse().ok()?;
        let m: i32 = m_str.trim().parse().ok()?;
        (h, m)
    } else if rest.len() == 4 && rest.chars().all(|c| c.is_ascii_digit()) {
        let h: i32 = rest[0..2].parse().ok()?;
        let m: i32 = rest[2..4].parse().ok()?;
        (h, m)
    } else if rest.len() <= 2 && rest.chars().all(|c| c.is_ascii_digit()) {
        let h: i32 = rest.parse().ok()?;
        (h, 0)
    } else {
        return None;
    };

    if hours < 0 || hours > 14 || minutes < 0 || minutes >= 60 {
        return None;
    }

    let total_secs = sign * (hours * 3600 + minutes * 60);
    if total_secs >= 0 {
        chrono::FixedOffset::east_opt(total_secs)
    } else {
        chrono::FixedOffset::west_opt(-total_secs)
    }
}

/// Backward-compatible wrapper for static/default offset parsing.
pub fn parse_timezone_offset(tz_str: &str) -> Option<chrono::FixedOffset> {
    resolve_timezone_offset(tz_str, None)
}

/// Extract temporal domain, ordering key, absolute UTC string, and conflict from `TimeEvidence`,
/// optionally taking into account an examiner-established timezone assertion.
///
/// FORENSIC RULES:
/// 1. System/browser/machine timezones are NEVER checked or used.
/// 2. If `time.timezone` is `TimeZoneState::Unknown` and no valid `examiner_tz` is provided,
///    the ordering key strictly remains `TemporalOrderingKey::DeviceLocal` without fabricating UTC.
/// 3. If `examiner_tz` is provided, recorder-native local wall-clock is converted to absolute UTC
///    instants using the examiner's documented offset. The original `time.timezone` is NOT mutated.
/// 4. If both filesystem and examiner timezones exist with conflicting offsets, conflict is flagged.
fn extract_temporal_evidence_with_examiner(
    time: &TimeEvidence,
    examiner_tz: Option<&ExaminerTimezone>,
) -> Option<(TemporalDomain, TemporalOrderingKey, Option<String>, Option<String>)> {
    let naive = time
        .recorder_native
        .as_ref()
        .and_then(|n| parse_naive(&n.iso_8601))
        .or_else(|| {
            time.normalized
                .as_ref()
                .and_then(|n| parse_naive(&n.iso_8601))
        });

    let ex_offset = examiner_tz.and_then(|ex| resolve_timezone_offset(&ex.timezone, naive));

    match &time.timezone {
        TimeZoneState::Known(label) => {
            let instant = comparable_instant(time)?;
            let mut conflict = None;
            if let (Some(ex), Some(ex_off)) = (examiner_tz, ex_offset) {
                if let Some(fs_off) = resolve_timezone_offset(label, naive) {
                    if fs_off.local_minus_utc() != ex_off.local_minus_utc() {
                        conflict = Some(format!(
                            "Filesystem reports '{label}' but examiner established '{}'",
                            ex.timezone
                        ));
                    }
                }
            }
            Some((
                TemporalDomain::Absolute(label.clone()),
                TemporalOrderingKey::Absolute(instant),
                Some(instant.to_rfc3339()),
                conflict,
            ))
        }
        TimeZoneState::Unknown => {
            let naive_dt = naive?;
            if let (Some(ex), Some(ex_off)) = (examiner_tz, ex_offset) {
                // Legitimate external examiner assertion: convert recorder local wall-clock to absolute UTC.
                let utc_naive = naive_dt - chrono::Duration::seconds(ex_off.local_minus_utc() as i64);
                let utc_instant = utc_naive.and_utc();
                Some((
                    TemporalDomain::Absolute(format!("{} (Examiner)", ex.timezone)),
                    TemporalOrderingKey::Absolute(utc_instant),
                    Some(utc_instant.to_rfc3339()),
                    None,
                ))
            } else {
                // Strictly retain DeviceLocal time domain without fabricating UTC.
                Some((
                    TemporalDomain::DeviceLocal,
                    TemporalOrderingKey::DeviceLocal(naive_dt),
                    None,
                    None,
                ))
            }
        }
    }
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

/// Internal working record for one packet with an ordering key.
struct Point {
    ordering_key: TemporalOrderingKey,
    native: Option<String>,
    offset: u64,
    length: u64,
    #[allow(dead_code)]
    fs_tz: String,
    absolute_utc: Option<String>,
    #[allow(dead_code)]
    conflict: Option<String>,
}

/// Build the per-recording timeline from parser-emitted recordings without examiner override.
pub fn build_recording_timeline(
    recordings: &[Recording],
    min_gap_seconds: i64,
    session_split_seconds: i64,
) -> RecordingTimeline {
    build_recording_timeline_with_examiner_tz(
        recordings,
        min_gap_seconds,
        session_split_seconds,
        None,
    )
}

/// Build the per-recording timeline from parser-emitted recordings, optionally incorporating
/// an examiner-established timezone metadata assertion.
///
/// * `min_gap_seconds` — a shortfall smaller than this (relative to the measured
///   cadence) is treated as normal jitter, not a reportable gap.
/// * `session_split_seconds` — a silence at least this long ends the current recording
///   and begins a new one, rather than being reported as an in-session gap.
/// * `examiner_tz` — optional documented timezone established by the examiner.
///
/// Sessions are returned sorted by temporal basis, then start instant ascending, so the
/// UI can present recordings in chronological order while maintaining strict cross-device safety.
pub fn build_recording_timeline_with_examiner_tz(
    recordings: &[Recording],
    min_gap_seconds: i64,
    session_split_seconds: i64,
    examiner_tz: Option<&ExaminerTimezone>,
) -> RecordingTimeline {
    use std::collections::BTreeMap;

    // Group packets per (channel, temporal_domain) to avoid cross-device/cross-basis mixing.
    let mut per_channel_domain: BTreeMap<
        (u32, TemporalDomain),
        (Vec<Point>, String, String, Option<String>),
    > = BTreeMap::new();
    let mut recordings_without_time = 0usize;
    let mut recordings_with_unknown_timezone = 0usize;

    for rec in recordings {
        let (domain, ordering_key, absolute_utc, conflict) =
            match extract_temporal_evidence_with_examiner(&rec.time, examiner_tz) {
                Some(res) => res,
                None => {
                    recordings_without_time += 1;
                    continue;
                }
            };

        if domain == TemporalDomain::DeviceLocal {
            recordings_with_unknown_timezone += 1;
        }

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

        let fs_tz = match &rec.time.timezone {
            TimeZoneState::Known(label) => label.clone(),
            TimeZoneState::Unknown => "Unknown".to_string(),
        };

        let display_tz = match (&rec.time.timezone, examiner_tz) {
            (TimeZoneState::Unknown, Some(ex)) => {
                format!("{} (Examiner Established)", ex.timezone)
            }
            (TimeZoneState::Known(label), _) => label.clone(),
            (TimeZoneState::Unknown, None) => "Unknown".to_string(),
        };

        let entry = per_channel_domain
            .entry((rec.channel, domain))
            .or_insert_with(|| (Vec::new(), display_tz, fs_tz, conflict.clone()));
        entry.0.push(Point {
            ordering_key,
            native,
            offset,
            length,
            fs_tz: entry.2.clone(),
            absolute_utc,
            conflict,
        });
    }

    let mut sessions: Vec<RecordingSession> = Vec::new();

    for ((channel, _domain), (mut points, display_tz, fs_tz, conflict)) in per_channel_domain {
        points.sort_by(|a, b| {
            match (&a.ordering_key, &b.ordering_key) {
                (TemporalOrderingKey::Absolute(d1), TemporalOrderingKey::Absolute(d2)) => {
                    d1.cmp(d2)
                }
                (TemporalOrderingKey::DeviceLocal(d1), TemporalOrderingKey::DeviceLocal(d2)) => {
                    d1.cmp(d2)
                }
                _ => std::cmp::Ordering::Equal,
            }
            .then(a.offset.cmp(&b.offset))
        });

        // Measure the channel's own nominal cadence from consecutive spacings.
        let deltas: Vec<i64> = points
            .windows(2)
            .filter_map(|w| w[0].ordering_key.delta_seconds(&w[1].ordering_key))
            .collect();
        let nominal = median_delta(&deltas).unwrap_or(0).max(1);

        // Walk the packets, cutting a new session whenever the silence is long enough
        // to be a separate recording rather than an in-recording gap.
        let mut current: Vec<&Point> = Vec::new();
        for point in &points {
            if let Some(prev) = current.last() {
                let delta = prev
                    .ordering_key
                    .delta_seconds(&point.ordering_key)
                    .unwrap_or(0);
                if delta >= session_split_seconds {
                    if let Some(session) = build_session(
                        channel,
                        &display_tz,
                        &fs_tz,
                        examiner_tz,
                        conflict.as_deref(),
                        &current,
                        nominal,
                        min_gap_seconds,
                    ) {
                        sessions.push(session);
                    }
                    current.clear();
                }
            }
            current.push(point);
        }
        if let Some(session) = build_session(
            channel,
            &display_tz,
            &fs_tz,
            examiner_tz,
            conflict.as_deref(),
            &current,
            nominal,
            min_gap_seconds,
        ) {
            sessions.push(session);
        }
    }

    // Chronological ordering across channels, keeping temporal bases segregated for safety.
    sessions.sort_by(|a, b| {
        a.temporal_basis
            .cmp(&b.temporal_basis)
            .then(a.start_normalized.cmp(&b.start_normalized))
            .then(a.channel.cmp(&b.channel))
    });

    let channels: std::collections::BTreeSet<u32> = sessions.iter().map(|s| s.channel).collect();
    let total_segments: usize = sessions.iter().map(|s| s.segment_count).sum();
    let total_missing_seconds: i64 = sessions.iter().map(|s| s.missing_seconds).sum();

    let method_suffix = if let Some(ex) = examiner_tz {
        format!(
            "; normalized to UTC using examiner-established timezone '{}' (basis: '{}', examiner: '{}')",
            ex.timezone, ex.source, ex.established_by
        )
    } else {
        String::new()
    };

    RecordingTimeline {
        channel_count: channels.len(),
        total_segments,
        total_recordings: sessions.len(),
        total_missing_seconds,
        recordings_without_time,
        recordings_with_unknown_timezone,
        examiner_timezone: examiner_tz.cloned(),
        method: format!(
            "Grouped parser recordings per channel and temporal domain; nominal cadence measured per channel from segment spacing; \
             in-recording gaps reported when a silence exceeds the cadence by at least {min_gap_seconds}s; \
             a silence of at least {session_split_seconds}s starts a new recording{method_suffix}"
        ),
        sessions,
    }
}

/// Build one session from an ordered, non-empty group of packets within the same temporal domain.
#[allow(clippy::too_many_arguments)]
fn build_session(
    channel: u32,
    timezone: &str,
    fs_timezone: &str,
    examiner_tz: Option<&ExaminerTimezone>,
    conflict: Option<&str>,
    group: &[&Point],
    nominal: i64,
    min_gap_seconds: i64,
) -> Option<RecordingSession> {
    let first = group.first()?;
    let last = group.last()?;

    let start_key = &first.ordering_key;
    let end_key = last.ordering_key.add_seconds(nominal);
    let span_seconds = start_key.delta_seconds(&end_key).unwrap_or(0).max(0);
    let temporal_basis = start_key.temporal_basis();

    // Detect in-recording gaps: a spacing longer than the cadence by a meaningful margin.
    let mut gaps: Vec<SessionGap> = Vec::new();
    for w in group.windows(2) {
        let prev = w[0];
        let next = w[1];
        let delta = prev
            .ordering_key
            .delta_seconds(&next.ordering_key)
            .unwrap_or(0);
        let missing = delta - nominal;
        if missing >= min_gap_seconds {
            let gap_open_key = prev.ordering_key.add_seconds(nominal);
            let gap_open_native = prev.native.as_ref().and_then(|n| native_plus(n, nominal));
            gaps.push(SessionGap {
                starts_after_native: gap_open_native,
                ends_before_native: next.native.clone(),
                starts_after_normalized: gap_open_key.format_iso(),
                ends_before_normalized: next.ordering_key.format_iso(),
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
            start_normalized: Some(p.ordering_key.format_iso()),
            source_offset: p.offset,
            source_length: p.length,
            absolute_utc: p.absolute_utc.clone(),
        })
        .collect();

    let start_str = start_key.format_iso();
    let end_str = end_key.format_iso();
    let id_prefix = match temporal_basis {
        TemporalBasis::AbsoluteUtc => format!("ch{channel}-{start_str}"),
        TemporalBasis::DeviceLocal => format!("ch{channel}-local-{start_str}"),
    };

    Some(RecordingSession {
        id: id_prefix,
        channel,
        start_native: first.native.clone(),
        end_native,
        start_normalized: start_str,
        end_normalized: end_str,
        timezone: timezone.to_string(),
        temporal_basis,
        segment_count: group.len(),
        span_seconds,
        covered_seconds,
        missing_seconds,
        coverage_ratio,
        nominal_segment_seconds: nominal,
        gaps,
        segments,
        filesystem_timezone: Some(fs_timezone.to_string()),
        examiner_timezone: examiner_tz.cloned(),
        timezone_conflict: conflict.map(str::to_string),
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
    fn test_1_known_timezone_timestamp_absolute_instant_works() {
        let rec = ist(1, 0, "2026-09-20T10:00:00", "2026-09-20T04:30:00Z");
        let instant = comparable_instant(&rec.time);
        assert!(instant.is_some());
        assert_eq!(instant.unwrap().to_rfc3339(), "2026-09-20T04:30:00+00:00");

        let tl = build_recording_timeline(&[rec], 30, 3600);
        assert_eq!(tl.total_recordings, 1);
        assert_eq!(tl.sessions[0].temporal_basis, TemporalBasis::AbsoluteUtc);
        assert_eq!(tl.sessions[0].timezone, "UTC+05:30");
        assert_eq!(tl.sessions[0].start_normalized, "2026-09-20T04:30:00+00:00");
    }

    #[test]
    fn test_2_unknown_timezone_valid_timestamp_local_ordering_and_no_absolute_instant() {
        let rec1 = recording(
            1,
            0,
            "2026-09-20T10:00:00",
            "2026-09-20T10:00:00",
            TimeZoneState::Unknown,
        );
        let rec2 = recording(
            1,
            1000,
            "2026-09-20T10:05:00",
            "2026-09-20T10:05:00",
            TimeZoneState::Unknown,
        );

        // FORENSIC INVARIANT: comparable_instant MUST return None when timezone is Unknown.
        assert_eq!(comparable_instant(&rec1.time), None);
        assert_eq!(comparable_instant(&rec2.time), None);

        // Local ordering remains available and segments are grouped.
        let tl = build_recording_timeline(&[rec1, rec2], 30, 3600);
        assert_eq!(tl.total_recordings, 1);
        assert_eq!(tl.sessions[0].segment_count, 2);
        assert_eq!(tl.sessions[0].temporal_basis, TemporalBasis::DeviceLocal);
        assert_eq!(tl.sessions[0].timezone, "Unknown");
        assert_eq!(
            tl.sessions[0].start_native.as_deref(),
            Some("2026-09-20T10:00:00")
        );
        assert_eq!(tl.sessions[0].start_normalized, "2026-09-20T10:00:00");
        assert_eq!(
            tl.sessions[0].end_native.as_deref(),
            Some("2026-09-20T10:10:00")
        );
        assert_eq!(tl.sessions[0].end_normalized, "2026-09-20T10:10:00");
    }

    #[test]
    fn test_3_missing_timestamp_remains_unusable() {
        let mut rec = recording(
            1,
            0,
            "2026-09-20T10:00:00",
            "2026-09-20T10:00:00",
            TimeZoneState::Unknown,
        );
        rec.time.recorder_native = None;
        rec.time.normalized = None;

        let tl = build_recording_timeline(&[rec], 30, 3600);
        assert_eq!(tl.recordings_without_time, 1);
        assert_eq!(tl.recordings_with_unknown_timezone, 0);
        assert_eq!(tl.total_recordings, 0);
    }

    #[test]
    fn test_4_unknown_timezone_recordings_not_counted_as_recordings_without_time() {
        let rec = recording(
            1,
            0,
            "2026-09-20T10:00:00",
            "2026-09-20T10:00:00",
            TimeZoneState::Unknown,
        );
        let tl = build_recording_timeline(&[rec], 30, 3600);
        assert_eq!(tl.recordings_without_time, 0);
        assert_eq!(tl.recordings_with_unknown_timezone, 1);
        assert_eq!(tl.total_recordings, 1);
    }

    #[test]
    fn test_5_preliminary_timeline_unknown_timezone_recordings_appear() {
        let recs = vec![
            recording(
                1,
                0,
                "2026-09-20T10:00:00",
                "2026-09-20T10:00:00",
                TimeZoneState::Unknown,
            ),
            recording(
                1,
                1000,
                "2026-09-20T10:00:10",
                "2026-09-20T10:00:10",
                TimeZoneState::Unknown,
            ),
        ];
        let tl = build_recording_timeline(&recs, 5, 3600);
        assert_eq!(tl.total_recordings, 1);
        assert_eq!(tl.total_segments, 2);
        assert_eq!(tl.channel_count, 1);
        assert_eq!(tl.sessions[0].temporal_basis, TemporalBasis::DeviceLocal);
        assert_eq!(tl.sessions[0].timezone, "Unknown");
    }

    #[test]
    fn test_6_cross_device_safety_local_time_not_silently_compared_with_utc() {
        // DeviceLocal ordering key
        let local_dt =
            chrono::NaiveDateTime::parse_from_str("2026-09-20T10:00:00", "%Y-%m-%dT%H:%M:%S")
                .unwrap();
        let key_local = TemporalOrderingKey::DeviceLocal(local_dt);

        // Absolute UTC ordering key
        let utc_dt = chrono::DateTime::parse_from_rfc3339("2026-09-20T10:05:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let key_utc = TemporalOrderingKey::Absolute(utc_dt);

        // FORENSIC SAFETY: delta_seconds across different bases MUST return None.
        assert_eq!(key_local.delta_seconds(&key_utc), None);
        assert_eq!(key_utc.delta_seconds(&key_local), None);

        // Timeline construction separates them into different temporal bases
        let rec_local = recording(
            1,
            0,
            "2026-09-20T10:00:00",
            "2026-09-20T10:00:00",
            TimeZoneState::Unknown,
        );
        let rec_utc = recording(
            2,
            1000,
            "2026-09-20T10:05:00",
            "2026-09-20T10:05:00Z",
            TimeZoneState::Known("UTC".into()),
        );

        let tl = build_recording_timeline(&[rec_local, rec_utc], 30, 3600);
        assert_eq!(tl.total_recordings, 2);
        // AbsoluteUtc session is segregated from DeviceLocal session
        let bases: Vec<TemporalBasis> = tl.sessions.iter().map(|s| s.temporal_basis).collect();
        assert!(bases.contains(&TemporalBasis::AbsoluteUtc));
        assert!(bases.contains(&TemporalBasis::DeviceLocal));
    }

    #[test]
    fn test_7_existing_known_timezone_behavior_no_regression() {
        let recs = vec![
            ist(1, 0, "2026-09-20T10:00:00", "2026-09-20T04:30:00Z"),
            ist(1, 1000, "2026-09-20T10:05:00", "2026-09-20T04:35:00Z"),
            ist(1, 2000, "2026-09-20T10:10:00", "2026-09-20T04:40:00Z"),
        ];
        let tl = build_recording_timeline(&recs, 30, 3600);
        assert_eq!(tl.total_recordings, 1);
        let s = &tl.sessions[0];
        assert_eq!(s.temporal_basis, TemporalBasis::AbsoluteUtc);
        assert_eq!(s.segment_count, 3);
        assert!(s.gaps.is_empty());
        assert_eq!(s.missing_seconds, 0);
        assert_eq!(tl.recordings_without_time, 0);
        assert_eq!(tl.recordings_with_unknown_timezone, 0);
    }

    // =========================================================================
    // PHASE 3 — EXAMINER-ESTABLISHED TIMEZONE TESTS
    // =========================================================================

    fn examiner_tz(tz: &str) -> ExaminerTimezone {
        ExaminerTimezone {
            timezone: tz.to_string(),
            source: "DVR On-screen Setup Menu Photo (Doc #1042)".to_string(),
            established_by: "Examiner Jane Doe".to_string(),
            notes: Some("Confirmed local time was set to Indian Standard Time".to_string()),
            established_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_phase3_1_no_examiner_timezone() {
        let rec = recording(1, 0, "2026-09-20T10:00:00", "2026-09-20T10:00:00", TimeZoneState::Unknown);
        let tl = build_recording_timeline_with_examiner_tz(&[rec], 30, 3600, None);
        assert_eq!(tl.total_recordings, 1);
        let s = &tl.sessions[0];
        assert_eq!(s.temporal_basis, TemporalBasis::DeviceLocal);
        assert_eq!(s.timezone, "Unknown");
        assert_eq!(s.filesystem_timezone.as_deref(), Some("Unknown"));
        assert_eq!(s.examiner_timezone, None);
        assert_eq!(s.start_normalized, "2026-09-20T10:00:00");
    }

    #[test]
    fn test_phase3_2_examiner_timezone_supplied() {
        let rec = recording(1, 0, "2026-09-20T10:00:00", "2026-09-20T10:00:00", TimeZoneState::Unknown);
        let ex = examiner_tz("Asia/Kolkata");
        let tl = build_recording_timeline_with_examiner_tz(&[rec], 30, 3600, Some(&ex));
        assert_eq!(tl.total_recordings, 1);
        let s = &tl.sessions[0];
        assert_eq!(s.temporal_basis, TemporalBasis::AbsoluteUtc);
        assert_eq!(s.timezone, "Asia/Kolkata (Examiner Established)");
        assert_eq!(s.filesystem_timezone.as_deref(), Some("Unknown"));
        assert_eq!(s.examiner_timezone.as_ref().map(|e| &e.timezone), Some(&"Asia/Kolkata".to_string()));
        // Verifies conversion: 10:00 local with +05:30 is 04:30 UTC
        assert_eq!(s.start_native.as_deref(), Some("2026-09-20T10:00:00"));
        assert_eq!(s.start_normalized, "2026-09-20T04:30:00+00:00");
    }

    #[test]
    fn test_phase3_3_known_parser_timezone_plus_matching_examiner_timezone() {
        let rec = ist(1, 0, "2026-09-20T10:00:00", "2026-09-20T04:30:00Z");
        let ex = examiner_tz("+05:30");
        let tl = build_recording_timeline_with_examiner_tz(&[rec], 30, 3600, Some(&ex));
        assert_eq!(tl.total_recordings, 1);
        let s = &tl.sessions[0];
        assert_eq!(s.temporal_basis, TemporalBasis::AbsoluteUtc);
        assert_eq!(s.filesystem_timezone.as_deref(), Some("UTC+05:30"));
        assert_eq!(s.timezone_conflict, None);
    }

    #[test]
    fn test_phase3_4_conflicting_parser_and_examiner_timezone() {
        // Filesystem reports UTC+05:30, but examiner asserts -05:00
        let rec = ist(1, 0, "2026-09-20T10:00:00", "2026-09-20T04:30:00Z");
        let ex = examiner_tz("-05:00");
        let tl = build_recording_timeline_with_examiner_tz(&[rec], 30, 3600, Some(&ex));
        assert_eq!(tl.total_recordings, 1);
        let s = &tl.sessions[0];
        assert!(s.timezone_conflict.is_some());
        assert!(s.timezone_conflict.as_ref().unwrap().contains("Filesystem reports 'UTC+05:30' but examiner established '-05:00'"));
    }

    #[test]
    fn test_phase3_5_changing_examiner_timezone() {
        let rec = recording(1, 0, "2026-09-20T10:00:00", "2026-09-20T10:00:00", TimeZoneState::Unknown);
        let ex1 = examiner_tz("+05:30");
        let tl1 = build_recording_timeline_with_examiner_tz(&[rec.clone()], 30, 3600, Some(&ex1));
        assert_eq!(tl1.sessions[0].start_normalized, "2026-09-20T04:30:00+00:00");

        // Change to +04:00
        let ex2 = examiner_tz("+04:00");
        let tl2 = build_recording_timeline_with_examiner_tz(&[rec], 30, 3600, Some(&ex2));
        assert_eq!(tl2.sessions[0].start_normalized, "2026-09-20T06:00:00+00:00");
    }

    #[test]
    fn test_phase3_6_removing_examiner_timezone() {
        let rec = recording(1, 0, "2026-09-20T10:00:00", "2026-09-20T10:00:00", TimeZoneState::Unknown);
        let ex = examiner_tz("+05:30");
        let tl1 = build_recording_timeline_with_examiner_tz(&[rec.clone()], 30, 3600, Some(&ex));
        assert_eq!(tl1.sessions[0].temporal_basis, TemporalBasis::AbsoluteUtc);

        // Remove examiner timezone: reverts cleanly to DeviceLocal without mutating recording
        let tl2 = build_recording_timeline_with_examiner_tz(&[rec], 30, 3600, None);
        assert_eq!(tl2.sessions[0].temporal_basis, TemporalBasis::DeviceLocal);
        assert_eq!(tl2.sessions[0].timezone, "Unknown");
        assert_eq!(tl2.sessions[0].examiner_timezone, None);
    }

    #[test]
    fn test_phase3_7_timeline_conversion_accuracy() {
        let rec = recording(1, 0, "2026-09-20T10:00:00", "2026-09-20T10:00:00", TimeZoneState::Unknown);
        let ex = examiner_tz("UTC+05:30");
        let tl = build_recording_timeline_with_examiner_tz(&[rec], 30, 3600, Some(&ex));
        let s = &tl.sessions[0];
        // 10:00 local minus 5:30 is 04:30 UTC
        assert_eq!(s.start_normalized, "2026-09-20T04:30:00+00:00");
        assert_eq!(s.start_native.as_deref(), Some("2026-09-20T10:00:00"));
        assert_eq!(s.segments[0].absolute_utc.as_deref(), Some("2026-09-20T04:30:00+00:00"));
    }

    #[test]
    fn test_phase3_8_cross_device_comparison_with_examiner_tz() {
        let rec1 = recording(1, 0, "2026-09-20T10:00:00", "2026-09-20T10:00:00", TimeZoneState::Unknown);
        let rec2 = recording(2, 1000, "2026-09-20T04:30:00", "2026-09-20T04:30:00Z", TimeZoneState::Known("UTC".into()));

        // Case A: rec1 has no examiner timezone -> cross-device comparison fails safely
        let tl_uncalibrated = build_recording_timeline_with_examiner_tz(&[rec1.clone(), rec2.clone()], 30, 3600, None);
        let s_local = tl_uncalibrated.sessions.iter().find(|s| s.channel == 1).unwrap();
        let s_utc = tl_uncalibrated.sessions.iter().find(|s| s.channel == 2).unwrap();
        assert_eq!(s_local.temporal_basis, TemporalBasis::DeviceLocal);
        assert_eq!(s_utc.temporal_basis, TemporalBasis::AbsoluteUtc);

        // Case B: rec1 has examiner timezone +05:30 -> both are now in AbsoluteUtc and comparable
        let ex = examiner_tz("+05:30");
        let tl_calibrated = build_recording_timeline_with_examiner_tz(&[rec1, rec2], 30, 3600, Some(&ex));
        for s in &tl_calibrated.sessions {
            assert_eq!(s.temporal_basis, TemporalBasis::AbsoluteUtc);
        }
        // Channel 1 at 10:00 +05:30 is 04:30 UTC, exactly matching Channel 2 at 04:30 UTC
        assert_eq!(tl_calibrated.sessions[0].start_normalized, "2026-09-20T04:30:00+00:00");
    }

    #[test]
    fn test_phase3_9_report_provenance_representation() {
        let rec = recording(1, 0, "2026-09-20T10:00:00", "2026-09-20T10:00:00", TimeZoneState::Unknown);
        let ex = examiner_tz("Asia/Kolkata");
        let tl = build_recording_timeline_with_examiner_tz(&[rec], 30, 3600, Some(&ex));
        assert!(tl.method.contains("normalized to UTC using examiner-established timezone 'Asia/Kolkata'"));
        assert!(tl.method.contains("DVR On-screen Setup Menu Photo"));
        assert_eq!(tl.examiner_timezone.unwrap().established_by, "Examiner Jane Doe");
    }

    #[test]
    fn test_phase3_10_system_timezone_never_used_automatically() {
        // Without an explicit examiner timezone, unknown stays unknown regardless of host OS/env
        let rec = recording(1, 0, "2026-09-20T10:00:00", "2026-09-20T10:00:00", TimeZoneState::Unknown);
        let tl = build_recording_timeline_with_examiner_tz(&[rec], 30, 3600, None);
        assert_eq!(tl.sessions[0].temporal_basis, TemporalBasis::DeviceLocal);
        assert_eq!(tl.sessions[0].timezone, "Unknown");
        assert_eq!(tl.sessions[0].start_normalized, "2026-09-20T10:00:00");
        assert!(!tl.sessions[0].start_normalized.ends_with('Z'));
    }

    #[test]
    fn test_iana_dst_america_new_york_winter_and_summer() {
        // Winter: 2026-01-15 10:00:00 in America/New_York is EST (-05:00) -> 15:00:00 UTC
        let rec_winter = recording(1, 0, "2026-01-15T10:00:00", "2026-01-15T10:00:00", TimeZoneState::Unknown);
        let ex = examiner_tz("America/New_York");
        let tl_winter = build_recording_timeline_with_examiner_tz(&[rec_winter], 30, 3600, Some(&ex));
        assert_eq!(tl_winter.sessions[0].start_normalized, "2026-01-15T15:00:00+00:00");

        // Summer: 2026-07-15 10:00:00 in America/New_York is EDT (-04:00) -> 14:00:00 UTC
        let rec_summer = recording(1, 0, "2026-07-15T10:00:00", "2026-07-15T10:00:00", TimeZoneState::Unknown);
        let tl_summer = build_recording_timeline_with_examiner_tz(&[rec_summer], 30, 3600, Some(&ex));
        assert_eq!(tl_summer.sessions[0].start_normalized, "2026-07-15T14:00:00+00:00");

        // Also verify case-insensitivity: "america/new_york"
        let ex_lower = examiner_tz("america/new_york");
        let rec_summer2 = recording(1, 0, "2026-07-15T10:00:00", "2026-07-15T10:00:00", TimeZoneState::Unknown);
        let tl_summer2 = build_recording_timeline_with_examiner_tz(&[rec_summer2], 30, 3600, Some(&ex_lower));
        assert_eq!(tl_summer2.sessions[0].start_normalized, "2026-07-15T14:00:00+00:00");
    }

    #[test]
    fn test_iana_dst_europe_london_winter_and_summer() {
        // Winter: 2026-01-15 10:00:00 in Europe/London is GMT (+00:00) -> 10:00:00 UTC
        let rec_winter = recording(1, 0, "2026-01-15T10:00:00", "2026-01-15T10:00:00", TimeZoneState::Unknown);
        let ex = examiner_tz("Europe/London");
        let tl_winter = build_recording_timeline_with_examiner_tz(&[rec_winter], 30, 3600, Some(&ex));
        assert_eq!(tl_winter.sessions[0].start_normalized, "2026-01-15T10:00:00+00:00");

        // Summer: 2026-07-15 10:00:00 in Europe/London is BST (+01:00) -> 09:00:00 UTC
        let rec_summer = recording(1, 0, "2026-07-15T10:00:00", "2026-07-15T10:00:00", TimeZoneState::Unknown);
        let tl_summer = build_recording_timeline_with_examiner_tz(&[rec_summer], 30, 3600, Some(&ex));
        assert_eq!(tl_summer.sessions[0].start_normalized, "2026-07-15T09:00:00+00:00");
    }

    #[test]
    fn test_iana_asia_kolkata_constant() {
        let ex = examiner_tz("Asia/Kolkata");
        // Winter: 2026-01-15 10:00:00 is +05:30 -> 04:30:00 UTC
        let rec_winter = recording(1, 0, "2026-01-15T10:00:00", "2026-01-15T10:00:00", TimeZoneState::Unknown);
        let tl_winter = build_recording_timeline_with_examiner_tz(&[rec_winter], 30, 3600, Some(&ex));
        assert_eq!(tl_winter.sessions[0].start_normalized, "2026-01-15T04:30:00+00:00");

        // Summer: 2026-07-15 10:00:00 is also +05:30 -> 04:30:00 UTC
        let rec_summer = recording(1, 0, "2026-07-15T10:00:00", "2026-07-15T10:00:00", TimeZoneState::Unknown);
        let tl_summer = build_recording_timeline_with_examiner_tz(&[rec_summer], 30, 3600, Some(&ex));
        assert_eq!(tl_summer.sessions[0].start_normalized, "2026-07-15T04:30:00+00:00");
    }

    #[test]
    fn test_numeric_fixed_offsets_preserved() {
        use chrono::NaiveDate;

        let winter = NaiveDate::from_ymd_opt(2026, 1, 15).unwrap().and_hms_opt(10, 0, 0);
        let summer = NaiveDate::from_ymd_opt(2026, 7, 15).unwrap().and_hms_opt(10, 0, 0);

        // Numeric offsets must remain completely constant across winter and summer
        assert_eq!(resolve_timezone_offset("UTC", winter), chrono::FixedOffset::east_opt(0));
        assert_eq!(resolve_timezone_offset("UTC", summer), chrono::FixedOffset::east_opt(0));
        assert_eq!(resolve_timezone_offset("Z", winter), chrono::FixedOffset::east_opt(0));
        assert_eq!(resolve_timezone_offset("+05:30", winter), chrono::FixedOffset::east_opt(19800));
        assert_eq!(resolve_timezone_offset("+05:30", summer), chrono::FixedOffset::east_opt(19800));
        assert_eq!(resolve_timezone_offset("-05:00", winter), chrono::FixedOffset::west_opt(18000));
        assert_eq!(resolve_timezone_offset("-05:00", summer), chrono::FixedOffset::west_opt(18000));
        assert_eq!(resolve_timezone_offset("UTC+05:30", winter), chrono::FixedOffset::east_opt(19800));
        assert_eq!(resolve_timezone_offset("UTC-04:00", summer), chrono::FixedOffset::west_opt(14400));
    }

    #[test]
    fn test_invalid_timezone_rejected() {
        assert_eq!(resolve_timezone_offset("", None), None);
        assert_eq!(resolve_timezone_offset("   ", None), None);
        assert_eq!(resolve_timezone_offset("Not_A_Real_Timezone", None), None);
        assert_eq!(resolve_timezone_offset("Mars/Phobos", None), None);
        assert_eq!(resolve_timezone_offset("+99:99", None), None);
        assert_eq!(resolve_timezone_offset("invalid", None), None);
    }
}
