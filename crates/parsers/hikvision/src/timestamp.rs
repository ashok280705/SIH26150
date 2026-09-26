//! # Hikvision timestamp decoding
//!
//! Hikvision records time as **unix epoch seconds**. There is no packed bit-field to
//! unpack, which makes this module short — but not trivial, because three things still
//! have to be represented honestly:
//!
//! 1. **The raw value survives.** A report must be able to quote the bytes that were on
//!    disk, not only this crate's interpretation of them.
//! 2. **`i32::MAX` is not a time.** A B-tree entry whose start time is `i32::MAX` marks a
//!    recording the recorder had not finished writing. Decoding that as
//!    *2038-01-19T03:14:07Z* would put a fabricated instant in front of an examiner.
//! 3. **No timezone is applied.** Nothing in the Hikvision structures records a UTC
//!    offset. The recorder's clock may well have been set to local time, but that is a
//!    fact about the deployment, not about the bytes. Zone selection belongs to the
//!    presentation layer, which can apply an offset established separately.
//!
//! ## Confidence
//!
//! Every decode carries a [`TimeConfidence`]. A value inside the profile's plausibility
//! window scores higher than one outside it, and an absent or sentinel value scores
//! nothing at all. The window is deliberately advisory: an implausible timestamp is
//! reported with low confidence rather than dropped, because a recorder with a wrong
//! clock is a common and forensically interesting condition.

use forensic_core::{OemProfile, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};

use crate::layout::{i64_from, key, u64_from, vs};

/// Which structure a timestamp was read from, for provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimestampStructure {
    /// The `+60` tree timestamp in a HIKBTREE header.
    BTreeHeader,
    /// The `+24` start time of a HIKBTREE entry.
    EntryStart,
    /// The `+28` end time of a HIKBTREE entry.
    EntryEnd,
    /// The `+32` epoch start in a block footer's index header.
    BlockIndexEpochStart,
    /// The `+36` epoch end in a block footer's index header.
    BlockIndexEpochEnd,
    /// A clip slot's start time (`+56`, falling back to `+40`).
    ClipStart,
    /// A clip slot's end time (`+48`).
    ClipEnd,
    /// A clip slot's `+40` field, used as the fallback start time.
    ClipTimeA,
}

impl TimestampStructure {
    /// Stable label for evidence strings and metadata keys.
    pub fn label(&self) -> &'static str {
        match self {
            Self::BTreeHeader => "hikbtree_header_tree_timestamp",
            Self::EntryStart => "hikbtree_entry_start_time",
            Self::EntryEnd => "hikbtree_entry_end_time",
            Self::BlockIndexEpochStart => "block_index_epoch_start",
            Self::BlockIndexEpochEnd => "block_index_epoch_end",
            Self::ClipStart => "clip_start_time",
            Self::ClipEnd => "clip_end_time",
            Self::ClipTimeA => "clip_time_a",
        }
    }
}

/// How much weight may be placed on a decoded instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TimeConfidence {
    /// No instant was established: the field was absent, zero, or the incomplete sentinel.
    None,
    /// An instant decoded, but outside the profile's plausibility window. Preserved
    /// because a recorder with a mis-set clock is evidence, not noise.
    Low,
    /// An instant decoded inside the plausibility window.
    High,
}

impl TimeConfidence {
    /// Numeric score for reports that need one. Not a probability.
    pub fn score(&self) -> f64 {
        match self {
            Self::None => 0.0,
            Self::Low => 0.4,
            Self::High => 0.9,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::High => "high",
        }
    }
}

/// A decoded Hikvision timestamp, with the raw value and the reason preserved.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HikTimestamp {
    /// The field exactly as stored, before any interpretation.
    pub raw: i64,
    /// Which structure the value came from.
    pub structure: TimestampStructure,
    /// Physical offset of the field in the evidence, for provenance.
    pub field_offset: u64,
    /// Unix seconds, when an instant was actually established. `None` for an absent,
    /// zero, or incomplete-sentinel field — never substituted with the epoch.
    pub unix_seconds: Option<i64>,
    /// ISO-8601 rendering of `unix_seconds` read as UTC, with no offset applied.
    ///
    /// `None` whenever `unix_seconds` is `None`. The "read as UTC" choice is recorded in
    /// [`Self::normalization_method`] so a reader can see that no zone was established.
    pub iso_8601_utc: Option<String>,
    /// Whether the recorder marked this as an unfinished recording.
    pub incomplete: bool,
    /// Confidence in the decoded instant.
    pub confidence: TimeConfidence,
    /// Human-readable account of what was decoded and why.
    pub evidence: String,
}

/// Names the normalization choice explicitly, so the absence of a timezone is visible in
/// the output rather than implied.
pub const NORMALIZATION_METHOD: &str =
    "hikvision_unix_seconds_read_as_utc; the Hikvision structures record no timezone offset, \
     so none was applied at parse time";

/// Encoding label recorded alongside a raw value.
pub const RAW_FORMAT: &str = "HIKVISION_UNIX_SECONDS_LE";

impl HikTimestamp {
    /// Decode a timestamp field.
    ///
    /// `raw` is the field widened to `i64` without reinterpretation, so both the `i32`
    /// entry times and the `u32` clip times pass through unchanged.
    pub fn decode(
        raw: i64,
        structure: TimestampStructure,
        field_offset: u64,
        profile: &OemProfile,
    ) -> Self {
        let incomplete_value = i64_from(profile, key::TS_INCOMPLETE_VALUE, i32::MAX as i64);
        let epoch_base = i64_from(profile, key::TS_EPOCH_BASE, 0);
        let min = i64_from(profile, key::TS_PLAUSIBLE_MIN, 946_684_800);
        let max = i64_from(profile, key::TS_PLAUSIBLE_MAX, 4_102_444_800);

        // The incomplete sentinel is checked before anything else: it is a status flag
        // that happens to occupy a time field, not a late-2038 instant.
        if raw == incomplete_value {
            return Self {
                raw,
                structure,
                field_offset,
                unix_seconds: None,
                iso_8601_utc: None,
                incomplete: true,
                confidence: TimeConfidence::None,
                evidence: format!(
                    "{} at offset {field_offset} holds the incomplete-recording sentinel \
                     ({incomplete_value}); the recorder had not finished writing this recording, \
                     so no instant was decoded",
                    structure.label()
                ),
            };
        }

        // Zero is the absent value in these structures, not 1970-01-01. Every Hikvision
        // recorder whose clock has ever been set writes a value far above zero, so
        // treating zero as the epoch would invent a timestamp for an empty field.
        if raw == 0 {
            return Self {
                raw,
                structure,
                field_offset,
                unix_seconds: None,
                iso_8601_utc: None,
                incomplete: false,
                confidence: TimeConfidence::None,
                evidence: format!(
                    "{} at offset {field_offset} is zero, which these structures use for an \
                     unwritten field; it was not decoded as 1970-01-01",
                    structure.label()
                ),
            };
        }

        // A negative value cannot be a recorder clock in this encoding. Reported rather
        // than clamped, because it is evidence the field is damaged.
        if raw < 0 {
            return Self {
                raw,
                structure,
                field_offset,
                unix_seconds: None,
                iso_8601_utc: None,
                incomplete: false,
                confidence: TimeConfidence::None,
                evidence: format!(
                    "{} at offset {field_offset} holds the negative value {raw}, which is not a \
                     representable Hikvision recorder clock; the field is damaged and was not \
                     decoded",
                    structure.label()
                ),
            };
        }

        let seconds = raw.saturating_add(epoch_base);
        let plausible = seconds >= min && seconds <= max;
        let iso = chrono::DateTime::from_timestamp(seconds, 0).map(|d| d.to_rfc3339());

        // A value that cannot be turned into a calendar instant at all establishes no
        // time, whatever the plausibility window says.
        let confidence = match (&iso, plausible) {
            (None, _) => TimeConfidence::None,
            (Some(_), true) => TimeConfidence::High,
            (Some(_), false) => TimeConfidence::Low,
        };

        let evidence = match (&iso, plausible) {
            (None, _) => format!(
                "{} at offset {field_offset} holds {raw}, which is outside the representable \
                 calendar range; no instant was decoded",
                structure.label()
            ),
            (Some(rendered), true) => format!(
                "{} at offset {field_offset} decoded from unix seconds {seconds} to {rendered}; \
                 {NORMALIZATION_METHOD}",
                structure.label()
            ),
            (Some(rendered), false) => format!(
                "{} at offset {field_offset} decoded from unix seconds {seconds} to {rendered}, \
                 which falls outside the profile's plausibility window [{min}, {max}]. Preserved \
                 with low confidence: a recorder clock that was never set, or was set wrongly, is \
                 itself evidence",
                structure.label()
            ),
        };

        Self {
            raw,
            structure,
            field_offset,
            unix_seconds: iso.as_ref().map(|_| seconds),
            iso_8601_utc: iso,
            incomplete: false,
            confidence,
            evidence,
        }
    }

    /// Whether an absolute instant was established.
    pub fn is_decoded(&self) -> bool {
        self.unix_seconds.is_some()
    }

    /// The validation outcome this decode implies.
    pub fn validation(&self) -> ValidationState {
        let kind = match self.confidence {
            TimeConfidence::High => ValidationStateKind::Pass,
            TimeConfidence::Low => ValidationStateKind::Review,
            // An absent timestamp is not a failure of the evidence; it is a fact about it.
            TimeConfidence::None if self.incomplete => ValidationStateKind::Review,
            TimeConfidence::None => ValidationStateKind::Unknown,
        };
        vs(
            kind,
            self.evidence.clone(),
            "hikvision_timestamp_decode",
            self.structure.label(),
        )
    }
}

/// Decide a clip's start time from its two candidate fields.
///
/// A clip slot carries a start time at `clip_start_time_offset` and another time value at
/// `clip_time_a_offset`. The dedicated start field wins when it decodes; `time A` is the
/// documented fallback. Which one was used is recorded, because silently preferring one
/// would make an examiner unable to tell a primary reading from a fallback.
pub fn resolve_clip_start(primary: HikTimestamp, fallback: HikTimestamp) -> (HikTimestamp, bool) {
    if primary.is_decoded() {
        (primary, false)
    } else if fallback.is_decoded() {
        let mut used = fallback;
        used.evidence = format!(
            "{} (used as the clip start time because the dedicated start field at offset {} \
             established no instant)",
            used.evidence, primary.field_offset
        );
        (used, true)
    } else {
        // Neither decoded. Keep the primary so its offset and raw value stay in the record.
        (primary, false)
    }
}

/// Whether a start/end pair spans no more than the profile's maximum plausible duration.
///
/// Returns `None` when the span cannot be evaluated because one end is undecoded — which
/// is different from "the span is fine" and must not collapse into it.
pub fn span_within_limit(
    start: &HikTimestamp,
    end: &HikTimestamp,
    profile: &OemProfile,
) -> Option<bool> {
    let limit = u64_from(profile, key::CLIP_MAX_DURATION_SECONDS, 604_800) as i64;
    let s = start.unix_seconds?;
    let e = end.unix_seconds?;
    // An end before its start is not a long span; it is an ordering anomaly, reported
    // separately by the caller. Here it simply is not within the limit.
    if e < s {
        return Some(false);
    }
    Some(e.saturating_sub(s) <= limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::tests_support::hikvision_profile;

    /// 2026-09-23T00:00:00Z
    const T_2026: i64 = 1_774_224_000;

    #[test]
    fn a_plausible_unix_second_decodes_with_high_confidence() {
        let p = hikvision_profile();
        let ts = HikTimestamp::decode(T_2026, TimestampStructure::EntryStart, 0x1000, &p);
        assert_eq!(ts.unix_seconds, Some(T_2026));
        assert_eq!(ts.confidence, TimeConfidence::High);
        assert!(ts.is_decoded());
        assert!(!ts.incomplete);
        assert_eq!(ts.raw, T_2026, "the raw value must survive decoding");
        assert_eq!(ts.field_offset, 0x1000);
    }

    #[test]
    fn the_incomplete_sentinel_is_a_status_flag_not_a_2038_timestamp() {
        let p = hikvision_profile();
        let ts = HikTimestamp::decode(i32::MAX as i64, TimestampStructure::EntryStart, 0x2000, &p);
        assert!(ts.incomplete);
        assert_eq!(ts.unix_seconds, None, "no instant may be decoded");
        assert_eq!(ts.iso_8601_utc, None);
        assert_eq!(ts.confidence, TimeConfidence::None);
        assert!(
            !ts.evidence.contains("2038"),
            "must not render a fake instant"
        );
        assert!(ts.evidence.contains("incomplete"));
        // It is a real observation about the recording, so it warrants review.
        assert_eq!(ts.validation().state, ValidationStateKind::Review);
    }

    #[test]
    fn zero_is_an_unwritten_field_not_the_epoch() {
        let p = hikvision_profile();
        let ts = HikTimestamp::decode(0, TimestampStructure::ClipEnd, 0x30, &p);
        assert_eq!(ts.unix_seconds, None);
        assert!(!ts.evidence.contains("1970-01-01T00:00:00"));
        assert_eq!(ts.confidence, TimeConfidence::None);
        assert_eq!(ts.validation().state, ValidationStateKind::Unknown);
    }

    #[test]
    fn a_negative_field_is_reported_damaged_rather_than_clamped() {
        let p = hikvision_profile();
        let ts = HikTimestamp::decode(-42, TimestampStructure::EntryEnd, 0x40, &p);
        assert_eq!(ts.unix_seconds, None);
        assert_eq!(ts.raw, -42, "the damaged value is preserved verbatim");
        assert!(ts.evidence.contains("damaged"));
    }

    #[test]
    fn an_implausible_but_representable_instant_is_kept_with_low_confidence() {
        let p = hikvision_profile();
        // 1980: before the profile's plausibility window, but a real recorder clock value
        // for a unit whose battery died.
        let ts = HikTimestamp::decode(315_532_800, TimestampStructure::ClipStart, 0x50, &p);
        assert_eq!(ts.confidence, TimeConfidence::Low);
        assert!(ts.is_decoded(), "it must not be discarded");
        assert!(ts.evidence.contains("plausibility window"));
        assert_eq!(ts.validation().state, ValidationStateKind::Review);
    }

    #[test]
    fn no_timezone_offset_is_ever_applied_at_parse_time() {
        let p = hikvision_profile();
        let ts = HikTimestamp::decode(T_2026, TimestampStructure::ClipStart, 0, &p);
        let iso = ts.iso_8601_utc.as_deref().unwrap();
        assert!(
            iso.ends_with("+00:00") || iso.ends_with('Z'),
            "the value must be rendered as UTC, not shifted: {iso}"
        );
        assert!(!iso.contains("+05:30"), "no regional offset may be applied");
        assert!(NORMALIZATION_METHOD.contains("no timezone offset"));
    }

    #[test]
    fn the_clip_start_falls_back_to_time_a_and_records_that_it_did() {
        let p = hikvision_profile();
        let primary = HikTimestamp::decode(0, TimestampStructure::ClipStart, 0x56, &p);
        let fallback = HikTimestamp::decode(T_2026, TimestampStructure::ClipTimeA, 0x40, &p);
        let (used, was_fallback) = resolve_clip_start(primary, fallback);
        assert!(was_fallback);
        assert_eq!(used.unix_seconds, Some(T_2026));
        assert!(used.evidence.contains("used as the clip start time"));
        assert!(used.evidence.contains("0x56") || used.evidence.contains("86"));
    }

    #[test]
    fn the_dedicated_start_field_wins_when_it_decodes() {
        let p = hikvision_profile();
        let primary = HikTimestamp::decode(T_2026, TimestampStructure::ClipStart, 0x56, &p);
        let fallback = HikTimestamp::decode(T_2026 - 900, TimestampStructure::ClipTimeA, 0x40, &p);
        let (used, was_fallback) = resolve_clip_start(primary, fallback);
        assert!(!was_fallback);
        assert_eq!(used.unix_seconds, Some(T_2026));
        assert_eq!(used.structure, TimestampStructure::ClipStart);
    }

    #[test]
    fn an_undecodable_pair_makes_the_span_unevaluable_not_acceptable() {
        let p = hikvision_profile();
        let start = HikTimestamp::decode(0, TimestampStructure::ClipStart, 0, &p);
        let end = HikTimestamp::decode(T_2026, TimestampStructure::ClipEnd, 8, &p);
        assert_eq!(
            span_within_limit(&start, &end, &p),
            None,
            "unknown must not collapse into 'within limit'"
        );
    }

    #[test]
    fn a_span_longer_than_the_declared_limit_is_rejected() {
        let p = hikvision_profile();
        let start = HikTimestamp::decode(T_2026, TimestampStructure::ClipStart, 0, &p);
        let eight_days =
            HikTimestamp::decode(T_2026 + 8 * 86_400, TimestampStructure::ClipEnd, 8, &p);
        assert_eq!(span_within_limit(&start, &eight_days, &p), Some(false));

        let one_hour = HikTimestamp::decode(T_2026 + 3_600, TimestampStructure::ClipEnd, 8, &p);
        assert_eq!(span_within_limit(&start, &one_hour, &p), Some(true));
    }

    #[test]
    fn exactly_seven_days_is_within_the_limit_and_one_second_more_is_not() {
        let p = hikvision_profile();
        let start = HikTimestamp::decode(T_2026, TimestampStructure::ClipStart, 0, &p);
        let seven = HikTimestamp::decode(T_2026 + 604_800, TimestampStructure::ClipEnd, 8, &p);
        let over = HikTimestamp::decode(T_2026 + 604_801, TimestampStructure::ClipEnd, 8, &p);
        assert_eq!(span_within_limit(&start, &seven, &p), Some(true));
        assert_eq!(span_within_limit(&start, &over, &p), Some(false));
    }

    #[test]
    fn an_end_before_its_start_is_not_reported_as_within_the_limit() {
        let p = hikvision_profile();
        let start = HikTimestamp::decode(T_2026, TimestampStructure::ClipStart, 0, &p);
        let end = HikTimestamp::decode(T_2026 - 60, TimestampStructure::ClipEnd, 8, &p);
        assert_eq!(span_within_limit(&start, &end, &p), Some(false));
    }

    #[test]
    fn confidence_orders_none_below_low_below_high() {
        assert!(TimeConfidence::None < TimeConfidence::Low);
        assert!(TimeConfidence::Low < TimeConfidence::High);
        assert!(TimeConfidence::None.score() < TimeConfidence::High.score());
    }
}
