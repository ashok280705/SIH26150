//! # Dahua packed timestamp decoding
//!
//! Dahua structures store wall-clock time as a packed 32-bit field with a base year of
//! 2000, not as a unix epoch value:
//!
//! ```text
//!   bit 31                                                            bit 0
//!   ┌────────────┬──────────┬───────────┬───────────┬────────────┬──────────┐
//!   │ year (6)   │ month(4) │  day (5)  │  hour (5) │ minute (6) │ second(6)│
//!   │ +2000      │          │           │           │            │          │
//!   └────────────┴──────────┴───────────┴───────────┴────────────┴──────────┘
//!     >> 26        >> 22       >> 17       >> 12       >> 6         >> 0
//! ```
//!
//! ## No timezone is applied here
//!
//! The recorder writes local wall-clock digits. This decoder reports those digits and the
//! instant they denote **read as UTC**, because that is the only interpretation that adds
//! no unverified assumption. It never applies the examiner's local zone and never applies
//! a fixed regional offset: presenting the recorder's clock in a jurisdiction's timezone
//! is an evidence-layer decision that requires a separately established clock offset.
//!
//! The previous implementation added a hard-coded +05:30 during parsing, which silently
//! attributed an offset the evidence never stated. That is gone.
//!
//! ## Per-structure decoders behind one interface
//!
//! [`TimestampStructure`] records which structure a value came from, and
//! [`DahuaTimestamp::confidence`] records how well established that structure's encoding
//! is. The DHAV frame header encoding is corroborated by independent public
//! implementations of the container; the block-table and DHII fields are read with the
//! same encoding but are reported as [`TimestampConfidence::DecodedProvisionalEncoding`],
//! so an examiner is told the difference rather than having it flattened.

use chrono::{NaiveDate, TimeZone, Utc};
use forensic_core::OemProfile;
use serde::{Deserialize, Serialize};

use crate::layout::{key, u32_from, u64_from};

/// Which Dahua structure a packed timestamp was read from.
///
/// Kept explicit because the confidence attached to the decoding differs per structure,
/// and because provenance should name the structure, not just the offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimestampStructure {
    /// The `date` field of a DHAV frame header.
    DhavFrameHeader,
    /// The start-time field of a block-table entry.
    BlockTableStart,
    /// The end-time field of a block-table entry.
    BlockTableEnd,
    /// The timestamp field of a DHII frame-index entry.
    DhiiFrameIndexEntry,
}

impl TimestampStructure {
    /// Stable label for provenance strings and reports.
    pub fn label(&self) -> &'static str {
        match self {
            Self::DhavFrameHeader => "DHAV frame header date field",
            Self::BlockTableStart => "block table entry start time",
            Self::BlockTableEnd => "block table entry end time",
            Self::DhiiFrameIndexEntry => "DHII frame index entry timestamp",
        }
    }

    /// Whether the packed encoding for this structure is corroborated independently.
    ///
    /// The DHAV header encoding is; the others reuse it because the field widths and base
    /// year match, which is a reasonable but not independently corroborated reading.
    pub fn encoding_is_corroborated(&self) -> bool {
        matches!(self, Self::DhavFrameHeader)
    }
}

/// How well established a decoded timestamp is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimestampConfidence {
    /// The field decoded to a calendar-valid instant using an encoding corroborated for
    /// this structure.
    Decoded,
    /// The field decoded to a calendar-valid instant, but the packed encoding is being
    /// reused from another structure rather than independently corroborated for this one.
    DecodedProvisionalEncoding,
    /// The field is all-zero. In these structures that is the absence of a timestamp, not
    /// midnight on the base year, so no instant is reported.
    Absent,
    /// The field decoded to digits that are not a valid calendar instant (month 0, day 31
    /// of February, hour 30, ...). The raw value is retained; no instant is reported.
    Implausible { reason: String },
}

impl TimestampConfidence {
    /// Whether an absolute instant was established.
    pub fn is_decoded(&self) -> bool {
        matches!(
            self,
            TimestampConfidence::Decoded | TimestampConfidence::DecodedProvisionalEncoding
        )
    }
}

/// One decoded Dahua timestamp, with the raw field and the reasoning retained.
///
/// The raw packed value is always preserved so an examiner can re-derive the decoding
/// independently, and so a value this platform could not interpret is still reportable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DahuaTimestamp {
    /// The packed field exactly as read from disk.
    pub raw: u32,
    /// Which structure it came from.
    pub structure: TimestampStructure,
    /// Absolute time as unix seconds, reading the recorder's digits as UTC. `None` when
    /// the field was absent or implausible.
    pub unix_seconds: Option<i64>,
    /// The recorder's own wall-clock digits, `YYYY-MM-DDTHH:MM:SS`, with no zone suffix
    /// because no zone was established. `None` when the field was absent or implausible.
    pub recorder_wall_clock: Option<String>,
    /// How well established the decoding is.
    pub confidence: TimestampConfidence,
    /// Exactly how this value was decoded, for the evidence layer to show verbatim.
    pub evidence: String,
}

impl DahuaTimestamp {
    /// Decode a packed field read from `structure`, using the profile-declared bit layout.
    pub fn decode(raw: u32, structure: TimestampStructure, profile: &OemProfile) -> Self {
        let base_year = u64_from(profile, key::TS_BASE_YEAR, 2000) as i32;
        let f = |shift_key: &str, mask_key: &str, shift_default: u64, mask_default: u64| -> u32 {
            let shift = u64_from(profile, shift_key, shift_default).min(31) as u32;
            let mask = u32_from(profile, mask_key, mask_default as u32);
            (raw >> shift) & mask
        };

        // An all-zero field is the absence of a value in every Dahua structure this
        // platform has read. Decoding it would report "2000-00-00T00:00:00", which is not
        // a time and would put a fabricated instant on an examiner's timeline.
        if raw == 0 {
            return Self {
                raw,
                structure,
                unix_seconds: None,
                recorder_wall_clock: None,
                confidence: TimestampConfidence::Absent,
                evidence: format!(
                    "{} is all-zero; recorded as absent rather than decoded to the base year",
                    structure.label()
                ),
            };
        }

        let second = f(key::TS_SECOND_SHIFT, key::TS_SECOND_MASK, 0, 63);
        let minute = f(key::TS_MINUTE_SHIFT, key::TS_MINUTE_MASK, 6, 63);
        let hour = f(key::TS_HOUR_SHIFT, key::TS_HOUR_MASK, 12, 31);
        let day = f(key::TS_DAY_SHIFT, key::TS_DAY_MASK, 17, 31);
        let month = f(key::TS_MONTH_SHIFT, key::TS_MONTH_MASK, 22, 15);
        let year_field = f(key::TS_YEAR_SHIFT, key::TS_YEAR_MASK, 26, 63);
        let year = base_year.saturating_add(year_field as i32);

        let decode_note = format!(
            "{} raw 0x{raw:08X} unpacked as year={year} (base {base_year} + {year_field}), \
             month={month}, day={day}, hour={hour}, minute={minute}, second={second}",
            structure.label()
        );

        // Calendar validation. `from_ymd_opt`/`and_hms_opt` reject month 0, day 0, day 31
        // in a 30-day month, February 30, hour 24, minute 60 and second 60, so an
        // implausible field can never become a plausible-looking instant.
        let naive = NaiveDate::from_ymd_opt(year, month, day)
            .and_then(|d| d.and_hms_opt(hour, minute, second));

        match naive {
            Some(dt) => {
                let confidence = if structure.encoding_is_corroborated() {
                    TimestampConfidence::Decoded
                } else {
                    TimestampConfidence::DecodedProvisionalEncoding
                };
                let qualifier = if structure.encoding_is_corroborated() {
                    "packed encoding corroborated for this structure"
                } else {
                    "packed encoding reused from the DHAV frame header; not independently \
                     corroborated for this structure"
                };
                Self {
                    raw,
                    structure,
                    unix_seconds: Some(Utc.from_utc_datetime(&dt).timestamp()),
                    recorder_wall_clock: Some(dt.format("%Y-%m-%dT%H:%M:%S").to_string()),
                    confidence,
                    evidence: format!(
                        "{decode_note}; read as UTC because no recorder timezone offset was \
                         established from evidence ({qualifier})"
                    ),
                }
            }
            None => {
                let reason = format!(
                    "unpacked digits are not a valid calendar instant: {year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}"
                );
                Self {
                    raw,
                    structure,
                    unix_seconds: None,
                    recorder_wall_clock: None,
                    confidence: TimestampConfidence::Implausible {
                        reason: reason.clone(),
                    },
                    evidence: format!("{decode_note}; rejected: {reason}"),
                }
            }
        }
    }

    /// Whether an absolute instant was established.
    pub fn is_decoded(&self) -> bool {
        self.confidence.is_decoded()
    }
}

/// Encode wall-clock digits into the packed representation.
///
/// Present so fixture builders and round-trip tests produce genuinely format-correct
/// bytes instead of hand-written constants. Returns `None` for digits the encoding cannot
/// represent, so a fixture can never claim to encode a time it does not.
pub fn pack(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    base_year: i32,
) -> Option<u32> {
    let year_field = year.checked_sub(base_year)?;
    if !(0..=63).contains(&year_field)
        || !(1..=15).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 31
        || minute > 63
        || second > 63
    {
        return None;
    }
    Some(
        ((year_field as u32) << 26)
            | (month << 22)
            | (day << 17)
            | (hour << 12)
            | (minute << 6)
            | second,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::tests_support::dahua_profile;

    #[test]
    fn a_known_instant_round_trips_through_the_packed_encoding() {
        let p = dahua_profile();
        let raw = pack(2026, 9, 22, 14, 35, 7, 2000).expect("representable");
        let ts = DahuaTimestamp::decode(raw, TimestampStructure::DhavFrameHeader, &p);
        assert_eq!(
            ts.recorder_wall_clock.as_deref(),
            Some("2026-09-22T14:35:07")
        );
        assert_eq!(ts.confidence, TimestampConfidence::Decoded);
        // Read as UTC: no offset was established, so none is applied.
        let expected = Utc
            .with_ymd_and_hms(2026, 9, 22, 14, 35, 7)
            .single()
            .unwrap()
            .timestamp();
        assert_eq!(ts.unix_seconds, Some(expected));
        assert_eq!(ts.raw, raw);
    }

    #[test]
    fn no_investigator_timezone_is_applied_during_parsing() {
        let p = dahua_profile();
        let raw = pack(2026, 1, 2, 3, 4, 5, 2000).unwrap();
        let ts = DahuaTimestamp::decode(raw, TimestampStructure::DhavFrameHeader, &p);
        let utc = Utc
            .with_ymd_and_hms(2026, 1, 2, 3, 4, 5)
            .single()
            .unwrap()
            .timestamp();
        assert_eq!(
            ts.unix_seconds,
            Some(utc),
            "a +05:30 (or any) offset must not be baked in at parse time"
        );
        assert!(
            ts.evidence
                .contains("no recorder timezone offset was established"),
            "the absence of a zone must be stated: {}",
            ts.evidence
        );
    }

    #[test]
    fn base_year_is_2000_not_1970() {
        let p = dahua_profile();
        // year_field 0 => 2000.
        let raw = pack(2000, 1, 1, 0, 0, 1, 2000).unwrap();
        let ts = DahuaTimestamp::decode(raw, TimestampStructure::DhavFrameHeader, &p);
        assert!(ts
            .recorder_wall_clock
            .as_deref()
            .unwrap()
            .starts_with("2000-01-01"));
    }

    #[test]
    fn an_all_zero_field_is_absent_not_the_base_year() {
        let p = dahua_profile();
        let ts = DahuaTimestamp::decode(0, TimestampStructure::BlockTableStart, &p);
        assert_eq!(ts.confidence, TimestampConfidence::Absent);
        assert!(ts.unix_seconds.is_none());
        assert!(ts.recorder_wall_clock.is_none());
        assert_eq!(ts.raw, 0, "the raw field is still reported");
    }

    #[test]
    fn calendar_invalid_digits_are_implausible_not_clamped() {
        let p = dahua_profile();
        // month = 0 is not a month. Build it directly since `pack` refuses to.
        let raw = (26u32 << 26) | (5 << 17) | (10 << 12);
        let ts = DahuaTimestamp::decode(raw, TimestampStructure::DhavFrameHeader, &p);
        assert!(matches!(
            ts.confidence,
            TimestampConfidence::Implausible { .. }
        ));
        assert!(ts.unix_seconds.is_none(), "no instant may be reported");
        assert_eq!(ts.raw, raw);
    }

    #[test]
    fn february_thirtieth_is_rejected() {
        let p = dahua_profile();
        let raw = (25u32 << 26) | (2 << 22) | (30 << 17);
        let ts = DahuaTimestamp::decode(raw, TimestampStructure::DhavFrameHeader, &p);
        assert!(!ts.is_decoded(), "2025-02-30 is not an instant");
    }

    #[test]
    fn hour_and_second_overflow_are_rejected() {
        let p = dahua_profile();
        // The hour field is 5 bits so it can hold 30, which is not an hour.
        let raw = (26u32 << 26) | (6 << 22) | (1 << 17) | (30 << 12);
        assert!(!DahuaTimestamp::decode(raw, TimestampStructure::DhavFrameHeader, &p).is_decoded());
        // The second field is 6 bits so it can hold 61.
        let raw = (26u32 << 26) | (6 << 22) | (1 << 17) | (1 << 12) | 61;
        assert!(!DahuaTimestamp::decode(raw, TimestampStructure::DhavFrameHeader, &p).is_decoded());
    }

    #[test]
    fn block_table_and_dhii_report_a_provisional_encoding() {
        let p = dahua_profile();
        let raw = pack(2026, 3, 4, 5, 6, 7, 2000).unwrap();
        for structure in [
            TimestampStructure::BlockTableStart,
            TimestampStructure::BlockTableEnd,
            TimestampStructure::DhiiFrameIndexEntry,
        ] {
            let ts = DahuaTimestamp::decode(raw, structure, &p);
            assert_eq!(
                ts.confidence,
                TimestampConfidence::DecodedProvisionalEncoding,
                "{} must not claim a corroborated encoding",
                structure.label()
            );
            assert!(ts.is_decoded());
            assert!(ts.evidence.contains("not independently corroborated"));
        }
    }

    #[test]
    fn pack_refuses_unrepresentable_digits() {
        assert!(
            pack(1999, 1, 1, 0, 0, 0, 2000).is_none(),
            "before base year"
        );
        assert!(
            pack(2100, 1, 1, 0, 0, 0, 2000).is_none(),
            "year field overflow"
        );
        assert!(pack(2026, 0, 1, 0, 0, 0, 2000).is_none(), "month 0");
        assert!(pack(2026, 1, 0, 0, 0, 0, 2000).is_none(), "day 0");
        assert!(pack(2026, 1, 1, 32, 0, 0, 2000).is_none(), "hour overflow");
    }

    #[test]
    fn the_evidence_string_names_the_structure_and_the_raw_value() {
        let p = dahua_profile();
        let raw = pack(2026, 9, 22, 1, 2, 3, 2000).unwrap();
        let ts = DahuaTimestamp::decode(raw, TimestampStructure::BlockTableEnd, &p);
        assert!(ts.evidence.contains("block table entry end time"));
        assert!(ts.evidence.contains(&format!("0x{raw:08X}")));
    }
}
