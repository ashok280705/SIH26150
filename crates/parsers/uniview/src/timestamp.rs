//! # Uniview packed 5-byte timestamp
//!
//! Uniview SUPER, UI-DATA and DI structures store wall-clock time as a packed 5-byte field.
//! It is **not** unix time. The vendor bit layout (CONFIRMED):
//!
//! ```text
//!   year   = b0 | ((b1 & 0x0F) << 8)          12 bits, full year (e.g. 2024)
//!   month  = b1 >> 4                          4 bits
//!   day    = b2 & 0x1F                        5 bits
//!   hour   = ((b3 & 0x03) << 3) | (b2 >> 5)   5 bits
//!   minute = b3 >> 2                          6 bits
//!   second = b4 & 0x3F                        6 bits
//! ```
//!
//! The top two bits of `b4` are not part of the timestamp. In UI-DATA entries they carry the
//! low bits of the lock field (see [`crate::ui`]); they are ignored here.
//!
//! ## No timezone is applied
//!
//! The digits are the recorder's own wall clock. This decoder reports them verbatim and, for
//! the platform's unix-seconds fields, the instant those digits denote **read as UTC** — the
//! only reading that adds no unverified assumption. No offset is stored anywhere in the
//! Uniview structures, so none is ever claimed.

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

/// Raw format label used on `RawTimestamp`.
pub const RAW_FORMAT: &str = "UNIVIEW_PACKED_5BYTE";

/// How the unix-seconds value was derived.
pub const NORMALIZATION_METHOD: &str =
    "uniview_packed_wall_clock_read_as_utc; the Uniview structures record no timezone offset, \
     so none was applied at parse time";

/// Why a 5-byte field did or did not decode to a calendar instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampStatus {
    /// All five bytes are zero: the field was never written.
    Empty,
    /// The fields form a real calendar date and time.
    Valid,
    /// The fields form a real date and time, outside the profile's plausibility window.
    /// Reported, not dropped: a recorder clock may simply be wrong.
    Implausible,
    /// At least one field is out of range (month 13, day 31 in February, hour 27, ...).
    Invalid,
    /// Fewer than five bytes were available.
    Truncated,
}

/// A decoded Uniview timestamp, with its raw bytes kept verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnvTimestamp {
    /// Physical byte offset of the 5-byte field.
    pub field_offset: u64,
    /// The five raw bytes, exactly as read (fewer if truncated).
    pub raw: Vec<u8>,
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub status: TimestampStatus,
}

impl UnvTimestamp {
    /// Decode the packed timestamp from the first five bytes of `raw`.
    pub fn decode(raw: &[u8], field_offset: u64, min_year: u16, max_year: u16) -> Self {
        if raw.len() < 5 {
            return Self {
                field_offset,
                raw: raw.to_vec(),
                year: 0,
                month: 0,
                day: 0,
                hour: 0,
                minute: 0,
                second: 0,
                status: TimestampStatus::Truncated,
            };
        }
        let (b0, b1, b2, b3, b4) = (raw[0], raw[1], raw[2], raw[3], raw[4]);
        let year = u16::from(b0) | (u16::from(b1 & 0x0F) << 8);
        let month = b1 >> 4;
        let day = b2 & 0x1F;
        let hour = ((b3 & 0x03) << 3) | (b2 >> 5);
        let minute = b3 >> 2;
        let second = b4 & 0x3F;

        let status = if raw[..5].iter().all(|&b| b == 0) {
            TimestampStatus::Empty
        } else if calendar(year, month, day, hour, minute, second).is_none() {
            TimestampStatus::Invalid
        } else if year < min_year || year > max_year {
            TimestampStatus::Implausible
        } else {
            TimestampStatus::Valid
        };

        Self {
            field_offset,
            raw: raw[..5].to_vec(),
            year,
            month,
            day,
            hour,
            minute,
            second,
            status,
        }
    }

    /// Whether the fields denote a real calendar instant (valid or merely implausible).
    pub fn is_decoded(&self) -> bool {
        matches!(
            self.status,
            TimestampStatus::Valid | TimestampStatus::Implausible
        )
    }

    /// The raw five bytes as a little-endian integer, for `RawTimestamp::value`.
    pub fn raw_value(&self) -> u64 {
        self.raw
            .iter()
            .take(5)
            .enumerate()
            .fold(0u64, |acc, (i, b)| acc | (u64::from(*b) << (8 * i)))
    }

    /// The recorder's wall-clock digits, `YYYY-MM-DDTHH:MM:SS`, with no zone suffix.
    pub fn wall_clock(&self) -> Option<String> {
        self.is_decoded().then(|| {
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
                self.year, self.month, self.day, self.hour, self.minute, self.second
            )
        })
    }

    /// The wall-clock digits read as UTC, as unix seconds.
    pub fn unix_seconds_as_utc(&self) -> Option<i64> {
        if !self.is_decoded() {
            return None;
        }
        calendar(
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
        )
        .map(|dt| dt.and_utc().timestamp())
    }

    /// The wall-clock digits read as UTC, ISO-8601 with an explicit `Z`.
    pub fn iso_8601_as_utc(&self) -> Option<String> {
        self.wall_clock().map(|s| format!("{s}Z"))
    }

    /// Short label for descriptions.
    pub fn label(&self) -> String {
        match self.status {
            TimestampStatus::Empty => "empty".to_string(),
            TimestampStatus::Truncated => "truncated".to_string(),
            TimestampStatus::Invalid => format!("invalid (raw {})", hex::encode(&self.raw)),
            TimestampStatus::Valid => self.wall_clock().unwrap_or_default(),
            TimestampStatus::Implausible => {
                format!(
                    "{} (outside plausibility window)",
                    self.wall_clock().unwrap_or_default()
                )
            }
        }
    }
}

fn calendar(
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
) -> Option<chrono::NaiveDateTime> {
    NaiveDate::from_ymd_opt(i32::from(year), u32::from(month), u32::from(day))?.and_hms_opt(
        u32::from(hour),
        u32::from(minute),
        u32::from(second),
    )
}

/// Encode wall-clock fields into the packed 5-byte form. The exact inverse of
/// [`UnvTimestamp::decode`]; used by test builders and never on evidence.
pub fn encode(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> [u8; 5] {
    [
        (year & 0xFF) as u8,
        (((year >> 8) & 0x0F) as u8) | ((month & 0x0F) << 4),
        (day & 0x1F) | ((hour & 0x07) << 5),
        ((hour >> 3) & 0x03) | ((minute & 0x3F) << 2),
        second & 0x3F,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(raw: &[u8]) -> UnvTimestamp {
        UnvTimestamp::decode(raw, 0x14, 2000, 2100)
    }

    #[test]
    fn decodes_the_exact_vendor_bit_layout() {
        // 2024-03-15 13:45:30
        //   year 2024 = 0x7E8 -> b0 = 0xE8, b1 low nibble = 0x7
        //   month 3   -> b1 high nibble = 0x3            => b1 = 0x37
        //   day 15, hour 13 = 0b01101 -> b2 = 15 | (0b101 << 5) = 0xAF
        //   hour high bits 0b01, minute 45 -> b3 = 0b01 | (45 << 2) = 0xB5
        //   second 30 -> b4 = 0x1E
        let t = d(&[0xE8, 0x37, 0xAF, 0xB5, 0x1E]);
        assert_eq!(
            (t.year, t.month, t.day, t.hour, t.minute, t.second),
            (2024, 3, 15, 13, 45, 30)
        );
        assert_eq!(t.status, TimestampStatus::Valid);
        assert_eq!(t.wall_clock().as_deref(), Some("2024-03-15T13:45:30"));
        assert_eq!(t.unix_seconds_as_utc(), Some(1_710_510_330));
        assert_eq!(
            encode(2024, 3, 15, 13, 45, 30),
            [0xE8, 0x37, 0xAF, 0xB5, 0x1E]
        );
    }

    #[test]
    fn every_field_boundary_round_trips() {
        for &(y, mo, da, h, mi, s) in &[
            (2000u16, 1u8, 1u8, 0u8, 0u8, 0u8),
            (2099, 12, 31, 23, 59, 59),
            (2024, 2, 29, 7, 8, 9),
            (4095, 12, 31, 23, 59, 59),
        ] {
            let t = d(&encode(y, mo, da, h, mi, s));
            assert_eq!(
                (t.year, t.month, t.day, t.hour, t.minute, t.second),
                (y, mo, da, h, mi, s)
            );
            assert!(t.is_decoded());
        }
        assert_eq!(
            d(&encode(4095, 12, 31, 23, 59, 59)).status,
            TimestampStatus::Implausible
        );
    }

    #[test]
    fn the_top_bits_of_byte_four_are_not_part_of_the_time() {
        let mut raw = encode(2024, 3, 15, 13, 45, 30);
        raw[4] |= 0xC0;
        let t = d(&raw);
        assert_eq!(t.second, 30);
        assert_eq!(t.status, TimestampStatus::Valid);
    }

    #[test]
    fn malformed_values_are_reported_not_coerced() {
        assert_eq!(d(&[0; 5]).status, TimestampStatus::Empty);
        assert_eq!(d(&[0xE8, 0x37]).status, TimestampStatus::Truncated);
        assert_eq!(
            d(&encode(2024, 13, 1, 0, 0, 0)).status,
            TimestampStatus::Invalid
        );
        assert_eq!(
            d(&encode(2023, 2, 29, 0, 0, 0)).status,
            TimestampStatus::Invalid
        );
        assert_eq!(
            d(&encode(2024, 1, 1, 24, 0, 0)).status,
            TimestampStatus::Invalid
        );
        assert_eq!(
            d(&encode(2024, 1, 1, 0, 60, 0)).status,
            TimestampStatus::Invalid
        );
        assert_eq!(
            d(&encode(2024, 1, 1, 0, 0, 60)).status,
            TimestampStatus::Invalid
        );
        assert_eq!(
            d(&encode(2024, 1, 0, 0, 0, 0)).status,
            TimestampStatus::Invalid
        );
        let bad = d(&[0xFF; 5]);
        assert_eq!(bad.status, TimestampStatus::Invalid);
        assert_eq!(bad.unix_seconds_as_utc(), None, "no instant is invented");
        assert_eq!(bad.wall_clock(), None);
    }

    #[test]
    fn raw_value_preserves_all_five_bytes() {
        let t = d(&[1, 2, 3, 4, 5]);
        assert_eq!(t.raw_value(), 0x05_04_03_02_01);
        assert_eq!(t.field_offset, 0x14);
    }
}
