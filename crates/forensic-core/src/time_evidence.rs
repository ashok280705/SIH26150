//! # Time Evidence Models
//!
//! Models representing timestamps extracted from DVR/NVR filesystems.
//!
//! To satisfy evidentiary requirements (Req 4.1–4.7, 24.2), this module maintains strict separation
//! between raw, recorder-native, normalized, and reference times. No field ever overwrites another.
//!
//! Impossible timestamps are handled as invalid states rather than causing panics.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::provenance::Provenance;

/// An examiner-established timezone assertion for an evidence source.
///
/// FORENSIC INTEGRITY: This assertion represents an external, documented claim
/// (e.g. DVR configuration sheet, site logs, or investigator verification).
/// It does NOT alter or mutate the disk-derived `TimeZoneState::Unknown` fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExaminerTimezone {
    /// The established timezone identifier or UTC offset (e.g. "Asia/Kolkata", "+05:30", "UTC-04:00").
    pub timezone: String,
    /// Basis or documentation source (e.g. "DVR on-screen setup menu documentation", "Dispatch room log").
    pub source: String,
    /// Who established this assertion.
    pub established_by: String,
    /// Optional justification or investigative notes.
    #[serde(default)]
    pub notes: Option<String>,
    /// When this assertion was recorded.
    pub established_at: DateTime<Utc>,
}

/// The raw bytes or primitive integer exactly as found on disk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawTimestamp {
    pub value: u64,
    pub format: String,
    pub source: Provenance,
}

/// The timestamp interpreted in the recorder's native format before normalization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecorderNativeTime {
    pub iso_8601: String,
}

/// A normalized UTC timestamp.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NormalizedTime {
    pub iso_8601: String,
    pub method: String,
}

/// A reference timestamp from an external trusted source (e.g. NTP, photo).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReferenceTime {
    pub iso_8601: String,
    pub source: String,
}

/// Time zone state to prevent silent assumptions of UTC (Req 4.6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TimeZoneState {
    Known(String),
    Unknown,
}

/// A calculated correction applied to a native time (Req 4.7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClockCorrection {
    pub method: String,
    pub anchor_evidence: Provenance,
    pub offset_seconds: i64,
    pub drift_rate: Option<f64>,
    pub residual_seconds: Option<f64>,
}

/// The comprehensive time evidence record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimeEvidence {
    pub raw: RawTimestamp,
    pub recorder_native: Option<RecorderNativeTime>,
    pub normalized: Option<NormalizedTime>,
    pub reference: Option<ReferenceTime>,
    pub timezone: TimeZoneState,
    pub correction: Option<ClockCorrection>,
}

impl TimeEvidence {
    /// Create a new TimeEvidence starting from raw data, with unknown timezone.
    pub fn new(raw_value: u64, format: &str, source: Provenance) -> Self {
        Self {
            raw: RawTimestamp {
                value: raw_value,
                format: format.to_string(),
                source,
            },
            recorder_native: None,
            normalized: None,
            reference: None,
            timezone: TimeZoneState::Unknown,
            correction: None,
        }
    }
}
