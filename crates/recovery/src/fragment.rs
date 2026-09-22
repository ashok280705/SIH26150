//! # Discovered video fragment
//!
//! A [`DiscoveredFragment`] is the physical-location-preserving record of one piece of
//! video the scanner found. It exists so a recovered candidate never degenerates into an
//! anonymous buffer: the exact evidence item, the exact physical range, the region it came
//! from, the OEM context, and how it was discovered all travel with it.
//!
//! ## Unknown stays unknown
//!
//! `camera_id`, `timestamp_unix` and `sequence_number` are [`FieldEvidence`], not bare
//! values. This phase populates them only from index evidence — a fragment carved from
//! unclaimed space genuinely has no camera or clock, and reporting it as camera 0 at the
//! epoch would be fabricated metadata. Deriving them from container headers inside the
//! fragment itself is deliberately left to the later fragment-association phase.

use forensic_core::{EvidenceId, Provenance, Region, ValidationState};
use serde::{Deserialize, Serialize};

/// A field that is either established from evidence or explicitly unknown.
///
/// This exists instead of a bare `Option` so serialized output and reports state the
/// difference between "no camera" and "camera unknown" without a reader having to guess.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FieldEvidence<T> {
    /// Read from evidence, with a note on where it came from.
    Known { value: T, source: String },
    /// Not established. `reason` explains why, so downstream layers can say so.
    Unknown { reason: String },
}

impl<T> FieldEvidence<T> {
    /// Construct a known value.
    pub fn known(value: T, source: impl Into<String>) -> Self {
        Self::Known {
            value,
            source: source.into(),
        }
    }

    /// Construct an explicitly unknown value.
    pub fn unknown(reason: impl Into<String>) -> Self {
        Self::Unknown {
            reason: reason.into(),
        }
    }

    /// The value, if established.
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Known { value, .. } => Some(value),
            Self::Unknown { .. } => None,
        }
    }

    /// Whether this field was established from evidence.
    pub fn is_known(&self) -> bool {
        matches!(self, Self::Known { .. })
    }
}

/// How a fragment was found. This is a provenance fact, not a confidence signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryMethod {
    /// Probed at a physical range an authoritative index entry claimed.
    IndexClaimedProbe,
    /// Found by scanning a physical range no index entry claimed, inside the region the
    /// authoritative index governs.
    UnclaimedScanInIndexScope,
    /// Found by scanning a range outside any authoritative index scope.
    UnclaimedScanOutsideIndexScope,
    /// Found by scanning with no index evidence available for this evidence item.
    WholeImageScanWithoutIndex,
}

impl DiscoveryMethod {
    /// Stable short label for logs, provenance strings and reports.
    pub fn label(&self) -> &'static str {
        match self {
            Self::IndexClaimedProbe => "index-claimed-probe",
            Self::UnclaimedScanInIndexScope => "unclaimed-scan-in-index-scope",
            Self::UnclaimedScanOutsideIndexScope => "unclaimed-scan-outside-index-scope",
            Self::WholeImageScanWithoutIndex => "whole-image-scan-without-index",
        }
    }
}

/// One piece of video located at an exact physical position in a specific evidence item.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiscoveredFragment {
    /// The evidence item these bytes came from. Propagated from the recovery request;
    /// never minted here.
    pub evidence_id: EvidenceId,
    /// Exact physical byte range in that evidence item, including container framing.
    pub physical_region: Region,
    /// Elementary-stream sub-range, when container framing could be separated. `None`
    /// when the payload boundary is not established.
    pub payload_region: Option<Region>,
    /// The planner region this fragment was found in — the claimed or unclaimed range
    /// that produced the read. Preserved so a fragment can be traced back to the range
    /// algebra that targeted it.
    pub originating_region: Region,
    /// OEM key the recovery ran under, and the profile id, for OEM context.
    pub oem_key: String,
    pub profile_id: String,
    /// How it was found.
    pub discovery_method: DiscoveryMethod,
    /// Codec as classified from the fragment's own bytes. Codec identity is a media fact
    /// and never implies OEM identity.
    pub codec: String,
    /// Camera/channel, only when index evidence supplied one.
    pub camera_id: FieldEvidence<u32>,
    /// Recording start as unix seconds, only when index evidence supplied one.
    pub timestamp_unix: FieldEvidence<i64>,
    /// Sequence number, only when evidence supplied one.
    pub sequence_number: FieldEvidence<u64>,
    /// Frame type, only when evidence supplied one.
    pub frame_type: FieldEvidence<String>,
    /// The validation outcome for these bytes. `Unknown` when no check ran — never
    /// `Pass` by default.
    pub validation: ValidationState,
    /// Full provenance chain back to the source evidence.
    pub provenance: Provenance,
}

impl DiscoveredFragment {
    /// Whether any recorder-derived metadata was established for this fragment.
    ///
    /// Useful for reporting: a fragment with no known camera and no known timestamp must
    /// not be placed on a timeline as camera 0 at time 0.
    pub fn has_recorder_metadata(&self) -> bool {
        self.camera_id.is_known() || self.timestamp_unix.is_known()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_fields_carry_a_reason_and_no_value() {
        let f: FieldEvidence<u32> = FieldEvidence::unknown("carved from unclaimed space");
        assert!(!f.is_known());
        assert!(f.value().is_none());
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("unknown"), "{json}");
        assert!(json.contains("carved from unclaimed space"), "{json}");
    }

    #[test]
    fn known_fields_record_where_they_came_from() {
        let f = FieldEvidence::known(3u32, "didx#4 channel field");
        assert_eq!(f.value(), Some(&3));
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("didx#4"), "{json}");
    }

    #[test]
    fn discovery_method_labels_are_distinct() {
        let labels = [
            DiscoveryMethod::IndexClaimedProbe.label(),
            DiscoveryMethod::UnclaimedScanInIndexScope.label(),
            DiscoveryMethod::UnclaimedScanOutsideIndexScope.label(),
            DiscoveryMethod::WholeImageScanWithoutIndex.label(),
        ];
        let unique: std::collections::BTreeSet<_> = labels.iter().collect();
        assert_eq!(unique.len(), labels.len());
    }
}
