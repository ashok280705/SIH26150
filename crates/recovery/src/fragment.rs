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

use std::collections::BTreeMap;

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
    /// Probed at a physical range that surviving OEM metadata describes, but which the
    /// recorder no longer reaches — the *available* case.
    ///
    /// Distinct from [`Self::UnclaimedScanInIndexScope`] because the recorder's own metadata
    /// supplied the channel and timestamps here, whereas an unreferenced gap supplies neither.
    AvailableMetadataProbe,
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
            Self::AvailableMetadataProbe => "available-metadata-probe",
            Self::UnclaimedScanInIndexScope => "unclaimed-scan-in-index-scope",
            Self::UnclaimedScanOutsideIndexScope => "unclaimed-scan-outside-index-scope",
            Self::WholeImageScanWithoutIndex => "whole-image-scan-without-index",
        }
    }

    /// Whether OEM metadata, rather than a blind sweep, put us on these bytes.
    pub fn is_metadata_driven(&self) -> bool {
        matches!(self, Self::IndexClaimedProbe | Self::AvailableMetadataProbe)
    }
}

/// How the fragment's own bytes were structurally established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FragmentFraming {
    /// The OEM parser walked its own container framing and reported this exact record, so the
    /// fragment's physical bounds are the record's declared bounds.
    OemContainerRecord,
    /// No container record was established; the fragment covers the bytes the scanner read and
    /// its bounds are the scan window's, not a record's.
    ScanWindow,
}

impl FragmentFraming {
    pub fn label(&self) -> &'static str {
        match self {
            Self::OemContainerRecord => "oem-container-record",
            Self::ScanWindow => "scan-window",
        }
    }
}

/// One piece of video located at an exact physical position in a specific evidence item.
///
/// This is the platform's **single** normalized fragment model. [`VideoFragment`] is an alias
/// for it, so there is one structure rather than a production type and a parallel test type
/// that can drift apart.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiscoveredFragment {
    /// The evidence item these bytes came from. Propagated from the recovery request;
    /// never minted here.
    pub evidence_id: EvidenceId,
    /// Stable identifier for this fragment, derived deterministically from the evidence id and
    /// the exact physical range it covers.
    ///
    /// Deterministic by construction: the same bytes in the same evidence item always produce
    /// the same id, across runs and across representations. Nothing downstream needs to mint a
    /// new identifier when converting a fragment into another form, which is what previously
    /// broke the provenance chain.
    pub fragment_id: String,
    /// Exact physical byte range in that evidence item, including container framing.
    pub physical_region: Region,
    /// Elementary-stream sub-range, when container framing could be separated. `None`
    /// when the payload boundary is not established.
    pub payload_region: Option<Region>,
    /// Whether the physical bounds are an OEM container record's or a scan window's.
    pub framing: FragmentFraming,
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
    /// The OEM storage partition these bytes live in, when the OEM's structures are
    /// partitioned and supplied one.
    pub partition: FieldEvidence<u32>,
    /// Camera/channel, only when evidence supplied one.
    pub camera_id: FieldEvidence<u32>,
    /// Recording start as unix seconds, only when evidence supplied one.
    pub timestamp_unix: FieldEvidence<i64>,
    /// Recording end as unix seconds, only when evidence supplied one.
    pub end_timestamp_unix: FieldEvidence<i64>,
    /// Sequence number, only when evidence supplied one.
    pub sequence_number: FieldEvidence<u64>,
    /// Frame type, only when evidence supplied one.
    pub frame_type: FieldEvidence<String>,
    /// The parent recording or chain this fragment belongs to, when OEM metadata established
    /// one. This is what lets several fragments be reassembled into one recording.
    pub parent_recording: FieldEvidence<String>,
    /// OEM-specific facts about this fragment, verbatim, so nothing OEM-specific is lost on the
    /// way through the generic layer.
    #[serde(default)]
    pub oem_metadata: BTreeMap<String, String>,
    /// The validation outcome for these bytes. `Unknown` when no check ran — never
    /// `Pass` by default.
    pub validation: ValidationState,
    /// How strongly the fragment is established, and on what basis.
    ///
    /// [`FieldEvidence`] rather than a bare float so "we did not compute a confidence" cannot
    /// be read as "confidence zero".
    pub confidence: FieldEvidence<f64>,
    /// Full provenance chain back to the source evidence.
    pub provenance: Provenance,
}

/// The platform's canonical normalized fragment.
///
/// An alias rather than a second structure: there is exactly one fragment model, and both names
/// refer to it.
pub type VideoFragment = DiscoveredFragment;

impl DiscoveredFragment {
    /// Derive the stable fragment id for an evidence item and a physical range.
    ///
    /// Deterministic and collision-resistant: a SHA-256 over the evidence id and the exact
    /// range, truncated for readability. Two runs over the same evidence produce identical ids,
    /// which is what makes a fragment traceable across representations.
    pub fn derive_id(evidence_id: EvidenceId, region: Region) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"video-fragment:v1:");
        h.update(evidence_id.0.as_bytes());
        h.update(region.offset.to_le_bytes());
        h.update(region.length.to_le_bytes());
        let digest = h.finalize();
        format!("frag-{}", hex::encode(&digest[..12]))
    }

    /// Whether any recorder-derived metadata was established for this fragment.
    ///
    /// Useful for reporting: a fragment with no known camera and no known timestamp must
    /// not be placed on a timeline as camera 0 at time 0.
    pub fn has_recorder_metadata(&self) -> bool {
        self.camera_id.is_known() || self.timestamp_unix.is_known()
    }

    /// Whether this fragment's id matches its own evidence id and physical range.
    ///
    /// Used by tests and by the export layer to confirm an id was preserved rather than
    /// regenerated from different inputs.
    pub fn id_is_consistent(&self) -> bool {
        self.fragment_id == Self::derive_id(self.evidence_id, self.physical_region)
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
            DiscoveryMethod::AvailableMetadataProbe.label(),
            DiscoveryMethod::UnclaimedScanInIndexScope.label(),
            DiscoveryMethod::UnclaimedScanOutsideIndexScope.label(),
            DiscoveryMethod::WholeImageScanWithoutIndex.label(),
        ];
        let unique: std::collections::BTreeSet<_> = labels.iter().collect();
        assert_eq!(unique.len(), labels.len());
    }

    #[test]
    fn metadata_driven_discovery_is_distinguished_from_a_blind_sweep() {
        assert!(DiscoveryMethod::IndexClaimedProbe.is_metadata_driven());
        assert!(DiscoveryMethod::AvailableMetadataProbe.is_metadata_driven());
        assert!(!DiscoveryMethod::UnclaimedScanInIndexScope.is_metadata_driven());
        assert!(!DiscoveryMethod::WholeImageScanWithoutIndex.is_metadata_driven());
    }

    #[test]
    fn fragment_ids_are_deterministic_and_range_specific() {
        let ev = EvidenceId::new();
        let a = Region::new(0x1000, 0x200).unwrap();
        let b = Region::new(0x1000, 0x201).unwrap();
        let c = Region::new(0x1001, 0x200).unwrap();

        assert_eq!(
            DiscoveredFragment::derive_id(ev, a),
            DiscoveredFragment::derive_id(ev, a),
            "the same inputs must always give the same id"
        );
        assert_ne!(
            DiscoveredFragment::derive_id(ev, a),
            DiscoveredFragment::derive_id(ev, b),
            "a different length is a different fragment"
        );
        assert_ne!(
            DiscoveredFragment::derive_id(ev, a),
            DiscoveredFragment::derive_id(ev, c),
            "a different offset is a different fragment"
        );
        assert_ne!(
            DiscoveredFragment::derive_id(ev, a),
            DiscoveredFragment::derive_id(EvidenceId::new(), a),
            "the same range in a different evidence item is a different fragment"
        );
        assert!(DiscoveredFragment::derive_id(ev, a).starts_with("frag-"));
    }

    #[test]
    fn framing_labels_distinguish_a_record_from_a_window() {
        assert_ne!(
            FragmentFraming::OemContainerRecord.label(),
            FragmentFraming::ScanWindow.label()
        );
    }
}
