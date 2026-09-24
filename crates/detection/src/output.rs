//! # DetectorOutput Model and DetectionStatus
//!
//! Output produced by storage structure detectors (Req 2.6, 2.7, 9.2, 9.3).
//!
//! Key invariants:
//! - A Detector cannot claim an OEM: `DetectorOutput` deliberately has NO `attribution_status`, NO `confidence`, and NO `classification` field (Req 2.6, 9.3).
//! - Detection_Status, Classification, and Attribution_Status are distinct concepts and never interchangeable (Req 2.7).

use serde::{Deserialize, Serialize};

use forensic_core::{EvidenceItem, Hash, Region};

/// Preliminary status assigned by an individual detector based purely on its observed indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionStatus {
    /// Indicators were observed matching profile expectations.
    Confirmed,
    /// Partial or conflicting indicators observed.
    Ambiguous,
    /// Insufficient structural indicators observed (e.g. lone magic).
    Insufficient,
    /// No matching indicators observed for this OEM format.
    NotDetected,
}

impl std::fmt::Display for DetectionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Confirmed => write!(f, "confirmed"),
            Self::Ambiguous => write!(f, "ambiguous"),
            Self::Insufficient => write!(f, "insufficient"),
            Self::NotDetected => write!(f, "not_detected"),
        }
    }
}

/// Output data structure returned by a storage detector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectorOutput {
    /// The OEM identifier (e.g. "dahua", "hikvision", "honeywell", "cpplus_ubs", "uniview").
    pub oem_key: String,
    /// Storage filesystem family (e.g. "DHFS", "HIKVISION_FS", "MAXPRO_NVR", "CPPLUS_UBS", "UNIVIEW_UBIFS").
    pub storage_family: String,
    /// Detector's preliminary indicator status.
    pub status: DetectionStatus,
    /// Observed structural evidence items.
    pub evidence: Vec<EvidenceItem>,
    /// Discovered candidate storage regions (e.g. partitions or segment boundaries).
    pub candidate_regions: Vec<Region>,
    /// Any warnings or non-fatal anomalies observed.
    pub warnings: Vec<String>,
    /// Profile version used during detection.
    pub profile_version: String,
    /// Profile hash used during detection.
    pub profile_hash: Hash,
}

impl DetectorOutput {
    /// Create a new DetectorOutput.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        oem_key: impl Into<String>,
        storage_family: impl Into<String>,
        status: DetectionStatus,
        evidence: Vec<EvidenceItem>,
        candidate_regions: Vec<Region>,
        warnings: Vec<String>,
        profile_version: impl Into<String>,
        profile_hash: Hash,
    ) -> Self {
        Self {
            oem_key: oem_key.into(),
            storage_family: storage_family.into(),
            status,
            evidence,
            candidate_regions,
            warnings,
            profile_version: profile_version.into(),
            profile_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip() {
        let output = DetectorOutput {
            oem_key: "dahua".into(),
            storage_family: "DHFS".into(),
            status: DetectionStatus::Confirmed,
            evidence: vec![],
            candidate_regions: vec![Region::new(0, 512).unwrap()],
            warnings: vec!["provisional rule evaluated".into()],
            profile_version: "1.0.0".into(),
            profile_hash: Hash::sha256(vec![0xAA; 32]),
        };

        let json = serde_json::to_string(&output).unwrap();
        let back: DetectorOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(output, back);
    }
}
