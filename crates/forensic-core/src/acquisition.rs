//! # Acquisition Model and AcquisitionStatus
//!
//! `Acquisition` with `AcquisitionStatus { Complete, Partial, Failed, Unknown }`, tool
//! details, acquisition map/receipt, bad-sector ranges, and verification state
//! (Req 7.7–7.9, 23.1–23.4).
//!
//! Key invariants:
//! - An incomplete acquisition is NEVER labeled `Complete` (Req 7.9, 23.4).
//! - Where acquisition information is unavailable, status is `Unknown` — completeness
//!   is never fabricated (Req 7.8).
//! - Bad-sector and unresolved ranges are recorded as structured regions (queryable).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::hash::Hash;
use crate::identifiers::{AcquisitionId, EvidenceId};
use crate::region::Region;
use crate::validation::ValidationState;

/// The status of an acquisition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionStatus {
    /// The acquisition completed successfully with no known gaps.
    Complete,
    /// The acquisition completed but has known gaps or unresolved ranges.
    Partial,
    /// The acquisition failed.
    Failed,
    /// The acquisition status could not be determined.
    Unknown,
}

impl Default for AcquisitionStatus {
    /// Defaults to `Unknown` — completeness is never fabricated (Req 7.8).
    fn default() -> Self {
        Self::Unknown
    }
}

impl std::fmt::Display for AcquisitionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Complete => write!(f, "complete"),
            Self::Partial => write!(f, "partial"),
            Self::Failed => write!(f, "failed"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// An acquisition record documenting how evidence was acquired from the source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Acquisition {
    /// Unique acquisition identifier.
    pub id: AcquisitionId,
    /// The evidence this acquisition belongs to.
    pub evidence_id: EvidenceId,
    /// Status of the acquisition.
    pub status: AcquisitionStatus,
    /// The tool used for acquisition.
    pub tool: Option<String>,
    /// Version of the acquisition tool.
    pub tool_version: Option<String>,
    /// Reference to the acquisition map/receipt (path or identifier).
    pub map_reference: Option<String>,
    /// Hash of the acquisition map/receipt.
    pub map_hash: Option<Hash>,
    /// Bad-sector ranges as structured, queryable regions.
    pub bad_sector_ranges: Vec<Region>,
    /// Unresolved ranges as structured, queryable regions.
    pub unresolved_ranges: Vec<Region>,
    /// Verification state of the acquisition.
    pub verification: ValidationState,
    /// When this acquisition record was created.
    pub created_at: DateTime<Utc>,
}

impl Acquisition {
    /// Create a new acquisition record.
    ///
    /// # Invariant enforcement
    /// If `bad_sector_ranges` or `unresolved_ranges` are non-empty, the status MUST NOT
    /// be `Complete`. This constructor enforces that invariant.
    pub fn new(
        evidence_id: EvidenceId,
        status: AcquisitionStatus,
        verification: ValidationState,
    ) -> Self {
        Self {
            id: AcquisitionId::new(),
            evidence_id,
            status,
            tool: None,
            tool_version: None,
            map_reference: None,
            map_hash: None,
            bad_sector_ranges: Vec::new(),
            unresolved_ranges: Vec::new(),
            verification,
            created_at: Utc::now(),
        }
    }

    /// Add bad-sector ranges. If any are added, the status cannot be `Complete`.
    pub fn with_bad_sectors(mut self, ranges: Vec<Region>) -> Self {
        if !ranges.is_empty() && self.status == AcquisitionStatus::Complete {
            // Enforce invariant: an acquisition with bad sectors is not complete (Req 7.9).
            self.status = AcquisitionStatus::Partial;
        }
        self.bad_sector_ranges = ranges;
        self
    }

    /// Add unresolved ranges. If any are added, the status cannot be `Complete`.
    pub fn with_unresolved(mut self, ranges: Vec<Region>) -> Self {
        if !ranges.is_empty() && self.status == AcquisitionStatus::Complete {
            // Enforce invariant: an acquisition with unresolved ranges is not complete.
            self.status = AcquisitionStatus::Partial;
        }
        self.unresolved_ranges = ranges;
        self
    }

    /// Set tool information.
    pub fn with_tool(
        mut self,
        tool: impl Into<String>,
        version: Option<impl Into<String>>,
    ) -> Self {
        self.tool = Some(tool.into());
        self.tool_version = version.map(|v| v.into());
        self
    }

    /// Set the acquisition map/receipt reference and compute its hash.
    pub fn with_map(
        mut self,
        reference: impl Into<String>,
        hash: Option<Hash>,
    ) -> Self {
        self.map_reference = Some(reference.into());
        self.map_hash = hash;
        self
    }

    /// Whether this acquisition has any known gaps.
    pub fn has_gaps(&self) -> bool {
        !self.bad_sector_ranges.is_empty() || !self.unresolved_ranges.is_empty()
    }

    /// Validate the invariant: an acquisition with gaps cannot be `Complete`.
    pub fn is_invariant_satisfied(&self) -> bool {
        if self.has_gaps() {
            self.status != AcquisitionStatus::Complete
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::ValidationState;

    fn unknown_verification() -> ValidationState {
        ValidationState::not_run("acquisition_verification", "test")
    }

    #[test]
    fn four_statuses_serde() {
        let statuses = [
            AcquisitionStatus::Complete,
            AcquisitionStatus::Partial,
            AcquisitionStatus::Failed,
            AcquisitionStatus::Unknown,
        ];
        for status in &statuses {
            let json = serde_json::to_string(status).unwrap();
            let back: AcquisitionStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, &back);
        }
    }

    #[test]
    fn default_status_is_unknown() {
        assert_eq!(AcquisitionStatus::default(), AcquisitionStatus::Unknown);
    }

    #[test]
    fn incomplete_acquisition_rejected_from_complete() {
        let ev_id = EvidenceId::new();
        let acq = Acquisition::new(ev_id, AcquisitionStatus::Complete, unknown_verification())
            .with_bad_sectors(vec![Region::new(1000, 512).unwrap()]);

        // The constructor should have downgraded to Partial.
        assert_eq!(acq.status, AcquisitionStatus::Partial);
        assert!(acq.is_invariant_satisfied());
    }

    #[test]
    fn unresolved_ranges_prevent_complete() {
        let ev_id = EvidenceId::new();
        let acq = Acquisition::new(ev_id, AcquisitionStatus::Complete, unknown_verification())
            .with_unresolved(vec![Region::new(5000, 1024).unwrap()]);

        assert_eq!(acq.status, AcquisitionStatus::Partial);
        assert!(acq.is_invariant_satisfied());
    }

    #[test]
    fn complete_without_gaps_is_valid() {
        let ev_id = EvidenceId::new();
        let acq = Acquisition::new(
            ev_id,
            AcquisitionStatus::Complete,
            ValidationState::pass("verified", "acq_check", "ev-1").unwrap(),
        );
        assert_eq!(acq.status, AcquisitionStatus::Complete);
        assert!(!acq.has_gaps());
        assert!(acq.is_invariant_satisfied());
    }

    #[test]
    fn unknown_info_yields_unknown_not_complete() {
        let ev_id = EvidenceId::new();
        let acq = Acquisition::new(ev_id, AcquisitionStatus::Unknown, unknown_verification());
        assert_eq!(acq.status, AcquisitionStatus::Unknown);
    }

    #[test]
    fn acquisition_serde_roundtrip() {
        let ev_id = EvidenceId::new();
        let acq = Acquisition::new(
            ev_id,
            AcquisitionStatus::Partial,
            ValidationState::review("partial data", "acq_verify", "ev-1").unwrap(),
        )
        .with_tool("dd", Some("8.32"))
        .with_bad_sectors(vec![Region::new(0, 512).unwrap()])
        .with_map("receipt.log", None);

        let json = serde_json::to_string(&acq).unwrap();
        let back: Acquisition = serde_json::from_str(&json).unwrap();
        assert_eq!(acq, back);
    }
}
