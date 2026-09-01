//! # Forensic Identifiers
//!
//! Newtype wrappers for domain identifiers: `CaseId`, `EvidenceId`, `ExaminerId`,
//! `ProfileId`, `AcquisitionId`, `ArtifactId`. All are serde-serializable and
//! `Display`-able for logging and reports.
//!
//! Using newtypes instead of raw `Uuid`/`String` prevents accidental interchange
//! (e.g. passing a CaseId where an EvidenceId is expected).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a forensic case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CaseId(pub Uuid);

impl CaseId {
    /// Generate a new random CaseId.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for CaseId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for CaseId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "case-{}", self.0)
    }
}

/// Unique identifier for a piece of evidence (disk image, physical device, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EvidenceId(pub Uuid);

impl EvidenceId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for EvidenceId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for EvidenceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "evidence-{}", self.0)
    }
}

/// Identifier for the examiner (human or automated agent) performing an action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExaminerId(pub String);

impl ExaminerId {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

impl std::fmt::Display for ExaminerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Identifier for an OEM profile (e.g. "dahua-xvr-v1.2").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProfileId(pub String);

impl ProfileId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for ProfileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for an acquisition record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AcquisitionId(pub Uuid);

impl AcquisitionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for AcquisitionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for AcquisitionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "acq-{}", self.0)
    }
}

/// Unique identifier for an artifact (native or derived).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArtifactId(pub Uuid);

impl ArtifactId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ArtifactId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ArtifactId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "artifact-{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_id_serde_roundtrip() {
        let id = CaseId::new();
        let json = serde_json::to_string(&id).unwrap();
        let back: CaseId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn evidence_id_serde_roundtrip() {
        let id = EvidenceId::new();
        let json = serde_json::to_string(&id).unwrap();
        let back: EvidenceId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn examiner_id_serde_roundtrip() {
        let id = ExaminerId::new("Det. Jane Doe");
        let json = serde_json::to_string(&id).unwrap();
        let back: ExaminerId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn profile_id_serde_roundtrip() {
        let id = ProfileId::new("dahua-xvr-v1.2");
        let json = serde_json::to_string(&id).unwrap();
        let back: ProfileId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn acquisition_id_serde_roundtrip() {
        let id = AcquisitionId::new();
        let json = serde_json::to_string(&id).unwrap();
        let back: AcquisitionId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn artifact_id_serde_roundtrip() {
        let id = ArtifactId::new();
        let json = serde_json::to_string(&id).unwrap();
        let back: ArtifactId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn display_formats_are_prefixed() {
        let case = CaseId::new();
        assert!(case.to_string().starts_with("case-"));
        let ev = EvidenceId::new();
        assert!(ev.to_string().starts_with("evidence-"));
        let acq = AcquisitionId::new();
        assert!(acq.to_string().starts_with("acq-"));
        let art = ArtifactId::new();
        assert!(art.to_string().starts_with("artifact-"));
    }

    #[test]
    fn newtypes_are_distinct() {
        // This test exists to document that CaseId and EvidenceId are different types.
        // A function expecting CaseId will reject EvidenceId at compile time.
        fn takes_case(_: CaseId) {}
        fn takes_evidence(_: EvidenceId) {}
        takes_case(CaseId::new());
        takes_evidence(EvidenceId::new());
    }
}
