//! # Provenance and SourceRegion Model
//!
//! `Provenance` records the complete lineage of a derived artifact: which evidence bytes
//! produced it, which component + version processed it, which profile was applied, the
//! transformation history, and the output hash (Req 5.4, 5.8).
//!
//! `SourceRegion` is the structured representation of which bytes in the evidence source
//! contributed to an artifact — structured/queryable, not an opaque blob.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::hash::Hash;
use crate::identifiers::EvidenceId;
use crate::region::Region;
use crate::validation::ValidationState;

/// A structured source region recording which bytes in evidence contributed to an artifact.
///
/// Structured/queryable so an examiner can ask "what bytes X..Y of evidence E produced
/// this artifact" (not an opaque blob).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRegion {
    /// The evidence this region belongs to.
    pub evidence_id: EvidenceId,
    /// The byte range in the evidence source.
    pub region: Region,
    /// Optional description of what this region contains (e.g. "recording header",
    /// "video frame cluster", "index block").
    pub description: Option<String>,
}

impl SourceRegion {
    /// Create a new source region.
    pub fn new(evidence_id: EvidenceId, region: Region) -> Self {
        Self {
            evidence_id,
            region,
            description: None,
        }
    }

    /// Set an optional description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

/// A step in the transformation history of a derived artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransformationStep {
    /// What operation was performed (e.g. "extraction", "remux", "decode").
    pub operation: String,
    /// Which component performed the operation.
    pub component: String,
    /// Version of the component.
    pub component_version: String,
    /// When the operation was performed.
    pub performed_at: DateTime<Utc>,
    /// Optional notes about the transformation.
    pub notes: Option<String>,
}

/// Complete provenance for an artifact.
///
/// Records source evidence, hash, source regions, producing component + version,
/// OEM profile version + hash, parser version, recovery level, output hash,
/// ordered transformation history, and validation state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Provenance {
    /// The evidence source this artifact was derived from.
    pub source_evidence_id: EvidenceId,
    /// Hash of the source evidence at the time of derivation.
    pub source_hash: Hash,
    /// Which byte ranges in the source contributed to this artifact.
    pub source_regions: Vec<SourceRegion>,
    /// The component that produced this artifact (e.g. "parser-dahua", "recovery-engine").
    pub producing_component: String,
    /// Version of the producing component.
    pub component_version: String,
    /// OEM profile version applied during production.
    pub profile_version: Option<String>,
    /// Hash of the OEM profile applied.
    pub profile_hash: Option<Hash>,
    /// Parser version if a parser was involved.
    pub parser_version: Option<String>,
    /// Recovery level if recovery was involved (e.g. "L1", "L2", "L3").
    pub recovery_level: Option<String>,
    /// Hash of the output artifact.
    pub output_hash: Hash,
    /// Ordered transformation history (earliest first).
    pub transformation_history: Vec<TransformationStep>,
    /// Validation state of this provenance record.
    pub validation_state: ValidationState,
    /// When this provenance record was created.
    pub created_at: DateTime<Utc>,
}

impl Provenance {
    /// Create a new provenance record.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_evidence_id: EvidenceId,
        source_hash: Hash,
        source_regions: Vec<SourceRegion>,
        producing_component: impl Into<String>,
        component_version: impl Into<String>,
        output_hash: Hash,
        validation_state: ValidationState,
    ) -> Self {
        Self {
            source_evidence_id,
            source_hash,
            source_regions,
            producing_component: producing_component.into(),
            component_version: component_version.into(),
            profile_version: None,
            profile_hash: None,
            parser_version: None,
            recovery_level: None,
            output_hash,
            transformation_history: Vec::new(),
            validation_state,
            created_at: Utc::now(),
        }
    }

    /// Set the OEM profile information.
    pub fn with_profile(mut self, version: impl Into<String>, hash: Hash) -> Self {
        self.profile_version = Some(version.into());
        self.profile_hash = Some(hash);
        self
    }

    /// Add a transformation step to the history.
    pub fn add_transformation(&mut self, step: TransformationStep) {
        self.transformation_history.push(step);
    }

    /// Check that this provenance record has all required fields for a complete
    /// derivation chain (Property 10).
    pub fn is_complete(&self) -> bool {
        !self.source_regions.is_empty()
            && !self.producing_component.is_empty()
            && !self.component_version.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::ValidationStateKind;

    fn sample_provenance() -> Provenance {
        let ev_id = EvidenceId::new();
        let source_hash = Hash::sha256(vec![0xaa; 32]);
        let output_hash = Hash::sha256(vec![0xbb; 32]);
        let region = SourceRegion::new(ev_id, Region::new(0, 1024).unwrap());
        let vs = ValidationState::pass("hash verified", "provenance_check", "artifact-1").unwrap();

        Provenance::new(
            ev_id,
            source_hash,
            vec![region],
            "parser-dahua",
            "0.1.0",
            output_hash,
            vs,
        )
    }

    #[test]
    fn provenance_serde_roundtrip() {
        let prov = sample_provenance();
        let json = serde_json::to_string(&prov).unwrap();
        let back: Provenance = serde_json::from_str(&json).unwrap();
        assert_eq!(prov, back);
    }

    #[test]
    fn source_region_serde_roundtrip() {
        let ev_id = EvidenceId::new();
        let sr = SourceRegion::new(ev_id, Region::new(512, 2048).unwrap())
            .with_description("video cluster header");
        let json = serde_json::to_string(&sr).unwrap();
        let back: SourceRegion = serde_json::from_str(&json).unwrap();
        assert_eq!(sr, back);
    }

    #[test]
    fn completeness_check() {
        let prov = sample_provenance();
        assert!(prov.is_complete());
    }

    #[test]
    fn incomplete_without_regions() {
        let ev_id = EvidenceId::new();
        let vs = ValidationState::not_run("check", "x");
        let prov = Provenance::new(
            ev_id,
            Hash::sha256(vec![0; 32]),
            vec![], // no source regions
            "test",
            "0.1.0",
            Hash::sha256(vec![0; 32]),
            vs,
        );
        assert!(!prov.is_complete());
    }

    #[test]
    fn with_profile_sets_fields() {
        let prov = sample_provenance().with_profile("dahua-xvr-v1.2", Hash::sha256(vec![0xcc; 32]));
        assert_eq!(prov.profile_version.as_deref(), Some("dahua-xvr-v1.2"));
        assert!(prov.profile_hash.is_some());
    }

    #[test]
    fn transformation_history_ordering() {
        let mut prov = sample_provenance();
        prov.add_transformation(TransformationStep {
            operation: "extraction".into(),
            component: "parser".into(),
            component_version: "0.1.0".into(),
            performed_at: Utc::now(),
            notes: None,
        });
        prov.add_transformation(TransformationStep {
            operation: "remux".into(),
            component: "recovery".into(),
            component_version: "0.1.0".into(),
            performed_at: Utc::now(),
            notes: Some("remuxed to MP4".into()),
        });
        assert_eq!(prov.transformation_history.len(), 2);
        assert_eq!(prov.transformation_history[0].operation, "extraction");
        assert_eq!(prov.transformation_history[1].operation, "remux");
    }

    #[test]
    fn provenance_carries_validation_state() {
        let prov = sample_provenance();
        assert_eq!(prov.validation_state.state, ValidationStateKind::Pass);
        assert!(!prov.validation_state.reason.is_empty());
    }
}
