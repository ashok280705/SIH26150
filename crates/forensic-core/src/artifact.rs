//! # Artifact Model — Native vs Derived
//!
//! `Artifact { Native(NativeArtifact), Derived(DerivedArtifact) }` — native artifacts are
//! never silently replaced by derived copies. Both are retained and independently queryable
//! (Req 5.8, 5.9).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::hash::Hash;
use crate::identifiers::{ArtifactId, EvidenceId};
use crate::provenance::Provenance;
use crate::region::Region;

/// The kind of derived artifact.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivedKind {
    /// An elementary stream extracted from a recording.
    ElementaryStream,
    /// A remuxed container (e.g. raw H.264 → MP4).
    Remux,
    /// A review copy for playback.
    ReviewCopy,
    /// AI-generated output (Phase 7).
    AiOutput,
    /// Other derived artifact type.
    Other(String),
}

/// A native artifact — data as it exists in the original evidence, with no transformation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NativeArtifact {
    /// Unique artifact identifier.
    pub id: ArtifactId,
    /// The evidence this artifact belongs to.
    pub evidence_id: EvidenceId,
    /// The byte region in the evidence source.
    pub region: Region,
    /// Hash of the artifact's bytes.
    pub hash: Hash,
    /// Description of the native artifact (e.g. "recording #3 header + data").
    pub description: String,
    /// When this artifact was identified.
    pub identified_at: DateTime<Utc>,
}

/// A derived artifact — produced by transforming native evidence data.
///
/// Carries its own `Provenance` and transformation history. Never inherits the native
/// artifact's identity — the native artifact remains present and unchanged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DerivedArtifact {
    /// Unique artifact identifier (distinct from any native artifact ID).
    pub id: ArtifactId,
    /// What kind of derived artifact this is.
    pub kind: DerivedKind,
    /// Complete provenance chain for this derived artifact.
    pub provenance: Provenance,
    /// Path where the derived artifact is stored (outside the evidence directory).
    pub output_path: String,
    /// Description of the derived artifact.
    pub description: String,
    /// When this artifact was produced.
    pub produced_at: DateTime<Utc>,
}

/// An artifact is either native (as found in evidence) or derived (produced by transformation).
///
/// Both variants coexist for the same source region — producing a derived artifact NEVER
/// replaces or invalidates the native artifact (Req 5.9).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Artifact {
    /// Data as it exists in the original evidence.
    Native(NativeArtifact),
    /// Data produced by transforming evidence.
    Derived(DerivedArtifact),
}

impl Artifact {
    /// Get the artifact ID regardless of variant.
    pub fn id(&self) -> ArtifactId {
        match self {
            Self::Native(a) => a.id,
            Self::Derived(a) => a.id,
        }
    }

    /// Whether this is a native artifact.
    pub fn is_native(&self) -> bool {
        matches!(self, Self::Native(_))
    }

    /// Whether this is a derived artifact.
    pub fn is_derived(&self) -> bool {
        matches!(self, Self::Derived(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Hash;
    use crate::provenance::{Provenance, SourceRegion};
    use crate::validation::ValidationState;

    fn sample_native() -> NativeArtifact {
        NativeArtifact {
            id: ArtifactId::new(),
            evidence_id: EvidenceId::new(),
            region: Region::new(0, 1024).unwrap(),
            hash: Hash::sha256(vec![0xaa; 32]),
            description: "recording header".into(),
            identified_at: Utc::now(),
        }
    }

    fn sample_derived(evidence_id: EvidenceId) -> DerivedArtifact {
        let vs = ValidationState::pass("decode OK", "reconstruction", "artifact").unwrap();
        let prov = Provenance::new(
            evidence_id,
            Hash::sha256(vec![0xaa; 32]),
            vec![SourceRegion::new(
                evidence_id,
                Region::new(0, 1024).unwrap(),
            )],
            "recovery-engine",
            "0.1.0",
            Hash::sha256(vec![0xbb; 32]),
            vs,
        );
        DerivedArtifact {
            id: ArtifactId::new(),
            kind: DerivedKind::Remux,
            provenance: prov,
            output_path: "/artifacts/recording_3.mp4".into(),
            description: "remuxed recording #3".into(),
            produced_at: Utc::now(),
        }
    }

    #[test]
    fn artifact_serde_roundtrip() {
        let native = Artifact::Native(sample_native());
        let json = serde_json::to_string(&native).unwrap();
        let back: Artifact = serde_json::from_str(&json).unwrap();
        assert_eq!(native, back);
        assert!(back.is_native());
    }

    #[test]
    fn derived_artifact_serde_roundtrip() {
        let ev_id = EvidenceId::new();
        let derived = Artifact::Derived(sample_derived(ev_id));
        let json = serde_json::to_string(&derived).unwrap();
        let back: Artifact = serde_json::from_str(&json).unwrap();
        assert_eq!(derived, back);
        assert!(back.is_derived());
    }

    #[test]
    fn native_and_derived_coexist() {
        // Producing a derived artifact leaves the native artifact intact.
        let native = sample_native();
        let evidence_id = native.evidence_id;
        let native_hash = native.hash.clone();
        let native_id = native.id;

        let derived = sample_derived(evidence_id);

        // Both exist as separate artifacts.
        assert_ne!(native_id, derived.id);
        // Native artifact's hash is unchanged.
        assert_eq!(native.hash, native_hash);
    }

    #[test]
    fn derived_has_own_provenance() {
        let ev_id = EvidenceId::new();
        let derived = sample_derived(ev_id);
        assert_eq!(derived.provenance.source_evidence_id, ev_id);
        assert!(!derived.provenance.producing_component.is_empty());
    }
}
