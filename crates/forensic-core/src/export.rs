//! # Export Provenance and Hashing Hooks
//!
//! Manages creation of exported forensic artifacts (both native extractions and derived review copies/remuxes)
//! ensuring complete SHA-256 hashing, provenance attachment, and chain-of-custody logging (Req 5.2, 5.4, 5.8, 5.9).
//!
//! Key invariants:
//! - Every derived artifact resolves to source evidence, regions, component+version, profile version, and output hash (Property 10).
//! - Producing a derived export never replaces or invalidates the native artifact (Req 5.9).

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::artifact::{Artifact, DerivedArtifact, DerivedKind, NativeArtifact};
use crate::chain_of_custody::{CustodyAction, CustodyEvent, CustodyLog};
use crate::error::ForensicError;
use crate::hash::Hash;
use crate::identifiers::{ArtifactId, CaseId, EvidenceId, ExaminerId};
use crate::provenance::{Provenance, SourceRegion, TransformationStep};
use crate::region::Region;
use crate::validation::ValidationState;

/// Export request descriptor for a native or derived forensic artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRequest {
    pub case_id: CaseId,
    pub evidence_id: EvidenceId,
    pub source_regions: Vec<SourceRegion>,
    pub source_hash: Hash,
    pub output_path: String,
    pub description: String,
    pub is_derived: bool,
    pub derived_kind: Option<DerivedKind>,
    pub component_name: String,
    pub component_version: String,
    pub profile_version: Option<String>,
    pub profile_hash: Option<Hash>,
    pub transformation_steps: Vec<TransformationStep>,
    pub validation_state: ValidationState,
}

/// The result of an export operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRecord {
    pub artifact: Artifact,
    pub hash: Hash,
    pub custody_event: CustodyEvent,
}

/// Finalize an export: wrap artifact into `Native` or `Derived`, stamp SHA-256 hash and provenance,
/// and append an export event to the chain of custody.
pub fn finalize_export(
    request: ExportRequest,
    output_hash: Hash,
    examiner: ExaminerId,
    custody_log: &mut CustodyLog,
) -> Result<ExportRecord, ForensicError> {
    let artifact_id = ArtifactId::new();

    let artifact = if request.is_derived {
        let mut provenance = Provenance::new(
            request.evidence_id,
            request.source_hash,
            request.source_regions,
            request.component_name,
            request.component_version,
            output_hash.clone(),
            request.validation_state,
        );

        if let (Some(ver), Some(h)) = (request.profile_version, request.profile_hash) {
            provenance = provenance.with_profile(ver, h);
        }

        for step in request.transformation_steps {
            provenance.add_transformation(step);
        }

        Artifact::Derived(DerivedArtifact {
            id: artifact_id,
            kind: request
                .derived_kind
                .unwrap_or(DerivedKind::Other("export".into())),
            provenance,
            output_path: request.output_path.clone(),
            description: request.description,
            produced_at: Utc::now(),
        })
    } else {
        let primary_region = request
            .source_regions
            .first()
            .map(|sr| sr.region)
            .unwrap_or_else(|| Region::point(0));

        Artifact::Native(NativeArtifact {
            id: artifact_id,
            evidence_id: request.evidence_id,
            region: primary_region,
            hash: output_hash.clone(),
            description: request.description,
            identified_at: Utc::now(),
        })
    };

    let event = CustodyEvent::new(
        examiner,
        CustodyAction::Export,
        format!(
            "exported {} artifact '{}' with hash {}",
            if request.is_derived {
                "derived"
            } else {
                "native"
            },
            request.output_path,
            output_hash
        ),
        request.case_id,
    )
    .with_artifact(artifact_id);

    custody_log.append(event.clone());

    Ok(ExportRecord {
        artifact,
        hash: output_hash,
        custody_event: event,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finalize_derived_export_creates_lineage_and_custody() {
        let mut log = CustodyLog::new();
        let case_id = CaseId::new();
        let ev_id = EvidenceId::new();
        let examiner = ExaminerId::new("analyst");

        let request = ExportRequest {
            case_id,
            evidence_id: ev_id,
            source_regions: vec![SourceRegion::new(ev_id, Region::new(0, 1024).unwrap())],
            source_hash: Hash::sha256(vec![0x11; 32]),
            output_path: "/exports/clip.mp4".into(),
            description: "extracted video clip".into(),
            is_derived: true,
            derived_kind: Some(DerivedKind::Remux),
            component_name: "video-reconstruction".into(),
            component_version: "0.1.0".into(),
            profile_version: Some("dahua-1.0".into()),
            profile_hash: Some(Hash::sha256(vec![0x22; 32])),
            transformation_steps: vec![],
            validation_state: ValidationState::pass("h264 stream intact", "export", "clip.mp4")
                .unwrap(),
        };

        let output_hash = Hash::sha256(vec![0x33; 32]);
        let record = finalize_export(request, output_hash, examiner, &mut log).unwrap();

        assert!(record.artifact.is_derived());
        assert_eq!(log.len(), 1);
        assert_eq!(log.events()[0].action, CustodyAction::Export);
    }
}
