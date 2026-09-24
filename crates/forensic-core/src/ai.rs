//! # AI Finding Model (Req 16.2, 16.3, 16.4, 16.6, 5.9)
//!
//! Models representing AI-assisted analytics findings (e.g. motion, object detection, anomaly).
//!
//! Constraints:
//! - Every finding is explicitly labeled `AI-assisted` and NEVER presented as absolute truth (Req 16.3, 16.4).
//! - Stored as a `DerivedArtifact` that never replaces or alters native evidence (Req 16.6, 5.9).
//! - Findings NEVER feed back into OEM attribution or recovery classification (Req 16.6).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::identifiers::EvidenceId;
use crate::provenance::Provenance;
use crate::region::Region;

/// An AI-detected finding in a validated recording or video clip.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiFinding {
    pub id: String,
    pub evidence_id: EvidenceId,
    pub recording_id: String,
    pub channel: u32,
    pub timestamp: String,
    pub finding_type: String, // e.g. "PersonDetected", "VehicleDetected", "MotionAnomaly"
    pub confidence: f64,
    pub bounding_box: Option<BoundingBox>,
    pub source_region: Region,
    
    /// Mandatory AI-assisted label (Req 16.3).
    pub is_ai_assisted: bool,
    pub disclaimer: String,

    /// Complete cryptographic provenance of the derived AI finding.
    pub provenance: Provenance,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BoundingBox {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl AiFinding {
    // A plain data constructor: each argument is one required field of the finding.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_id: EvidenceId,
        recording_id: String,
        channel: u32,
        timestamp: String,
        finding_type: String,
        confidence: f64,
        bounding_box: Option<BoundingBox>,
        source_region: Region,
        provenance: Provenance,
    ) -> Self {
        Self {
            id: format!("ai-find-{}", uuid::Uuid::new_v4()),
            evidence_id,
            recording_id,
            channel,
            timestamp,
            finding_type,
            confidence,
            bounding_box,
            source_region,
            is_ai_assisted: true,
            disclaimer: "AI-assisted finding; probabilistic analysis only; not absolute truth".to_string(),
            provenance,
            created_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Hash;
    use crate::validation::ValidationState;

    #[test]
    fn test_ai_finding_is_always_labeled_ai_assisted() {
        let evidence_id = EvidenceId::new();
        let prov = Provenance::new(
            evidence_id,
            Hash::sha256(vec![0; 32]),
            vec![],
            "AiAnalyticsService",
            "1.0.0",
            Hash::sha256(vec![1; 32]),
            ValidationState::pass("ai_detect", "Detected motion", "AiFinding").unwrap(),
        );

        let finding = AiFinding::new(
            evidence_id,
            "rec-123".into(),
            1,
            "2026-09-01T12:00:00Z".into(),
            "PersonDetected".into(),
            0.88,
            Some(BoundingBox { x: 0.1, y: 0.2, width: 0.3, height: 0.4 }),
            Region { offset: 1024, length: 512 },
            prov,
        );

        assert!(finding.is_ai_assisted);
        assert!(finding.disclaimer.contains("AI-assisted finding"));
        assert!(finding.disclaimer.contains("not absolute truth"));
    }
}
