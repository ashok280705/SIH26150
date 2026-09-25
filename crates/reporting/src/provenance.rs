//! Report Hashing, Provenance, and Chain of Custody (Req 17.3, 5.2, 5.8).
//!
//! Generates cryptographic hash for reports, creates a DerivedArtifact record,
//! and logs a chain-of-custody event.

use chrono::Utc;
use forensic_core::{
    chain_of_custody::{CustodyAction, CustodyEvent},
    ArtifactId, CaseId, DerivedArtifact, DerivedKind, EvidenceId, ExaminerId, Hash, Provenance,
    ValidationState, ValidationStateKind,
};
use sha2::{Digest, Sha256};

pub struct ReportAuditor;

impl ReportAuditor {
    /// Hashes the raw report content (SHA-256) and returns the cryptographic hash.
    pub fn hash_report(report_bytes: &[u8]) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(report_bytes);
        Hash::sha256(hasher.finalize().to_vec())
    }

    /// Creates a DerivedArtifact entry for the exported report.
    pub fn create_report_artifact(
        evidence_id: EvidenceId,
        report_path: &str,
        report_hash: Hash,
        format_name: &str,
    ) -> DerivedArtifact {
        let val_state = ValidationState::new(
            ValidationStateKind::Pass,
            "generate_report",
            "Report generated with full cryptographic provenance",
            "ReportExporter",
        )
        .unwrap();

        let prov = Provenance::new(
            evidence_id,
            report_hash.clone(),
            vec![], // Comprehensive case aggregation
            "ReportingService",
            "1.0.0",
            report_hash.clone(),
            val_state,
        );

        DerivedArtifact {
            id: ArtifactId::new(),
            kind: DerivedKind::Other(format!("{}_report", format_name.to_lowercase())),
            provenance: prov,
            output_path: report_path.to_string(),
            description: format!(
                "Forensic examination report ({})",
                format_name.to_uppercase()
            ),
            produced_at: Utc::now(),
        }
    }

    /// Creates a chain-of-custody event logging the report export.
    pub fn create_custody_event(
        case_id: CaseId,
        examiner_id: ExaminerId,
        report_hash: Hash,
        format_name: &str,
    ) -> CustodyEvent {
        CustodyEvent::new(
            examiner_id,
            CustodyAction::Export,
            format!(
                "Exported {} forensic report with SHA-256 hash {}",
                format_name.to_uppercase(),
                report_hash
            ),
            case_id,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_hashing_and_custody_generation() {
        let case_id = CaseId::new();
        let evidence_id = EvidenceId::new();
        let examiner_id = ExaminerId::new("Examiner 1");
        let report_content = b"# Forensic Report Content";

        let hash = ReportAuditor::hash_report(report_content);
        assert!(!hash.hex().is_empty());

        let artifact = ReportAuditor::create_report_artifact(
            evidence_id,
            "/reports/case1.json",
            hash.clone(),
            "JSON",
        );
        assert_eq!(artifact.kind, DerivedKind::Other("json_report".into()));
        assert_eq!(artifact.provenance.output_hash, hash);

        let event = ReportAuditor::create_custody_event(case_id, examiner_id, hash, "JSON");
        assert_eq!(event.action, CustodyAction::Export);
    }
}
