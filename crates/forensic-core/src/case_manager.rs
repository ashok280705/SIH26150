//! # Case Manager Service and Acquisition Verification
//!
//! Provides the core `CaseManager` handling case creation, evidence registration with
//! strict field validation (naming missing fields), acquisition verification, ingest hashing,
//! source safety inspection, and chain-of-custody recording (Req 7.1–7.9, 1.9, 1.11, 23.1–23.4).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::acquisition::{Acquisition, AcquisitionStatus};
use crate::case::{Case, Evidence, ImageFormat, SourceState};
use crate::chain_of_custody::{CustodyAction, CustodyEvent, CustodyLog};
use crate::error::ForensicError;
use crate::hash::Hash;
use crate::identifiers::{AcquisitionId, CaseId, EvidenceId, ExaminerId};
use crate::region::Region;
use crate::validation::ValidationState;

/// Input payload for registering a new piece of evidence into a case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRegistrationInput {
    pub source_device: String,
    pub acquisition_time: DateTime<Utc>,
    pub capacity: u64,
    pub image_format: ImageFormat,
    pub responsible_examiner: ExaminerId,
    pub acquisition_tool: Option<String>,
    pub acquisition_tool_version: Option<String>,
    pub path: String,
    /// Acquisition metadata (if available from imaging receipt).
    pub acquisition_status: Option<AcquisitionStatus>,
    pub map_reference: Option<String>,
    pub map_hash: Option<Hash>,
    pub bad_sector_ranges: Vec<Region>,
    pub unresolved_ranges: Vec<Region>,
    pub source_state: Option<SourceState>,
}

impl EvidenceRegistrationInput {
    /// Strict required-field validation that explicitly names any missing field (Req 7.4).
    pub fn validate(&self) -> Result<(), ForensicError> {
        if self.source_device.trim().is_empty() {
            return Err(ForensicError::corrupt(
                "evidence_registration",
                "missing required field: 'source_device'",
            ));
        }
        if self.responsible_examiner.0.trim().is_empty() {
            return Err(ForensicError::corrupt(
                "evidence_registration",
                "missing required field: 'responsible_examiner'",
            ));
        }
        if self.path.trim().is_empty() {
            return Err(ForensicError::corrupt(
                "evidence_registration",
                "missing required field: 'path'",
            ));
        }
        Ok(())
    }
}

/// In-memory / core CaseManager service managing cases, evidence, and custody tracking.
#[derive(Debug, Default)]
pub struct CaseManager {
    cases: HashMap<CaseId, Case>,
    evidence_store: HashMap<EvidenceId, Evidence>,
    acquisitions: HashMap<AcquisitionId, Acquisition>,
    custody_logs: HashMap<CaseId, CustodyLog>,
}

impl CaseManager {
    /// Create a new empty case manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create and store a new forensic case.
    pub fn create_case(
        &mut self,
        name: impl Into<String>,
        description: impl Into<String>,
        examiner: ExaminerId,
    ) -> Result<Case, ForensicError> {
        let name_str = name.into();
        if name_str.trim().is_empty() {
            return Err(ForensicError::corrupt(
                "create_case",
                "missing required field: 'name'",
            ));
        }

        let case = Case::new(name_str, description, examiner.clone());
        let case_id = case.id;

        self.cases.insert(case_id, case.clone());
        let mut log = CustodyLog::new();
        log.append(CustodyEvent::new(
            examiner,
            CustodyAction::Ingest,
            format!("case '{}' created", case.name),
            case_id,
        ));
        self.custody_logs.insert(case_id, log);

        Ok(case)
    }

    /// Register a piece of evidence within a case, verifying required fields, recording
    /// the acquisition status honestly, and logging to chain of custody.
    pub fn register_evidence(
        &mut self,
        case_id: CaseId,
        input: EvidenceRegistrationInput,
        ingest_hash: Hash,
    ) -> Result<(Evidence, Option<Acquisition>), ForensicError> {
        // Validate required fields explicitly (Req 7.4).
        input.validate()?;

        if !self.cases.contains_key(&case_id) {
            return Err(ForensicError::corrupt(
                "register_evidence",
                format!("case '{}' not found", case_id),
            ));
        }

        let evidence_id = EvidenceId::new();

        // Check acquisition completeness honestly (Req 7.8, 7.9, 23.4).
        let status = input
            .acquisition_status
            .unwrap_or(AcquisitionStatus::Unknown);
        let has_gaps = !input.bad_sector_ranges.is_empty() || !input.unresolved_ranges.is_empty();

        let honest_status = if has_gaps && status == AcquisitionStatus::Complete {
            AcquisitionStatus::Partial
        } else {
            status
        };

        let acq_val_state = if honest_status == AcquisitionStatus::Complete {
            ValidationState::pass(
                "acquisition reported complete without gaps",
                "ingest_verification",
                &input.path,
            )
            .map_err(|e| ForensicError::corrupt("register_evidence", format!("{e}")))?
        } else if honest_status == AcquisitionStatus::Partial {
            ValidationState::review(
                "acquisition contains bad sectors or unresolved gaps",
                "ingest_verification",
                &input.path,
            )
            .map_err(|e| ForensicError::corrupt("register_evidence", format!("{e}")))?
        } else {
            ValidationState::not_run("ingest_verification", &input.path)
        };

        let mut acquisition = Acquisition::new(evidence_id, honest_status, acq_val_state)
            .with_bad_sectors(input.bad_sector_ranges)
            .with_unresolved(input.unresolved_ranges);

        if let (Some(tool), ver) = (
            input.acquisition_tool.clone(),
            input.acquisition_tool_version.clone(),
        ) {
            acquisition = acquisition.with_tool(tool, ver);
        }

        if let Some(map_ref) = input.map_reference {
            acquisition = acquisition.with_map(map_ref, input.map_hash);
        }

        let acq_id = acquisition.id;
        self.acquisitions.insert(acq_id, acquisition.clone());

        let mut evidence = Evidence::new(
            case_id,
            input.source_device,
            input.acquisition_time,
            input.capacity,
            input.image_format,
            input.responsible_examiner.clone(),
            input.path,
        );
        evidence.id = evidence_id;
        evidence.acquisition_tool = input.acquisition_tool;
        evidence.acquisition_tool_version = input.acquisition_tool_version;
        evidence.source_state = input.source_state.unwrap_or(SourceState::Unknown);
        evidence.acquisition_id = Some(acq_id);

        self.evidence_store.insert(evidence_id, evidence.clone());

        // Log ingest to Chain of Custody.
        if let Some(log) = self.custody_logs.get_mut(&case_id) {
            log.append(CustodyEvent::new(
                input.responsible_examiner,
                CustodyAction::Ingest,
                format!(
                    "evidence '{}' registered with ingest hash {}",
                    evidence.source_device, ingest_hash
                ),
                case_id,
            ));
        }

        Ok((evidence, Some(acquisition)))
    }

    /// Retrieve a case by ID.
    pub fn get_case(&self, case_id: &CaseId) -> Option<&Case> {
        self.cases.get(case_id)
    }

    /// Retrieve evidence by ID.
    pub fn get_evidence(&self, evidence_id: &EvidenceId) -> Option<&Evidence> {
        self.evidence_store.get(evidence_id)
    }

    /// Retrieve custody log for a case.
    pub fn get_custody_log(&self, case_id: &CaseId) -> Option<&CustodyLog> {
        self.custody_logs.get(case_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_creation_and_evidence_registration() {
        let mut manager = CaseManager::new();
        let examiner = ExaminerId::new("examiner-1");
        let case = manager
            .create_case("Homicide 2026", "DVR seized at scene", examiner.clone())
            .unwrap();

        let input = EvidenceRegistrationInput {
            source_device: "Hikvision DS-7204HGHI".into(),
            acquisition_time: Utc::now(),
            capacity: 1_000_000_000_000,
            image_format: ImageFormat::Raw,
            responsible_examiner: examiner,
            acquisition_tool: Some("dd".into()),
            acquisition_tool_version: Some("8.32".into()),
            path: "/cases/01/disk.raw".into(),
            acquisition_status: Some(AcquisitionStatus::Complete),
            map_reference: None,
            map_hash: None,
            bad_sector_ranges: vec![],
            unresolved_ranges: vec![],
            source_state: Some(SourceState::ReadOnly),
        };

        let dummy_hash = Hash::sha256(vec![0xAA; 32]);
        let (ev, acq) = manager
            .register_evidence(case.id, input, dummy_hash)
            .unwrap();

        assert_eq!(ev.case_id, case.id);
        assert_eq!(acq.unwrap().status, AcquisitionStatus::Complete);

        let log = manager.get_custody_log(&case.id).unwrap();
        assert_eq!(log.len(), 2); // create_case + register_evidence
    }

    #[test]
    fn missing_required_field_is_rejected_with_field_name() {
        let mut manager = CaseManager::new();
        let case = manager
            .create_case("Test", "", ExaminerId::new("ex"))
            .unwrap();

        let input = EvidenceRegistrationInput {
            source_device: "".into(), // Missing!
            acquisition_time: Utc::now(),
            capacity: 100,
            image_format: ImageFormat::Raw,
            responsible_examiner: ExaminerId::new("ex"),
            acquisition_tool: None,
            acquisition_tool_version: None,
            path: "/path".into(),
            acquisition_status: None,
            map_reference: None,
            map_hash: None,
            bad_sector_ranges: vec![],
            unresolved_ranges: vec![],
            source_state: None,
        };

        let dummy_hash = Hash::sha256(vec![0; 32]);
        let err = manager
            .register_evidence(case.id, input, dummy_hash)
            .unwrap_err();
        assert!(format!("{err}").contains("source_device"));
    }

    #[test]
    fn incomplete_acquisition_never_complete() {
        let mut manager = CaseManager::new();
        let case = manager
            .create_case("Test", "", ExaminerId::new("ex"))
            .unwrap();

        let input = EvidenceRegistrationInput {
            source_device: "Dahua".into(),
            acquisition_time: Utc::now(),
            capacity: 100,
            image_format: ImageFormat::Raw,
            responsible_examiner: ExaminerId::new("ex"),
            acquisition_tool: None,
            acquisition_tool_version: None,
            path: "/path".into(),
            acquisition_status: Some(AcquisitionStatus::Complete),
            map_reference: None,
            map_hash: None,
            bad_sector_ranges: vec![Region::new(100, 50).unwrap()], // Has bad sectors!
            unresolved_ranges: vec![],
            source_state: None,
        };

        let dummy_hash = Hash::sha256(vec![0; 32]);
        let (_, acq) = manager
            .register_evidence(case.id, input, dummy_hash)
            .unwrap();
        // Incomplete acquisition must be downgraded from Complete to Partial (Req 7.9, 23.4)
        assert_eq!(acq.unwrap().status, AcquisitionStatus::Partial);
    }
}
