//! # Machine-Readable Validation Corpus Schema and Loader
//!
//! Implements the manifest loader and validation logic for regression fixtures in `validation_corpus/` (Req 19.10, 19.11).
//!
//! Key invariants:
//! - All synthetic test cases carry `synthetic: true` (Req 19.11).
//! - Incomplete cases missing any required expected field are rejected with an error.

use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use forensic_core::{ForensicError, Hash, Region};

/// A single validation corpus case definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusCase {
    pub case_id: String,
    pub source_path: String,
    pub source_hash: Hash,
    pub source_type: String,
    pub expected_detection: String,
    pub expected_detection_status: String,
    pub expected_classification: String,
    pub expected_attribution_status: String,
    pub expected_regions: Vec<Region>,
    pub expected_parser_state: String,
    pub expected_recovery_state: String,
    pub expected_validation_state: String,
    pub expected_warnings: Vec<String>,
    pub synthetic: bool,
}

impl CorpusCase {
    /// Strict validation ensuring no required expected field is blank.
    pub fn validate(&self) -> Result<(), ForensicError> {
        if self.case_id.trim().is_empty() {
            return Err(ForensicError::corrupt("corpus_validation", "missing case_id"));
        }
        if self.expected_detection.trim().is_empty() {
            return Err(ForensicError::corrupt("corpus_validation", "missing expected_detection"));
        }
        if self.expected_detection_status.trim().is_empty() {
            return Err(ForensicError::corrupt("corpus_validation", "missing expected_detection_status"));
        }
        if self.expected_classification.trim().is_empty() {
            return Err(ForensicError::corrupt("corpus_validation", "missing expected_classification"));
        }
        if self.expected_attribution_status.trim().is_empty() {
            return Err(ForensicError::corrupt("corpus_validation", "missing expected_attribution_status"));
        }
        if self.expected_parser_state.trim().is_empty() {
            return Err(ForensicError::corrupt("corpus_validation", "missing expected_parser_state"));
        }
        if self.expected_recovery_state.trim().is_empty() {
            return Err(ForensicError::corrupt("corpus_validation", "missing expected_recovery_state"));
        }
        if self.expected_validation_state.trim().is_empty() {
            return Err(ForensicError::corrupt("corpus_validation", "missing expected_validation_state"));
        }
        Ok(())
    }
}

/// Loader for reading and parsing all case manifests from a directory.
pub struct CorpusLoader;

impl CorpusLoader {
    /// Load and validate all `.json` manifests in the specified corpus directory.
    pub fn load_dir(dir: &Path) -> Result<Vec<CorpusCase>, ForensicError> {
        let mut cases = Vec::new();

        if !dir.exists() {
            return Ok(cases);
        }

        let entries = fs::read_dir(dir).map_err(|e| {
            ForensicError::io(format!("reading corpus dir {}", dir.display()), e)
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                ForensicError::io(format!("reading corpus entry in {}", dir.display()), e)
            })?;
            let path = entry.path();

            if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                let content = fs::read_to_string(&path).map_err(|e| {
                    ForensicError::io(format!("reading {}", path.display()), e)
                })?;

                let case: CorpusCase = serde_json::from_str(&content).map_err(|e| {
                    ForensicError::corrupt("corpus_loader", format!("invalid JSON in {}: {e}", path.display()))
                })?;

                case.validate()?;
                cases.push(case);
            }
        }

        // Deterministic sorting by case_id
        cases.sort_by(|a, b| a.case_id.cmp(&b.case_id));

        Ok(cases)
    }

    /// Save a case manifest to disk as pretty JSON.
    pub fn save_case(dir: &Path, case: &CorpusCase) -> Result<PathBuf, ForensicError> {
        case.validate()?;
        fs::create_dir_all(dir).map_err(|e| {
            ForensicError::io(format!("creating corpus dir {}", dir.display()), e)
        })?;

        let filename = format!("{}.json", case.case_id);
        let path = dir.join(filename);
        let json = serde_json::to_string_pretty(case).map_err(|e| {
            ForensicError::corrupt("save_case", format!("serializing case {}: {e}", case.case_id))
        })?;

        fs::write(&path, json).map_err(|e| {
            ForensicError::io(format!("writing case to {}", path.display()), e)
        })?;

        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_valid_case() -> CorpusCase {
        CorpusCase {
            case_id: "SYNTH-DAHUA-001".into(),
            source_path: "synthetic_dahua_normal_1.raw".into(),
            source_hash: Hash::sha256(vec![0xAA; 32]),
            source_type: "raw".into(),
            expected_detection: "dahua".into(),
            expected_detection_status: "confirmed".into(),
            expected_classification: "confirmed".into(),
            expected_attribution_status: "confirmed".into(),
            expected_regions: vec![Region::new(0, 512).unwrap()],
            expected_parser_state: "parse_success".into(),
            expected_recovery_state: "l1_carving_available".into(),
            expected_validation_state: "pass".into(),
            expected_warnings: vec![],
            synthetic: true,
        }
    }

    #[test]
    fn valid_manifest_roundtrip() {
        let temp_dir = std::env::temp_dir().join(format!("corpus_test_{}", uuid::Uuid::new_v4()));
        let case = sample_valid_case();

        let path = CorpusLoader::save_case(&temp_dir, &case).unwrap();
        assert!(path.exists());

        let loaded = CorpusLoader::load_dir(&temp_dir).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], case);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn incomplete_manifest_is_rejected() {
        let mut case = sample_valid_case();
        case.expected_detection = "".into(); // Empty!
        assert!(case.validate().is_err());
    }
}
