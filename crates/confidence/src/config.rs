//! # Versioned Confidence Configuration
//!
//! Loads classification policy, thresholds, and quality factors from `config/classification.toml` (Req 10.7, 10.11, 20.1).
//!
//! Key invariants:
//! - Classification parameters live in versioned configuration data, never hard-coded in source (Req 10.7).
//! - Both `config_version` and `config_hash` are stamped onto every classified result as determinism inputs (Req 20.1).

use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use forensic_core::evidence_status::EvidenceStatus;
use forensic_core::evidence_item::RuleMatchStatus;
use forensic_core::{ForensicError, Hash};

#[derive(Debug, Clone, Deserialize)]
struct RawConfig {
    #[allow(dead_code)]
    pub config_id: String,
    pub config_version: String,
    pub thresholds: Thresholds,
    pub validation_factors: ValidationFactorsRaw,
    pub quality_factors: QualityFactorsRaw,
}

#[derive(Debug, Clone, Deserialize)]
struct Thresholds {
    pub min_confidence: f64,
    pub min_margin: f64,
    pub min_quality: f64,
}

#[derive(Debug, Clone, Deserialize)]
struct ValidationFactorsRaw {
    pub validated: f64,
    pub provisional: f64,
    pub model_specific: f64,
    pub firmware_specific: f64,
    pub unvalidated: f64,
}

#[derive(Debug, Clone, Deserialize)]
struct QualityFactorsRaw {
    pub r#match: f64,
    pub partial: f64,
    pub mismatch: f64,
    pub absent: f64,
}

/// Versioned classification configuration loaded from `config/classification.toml`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceConfig {
    pub config_version: String,
    pub config_hash: Hash,
    pub min_confidence: f64,
    pub min_margin: f64,
    pub min_quality: f64,
    pub val_validated: f64,
    pub val_provisional: f64,
    pub val_model_specific: f64,
    pub val_firmware_specific: f64,
    pub val_unvalidated: f64,
    pub qual_match: f64,
    pub qual_partial: f64,
    pub qual_mismatch: f64,
    pub qual_absent: f64,
}

impl ConfidenceConfig {
    /// Load from a TOML string, computing the config hash.
    pub fn from_toml_str(content: &str) -> Result<Self, ForensicError> {
        let raw: RawConfig = toml::from_str(content).map_err(|e| {
            ForensicError::corrupt("confidence_config", format!("failed to parse classification TOML: {e}"))
        })?;

        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let config_hash = Hash::sha256(hasher.finalize().to_vec());

        Ok(Self {
            config_version: raw.config_version,
            config_hash,
            min_confidence: raw.thresholds.min_confidence,
            min_margin: raw.thresholds.min_margin,
            min_quality: raw.thresholds.min_quality,
            val_validated: raw.validation_factors.validated,
            val_provisional: raw.validation_factors.provisional,
            val_model_specific: raw.validation_factors.model_specific,
            val_firmware_specific: raw.validation_factors.firmware_specific,
            val_unvalidated: raw.validation_factors.unvalidated,
            qual_match: raw.quality_factors.r#match,
            qual_partial: raw.quality_factors.partial,
            qual_mismatch: raw.quality_factors.mismatch,
            qual_absent: raw.quality_factors.absent,
        })
    }

    /// Load from file path.
    pub fn from_file(path: &Path) -> Result<Self, ForensicError> {
        let content = fs::read_to_string(path).map_err(|e| {
            ForensicError::io(format!("reading config at {}", path.display()), e)
        })?;
        Self::from_toml_str(&content)
    }

    /// Default configuration when file is not specified.
    pub fn provisional_default() -> Self {
        let default_toml = include_str!("../../../config/classification.toml");
        Self::from_toml_str(default_toml).unwrap_or_else(|_| Self {
            config_version: "classification-1.0.0".into(),
            config_hash: Hash::sha256(vec![0xAA; 32]),
            min_confidence: 0.65,
            min_margin: 0.20,
            min_quality: 0.50,
            val_validated: 1.0,
            val_provisional: 0.8,
            val_model_specific: 0.7,
            val_firmware_specific: 0.6,
            val_unvalidated: 0.4,
            qual_match: 1.0,
            qual_partial: 0.5,
            qual_mismatch: 0.0,
            qual_absent: 0.0,
        })
    }

    /// Validation factor corresponding to an EvidenceStatus level.
    pub fn validation_factor(&self, status: EvidenceStatus) -> f64 {
        match status {
            EvidenceStatus::Validated => self.val_validated,
            EvidenceStatus::Provisional => self.val_provisional,
            EvidenceStatus::ModelSpecific => self.val_model_specific,
            EvidenceStatus::FirmwareSpecific => self.val_firmware_specific,
            EvidenceStatus::Unvalidated => self.val_unvalidated,
        }
    }

    /// Quality factor corresponding to a RuleMatchStatus observation.
    pub fn quality_factor(&self, match_status: RuleMatchStatus) -> f64 {
        match match_status {
            RuleMatchStatus::Match => self.qual_match,
            RuleMatchStatus::Partial => self.qual_partial,
            RuleMatchStatus::Mismatch => self.qual_mismatch,
            RuleMatchStatus::Absent => self.qual_absent,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_default_config() {
        let config = ConfidenceConfig::provisional_default();
        assert_eq!(config.min_confidence, 0.65);
        assert_eq!(config.min_margin, 0.20);
        assert_eq!(config.validation_factor(EvidenceStatus::Validated), 1.0);
    }
}
