//! # ClassifiedDetectionResult and Attribution Models
//!
//! Output models produced exclusively by the Confidence_Engine (Req 2.6, 2.7, 9.6, 10.9).
//!
//! Key invariants:
//! - Sole carrier and producer of `Classification`, `AttributionStatus`, and normalized `confidence` (Req 9.6).
//! - Detectors cannot construct or emit this type.
//! - Carries top/second candidates, margin, evidence quality, validation state, and config provenance.

use serde::{Deserialize, Serialize};

use detection::DetectorOutput;
use forensic_core::{Hash, ValidationState};

/// The forensic classification assigned to evidence after multi-vendor evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// Threshold + margin + quality satisfied AND OEM-exclusive evidence present.
    Confirmed,
    /// Threshold + margin satisfied, but evidence is compatible/non-exclusive.
    CompatibleCandidate,
    /// Multiple candidate formats scored within the minimum margin of each other.
    Ambiguous,
    /// Structural evidence is insufficient (e.g. lone magic or truncated structure).
    Insufficient,
    /// No candidate reached the minimum threshold.
    Unknown,
}

impl std::fmt::Display for Classification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Confirmed => write!(f, "confirmed"),
            Self::CompatibleCandidate => write!(f, "compatible_candidate"),
            Self::Ambiguous => write!(f, "ambiguous"),
            Self::Insufficient => write!(f, "insufficient"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// The legal/forensic attribution claim assigned to an evidence source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionStatus {
    /// Confirmed OEM attribution supported by exclusive structural proof.
    Confirmed,
    /// Compatible storage candidate (e.g. UBS storage without CP Plus branding).
    CompatibleCandidate,
    /// Known unsupported storage format.
    Unsupported,
    /// Unidentified / unknown format.
    Unknown,
}

impl std::fmt::Display for AttributionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Confirmed => write!(f, "confirmed"),
            Self::CompatibleCandidate => write!(f, "compatible_candidate"),
            Self::Unsupported => write!(f, "unsupported"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Comprehensive forensic attribution result produced exclusively by the Confidence_Engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassifiedDetectionResult {
    /// The winning or primary detector's raw output.
    pub detector_output: DetectorOutput,
    /// Raw cumulative score.
    pub raw_score: f64,
    /// Normalized confidence (0.0 .. 1.0).
    pub confidence: f64,
    /// Name of top candidate format.
    pub top_candidate: String,
    /// Name of second candidate format (for margin tracking).
    pub second_candidate: Option<String>,
    /// Confidence margin between top 1 and top 2 candidates.
    pub margin: f64,
    /// Average evidence observation quality (0.0 .. 1.0).
    pub evidence_quality: f64,
    /// Assigned classification.
    pub classification: Classification,
    /// Assigned attribution status.
    pub attribution_status: AttributionStatus,
    /// Forensic validation state with mandatory explanation.
    pub validation_state: ValidationState,
    /// Human-readable explanation of the attribution decision.
    pub explanation: String,
    /// ConfidenceConfig version applied.
    pub config_version: String,
    /// ConfidenceConfig SHA-256 hash.
    pub config_hash: Hash,
}
