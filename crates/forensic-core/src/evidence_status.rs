//! # Evidence Status Model
//!
//! `EvidenceStatus` tracks how well established an OEM profile rule/signature is (Req 11.5, 11.6, 11.8).
//!
//! Key invariants:
//! - Exact 5 values: `validated`, `provisional`, `model_specific`, `firmware_specific`, `unvalidated`.
//! - Status is never upgraded by score (Req 10.8) and non-validated signatures are never treated as universal facts (Req 11.6).
//! - Distinct from `RuleMatchStatus` (Req 2.8).

use serde::{Deserialize, Serialize};

/// Maturity/validation level of a profile signature rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    /// Universally verified and scientifically grounded for the specified format.
    Validated,
    /// Engineering observation, provisional and subject to refinement.
    Provisional,
    /// Restricted to specific hardware model variants.
    ModelSpecific,
    /// Restricted to specific firmware builds.
    FirmwareSpecific,
    /// Unvalidated candidate / heuristic indicator.
    Unvalidated,
}

impl std::fmt::Display for EvidenceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validated => write!(f, "validated"),
            Self::Provisional => write!(f, "provisional"),
            Self::ModelSpecific => write!(f, "model_specific"),
            Self::FirmwareSpecific => write!(f, "firmware_specific"),
            Self::Unvalidated => write!(f, "unvalidated"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip_all_five_values() {
        let values = [
            EvidenceStatus::Validated,
            EvidenceStatus::Provisional,
            EvidenceStatus::ModelSpecific,
            EvidenceStatus::FirmwareSpecific,
            EvidenceStatus::Unvalidated,
        ];

        for val in values {
            let json = serde_json::to_string(&val).unwrap();
            let back: EvidenceStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(val, back);
        }
    }

    #[test]
    fn reject_unknown_value() {
        let invalid_json = "\"universal_fact\"";
        let res: Result<EvidenceStatus, _> = serde_json::from_str(invalid_json);
        assert!(res.is_err());
    }
}
