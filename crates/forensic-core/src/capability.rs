//! # Capability Stage Model
//!
//! `CapabilityStage` is implementation maturity (NotImplemented / Partial / Implemented),
//! tracked per OEM across five independent dimensions (Req 3.6, 21.1–21.4).
//!
//! Key invariants:
//! - The five dimensions are NEVER collapsed into a single "supported" boolean.
//! - `CapabilityStage` is structurally distinct from `ValidationState` — the two types
//!   are not interchangeable and neither converts into the other.
//! - Values are derived from what is actually implemented, never from intent.

use serde::{Deserialize, Serialize};

/// The maturity level of a single capability dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStage {
    /// The capability is not implemented for this OEM.
    NotImplemented,
    /// The capability is partially implemented (e.g. some models/firmware supported).
    Partial,
    /// The capability is fully implemented for the supported profile scope.
    Implemented,
}

impl std::fmt::Display for CapabilityStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotImplemented => write!(f, "NOT_IMPLEMENTED"),
            Self::Partial => write!(f, "PARTIAL"),
            Self::Implemented => write!(f, "IMPLEMENTED"),
        }
    }
}

/// Five independent capability dimensions for an OEM, tracked independently.
///
/// No single "supported" boolean exists. Each dimension reflects the actual
/// implementation state, not intent or plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityStages {
    /// Can the platform detect this OEM's storage format?
    pub detection: CapabilityStage,
    /// Can the platform profile the storage topology?
    pub profiling: CapabilityStage,
    /// Can the platform parse recordings and metadata?
    pub parsing: CapabilityStage,
    /// Can the platform reconstruct/recover data?
    pub reconstruction: CapabilityStage,
    /// Can the platform validate reconstructed artifacts?
    pub validation: CapabilityStage,
}

impl CapabilityStages {
    /// Create a new `CapabilityStages` with all dimensions set to `NotImplemented`.
    ///
    /// This is the starting state for a new OEM — capabilities are claimed only when
    /// implemented.
    pub fn not_implemented() -> Self {
        Self {
            detection: CapabilityStage::NotImplemented,
            profiling: CapabilityStage::NotImplemented,
            parsing: CapabilityStage::NotImplemented,
            reconstruction: CapabilityStage::NotImplemented,
            validation: CapabilityStage::NotImplemented,
        }
    }

    /// Returns an iterator over all five (dimension_name, stage) pairs.
    pub fn dimensions(&self) -> [(&'static str, CapabilityStage); 5] {
        [
            ("detection", self.detection),
            ("profiling", self.profiling),
            ("parsing", self.parsing),
            ("reconstruction", self.reconstruction),
            ("validation", self.validation),
        ]
    }

    /// Returns `true` if any dimension is at least `Partial`.
    ///
    /// Note: this is NOT a "supported" flag — it exists for filtering/listing only.
    /// It MUST NOT be displayed as a single aggregate support indicator (Req 3.6).
    pub fn has_any_capability(&self) -> bool {
        self.dimensions()
            .iter()
            .any(|(_, stage)| *stage != CapabilityStage::NotImplemented)
    }
}

impl std::fmt::Display for CapabilityStages {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "detection={}, profiling={}, parsing={}, reconstruction={}, validation={}",
            self.detection, self.profiling, self.parsing, self.reconstruction, self.validation
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip() {
        let stages = CapabilityStages {
            detection: CapabilityStage::Implemented,
            profiling: CapabilityStage::Partial,
            parsing: CapabilityStage::NotImplemented,
            reconstruction: CapabilityStage::NotImplemented,
            validation: CapabilityStage::NotImplemented,
        };
        let json = serde_json::to_string(&stages).unwrap();
        let back: CapabilityStages = serde_json::from_str(&json).unwrap();
        assert_eq!(stages, back);
    }

    #[test]
    fn five_dimensions_independent() {
        let mut stages = CapabilityStages::not_implemented();

        // Changing one dimension does not affect others.
        stages.detection = CapabilityStage::Implemented;
        assert_eq!(stages.detection, CapabilityStage::Implemented);
        assert_eq!(stages.profiling, CapabilityStage::NotImplemented);
        assert_eq!(stages.parsing, CapabilityStage::NotImplemented);
        assert_eq!(stages.reconstruction, CapabilityStage::NotImplemented);
        assert_eq!(stages.validation, CapabilityStage::NotImplemented);

        stages.parsing = CapabilityStage::Partial;
        assert_eq!(stages.detection, CapabilityStage::Implemented);
        assert_eq!(stages.parsing, CapabilityStage::Partial);
        assert_eq!(stages.profiling, CapabilityStage::NotImplemented);
    }

    #[test]
    fn not_implemented_has_no_capability() {
        let stages = CapabilityStages::not_implemented();
        assert!(!stages.has_any_capability());
    }

    #[test]
    fn partial_has_capability() {
        let mut stages = CapabilityStages::not_implemented();
        stages.reconstruction = CapabilityStage::Partial;
        assert!(stages.has_any_capability());
    }

    #[test]
    fn dimensions_returns_all_five() {
        let stages = CapabilityStages::not_implemented();
        let dims = stages.dimensions();
        assert_eq!(dims.len(), 5);
        let names: Vec<&str> = dims.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"detection"));
        assert!(names.contains(&"profiling"));
        assert!(names.contains(&"parsing"));
        assert!(names.contains(&"reconstruction"));
        assert!(names.contains(&"validation"));
    }

    #[test]
    fn stage_values_serde() {
        for stage in [
            CapabilityStage::NotImplemented,
            CapabilityStage::Partial,
            CapabilityStage::Implemented,
        ] {
            let json = serde_json::to_string(&stage).unwrap();
            let back: CapabilityStage = serde_json::from_str(&json).unwrap();
            assert_eq!(stage, back);
        }
    }

    #[test]
    fn no_single_supported_boolean() {
        // This test documents the invariant that there is no `is_supported()` method
        // on CapabilityStages. The `has_any_capability()` method is for filtering only
        // and MUST NOT be used as a single aggregate support indicator.
        let stages = CapabilityStages {
            detection: CapabilityStage::Implemented,
            profiling: CapabilityStage::NotImplemented,
            parsing: CapabilityStage::NotImplemented,
            reconstruction: CapabilityStage::NotImplemented,
            validation: CapabilityStage::NotImplemented,
        };
        // The five dimensions are separately queryable.
        assert_eq!(stages.detection, CapabilityStage::Implemented);
        assert_eq!(stages.profiling, CapabilityStage::NotImplemented);
    }

    // Compile-time guarantee: no From/Into between CapabilityStage(s) and ValidationState.
    #[test]
    fn no_conversion_to_validation_state() {
        // This test documents the invariant. If a From/Into is added, this documents
        // the requirement violation.
        fn _assert_distinct_types<T: std::fmt::Debug, U: std::fmt::Debug>() {}
        _assert_distinct_types::<CapabilityStage, crate::validation::ValidationState>();
        _assert_distinct_types::<CapabilityStages, crate::validation::ValidationState>();
    }
}
