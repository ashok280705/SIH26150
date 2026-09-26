//! # Finding — structured forensic diagnostic
//!
//! A `Finding` records a forensic observation about evidence without discarding the
//! original fact that produced it. It is **additive**: it does not replace
//! [`crate::error::ForensicError`] (which signals an operation could not proceed) nor
//! [`crate::validation::ValidationState`] (the pass/review/fail/unknown outcome of a
//! named operation). A `Finding` is a preserved detail — for example, that an MBR
//! partition declared a range extending past the end of the image.
//!
//! Design mirrors the conventions of `ValidationState`:
//! * a machine-stable `code` and a human-readable `message` are always present,
//! * the affected [`Region`] is recorded,
//! * where a structure was clamped or reinterpreted, the **original declared** region is
//!   preserved alongside the safe region so the forensic fact is never lost.
//!
//! The severity model is deliberately minimal (three levels). It is not an elaborate
//! taxonomy; it exists only to let downstream reporting sort and filter observations.

use serde::{Deserialize, Serialize};

use crate::region::Region;

/// Severity of a [`Finding`]. Intentionally small and extensible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    /// Informational: a preserved observation with no correctness concern.
    Info,
    /// Warning: an anomaly that warrants human review but was handled safely.
    Warning,
    /// Error: a malformed or inconsistent structure that could not be used as declared.
    Error,
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Error => write!(f, "error"),
        }
    }
}

/// A structured forensic finding.
///
/// Construction is infallible: `code` and `message` are developer-supplied string
/// constants (never evidence-derived), and `region` is a caller-provided [`Region`], so
/// there is no fallible arithmetic to guard here. This keeps call sites (e.g. MBR
/// analysis) free of `unwrap`/`expect` while still requiring the fields to be provided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Severity of the observation.
    pub severity: FindingSeverity,
    /// A machine-stable code identifying the kind of finding (e.g.
    /// `"mbr.partition.out_of_bounds"`).
    pub code: String,
    /// Human-readable explanation.
    pub message: String,
    /// The region affected by the finding. For a clamped structure this is the **safe**
    /// region actually usable within the evidence bounds.
    pub region: Region,
    /// Where a structure was clamped or reinterpreted, the **originally declared** region
    /// before clamping. `None` when the finding does not involve a clamp.
    pub declared_region: Option<Region>,
}

impl Finding {
    /// Create a new finding with an explicit severity.
    pub fn new(
        severity: FindingSeverity,
        code: impl Into<String>,
        message: impl Into<String>,
        region: Region,
    ) -> Self {
        Self {
            severity,
            code: code.into(),
            message: message.into(),
            region,
            declared_region: None,
        }
    }

    /// Convenience constructor for an [`FindingSeverity::Info`] finding.
    pub fn info(code: impl Into<String>, message: impl Into<String>, region: Region) -> Self {
        Self::new(FindingSeverity::Info, code, message, region)
    }

    /// Convenience constructor for a [`FindingSeverity::Warning`] finding.
    pub fn warning(code: impl Into<String>, message: impl Into<String>, region: Region) -> Self {
        Self::new(FindingSeverity::Warning, code, message, region)
    }

    /// Convenience constructor for a [`FindingSeverity::Error`] finding.
    pub fn error(code: impl Into<String>, message: impl Into<String>, region: Region) -> Self {
        Self::new(FindingSeverity::Error, code, message, region)
    }

    /// Attach the originally declared (pre-clamp) region to this finding.
    #[must_use]
    pub fn with_declared(mut self, declared: Region) -> Self {
        self.declared_region = Some(declared);
        self
    }
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.declared_region {
            Some(declared) => write!(
                f,
                "[{}] {}: {} (affected {}, declared {})",
                self.severity, self.code, self.message, self.region, declared
            ),
            None => write!(
                f,
                "[{}] {}: {} (affected {})",
                self.severity, self.code, self.message, self.region
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construct_basic_finding() {
        let f = Finding::warning(
            "mbr.partition.overlap",
            "partition 0 overlaps partition 1",
            Region::new(100, 400).unwrap(),
        );
        assert_eq!(f.severity, FindingSeverity::Warning);
        assert_eq!(f.code, "mbr.partition.overlap");
        assert_eq!(f.region, Region::new(100, 400).unwrap());
        assert!(f.declared_region.is_none());
    }

    #[test]
    fn declared_region_is_preserved() {
        let safe = Region::new(900, 100).unwrap(); // clamped to image end
        let declared = Region::new(900, 300).unwrap(); // original declaration
        let f = Finding::warning(
            "mbr.partition.out_of_bounds",
            "declared partition extends beyond evidence",
            safe,
        )
        .with_declared(declared);
        assert_eq!(f.region, safe);
        assert_eq!(f.declared_region, Some(declared));
        // The forensic fact — the original declaration — is not lost.
        assert_ne!(f.region, f.declared_region.unwrap());
    }

    #[test]
    fn severity_ordering_variants_distinct() {
        assert_ne!(FindingSeverity::Info, FindingSeverity::Warning);
        assert_ne!(FindingSeverity::Warning, FindingSeverity::Error);
    }

    #[test]
    fn serde_roundtrip() {
        let f = Finding::error(
            "mbr.partition.arithmetic_overflow",
            "start_lba * sector_size overflows",
            Region::point(0),
        )
        .with_declared(Region::new(10, 20).unwrap());
        let json = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn display_includes_declared_when_present() {
        let f = Finding::warning("code.x", "msg", Region::new(0, 10).unwrap())
            .with_declared(Region::new(0, 30).unwrap());
        let s = f.to_string();
        assert!(s.contains("warning"), "got: {s}");
        assert!(s.contains("code.x"), "got: {s}");
        assert!(s.contains("declared"), "got: {s}");
    }
}
