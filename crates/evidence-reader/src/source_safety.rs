//! # Source Safety Inspection
//!
//! Implements `SourceState`, `SafetyDecision`, `SourceSafetyReport`, and `inspect_source`
//! which runs BEFORE any analysis of a physical block device and rejects mounted or
//! write-enabled sources by default (Req 1.8–1.12).
//!
//! Key invariants:
//! - A read_write, mounted, or write-enabled source produces a VISIBLE failure (Req 1.10).
//! - Where state cannot be determined, it is `Unknown`, NEVER reported as `ReadOnly` (Req 1.12).
//! - Software controls do not replace a hardware write blocker (Req 1.7).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use forensic_core::case::SourceState;

/// The decision made after inspecting a source's safety state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyDecision {
    /// The source was accepted for analysis.
    Accepted,
    /// The source was rejected — analysis MUST NOT proceed.
    Rejected,
}

impl std::fmt::Display for SafetyDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accepted => write!(f, "accepted"),
            Self::Rejected => write!(f, "rejected"),
        }
    }
}

/// The result of inspecting a source's safety state.
///
/// Recorded in chain of custody (Req 1.11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSafetyReport {
    /// The observed source state.
    pub source_state: SourceState,
    /// The decision made.
    pub decision: SafetyDecision,
    /// The reason for the decision.
    pub reason: String,
    /// When the inspection was performed.
    pub inspected_at: DateTime<Utc>,
}

impl SourceSafetyReport {
    /// Create a new report.
    pub fn new(
        source_state: SourceState,
        decision: SafetyDecision,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            source_state,
            decision,
            reason: reason.into(),
            inspected_at: Utc::now(),
        }
    }

    /// Whether the source was accepted.
    pub fn is_accepted(&self) -> bool {
        self.decision == SafetyDecision::Accepted
    }
}

/// Inspect a source and decide whether analysis should proceed.
///
/// This function MUST run BEFORE any analysis of a physical block device.
///
/// Policy:
/// - `ReadOnly` sources are accepted.
/// - `ReadWrite` and mounted sources are REJECTED with a visible failure (Req 1.10).
/// - `Unknown` sources are accepted with a warning (the state is recorded as Unknown,
///   not fabricated as ReadOnly — Req 1.12).
///
/// Note: This is a software inspection only. Software controls do not replace a
/// hardware write blocker (Req 1.7).
pub fn inspect_source(source_state: SourceState) -> SourceSafetyReport {
    match source_state {
        SourceState::ReadOnly => SourceSafetyReport::new(
            source_state,
            SafetyDecision::Accepted,
            "source inspected: read-only state confirmed (software inspection only; \
             does not replace hardware write blocker)",
        ),
        SourceState::ReadWrite => SourceSafetyReport::new(
            source_state,
            SafetyDecision::Rejected,
            "REJECTED: source is read-write or mounted. Analysis cannot proceed on a \
             write-enabled source. Use a hardware write blocker and re-acquire.",
        ),
        SourceState::Unknown => SourceSafetyReport::new(
            source_state,
            SafetyDecision::Accepted,
            "WARNING: source state could not be determined. Recorded as Unknown \
             (not assumed read-only). Proceed with caution; verify hardware write \
             blocker is in use.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_accepted() {
        let report = inspect_source(SourceState::ReadOnly);
        assert_eq!(report.decision, SafetyDecision::Accepted);
        assert_eq!(report.source_state, SourceState::ReadOnly);
    }

    #[test]
    fn read_write_rejected_with_visible_failure() {
        let report = inspect_source(SourceState::ReadWrite);
        assert_eq!(report.decision, SafetyDecision::Rejected);
        assert!(report.reason.contains("REJECTED"));
    }

    #[test]
    fn unknown_accepted_with_warning() {
        let report = inspect_source(SourceState::Unknown);
        assert_eq!(report.decision, SafetyDecision::Accepted);
        assert_eq!(report.source_state, SourceState::Unknown);
        assert!(report.reason.contains("WARNING"));
        // State is Unknown, NOT fabricated as ReadOnly.
        assert_ne!(report.source_state, SourceState::ReadOnly);
    }

    #[test]
    fn undeterminable_never_reported_as_read_only() {
        // Req 1.12: Unknown is never reported as ReadOnly.
        let report = inspect_source(SourceState::Unknown);
        assert_eq!(report.source_state, SourceState::Unknown);
    }

    #[test]
    fn report_serde_roundtrip() {
        let report = inspect_source(SourceState::ReadOnly);
        let json = serde_json::to_string(&report).unwrap();
        let back: SourceSafetyReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn mounted_source_blocks_analysis() {
        // A mounted/write-enabled source must produce a rejection.
        let report = inspect_source(SourceState::ReadWrite);
        assert!(!report.is_accepted());
    }
}
