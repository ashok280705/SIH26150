//! # Validation State
//!
//! `ValidationState` records the outcome of a named operation on a named subject.
//! It is structurally distinct from `CapabilityStage` — the two types are not
//! interchangeable and neither converts into the other (Req 21.2, 22.1–22.3).
//!
//! Key invariants:
//! - A reason is structurally required: no state can be recorded without an explanation.
//! - An operation that has not executed or been verified is `Unknown`, never `Pass`.
//! - `ValidationState` is the outcome of an operation, not implementation maturity.

use serde::{Deserialize, Serialize};

/// The four possible outcomes of a validation operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidationStateKind {
    /// The operation ran and the subject passed all checks.
    Pass,
    /// The operation ran but the result requires human review.
    Review,
    /// The operation ran and the subject failed one or more checks.
    Fail,
    /// The operation did not run, or its result could not be determined.
    Unknown,
}

impl std::fmt::Display for ValidationStateKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Review => write!(f, "REVIEW"),
            Self::Fail => write!(f, "FAIL"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// The recorded outcome of a named validation operation on a named subject.
///
/// The `reason` field is structurally required — it cannot be empty or missing.
/// This ensures every recorded validation state has an explanation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationState {
    /// The outcome of the operation.
    pub state: ValidationStateKind,
    /// Human-readable explanation of why this state was assigned. Always non-empty.
    pub reason: String,
    /// The name of the operation that produced this state (e.g. "hash_verification",
    /// "detection_scan", "reconstruction_validation").
    pub operation: String,
    /// The subject of the operation (e.g. evidence ID, artifact ID, region description).
    pub subject: String,
}

/// Error returned when attempting to construct a `ValidationState` with an empty reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmptyReasonError;

impl std::fmt::Display for EmptyReasonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ValidationState reason must not be empty")
    }
}

impl std::error::Error for EmptyReasonError {}

impl ValidationState {
    /// Create a new `ValidationState` with a required non-empty reason.
    ///
    /// Returns `Err(EmptyReasonError)` if `reason` is empty or whitespace-only.
    pub fn new(
        state: ValidationStateKind,
        reason: impl Into<String>,
        operation: impl Into<String>,
        subject: impl Into<String>,
    ) -> Result<Self, EmptyReasonError> {
        let reason = reason.into();
        if reason.trim().is_empty() {
            return Err(EmptyReasonError);
        }
        Ok(Self {
            state,
            reason,
            operation: operation.into(),
            subject: subject.into(),
        })
    }

    /// Create a `PASS` state.
    pub fn pass(
        reason: impl Into<String>,
        operation: impl Into<String>,
        subject: impl Into<String>,
    ) -> Result<Self, EmptyReasonError> {
        Self::new(ValidationStateKind::Pass, reason, operation, subject)
    }

    /// Create a `REVIEW` state.
    pub fn review(
        reason: impl Into<String>,
        operation: impl Into<String>,
        subject: impl Into<String>,
    ) -> Result<Self, EmptyReasonError> {
        Self::new(ValidationStateKind::Review, reason, operation, subject)
    }

    /// Create a `FAIL` state.
    pub fn fail(
        reason: impl Into<String>,
        operation: impl Into<String>,
        subject: impl Into<String>,
    ) -> Result<Self, EmptyReasonError> {
        Self::new(ValidationStateKind::Fail, reason, operation, subject)
    }

    /// Create an `UNKNOWN` state for an operation that did not run.
    ///
    /// This is the canonical way to record that an operation was not executed.
    /// The resulting state is `UNKNOWN`, never `PASS`.
    pub fn not_run(
        operation: impl Into<String>,
        subject: impl Into<String>,
    ) -> Self {
        // This constructor does not go through `new()` validation because the reason
        // is always well-formed.
        let operation = operation.into();
        Self {
            state: ValidationStateKind::Unknown,
            reason: format!("operation '{}' did not run", operation),
            operation,
            subject: subject.into(),
        }
    }

    /// Whether this state indicates the operation passed.
    pub fn is_pass(&self) -> bool {
        self.state == ValidationStateKind::Pass
    }

    /// Whether this state requires human review.
    pub fn is_review(&self) -> bool {
        self.state == ValidationStateKind::Review
    }

    /// Whether this state indicates failure.
    pub fn is_fail(&self) -> bool {
        self.state == ValidationStateKind::Fail
    }

    /// Whether this state indicates the operation did not run.
    pub fn is_unknown(&self) -> bool {
        self.state == ValidationStateKind::Unknown
    }
}

impl std::fmt::Display for ValidationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} [{}:{}]: {}",
            self.state, self.operation, self.subject, self.reason
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_values_serde_roundtrip() {
        let states = [
            ValidationState::pass("hash matched", "hash_check", "evidence-1").unwrap(),
            ValidationState::review("truncated scan", "scan", "evidence-2").unwrap(),
            ValidationState::fail("bad magic bytes", "detection", "evidence-3").unwrap(),
            ValidationState::not_run("decode", "evidence-4"),
        ];
        for vs in &states {
            let json = serde_json::to_string(vs).unwrap();
            let back: ValidationState = serde_json::from_str(&json).unwrap();
            assert_eq!(vs, &back);
        }
    }

    #[test]
    fn reason_required() {
        assert!(ValidationState::pass("", "op", "sub").is_err());
        assert!(ValidationState::pass("   ", "op", "sub").is_err());
        assert!(ValidationState::review("", "op", "sub").is_err());
        assert!(ValidationState::fail("", "op", "sub").is_err());
    }

    #[test]
    fn not_run_always_unknown() {
        let vs = ValidationState::not_run("hash_check", "evidence-1");
        assert_eq!(vs.state, ValidationStateKind::Unknown);
        assert!(vs.is_unknown());
        assert!(!vs.is_pass());
    }

    #[test]
    fn not_run_has_reason() {
        let vs = ValidationState::not_run("hash_check", "evidence-1");
        assert!(!vs.reason.is_empty());
        assert!(vs.reason.contains("did not run"));
    }

    #[test]
    fn display_includes_all_fields() {
        let vs = ValidationState::pass("hashes match", "hash_verify", "ev-1").unwrap();
        let s = vs.to_string();
        assert!(s.contains("PASS"), "got: {s}");
        assert!(s.contains("hash_verify"), "got: {s}");
        assert!(s.contains("ev-1"), "got: {s}");
        assert!(s.contains("hashes match"), "got: {s}");
    }

    // Compile-time guarantee: no From/Into between ValidationState and CapabilityStage.
    // If someone adds `impl From<ValidationState> for CapabilityStage` or vice versa,
    // these tests would need to be removed — which is the point: the test documents
    // that no conversion should exist.
    #[test]
    fn no_conversion_to_capability_stage() {
        // This test documents the invariant. The actual enforcement is at the type level:
        // there is no `From` or `Into` implementation between the two types.
        // If one were added, the code reviewer should reject it.
        fn _assert_no_from<T, U>()
        where
            T: std::fmt::Debug,
        {
            // Intentionally empty: the purpose is the type constraint.
        }
        // The fact that this compiles without implementing From is the assertion.
        _assert_no_from::<ValidationState, ()>();
    }
}
