use crate::{Provenance, Region, ValidationState};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Represents the physical state of the data on the storage medium (Req 13.2).
/// This is an independent dimension from RecoveryStatus (Req 13.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataState {
    /// Data is actively allocated and referenced by the filesystem/index.
    Active,
    /// Data is marked as deleted by the filesystem/index but remains structurally intact.
    Deleted,
    /// Data exists on disk but is **positively established** to be unreferenced by the
    /// authoritative index structure that governs that physical region.
    ///
    /// Requires two independent facts: an authoritative OEM index was read, *and* the
    /// region it governs does not claim these bytes. "The parser did not find an index"
    /// is NOT sufficient — that is [`DataState::Unindexed`].
    Orphaned,
    /// Valid data was discovered but there is insufficient index/metadata evidence to
    /// associate it with an active recording or to support a stronger orphan/deleted
    /// conclusion.
    ///
    /// This is the conservative fallback. It records an **absence of evidence**, not
    /// evidence of deletion, and must never be reported or reasoned about as
    /// `Deleted`/`Orphaned`.
    Unindexed,
    /// Data structure or payload is mathematically/structurally invalid (e.g. invalid CRC or frame).
    Corrupted,
    /// Data has been partially or fully overwritten by new data.
    Overwritten,
}

/// Represents the practical outcome of the forensic recovery effort (Req 13.6).
/// This is an independent dimension from DataState (Req 13.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecoveryStatus {
    /// The data was fully recovered.
    Recoverable,
    /// The data was partially recovered (e.g. some frames missing).
    PartiallyRecoverable,
    /// The data could not be recovered into a usable artifact.
    Unrecoverable,
}

/// A container demonstrating that DataState and RecoveryStatus are independent
/// dimensions and can be held together without collapsing (Req 13.8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryAssessment {
    pub data_state: DataState,
    pub recovery_status: RecoveryStatus,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_independence() {
        // Demonstrate that Corrupted != Unrecoverable by construction (Req 13.7)
        let assessment = RecoveryAssessment {
            data_state: DataState::Corrupted,
            recovery_status: RecoveryStatus::Recoverable, // Corrupted data CAN be recoverable
        };

        assert_eq!(assessment.data_state, DataState::Corrupted);
        assert_eq!(assessment.recovery_status, RecoveryStatus::Recoverable);
    }

    #[test]
    fn test_recovery_candidate_construction_and_serde() {
        use crate::validation::ValidationStateKind;
        use crate::{EvidenceId, Hash};

        let mock_evidence = EvidenceId::new();
        let mock_hash = Hash::sha256(vec![0; 32]);
        let prov = Provenance::new(
            mock_evidence,
            mock_hash.clone(),
            vec![],
            "test_component",
            "1.0",
            mock_hash,
            ValidationState::pass("prov", "reason", "subject").unwrap(),
        );

        let candidate = RecoveryCandidate {
            recovery_level: RecoveryLevel::L2,
            data_state: DataState::Deleted,
            recovery_status: RecoveryStatus::PartiallyRecoverable,
            source_offsets: vec![Region {
                offset: 1024,
                length: 512,
            }],
            validation: FrameValidationReport {
                signatures: ValidationState::pass("sig", "Signature valid", "subject").unwrap(),
                structure: ValidationState::pass("struct", "Structure valid", "subject").unwrap(),
                timestamps: ValidationState::new(
                    ValidationStateKind::Review,
                    "timestamps",
                    "Timestamp jump detected",
                    "subject",
                )
                .unwrap(),
                channel: ValidationState::new(
                    ValidationStateKind::Unknown,
                    "channel",
                    "Channel ID missing",
                    "subject",
                )
                .unwrap(),
                continuity: ValidationState::fail("continuity", "Frame drop detected", "subject")
                    .unwrap(),
            },
            provenance: prov,
        };

        let json =
            serde_json::to_string(&candidate).expect("Failed to serialize RecoveryCandidate");
        let deserialized: RecoveryCandidate =
            serde_json::from_str(&json).expect("Failed to deserialize RecoveryCandidate");

        assert_eq!(candidate, deserialized);

        // Assert both dimensions are explicitly present on the candidate
        assert_eq!(candidate.data_state, DataState::Deleted);
        assert_eq!(
            candidate.recovery_status,
            RecoveryStatus::PartiallyRecoverable
        );
    }

    #[test]
    fn test_recovery_run_truncation_downgrades_to_review() {
        use crate::validation::ValidationStateKind;
        let mut run = RecoveryRun {
            searched_regions: vec![],
            searched_bytes: 0,
            skipped_ranges: vec![],
            candidate_count: 0,
            rejected: 0,
            accepted: 0,
            hypothesis_count: 0,
            truncated: true,
            cancelled: false,
            validation_state: ValidationState::pass("test", "Initial pass", "subject").unwrap(),
            reason: String::new(),
        };

        run.finalize();

        assert_eq!(run.validation_state.state, ValidationStateKind::Review);
        assert_eq!(run.reason, "Search bounds reached");
    }

    #[test]
    fn test_recovery_run_cancellation_downgrades_to_review() {
        use crate::validation::ValidationStateKind;
        let mut run = RecoveryRun {
            searched_regions: vec![],
            searched_bytes: 0,
            skipped_ranges: vec![],
            candidate_count: 0,
            rejected: 0,
            accepted: 0,
            hypothesis_count: 0,
            truncated: false,
            cancelled: true,
            validation_state: ValidationState::pass("test", "Initial pass", "subject").unwrap(),
            reason: String::new(),
        };

        run.finalize();

        assert_eq!(run.validation_state.state, ValidationStateKind::Review);
        assert_eq!(run.reason, "Search cancelled");
    }

    #[test]
    fn test_cancel_token_behavior() {
        let token = CancelToken::new();
        assert!(!token.is_cancelled());
        token.cancel();
        assert!(token.is_cancelled());
    }
}

/// The level at which recovery was performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecoveryLevel {
    /// L1: File-based/header-based recovery.
    L1,
    /// L2: Index-based reconstruction.
    L2,
    /// L3: Deep frame-level / payload carving.
    L3,
}

/// Aggregates specific validation states for a candidate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrameValidationReport {
    pub signatures: ValidationState,
    pub structure: ValidationState,
    pub timestamps: ValidationState,
    pub channel: ValidationState,
    pub continuity: ValidationState,
}

/// A candidate produced by the recovery engine (Req 13.5, 5.4).
/// Records the recovery level, DataState, and RecoveryStatus per item plus complete provenance.
/// Both DataState and RecoveryStatus dimensions are always present and neither is derived from the other.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveryCandidate {
    pub recovery_level: RecoveryLevel,
    pub data_state: DataState,
    pub recovery_status: RecoveryStatus,
    pub source_offsets: Vec<Region>,
    pub validation: FrameValidationReport,
    pub provenance: Provenance,
}

/// A thread-safe cancellation token.
#[derive(Debug, Clone)]
pub struct CancelToken {
    is_cancelled: Arc<AtomicBool>,
}

// We implement serialization manually or skip it since we can't serialize AtomicBool easily.
// For forensic persistence, configuration is preserved but the runtime cancellation state is not.
impl serde::Serialize for CancelToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bool(self.is_cancelled())
    }
}

impl<'de> serde::Deserialize<'de> for CancelToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let val = bool::deserialize(deserializer)?;
        let token = CancelToken::new();
        if val {
            token.cancel();
        }
        Ok(token)
    }
}

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancelToken {
    pub fn new() -> Self {
        Self {
            is_cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.is_cancelled.load(Ordering::SeqCst)
    }

    pub fn cancel(&self) {
        self.is_cancelled.store(true, Ordering::SeqCst);
    }
}

impl PartialEq for CancelToken {
    fn eq(&self, other: &Self) -> bool {
        self.is_cancelled() == other.is_cancelled()
    }
}

/// Configuration boundaries for a recovery operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveryBounds {
    pub max_scan_bytes: u64,
    pub max_scan_regions: u32,
    pub max_candidates: u32,
    pub max_hypotheses: u32,
    pub max_search_depth: Option<u32>,
    pub cancel: CancelToken,
    pub time_limit: Option<Duration>,
}

/// A comprehensive record of a bounded recovery operation's execution and outcome.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveryRun {
    pub searched_regions: Vec<Region>,
    pub searched_bytes: u64,
    pub skipped_ranges: Vec<Region>,
    pub candidate_count: u32,
    pub rejected: u32,
    pub accepted: u32,
    pub hypothesis_count: u32,
    pub truncated: bool,
    pub cancelled: bool,
    pub validation_state: ValidationState, // PASS | REVIEW | FAIL | UNKNOWN
    pub reason: String,
}

impl RecoveryRun {
    /// Finalizes the run. If the run was truncated or cancelled, it explicitly
    /// downgrades the validation state to REVIEW, as a bounded search can never
    /// guarantee a global optimum (Req 13.10).
    pub fn finalize(&mut self) {
        // Argument order is (state, reason, operation, subject). The reason is the field an
        // examiner reads, so it carries the explanation; "RecoveryRun" is the subject, not a
        // reason, and putting it there left every bounded run explaining itself as a type name.
        if self.cancelled {
            self.validation_state = ValidationState::new(
                crate::ValidationStateKind::Review,
                "Run was cancelled by the user",
                "RecoveryRun::finalize",
                "Search",
            )
            .expect("static reason is non-empty");
            self.reason = "Search cancelled".to_string();
        } else if self.truncated {
            self.validation_state = ValidationState::new(
                crate::ValidationStateKind::Review,
                "Search space was truncated; global optimum not guaranteed",
                "RecoveryRun::finalize",
                "Search",
            )
            .expect("static reason is non-empty");
            self.reason = "Search bounds reached".to_string();
        }
    }
}
