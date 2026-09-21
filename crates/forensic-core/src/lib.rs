//! # forensic-core
//!
//! Shared forensic domain vocabulary for the platform: identifiers, `Hash`, `Region`,
//! `ForensicError`, and the cross-cutting state enums (`ValidationState`,
//! `CapabilityStage`), plus the case/evidence/acquisition/provenance/artifact models,
//! chain-of-custody logging, checked-arithmetic primitives, write protection, export hooks,
//! OEM profile loader, EvidenceStatus, EvidenceItem, and the determinism harness.
//!
//! Constraints this crate must uphold:
//!
//! * Types are pure and serde-serializable, with no environment coupling, so forensic
//!   results stay deterministic (Req 20).
//! * Fallible operations return `Result<T, ForensicError>`; malformed evidence is data,
//!   not a crash (Req 24.1).
//! * No OEM signature, magic value, offset, or structure is ever declared here. All OEM
//!   factual knowledge is versioned `OEM_Profile` data under `profiles/` (Req 6.1, 11).

#![forbid(unsafe_code)]

// --- Foundational types ---
pub mod error;
pub mod identifiers;
pub mod hash;
pub mod region;
pub mod range_set;
pub mod finding;
pub mod recovery;

// --- Cross-cutting state enums ---
pub mod validation;
pub mod capability;
pub mod evidence_status;

// --- Checked arithmetic (Req 24) ---
pub mod checked;

// --- Domain models ---
pub mod case;
pub mod acquisition;
pub mod provenance;
pub mod artifact;
pub mod chain_of_custody;
pub mod write_guard;
pub mod export;
pub mod case_manager;
pub mod profile;
pub mod evidence_item;

// --- Parsing Models ---
pub mod time_evidence;
pub mod recording;
pub mod timeline_event;
pub mod parser_run;
pub mod ai;
pub mod ai_pipeline;

// --- Determinism harness (Req 20) ---
pub mod determinism;

// --- Convenience re-exports ---
pub use error::ForensicError;
pub use identifiers::{
    AcquisitionId, ArtifactId, CaseId, EvidenceId, ExaminerId, ProfileId,
};
pub use ai::AiFinding;
pub use ai_pipeline::AiPipeline;
pub use hash::{Hash, HashAlgorithm};
pub use region::Region;
pub use range_set::RangeSet;
pub use finding::{Finding, FindingSeverity};
pub use recovery::{DataState, RecoveryStatus, RecoveryAssessment, RecoveryLevel, FrameValidationReport, RecoveryCandidate, RecoveryBounds, RecoveryRun, CancelToken};
pub use validation::{ValidationState, ValidationStateKind};
pub use capability::{CapabilityStage, CapabilityStages};
pub use evidence_status::EvidenceStatus;
pub use case::{Case, Evidence, ImageFormat, SourceState};
pub use acquisition::{Acquisition, AcquisitionStatus};
pub use provenance::{Provenance, SourceRegion, TransformationStep};
pub use artifact::{Artifact, DerivedArtifact, DerivedKind, NativeArtifact};
pub use chain_of_custody::{CustodyAction, CustodyEvent, CustodyLog};
pub use write_guard::WriteGuard;
pub use export::{finalize_export, ExportRecord, ExportRequest};
pub use case_manager::{CaseManager, EvidenceRegistrationInput};
pub use profile::{Applicability, ConfidenceWeights, OemProfile, OffsetConstraint, ProfileRegistry, SignatureRule, ValidationRule};
pub use evidence_item::{EvidenceItem, RuleMatchStatus};


pub use time_evidence::{TimeEvidence, RawTimestamp, RecorderNativeTime, NormalizedTime, ReferenceTime, TimeZoneState, ClockCorrection};
pub use recording::{Recording, IntegrityFlag};
pub use timeline_event::TimelineEvent;
pub use parser_run::ParserRun;

pub use determinism::{
    compare_forensic_results, ComparisonResult, ComponentVersions,
    DeterminismKey, ForensicResult, ResultMetadata,
};

/// Convenience type alias for forensic results.
pub type Result<T> = std::result::Result<T, ForensicError>;
