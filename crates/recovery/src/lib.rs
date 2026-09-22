//! # recovery
//!
//! The `Recovery_Engine` (L1 indexed, L2 orphan/slack, L3 raw carving), `RecoveryBounds`,
//! `RecoveryRun`, and the `Video_Reconstructor`.
//!
//! Constraints this crate must uphold:
//!
//! * `Data_State` and `Recovery_Status` are independent dimensions and are never collapsed.
//!   `Overwritten` data is never reconstructed; `Corrupted` is never forced to
//!   `Unrecoverable` (Req 13).
//! * A bounded search that was truncated is reported as `REVIEW`, never `PASS` (Req 13.9).
//! * Gaps are marked, never filled. No frame, recording, or timestamp is ever synthesized
//!   (Req 14).
//! * Recovery orchestration lives here; per-OEM recovery *knowledge* comes from the parser
//!   crates and profile data.
//! * Evidence is adversarial input: checked arithmetic throughout, no panic, and
//!   cancellation is honored (Req 24).
//!
//! ## The index-aware recovery path
//!
//! `OEM detection` is separate from `storage interpretation`, which is separate from
//! `index discovery`, which is separate from `raw video discovery`, which is separate
//! from `state classification`. Concretely:
//!
//! * [`plan`] compares the OEM index against the physical address space using the
//!   canonical [`forensic_core::RangeSet`], producing claimed and unclaimed ranges.
//! * [`claims`] owns that comparison and records how strong each "unclaimed" fact is.
//! * [`levels`] performs the bounded reads and establishes what video is present.
//! * [`classification`] combines index evidence with video evidence into a `DataState`.
//!
//! Recognising an OEM, matching a container signature, or classifying a codec can never
//! produce `DataState::Active`; that requires an index claim. Conversely, absence from an
//! index only reaches `Orphaned` when the index is authoritative over those bytes —
//! otherwise it stays `DataState::Unindexed`, which is an absence of evidence and never
//! a deletion finding.

#![forbid(unsafe_code)]

pub mod claims;
pub mod classification;
pub mod engine;
pub mod ffmpeg;
pub mod fragment;
pub mod fragmentation;
pub mod hypothesis;
pub mod levels;
pub mod metrics;
pub mod plan;
pub mod reconstructor;
pub mod validation;
pub mod video;
pub mod wrap_storage;

pub use claims::{build_claim_map, ClaimMap, ClaimedRegion, UnclaimedKind, UnclaimedRegion};
pub use classification::{
    classify_recovery, classify_region_state, RegionClaim, StateAssessment, VideoEvidence,
};
pub use engine::{RecoveryEngine, RecoveryOutcome, RecoveryRequest};
pub use ffmpeg::{
    hash_file_sha256, reverify_artifact_sha256, FfmpegInfo, FfmpegService, ProbeResult,
    RemuxOptions, RemuxResult,
};
pub use fragment::{DiscoveredFragment, DiscoveryMethod, FieldEvidence};
pub use levels::{scan_target, ScanContext, ScanFinding};
pub use metrics::RecoveryMetrics;
pub use plan::{plan_recovery, RecoveryPlan, ScanTarget, CLAIM_PROBE_BYTES, UNCLAIMED_CHUNK_BYTES};
pub use reconstructor::{MediaMetadata, ReconstructionOutput, VideoCodec, VideoReconstructor};
