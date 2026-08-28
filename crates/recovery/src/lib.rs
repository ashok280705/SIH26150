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
//! Skeleton only — the engine lands in Phase 4.

#![forbid(unsafe_code)]
