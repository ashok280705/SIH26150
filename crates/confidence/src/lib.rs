//! # confidence
//!
//! The `Confidence_Engine`, versioned `ConfidenceConfig`, and `ClassifiedDetectionResult`.
//!
//! Constraints this crate must uphold:
//!
//! * This crate is the **only** place `Classification` and `Attribution_Status` are set
//!   (Req 2.6, 10).
//! * `confirmed` requires OEM-exclusive evidence. A lone matching signature never confirms,
//!   and a non-`validated` `Evidence_Status` is never upgraded by score (Req 2.3, 10).
//! * The rule is prefer UNKNOWN over WRONG: insufficient or ambiguous evidence yields
//!   `compatible_candidate`, `Ambiguous`, `Insufficient`, or `Unknown`, never an invented
//!   OEM claim.
//! * Thresholds, margins, quality floors, and weights are versioned, hashed configuration
//!   data, not source constants (Req 10.7; OPEN-4).
//! * Decision rules are applied in the fixed Req 10.11 order, and permuting detector input
//!   order never changes the classification (Req 20).
//!
//! Skeleton only — the engine lands in Phase 2.

#![forbid(unsafe_code)]
