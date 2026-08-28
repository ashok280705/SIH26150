//! # parser-dahua
//!
//! Dahua parser. Implements the common `Parser` interface (Req 6.3) over evidence the
//! confidence engine attributed to the Dahua storage family.
//!
//! All Dahua factual knowledge — signatures, offsets, structure layouts, validation rules,
//! applicability, and weights — is supplied by versioned profile data under
//! `profiles/dahua/`, each rule carrying an `Evidence_Status`. Nothing OEM-specific is
//! declared as a source constant (Req 6.1, 11.5).
//!
//! The parser interprets storage into `Recording`s, `TimeEvidence`, `TimelineEvent`
//! candidates, and a `StructureReport`. It supplies recovery *knowledge* but does not
//! orchestrate recovery, does not build the unified timeline, and never makes the final OEM
//! attribution (Req 3, 12, 15.1).
//!
//! Skeleton only — the parser lands in P3-008.

#![forbid(unsafe_code)]
