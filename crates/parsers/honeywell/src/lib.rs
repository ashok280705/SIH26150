//! # parser-honeywell
//!
//! Honeywell parser. Implements the common `Parser` interface (Req 6.3) over evidence the
//! confidence engine attributed to the Honeywell storage family.
//!
//! All Honeywell factual knowledge — partition and layout observations, signatures,
//! offsets, validation rules, applicability, and weights — is supplied by versioned profile
//! data under `profiles/honeywell/`, each rule carrying an `Evidence_Status`. Layout
//! observations are model- and firmware-scoped, never universal facts (Req 6.5, 11.7).
//!
//! The parser interprets storage into `Recording`s, `TimeEvidence`, `TimelineEvent`
//! candidates, and a `StructureReport`. It supplies recovery *knowledge* but does not
//! orchestrate recovery, does not build the unified timeline, and never makes the final OEM
//! attribution (Req 3, 12, 15.1).
//!
//! Skeleton only — the parser lands in P3-010.

#![forbid(unsafe_code)]

pub mod parser;

pub use parser::HoneywellParser;
