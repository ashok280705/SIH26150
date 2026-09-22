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
//! ## Modules
//!
//! * [`parser`] — the `Parser` trait implementation (filesystem, metadata, recordings,
//!   timeline events, structural validation).
//! * [`dhfs`] — DHFS storage geometry and DIDX recording-index readers. These produce
//!   the OEM-neutral `StorageGeometry`/`RecordingIndex` the recovery engine consumes, so
//!   the engine reasons about physical byte ranges and never about DHFS/DIDX layout.

#![forbid(unsafe_code)]

pub mod dhfs;
pub mod parser;

pub use parser::DahuaParser;
