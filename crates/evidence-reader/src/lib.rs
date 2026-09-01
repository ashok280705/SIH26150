//! # evidence-reader
//!
//! Read-only, streaming access to evidence: the `EvidenceReader` trait, the bounded
//! `RegionScanner`, source-safety inspection, and per-format sources.
//!
//! Constraints this crate must uphold:
//!
//! * The reader never obtains a writable OS handle to evidence, and the trait exposes
//!   **no write method** at the type level (Req 1, 8).
//! * Reads are bounded: no operation allocates memory proportional to total evidence
//!   size, and the maximum window is configuration, not a hard-coded constant (Req 8.2,
//!   8.3; OPEN-2). The bound is loaded from `config/reader.toml` → `[read_window]`
//!   (`max_bytes`, `min_bytes`); see `docs/decisions/OPEN-2-max-read-window.md`. Forensic
//!   results must be identical for every value in the allowed range.
//! * Sparse/unallocated regions are never reported as source truncation; out-of-bounds
//!   requests are rejected with `OutOfBounds` (Req 8.9–8.11).
//! * `.raw`, `.dd`, `.img`, and physical disks are in scope. `.E01` stays a planned,
//!   dependency-gated integration and is not implemented by assumption (Req 8.8; OPEN-1).

// This crate deliberately does not `forbid(unsafe_code)`: read-only memory maps may
// require `unsafe`.

pub mod reader;
pub mod config;
pub mod raw;
pub mod source_safety;
pub mod progress;
pub mod scanner;
pub mod mmap;

pub use reader::{EvidenceReader, SourceKind};
pub use config::ReaderConfig;
pub use raw::RawReader;
pub use source_safety::{SafetyDecision, SourceSafetyReport, inspect_source};
pub use progress::{CancellationToken, ProgressCallback, ProgressInfo};
pub use scanner::{RegionScanner, ScanOptions, ScanReport, TerminationReason};
pub use mmap::ReadOnlyMmap;
