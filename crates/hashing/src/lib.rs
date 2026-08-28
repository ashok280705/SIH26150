//! # hashing
//!
//! The `Hashing_Service` and `HashRecord`: SHA-256 computed by streaming through an
//! `EvidenceReader` in bounded windows, linked to provenance for exports and reports.
//!
//! Constraints this crate must uphold:
//!
//! * Hashing never loads a whole image; multi-terabyte evidence is hashed via bounded
//!   streaming reads (Req 5.1, 8.2).
//! * Every record captures algorithm, status, duration, and bytes hashed so a report can
//!   state exactly what was covered (Req 5).
//! * SHA-256 is required; the `algo` field leaves room for additional algorithms without
//!   a schema change.
//!
//! Skeleton only — the service lands in P1-006/P1-007.

#![forbid(unsafe_code)]
