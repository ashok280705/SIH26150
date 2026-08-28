//! # forensic-core
//!
//! Shared forensic domain vocabulary for the platform: identifiers, `Hash`, `Region`,
//! `ForensicError`, and the cross-cutting state enums (`Evidence_Status`,
//! `Attribution_Status`, `Validation_State`, `Data_State`, `Recovery_Status`,
//! `Capability_Stage`).
//!
//! Constraints this crate must uphold:
//!
//! * Types are pure and serde-serializable, with no environment coupling, so forensic
//!   results stay deterministic (Req 20).
//! * Fallible operations return `Result<T, ForensicError>`; malformed evidence is data,
//!   not a crash (Req 24.1).
//! * No OEM signature, magic value, offset, or structure is ever declared here. All OEM
//!   factual knowledge is versioned `OEM_Profile` data under `profiles/` (Req 6.1, 11).
//!
//! Skeleton only — types land in P1-002.

#![forbid(unsafe_code)]
