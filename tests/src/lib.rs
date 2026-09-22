//! # forensic-tests
//!
//! Cross-crate test support: shared harness helpers and the **synthetic fixture generator**
//! that produces small, deterministic images embedding profile-shaped structures so tests
//! run in CI without real HDDs.
//!
//! Constraints this crate must uphold:
//!
//! * Synthetic fixtures are explicitly labeled `synthetic` and are **never** described or
//!   used as real OEM forensic evidence (Req 19).
//! * Fixtures are deterministic: the same generator inputs always produce the same bytes.
//! * A fixture containing only a lone magic value must not pass OEM detection.
//!
//! The workspace layout assertions for `P1-001` live in `tests/workspace_layout.rs`.

#![forbid(unsafe_code)]

pub mod corpus;
pub mod dahua_fixtures;
pub mod fixtures;
pub mod recording_reader;
