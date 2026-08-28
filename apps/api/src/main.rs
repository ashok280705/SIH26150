//! # forensic-api
//!
//! Axum/Tokio HTTP API for the DVR/NVR forensic platform. This is the **only** crate in the
//! workspace permitted to touch the network or the database; the forensic core crates stay
//! pure, offline, and testable (design.md → Workspace Layout rationale).
//!
//! Responsibilities as later tasks fill it in:
//!
//! * wire the forensic core crates behind REST endpoints,
//! * own the PostgreSQL connection and metadata persistence (never raw multi-TB media),
//! * map `ForensicError` to structured HTTP problem responses,
//! * return a job id and stream progress for long-running operations,
//! * serve all raw-byte access through the read-only `EvidenceReader` by evidence id,
//!   offset, and length — never arbitrary filesystem paths.
//!
//! Endpoints are unauthenticated until the auth task lands; nothing here binds a socket yet.
//!
//! Skeleton only — no routes, no listener, no database.

fn main() {
    // Intentionally empty: the API is wired up in later Phase 1 and Phase 2 tasks.
}
