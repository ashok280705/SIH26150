//! # detection
//!
//! The common `Detector` interface (Req 6.4), the `OEM_Profile` loader, `EvidenceItem`,
//! `DetectorOutput`, and the `Detection_Orchestrator` that runs every available detector
//! in parallel over one read-only reader.
//!
//! Constraints this crate must uphold:
//!
//! * A `DetectorOutput` carries evidence and a `Detection_Status` only. It has **no**
//!   attribution field: a detector can never claim an OEM. `Attribution_Status` is written
//!   solely by the confidence engine (Req 2.6).
//! * Detectors reason over storage-structure evidence only. Recording, packet, frame, and
//!   video content interpretation belongs to the parsers and downstream stages (Req 3.1).
//! * OEM signatures, offsets, structures, and validation rules arrive as versioned profile
//!   data. The profile loader is strict and fail-closed: it rejects any rule missing an
//!   `evidence_status`, and any malformed profile, with `ProfileInvalid` (Req 6.1, 11.5,
//!   11.8).
//! * Adding a profile plus a detector impl joins a new OEM automatically — no orchestration
//!   edits (Req 6.2).
//! * `Evidence_Status` (how well established the profile rule is) and `rule_match_status`
//!   (whether the observed bytes matched the expectation) are distinct axes, never
//!   conflated.
//! * Ordering is content-derived and stable so parallelism never changes a result (Req
//!   9, 20.4).
//!
//! Skeleton only — the trait and orchestrator land in Phase 2.

#![forbid(unsafe_code)]
