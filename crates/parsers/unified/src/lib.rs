//! # parser-unified
//!
//! The **unified fallback parser**: the "Unified parser" branch of the pipeline that
//! runs when the confidence engine could not attribute evidence to a supported OEM
//! (the `Unresolved` path in the flow). It is deliberately OEM-agnostic.
//!
//! What it does:
//! * Scans raw bytes for H.264 / H.265 Annex-B NAL start codes and MJPEG SOI markers.
//! * Groups contiguous codec activity into carved recording regions.
//! * Emits generic `Recording` and `TimelineEvent` candidates with provenance.
//!
//! What it never does:
//! * Claim an OEM identity (attribution is the confidence engine's job alone).
//! * Assume a timezone. Carved streams carry no recorder clock, so every timestamp is
//!   `raw = 0` with `TimeZoneState::Unknown` and no normalized instant — never UTC.
//! * Synthesize frames or fill gaps.

#![forbid(unsafe_code)]

pub mod parser;

pub use parser::{CarvedCodec, CarvedRegion, UnifiedParser};
