//! # timeline
//!
//! The `Timeline_Engine`: normalizes `TimeEvidence`, builds the unified cross-camera
//! timeline, and correlates events across cameras.
//!
//! Constraints this crate must uphold:
//!
//! * Raw and recorder-native timestamps are preserved verbatim and never overwritten by a
//!   normalized value; `raw` is always recoverable (Req 4).
//! * An unknown timezone stays `Unknown` and is never silently treated as UTC (Req 4.5–4.7).
//! * Physical storage order is not chronological order; the two are reported distinctly
//!   (Req 15).
//! * The engine owns unified-timeline construction; parsers only extract `TimelineEvent`
//!   candidates (Req 15.1).
//!
//! Skeleton only — the engine lands in Phase 5.

#![forbid(unsafe_code)]

pub mod clock;
pub mod correlation;
pub mod engine;
pub mod gaps;
pub mod sessions;

pub use clock::{apply_correction, compute_correction, ClockAnchor};
pub use correlation::{CorrelatedEventGroup, CrossCameraCorrelator};
pub use engine::{TimelineEngine, TimelineOrdering, UnifiedTimeline};
pub use gaps::{
    analyze as analyze_gaps, CoverageEstimate, GapAnalysis, TimelineGap, UnaccountedRegion,
};
pub use sessions::{
    build_recording_timeline, build_recording_timeline_with_examiner_tz, parse_timezone_offset,
    resolve_timezone_offset, RecordingSegment, RecordingSession, RecordingTimeline, SessionGap,
    TemporalBasis,
};
