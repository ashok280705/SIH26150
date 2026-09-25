//! # media
//!
//! The standardized, OEM-agnostic media processing pipeline.
//!
//! This crate sits strictly **downstream** of OEM detection, OEM parsing and the recovery
//! engine. It receives a reconstructed media file plus whatever metadata the upstream layer
//! happens to know, and it takes that information as given. It contains no OEM knowledge, no
//! filesystem interpretation and no recovery heuristics, and it deliberately has no dependency
//! on the `recovery` or `parsers/*` crates — so it cannot acquire any by accident.
//!
//! ```text
//!   Evidence image
//!        │   (OEM detection → OEM parser → recovery engine — not this crate)
//!        ▼
//!   Recovered / referenced recording
//!        │   (media reconstruction writes a DERIVED file — never touches evidence)
//!        ▼
//!   MediaArtifact ──► validate ──► decode ──► VideoFrame ──► process ──► analysis
//! ```
//!
//! ## What this crate guarantees
//!
//! * **Nothing is invented.** A property the upstream layer does not supply, and that no probe
//!   established, is `Unknown`/`None` and renders as `UNKNOWN`. See [`artifact`].
//! * **Unrun is not passed.** A host without ffprobe yields `VALIDATION_UNAVAILABLE`, not a
//!   pass. See [`validate`].
//! * **Decoding is decoding.** [`decode`] asks FFmpeg for `-f rawvideo`, which requires the
//!   decoder to run; a stream copy cannot satisfy it. Frames carry real pixels.
//! * **Timeouts terminate.** [`exec`] enforces its budget by killing and reaping the child, and
//!   reports `FFMPEG_TIMEOUT`. Concurrency is bounded by a configurable permit pool.
//! * **Provenance survives.** Evidence id, artifact id, source offset, media hash, frame id,
//!   frame hash, timestamp and its source, and every processing step travel with the frame.
//! * **AI is never claimed.** With no engine registered, [`analysis`] reports
//!   `AI_ANALYSIS_NOT_CONFIGURED` and returns zero observations. This crate ships no detector.
//! * **Evidence is read-only.** Nothing here opens the evidence image at all; it reads only
//!   derived files, which the upstream layer wrote to a separate derived-artifact location.
//!
//! ## Optional OpenCV
//!
//! Image processing has two interchangeable backends and always reports which one ran, by name
//! and — for OpenCV — by the native library's own version string. A caller that must have one
//! specific backend sets [`pipeline::ProcessingPlan::require_backend`] and gets an explicit
//! failure rather than a substitution. See [`process`] for why the `opencv-backend` feature is
//! optional, what the fallback does, and exactly how closely the two agree.
//!
//! The native OpenCV backend has **not** been compiled or executed on any host to date. The
//! code is written against the `opencv` 0.94 API and is structurally complete; that is a
//! different statement from "verified", and this crate does not make the second one. See
//! `docs/MEDIA_PIPELINE_VERIFICATION.md`.

#![forbid(unsafe_code)]

pub mod analysis;
pub mod artifact;
pub mod decode;
pub mod error;
pub mod exec;
pub mod frame;
pub mod hashing;
pub mod pipeline;
pub mod probe;
pub mod process;
pub mod tools;
pub mod validate;

pub use analysis::{
    AnalysisEngine, AnalysisInput, AnalysisPipeline, AnalysisResult, EngineIdentity,
    FrameObservation, AI_NOT_CONFIGURED,
};
pub use artifact::{
    CodecKind, ContainerType, ContentHash, MediaArtifact, MediaProperties, MediaProvenance,
    ReconstructionMethod, ReconstructionStatus, SourceByteRange, ValidationStatus,
};
pub use decode::{
    decode_frames, decode_frames_with, DecodeMetrics, DecodeReport, DecodeRequest,
    DecodeStopReason, ExtractionMode, FrameAction, SeekAccuracy,
};
pub use error::{MediaError, MediaErrorKind, MediaResult};
pub use exec::{CommandSpec, ProcessLimits, ProcessOutcome, ProcessRunner};
pub use frame::{
    FrameProvenance, FrameTiming, PixelFormat, ProcessingStep, TimestampSource, VideoFrame,
};
pub use pipeline::{MediaPipeline, MediaPipelineReport, ProcessingPlan, StageOutcome};
pub use probe::{ProbeReport, ProbeStream};
pub use process::{
    active_backend, backend_identity, FrameProcessor, FrameQuality, ProcessingBackend, Roi,
};
pub use tools::{MediaConfig, MediaToolchain, ToolAvailability, ToolPaths, ToolSource};
pub use validate::{validate_artifact, ValidationCheck, ValidationReport};
