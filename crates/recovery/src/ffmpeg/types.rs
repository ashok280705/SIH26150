//! Domain and configuration types for FFmpeg & ffprobe operations.

use crate::reconstructor::VideoCodec;
use forensic_core::ValidationState;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The discovery source of the resolved FFmpeg executable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FfmpegSource {
    Configured(PathBuf),
    Environment(PathBuf),
    Bundled(PathBuf),
    Path(PathBuf),
    Unavailable,
}

impl std::fmt::Display for FfmpegSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configured(p) => write!(f, "configured ({})", p.display()),
            Self::Environment(p) => write!(f, "environment ({})", p.display()),
            Self::Bundled(p) => write!(f, "bundled ({})", p.display()),
            Self::Path(p) => write!(f, "system_path ({})", p.display()),
            Self::Unavailable => write!(f, "unavailable"),
        }
    }
}

/// Runtime status and capability information for the FFmpeg environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FfmpegInfo {
    pub available: bool,
    pub executable_path: Option<PathBuf>,
    pub version: Option<String>,
    pub source: FfmpegSource,
    pub capabilities: Vec<String>,
}

/// Parameters configuring a stream-copy remuxing operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemuxOptions {
    pub codec: VideoCodec,
    pub timeout_secs: Option<u64>,
}

impl Default for RemuxOptions {
    fn default() -> Self {
        Self {
            codec: VideoCodec::H264,
            timeout_secs: Some(300), // 5-minute safety timeout
        }
    }
}

/// Output and provenance details from an executed stream-copy remux operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemuxResult {
    pub output_path: PathBuf,
    pub output_size_bytes: u64,
    pub output_sha256: String,
    pub duration_ms: u64,
    pub ffmpeg_version: String,
    pub arguments: Vec<String>,
    pub exit_code: i32,
    pub validation_state: ValidationState,
    pub stderr_log: String,
}

/// Stream metadata extracted via machine-readable ffprobe JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ProbeStream {
    pub index: u32,
    pub codec_name: String,
    pub codec_type: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub pix_fmt: Option<String>,
    pub r_frame_rate: Option<String>,
    pub duration: Option<String>,
    pub nb_frames: Option<String>,
}

/// Overall container and video stream probe results.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProbeResult {
    pub streams: Vec<ProbeStream>,
    pub format_name: String,
    pub duration_secs: Option<f64>,
    pub size_bytes: Option<u64>,
    pub video_codec: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub is_valid_mp4: bool,
}

/// Complete lifecycle state of a forensic artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactLifecycleState {
    Pending,
    Materializing,
    Materialized,
    Processing,
    Generated,
    Validating,
    Validated,
    Failed,
    Cancelled,
}

/// Verification outcome comparing on-disk artifact bytes against stored SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactVerificationResult {
    pub artifact_id: String,
    pub stored_sha256: String,
    pub computed_sha256: String,
    pub status: String, // "MATCH" | "MISMATCH"
    pub verified_at: String,
    pub size_bytes: u64,
}
