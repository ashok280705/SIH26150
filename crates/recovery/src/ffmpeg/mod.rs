//! # FFmpeg Video Artifact Pipeline Module
//!
//! Exposes modular, forensically sound FFmpeg services for derived artifact containerization.

pub mod command;
pub mod probe;
pub mod service;
pub mod types;

pub use command::{build_file_remux_command, build_probe_command, CommandSpec};
pub use probe::{parse_probe_json, probe_media_file, validate_codec_consistency};
pub use service::{hash_file_sha256, reverify_artifact_sha256, FfmpegService};
pub use types::*;
