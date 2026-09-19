//! # FFmpeg Video Artifact Pipeline Module
//!
//! Exposes modular, forensically sound FFmpeg services for derived artifact containerization.

pub mod types;
pub mod command;
pub mod probe;
pub mod service;

pub use types::*;
pub use command::{build_file_remux_command, build_probe_command, CommandSpec};
pub use probe::{probe_media_file, parse_probe_json, validate_codec_consistency};
pub use service::{FfmpegService, hash_file_sha256, reverify_artifact_sha256};
