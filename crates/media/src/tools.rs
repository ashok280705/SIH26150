//! Discovery and configuration of the external media toolchain.
//!
//! `ffmpeg` and `ffprobe` are discovered independently: a host can easily have one and not the
//! other, and the pipeline must report that honestly rather than inferring one from the other.
//! An absent tool is [`ToolAvailability::NotFound`] — never a silent pass.

use crate::error::{MediaError, MediaErrorKind, MediaResult};
use crate::exec::{
    ProcessLimits, ProcessRunner, DEFAULT_MAX_CONCURRENT_PROCESSES, DEFAULT_PROCESS_TIMEOUT_SECS,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Where a resolved executable came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolSource {
    Configured,
    Environment,
    Bundled,
    SystemPath,
}

/// Whether a tool is usable, and on what evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolAvailability {
    /// The executable ran `-version` successfully.
    Available {
        path: PathBuf,
        source: ToolSource,
        version: String,
    },
    /// The executable could not be located, or could not be executed.
    NotFound { searched: Vec<String> },
}

impl ToolAvailability {
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }

    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Available { path, .. } => Some(path.as_path()),
            Self::NotFound { .. } => None,
        }
    }

    pub fn version(&self) -> Option<&str> {
        match self {
            Self::Available { version, .. } => Some(version.as_str()),
            Self::NotFound { .. } => None,
        }
    }
}

/// Tunables for the whole media subsystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaConfig {
    /// Wall-clock budget for a single probe run.
    pub probe_timeout: Duration,
    /// Wall-clock budget for a single decode run.
    pub decode_timeout: Duration,
    /// Maximum simultaneous FFmpeg/ffprobe children across the whole process.
    pub max_concurrent_processes: usize,
    /// Trailing stderr bytes retained per run.
    pub stderr_tail_bytes: usize,
    /// Hard ceiling on the byte size of a single decoded frame.
    ///
    /// This bounds peak memory for adversarial or mis-probed geometry: a corrupt header
    /// claiming 65535x65535 would otherwise ask for a 12 GiB allocation per frame.
    pub max_frame_bytes: usize,
    /// Hard ceiling on frames produced by one extraction request.
    pub max_frames_per_request: u64,
}

impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            // Probing reads headers, so it is fast; a long budget here only delays a clear
            // failure.
            probe_timeout: Duration::from_secs(60),
            decode_timeout: Duration::from_secs(DEFAULT_PROCESS_TIMEOUT_SECS),
            max_concurrent_processes: DEFAULT_MAX_CONCURRENT_PROCESSES,
            stderr_tail_bytes: crate::exec::DEFAULT_STDERR_TAIL_BYTES,
            // 4096x4096 BGR24 = 48 MiB, comfortably above any DVR resolution.
            max_frame_bytes: 64 * 1024 * 1024,
            max_frames_per_request: 10_000,
        }
    }
}

impl MediaConfig {
    pub fn probe_limits(&self) -> ProcessLimits {
        ProcessLimits {
            timeout: self.probe_timeout,
            stderr_tail_bytes: self.stderr_tail_bytes,
            // ffprobe JSON for a pathological stream list is still small; 16 MiB is generous.
            max_stdout_bytes: Some(16 * 1024 * 1024),
        }
    }

    pub fn decode_limits(&self) -> ProcessLimits {
        ProcessLimits {
            timeout: self.decode_timeout,
            stderr_tail_bytes: self.stderr_tail_bytes,
            // Decoding uses the streaming path; stdout is never captured whole.
            max_stdout_bytes: Some(0),
        }
    }
}

/// Explicit executable overrides, e.g. from application configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolPaths {
    pub ffmpeg: Option<PathBuf>,
    pub ffprobe: Option<PathBuf>,
}

/// The discovered toolchain plus the bounded runner every media operation shares.
#[derive(Debug, Clone)]
pub struct MediaToolchain {
    ffmpeg: ToolAvailability,
    ffprobe: ToolAvailability,
    config: MediaConfig,
    runner: ProcessRunner,
}

impl Default for MediaToolchain {
    fn default() -> Self {
        Self::discover(&ToolPaths::default(), MediaConfig::default())
    }
}

impl MediaToolchain {
    /// Discovers both executables using the precedence:
    /// explicit configuration, environment variable, bundled runtime, system PATH.
    pub fn discover(paths: &ToolPaths, config: MediaConfig) -> Self {
        let runner = ProcessRunner::new(config.max_concurrent_processes);
        Self {
            ffmpeg: resolve("ffmpeg", paths.ffmpeg.as_deref(), "FORENSIC_FFMPEG_PATH"),
            ffprobe: resolve("ffprobe", paths.ffprobe.as_deref(), "FORENSIC_FFPROBE_PATH"),
            config,
            runner,
        }
    }

    /// Builds a toolchain with explicitly stated availability. Used by tests to exercise the
    /// "tool absent" paths on a host that happens to have the tool installed.
    pub fn with_availability(
        ffmpeg: ToolAvailability,
        ffprobe: ToolAvailability,
        config: MediaConfig,
    ) -> Self {
        let runner = ProcessRunner::new(config.max_concurrent_processes);
        Self {
            ffmpeg,
            ffprobe,
            config,
            runner,
        }
    }

    pub fn ffmpeg(&self) -> &ToolAvailability {
        &self.ffmpeg
    }

    pub fn ffprobe(&self) -> &ToolAvailability {
        &self.ffprobe
    }

    pub fn config(&self) -> &MediaConfig {
        &self.config
    }

    pub fn runner(&self) -> &ProcessRunner {
        &self.runner
    }

    /// The ffmpeg executable path, or `FFMPEG_UNAVAILABLE`.
    pub fn require_ffmpeg(&self, operation: &str) -> MediaResult<&Path> {
        self.ffmpeg.path().ok_or_else(|| {
            MediaError::new(
                MediaErrorKind::FfmpegUnavailable,
                operation,
                "ffmpeg was not found on this host; no decoding was attempted",
            )
        })
    }

    /// The ffprobe executable path, or `FFPROBE_UNAVAILABLE`.
    pub fn require_ffprobe(&self, operation: &str) -> MediaResult<&Path> {
        self.ffprobe.path().ok_or_else(|| {
            MediaError::new(
                MediaErrorKind::FfprobeUnavailable,
                operation,
                "ffprobe was not found on this host; no validation was performed",
            )
        })
    }

    /// Capability report for the API/UI.
    ///
    /// Every capability listed here is one this build can actually perform. `frame_decode` is
    /// only listed when ffmpeg is present, and the OpenCV entry reflects the compiled feature,
    /// not a wish.
    pub fn status(&self) -> serde_json::Value {
        let mut capabilities = Vec::new();
        if self.ffprobe.is_available() {
            capabilities.push("media_probe");
            capabilities.push("media_validation");
        }
        if self.ffmpeg.is_available() {
            capabilities.push("stream_copy_remux");
            capabilities.push("frame_decode");
            capabilities.push("frame_sampling");
            capabilities.push("time_range_extraction");
        }
        capabilities.push(crate::process::BACKEND_CAPABILITY);

        serde_json::json!({
            "ffmpeg": self.ffmpeg,
            "ffprobe": self.ffprobe,
            "capabilities": capabilities,
            // The backend this build will use, with the native library's own version where
            // there is one. A capability, not a claim that anything has been processed.
            "image_processing_backend": crate::process::backend_identity(),
            "max_concurrent_processes": self.config.max_concurrent_processes,
            "probe_timeout_secs": self.config.probe_timeout.as_secs(),
            "decode_timeout_secs": self.config.decode_timeout.as_secs(),
            "ai_analysis": crate::analysis::AI_NOT_CONFIGURED,
        })
    }
}

fn resolve(name: &str, configured: Option<&Path>, env_var: &str) -> ToolAvailability {
    let mut searched = Vec::new();

    if let Some(cfg) = configured {
        searched.push(format!("configured: {}", cfg.display()));
        if let Some(v) = probe_version(cfg) {
            return ToolAvailability::Available {
                path: cfg.to_path_buf(),
                source: ToolSource::Configured,
                version: v,
            };
        }
    }

    if let Ok(env_path) = std::env::var(env_var) {
        let p = PathBuf::from(&env_path);
        searched.push(format!("{env_var}: {env_path}"));
        if let Some(v) = probe_version(&p) {
            return ToolAvailability::Available {
                path: p,
                source: ToolSource::Environment,
                version: v,
            };
        }
    }

    // Check executable-relative and bundled application resource locations
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            let exe_candidates = [
                parent.join(name),
                parent.join(format!("{name}.exe")),
                parent.join("ffmpeg").join(name),
                parent.join("ffmpeg").join(format!("{name}.exe")),
                parent.join("../Resources").join(name),
                parent.join("../Resources").join(format!("{name}.exe")),
                parent.join("../Resources/ffmpeg").join(name),
                parent.join("../Resources/ffmpeg").join(format!("{name}.exe")),
                parent.join("../Resources/runtime/ffmpeg").join(name),
                parent.join("../Resources/runtime/ffmpeg").join(format!("{name}.exe")),
            ];
            for candidate in &exe_candidates {
                if candidate.exists() {
                    searched.push(format!("executable_relative: {}", candidate.display()));
                    if let Some(v) = probe_version(candidate) {
                        return ToolAvailability::Available {
                            path: candidate.clone(),
                            source: ToolSource::Bundled,
                            version: v,
                        };
                    }
                }
            }
        }
    }

    for candidate in [
        PathBuf::from(format!("runtime/ffmpeg/{name}")),
        PathBuf::from(format!("runtime/ffmpeg/linux/{name}")),
        PathBuf::from(format!("runtime/ffmpeg/macos/{name}")),
        PathBuf::from(format!("runtime/ffmpeg/windows/{name}.exe")),
    ] {
        if candidate.exists() {
            searched.push(format!("bundled: {}", candidate.display()));
            if let Some(v) = probe_version(&candidate) {
                return ToolAvailability::Available {
                    path: candidate,
                    source: ToolSource::Bundled,
                    version: v,
                };
            }
        }
    }

    searched.push(format!("PATH: {name}"));
    let bare = PathBuf::from(name);
    if let Some(v) = probe_version(&bare) {
        return ToolAvailability::Available {
            path: bare,
            source: ToolSource::SystemPath,
            version: v,
        };
    }

    ToolAvailability::NotFound { searched }
}

/// Runs `-version` and returns the first line. A tool that cannot report a version is not
/// treated as available: presence of a file proves nothing about whether it will run.
fn probe_version(path: &Path) -> Option<String> {
    let output = std::process::Command::new(path)
        .arg("-version")
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines().next().map(|l| l.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_executable_resolves_to_not_found_with_the_search_trail() {
        let availability = resolve(
            "ffprobe-not-installed-7c1d4e",
            None,
            "FORENSIC_NO_SUCH_VAR_7C1D4E",
        );
        assert!(!availability.is_available());
        match availability {
            ToolAvailability::NotFound { searched } => {
                assert!(searched.iter().any(|s| s.contains("PATH")));
            }
            _ => panic!("expected NotFound"),
        }
    }

    #[test]
    fn require_reports_the_dependency_code_rather_than_a_decode_failure() {
        let tc = MediaToolchain::with_availability(
            ToolAvailability::NotFound { searched: vec![] },
            ToolAvailability::NotFound { searched: vec![] },
            MediaConfig::default(),
        );
        assert_eq!(
            tc.require_ffmpeg("decode").unwrap_err().kind,
            MediaErrorKind::FfmpegUnavailable
        );
        assert_eq!(
            tc.require_ffprobe("validate").unwrap_err().kind,
            MediaErrorKind::FfprobeUnavailable
        );
    }

    #[test]
    fn status_lists_no_decode_capability_when_ffmpeg_is_absent() {
        let tc = MediaToolchain::with_availability(
            ToolAvailability::NotFound { searched: vec![] },
            ToolAvailability::NotFound { searched: vec![] },
            MediaConfig::default(),
        );
        let s = tc.status();
        let caps = s["capabilities"].as_array().unwrap();
        assert!(!caps.iter().any(|c| c == "frame_decode"));
        assert!(!caps.iter().any(|c| c == "media_validation"));
        assert_eq!(s["ai_analysis"], "AI_ANALYSIS_NOT_CONFIGURED");
    }

    #[test]
    fn status_lists_decode_capability_when_ffmpeg_is_present() {
        let tc = MediaToolchain::with_availability(
            ToolAvailability::Available {
                path: PathBuf::from("ffmpeg"),
                source: ToolSource::SystemPath,
                version: "ffmpeg version 6.0".into(),
            },
            ToolAvailability::Available {
                path: PathBuf::from("ffprobe"),
                source: ToolSource::SystemPath,
                version: "ffprobe version 6.0".into(),
            },
            MediaConfig::default(),
        );
        let s = tc.status();
        let caps = s["capabilities"].as_array().unwrap();
        assert!(caps.iter().any(|c| c == "frame_decode"));
        assert!(caps.iter().any(|c| c == "media_probe"));
    }

    #[test]
    fn limits_are_derived_from_configuration_not_from_constants_at_the_call_site() {
        let cfg = MediaConfig {
            probe_timeout: Duration::from_secs(7),
            decode_timeout: Duration::from_secs(11),
            max_concurrent_processes: 3,
            ..Default::default()
        };
        assert_eq!(cfg.probe_limits().timeout, Duration::from_secs(7));
        assert_eq!(cfg.decode_limits().timeout, Duration::from_secs(11));
        let tc = MediaToolchain::with_availability(
            ToolAvailability::NotFound { searched: vec![] },
            ToolAvailability::NotFound { searched: vec![] },
            cfg,
        );
        assert_eq!(tc.runner().max_concurrent(), 3);
    }
}
