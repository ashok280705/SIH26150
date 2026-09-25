//! FFmpeg execution engine, executable discovery, and atomic artifact materialization.

use super::command::build_file_remux_command;
use super::probe::{probe_media_file, validate_codec_consistency};
use super::types::{
    ArtifactVerificationResult, FfmpegInfo, FfmpegSource, ProbeResult, RemuxOptions, RemuxResult,
};
use chrono::Utc;
use forensic_core::{CancelToken, ForensicError, ValidationState, ValidationStateKind};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Service managing external FFmpeg and ffprobe discovery and execution.
#[derive(Debug, Clone)]
pub struct FfmpegService {
    ffmpeg_path: Option<PathBuf>,
    ffprobe_path: Option<PathBuf>,
    ffmpeg_source: FfmpegSource,
    version_string: Option<String>,
}

impl Default for FfmpegService {
    fn default() -> Self {
        Self::discover(None)
    }
}

impl FfmpegService {
    /// Discovers FFmpeg runtime using strict precedence:
    /// 1. Explicit application config
    /// 2. `FORENSIC_FFMPEG_PATH` env var
    /// 3. Application-bundled runtime binary
    /// 4. System PATH
    pub fn discover(configured_path: Option<&Path>) -> Self {
        let (ffmpeg_path, ffmpeg_source) =
            resolve_binary("ffmpeg", configured_path, "FORENSIC_FFMPEG_PATH");
        let (ffprobe_path, _) = resolve_binary("ffprobe", None, "FORENSIC_FFPROBE_PATH");

        let version_string = if let Some(ref path) = ffmpeg_path {
            detect_version(path)
        } else {
            None
        };

        Self {
            ffmpeg_path,
            ffprobe_path,
            ffmpeg_source,
            version_string,
        }
    }

    /// Checks runtime status and returns structured information for forensic provenance.
    pub fn status(&self) -> FfmpegInfo {
        let available = self.ffmpeg_path.is_some() && self.version_string.is_some();
        let mut capabilities = Vec::new();
        if available {
            capabilities.push("stream_copy_h264".to_string());
            capabilities.push("stream_copy_hevc".to_string());
            if self.ffprobe_path.is_some() {
                capabilities.push("ffprobe_media_qc".to_string());
            }
        }

        FfmpegInfo {
            available,
            executable_path: self.ffmpeg_path.clone(),
            version: self.version_string.clone(),
            source: self.ffmpeg_source.clone(),
            capabilities,
        }
    }

    /// Remuxes a materialized elementary stream file into a standard MP4 container using atomic lifecycle.
    ///
    /// Flow:
    /// 1. Verifies input elementary stream exists and output target does not exist (no-overwrite rule).
    /// 2. Spawns FFmpeg writing to temporary `.partial` file.
    /// 3. Monitors execution with cancellation and timeout protection.
    /// 4. Validates process exit code and non-zero output size.
    /// 5. Probes container with ffprobe if available.
    /// 6. Calculates SHA-256 of the generated MP4 bitstream container.
    /// 7. Atomically renames `.partial` to final output path.
    pub async fn remux_elementary_stream_file(
        &self,
        input_es_path: &Path,
        output_final_path: &Path,
        options: RemuxOptions,
        cancel: Option<&CancelToken>,
    ) -> Result<RemuxResult, ForensicError> {
        let Some(ref ffmpeg_bin) = self.ffmpeg_path else {
            return Err(ForensicError::UnsupportedFormat {
                format: "ffmpeg".into(),
                reason: "FFmpeg executable not available on host system (configure path or bundle runtime)".into(),
            });
        };

        if !input_es_path.exists() {
            return Err(ForensicError::io(
                format!(
                    "Input elementary stream '{}' not found",
                    input_es_path.display()
                ),
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Elementary stream artifact missing",
                ),
            ));
        }

        // Enforce no-overwrite rule on finalized artifacts
        if output_final_path.exists() {
            return Err(ForensicError::WriteDenied {
                path: output_final_path.display().to_string(),
                reason: "Destination artifact path already exists; overwriting finalized artifacts is forbidden".into(),
            });
        }

        // Ensure parent output directory exists
        let output_dir = output_final_path.parent().unwrap_or_else(|| Path::new("."));
        let tmp_dir = output_dir.join(".tmp");
        std::fs::create_dir_all(&tmp_dir).map_err(|e| {
            ForensicError::io(
                format!("Creating temporary artifact dir '{}'", tmp_dir.display()),
                e,
            )
        })?;

        // Generate isolated .partial file path
        let partial_id = uuid::Uuid::new_v4();
        let partial_path = tmp_dir.join(format!("{}.mp4.partial", partial_id));

        // Build pure direct argument list
        let cmd_spec = build_file_remux_command(
            &ffmpeg_bin.to_string_lossy(),
            options.codec,
            input_es_path,
            &partial_path,
        )?;

        let start_time = Instant::now();
        let mut cmd = cmd_spec.to_tokio_command();
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            ForensicError::io(format!("Spawning FFmpeg at '{}'", ffmpeg_bin.display()), e)
        })?;

        let mut stderr = child.stderr.take();

        // `options.timeout_secs` is a real budget, not a recorded intention: the wait below is
        // wrapped in it, and when it expires the child is killed and reaped. A configured
        // timeout that never terminates anything reads as a safety control in review while
        // providing none, so it is enforced here rather than merely stored.
        let timeout = options
            .timeout_secs
            .map(std::time::Duration::from_secs)
            .unwrap_or(std::time::Duration::MAX);

        let wait_for_exit = async {
            if let Some(token) = cancel {
                tokio::select! {
                    status_res = child.wait() => {
                        let stderr_bytes = drain(&mut stderr).await;
                        status_res.map(|status| (status, stderr_bytes, false))
                    }
                    _ = async {
                        while !token.is_cancelled() {
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        }
                    } => {
                        let _ = child.kill().await;
                        let status_res = child.wait().await;
                        let stderr_bytes = drain(&mut stderr).await;
                        status_res.map(|status| (status, stderr_bytes, true))
                    }
                }
            } else {
                let status_res = child.wait().await;
                let stderr_bytes = drain(&mut stderr).await;
                status_res.map(|status| (status, stderr_bytes, false))
            }
        };

        let run_result = match tokio::time::timeout(timeout, wait_for_exit).await {
            Ok(res) => res,
            Err(_elapsed) => {
                // Terminate and reap, then delete the partial output. An over-running remux
                // is FFMPEG_TIMEOUT — never a success, and never a half-written artifact.
                let _ = child.kill().await;
                let _ = child.wait().await;
                let _ = std::fs::remove_file(&partial_path);
                return Err(ForensicError::DecodeFailed {
                    context: "remux_elementary_stream_file".into(),
                    reason: format!(
                        "FFMPEG_TIMEOUT: remux exceeded its {}s budget and the child process \
                         was terminated",
                        timeout.as_secs()
                    ),
                });
            }
        };

        let duration_ms = start_time.elapsed().as_millis() as u64;

        let (exit_status, stderr_bytes, was_cancelled) = match run_result {
            Ok(triple) => triple,
            Err(e) => {
                let _ = std::fs::remove_file(&partial_path);
                return Err(ForensicError::io("Awaiting FFmpeg child process", e));
            }
        };

        if was_cancelled {
            let _ = std::fs::remove_file(&partial_path);
            return Err(ForensicError::Cancelled {
                context: "remux_elementary_stream_file".into(),
                bytes_processed: 0,
            });
        }

        let stderr_str = String::from_utf8_lossy(&stderr_bytes).to_string();
        let exit_code = exit_status.code().unwrap_or(-1);

        if !exit_status.success() {
            let _ = std::fs::remove_file(&partial_path);
            return Err(ForensicError::DecodeFailed {
                context: "remux_elementary_stream_file".into(),
                reason: format!(
                    "FFmpeg remux exited with code {}: {}",
                    exit_code,
                    stderr_str.trim()
                ),
            });
        }

        // Validate partial file existence and size
        let metadata = std::fs::metadata(&partial_path).map_err(|e| {
            let _ = std::fs::remove_file(&partial_path);
            ForensicError::io("Reading remuxed partial output metadata", e)
        })?;

        let output_size = metadata.len();
        if output_size == 0 {
            let _ = std::fs::remove_file(&partial_path);
            return Err(ForensicError::DecodeFailed {
                context: "remux_elementary_stream_file".into(),
                reason: "FFmpeg remux produced empty 0-byte output file".into(),
            });
        }

        // Calculate SHA-256 of the generated MP4 bitstream
        let output_sha256 = hash_file_sha256(&partial_path).inspect_err(|_| {
            let _ = std::fs::remove_file(&partial_path);
        })?;

        // Run ffprobe QC if available
        let mut probe_result = ProbeResult::default();
        let validation_state = if let Some(ref ffprobe_bin) = self.ffprobe_path {
            match probe_media_file(&ffprobe_bin.to_string_lossy(), &partial_path).await {
                Ok(pr) => {
                    let val = validate_codec_consistency(options.codec, &pr);
                    probe_result = pr;
                    val
                }
                Err(e) => ValidationState::new(
                    ValidationStateKind::Review,
                    format!("MP4 generated; ffprobe QC check inconclusive: {e}"),
                    "remux_elementary_stream_file",
                    "DerivedMp4",
                )
                .unwrap(),
            }
        } else {
            // ffprobe is absent, so the container was never inspected. An unrun check is
            // UNKNOWN, never PASS: "we could not look" must not render as "we looked and it
            // was fine". The MP4 was written and FFmpeg exited zero — that is a successful
            // *remux*, and it is stated as such — but nothing has validated the container.
            ValidationState::new(
                ValidationStateKind::Unknown,
                format!(
                    "VALIDATION_UNAVAILABLE: stream-copy remux completed ({:?}) but ffprobe is \
                     not available on this host, so the container was not validated",
                    options.codec
                ),
                "remux_elementary_stream_file",
                "DerivedMp4",
            )
            .unwrap()
        };

        // Two-domain atomicity: filesystem atomic rename to finalized artifact path
        if let Some(parent) = output_final_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                let _ = std::fs::remove_file(&partial_path);
                ForensicError::io("Ensuring final artifact parent dir", e)
            })?;
        }

        std::fs::rename(&partial_path, output_final_path).map_err(|e| {
            let _ = std::fs::remove_file(&partial_path);
            ForensicError::io(
                format!(
                    "Atomically renaming '{}' to '{}'",
                    partial_path.display(),
                    output_final_path.display()
                ),
                e,
            )
        })?;

        let _ = probe_result;

        Ok(RemuxResult {
            output_path: output_final_path.to_path_buf(),
            output_size_bytes: output_size,
            output_sha256,
            duration_ms,
            ffmpeg_version: self
                .version_string
                .clone()
                .unwrap_or_else(|| "unknown".into()),
            arguments: cmd_spec.args,
            exit_code,
            validation_state,
            stderr_log: stderr_str,
        })
    }
}

/// Re-verifies an on-disk artifact against its recorded SHA-256 hash.
pub fn reverify_artifact_sha256(
    artifact_id: &str,
    target_path: &Path,
    stored_sha256: &str,
) -> Result<ArtifactVerificationResult, ForensicError> {
    if !target_path.exists() {
        return Err(ForensicError::io(
            format!(
                "Artifact file '{}' not found for verification",
                target_path.display()
            ),
            std::io::Error::new(std::io::ErrorKind::NotFound, "Target artifact missing"),
        ));
    }

    let meta = std::fs::metadata(target_path).map_err(|e| {
        ForensicError::io(
            format!("Reading metadata for '{}'", target_path.display()),
            e,
        )
    })?;

    let computed = hash_file_sha256(target_path)?;
    let is_match = computed.eq_ignore_ascii_case(stored_sha256);

    Ok(ArtifactVerificationResult {
        artifact_id: artifact_id.to_string(),
        stored_sha256: stored_sha256.to_string(),
        computed_sha256: computed,
        status: if is_match {
            "MATCH".to_string()
        } else {
            "MISMATCH".to_string()
        },
        verified_at: Utc::now().to_rfc3339(),
        size_bytes: meta.len(),
    })
}

/// Helper calculating SHA-256 of any file via bounded buffer reads.
pub fn hash_file_sha256(path: &Path) -> Result<String, ForensicError> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|e| {
        ForensicError::io(format!("Opening file for hashing: '{}'", path.display()), e)
    })?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024]; // 64 KiB chunks
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|e| ForensicError::io("Reading chunk for SHA-256", e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Reads a child pipe to end, returning whatever arrived.
///
/// Diagnostics are best-effort: a read error here must not mask the process outcome, which is
/// what the caller actually reports on.
async fn drain(stream: &mut Option<tokio::process::ChildStderr>) -> Vec<u8> {
    let mut bytes = Vec::new();
    if let Some(s) = stream.as_mut() {
        let _ = tokio::io::AsyncReadExt::read_to_end(s, &mut bytes).await;
    }
    bytes
}

fn resolve_binary(
    name: &str,
    configured: Option<&Path>,
    env_var: &str,
) -> (Option<PathBuf>, FfmpegSource) {
    if let Some(cfg) = configured {
        if cfg.exists() {
            return (
                Some(cfg.to_path_buf()),
                FfmpegSource::Configured(cfg.to_path_buf()),
            );
        }
    }

    if let Ok(env_path_str) = std::env::var(env_var) {
        let p = PathBuf::from(env_path_str);
        if p.exists() {
            return (Some(p.clone()), FfmpegSource::Environment(p));
        }
    }

    // Check bundled runtime paths
    let bundled_candidates = [
        PathBuf::from(format!("runtime/ffmpeg/{}", name)),
        PathBuf::from(format!("runtime/ffmpeg/macos/{}", name)),
        PathBuf::from(format!("runtime/ffmpeg/linux/{}", name)),
        PathBuf::from(format!("runtime/ffmpeg/windows/{}.exe", name)),
    ];

    for candidate in &bundled_candidates {
        if candidate.exists() {
            return (
                Some(candidate.clone()),
                FfmpegSource::Bundled(candidate.clone()),
            );
        }
    }

    // Check system PATH
    if let Ok(output) = std::process::Command::new(name).arg("-version").output() {
        if output.status.success() {
            return (
                Some(PathBuf::from(name)),
                FfmpegSource::Path(PathBuf::from(name)),
            );
        }
    }

    (None, FfmpegSource::Unavailable)
}

fn detect_version(path: &Path) -> Option<String> {
    match std::process::Command::new(path).arg("-version").output() {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let first_line = stdout.lines().next().unwrap_or("");
            Some(first_line.to_string())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_sha256_file_hashing() {
        let temp_dir = std::env::temp_dir().join(format!("hash_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let test_file = temp_dir.join("sample.bin");

        let mut f = std::fs::File::create(&test_file).unwrap();
        f.write_all(b"FORENSIC_STREAM_TEST_BYTES").unwrap();
        drop(f);

        let hash = hash_file_sha256(&test_file).unwrap();
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64);

        let reverify = reverify_artifact_sha256("test-art-1", &test_file, &hash).unwrap();
        assert_eq!(reverify.status, "MATCH");

        let mismatch = reverify_artifact_sha256(
            "test-art-1",
            &test_file,
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        assert_eq!(mismatch.status, "MISMATCH");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
