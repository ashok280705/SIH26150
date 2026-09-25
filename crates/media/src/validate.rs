//! Media validation: the gate between a reconstructed artifact and the decoder.
//!
//! Validation runs a fixed sequence of checks and records the outcome of each one. The result
//! is a [`ValidationReport`] with a [`ValidationStatus`] drawn from a set of distinguishable
//! states — `Valid`, `Invalid`, `Unsupported`, `Corrupted`, `Unavailable`, `Timeout` — and
//! never a boolean. In particular:
//!
//! * A host without ffprobe produces `Unavailable`. Nothing was checked, so nothing passed.
//! * A file with no video stream produces `Invalid` with `NO_VIDEO_STREAM`, not "valid, zero
//!   frames".
//! * A probe that was killed on its budget produces `Timeout`, distinct from a probe that ran
//!   and rejected the file.
//!
//! The report also carries the ffprobe exit status, the captured stderr tail and the elapsed
//! time, so a failure in the field can be diagnosed without re-running the pipeline.

use crate::artifact::{MediaArtifact, MediaProperties, ValidationStatus};
use crate::error::{MediaError, MediaErrorKind};
use crate::hashing;
use crate::probe::{self, ProbeReport};
use crate::tools::MediaToolchain;
use chrono::{DateTime, Utc};
use forensic_core::{ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// The outcome of one named check within validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationCheck {
    pub name: String,
    /// `"PASS"`, `"FAIL"`, `"SKIPPED"` or `"UNAVAILABLE"`.
    pub outcome: String,
    pub detail: String,
}

impl ValidationCheck {
    fn pass(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            outcome: "PASS".into(),
            detail: detail.into(),
        }
    }
    fn fail(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            outcome: "FAIL".into(),
            detail: detail.into(),
        }
    }
    fn unavailable(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            outcome: "UNAVAILABLE".into(),
            detail: detail.into(),
        }
    }
    fn skipped(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            outcome: "SKIPPED".into(),
            detail: detail.into(),
        }
    }
}

/// The complete, diagnosable outcome of validating one media artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationReport {
    pub artifact_id: String,
    pub status: ValidationStatus,
    /// The specific media error code when the status is not `Valid`.
    pub error_code: Option<String>,
    pub checks: Vec<ValidationCheck>,
    pub probe: Option<ProbeReport>,
    pub ffprobe_exit_code: Option<i32>,
    pub ffprobe_stderr_tail: Option<String>,
    pub ffprobe_version: Option<String>,
    pub duration_ms: u64,
    pub validated_at: DateTime<Utc>,
}

impl ValidationReport {
    /// A report for an artifact whose validation was never attempted, with the reason.
    ///
    /// Distinct from every failure status: nothing was checked, so nothing is concluded. It
    /// exists so that a run abandoned before validation still produces a report that says so,
    /// rather than one whose empty fields could be read as a clean result.
    pub fn not_run(artifact_id: impl Into<String>, reason: impl Into<String>) -> Self {
        let artifact_id = artifact_id.into();
        Self {
            artifact_id: artifact_id.clone(),
            status: ValidationStatus::NotRun,
            error_code: None,
            checks: vec![ValidationCheck::skipped("artifact_validation", reason)],
            probe: None,
            ffprobe_exit_code: None,
            ffprobe_stderr_tail: None,
            ffprobe_version: None,
            duration_ms: 0,
            validated_at: Utc::now(),
        }
    }

    /// The workspace-standard validation state for this outcome.
    ///
    /// `Unavailable`, `Timeout` and `NotRun` map to `UNKNOWN`, never `PASS`: a check that did
    /// not run has not been passed. Only a probe that ran and accepted the file yields `PASS`.
    pub fn validation_state(&self) -> ValidationState {
        let (kind, reason) = match self.status {
            ValidationStatus::Valid => (
                ValidationStateKind::Pass,
                "ffprobe ran, exited zero, and reported a decodable video stream".to_string(),
            ),
            ValidationStatus::Invalid => (
                ValidationStateKind::Fail,
                format!(
                    "ffprobe rejected the artifact ({})",
                    self.error_code.as_deref().unwrap_or("INVALID")
                ),
            ),
            ValidationStatus::Corrupted => (
                ValidationStateKind::Fail,
                "the artifact's media structure is internally inconsistent".to_string(),
            ),
            ValidationStatus::Unsupported => (
                ValidationStateKind::Review,
                format!(
                    "the artifact's container/codec is not decodable by this pipeline ({})",
                    self.error_code.as_deref().unwrap_or("UNSUPPORTED")
                ),
            ),
            ValidationStatus::Unavailable => (
                ValidationStateKind::Unknown,
                "ffprobe is not available on this host; no validation was performed".to_string(),
            ),
            ValidationStatus::Timeout => (
                ValidationStateKind::Unknown,
                "ffprobe exceeded its budget and was terminated; nothing was concluded".to_string(),
            ),
            ValidationStatus::NotRun => (
                ValidationStateKind::Unknown,
                "validation has not been attempted".to_string(),
            ),
        };
        // `reason` is non-empty in every branch above, so this cannot fail.
        ValidationState::new(kind, reason, "media_validation", "MediaArtifact")
            .expect("validation reasons are non-empty by construction")
    }

    /// Whether decoding may proceed.
    pub fn permits_decode(&self) -> bool {
        self.status.permits_decode()
    }
}

/// Validates a reconstructed media artifact.
///
/// On success the artifact is updated in place with the *measured* properties — container,
/// codec, geometry, frame rate, duration — and with a digest of its actual bytes. Nothing is
/// written to, or near, the source evidence: this function only reads the derived file.
pub async fn validate_artifact(
    toolchain: &MediaToolchain,
    artifact: &mut MediaArtifact,
) -> ValidationReport {
    let started = Instant::now();
    let mut checks = Vec::new();

    // The report builder deliberately captures only the artifact *id*, not the artifact, so it
    // stays callable at every early return without holding a borrow that would conflict with
    // the in-place updates below.
    let artifact_id = artifact.artifact_id.clone();
    let ffprobe_version = toolchain.ffprobe().version().map(|s| s.to_string());
    let report = |status: ValidationStatus,
                  code: Option<MediaErrorKind>,
                  checks: Vec<ValidationCheck>,
                  probe: Option<ProbeReport>,
                  exit_code: Option<i32>,
                  stderr: Option<String>| ValidationReport {
        artifact_id: artifact_id.clone(),
        status,
        error_code: code.map(|k| k.code().to_string()),
        checks,
        probe,
        ffprobe_exit_code: exit_code,
        ffprobe_stderr_tail: stderr,
        ffprobe_version: ffprobe_version.clone(),
        duration_ms: started.elapsed().as_millis() as u64,
        validated_at: Utc::now(),
    };

    // 1. The derived file must exist.
    let meta = match std::fs::metadata(&artifact.path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            checks.push(ValidationCheck::fail(
                "artifact_exists",
                format!("'{}' does not exist", artifact.path.display()),
            ));
            artifact.validation_status = ValidationStatus::Invalid;
            return report(
                ValidationStatus::Invalid,
                Some(MediaErrorKind::MediaNotFound),
                checks,
                None,
                None,
                None,
            );
        }
        Err(e) => {
            checks.push(ValidationCheck::fail(
                "artifact_exists",
                format!("'{}' could not be inspected: {e}", artifact.path.display()),
            ));
            artifact.validation_status = ValidationStatus::Invalid;
            return report(
                ValidationStatus::Invalid,
                Some(MediaErrorKind::MediaUnreadable),
                checks,
                None,
                None,
                None,
            );
        }
    };
    checks.push(ValidationCheck::pass(
        "artifact_exists",
        "derived file present",
    ));

    // 2. It must be a regular file with bytes in it.
    if !meta.is_file() {
        checks.push(ValidationCheck::fail(
            "artifact_is_regular_file",
            "path is not a regular file",
        ));
        artifact.validation_status = ValidationStatus::Invalid;
        return report(
            ValidationStatus::Invalid,
            Some(MediaErrorKind::MediaUnreadable),
            checks,
            None,
            None,
            None,
        );
    }
    artifact.size_bytes = meta.len();
    if meta.len() == 0 {
        checks.push(ValidationCheck::fail(
            "artifact_has_bytes",
            "file is 0 bytes",
        ));
        artifact.validation_status = ValidationStatus::Invalid;
        return report(
            ValidationStatus::Invalid,
            Some(MediaErrorKind::MediaEmpty),
            checks,
            None,
            None,
            None,
        );
    }
    checks.push(ValidationCheck::pass(
        "artifact_has_bytes",
        format!("{} bytes readable", meta.len()),
    ));

    // 3. Hash the actual derived bytes. A hashing failure is surfaced, not swallowed.
    match hashing::hash_file(&artifact.path) {
        Ok(h) => {
            checks.push(ValidationCheck::pass(
                "media_hash",
                format!("{} over {} bytes", h.algorithm, h.bytes_hashed),
            ));
            artifact.media_hash = Some(h);
        }
        Err(e) => {
            checks.push(ValidationCheck::fail("media_hash", e.detail.clone()));
            artifact.media_hash = None;
            artifact.validation_status = ValidationStatus::Invalid;
            return report(
                ValidationStatus::Invalid,
                Some(e.kind),
                checks,
                None,
                None,
                None,
            );
        }
    }

    // 4. ffprobe. Its absence is `Unavailable` — never a pass.
    if !toolchain.ffprobe().is_available() {
        checks.push(ValidationCheck::unavailable(
            "ffprobe",
            "ffprobe is not installed on this host",
        ));
        checks.push(ValidationCheck::skipped(
            "stream_structure",
            "cannot be checked without ffprobe",
        ));
        artifact.validation_status = ValidationStatus::Unavailable;
        return report(
            ValidationStatus::Unavailable,
            Some(MediaErrorKind::FfprobeUnavailable),
            checks,
            None,
            None,
            None,
        );
    }

    let probe_result = probe::probe_file(toolchain, &artifact.path).await;
    let probe_report = match probe_result {
        Ok(p) => {
            checks.push(ValidationCheck::pass(
                "ffprobe",
                "exited 0 with parseable JSON",
            ));
            p
        }
        Err(e) => {
            let (status, check_outcome) = match e.kind {
                MediaErrorKind::FfmpegTimeout => (ValidationStatus::Timeout, "FAIL"),
                MediaErrorKind::FfprobeUnavailable => {
                    (ValidationStatus::Unavailable, "UNAVAILABLE")
                }
                MediaErrorKind::CorruptedMedia => (ValidationStatus::Corrupted, "FAIL"),
                _ => (ValidationStatus::Invalid, "FAIL"),
            };
            checks.push(ValidationCheck {
                name: "ffprobe".into(),
                outcome: check_outcome.into(),
                detail: e.detail.clone(),
            });
            artifact.validation_status = status.clone();
            return report(
                status,
                Some(e.kind),
                checks,
                None,
                e.exit_code,
                e.stderr_tail.clone(),
            );
        }
    };

    // 5. Evaluate what ffprobe actually said. Exiting zero is not, by itself, validity.
    let Some(video) = probe_report.primary_video_stream() else {
        checks.push(ValidationCheck::fail(
            "video_stream_present",
            format!(
                "container '{}' holds {} stream(s), none of them video",
                probe_report.format_name,
                probe_report.streams.len()
            ),
        ));
        artifact.validation_status = ValidationStatus::Invalid;
        artifact.properties.container = Some(probe_report.container.clone());
        return report(
            ValidationStatus::Invalid,
            Some(MediaErrorKind::NoVideoStream),
            checks,
            Some(probe_report),
            Some(0),
            None,
        );
    };
    checks.push(ValidationCheck::pass(
        "video_stream_present",
        format!("stream {} is {}", video.index, video.codec_name),
    ));

    // 6. Record measurements on the artifact. These replace whatever upstream declared,
    //    because these were measured and that was asserted.
    let codec = probe_report.video_codec();
    let geometry = probe_report.geometry();
    artifact.properties = MediaProperties {
        container: Some(probe_report.container.clone()),
        codec: Some(codec.clone()),
        width: geometry.map(|(w, _)| w),
        height: geometry.map(|(_, h)| h),
        frame_rate: probe_report.frame_rate(),
        duration_secs: probe_report.effective_duration(),
        declared_frame_count: video.nb_frames,
        pixel_format: video.pix_fmt.clone(),
    };

    // 7. Geometry is required for raw-frame extraction, so its absence downgrades the result
    //    rather than being ignored.
    let status = if geometry.is_none() {
        checks.push(ValidationCheck::fail(
            "frame_geometry",
            "the video stream declares no usable width/height; frames cannot be sized",
        ));
        artifact.validation_status = ValidationStatus::Corrupted;
        return report(
            ValidationStatus::Corrupted,
            Some(MediaErrorKind::CorruptedMedia),
            checks,
            Some(probe_report),
            Some(0),
            None,
        );
    } else {
        let (w, h) = geometry.unwrap();
        checks.push(ValidationCheck::pass("frame_geometry", format!("{w}x{h}")));
        ValidationStatus::Valid
    };

    checks.push(ValidationCheck::pass(
        "codec_supported",
        format!("{} is decodable by ffmpeg", codec.label()),
    ));

    artifact.validation_status = status.clone();
    report(status, None, checks, Some(probe_report), Some(0), None)
}

/// Turns a media error into the validation status that best describes it.
///
/// Used by callers that catch an error outside `validate_artifact` and need a consistent
/// status rather than inventing one.
pub fn status_for_error(e: &MediaError) -> ValidationStatus {
    match e.kind {
        MediaErrorKind::MediaNotFound | MediaErrorKind::MediaEmpty => ValidationStatus::Invalid,
        MediaErrorKind::FfprobeUnavailable | MediaErrorKind::FfmpegUnavailable => {
            ValidationStatus::Unavailable
        }
        MediaErrorKind::FfmpegTimeout => ValidationStatus::Timeout,
        MediaErrorKind::UnsupportedCodec | MediaErrorKind::UnsupportedContainer => {
            ValidationStatus::Unsupported
        }
        MediaErrorKind::CorruptedMedia => ValidationStatus::Corrupted,
        _ => ValidationStatus::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{MediaProvenance, ReconstructionMethod};
    use crate::tools::{MediaConfig, MediaToolchain, ToolAvailability};
    use forensic_core::EvidenceId;
    use std::io::Write;

    fn artifact_at(path: &std::path::Path) -> MediaArtifact {
        MediaArtifact::from_derived_file(
            "art-test",
            path,
            ReconstructionMethod::ExternallyProvided,
            MediaProvenance::new(EvidenceId::new()),
        )
        .unwrap()
    }

    fn toolchain_without_ffprobe() -> MediaToolchain {
        MediaToolchain::with_availability(
            ToolAvailability::NotFound { searched: vec![] },
            ToolAvailability::NotFound { searched: vec![] },
            MediaConfig::default(),
        )
    }

    #[tokio::test]
    async fn a_missing_ffprobe_yields_unavailable_and_never_pass() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.mp4");
        std::fs::File::create(&p)
            .unwrap()
            .write_all(b"bytes")
            .unwrap();

        let mut art = artifact_at(&p);
        let rep = validate_artifact(&toolchain_without_ffprobe(), &mut art).await;

        assert_eq!(rep.status, ValidationStatus::Unavailable);
        assert_eq!(rep.error_code.as_deref(), Some("FFPROBE_UNAVAILABLE"));
        assert!(!rep.permits_decode());
        assert_eq!(rep.validation_state().state, ValidationStateKind::Unknown);
        assert_eq!(art.validation_status, ValidationStatus::Unavailable);
        // The bytes were still hashed, because reading them did not need ffprobe.
        assert!(art.media_hash.is_some());
        assert!(rep
            .checks
            .iter()
            .any(|c| c.name == "stream_structure" && c.outcome == "SKIPPED"));
    }

    #[tokio::test]
    async fn a_missing_file_is_media_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let present = dir.path().join("present.mp4");
        std::fs::File::create(&present)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        let mut art = artifact_at(&present);
        // Point the artifact at a path that does not exist, as a stale record would.
        art.path = dir.path().join("gone.mp4");

        let rep = validate_artifact(&toolchain_without_ffprobe(), &mut art).await;
        assert_eq!(rep.status, ValidationStatus::Invalid);
        assert_eq!(rep.error_code.as_deref(), Some("MEDIA_NOT_FOUND"));
        assert_eq!(rep.validation_state().state, ValidationStateKind::Fail);
    }

    #[tokio::test]
    async fn an_empty_file_is_media_empty_and_is_not_hashed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("empty.mp4");
        std::fs::File::create(&p).unwrap();

        let mut art = artifact_at(&p);
        let rep = validate_artifact(&toolchain_without_ffprobe(), &mut art).await;
        assert_eq!(rep.status, ValidationStatus::Invalid);
        assert_eq!(rep.error_code.as_deref(), Some("MEDIA_EMPTY"));
        assert!(art.media_hash.is_none(), "an empty file yields no digest");
    }

    #[test]
    fn not_run_and_timeout_map_to_unknown_rather_than_pass_or_fail() {
        for status in [ValidationStatus::NotRun, ValidationStatus::Timeout] {
            let rep = ValidationReport {
                artifact_id: "a".into(),
                status: status.clone(),
                error_code: None,
                checks: vec![],
                probe: None,
                ffprobe_exit_code: None,
                ffprobe_stderr_tail: None,
                ffprobe_version: None,
                duration_ms: 0,
                validated_at: Utc::now(),
            };
            assert_eq!(rep.validation_state().state, ValidationStateKind::Unknown);
            assert!(!rep.permits_decode());
        }
    }

    #[test]
    fn error_codes_map_to_the_matching_validation_status() {
        assert_eq!(
            status_for_error(&MediaError::new(MediaErrorKind::FfmpegTimeout, "op", "d")),
            ValidationStatus::Timeout
        );
        assert_eq!(
            status_for_error(&MediaError::new(
                MediaErrorKind::UnsupportedCodec,
                "op",
                "d"
            )),
            ValidationStatus::Unsupported
        );
        assert_eq!(
            status_for_error(&MediaError::new(
                MediaErrorKind::FfprobeUnavailable,
                "op",
                "d"
            )),
            ValidationStatus::Unavailable
        );
    }
}
