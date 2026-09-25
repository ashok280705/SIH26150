//! Explicit media-pipeline error states.
//!
//! A forensic operator needs to know *what* happened, so this module never collapses an
//! outcome into `Ok(false)` or a bare string. [`MediaErrorKind`] is a closed set of machine
//! readable codes; [`MediaError`] carries the code plus the diagnostic context that produced
//! it.
//!
//! This is deliberately NOT a second, competing error system: [`MediaError`] converts into the
//! workspace's [`forensic_core::ForensicError`] via `From`, so a media failure crossing into
//! the existing API/recovery layers arrives as the error type those layers already handle. The
//! extra structure exists because `ForensicError` has no vocabulary for "ffprobe is not
//! installed" as distinct from "ffprobe said this file is broken", and a forensic report must
//! not conflate the two.

use forensic_core::ForensicError;
use serde::{Deserialize, Serialize};

/// Machine-readable media-pipeline outcome codes.
///
/// The string spelling produced by [`MediaErrorKind::code`] is the stable contract used by the
/// API, the UI and the verification procedure. It is a SCREAMING_SNAKE_CASE token, never a
/// prose sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MediaErrorKind {
    /// The artifact path does not exist.
    MediaNotFound,
    /// The artifact exists but holds zero bytes.
    MediaEmpty,
    /// The artifact could not be read (permissions, I/O fault, truncation mid-read).
    MediaUnreadable,
    /// The container format is recognised but not handled by this pipeline.
    UnsupportedContainer,
    /// The codec is recognised but this pipeline cannot decode it.
    UnsupportedCodec,
    /// Structure is present but internally inconsistent or truncated.
    CorruptedMedia,
    /// `ffprobe` ran and exited non-zero.
    FfprobeFailed,
    /// `ffprobe` could not be located on this host. NOT a validation pass.
    FfprobeUnavailable,
    /// `ffmpeg` ran and exited non-zero.
    FfmpegFailed,
    /// `ffmpeg` could not be located on this host.
    FfmpegUnavailable,
    /// The child process exceeded its wall-clock budget and was terminated.
    FfmpegTimeout,
    /// Decoding started but did not produce a usable picture.
    DecodeFailed,
    /// The container carries no video stream at all.
    NoVideoStream,
    /// Frame extraction failed after decoding began (short read, geometry mismatch, …).
    FrameExtractionFailed,
    /// An OpenCV-backed operation was requested but this build has no OpenCV backend.
    OpencvUnavailable,
    /// OpenCV was present and ran, but the library call itself failed.
    ///
    /// Deliberately distinct from [`Self::InvalidFrame`]. An OpenCV fault is a property of this
    /// host's image-processing library — a bad build, an unsupported `Mat` type, an internal
    /// assertion — and says nothing whatsoever about the evidence. Collapsing the two would
    /// make a broken OpenCV installation read as corrupt evidence, which is exactly the
    /// misattribution this crate exists to avoid.
    OpencvOperationFailed,
    /// A frame failed its own structural checks (byte length vs. declared geometry).
    InvalidFrame,
    /// No AI engine is configured; nothing was inferred and nothing is claimed.
    AiNotConfigured,
    /// The caller cancelled the operation.
    Cancelled,
    /// A requested configuration is not satisfiable (e.g. sampling interval of zero).
    InvalidConfiguration,
}

impl MediaErrorKind {
    /// The stable token for this outcome, e.g. `"FFMPEG_TIMEOUT"`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MediaNotFound => "MEDIA_NOT_FOUND",
            Self::MediaEmpty => "MEDIA_EMPTY",
            Self::MediaUnreadable => "MEDIA_UNREADABLE",
            Self::UnsupportedContainer => "UNSUPPORTED_CONTAINER",
            Self::UnsupportedCodec => "UNSUPPORTED_CODEC",
            Self::CorruptedMedia => "CORRUPTED_MEDIA",
            Self::FfprobeFailed => "FFPROBE_FAILED",
            Self::FfprobeUnavailable => "FFPROBE_UNAVAILABLE",
            Self::FfmpegFailed => "FFMPEG_FAILED",
            Self::FfmpegUnavailable => "FFMPEG_UNAVAILABLE",
            Self::FfmpegTimeout => "FFMPEG_TIMEOUT",
            Self::DecodeFailed => "DECODE_FAILED",
            Self::NoVideoStream => "NO_VIDEO_STREAM",
            Self::FrameExtractionFailed => "FRAME_EXTRACTION_FAILED",
            Self::OpencvUnavailable => "OPENCV_UNAVAILABLE",
            Self::OpencvOperationFailed => "OPENCV_OPERATION_FAILED",
            Self::InvalidFrame => "INVALID_FRAME",
            Self::AiNotConfigured => "AI_NOT_CONFIGURED",
            Self::Cancelled => "CANCELLED",
            Self::InvalidConfiguration => "INVALID_CONFIGURATION",
        }
    }

    /// Whether the code describes a missing host dependency rather than a property of the
    /// media.
    ///
    /// The distinction matters because "we could not check" must never be rendered as "we
    /// checked and it is fine", and it must never be rendered as "the evidence is bad" either.
    pub fn is_dependency_unavailable(&self) -> bool {
        matches!(
            self,
            Self::FfprobeUnavailable | Self::FfmpegUnavailable | Self::OpencvUnavailable
        )
    }

    /// Whether the code describes a fault in this host's tooling rather than in the evidence.
    ///
    /// A missing dependency and a dependency that ran and failed are both facts about the
    /// machine. Neither is a finding about the media, and neither may be rendered as one.
    pub fn is_implementation_fault(&self) -> bool {
        self.is_dependency_unavailable()
            || matches!(
                self,
                Self::OpencvOperationFailed | Self::FfprobeFailed | Self::FfmpegFailed
            )
    }

    /// Whether the code describes a property of the media itself.
    ///
    /// The complement of [`Self::is_implementation_fault`] for the codes where the distinction
    /// is load-bearing: these are the only ones a report may present as a finding about the
    /// evidence.
    pub fn is_evidence_fault(&self) -> bool {
        matches!(
            self,
            Self::CorruptedMedia
                | Self::InvalidFrame
                | Self::MediaEmpty
                | Self::UnsupportedContainer
                | Self::UnsupportedCodec
                | Self::NoVideoStream
        )
    }
}

impl std::fmt::Display for MediaErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

/// A media-pipeline failure: a code, the operation that produced it, and its diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaError {
    pub kind: MediaErrorKind,
    /// The operation that failed, e.g. `"decode_frames"`.
    pub operation: String,
    /// Human-readable detail. Never empty.
    pub detail: String,
    /// Captured child-process stderr tail, when a child process was involved.
    pub stderr_tail: Option<String>,
    /// Child-process exit code, when a child process ran to completion.
    pub exit_code: Option<i32>,
}

impl MediaError {
    pub fn new(
        kind: MediaErrorKind,
        operation: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        let detail = detail.into();
        Self {
            kind,
            operation: operation.into(),
            detail: if detail.trim().is_empty() {
                kind.code().to_string()
            } else {
                detail
            },
            stderr_tail: None,
            exit_code: None,
        }
    }

    /// Attaches captured child-process diagnostics.
    pub fn with_process(mut self, exit_code: Option<i32>, stderr_tail: impl Into<String>) -> Self {
        let tail = stderr_tail.into();
        self.exit_code = exit_code;
        self.stderr_tail = if tail.trim().is_empty() {
            None
        } else {
            Some(tail)
        };
        self
    }

    /// The stable token, for API responses and UI labels.
    pub fn code(&self) -> &'static str {
        self.kind.code()
    }
}

impl std::fmt::Display for MediaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {} — {}",
            self.kind.code(),
            self.operation,
            self.detail
        )?;
        if let Some(code) = self.exit_code {
            write!(f, " (exit {code})")?;
        }
        Ok(())
    }
}

impl std::error::Error for MediaError {}

/// Bridges into the workspace error type so media failures travel through existing APIs.
///
/// The mapping keeps the media code inside the message so it survives the conversion; the
/// structured [`MediaError`] is what callers should prefer when they can hold it.
impl From<MediaError> for ForensicError {
    fn from(e: MediaError) -> Self {
        let message = e.to_string();
        match e.kind {
            MediaErrorKind::MediaNotFound => ForensicError::io(
                message,
                std::io::Error::new(std::io::ErrorKind::NotFound, e.kind.code()),
            ),
            MediaErrorKind::MediaUnreadable | MediaErrorKind::MediaEmpty => ForensicError::io(
                message,
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.kind.code()),
            ),
            MediaErrorKind::UnsupportedContainer
            | MediaErrorKind::UnsupportedCodec
            | MediaErrorKind::FfprobeUnavailable
            | MediaErrorKind::FfmpegUnavailable
            | MediaErrorKind::OpencvUnavailable
            | MediaErrorKind::AiNotConfigured => ForensicError::UnsupportedFormat {
                format: e.kind.code().to_string(),
                reason: message,
            },
            MediaErrorKind::CorruptedMedia | MediaErrorKind::InvalidFrame => {
                ForensicError::corrupt(e.operation.clone(), message)
            }
            // Explicitly NOT `corrupt`. OpenCV failing is a fact about this host's image
            // library; routing it through the corruption vocabulary would attribute a local
            // toolchain fault to the evidence.
            MediaErrorKind::OpencvOperationFailed => ForensicError::DecodeFailed {
                context: e.operation.clone(),
                reason: message,
            },
            MediaErrorKind::Cancelled => ForensicError::Cancelled {
                context: e.operation.clone(),
                bytes_processed: 0,
            },
            MediaErrorKind::InvalidConfiguration => ForensicError::UnsupportedFormat {
                format: e.kind.code().to_string(),
                reason: message,
            },
            // Everything else is a decode-domain failure in the existing vocabulary.
            _ => ForensicError::DecodeFailed {
                context: e.operation.clone(),
                reason: message,
            },
        }
    }
}

/// Result alias for media-pipeline operations.
pub type MediaResult<T> = Result<T, MediaError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable_screaming_snake_tokens() {
        assert_eq!(MediaErrorKind::FfmpegTimeout.code(), "FFMPEG_TIMEOUT");
        assert_eq!(MediaErrorKind::MediaNotFound.code(), "MEDIA_NOT_FOUND");
        assert_eq!(MediaErrorKind::AiNotConfigured.code(), "AI_NOT_CONFIGURED");
        assert_eq!(MediaErrorKind::NoVideoStream.code(), "NO_VIDEO_STREAM");
    }

    #[test]
    fn dependency_unavailable_is_distinct_from_media_faults() {
        assert!(MediaErrorKind::FfprobeUnavailable.is_dependency_unavailable());
        assert!(MediaErrorKind::OpencvUnavailable.is_dependency_unavailable());
        // OpenCV present-but-broken is a host fault, not a missing dependency and not a
        // statement about the evidence.
        assert_eq!(
            MediaErrorKind::OpencvOperationFailed.code(),
            "OPENCV_OPERATION_FAILED"
        );
        assert!(!MediaErrorKind::OpencvOperationFailed.is_dependency_unavailable());
        assert!(MediaErrorKind::OpencvOperationFailed.is_implementation_fault());
        // An OpenCV fault must never travel as corruption of the media.
        let forensic: ForensicError = MediaError::new(
            MediaErrorKind::OpencvOperationFailed,
            "imgproc_resize",
            "assertion failed",
        )
        .into();
        assert!(
            !matches!(forensic, ForensicError::CorruptStructure { .. }),
            "an OpenCV library fault must not be reported as corrupt evidence"
        );
        // Whereas a frame whose bytes disagree with its geometry genuinely is.
        assert!(MediaErrorKind::InvalidFrame.is_evidence_fault());
        assert!(!MediaErrorKind::InvalidFrame.is_implementation_fault());
        // A corrupt file is a property of the evidence, not of the host.
        assert!(!MediaErrorKind::CorruptedMedia.is_dependency_unavailable());
        assert!(!MediaErrorKind::FfprobeFailed.is_dependency_unavailable());
    }

    #[test]
    fn empty_detail_falls_back_to_the_code_rather_than_an_empty_string() {
        let e = MediaError::new(MediaErrorKind::DecodeFailed, "decode", "   ");
        assert_eq!(e.detail, "DECODE_FAILED");
    }

    #[test]
    fn process_diagnostics_are_retained_and_blank_stderr_is_dropped() {
        let e = MediaError::new(MediaErrorKind::FfmpegFailed, "decode", "non-zero exit")
            .with_process(Some(1), "Invalid data found when processing input");
        assert_eq!(e.exit_code, Some(1));
        assert!(e.stderr_tail.unwrap().contains("Invalid data"));

        let blank = MediaError::new(MediaErrorKind::FfmpegFailed, "decode", "x")
            .with_process(Some(1), "\n  \n");
        assert!(blank.stderr_tail.is_none());
    }

    #[test]
    fn conversion_to_forensic_error_preserves_the_code_in_the_message() {
        let e = MediaError::new(
            MediaErrorKind::FfmpegTimeout,
            "decode_frames",
            "exceeded 30s",
        );
        let fe: ForensicError = e.into();
        let msg = format!("{fe}");
        assert!(msg.contains("FFMPEG_TIMEOUT"), "got: {msg}");
        assert!(msg.contains("decode_frames"), "got: {msg}");
    }

    #[test]
    fn not_found_maps_to_an_io_not_found_rather_than_a_decode_failure() {
        let fe: ForensicError =
            MediaError::new(MediaErrorKind::MediaNotFound, "validate", "missing").into();
        assert!(matches!(fe, ForensicError::Io { .. }));
    }
}
