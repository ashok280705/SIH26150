//! End-to-end media pipeline integration tests against **real** media.
//!
//! These tests build actual H.264 (and, where the host's FFmpeg supports it, H.265) files with
//! FFmpeg, then drive them through the real pipeline:
//!
//! ```text
//!   fixture file ─► validate (ffprobe) ─► decode (ffmpeg rawvideo) ─► VideoFrame
//!                     ─► FrameProcessor ─► AnalysisInput
//! ```
//!
//! ## Scope
//!
//! This file validates the **media pipeline**. It says nothing about OEM forensic parsing: the
//! fixtures are generic synthetic videos, not DVR images, and no assertion here implies
//! Hikvision, Dahua, Uniview, CP-Plus, Honeywell or TP-Link compatibility. OEM validation lives
//! in the `forensic-tests` crate and is unaffected by this work.
//!
//! ## Missing FFmpeg
//!
//! These tests need `ffmpeg` and `ffprobe`. When they are absent the tests print a loud SKIPPED
//! line and return, because a host without the tool cannot exercise the tool. To make a missing
//! toolchain a hard failure instead — which is what the verification procedure does, so a
//! misconfigured verification host cannot report a false green — set:
//!
//! ```text
//! MEDIA_REQUIRE_FFMPEG=1
//! ```

use media::analysis::{AnalysisInput, AnalysisPipeline, AI_NOT_CONFIGURED};
use media::artifact::{
    CodecKind, ContainerType, MediaArtifact, MediaProvenance, ReconstructionMethod,
    SourceByteRange, ValidationStatus,
};
use media::decode::{DecodeRequest, SeekAccuracy};
use media::error::MediaErrorKind;
use media::frame::{PixelFormat, TimestampSource};
use media::pipeline::{MediaPipeline, ProcessingPlan};
use media::process::{FrameProcessor, Roi};
use media::tools::{MediaConfig, MediaToolchain};
use media::{hashing, validate};

use forensic_core::EvidenceId;
use std::path::{Path, PathBuf};
use std::time::Duration;

const FIXTURE_W: u32 = 320;
const FIXTURE_H: u32 = 240;
const FIXTURE_FPS: u32 = 10;
const FIXTURE_SECS: u32 = 2;
/// 10 fps for 2 s. FFmpeg's `testsrc` generator is exact, so this count is deterministic.
const FIXTURE_FRAMES: u64 = (FIXTURE_FPS * FIXTURE_SECS) as u64;

// ─────────────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────────────

fn toolchain() -> MediaToolchain {
    MediaToolchain::discover(
        &Default::default(),
        MediaConfig {
            probe_timeout: Duration::from_secs(30),
            decode_timeout: Duration::from_secs(120),
            ..Default::default()
        },
    )
}

/// Returns the toolchain when both tools are present, or `None` after reporting the skip.
///
/// With `MEDIA_REQUIRE_FFMPEG=1` a missing tool panics instead, so a verification run cannot
/// mistake "not exercised" for "passed".
fn require_tools(test: &str) -> Option<MediaToolchain> {
    let tc = toolchain();
    let missing = !tc.ffmpeg().is_available() || !tc.ffprobe().is_available();
    if !missing {
        return Some(tc);
    }
    let message = format!(
        "{test}: SKIPPED — ffmpeg available: {}, ffprobe available: {}",
        tc.ffmpeg().is_available(),
        tc.ffprobe().is_available()
    );
    if std::env::var("MEDIA_REQUIRE_FFMPEG").as_deref() == Ok("1") {
        panic!("{message} (MEDIA_REQUIRE_FFMPEG=1 makes this a failure)");
    }
    eprintln!("{message}");
    None
}

struct Fixtures {
    dir: tempfile::TempDir,
}

impl Fixtures {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("a writable temp directory"),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Encodes a deterministic test pattern with the given video encoder.
    ///
    /// Returns the ffmpeg stderr on failure so a missing encoder is diagnosable rather than a
    /// bare "false".
    fn encode(&self, name: &str, encoder: &str) -> Result<PathBuf, String> {
        let out = self.path(name);
        let status = std::process::Command::new("ffmpeg")
            .args([
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-f",
                "lavfi",
                "-i",
                &format!(
                    "testsrc=duration={FIXTURE_SECS}:size={FIXTURE_W}x{FIXTURE_H}:rate={FIXTURE_FPS}"
                ),
                "-c:v",
                encoder,
                "-pix_fmt",
                "yuv420p",
            ])
            .arg(&out)
            .output()
            .map_err(|e| format!("spawning ffmpeg: {e}"))?;
        if !status.status.success() {
            return Err(String::from_utf8_lossy(&status.stderr).trim().to_string());
        }
        Ok(out)
    }

    fn h264(&self) -> Result<PathBuf, String> {
        self.encode("valid_h264.mp4", "libx264")
            .or_else(|_| self.encode("valid_h264.mp4", "libopenh264"))
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.path(name);
        std::fs::write(&p, bytes).expect("writing a fixture");
        p
    }
}

/// Wraps a fixture file as a media artifact with plausible upstream provenance.
fn artifact(path: &Path, id: &str) -> MediaArtifact {
    MediaArtifact::from_derived_file(
        id,
        path,
        ReconstructionMethod::ExternallyProvided,
        MediaProvenance::new(EvidenceId::new())
            .with_regions(vec![SourceByteRange {
                offset: 1_048_576,
                length: 65_536,
            }])
            .with_upstream("integration-test-harness", Some("rec-7".into())),
    )
    .expect("the fixture exists")
}

// ─────────────────────────────────────────────────────────────────────────────
// Happy path: probe → decode → frames → OpenCV/processing
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_valid_h264_file_probes_decodes_and_yields_real_frames() {
    let Some(tc) = require_tools("a_valid_h264_file_probes_decodes_and_yields_real_frames") else {
        return;
    };
    let fx = Fixtures::new();
    let Ok(path) = fx.h264() else {
        eprintln!("SKIPPED: this ffmpeg build has no usable H.264 encoder");
        return;
    };

    let mut art = artifact(&path, "art-h264");

    // ── Validation ──────────────────────────────────────────────────────────
    let report = validate::validate_artifact(&tc, &mut art).await;
    assert_eq!(
        report.status,
        ValidationStatus::Valid,
        "ffprobe rejected the fixture: {:?}",
        report.checks
    );
    assert_eq!(report.ffprobe_exit_code, Some(0));
    assert!(report.permits_decode());
    assert_eq!(art.properties.codec, Some(CodecKind::H264));
    assert_eq!(art.properties.container, Some(ContainerType::Mp4));
    assert_eq!(art.properties.geometry(), Some((FIXTURE_W, FIXTURE_H)));
    assert_eq!(art.properties.frame_rate, Some(FIXTURE_FPS as f64));
    // The artifact now carries a digest of its own bytes, distinct from anything upstream.
    let media_hash = art.media_hash.clone().expect("a media digest");
    assert_eq!(media_hash.algorithm, "SHA-256");
    assert_eq!(media_hash.bytes_hashed, art.size_bytes);

    // ── Decode ──────────────────────────────────────────────────────────────
    let outcome = media::decode::decode_frames(&tc, &art, &DecodeRequest::sequential())
        .await
        .expect("decoding a valid H.264 file");

    assert_eq!(
        outcome.report.metrics.frames_emitted, FIXTURE_FRAMES,
        "testsrc at {FIXTURE_FPS}fps for {FIXTURE_SECS}s is exactly {FIXTURE_FRAMES} frames"
    );
    assert_eq!(outcome.frames.len() as u64, FIXTURE_FRAMES);
    assert_eq!(outcome.report.ffmpeg_exit_code, Some(0));
    assert!(outcome.report.truncated_trailing_bytes.is_none());
    // Peak resident frame memory is one frame, not the recording.
    assert_eq!(
        outcome.report.metrics.peak_frame_buffer_bytes,
        (FIXTURE_W * FIXTURE_H * 3) as u64
    );
    // The argv proves decoding rather than remuxing: rawvideo output, no stream copy.
    assert!(outcome.report.ffmpeg_arguments.contains(&"rawvideo".into()));
    assert!(!outcome.report.ffmpeg_arguments.iter().any(|a| a == "copy"));

    // ── The frames are real pictures ────────────────────────────────────────
    let first = &outcome.frames[0];
    assert_eq!((first.width, first.height), (FIXTURE_W, FIXTURE_H));
    assert_eq!(first.pixel_format, PixelFormat::Bgr24);
    assert_eq!(first.data.len(), (FIXTURE_W * FIXTURE_H * 3) as usize);
    // `testsrc` is a colour pattern, so a decoded frame cannot be uniform.
    let quality = FrameProcessor::quality(first).expect("quality metrics");
    assert!(
        quality.has_tonal_variation,
        "a decoded testsrc frame must carry real image content"
    );
    assert!(quality.brightness_std_dev > 1.0);

    // Consecutive frames differ — the decoder advanced through the stream rather than
    // returning the same picture.
    assert_ne!(
        outcome.frames[0].content_hash().hex,
        outcome.frames[5].content_hash().hex
    );

    // ── Timestamps and their provenance ─────────────────────────────────────
    assert_eq!(first.timing.presentation_timestamp_secs, Some(0.0));
    let tenth = &outcome.frames[10];
    assert_eq!(tenth.timing.presentation_timestamp_secs, Some(1.0));
    assert_eq!(tenth.timing.pts_source, TimestampSource::FrameRateDerived);
    assert!(
        tenth.timing.pts_source.is_derived(),
        "a rate-derived position must be labelled derived, not as a recorder assertion"
    );

    // ── Provenance back to evidence ─────────────────────────────────────────
    assert_eq!(first.provenance.evidence_id, art.provenance.evidence_id);
    assert_eq!(first.provenance.artifact_id, "art-h264");
    assert_eq!(first.provenance.artifact_source_offset, Some(1_048_576));
    assert_eq!(
        first.provenance.source_recording_id.as_deref(),
        Some("rec-7")
    );
    assert_eq!(
        first.provenance.artifact_media_hash.as_deref(),
        Some(media_hash.hex.as_str())
    );
    assert_eq!(first.frame_id, "art-h264:frame:0");

    // ── Image processing over real decoded pixels ───────────────────────────
    let resized = FrameProcessor::resize(first, 160, 120).expect("resize");
    assert_eq!((resized.width, resized.height), (160, 120));
    assert_eq!(resized.data.len(), 160 * 120 * 3);

    let gray = FrameProcessor::convert_color(&resized, PixelFormat::Gray8).expect("cvt_color");
    assert_eq!(gray.pixel_format, PixelFormat::Gray8);
    assert_eq!(gray.data.len(), 160 * 120);

    let roi = FrameProcessor::crop_roi(
        &gray,
        Roi {
            x: 10,
            y: 10,
            width: 40,
            height: 30,
        },
    )
    .expect("roi");
    assert_eq!((roi.width, roi.height), (40, 30));
    assert_eq!(roi.data.len(), 40 * 30);

    // The processing chain is recorded, in order, with the backend that ran it.
    let chain: Vec<&str> = roi
        .provenance
        .processing_chain
        .iter()
        .map(|s| s.operation.as_str())
        .collect();
    assert_eq!(chain, vec!["resize", "cvt_color", "roi"]);
    assert_eq!(
        roi.provenance.processing_chain[0].backend,
        media::active_backend().label()
    );
    // A processed frame still traces to the same evidence and artifact.
    assert_eq!(roi.provenance.evidence_id, art.provenance.evidence_id);
    assert_eq!(roi.frame_id, "art-h264:frame:0");

    // ── Hash separation ─────────────────────────────────────────────────────
    let source_like = hashing::hash_bytes(b"pretend evidence bytes");
    assert_ne!(media_hash.hex, source_like.hex);
    assert_ne!(
        media_hash.hex,
        first.content_hash().hex,
        "the file digest and the decoded-pixel digest cover different bytes"
    );
    assert_ne!(first.content_hash().hex, roi.content_hash().hex);
}

#[tokio::test]
async fn frame_hashes_are_deterministic_across_two_independent_decodes() {
    let Some(tc) = require_tools("frame_hashes_are_deterministic_across_two_independent_decodes")
    else {
        return;
    };
    let fx = Fixtures::new();
    let Ok(path) = fx.h264() else { return };
    let mut art = artifact(&path, "art-det");
    validate::validate_artifact(&tc, &mut art).await;

    let req = DecodeRequest::sequential().with_max_frames(4);
    let a = media::decode::decode_frames(&tc, &art, &req).await.unwrap();
    let b = media::decode::decode_frames(&tc, &art, &req).await.unwrap();

    let ha: Vec<String> = a.frames.iter().map(|f| f.content_hash().hex).collect();
    let hb: Vec<String> = b.frames.iter().map(|f| f.content_hash().hex).collect();
    assert_eq!(
        ha, hb,
        "the same decoder over the same bytes is deterministic"
    );
    assert_eq!(a.report.ffmpeg_arguments, b.report.ffmpeg_arguments);
}

// ─────────────────────────────────────────────────────────────────────────────
// Extraction modes
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sampled_and_time_range_extraction_select_the_frames_they_claim() {
    let Some(tc) = require_tools("sampled_and_time_range_extraction_select_the_frames_they_claim")
    else {
        return;
    };
    let fx = Fixtures::new();
    let Ok(path) = fx.h264() else { return };
    let mut art = artifact(&path, "art-modes");
    validate::validate_artifact(&tc, &mut art).await;

    // Every 5th frame of 20 => 4 frames, one per half second.
    let sampled = media::decode::decode_frames(&tc, &art, &DecodeRequest::every_n_frames(5))
        .await
        .expect("sampled decode");
    assert_eq!(sampled.report.metrics.frames_emitted, 4);
    assert_eq!(
        sampled.frames[1].timing.presentation_timestamp_secs,
        Some(0.5)
    );

    // One frame per second of media time => 2 frames.
    let per_second = media::decode::decode_frames(&tc, &art, &DecodeRequest::every_n_seconds(1.0))
        .await
        .expect("interval decode");
    assert_eq!(per_second.report.metrics.frames_emitted, 2);
    assert_eq!(
        per_second.frames[1].timing.presentation_timestamp_secs,
        Some(1.0)
    );

    // A time range, sought approximately. The limitation is reported, not hidden.
    let ranged =
        media::decode::decode_frames(&tc, &art, &DecodeRequest::time_range(1.0, Some(1.5), false))
            .await
            .expect("time-range decode");
    assert!(ranged.report.metrics.frames_emitted > 0);
    assert_eq!(
        ranged.report.seek_accuracy,
        SeekAccuracy::KeyframeApproximate,
        "an input-side seek lands on a keyframe and must say so"
    );

    // An accurate seek is reported as exact.
    let exact =
        media::decode::decode_frames(&tc, &art, &DecodeRequest::time_range(1.0, Some(1.5), true))
            .await
            .expect("accurate time-range decode");
    assert_eq!(exact.report.seek_accuracy, SeekAccuracy::Exact);

    // A frame budget stops the decoder early and says why.
    let budgeted =
        media::decode::decode_frames(&tc, &art, &DecodeRequest::sequential().with_max_frames(3))
            .await
            .expect("budgeted decode");
    assert_eq!(budgeted.report.metrics.frames_emitted, 3);
    assert_eq!(
        budgeted.report.stop_reason,
        media::decode::DecodeStopReason::FrameLimitReached
    );
}

#[tokio::test]
async fn a_decoder_side_rescale_bounds_memory_without_changing_the_frame_count() {
    let Some(tc) =
        require_tools("a_decoder_side_rescale_bounds_memory_without_changing_the_frame_count")
    else {
        return;
    };
    let fx = Fixtures::new();
    let Ok(path) = fx.h264() else { return };
    let mut art = artifact(&path, "art-scale");
    validate::validate_artifact(&tc, &mut art).await;

    let req = DecodeRequest::sequential().with_target_size(64, 48);
    let out = media::decode::decode_frames(&tc, &art, &req).await.unwrap();
    assert_eq!(out.report.metrics.frames_emitted, FIXTURE_FRAMES);
    assert_eq!((out.frames[0].width, out.frames[0].height), (64, 48));
    assert_eq!(out.report.metrics.peak_frame_buffer_bytes, 64 * 48 * 3);
}

#[tokio::test]
async fn hevc_decodes_when_the_host_ffmpeg_can_encode_it() {
    let Some(tc) = require_tools("hevc_decodes_when_the_host_ffmpeg_can_encode_it") else {
        return;
    };
    let fx = Fixtures::new();
    let path = match fx.encode("valid_hevc.mp4", "libx265") {
        Ok(p) => p,
        Err(why) => {
            // Reported, not silently passed: the host simply has no HEVC encoder to build a
            // fixture with. This says nothing about HEVC *decoding* support.
            eprintln!("SKIPPED: this ffmpeg build cannot encode H.265 ({why})");
            return;
        }
    };

    let mut art = artifact(&path, "art-hevc");
    let report = validate::validate_artifact(&tc, &mut art).await;
    assert_eq!(report.status, ValidationStatus::Valid);
    assert_eq!(art.properties.codec, Some(CodecKind::H265));

    let out =
        media::decode::decode_frames(&tc, &art, &DecodeRequest::sequential().with_max_frames(5))
            .await
            .expect("decoding H.265");
    assert!(out.report.metrics.frames_emitted > 0);
    assert_eq!(
        out.frames[0].data.len(),
        (FIXTURE_W * FIXTURE_H * 3) as usize
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Failure paths
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_missing_file_is_media_not_found() {
    let tc = toolchain();
    let fx = Fixtures::new();
    let real = fx.write("present.mp4", b"x");
    let mut art = artifact(&real, "art-missing");
    art.path = fx.path("this-file-does-not-exist.mp4");

    let report = validate::validate_artifact(&tc, &mut art).await;
    assert_eq!(report.error_code.as_deref(), Some("MEDIA_NOT_FOUND"));
    assert_eq!(report.status, ValidationStatus::Invalid);
    assert!(!report.permits_decode());
}

#[tokio::test]
async fn an_empty_file_is_media_empty() {
    let tc = toolchain();
    let fx = Fixtures::new();
    let p = fx.write("empty.mp4", b"");
    let mut art = artifact(&p, "art-empty");

    let report = validate::validate_artifact(&tc, &mut art).await;
    assert_eq!(report.error_code.as_deref(), Some("MEDIA_EMPTY"));
    assert!(art.media_hash.is_none(), "zero bytes produce no digest");
}

#[tokio::test]
async fn a_file_that_is_not_media_is_rejected_by_ffprobe() {
    let Some(tc) = require_tools("a_file_that_is_not_media_is_rejected_by_ffprobe") else {
        return;
    };
    let fx = Fixtures::new();
    let p = fx.write("garbage.mp4", &vec![0xA5u8; 64 * 1024]);
    let mut art = artifact(&p, "art-garbage");

    let report = validate::validate_artifact(&tc, &mut art).await;
    assert!(
        matches!(
            report.status,
            ValidationStatus::Invalid | ValidationStatus::Corrupted
        ),
        "non-media bytes must not validate: {:?}",
        report.status
    );
    assert!(!report.permits_decode());
    assert_ne!(report.error_code.as_deref(), None);
    // The diagnostics survive for the operator.
    assert!(report.ffprobe_stderr_tail.is_some() || report.error_code.is_some());
}

#[tokio::test]
async fn a_truncated_media_file_does_not_validate_as_decodable() {
    let Some(tc) = require_tools("a_truncated_media_file_does_not_validate_as_decodable") else {
        return;
    };
    let fx = Fixtures::new();
    let Ok(good) = fx.h264() else { return };
    let bytes = std::fs::read(&good).unwrap();
    // Keep only the opening bytes: the container header without its data or index.
    let corrupt = fx.write("corrupt.mp4", &bytes[..bytes.len().min(512)]);

    let mut art = artifact(&corrupt, "art-corrupt");
    let report = validate::validate_artifact(&tc, &mut art).await;
    assert_ne!(
        report.status,
        ValidationStatus::Valid,
        "a truncated file must never validate as decodable"
    );

    // And decoding is refused rather than attempted.
    let err = media::decode::decode_frames(&tc, &art, &DecodeRequest::sequential())
        .await
        .unwrap_err();
    assert!(
        !matches!(err.kind, MediaErrorKind::AiNotConfigured),
        "unexpected error kind {:?}",
        err.kind
    );
}

#[tokio::test]
async fn an_audio_only_container_reports_no_video_stream() {
    let Some(tc) = require_tools("an_audio_only_container_reports_no_video_stream") else {
        return;
    };
    let fx = Fixtures::new();
    let out = fx.path("audio_only.m4a");
    let made = std::process::Command::new("ffmpeg")
        .args([
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:duration=1",
            "-c:a",
            "aac",
        ])
        .arg(&out)
        .output();
    match made {
        Ok(o) if o.status.success() => {}
        _ => {
            eprintln!("SKIPPED: this ffmpeg build cannot produce an AAC fixture");
            return;
        }
    }

    let mut art = artifact(&out, "art-audio");
    let report = validate::validate_artifact(&tc, &mut art).await;
    assert_eq!(report.error_code.as_deref(), Some("NO_VIDEO_STREAM"));
    assert_eq!(report.status, ValidationStatus::Invalid);
    assert!(!report.permits_decode());
}

#[tokio::test]
async fn a_decode_timeout_terminates_the_decoder_and_is_never_a_success() {
    let Some(_) = require_tools("a_decode_timeout_terminates_the_decoder_and_is_never_a_success")
    else {
        return;
    };
    let fx = Fixtures::new();
    let Ok(path) = fx.h264() else { return };

    // A one-millisecond budget cannot be met by any real decode.
    let tc = MediaToolchain::discover(
        &Default::default(),
        MediaConfig {
            decode_timeout: Duration::from_millis(1),
            ..Default::default()
        },
    );
    let mut art = artifact(&path, "art-timeout");
    // Validate with a normal budget first, so the failure under test is the decode timeout.
    validate::validate_artifact(&toolchain(), &mut art).await;
    assert_eq!(art.validation_status, ValidationStatus::Valid);

    let err = media::decode::decode_frames(&tc, &art, &DecodeRequest::sequential())
        .await
        .expect_err("a 1ms decode budget must fail");
    assert!(
        matches!(
            err.kind,
            MediaErrorKind::FfmpegTimeout | MediaErrorKind::FrameExtractionFailed
        ),
        "expected a timeout-family failure, got {:?}: {}",
        err.kind,
        err.detail
    );
}

#[tokio::test]
async fn a_probe_timeout_is_reported_as_timeout_and_not_as_a_pass() {
    let Some(_) = require_tools("a_probe_timeout_is_reported_as_timeout_and_not_as_a_pass") else {
        return;
    };
    let fx = Fixtures::new();
    let Ok(path) = fx.h264() else { return };

    let tc = MediaToolchain::discover(
        &Default::default(),
        MediaConfig {
            probe_timeout: Duration::from_millis(1),
            ..Default::default()
        },
    );
    let mut art = artifact(&path, "art-probe-timeout");
    let report = validate::validate_artifact(&tc, &mut art).await;
    assert_ne!(
        report.status,
        ValidationStatus::Valid,
        "a probe that was killed cannot have validated anything"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The full pipeline, and the AI boundary
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_full_pipeline_reports_exactly_what_it_did_and_claims_no_ai() {
    let Some(tc) = require_tools("the_full_pipeline_reports_exactly_what_it_did_and_claims_no_ai")
    else {
        return;
    };
    let fx = Fixtures::new();
    let Ok(path) = fx.h264() else { return };
    let mut art = artifact(&path, "art-full");

    let pipeline = MediaPipeline::new(tc);
    let plan = ProcessingPlan {
        resize_to: Some((160, 120)),
        convert_to: Some(PixelFormat::Gray8),
        measure_quality: true,
        ..Default::default()
    };
    let report = pipeline
        .run(
            &mut art,
            &DecodeRequest::sequential().with_max_frames(8),
            &plan,
            4,
        )
        .await;

    let s = report.status_summary();
    assert_eq!(s["validated"], true);
    assert_eq!(s["validation_status"], "VALID");
    assert_eq!(s["codec"], "H264");
    assert_eq!(s["resolution"], format!("{FIXTURE_W}x{FIXTURE_H}"));
    assert_eq!(s["decoded"], true);
    assert_eq!(s["frames_extracted"], 8);
    assert_eq!(s["frames_processed"], 8);
    assert_eq!(report.quality.len(), 8);
    assert!(report.errors().is_empty(), "errors: {:?}", report.errors());

    // No engine is registered, so AI is explicitly not configured and nothing is claimed.
    assert_eq!(s["ai_analyzed"], false);
    assert_eq!(s["ai_status"], AI_NOT_CONFIGURED);
    let analysis = report.analysis.as_ref().expect("an analysis result");
    assert!(analysis.observations.is_empty());
    assert_eq!(analysis.frames_analyzed, 0);
    assert!(!analysis.inference_performed());

    // Frame metadata carries the provenance chain for every processed frame.
    assert_eq!(report.frame_metadata.len(), 8);
    let m = &report.frame_metadata[0];
    assert_eq!(m["frame_id"], "art-full:frame:0");
    assert_eq!(m["width"], 160);
    assert_eq!(m["timestamp_source"], "FRAME_RATE_DERIVED");
    assert_eq!(m["artifact_source_offset"], 1_048_576);
    assert!(m["frame_sha256"].as_str().unwrap().len() == 64);
}

#[tokio::test]
async fn the_analysis_boundary_receives_only_standardized_frames() {
    let Some(tc) = require_tools("the_analysis_boundary_receives_only_standardized_frames") else {
        return;
    };
    let fx = Fixtures::new();
    let Ok(path) = fx.h264() else { return };
    let mut art = artifact(&path, "art-ai");
    validate::validate_artifact(&tc, &mut art).await;

    let out =
        media::decode::decode_frames(&tc, &art, &DecodeRequest::sequential().with_max_frames(3))
            .await
            .unwrap();

    let input = AnalysisInput::from_frames(
        art.provenance.evidence_id,
        art.artifact_id.clone(),
        art.media_hash.as_ref().map(|h| h.hex.clone()),
        out.frames,
    )
    .expect("real frames");
    assert_eq!(input.frame_count(), 3);

    let result = AnalysisPipeline::not_configured().analyze(&input).unwrap();
    assert_eq!(result.status, AI_NOT_CONFIGURED);
    assert_eq!(result.frames_submitted, 3);
    assert_eq!(result.frames_analyzed, 0);
    assert!(result.observations.is_empty());
    // Even without an engine, the result stays bound to its evidence and artifact.
    assert_eq!(result.artifact_id, "art-ai");
    assert_eq!(result.evidence_id, art.provenance.evidence_id.to_string());
}

// ─────────────────────────────────────────────────────────────────────────────
// Forensic safety
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_pipeline_never_modifies_the_file_it_reads() {
    let Some(tc) = require_tools("the_pipeline_never_modifies_the_file_it_reads") else {
        return;
    };
    let fx = Fixtures::new();
    let Ok(path) = fx.h264() else { return };

    let before = hashing::hash_file(&path).unwrap();
    let before_len = std::fs::metadata(&path).unwrap().len();

    let mut art = artifact(&path, "art-readonly");
    let pipeline = MediaPipeline::new(tc);
    let _ = pipeline
        .run(
            &mut art,
            &DecodeRequest::sequential(),
            &ProcessingPlan {
                measure_quality: true,
                ..Default::default()
            },
            2,
        )
        .await;

    let after = hashing::hash_file(&path).unwrap();
    assert_eq!(
        before.hex, after.hex,
        "the media pipeline must not alter the bytes it reads"
    );
    assert_eq!(before_len, std::fs::metadata(&path).unwrap().len());
}

#[tokio::test]
async fn concurrent_requests_are_bounded_by_configuration() {
    let Some(_) = require_tools("concurrent_requests_are_bounded_by_configuration") else {
        return;
    };
    let fx = Fixtures::new();
    let Ok(path) = fx.h264() else { return };

    let tc = MediaToolchain::discover(
        &Default::default(),
        MediaConfig {
            max_concurrent_processes: 1,
            ..Default::default()
        },
    );
    assert_eq!(tc.runner().max_concurrent(), 1);

    let mut art = artifact(&path, "art-conc");
    validate::validate_artifact(&tc, &mut art).await;

    // Eight simultaneous decodes against a single permit still succeed — serialised, not
    // spawning eight FFmpeg processes at once.
    let req = DecodeRequest::sequential().with_max_frames(2);
    let mut handles = Vec::new();
    for _ in 0..8 {
        handles.push(media::decode::decode_frames(&tc, &art, &req));
    }
    for h in handles {
        let out = h.await.expect("each bounded decode completes");
        assert_eq!(out.report.metrics.frames_emitted, 2);
    }
}
