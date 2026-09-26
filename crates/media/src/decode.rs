//! Genuine FFmpeg demux + decode into raw video frames.
//!
//! This is the stage the pipeline previously lacked. It is not a remux and not a copy: FFmpeg
//! is asked for `-f rawvideo`, which forces it to demux the container, run the codec's decoder,
//! and write decoded pictures. The bytes this module reads are pixels, and there is no path by
//! which a stream copy could satisfy the same command.
//!
//! ```text
//!   derived media file
//!         │  ffmpeg -i <file> -f rawvideo -pix_fmt bgr24 -
//!         ▼
//!   demux ─► decode ─► raw picture bytes on stdout
//!         │  read exactly width*height*channels per frame
//!         ▼
//!   VideoFrame
//! ```
//!
//! ## Memory
//!
//! Frames are consumed from the child's stdout one at a time, so peak memory is one frame plus
//! whatever the caller chooses to retain — not the recording. A multi-gigabyte artifact decodes
//! with the same footprint as a small one. [`decode_frames_with`] is the streaming entry point;
//! [`decode_frames`] is the convenience wrapper that collects, and it is bounded by
//! `max_frames_per_request`.
//!
//! ## Honesty rules
//!
//! * Decoding is only attempted on an artifact whose validation actually passed.
//! * A short final read is a truncated frame and is reported, never padded into a frame.
//! * A non-zero FFmpeg exit, a timeout, or zero frames produced is a failure, even if some
//!   bytes were read first.
//! * Input-side seeking lands on a keyframe. That limitation is reported as
//!   [`SeekAccuracy::KeyframeApproximate`] rather than described as an exact seek.

use crate::artifact::{CodecKind, MediaArtifact, ValidationStatus};
use crate::error::{MediaError, MediaErrorKind, MediaResult};
use crate::exec::CommandSpec;
use crate::frame::{FrameProvenance, FrameTiming, PixelFormat, TimestampSource, VideoFrame};
use crate::tools::MediaToolchain;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Instant;

/// Which frames to extract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ExtractionMode {
    /// Every decoded frame, in order.
    Sequential,
    /// Every `n`-th source frame. `n == 1` is equivalent to [`ExtractionMode::Sequential`].
    EveryNFrames { n: u64 },
    /// One frame per `interval_secs` of media time.
    EveryNSeconds { interval_secs: f64 },
    /// Frames within a media-time window.
    TimeRange {
        start_secs: f64,
        end_secs: Option<f64>,
        /// When true, FFmpeg decodes from the start of the file and discards, giving an exact
        /// boundary at the cost of time. When false, it seeks to the preceding keyframe.
        accurate_seek: bool,
    },
}

impl ExtractionMode {
    fn label(&self) -> &'static str {
        match self {
            Self::Sequential => "SEQUENTIAL",
            Self::EveryNFrames { .. } => "SAMPLED_EVERY_N_FRAMES",
            Self::EveryNSeconds { .. } => "SAMPLED_EVERY_N_SECONDS",
            Self::TimeRange { .. } => "TIME_RANGE",
        }
    }

    fn validate(&self) -> MediaResult<()> {
        match self {
            Self::EveryNFrames { n } if *n == 0 => Err(MediaError::new(
                MediaErrorKind::InvalidConfiguration,
                "ExtractionMode::validate",
                "a frame sampling interval of 0 selects no frames",
            )),
            Self::EveryNSeconds { interval_secs }
                if !interval_secs.is_finite() || *interval_secs <= 0.0 =>
            {
                Err(MediaError::new(
                    MediaErrorKind::InvalidConfiguration,
                    "ExtractionMode::validate",
                    format!("a time sampling interval of {interval_secs} is not usable"),
                ))
            }
            Self::TimeRange {
                start_secs,
                end_secs,
                ..
            } => {
                if !start_secs.is_finite() || *start_secs < 0.0 {
                    return Err(MediaError::new(
                        MediaErrorKind::InvalidConfiguration,
                        "ExtractionMode::validate",
                        format!("a start time of {start_secs}s is not usable"),
                    ));
                }
                if let Some(end) = end_secs {
                    if !end.is_finite() || end <= start_secs {
                        return Err(MediaError::new(
                            MediaErrorKind::InvalidConfiguration,
                            "ExtractionMode::validate",
                            format!("the time range {start_secs}s..{end}s is empty or reversed"),
                        ));
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// How faithfully a requested start time could be honoured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SeekAccuracy {
    /// No seek was requested.
    NotApplicable,
    /// FFmpeg decoded from the file start and discarded, so the boundary is frame-exact.
    Exact,
    /// FFmpeg seeked to the keyframe at or before the requested time. The first returned frame
    /// may precede the requested start; it is not claimed to be exact.
    KeyframeApproximate,
}

/// A decode request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecodeRequest {
    pub mode: ExtractionMode,
    /// The pixel layout to decode into. `Bgr24` is the layout OpenCV expects natively.
    pub pixel_format: PixelFormat,
    /// Optional decoder-side rescale. Applied by FFmpeg before the bytes ever reach this
    /// process, which is what makes it a memory bound rather than a post-processing step.
    pub target_size: Option<(u32, u32)>,
    /// Upper bound on frames emitted. Also clamped by `MediaConfig::max_frames_per_request`.
    pub max_frames: Option<u64>,
}

impl Default for DecodeRequest {
    fn default() -> Self {
        Self {
            mode: ExtractionMode::Sequential,
            pixel_format: PixelFormat::Bgr24,
            target_size: None,
            max_frames: None,
        }
    }
}

impl DecodeRequest {
    pub fn sequential() -> Self {
        Self::default()
    }

    pub fn every_n_frames(n: u64) -> Self {
        Self {
            mode: ExtractionMode::EveryNFrames { n },
            ..Self::default()
        }
    }

    pub fn every_n_seconds(interval_secs: f64) -> Self {
        Self {
            mode: ExtractionMode::EveryNSeconds { interval_secs },
            ..Self::default()
        }
    }

    pub fn time_range(start_secs: f64, end_secs: Option<f64>, accurate_seek: bool) -> Self {
        Self {
            mode: ExtractionMode::TimeRange {
                start_secs,
                end_secs,
                accurate_seek,
            },
            ..Self::default()
        }
    }

    pub fn with_max_frames(mut self, max: u64) -> Self {
        self.max_frames = Some(max);
        self
    }

    pub fn with_pixel_format(mut self, fmt: PixelFormat) -> Self {
        self.pixel_format = fmt;
        self
    }

    pub fn with_target_size(mut self, w: u32, h: u32) -> Self {
        self.target_size = Some((w, h));
        self
    }
}

/// Why decoding stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecodeStopReason {
    /// FFmpeg reached the end of the stream and exited cleanly.
    EndOfStream,
    /// The caller's frame budget was reached; more frames remain in the media.
    FrameLimitReached,
    /// The caller's callback asked to stop.
    CallerStopped,
}

/// Measured cost of a decode run. Measured, not estimated.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DecodeMetrics {
    pub decode_duration_ms: u64,
    pub frames_emitted: u64,
    pub bytes_read: u64,
    /// Frames emitted per second of wall clock. `None` when the run was too short to measure.
    pub effective_fps: Option<f64>,
    /// Peak resident frame buffer in bytes — one frame, by construction of the streaming loop.
    pub peak_frame_buffer_bytes: u64,
}

/// The outcome of a decode run, including its diagnostics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecodeReport {
    pub artifact_id: String,
    pub mode: String,
    pub stop_reason: DecodeStopReason,
    pub seek_accuracy: SeekAccuracy,
    pub width: u32,
    pub height: u32,
    pub pixel_format: PixelFormat,
    pub metrics: DecodeMetrics,
    pub ffmpeg_arguments: Vec<String>,
    pub ffmpeg_version: Option<String>,
    pub ffmpeg_exit_code: Option<i32>,
    pub ffmpeg_stderr_tail: Option<String>,
    /// Timestamp provenance for the frames this run produced.
    pub timestamp_source: TimestampSource,
    /// Set when a trailing partial frame was discarded rather than padded.
    pub truncated_trailing_bytes: Option<u64>,
}

/// Frames plus the report describing how they were produced.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodeOutcome {
    pub frames: Vec<VideoFrame>,
    pub report: DecodeReport,
}

/// What a frame callback asks the decoder to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameAction {
    Continue,
    Stop,
}

/// Decodes frames, handing each one to `on_frame` as it is produced.
///
/// This is the memory-safe entry point for large evidence: nothing accumulates unless the
/// callback chooses to accumulate it.
pub async fn decode_frames_with<F>(
    toolchain: &MediaToolchain,
    artifact: &MediaArtifact,
    request: &DecodeRequest,
    mut on_frame: F,
) -> MediaResult<DecodeReport>
where
    F: FnMut(VideoFrame) -> MediaResult<FrameAction>,
{
    const OP: &str = "decode_frames";
    request.mode.validate()?;

    // 1. Decoding requires a validated artifact. An unvalidated or unavailable-validation
    //    artifact is refused here so that no part of the system can decode its way past the
    //    gate and then report the result as validated.
    if artifact.validation_status != ValidationStatus::Valid {
        return Err(MediaError::new(
            match artifact.validation_status {
                ValidationStatus::Unavailable => MediaErrorKind::FfprobeUnavailable,
                ValidationStatus::Timeout => MediaErrorKind::FfmpegTimeout,
                ValidationStatus::Unsupported => MediaErrorKind::UnsupportedCodec,
                ValidationStatus::Corrupted => MediaErrorKind::CorruptedMedia,
                _ => MediaErrorKind::DecodeFailed,
            },
            OP,
            format!(
                "artifact '{}' is {} and was not decoded; validation must pass first",
                artifact.artifact_id,
                artifact.validation_status.label()
            ),
        ));
    }

    let ffmpeg = toolchain.require_ffmpeg(OP)?.to_path_buf();
    let config = toolchain.config();

    // 2. Establish output geometry. Without it a raw frame has no length and cannot be read.
    let source_geometry = artifact.properties.geometry().ok_or_else(|| {
        MediaError::new(
            MediaErrorKind::CorruptedMedia,
            OP,
            "the artifact has no established frame geometry; probe it before decoding",
        )
    })?;
    let (out_w, out_h) = request.target_size.unwrap_or(source_geometry);
    if out_w == 0 || out_h == 0 {
        return Err(MediaError::new(
            MediaErrorKind::InvalidConfiguration,
            OP,
            format!("a target size of {out_w}x{out_h} has no pixels"),
        ));
    }

    let frame_len = request
        .pixel_format
        .frame_len(out_w, out_h)
        .ok_or_else(|| {
            MediaError::new(
                MediaErrorKind::InvalidConfiguration,
                OP,
                format!("frame geometry {out_w}x{out_h} overflows an address"),
            )
        })?;
    if frame_len > config.max_frame_bytes {
        return Err(MediaError::new(
            MediaErrorKind::InvalidConfiguration,
            OP,
            format!(
                "a single {out_w}x{out_h} {:?} frame is {frame_len} bytes, above the \
                 configured ceiling of {}; request a target size",
                request.pixel_format, config.max_frame_bytes
            ),
        ));
    }

    // 3. A codec ffmpeg has no decoder for is UNSUPPORTED_CODEC, distinct from a decode failure.
    if let CodecKind::Other(name) = artifact.properties.codec_or_unknown() {
        return Err(MediaError::new(
            MediaErrorKind::UnsupportedCodec,
            OP,
            format!("codec '{name}' is not handled by this pipeline"),
        ));
    }

    let budget = frame_budget(request, config.max_frames_per_request);
    let (spec, seek_accuracy) =
        build_decode_command(&ffmpeg, &artifact.path, request, out_w, out_h);

    // 4. Run the decoder, draining stdout one frame at a time.
    let started = Instant::now();
    let mut child = toolchain
        .runner()
        .spawn_streaming(&spec, &config.decode_limits(), OP)
        .await?;

    let timing_plan = TimingPlan::for_request(artifact, request);
    let base_provenance = FrameProvenance {
        evidence_id: artifact.provenance.evidence_id,
        artifact_id: artifact.artifact_id.clone(),
        artifact_source_offset: artifact.source_offset(),
        source_recording_id: artifact.provenance.source_recording_id.clone(),
        artifact_media_hash: artifact.media_hash.as_ref().map(|h| h.hex.clone()),
        decoder: format!(
            "ffmpeg rawvideo ({})",
            toolchain.ffmpeg().version().unwrap_or("version unknown")
        ),
        processing_chain: Vec::new(),
    };

    let mut buffer = vec![0u8; frame_len];
    let mut index: u64 = 0;
    let mut bytes_read: u64 = 0;
    let mut truncated: Option<u64> = None;
    let mut stop_reason = DecodeStopReason::EndOfStream;
    let mut decode_error: Option<MediaError> = None;

    loop {
        if index >= budget {
            stop_reason = DecodeStopReason::FrameLimitReached;
            child.stop().await;
            break;
        }

        let filled = match child.read_exact_or_eof(&mut buffer).await {
            Ok(n) => n,
            Err(e) => {
                decode_error = Some(e);
                break;
            }
        };

        if filled == 0 {
            break; // clean end of stream
        }
        bytes_read += filled as u64;
        if filled < frame_len {
            // A trailing partial picture is not a frame. It is recorded and discarded; padding
            // it would fabricate pixels that FFmpeg never produced.
            truncated = Some(filled as u64);
            break;
        }

        let frame = VideoFrame::new(
            &artifact.artifact_id,
            index,
            out_w,
            out_h,
            request.pixel_format,
            buffer.clone(),
            timing_plan.timing_for(index),
            base_provenance.clone(),
        )?;
        index += 1;

        match on_frame(frame) {
            Ok(FrameAction::Continue) => {}
            Ok(FrameAction::Stop) => {
                stop_reason = DecodeStopReason::CallerStopped;
                child.stop().await;
                break;
            }
            Err(e) => {
                decode_error = Some(e);
                child.stop().await;
                break;
            }
        }
    }

    let outcome = child.finish().await?;
    let elapsed = started.elapsed();

    if let Some(e) = decode_error {
        return Err(e.with_process(outcome.exit_code, outcome.stderr_tail));
    }

    // 5. Exit status is authoritative — except where the caller deliberately stopped early,
    //    in which case FFmpeg was killed by us and its status describes our kill, not the media.
    let caller_ended_early = matches!(
        stop_reason,
        DecodeStopReason::FrameLimitReached | DecodeStopReason::CallerStopped
    );
    if !caller_ended_early {
        outcome.require_success(MediaErrorKind::FfmpegFailed, OP)?;
    } else if outcome.timed_out {
        return Err(MediaError::new(
            MediaErrorKind::FfmpegTimeout,
            OP,
            "the decoder exceeded its budget before it could be stopped",
        )
        .with_process(outcome.exit_code, outcome.stderr_tail));
    }

    if index == 0 {
        return Err(MediaError::new(
            MediaErrorKind::FrameExtractionFailed,
            OP,
            match truncated {
                Some(n) => format!(
                    "the decoder produced {n} bytes, short of a single {out_w}x{out_h} frame"
                ),
                None => format!(
                    "the decoder exited without producing any frame for the requested {} selection",
                    request.mode.label()
                ),
            },
        )
        .with_process(outcome.exit_code, outcome.stderr_tail));
    }

    let secs = elapsed.as_secs_f64();
    Ok(DecodeReport {
        artifact_id: artifact.artifact_id.clone(),
        mode: request.mode.label().to_string(),
        stop_reason,
        seek_accuracy,
        width: out_w,
        height: out_h,
        pixel_format: request.pixel_format,
        metrics: DecodeMetrics {
            decode_duration_ms: elapsed.as_millis() as u64,
            frames_emitted: index,
            bytes_read,
            effective_fps: if secs > 0.0 {
                Some(index as f64 / secs)
            } else {
                None
            },
            peak_frame_buffer_bytes: frame_len as u64,
        },
        ffmpeg_arguments: spec.display_args(),
        ffmpeg_version: toolchain.ffmpeg().version().map(|s| s.to_string()),
        ffmpeg_exit_code: outcome.exit_code,
        ffmpeg_stderr_tail: if outcome.stderr_tail.is_empty() {
            None
        } else {
            Some(outcome.stderr_tail.clone())
        },
        timestamp_source: timing_plan.source,
        truncated_trailing_bytes: truncated,
    })
}

/// Decodes and collects frames.
///
/// Convenience over [`decode_frames_with`] for bounded requests. The frame budget applies, so
/// an unbounded request against a large recording is clamped by configuration rather than
/// exhausting memory.
pub async fn decode_frames(
    toolchain: &MediaToolchain,
    artifact: &MediaArtifact,
    request: &DecodeRequest,
) -> MediaResult<DecodeOutcome> {
    let mut frames = Vec::new();
    let report = decode_frames_with(toolchain, artifact, request, |f| {
        frames.push(f);
        Ok(FrameAction::Continue)
    })
    .await?;
    Ok(DecodeOutcome { frames, report })
}

fn frame_budget(request: &DecodeRequest, configured_max: u64) -> u64 {
    match request.max_frames {
        Some(n) => n.min(configured_max).max(1),
        None => configured_max.max(1),
    }
}

/// Builds the decode argv.
///
/// The output is `-f rawvideo`, which cannot be satisfied by a stream copy: FFmpeg must run the
/// decoder to produce it.
pub fn build_decode_command(
    ffmpeg: &Path,
    input: &Path,
    request: &DecodeRequest,
    out_w: u32,
    out_h: u32,
) -> (CommandSpec, SeekAccuracy) {
    let mut args: Vec<String> = vec![
        "-hide_banner".into(),
        "-loglevel".into(),
        "error".into(),
        "-nostdin".into(),
    ];

    let mut seek_accuracy = SeekAccuracy::NotApplicable;
    let mut post_input_seek: Option<f64> = None;
    let mut duration: Option<f64> = None;

    if let ExtractionMode::TimeRange {
        start_secs,
        end_secs,
        accurate_seek,
    } = &request.mode
    {
        if *accurate_seek {
            // Output-side -ss: FFmpeg decodes from the start and discards, so the boundary is
            // frame-exact at the cost of decoding the lead-in.
            post_input_seek = Some(*start_secs);
            seek_accuracy = SeekAccuracy::Exact;
        } else {
            // Input-side -ss: fast, but lands on the keyframe at or before the request.
            args.push("-ss".into());
            args.push(format_secs(*start_secs));
            seek_accuracy = SeekAccuracy::KeyframeApproximate;
        }
        if let Some(end) = end_secs {
            duration = Some(end - start_secs);
        }
    }

    args.push("-i".into());
    args.push(input.to_string_lossy().to_string());

    if let Some(ss) = post_input_seek {
        args.push("-ss".into());
        args.push(format_secs(ss));
    }
    if let Some(d) = duration {
        args.push("-t".into());
        args.push(format_secs(d));
    }

    // Select the first video stream explicitly; a container with audio must not confuse the
    // raw output geometry.
    args.push("-map".into());
    args.push("0:v:0".into());

    let mut filters: Vec<String> = Vec::new();
    match &request.mode {
        ExtractionMode::EveryNFrames { n } if *n > 1 => {
            filters.push(format!("select=not(mod(n\\,{n}))"));
        }
        ExtractionMode::EveryNSeconds { interval_secs } => {
            filters.push(format!("fps=1/{}", format_secs(*interval_secs)));
        }
        _ => {}
    }
    if request.target_size.is_some() {
        filters.push(format!("scale={out_w}:{out_h}"));
    }
    if !filters.is_empty() {
        args.push("-vf".into());
        args.push(filters.join(","));
    }

    // `select` drops frames, so frame-rate normalisation must be off or FFmpeg would duplicate
    // pictures to keep the nominal rate — which would fabricate frames.
    args.push("-vsync".into());
    args.push("0".into());

    args.push("-pix_fmt".into());
    args.push(request.pixel_format.ffmpeg_name().to_string());
    args.push("-f".into());
    args.push("rawvideo".into());
    args.push("-".into());

    (CommandSpec::new(ffmpeg, args), seek_accuracy)
}

fn format_secs(v: f64) -> String {
    // A fixed 6-decimal spelling keeps the argv deterministic for a given request, which keeps
    // the recorded provenance reproducible.
    format!("{v:.6}")
}

/// How frame indices map to media time for one request.
#[derive(Debug, Clone, Copy)]
struct TimingPlan {
    /// Media-time of emitted frame 0.
    base_secs: Option<f64>,
    /// Media-time step between consecutive emitted frames.
    step_secs: Option<f64>,
    source: TimestampSource,
    recording_start: Option<chrono::DateTime<chrono::Utc>>,
}

impl TimingPlan {
    fn for_request(artifact: &MediaArtifact, request: &DecodeRequest) -> Self {
        let fps = artifact.properties.frame_rate.filter(|f| *f > 0.0);
        let (base, step, source) = match &request.mode {
            ExtractionMode::Sequential => (Some(0.0), fps.map(|f| 1.0 / f), rate_source(fps)),
            ExtractionMode::EveryNFrames { n } => {
                (Some(0.0), fps.map(|f| *n as f64 / f), rate_source(fps))
            }
            // The `fps` filter emits one frame per interval by construction, so the step is
            // exactly the interval and does not depend on the container's declared rate.
            ExtractionMode::EveryNSeconds { interval_secs } => (
                Some(0.0),
                Some(*interval_secs),
                TimestampSource::FrameRateDerived,
            ),
            ExtractionMode::TimeRange { start_secs, .. } => {
                (Some(*start_secs), fps.map(|f| 1.0 / f), rate_source(fps))
            }
        };
        Self {
            base_secs: base,
            step_secs: step,
            source,
            recording_start: artifact.start_timestamp,
        }
    }

    fn timing_for(&self, index: u64) -> FrameTiming {
        let pts = match (self.base_secs, self.step_secs) {
            (Some(base), Some(step)) => Some(base + index as f64 * step),
            // Frame 0 of a request still has a known position even without a rate.
            (Some(base), None) if index == 0 => Some(base),
            _ => None,
        };
        let source = if pts.is_some() {
            self.source
        } else {
            TimestampSource::Unknown
        };
        FrameTiming::from_offset(pts, source, self.recording_start)
    }
}

fn rate_source(fps: Option<f64>) -> TimestampSource {
    // Positions computed from a frame rate are an inference by this pipeline, so they are
    // labelled derived — never promoted to a container or DVR assertion.
    if fps.is_some() {
        TimestampSource::FrameRateDerived
    } else {
        TimestampSource::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{ContainerType, MediaProperties, MediaProvenance, ReconstructionMethod};
    use forensic_core::EvidenceId;
    use std::path::PathBuf;

    fn artifact(fps: Option<f64>) -> MediaArtifact {
        MediaArtifact {
            artifact_id: "art-1".into(),
            path: PathBuf::from("derived/art-1.mp4"),
            size_bytes: 4096,
            media_hash: None,
            properties: MediaProperties {
                container: Some(ContainerType::Mp4),
                codec: Some(CodecKind::H264),
                width: Some(320),
                height: Some(240),
                frame_rate: fps,
                duration_secs: Some(2.0),
                declared_frame_count: Some(50),
                pixel_format: Some("yuv420p".into()),
            },
            reconstruction_method: ReconstructionMethod::ContainerRemux,
            reconstruction_status: crate::artifact::ReconstructionStatus::Complete,
            validation_status: ValidationStatus::Valid,
            provenance: MediaProvenance::new(EvidenceId::new()),
            start_timestamp: None,
            end_timestamp: None,
        }
    }

    #[test]
    fn the_decode_command_asks_for_rawvideo_which_a_stream_copy_cannot_satisfy() {
        let (spec, accuracy) = build_decode_command(
            Path::new("ffmpeg"),
            Path::new("in.mp4"),
            &DecodeRequest::sequential(),
            320,
            240,
        );
        assert!(spec.args.contains(&"rawvideo".to_string()));
        assert!(spec.args.contains(&"bgr24".to_string()));
        assert_eq!(spec.args.last().unwrap(), "-");
        // The decisive assertion: no stream copy anywhere in the argv.
        assert!(!spec.args.iter().any(|a| a == "copy"));
        assert_eq!(accuracy, SeekAccuracy::NotApplicable);
    }

    #[test]
    fn sampling_every_n_frames_uses_a_select_filter_and_disables_frame_duplication() {
        let (spec, _) = build_decode_command(
            Path::new("ffmpeg"),
            Path::new("in.mp4"),
            &DecodeRequest::every_n_frames(5),
            320,
            240,
        );
        let vf = spec.args.iter().position(|a| a == "-vf").unwrap();
        assert_eq!(spec.args[vf + 1], "select=not(mod(n\\,5))");
        // Without -vsync 0, FFmpeg would re-duplicate dropped frames to hold the nominal rate.
        let vsync = spec.args.iter().position(|a| a == "-vsync").unwrap();
        assert_eq!(spec.args[vsync + 1], "0");
    }

    #[test]
    fn sampling_every_n_frames_with_n_of_one_adds_no_select_filter() {
        let (spec, _) = build_decode_command(
            Path::new("ffmpeg"),
            Path::new("in.mp4"),
            &DecodeRequest::every_n_frames(1),
            320,
            240,
        );
        assert!(!spec.args.iter().any(|a| a.starts_with("select=")));
    }

    #[test]
    fn sampling_every_n_seconds_uses_an_fps_filter() {
        let (spec, _) = build_decode_command(
            Path::new("ffmpeg"),
            Path::new("in.mp4"),
            &DecodeRequest::every_n_seconds(2.0),
            320,
            240,
        );
        let vf = spec.args.iter().position(|a| a == "-vf").unwrap();
        assert_eq!(spec.args[vf + 1], "fps=1/2.000000");
    }

    #[test]
    fn fast_seeking_is_reported_as_keyframe_approximate_not_as_exact() {
        let (spec, accuracy) = build_decode_command(
            Path::new("ffmpeg"),
            Path::new("in.mp4"),
            &DecodeRequest::time_range(1.5, Some(3.5), false),
            320,
            240,
        );
        assert_eq!(accuracy, SeekAccuracy::KeyframeApproximate);
        // Input-side -ss precedes -i.
        let ss = spec.args.iter().position(|a| a == "-ss").unwrap();
        let i = spec.args.iter().position(|a| a == "-i").unwrap();
        assert!(ss < i);
        let t = spec.args.iter().position(|a| a == "-t").unwrap();
        assert_eq!(spec.args[t + 1], "2.000000");
    }

    #[test]
    fn accurate_seeking_places_ss_after_the_input_and_is_reported_as_exact() {
        let (spec, accuracy) = build_decode_command(
            Path::new("ffmpeg"),
            Path::new("in.mp4"),
            &DecodeRequest::time_range(1.5, None, true),
            320,
            240,
        );
        assert_eq!(accuracy, SeekAccuracy::Exact);
        let ss = spec.args.iter().position(|a| a == "-ss").unwrap();
        let i = spec.args.iter().position(|a| a == "-i").unwrap();
        assert!(ss > i);
    }

    #[test]
    fn a_target_size_adds_a_decoder_side_scale_filter() {
        let req = DecodeRequest::sequential().with_target_size(160, 120);
        let (spec, _) =
            build_decode_command(Path::new("ffmpeg"), Path::new("in.mp4"), &req, 160, 120);
        let vf = spec.args.iter().position(|a| a == "-vf").unwrap();
        assert_eq!(spec.args[vf + 1], "scale=160:120");
    }

    #[test]
    fn unusable_sampling_configurations_are_rejected_before_any_process_is_spawned() {
        assert_eq!(
            ExtractionMode::EveryNFrames { n: 0 }
                .validate()
                .unwrap_err()
                .kind,
            MediaErrorKind::InvalidConfiguration
        );
        assert_eq!(
            ExtractionMode::EveryNSeconds { interval_secs: 0.0 }
                .validate()
                .unwrap_err()
                .kind,
            MediaErrorKind::InvalidConfiguration
        );
        assert_eq!(
            ExtractionMode::TimeRange {
                start_secs: 5.0,
                end_secs: Some(2.0),
                accurate_seek: false
            }
            .validate()
            .unwrap_err()
            .kind,
            MediaErrorKind::InvalidConfiguration
        );
        assert!(ExtractionMode::Sequential.validate().is_ok());
    }

    #[test]
    fn sequential_timestamps_step_by_the_frame_interval_and_are_labelled_derived() {
        let art = artifact(Some(25.0));
        let plan = TimingPlan::for_request(&art, &DecodeRequest::sequential());
        assert_eq!(plan.timing_for(0).presentation_timestamp_secs, Some(0.0));
        assert_eq!(plan.timing_for(25).presentation_timestamp_secs, Some(1.0));
        assert_eq!(
            plan.timing_for(0).pts_source,
            TimestampSource::FrameRateDerived
        );
        assert!(plan.timing_for(0).pts_source.is_derived());
    }

    #[test]
    fn sampled_timestamps_account_for_the_sampling_interval() {
        let art = artifact(Some(25.0));
        let plan = TimingPlan::for_request(&art, &DecodeRequest::every_n_frames(25));
        // Emitted frame 1 is source frame 25, i.e. one second in.
        assert_eq!(plan.timing_for(1).presentation_timestamp_secs, Some(1.0));

        let plan2 = TimingPlan::for_request(&art, &DecodeRequest::every_n_seconds(0.5));
        assert_eq!(plan2.timing_for(4).presentation_timestamp_secs, Some(2.0));
    }

    #[test]
    fn time_range_timestamps_are_offset_by_the_requested_start() {
        let art = artifact(Some(10.0));
        let plan = TimingPlan::for_request(&art, &DecodeRequest::time_range(3.0, Some(4.0), false));
        assert_eq!(plan.timing_for(0).presentation_timestamp_secs, Some(3.0));
        assert_eq!(plan.timing_for(5).presentation_timestamp_secs, Some(3.5));
    }

    #[test]
    fn without_a_frame_rate_only_the_first_frames_position_is_known() {
        let art = artifact(None);
        let plan = TimingPlan::for_request(&art, &DecodeRequest::sequential());
        assert_eq!(plan.timing_for(0).presentation_timestamp_secs, Some(0.0));
        assert_eq!(plan.timing_for(1).presentation_timestamp_secs, None);
        assert_eq!(plan.timing_for(1).pts_source, TimestampSource::Unknown);
    }

    #[test]
    fn a_dvr_start_time_anchors_the_wall_clock_but_does_not_strengthen_it() {
        let mut art = artifact(Some(25.0));
        art.start_timestamp = Some("2024-05-06T08:00:00Z".parse().unwrap());
        let plan = TimingPlan::for_request(&art, &DecodeRequest::sequential());
        let t = plan.timing_for(50);
        assert_eq!(
            t.wall_clock.unwrap().to_rfc3339(),
            "2024-05-06T08:00:02+00:00"
        );
        assert_eq!(t.wall_clock_source, TimestampSource::FrameRateDerived);
        assert!(!t.wall_clock_source.is_authoritative());
    }

    #[test]
    fn the_frame_budget_is_clamped_by_configuration() {
        assert_eq!(frame_budget(&DecodeRequest::sequential(), 100), 100);
        assert_eq!(
            frame_budget(&DecodeRequest::sequential().with_max_frames(10), 100),
            10
        );
        assert_eq!(
            frame_budget(&DecodeRequest::sequential().with_max_frames(1_000), 100),
            100
        );
    }

    #[tokio::test]
    async fn decoding_an_unvalidated_artifact_is_refused_rather_than_attempted() {
        let tc = MediaToolchain::with_availability(
            crate::tools::ToolAvailability::Available {
                path: PathBuf::from("ffmpeg"),
                source: crate::tools::ToolSource::SystemPath,
                version: "ffmpeg version test".into(),
            },
            crate::tools::ToolAvailability::NotFound { searched: vec![] },
            crate::tools::MediaConfig::default(),
        );
        let mut art = artifact(Some(25.0));
        art.validation_status = ValidationStatus::Unavailable;
        let err = decode_frames(&tc, &art, &DecodeRequest::sequential())
            .await
            .unwrap_err();
        assert_eq!(err.kind, MediaErrorKind::FfprobeUnavailable);
        assert!(err.detail.contains("VALIDATION_UNAVAILABLE"));
    }

    #[tokio::test]
    async fn decoding_without_ffmpeg_reports_the_dependency_not_a_decode_failure() {
        let tc = MediaToolchain::with_availability(
            crate::tools::ToolAvailability::NotFound { searched: vec![] },
            crate::tools::ToolAvailability::NotFound { searched: vec![] },
            crate::tools::MediaConfig::default(),
        );
        let art = artifact(Some(25.0));
        let err = decode_frames(&tc, &art, &DecodeRequest::sequential())
            .await
            .unwrap_err();
        assert_eq!(err.kind, MediaErrorKind::FfmpegUnavailable);
    }
}
