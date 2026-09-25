//! The standardized decoded-frame representation.
//!
//! [`VideoFrame`] is the boundary type of this subsystem: everything downstream — image
//! processing, analysis, any future AI engine — consumes this and nothing else. It carries no
//! OEM concept at all, so an analysis engine cannot come to depend on which vendor's recorder
//! produced the bytes.
//!
//! Note the deliberate distinction from `recovery::video::VideoFrame`. That type describes a
//! *frame-shaped byte range inside the evidence image* (offset, size, NAL type) and holds no
//! pixels; it belongs to the recovery layer and is untouched by this work. This type describes
//! a *decoded picture* and holds actual pixel data. They are different objects at different
//! stages and are intentionally not merged.
//!
//! ## Temporal provenance
//!
//! A forensic frame must be able to answer "how do you know this frame is from 14:32:07?".
//! Every frame therefore carries both a timestamp and a [`TimestampSource`] saying how that
//! timestamp was obtained. A timestamp derived from a frame index and a nominal frame rate is
//! never labelled as if the recorder had asserted it.

use crate::artifact::ContentHash;
use crate::error::{MediaError, MediaErrorKind, MediaResult};
use crate::hashing;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use forensic_core::EvidenceId;
use serde::{Deserialize, Serialize};

/// Pixel layout of a decoded frame buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PixelFormat {
    /// 8 bits per channel, blue-green-red interleaved. The OpenCV-native layout.
    Bgr24,
    /// 8 bits per channel, red-green-blue interleaved.
    Rgb24,
    /// 8-bit single channel.
    Gray8,
}

impl PixelFormat {
    pub fn channels(&self) -> usize {
        match self {
            Self::Bgr24 | Self::Rgb24 => 3,
            Self::Gray8 => 1,
        }
    }

    /// The FFmpeg `-pix_fmt` token for this layout.
    pub fn ffmpeg_name(&self) -> &'static str {
        match self {
            Self::Bgr24 => "bgr24",
            Self::Rgb24 => "rgb24",
            Self::Gray8 => "gray",
        }
    }

    /// Exact byte length of one frame at the given geometry, or `None` on overflow.
    pub fn frame_len(&self, width: u32, height: u32) -> Option<usize> {
        (width as usize)
            .checked_mul(height as usize)
            .and_then(|px| px.checked_mul(self.channels()))
    }
}

/// How a frame's wall-clock timestamp was established.
///
/// Ordered from strongest to weakest evidence. A weaker source is never reported as a stronger
/// one; in particular [`TimestampSource::FrameRateDerived`] is an inference by this pipeline and
/// says nothing about what the recorder wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TimestampSource {
    /// Asserted by the DVR/NVR recording metadata supplied by the upstream parser.
    DvrMetadata,
    /// Read from the media container's own timing fields.
    Container,
    /// FFmpeg's presentation timestamp for this packet/frame.
    Pts,
    /// Computed as `frame_index / frame_rate`. An inference, not an assertion.
    FrameRateDerived,
    /// No timing information of any kind was available.
    Unknown,
}

impl TimestampSource {
    pub fn label(&self) -> &'static str {
        match self {
            Self::DvrMetadata => "DVR_METADATA",
            Self::Container => "CONTAINER",
            Self::Pts => "PTS",
            Self::FrameRateDerived => "FRAME_RATE_DERIVED",
            Self::Unknown => "UNKNOWN",
        }
    }

    /// Whether this pipeline computed the value rather than reading it from the media.
    pub fn is_derived(&self) -> bool {
        matches!(self, Self::FrameRateDerived)
    }

    /// Whether the recorder itself asserted the value.
    pub fn is_authoritative(&self) -> bool {
        matches!(self, Self::DvrMetadata)
    }
}

/// The temporal position of a frame, with its evidentiary strength attached.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrameTiming {
    /// Seconds from the start of the media. `None` when not determinable.
    pub presentation_timestamp_secs: Option<f64>,
    /// How `presentation_timestamp_secs` was obtained.
    pub pts_source: TimestampSource,
    /// Absolute wall-clock time, when an anchor exists to compute one.
    ///
    /// This requires both a media-relative position and a recording start time from upstream.
    /// Without an anchor it stays `None` rather than defaulting to the current time.
    pub wall_clock: Option<DateTime<Utc>>,
    /// The strength of `wall_clock`. Never stronger than the weaker of its two inputs.
    pub wall_clock_source: TimestampSource,
}

impl FrameTiming {
    /// Timing for a frame with no temporal information at all.
    pub fn unknown() -> Self {
        Self {
            presentation_timestamp_secs: None,
            pts_source: TimestampSource::Unknown,
            wall_clock: None,
            wall_clock_source: TimestampSource::Unknown,
        }
    }

    /// Builds timing from a media-relative position and an optional recording anchor.
    ///
    /// The wall-clock strength is `max(anchor_strength, pts_strength)` in the ordering of
    /// [`TimestampSource`], i.e. the *weaker* of the two pieces of evidence — a DVR-asserted
    /// start time combined with a frame-rate-derived offset yields a frame-rate-derived
    /// wall clock, because that is how good the answer actually is.
    pub fn from_offset(
        pts_secs: Option<f64>,
        pts_source: TimestampSource,
        recording_start: Option<DateTime<Utc>>,
    ) -> Self {
        let (wall_clock, wall_clock_source) = match (recording_start, pts_secs) {
            (Some(anchor), Some(offset)) => {
                let nanos = (offset * 1_000_000_000.0).round();
                // A position outside the representable range is refused rather than wrapped
                // into a wrong but plausible-looking timestamp.
                if !nanos.is_finite() || nanos.abs() > i64::MAX as f64 {
                    (None, TimestampSource::Unknown)
                } else {
                    let delta = ChronoDuration::nanoseconds(nanos as i64);
                    match anchor.checked_add_signed(delta) {
                        Some(t) => (
                            Some(t),
                            // DvrMetadata is the strongest variant and sorts first, so `max`
                            // selects the weaker of the two sources.
                            TimestampSource::DvrMetadata.max(pts_source),
                        ),
                        None => (None, TimestampSource::Unknown),
                    }
                }
            }
            _ => (None, TimestampSource::Unknown),
        };
        Self {
            presentation_timestamp_secs: pts_secs,
            pts_source,
            wall_clock,
            wall_clock_source,
        }
    }
}

/// What has been done to a frame since it left the decoder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessingStep {
    /// e.g. `"resize"`, `"cvt_color"`, `"roi"`.
    pub operation: String,
    /// The exact configuration applied, so the step is reproducible.
    pub parameters: String,
    /// Which implementation performed it. Never claims OpenCV for a fallback operation.
    pub backend: String,
}

/// Traceability of a decoded frame back to the evidence image.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrameProvenance {
    pub evidence_id: EvidenceId,
    pub artifact_id: String,
    /// The first evidence byte offset of the media artifact this frame was decoded from.
    ///
    /// This locates the *artifact* in the image, not the individual frame: a decoded picture
    /// generally has no single byte range in the source, and claiming one would be an
    /// invention. Per-frame source offsets belong to the recovery layer's own frame index.
    pub artifact_source_offset: Option<u64>,
    pub source_recording_id: Option<String>,
    /// The media artifact's digest, linking this frame to exact derived bytes.
    pub artifact_media_hash: Option<String>,
    /// The decoder that produced the frame, e.g. `"ffmpeg rawvideo"` plus its version.
    pub decoder: String,
    /// Operations applied after decoding, in order.
    pub processing_chain: Vec<ProcessingStep>,
}

/// A decoded video frame with pixel data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VideoFrame {
    /// Deterministic identifier: `"{artifact_id}:frame:{frame_index}"`.
    pub frame_id: String,
    pub artifact_id: String,
    /// Zero-based index in the *decoded output sequence*.
    ///
    /// Under sampled extraction this counts emitted frames, not source frames; the sampling
    /// configuration recorded on the extraction result is what relates the two.
    pub frame_index: u64,
    pub timing: FrameTiming,
    pub width: u32,
    pub height: u32,
    pub pixel_format: PixelFormat,
    /// Raw interleaved pixel bytes, exactly `width * height * channels` long.
    #[serde(skip)]
    pub data: Vec<u8>,
    pub provenance: FrameProvenance,
}

impl VideoFrame {
    /// Builds a frame, checking the buffer against the declared geometry.
    ///
    /// A buffer whose length disagrees with `width * height * channels` is rejected as
    /// [`MediaErrorKind::InvalidFrame`] rather than padded or cropped into shape. A short read
    /// at end of stream is a truncated frame, and a truncated frame is not evidence.
    pub fn new(
        artifact_id: impl Into<String>,
        frame_index: u64,
        width: u32,
        height: u32,
        pixel_format: PixelFormat,
        data: Vec<u8>,
        timing: FrameTiming,
        provenance: FrameProvenance,
    ) -> MediaResult<Self> {
        let artifact_id = artifact_id.into();
        let expected = pixel_format.frame_len(width, height).ok_or_else(|| {
            MediaError::new(
                MediaErrorKind::InvalidFrame,
                "VideoFrame::new",
                format!("frame geometry {width}x{height} overflows an address"),
            )
        })?;
        if expected == 0 {
            return Err(MediaError::new(
                MediaErrorKind::InvalidFrame,
                "VideoFrame::new",
                format!("frame geometry {width}x{height} has no pixels"),
            ));
        }
        if data.len() != expected {
            return Err(MediaError::new(
                MediaErrorKind::InvalidFrame,
                "VideoFrame::new",
                format!(
                    "frame buffer is {} bytes but {width}x{height} {:?} requires {expected}",
                    data.len(),
                    pixel_format
                ),
            ));
        }
        Ok(Self {
            frame_id: format!("{artifact_id}:frame:{frame_index}"),
            artifact_id,
            frame_index,
            timing,
            width,
            height,
            pixel_format,
            data,
            provenance,
        })
    }

    /// Bytes per pixel row.
    pub fn stride(&self) -> usize {
        self.width as usize * self.pixel_format.channels()
    }

    /// SHA-256 over this frame's pixel buffer.
    ///
    /// Distinct from both the source hash and the media artifact hash: it covers decoded
    /// pixels, which exist in no file. It is deterministic for a given decoder and settings,
    /// which is what makes a processed-frame chain auditable.
    pub fn content_hash(&self) -> ContentHash {
        hashing::hash_bytes(&self.data)
    }

    /// Records a processing step on the frame's provenance chain.
    pub fn record_processing(&mut self, step: ProcessingStep) {
        self.provenance.processing_chain.push(step);
    }

    /// Frame metadata without the pixel buffer, for API responses and reports.
    pub fn metadata(&self) -> serde_json::Value {
        serde_json::json!({
            "frame_id": self.frame_id,
            "artifact_id": self.artifact_id,
            "frame_index": self.frame_index,
            "width": self.width,
            "height": self.height,
            "pixel_format": self.pixel_format,
            "byte_len": self.data.len(),
            "presentation_timestamp_secs": self.timing.presentation_timestamp_secs,
            "timestamp_source": self.timing.pts_source.label(),
            "timestamp_is_derived": self.timing.pts_source.is_derived(),
            "wall_clock": self.timing.wall_clock.map(|t| t.to_rfc3339()),
            "wall_clock_source": self.timing.wall_clock_source.label(),
            "frame_sha256": self.content_hash().hex,
            "evidence_id": self.provenance.evidence_id.to_string(),
            "artifact_source_offset": self.provenance.artifact_source_offset,
            "source_recording_id": self.provenance.source_recording_id,
            "decoder": self.provenance.decoder,
            "processing_chain": self.provenance.processing_chain,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance() -> FrameProvenance {
        FrameProvenance {
            evidence_id: EvidenceId::new(),
            artifact_id: "art-1".into(),
            artifact_source_offset: Some(65536),
            source_recording_id: Some("dahua:p0:blk1".into()),
            artifact_media_hash: Some("deadbeef".into()),
            decoder: "ffmpeg rawvideo".into(),
            processing_chain: vec![],
        }
    }

    fn frame(w: u32, h: u32, fmt: PixelFormat) -> MediaResult<VideoFrame> {
        let len = fmt.frame_len(w, h).unwrap_or(0);
        VideoFrame::new(
            "art-1",
            0,
            w,
            h,
            fmt,
            vec![7u8; len],
            FrameTiming::unknown(),
            provenance(),
        )
    }

    #[test]
    fn frame_length_follows_geometry_and_channel_count() {
        assert_eq!(PixelFormat::Bgr24.frame_len(4, 3), Some(36));
        assert_eq!(PixelFormat::Gray8.frame_len(4, 3), Some(12));
        assert_eq!(PixelFormat::Bgr24.channels(), 3);
        assert_eq!(PixelFormat::Bgr24.ffmpeg_name(), "bgr24");
    }

    #[test]
    fn a_buffer_that_disagrees_with_the_geometry_is_rejected_not_reshaped() {
        let err = VideoFrame::new(
            "art-1",
            0,
            4,
            3,
            PixelFormat::Bgr24,
            vec![0u8; 30], // 6 bytes short of 36
            FrameTiming::unknown(),
            provenance(),
        )
        .unwrap_err();
        assert_eq!(err.kind, MediaErrorKind::InvalidFrame);
        assert!(err.detail.contains("30"));
    }

    #[test]
    fn a_zero_pixel_geometry_is_rejected() {
        assert_eq!(
            frame(0, 10, PixelFormat::Bgr24).unwrap_err().kind,
            MediaErrorKind::InvalidFrame
        );
    }

    #[test]
    fn frame_ids_are_deterministic_and_carry_the_artifact() {
        let f = frame(4, 3, PixelFormat::Bgr24).unwrap();
        assert_eq!(f.frame_id, "art-1:frame:0");
        assert_eq!(f.stride(), 12);
    }

    #[test]
    fn frame_hash_is_deterministic_and_covers_pixels_not_the_file() {
        let a = frame(4, 3, PixelFormat::Bgr24).unwrap();
        let b = frame(4, 3, PixelFormat::Bgr24).unwrap();
        assert_eq!(a.content_hash().hex, b.content_hash().hex);
        assert_eq!(a.content_hash().bytes_hashed, 36);

        let mut c = frame(4, 3, PixelFormat::Bgr24).unwrap();
        c.data[0] = 8;
        assert_ne!(a.content_hash().hex, c.content_hash().hex);
    }

    #[test]
    fn a_derived_timestamp_is_labelled_derived_and_not_promoted_to_dvr_metadata() {
        let t = FrameTiming::from_offset(Some(2.0), TimestampSource::FrameRateDerived, None);
        assert_eq!(t.pts_source, TimestampSource::FrameRateDerived);
        assert!(t.pts_source.is_derived());
        assert!(!t.pts_source.is_authoritative());
        assert!(t.wall_clock.is_none(), "no anchor means no wall clock");
        assert_eq!(t.wall_clock_source, TimestampSource::Unknown);
    }

    #[test]
    fn a_wall_clock_is_only_as_strong_as_its_weakest_input() {
        let anchor: DateTime<Utc> = "2024-03-01T10:00:00Z".parse().unwrap();

        // DVR anchor + derived offset => the answer is derived.
        let derived =
            FrameTiming::from_offset(Some(1.5), TimestampSource::FrameRateDerived, Some(anchor));
        assert_eq!(
            derived.wall_clock.unwrap().to_rfc3339(),
            "2024-03-01T10:00:01.500+00:00"
        );
        assert_eq!(derived.wall_clock_source, TimestampSource::FrameRateDerived);

        // DVR anchor + container PTS => still only as strong as PTS.
        let from_pts = FrameTiming::from_offset(Some(1.5), TimestampSource::Pts, Some(anchor));
        assert_eq!(from_pts.wall_clock_source, TimestampSource::Pts);
    }

    #[test]
    fn no_position_means_no_wall_clock_rather_than_the_anchor_itself() {
        let anchor: DateTime<Utc> = "2024-03-01T10:00:00Z".parse().unwrap();
        let t = FrameTiming::from_offset(None, TimestampSource::Unknown, Some(anchor));
        assert!(t.wall_clock.is_none());
    }

    #[test]
    fn processing_steps_accumulate_in_order_on_the_provenance_chain() {
        let mut f = frame(4, 3, PixelFormat::Bgr24).unwrap();
        f.record_processing(ProcessingStep {
            operation: "resize".into(),
            parameters: "2x2".into(),
            backend: "pure_rust_fallback".into(),
        });
        f.record_processing(ProcessingStep {
            operation: "cvt_color".into(),
            parameters: "BGR24->GRAY8".into(),
            backend: "pure_rust_fallback".into(),
        });
        assert_eq!(f.provenance.processing_chain.len(), 2);
        assert_eq!(f.provenance.processing_chain[0].operation, "resize");
        let meta = f.metadata();
        assert_eq!(meta["frame_id"], "art-1:frame:0");
        assert_eq!(meta["timestamp_source"], "UNKNOWN");
        assert_eq!(meta["artifact_source_offset"], 65536);
    }

    #[test]
    fn timestamp_source_ordering_ranks_evidence_strength() {
        assert!(TimestampSource::DvrMetadata < TimestampSource::Container);
        assert!(TimestampSource::Container < TimestampSource::Pts);
        assert!(TimestampSource::Pts < TimestampSource::FrameRateDerived);
        assert!(TimestampSource::FrameRateDerived < TimestampSource::Unknown);
    }
}
