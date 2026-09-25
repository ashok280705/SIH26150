//! The standardized media artifact: the single object the media pipeline consumes.
//!
//! A [`MediaArtifact`] describes one reconstructed, derived media file on disk together with
//! everything the pipeline knows about where its bytes came from. Two rules govern it:
//!
//! 1. **It is a derived artifact, never source evidence.** The source evidence image is
//!    identified by [`MediaArtifact::source_evidence_id`] and the byte ranges it came from,
//!    but the path in [`MediaArtifact::path`] always points at a separate derived file. The
//!    media pipeline has no write path to evidence at all.
//! 2. **Nothing is invented.** Every field the upstream OEM/recovery layer does not supply is
//!    `None`/`Unknown`, and stays that way until an actual measurement — an ffprobe run, a
//!    decode — establishes it. A field is never defaulted to a plausible value to make the
//!    pipeline look complete.

use chrono::{DateTime, Utc};
use forensic_core::EvidenceId;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Container format, as observed — not as assumed from a filename.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContainerType {
    Mp4,
    Matroska,
    Mpegts,
    /// A raw Annex-B / elementary bitstream with no container at all.
    ElementaryStream,
    /// ffprobe reported a container this pipeline has no specific handling for; the exact
    /// `format_name` string is preserved.
    Other(String),
    /// Not established. This is the correct value before a probe has run.
    Unknown,
}

impl ContainerType {
    /// Classifies an ffprobe `format_name` list (e.g. `"mov,mp4,m4a,3gp,3g2,mj2"`).
    pub fn from_ffprobe_format_name(name: &str) -> Self {
        let n = name.to_ascii_lowercase();
        if n.is_empty() {
            Self::Unknown
        } else if n.contains("mp4") || n.contains("mov") || n.contains("isom") {
            Self::Mp4
        } else if n.contains("matroska") || n.contains("webm") {
            Self::Matroska
        } else if n.contains("mpegts") {
            Self::Mpegts
        } else if n.contains("h264") || n.contains("hevc") || n.contains("h265") {
            Self::ElementaryStream
        } else {
            Self::Other(name.to_string())
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Mp4 => "MP4".into(),
            Self::Matroska => "MATROSKA".into(),
            Self::Mpegts => "MPEGTS".into(),
            Self::ElementaryStream => "ELEMENTARY_STREAM".into(),
            Self::Other(s) => format!("OTHER({s})"),
            Self::Unknown => "UNKNOWN".into(),
        }
    }
}

/// Codec identity as a media fact.
///
/// This is intentionally the media layer's own type rather than a re-export of an upstream
/// codec enum: the media subsystem must compile and run without knowing which OEM crate, if
/// any, produced the bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CodecKind {
    H264,
    H265,
    Mjpeg,
    Mpeg4,
    /// A codec name ffprobe reported that this pipeline has no specific handling for.
    Other(String),
    /// Not established. The correct value when the upstream parser does not supply a codec.
    Unknown,
}

impl CodecKind {
    /// Maps an ffprobe `codec_name` to a codec identity.
    pub fn from_ffprobe_codec_name(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "h264" | "avc1" | "avc" => Self::H264,
            "hevc" | "h265" | "hvc1" | "hev1" => Self::H265,
            "mjpeg" | "jpeg" => Self::Mjpeg,
            "mpeg4" | "msmpeg4v3" | "mp4v" => Self::Mpeg4,
            "" => Self::Unknown,
            other => Self::Other(other.to_string()),
        }
    }

    /// The FFmpeg input demuxer name for this codec as a raw elementary stream, when one
    /// exists.
    ///
    /// Returning `None` is what drives `UNSUPPORTED_CODEC` for raw-stream inputs; it does not
    /// prevent decoding the same codec inside a real container, where the container's own
    /// demuxer is used.
    pub fn elementary_stream_demuxer(&self) -> Option<&'static str> {
        match self {
            Self::H264 => Some("h264"),
            Self::H265 => Some("hevc"),
            Self::Mjpeg => Some("mjpeg"),
            Self::Mpeg4 => Some("m4v"),
            Self::Other(_) | Self::Unknown => None,
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::H264 => "H264".into(),
            Self::H265 => "H265".into(),
            Self::Mjpeg => "MJPEG".into(),
            Self::Mpeg4 => "MPEG4".into(),
            Self::Other(s) => format!("OTHER({s})"),
            Self::Unknown => "UNKNOWN".into(),
        }
    }
}

/// How the derived media file came to exist.
///
/// This records the media layer's own operation. It deliberately says nothing about which OEM
/// recovery level produced the byte ranges — that is upstream provenance, carried separately in
/// [`MediaProvenance::source_regions`] and [`MediaProvenance::upstream_component`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReconstructionMethod {
    /// Evidence bytes were concatenated verbatim into an elementary stream file.
    ElementaryStreamMaterialization,
    /// An elementary stream was stream-copied into a container. No re-encoding.
    ContainerRemux,
    /// The file was supplied by a caller outside this pipeline (e.g. a test fixture).
    ExternallyProvided,
    Unknown,
}

/// Whether the derived file was actually produced, and how completely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReconstructionStatus {
    /// The file exists on disk and its byte count matches what was written.
    Complete,
    /// The file exists but upstream reported that some source ranges were missing. Gaps are
    /// marked, never filled.
    PartialWithGaps,
    /// Reconstruction was attempted and did not produce a usable file.
    Failed,
    /// Not attempted or not reported.
    Unknown,
}

/// The outcome of media validation, as a set of distinguishable states.
///
/// This is *not* a boolean, and `Unavailable` is *not* `Valid`. A host without ffprobe has not
/// validated anything, and the UI must not be able to render that as a pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidationStatus {
    /// ffprobe ran, exited zero, and reported a usable video stream.
    Valid,
    /// ffprobe ran and rejected the file, or reported no video stream.
    Invalid,
    /// The file parses but carries a container/codec this pipeline cannot decode.
    Unsupported,
    /// Structure is partially readable but internally inconsistent.
    Corrupted,
    /// ffprobe is not installed on this host. Nothing was checked.
    Unavailable,
    /// ffprobe was terminated for exceeding its budget. Nothing was concluded.
    Timeout,
    /// Validation has not been attempted yet.
    NotRun,
}

impl ValidationStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Valid => "VALID",
            Self::Invalid => "INVALID",
            Self::Unsupported => "UNSUPPORTED",
            Self::Corrupted => "CORRUPTED",
            Self::Unavailable => "VALIDATION_UNAVAILABLE",
            Self::Timeout => "VALIDATION_TIMEOUT",
            Self::NotRun => "VALIDATION_NOT_RUN",
        }
    }

    /// Whether decoding may be attempted. Only an actually-validated file qualifies.
    pub fn permits_decode(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// One contiguous byte range of the source evidence image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceByteRange {
    pub offset: u64,
    pub length: u64,
}

/// A digest over bytes that were actually read.
///
/// There is no "empty" or zero-filled variant by construction: a [`ContentHash`] can only be
/// built by [`crate::hashing`] after a successful read, so a failed hash surfaces as an error
/// rather than as a plausible-looking string of zeroes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentHash {
    /// Always `"SHA-256"` today; recorded explicitly so a future change is visible in reports.
    pub algorithm: String,
    pub hex: String,
    /// The number of bytes fed into the digest. A hash without a byte count cannot be audited.
    pub bytes_hashed: u64,
}

/// The provenance chain from source evidence down to this derived media file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaProvenance {
    pub evidence_id: EvidenceId,
    /// The evidence byte ranges these media bytes came from, in the order they were joined.
    /// Empty when the artifact was supplied from outside the evidence path (e.g. a fixture).
    pub source_regions: Vec<SourceByteRange>,
    /// Hash of the source bytes as read from evidence, when upstream computed one.
    ///
    /// Distinct from [`MediaArtifact::media_hash`]: they cover different byte sequences and are
    /// expected to differ whenever any containerization happened.
    pub source_hash: Option<ContentHash>,
    /// The upstream component that produced the source ranges, e.g. `"recovery::engine"`.
    /// Free text supplied by the caller; the media layer does not interpret it.
    pub upstream_component: Option<String>,
    /// The upstream recording identifier, kept verbatim so an artifact traces back to the
    /// exact discovery it came from.
    pub source_recording_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl MediaProvenance {
    pub fn new(evidence_id: EvidenceId) -> Self {
        Self {
            evidence_id,
            source_regions: Vec::new(),
            source_hash: None,
            upstream_component: None,
            source_recording_id: None,
            created_at: Utc::now(),
        }
    }

    pub fn with_regions(mut self, regions: Vec<SourceByteRange>) -> Self {
        self.source_regions = regions;
        self
    }

    pub fn with_source_hash(mut self, hash: ContentHash) -> Self {
        self.source_hash = Some(hash);
        self
    }

    pub fn with_upstream(
        mut self,
        component: impl Into<String>,
        recording_id: Option<String>,
    ) -> Self {
        self.upstream_component = Some(component.into());
        self.source_recording_id = recording_id;
        self
    }

    /// The first source offset, when one is known. Used to anchor frame provenance.
    pub fn primary_source_offset(&self) -> Option<u64> {
        self.source_regions.first().map(|r| r.offset)
    }

    /// Total source bytes across all ranges.
    pub fn source_size(&self) -> Option<u64> {
        if self.source_regions.is_empty() {
            None
        } else {
            self.source_regions
                .iter()
                .map(|r| r.length)
                .sum::<u64>()
                .into()
        }
    }
}

/// Measured media properties. Every field is optional because every field is a measurement.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct MediaProperties {
    pub container: Option<ContainerType>,
    pub codec: Option<CodecKind>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    /// Frames per second as reported by the container, as an exact rational reduced to f64.
    pub frame_rate: Option<f64>,
    pub duration_secs: Option<f64>,
    /// Number of frames the container claims. Not the number decoded.
    pub declared_frame_count: Option<u64>,
    pub pixel_format: Option<String>,
}

impl MediaProperties {
    /// The container/codec facts the upstream layer supplied before any probe ran.
    ///
    /// Callers pass `CodecKind::Unknown` when the OEM parser does not establish a codec. That
    /// is the intended value; it is never upgraded by guesswork.
    pub fn declared(container: ContainerType, codec: CodecKind) -> Self {
        Self {
            container: Some(container),
            codec: Some(codec),
            ..Default::default()
        }
    }

    pub fn codec_or_unknown(&self) -> CodecKind {
        self.codec.clone().unwrap_or(CodecKind::Unknown)
    }

    pub fn container_or_unknown(&self) -> ContainerType {
        self.container.clone().unwrap_or(ContainerType::Unknown)
    }

    /// Frame geometry, when both dimensions are established.
    pub fn geometry(&self) -> Option<(u32, u32)> {
        match (self.width, self.height) {
            (Some(w), Some(h)) if w > 0 && h > 0 => Some((w, h)),
            _ => None,
        }
    }
}

/// A reconstructed media file, ready to be validated and decoded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediaArtifact {
    /// Stable identifier. Supplied by the caller so it matches the artifact id the recovery
    /// layer already assigned, rather than being minted a second time here.
    pub artifact_id: String,
    /// Path to the DERIVED file. Never a path into the evidence image.
    pub path: PathBuf,
    /// Size of the derived file in bytes, as measured on disk.
    pub size_bytes: u64,
    /// Digest of the derived file's actual bytes.
    pub media_hash: Option<ContentHash>,
    pub properties: MediaProperties,
    pub reconstruction_method: ReconstructionMethod,
    pub reconstruction_status: ReconstructionStatus,
    pub validation_status: ValidationStatus,
    pub provenance: MediaProvenance,
    /// Wall-clock start of the recording, when the DVR/recording metadata established one.
    ///
    /// `None` is the correct value when the OEM parser does not supply a start time. It is
    /// never back-filled from the file's mtime or from "now".
    pub start_timestamp: Option<DateTime<Utc>>,
    /// Wall-clock end, when upstream established one.
    pub end_timestamp: Option<DateTime<Utc>>,
}

impl MediaArtifact {
    /// Builds an artifact descriptor for an existing derived file.
    ///
    /// The size is measured from the filesystem rather than taken on trust. The artifact starts
    /// at `ValidationStatus::NotRun` and with no media hash: both are produced by operations
    /// that have not happened yet.
    pub fn from_derived_file(
        artifact_id: impl Into<String>,
        path: impl AsRef<Path>,
        method: ReconstructionMethod,
        provenance: MediaProvenance,
    ) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let size_bytes = std::fs::metadata(&path)?.len();
        Ok(Self {
            artifact_id: artifact_id.into(),
            path,
            size_bytes,
            media_hash: None,
            properties: MediaProperties::default(),
            reconstruction_method: method,
            reconstruction_status: ReconstructionStatus::Complete,
            validation_status: ValidationStatus::NotRun,
            provenance,
            start_timestamp: None,
            end_timestamp: None,
        })
    }

    /// Records the container/codec the upstream layer declared, without probing.
    pub fn with_declared_properties(mut self, props: MediaProperties) -> Self {
        self.properties = props;
        self
    }

    pub fn with_recording_window(
        mut self,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
    ) -> Self {
        self.start_timestamp = start;
        self.end_timestamp = end;
        self
    }

    pub fn with_reconstruction_status(mut self, status: ReconstructionStatus) -> Self {
        self.reconstruction_status = status;
        self
    }

    pub fn source_offset(&self) -> Option<u64> {
        self.provenance.primary_source_offset()
    }

    pub fn source_size(&self) -> Option<u64> {
        self.provenance.source_size()
    }

    /// A report-facing rendering of every field, with `UNKNOWN` where nothing was established.
    ///
    /// The whole point of this function is that a missing measurement renders as the word
    /// UNKNOWN rather than as an empty cell that a reader might fill in themselves.
    pub fn summary(&self) -> serde_json::Value {
        fn or_unknown<T: std::fmt::Display>(v: Option<T>) -> String {
            v.map(|x| x.to_string()).unwrap_or_else(|| "UNKNOWN".into())
        }
        serde_json::json!({
            "artifact_id": self.artifact_id,
            "source_evidence_id": self.provenance.evidence_id.to_string(),
            "source_offset": or_unknown(self.source_offset()),
            "source_size": or_unknown(self.source_size()),
            "source_hash": self.provenance.source_hash.as_ref()
                .map(|h| h.hex.clone()).unwrap_or_else(|| "UNKNOWN".into()),
            "derived_path": self.path.display().to_string(),
            "derived_size_bytes": self.size_bytes,
            "media_hash": self.media_hash.as_ref()
                .map(|h| h.hex.clone()).unwrap_or_else(|| "UNKNOWN".into()),
            "container_type": self.properties.container_or_unknown().label(),
            "codec": self.properties.codec_or_unknown().label(),
            "width": or_unknown(self.properties.width),
            "height": or_unknown(self.properties.height),
            "frame_rate": or_unknown(self.properties.frame_rate),
            "duration_secs": or_unknown(self.properties.duration_secs),
            "start_timestamp": or_unknown(self.start_timestamp.map(|t| t.to_rfc3339())),
            "end_timestamp": or_unknown(self.end_timestamp.map(|t| t.to_rfc3339())),
            "reconstruction_method": self.reconstruction_method,
            "reconstruction_status": self.reconstruction_status,
            "validation_status": self.validation_status.label(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_validation_is_not_a_pass_and_does_not_permit_decoding() {
        assert!(!ValidationStatus::Unavailable.permits_decode());
        assert!(!ValidationStatus::NotRun.permits_decode());
        assert!(!ValidationStatus::Timeout.permits_decode());
        assert!(ValidationStatus::Valid.permits_decode());
        assert_eq!(
            ValidationStatus::Unavailable.label(),
            "VALIDATION_UNAVAILABLE"
        );
    }

    #[test]
    fn ffprobe_format_names_map_to_containers() {
        assert_eq!(
            ContainerType::from_ffprobe_format_name("mov,mp4,m4a,3gp,3g2,mj2"),
            ContainerType::Mp4
        );
        assert_eq!(
            ContainerType::from_ffprobe_format_name("matroska,webm"),
            ContainerType::Matroska
        );
        assert_eq!(
            ContainerType::from_ffprobe_format_name("h264"),
            ContainerType::ElementaryStream
        );
        assert_eq!(
            ContainerType::from_ffprobe_format_name(""),
            ContainerType::Unknown
        );
    }

    #[test]
    fn ffprobe_codec_names_map_to_codecs() {
        assert_eq!(CodecKind::from_ffprobe_codec_name("h264"), CodecKind::H264);
        assert_eq!(CodecKind::from_ffprobe_codec_name("hevc"), CodecKind::H265);
        assert_eq!(CodecKind::from_ffprobe_codec_name(""), CodecKind::Unknown);
        assert_eq!(
            CodecKind::from_ffprobe_codec_name("vp9"),
            CodecKind::Other("vp9".into())
        );
    }

    #[test]
    fn an_unknown_codec_has_no_elementary_stream_demuxer() {
        assert_eq!(CodecKind::Unknown.elementary_stream_demuxer(), None);
        assert_eq!(
            CodecKind::Other("vp9".into()).elementary_stream_demuxer(),
            None
        );
        assert_eq!(CodecKind::H264.elementary_stream_demuxer(), Some("h264"));
        assert_eq!(CodecKind::H265.elementary_stream_demuxer(), Some("hevc"));
    }

    #[test]
    fn unestablished_fields_render_as_unknown_never_as_a_plausible_default() {
        let ev = EvidenceId::new();
        let art = MediaArtifact {
            artifact_id: "art-1".into(),
            path: PathBuf::from("derived/art-1.mp4"),
            size_bytes: 1024,
            media_hash: None,
            properties: MediaProperties::declared(ContainerType::Mp4, CodecKind::Unknown),
            reconstruction_method: ReconstructionMethod::ContainerRemux,
            reconstruction_status: ReconstructionStatus::Complete,
            validation_status: ValidationStatus::NotRun,
            provenance: MediaProvenance::new(ev),
            start_timestamp: None,
            end_timestamp: None,
        };
        let s = art.summary();
        assert_eq!(s["codec"], "UNKNOWN");
        assert_eq!(s["width"], "UNKNOWN");
        assert_eq!(s["frame_rate"], "UNKNOWN");
        assert_eq!(s["start_timestamp"], "UNKNOWN");
        assert_eq!(s["media_hash"], "UNKNOWN");
        assert_eq!(s["source_offset"], "UNKNOWN");
        assert_eq!(s["validation_status"], "VALIDATION_NOT_RUN");
    }

    #[test]
    fn provenance_reports_the_first_offset_and_the_summed_source_size() {
        let p = MediaProvenance::new(EvidenceId::new()).with_regions(vec![
            SourceByteRange {
                offset: 4096,
                length: 100,
            },
            SourceByteRange {
                offset: 9000,
                length: 50,
            },
        ]);
        assert_eq!(p.primary_source_offset(), Some(4096));
        assert_eq!(p.source_size(), Some(150));
    }

    #[test]
    fn geometry_requires_both_dimensions_to_be_non_zero() {
        let mut p = MediaProperties::default();
        assert_eq!(p.geometry(), None);
        p.width = Some(640);
        assert_eq!(p.geometry(), None);
        p.height = Some(0);
        assert_eq!(p.geometry(), None);
        p.height = Some(480);
        assert_eq!(p.geometry(), Some((640, 480)));
    }
}
