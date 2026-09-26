//! ffprobe invocation and parsing.
//!
//! The probe result is *evaluated*, never merely obtained. A run that exits non-zero, produces
//! unparseable JSON, or reports no video stream is a distinct, named outcome — not a shrug.

use crate::artifact::{CodecKind, ContainerType};
use crate::error::{MediaError, MediaErrorKind, MediaResult};
use crate::exec::CommandSpec;
use crate::tools::MediaToolchain;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

/// One stream as ffprobe described it.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ProbeStream {
    pub index: u32,
    pub codec_type: String,
    pub codec_name: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub pix_fmt: Option<String>,
    /// The container's nominal frame rate as the `"num/den"` string ffprobe emits.
    pub r_frame_rate: Option<String>,
    pub avg_frame_rate: Option<String>,
    pub duration_secs: Option<f64>,
    pub nb_frames: Option<u64>,
    /// Stream start time in seconds, when the container declares one.
    pub start_time_secs: Option<f64>,
}

impl ProbeStream {
    pub fn is_video(&self) -> bool {
        self.codec_type.eq_ignore_ascii_case("video")
    }

    /// The most trustworthy frame rate available, preferring the real average over the nominal
    /// rate when the two disagree, since the average reflects what is actually in the file.
    pub fn frame_rate(&self) -> Option<f64> {
        parse_rational(self.avg_frame_rate.as_deref())
            .or_else(|| parse_rational(self.r_frame_rate.as_deref()))
    }
}

/// Everything ffprobe established about one media file.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ProbeReport {
    pub format_name: String,
    pub container: ContainerType,
    pub duration_secs: Option<f64>,
    pub size_bytes: Option<u64>,
    pub start_time_secs: Option<f64>,
    pub streams: Vec<ProbeStream>,
}

impl Default for ContainerType {
    fn default() -> Self {
        ContainerType::Unknown
    }
}

impl ProbeReport {
    /// The first video stream, if any.
    pub fn primary_video_stream(&self) -> Option<&ProbeStream> {
        self.streams.iter().find(|s| s.is_video())
    }

    pub fn video_codec(&self) -> CodecKind {
        self.primary_video_stream()
            .map(|s| CodecKind::from_ffprobe_codec_name(&s.codec_name))
            .unwrap_or(CodecKind::Unknown)
    }

    /// Geometry of the primary video stream, when both dimensions are present and non-zero.
    pub fn geometry(&self) -> Option<(u32, u32)> {
        let s = self.primary_video_stream()?;
        match (s.width, s.height) {
            (Some(w), Some(h)) if w > 0 && h > 0 => Some((w, h)),
            _ => None,
        }
    }

    pub fn frame_rate(&self) -> Option<f64> {
        self.primary_video_stream().and_then(|s| s.frame_rate())
    }

    /// Duration preferring the stream's own value over the container's.
    pub fn effective_duration(&self) -> Option<f64> {
        self.primary_video_stream()
            .and_then(|s| s.duration_secs)
            .or(self.duration_secs)
    }
}

/// Builds the argv for a JSON probe.
pub fn build_probe_command(ffprobe: &Path, media: &Path) -> CommandSpec {
    CommandSpec::new(
        ffprobe,
        vec![
            "-hide_banner".into(),
            "-v".into(),
            "error".into(),
            "-show_streams".into(),
            "-show_format".into(),
            "-of".into(),
            "json".into(),
            media.to_string_lossy().to_string(),
        ],
    )
}

/// Runs ffprobe against a file and parses the result.
///
/// Returns `FFPROBE_UNAVAILABLE` when the tool is absent, `FFPROBE_FAILED` when it ran and
/// rejected the file, `FFMPEG_TIMEOUT` when it was killed for overrunning, and
/// `CORRUPTED_MEDIA` when it exited zero but emitted output that does not parse.
pub async fn probe_file(toolchain: &MediaToolchain, media: &Path) -> MediaResult<ProbeReport> {
    let ffprobe = toolchain.require_ffprobe("probe_file")?.to_path_buf();
    let spec = build_probe_command(&ffprobe, media);
    let outcome = toolchain
        .runner()
        .run_capture(&spec, &toolchain.config().probe_limits(), "probe_file")
        .await?;

    outcome.require_success(MediaErrorKind::FfprobeFailed, "probe_file")?;

    parse_probe_json(&outcome.stdout)
        .map_err(|e| e.with_process(outcome.exit_code, outcome.stderr_tail))
}

/// Parses ffprobe's `-of json` output.
pub fn parse_probe_json(stdout: &[u8]) -> MediaResult<ProbeReport> {
    let json: Value = serde_json::from_slice(stdout).map_err(|e| {
        MediaError::new(
            MediaErrorKind::CorruptedMedia,
            "parse_probe_json",
            format!("ffprobe returned output that is not valid JSON: {e}"),
        )
    })?;

    let mut streams = Vec::new();
    if let Some(arr) = json.get("streams").and_then(|s| s.as_array()) {
        for st in arr {
            streams.push(ProbeStream {
                index: st
                    .get("index")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(streams.len() as u64) as u32,
                codec_type: str_field(st, "codec_type").unwrap_or_default(),
                codec_name: str_field(st, "codec_name").unwrap_or_default(),
                width: st.get("width").and_then(|v| v.as_u64()).map(|v| v as u32),
                height: st.get("height").and_then(|v| v.as_u64()).map(|v| v as u32),
                pix_fmt: str_field(st, "pix_fmt"),
                r_frame_rate: str_field(st, "r_frame_rate"),
                avg_frame_rate: str_field(st, "avg_frame_rate"),
                duration_secs: str_field(st, "duration").and_then(|s| s.parse().ok()),
                nb_frames: str_field(st, "nb_frames").and_then(|s| s.parse().ok()),
                start_time_secs: str_field(st, "start_time").and_then(|s| s.parse().ok()),
            });
        }
    }

    let format = json.get("format");
    let format_name = format
        .and_then(|f| str_field(f, "format_name"))
        .unwrap_or_default();

    Ok(ProbeReport {
        container: ContainerType::from_ffprobe_format_name(&format_name),
        format_name,
        duration_secs: format
            .and_then(|f| str_field(f, "duration"))
            .and_then(|s| s.parse().ok()),
        size_bytes: format
            .and_then(|f| str_field(f, "size"))
            .and_then(|s| s.parse().ok()),
        start_time_secs: format
            .and_then(|f| str_field(f, "start_time"))
            .and_then(|s| s.parse().ok()),
        streams,
    })
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(|s| s.to_string())
}

/// Parses an ffprobe `"num/den"` rational. `"0/0"` — ffprobe's "unknown" — yields `None`.
pub fn parse_rational(s: Option<&str>) -> Option<f64> {
    let s = s?.trim();
    let (num, den) = s.split_once('/')?;
    let num: f64 = num.trim().parse().ok()?;
    let den: f64 = den.trim().parse().ok()?;
    if den == 0.0 || num <= 0.0 || !num.is_finite() || !den.is_finite() {
        return None;
    }
    Some(num / den)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = br#"{
        "streams": [
            {
                "index": 0,
                "codec_name": "h264",
                "codec_type": "video",
                "width": 320,
                "height": 240,
                "pix_fmt": "yuv420p",
                "r_frame_rate": "25/1",
                "avg_frame_rate": "25/1",
                "duration": "2.000000",
                "nb_frames": "50",
                "start_time": "0.000000"
            },
            {
                "index": 1,
                "codec_name": "aac",
                "codec_type": "audio"
            }
        ],
        "format": {
            "format_name": "mov,mp4,m4a,3gp,3g2,mj2",
            "duration": "2.000000",
            "size": "40960",
            "start_time": "0.000000"
        }
    }"#;

    #[test]
    fn a_full_probe_yields_container_codec_geometry_and_rate() {
        let r = parse_probe_json(SAMPLE).unwrap();
        assert_eq!(r.container, ContainerType::Mp4);
        assert_eq!(r.video_codec(), CodecKind::H264);
        assert_eq!(r.geometry(), Some((320, 240)));
        assert_eq!(r.frame_rate(), Some(25.0));
        assert_eq!(r.effective_duration(), Some(2.0));
        assert_eq!(r.size_bytes, Some(40960));
        assert_eq!(r.primary_video_stream().unwrap().nb_frames, Some(50));
        // The audio stream is present but never mistaken for the video stream.
        assert_eq!(r.streams.len(), 2);
        assert_eq!(r.primary_video_stream().unwrap().index, 0);
    }

    #[test]
    fn a_container_with_no_video_stream_reports_unknown_codec_and_no_geometry() {
        let audio_only = br#"{
            "streams": [{"index": 0, "codec_name": "aac", "codec_type": "audio"}],
            "format": {"format_name": "mp4", "duration": "1.0", "size": "100"}
        }"#;
        let r = parse_probe_json(audio_only).unwrap();
        assert!(r.primary_video_stream().is_none());
        assert_eq!(r.video_codec(), CodecKind::Unknown);
        assert_eq!(r.geometry(), None);
        assert_eq!(r.frame_rate(), None);
    }

    #[test]
    fn unparseable_output_is_corrupted_media_not_a_silent_default() {
        let err = parse_probe_json(b"not json at all").unwrap_err();
        assert_eq!(err.kind, MediaErrorKind::CorruptedMedia);
    }

    #[test]
    fn absent_fields_stay_none_rather_than_becoming_zero() {
        let sparse = br#"{"streams":[{"codec_type":"video","codec_name":"h264"}],"format":{}}"#;
        let r = parse_probe_json(sparse).unwrap();
        let s = r.primary_video_stream().unwrap();
        assert_eq!(s.width, None);
        assert_eq!(s.height, None);
        assert_eq!(s.nb_frames, None);
        assert_eq!(r.duration_secs, None);
        assert_eq!(r.container, ContainerType::Unknown);
    }

    #[test]
    fn rationals_parse_and_ffprobes_unknown_rate_is_rejected() {
        assert_eq!(parse_rational(Some("30000/1001")).unwrap().round(), 30.0);
        assert_eq!(parse_rational(Some("25/1")), Some(25.0));
        assert_eq!(parse_rational(Some("0/0")), None);
        assert_eq!(parse_rational(Some("25")), None);
        assert_eq!(parse_rational(None), None);
    }

    #[test]
    fn the_average_rate_is_preferred_over_the_nominal_rate() {
        let s = ProbeStream {
            r_frame_rate: Some("60/1".into()),
            avg_frame_rate: Some("30/1".into()),
            ..Default::default()
        };
        assert_eq!(s.frame_rate(), Some(30.0));
    }

    #[test]
    fn the_nominal_rate_is_used_when_the_average_is_unknown() {
        let s = ProbeStream {
            r_frame_rate: Some("25/1".into()),
            avg_frame_rate: Some("0/0".into()),
            ..Default::default()
        };
        assert_eq!(s.frame_rate(), Some(25.0));
    }

    #[test]
    fn the_probe_argv_is_literal_and_asks_for_json() {
        let spec = build_probe_command(Path::new("ffprobe"), Path::new("/d/a b;c.mp4"));
        assert!(spec.args.contains(&"json".to_string()));
        assert!(spec.args.contains(&"-show_streams".to_string()));
        assert_eq!(spec.args.last().unwrap(), "/d/a b;c.mp4");
    }
}
