//! Media validation and ffprobe JSON output parser.

use super::command::build_probe_command;
use super::types::{ProbeResult, ProbeStream};
use crate::reconstructor::VideoCodec;
use forensic_core::{ForensicError, ValidationState, ValidationStateKind};
use serde_json::Value;
use std::path::Path;

/// Runs ffprobe on a target container file and parses the machine-readable JSON structure.
pub async fn probe_media_file(
    ffprobe_bin: &str,
    target_path: &Path,
) -> Result<ProbeResult, ForensicError> {
    if !target_path.exists() {
        return Err(ForensicError::io(
            format!(
                "probe_media_file: target '{}' does not exist",
                target_path.display()
            ),
            std::io::Error::new(std::io::ErrorKind::NotFound, "Target media file not found"),
        ));
    }

    let spec = build_probe_command(ffprobe_bin, target_path);
    let mut cmd = spec.to_tokio_command();

    let output = cmd.output().await.map_err(|e| {
        ForensicError::io(
            format!("executing ffprobe on '{}'", target_path.display()),
            e,
        )
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ForensicError::DecodeFailed {
            context: "probe_media_file".into(),
            reason: format!("ffprobe exited with error: {}", stderr.trim()),
        });
    }

    parse_probe_json(&output.stdout)
}

/// Parses raw ffprobe JSON stdout bytes into a `ProbeResult`.
pub fn parse_probe_json(stdout_bytes: &[u8]) -> Result<ProbeResult, ForensicError> {
    let json: Value = serde_json::from_slice(stdout_bytes).map_err(|e| {
        ForensicError::corrupt("parse_probe_json", format!("Invalid ffprobe JSON: {e}"))
    })?;

    let mut streams = Vec::new();
    let mut video_codec = None;
    let mut width = None;
    let mut height = None;

    if let Some(stream_array) = json.get("streams").and_then(|s| s.as_array()) {
        for (i, st) in stream_array.iter().enumerate() {
            let codec_type = st
                .get("codec_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let codec_name = st
                .get("codec_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let w = st.get("width").and_then(|v| v.as_u64()).map(|v| v as u32);
            let h = st.get("height").and_then(|v| v.as_u64()).map(|v| v as u32);
            let pix_fmt = st
                .get("pix_fmt")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let r_frame_rate = st
                .get("r_frame_rate")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let duration = st
                .get("duration")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let nb_frames = st
                .get("nb_frames")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);

            if codec_type == "video" && video_codec.is_none() {
                video_codec = Some(codec_name.clone());
                width = w;
                height = h;
            }

            streams.push(ProbeStream {
                index: i as u32,
                codec_name,
                codec_type,
                width: w,
                height: h,
                pix_fmt,
                r_frame_rate,
                duration,
                nb_frames,
            });
        }
    }

    let format_name = json
        .get("format")
        .and_then(|f| f.get("format_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let duration_secs = json
        .get("format")
        .and_then(|f| f.get("duration"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<f64>().ok());

    let size_bytes = json
        .get("format")
        .and_then(|f| f.get("size"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok());

    let is_valid_mp4 =
        format_name.contains("mp4") || format_name.contains("mov") || format_name.contains("isom");

    Ok(ProbeResult {
        streams,
        format_name,
        duration_secs,
        size_bytes,
        video_codec,
        width,
        height,
        is_valid_mp4,
    })
}

/// Evaluates consistency between expected forensic codec and observed ffprobe stream properties.
pub fn validate_codec_consistency(
    expected_codec: VideoCodec,
    probe: &ProbeResult,
) -> ValidationState {
    if !probe.is_valid_mp4 {
        return ValidationState::new(
            ValidationStateKind::Fail,
            "Output container is not recognized as valid ISO/IEC 14496-14 MP4",
            "validate_codec_consistency",
            "RemuxContainer",
        )
        .unwrap();
    }

    let Some(ref observed) = probe.video_codec else {
        return ValidationState::new(
            ValidationStateKind::Fail,
            "No video stream identified in remuxed MP4 container",
            "validate_codec_consistency",
            "RemuxContainer",
        )
        .unwrap();
    };

    let matches = match expected_codec {
        VideoCodec::H264 => {
            observed.eq_ignore_ascii_case("h264") || observed.eq_ignore_ascii_case("avc1")
        }
        VideoCodec::H265 => {
            observed.eq_ignore_ascii_case("hevc") || observed.eq_ignore_ascii_case("h265")
        }
        _ => false,
    };

    if matches {
        ValidationState::new(
            ValidationStateKind::Pass,
            format!(
                "Stream-copy verified: container holds expected {:?} video stream ({})",
                expected_codec, observed
            ),
            "validate_codec_consistency",
            "RemuxContainer",
        )
        .unwrap()
    } else {
        ValidationState::new(
            ValidationStateKind::Review,
            format!(
                "Codec discrepancy: expected {:?} bitstream, but container probe observed '{}'",
                expected_codec, observed
            ),
            "validate_codec_consistency",
            "RemuxContainer",
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_probe_json_valid_mp4() {
        let sample_json = br#"{
            "streams": [
                {
                    "index": 0,
                    "codec_name": "h264",
                    "codec_type": "video",
                    "width": 1920,
                    "height": 1080,
                    "pix_fmt": "yuv420p",
                    "r_frame_rate": "25/1",
                    "duration": "120.000000",
                    "nb_frames": "3000"
                }
            ],
            "format": {
                "format_name": "mov,mp4,m4a,3gp,3g2,mj2",
                "duration": "120.000000",
                "size": "52428800"
            }
        }"#;

        let result = parse_probe_json(sample_json).unwrap();
        assert!(result.is_valid_mp4);
        assert_eq!(result.video_codec.as_deref(), Some("h264"));
        assert_eq!(result.width, Some(1920));
        assert_eq!(result.height, Some(1080));
        assert_eq!(result.duration_secs, Some(120.0));

        let val = validate_codec_consistency(VideoCodec::H264, &result);
        assert_eq!(val.state, ValidationStateKind::Pass);
    }

    #[test]
    fn test_parse_probe_json_codec_mismatch_yields_review() {
        let sample_json = br#"{
            "streams": [
                {
                    "index": 0,
                    "codec_name": "hevc",
                    "codec_type": "video",
                    "width": 3840,
                    "height": 2160
                }
            ],
            "format": {
                "format_name": "mp4",
                "duration": "60.0",
                "size": "100000"
            }
        }"#;

        let result = parse_probe_json(sample_json).unwrap();
        let val = validate_codec_consistency(VideoCodec::H264, &result);
        assert_eq!(val.state, ValidationStateKind::Review);
        assert!(val.reason.contains("discrepancy"));
    }
}
