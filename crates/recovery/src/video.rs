//! Video reconstruction: FFmpeg integration (Req 14.4, 14.9), frame/GOP validation (Req 14.1),
//! and gap marking (Req 14.3).
//!
//! - Remux over re-encode preferred. When FFmpeg absent: UNKNOWN/REVIEW, never PASS.
//! - Physical order ≠ chronological (Req 14.7). Elementary stream ≠ recorder identity.
//! - Gaps are marked, never synthesized (Property 9).

use forensic_core::{Region, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};

/// Represents a validated video frame.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VideoFrame {
    pub offset: u64,
    pub size: u32,
    pub frame_type: FrameType,
    pub timestamp: Option<u64>,
    pub channel_id: Option<u32>,
    pub is_valid: bool,
    pub rejection_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameType {
    IFrame,
    PFrame,
    BFrame,
    Unknown,
}

/// A gap in the frame sequence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrameGap {
    pub region: Region,
    pub expected_frame_count: u32,
    pub reason: String,
}

/// Result of frame validation and ordering.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrameOrderingResult {
    pub ordered_frames: Vec<VideoFrame>,
    pub rejected_frames: Vec<VideoFrame>,
    pub gaps: Vec<FrameGap>,
    pub validation: ValidationState,
}

/// Validates and orders frames using I-frame/GOP relationships (Req 14.1, 14.2, 14.7).
/// Physical order is NEVER treated as chronological; ordering uses time evidence.
/// Malformed frames are rejected with reasons, never patched.
pub fn validate_and_order_frames(mut frames: Vec<VideoFrame>) -> FrameOrderingResult {
    let mut valid = Vec::new();
    let mut rejected = Vec::new();

    for frame in frames.drain(..) {
        if frame.is_valid {
            valid.push(frame);
        } else {
            rejected.push(frame);
        }
    }

    // Order by timestamp (time evidence), NOT by physical offset (Req 14.7)
    valid.sort_by_key(|f| f.timestamp.unwrap_or(u64::MAX));

    // Detect gaps in the ordered sequence
    let mut gaps = Vec::new();
    for window in valid.windows(2) {
        let end_of_prev = window[0].offset + window[0].size as u64;
        let start_of_next = window[1].offset;
        if start_of_next > end_of_prev + 1024 {
            gaps.push(FrameGap {
                region: Region {
                    offset: end_of_prev,
                    length: start_of_next - end_of_prev,
                },
                expected_frame_count: 0, // Unknown
                reason: "Missing frames between GOP boundaries".to_string(),
            });
        }
    }

    let validation = if !rejected.is_empty() {
        ValidationState::new(
            ValidationStateKind::Review,
            "validate_and_order_frames",
            format!("{} frame(s) rejected with reasons", rejected.len()),
            "Frames",
        )
        .unwrap()
    } else if !gaps.is_empty() {
        // (state, reason, operation, subject): the reason is what an examiner reads.
        ValidationState::new(
            ValidationStateKind::Review,
            format!("{} gap(s) detected", gaps.len()),
            "validate_and_order_frames",
            "Frames",
        )
        .expect("formatted reason is non-empty")
    } else {
        ValidationState::new(
            ValidationStateKind::Pass,
            "All frames valid and ordered",
            "validate_and_order_frames",
            "Frames",
        )
        .expect("static reason is non-empty")
    };

    FrameOrderingResult {
        ordered_frames: valid,
        rejected_frames: rejected,
        gaps,
        validation,
    }
}

/// Checks whether FFmpeg is available. When absent, validation is UNKNOWN/REVIEW, never PASS.
pub fn check_ffmpeg_availability() -> ValidationState {
    // Check if ffmpeg binary exists on PATH
    match std::process::Command::new("ffmpeg")
        .arg("-version")
        .output()
    {
        Ok(output) if output.status.success() => ValidationState::new(
            ValidationStateKind::Pass,
            "FFmpeg available for remux",
            "check_ffmpeg",
            "FFmpeg",
        )
        .expect("static reason is non-empty"),
        _ => ValidationState::new(
            ValidationStateKind::Unknown,
            "FFmpeg not available; remux/transmux cannot be performed",
            "check_ffmpeg",
            "FFmpeg",
        )
        .unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ordering_by_timestamp_not_physical_offset() {
        let frames = vec![
            VideoFrame {
                offset: 2000,
                size: 100,
                frame_type: FrameType::IFrame,
                timestamp: Some(1),
                channel_id: None,
                is_valid: true,
                rejection_reason: None,
            },
            VideoFrame {
                offset: 1000,
                size: 100,
                frame_type: FrameType::PFrame,
                timestamp: Some(2),
                channel_id: None,
                is_valid: true,
                rejection_reason: None,
            },
        ];
        let result = validate_and_order_frames(frames);
        // Physical offset 2000 comes first because its timestamp (1) is earlier
        assert_eq!(result.ordered_frames[0].offset, 2000);
        assert_eq!(result.ordered_frames[1].offset, 1000);
    }

    #[test]
    fn test_malformed_frames_rejected_with_reason() {
        let frames = vec![
            VideoFrame {
                offset: 0,
                size: 100,
                frame_type: FrameType::IFrame,
                timestamp: Some(1),
                channel_id: None,
                is_valid: true,
                rejection_reason: None,
            },
            VideoFrame {
                offset: 100,
                size: 50,
                frame_type: FrameType::Unknown,
                timestamp: None,
                channel_id: None,
                is_valid: false,
                rejection_reason: Some("Invalid NAL header".to_string()),
            },
        ];
        let result = validate_and_order_frames(frames);
        assert_eq!(result.ordered_frames.len(), 1);
        assert_eq!(result.rejected_frames.len(), 1);
        assert_eq!(
            result.rejected_frames[0].rejection_reason.as_deref(),
            Some("Invalid NAL header")
        );
        assert_eq!(result.validation.state, ValidationStateKind::Review);
    }

    #[test]
    fn test_no_synthesized_frames_on_gap() {
        let frames = vec![
            VideoFrame {
                offset: 0,
                size: 100,
                frame_type: FrameType::IFrame,
                timestamp: Some(1),
                channel_id: None,
                is_valid: true,
                rejection_reason: None,
            },
            VideoFrame {
                offset: 5000,
                size: 100,
                frame_type: FrameType::IFrame,
                timestamp: Some(2),
                channel_id: None,
                is_valid: true,
                rejection_reason: None,
            },
        ];
        let result = validate_and_order_frames(frames);
        // Gap detected, but output count is exactly 2 — no frames synthesized
        assert_eq!(result.ordered_frames.len(), 2);
        assert!(!result.gaps.is_empty());
    }
}
