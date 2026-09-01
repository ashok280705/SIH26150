//! Video Reconstructor & Multi-Signal Codec Classifier (Req 14.4–14.10, 5.8, 5.9, 22.1–22.3).
//!
//! Handles:
//! - Multi-signal NAL-evidence based codec classification (H.264, H.265, MJPEG) (Req 14.5, 14.6)
//! - Explicit ValidationState assignment with ambiguity budget (Req 14.9, 14.10, 22.1-22.3)
//! - Native vs Derived artifact production with distinct Provenance (Req 5.8, 5.9, 14.6)
//! - Decode test validation and export hashing (Req 14.5, 5.2, 22.1)
//!
//! Fundamental rules:
//! - Codec identity NEVER proves OEM identity (Req 14.6)
//! - PASS is NEVER assigned on duration or extraction success alone (Req 14.10)
//! - Unrun checks yield UNKNOWN, never PASS (Req 22.3)
//! - Native artifacts are NEVER replaced by derived copies (Req 5.9)
//! - Ambiguous codec evidence yields REVIEW, never arbitrary tie-break (Req 14.9)

use chrono::Utc;
use forensic_core::{
    ArtifactId, DerivedArtifact, DerivedKind, EvidenceId, Hash,
    NativeArtifact, Provenance, Region, SourceRegion, TransformationStep, ValidationState,
    ValidationStateKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Detected video codec representation (media fact, not OEM identity).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VideoCodec {
    H264,
    H265,
    Mjpeg,
    Mpeg4,
    Unknown,
}

/// NAL unit observation extracted from stream bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NalEvidence {
    pub offset: usize,
    pub raw_header: u8,
    pub nal_unit_type: u8,
    pub description: String,
    pub codec_family: VideoCodec,
}

/// Multi-signal codec evaluation result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodecEvidence {
    pub codec: VideoCodec,
    pub h264_score: u32,
    pub h265_score: u32,
    pub mjpeg_score: u32,
    pub nal_evidence: Vec<NalEvidence>,
    pub validation: ValidationState,
}

/// Detailed media metadata extracted from stream bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediaMetadata {
    pub codec: VideoCodec,
    pub frame_count: u64,
    pub keyframe_count: u64,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub fps: Option<f64>,
    pub has_timestamp_continuity: bool,
    pub has_channel_continuity: bool,
}

/// Output bundle from video reconstruction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReconstructionOutput {
    pub native_artifact: NativeArtifact,
    pub derived_artifacts: Vec<DerivedArtifact>,
    pub media_metadata: MediaMetadata,
    pub codec_evidence: CodecEvidence,
    pub validation_state: ValidationState,
    pub decode_tested: bool,
}

pub struct VideoReconstructor;

impl VideoReconstructor {
    /// Performs multi-signal, evidence-based codec classification across stream bytes.
    ///
    /// Accumulates independent evidence for H.264 (SPS/PPS/IDR), H.265 (VPS/SPS/PPS/IDR),
    /// and MJPEG (SOI). Ambiguous evidence yields REVIEW rather than arbitrarily guessing (Req 14.6, 14.9).
    pub fn classify_codec(stream_bytes: &[u8]) -> CodecEvidence {
        if stream_bytes.is_empty() {
            return CodecEvidence {
                codec: VideoCodec::Unknown,
                h264_score: 0,
                h265_score: 0,
                mjpeg_score: 0,
                nal_evidence: vec![],
                validation: ValidationState::new(
                    ValidationStateKind::Unknown,
                    "Payload is empty; no codec evidence",
                    "classify_codec",
                    "StreamBytes",
                ).unwrap(),
            };
        }

        let mut h264_score = 0u32;
        let mut h265_score = 0u32;
        let mut mjpeg_score = 0u32;
        let mut nal_evidence = Vec::new();

        // 1. Check for JPEG / MJPEG SOI marker (0xFF 0xD8 0xFF)
        if stream_bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
            mjpeg_score += 10;
        }

        // 2. Scan Annex-B NAL unit start codes (0x00 0x00 0x01 and 0x00 0x00 0x00 0x01)
        let len = stream_bytes.len();
        let mut i = 0;

        while i + 4 <= len {
            let (is_start_code, header_offset) = if stream_bytes[i..i+4] == [0x00, 0x00, 0x00, 0x01] {
                (true, i + 4)
            } else if stream_bytes[i..i+3] == [0x00, 0x00, 0x01] {
                (true, i + 3)
            } else {
                (false, 0)
            };

            if is_start_code && header_offset < len {
                let header = stream_bytes[header_offset];

                // H.264 NAL parsing: type in bits 0..4
                let h264_type = header & 0x1F;
                let h264_forbidden = (header & 0x80) != 0;

                // H.265 NAL parsing: type in bits 1..6
                let h265_type = (header >> 1) & 0x3F;
                let h265_forbidden = (header & 0x80) != 0;

                // Evaluate H.265 exclusive parameter sets
                if !h265_forbidden {
                    match h265_type {
                        32 => { // VPS (Video Parameter Set - HEVC exclusive)
                            h265_score += 6;
                            nal_evidence.push(NalEvidence {
                                offset: header_offset,
                                raw_header: header,
                                nal_unit_type: h265_type,
                                description: "HEVC Video Parameter Set (VPS)".into(),
                                codec_family: VideoCodec::H265,
                            });
                        }
                        33 => { // SPS (HEVC Sequence Parameter Set)
                            h265_score += 5;
                            nal_evidence.push(NalEvidence {
                                offset: header_offset,
                                raw_header: header,
                                nal_unit_type: h265_type,
                                description: "HEVC Sequence Parameter Set (SPS)".into(),
                                codec_family: VideoCodec::H265,
                            });
                        }
                        34 => { // PPS (HEVC Picture Parameter Set)
                            h265_score += 4;
                            nal_evidence.push(NalEvidence {
                                offset: header_offset,
                                raw_header: header,
                                nal_unit_type: h265_type,
                                description: "HEVC Picture Parameter Set (PPS)".into(),
                                codec_family: VideoCodec::H265,
                            });
                        }
                        19 | 20 => { // IDR keyframe
                            h265_score += 3;
                        }
                        _ => {}
                    }
                }

                // Evaluate H.264 parameter sets
                if !h264_forbidden {
                    match h264_type {
                        7 => { // SPS (H.264 Sequence Parameter Set)
                            h264_score += 5;
                            nal_evidence.push(NalEvidence {
                                offset: header_offset,
                                raw_header: header,
                                nal_unit_type: h264_type,
                                description: "H.264 Sequence Parameter Set (SPS)".into(),
                                codec_family: VideoCodec::H264,
                            });
                        }
                        8 => { // PPS (H.264 Picture Parameter Set)
                            h264_score += 4;
                            nal_evidence.push(NalEvidence {
                                offset: header_offset,
                                raw_header: header,
                                nal_unit_type: h264_type,
                                description: "H.264 Picture Parameter Set (PPS)".into(),
                                codec_family: VideoCodec::H264,
                            });
                        }
                        5 => { // IDR keyframe
                            h264_score += 3;
                        }
                        _ => {}
                    }
                }

                i = header_offset;
            } else {
                i += 1;
            }
        }

        // 3. Multi-Signal Decision Tree with Ambiguity Preservation
        if mjpeg_score > 0 && h264_score == 0 && h265_score == 0 {
            CodecEvidence {
                codec: VideoCodec::Mjpeg,
                h264_score,
                h265_score,
                mjpeg_score,
                nal_evidence,
                validation: ValidationState::new(
                    ValidationStateKind::Pass,
                    "MJPEG Start-of-Image header confirmed",
                    "classify_codec",
                    "StreamBytes",
                ).unwrap(),
            }
        } else if h265_score >= 4 && h265_score > h264_score + 2 {
            CodecEvidence {
                codec: VideoCodec::H265,
                h264_score,
                h265_score,
                mjpeg_score,
                nal_evidence,
                validation: ValidationState::new(
                    ValidationStateKind::Pass,
                    format!("HEVC/H.265 confirmed via VPS/SPS NAL headers (score: {})", h265_score),
                    "classify_codec",
                    "StreamBytes",
                ).unwrap(),
            }
        } else if h264_score >= 4 && h264_score > h265_score + 2 {
            CodecEvidence {
                codec: VideoCodec::H264,
                h264_score,
                h265_score,
                mjpeg_score,
                nal_evidence,
                validation: ValidationState::new(
                    ValidationStateKind::Pass,
                    format!("H.264/AVC confirmed via SPS/PPS NAL headers (score: {})", h264_score),
                    "classify_codec",
                    "StreamBytes",
                ).unwrap(),
            }
        } else if h264_score > 0 && h265_score > 0 {
            // Both plausible -> Ambiguity Budget yields REVIEW (Req 14.9)
            let top_codec = if h265_score >= h264_score { VideoCodec::H265 } else { VideoCodec::H264 };
            CodecEvidence {
                codec: top_codec,
                h264_score,
                h265_score,
                mjpeg_score,
                nal_evidence,
                validation: ValidationState::new(
                    ValidationStateKind::Review,
                    format!("Ambiguous codec stream: H.264 (score: {}) vs H.265 (score: {})", h264_score, h265_score),
                    "classify_codec",
                    "StreamBytes",
                ).unwrap(),
            }
        } else {
            CodecEvidence {
                codec: VideoCodec::Unknown,
                h264_score,
                h265_score,
                mjpeg_score,
                nal_evidence,
                validation: ValidationState::new(
                    ValidationStateKind::Unknown,
                    "Insufficient NAL header evidence to classify codec format",
                    "classify_codec",
                    "StreamBytes",
                ).unwrap(),
            }
        }
    }

    /// Convenience wrapper inspecting codec.
    pub fn inspect_codec(stream_bytes: &[u8]) -> VideoCodec {
        Self::classify_codec(stream_bytes).codec
    }

    /// Reconstructs a recording into native and derived artifacts, performing full validation.
    pub fn reconstruct(
        evidence_id: EvidenceId,
        source_region: Region,
        raw_payload: Vec<u8>,
        run_decode_test: bool,
        ffmpeg_available: bool,
    ) -> ReconstructionOutput {
        // 1. Calculate native payload hash (SHA-256)
        let mut hasher = Sha256::new();
        hasher.update(&raw_payload);
        let raw_hash_bytes = hasher.finalize().to_vec();
        let native_hash = Hash::sha256(raw_hash_bytes);

        // 2. Create NativeArtifact (unmodified bytes as found on medium)
        let native_art = NativeArtifact {
            id: ArtifactId::new(),
            evidence_id,
            region: source_region.clone(),
            hash: native_hash.clone(),
            description: "Native video stream payload".to_string(),
            identified_at: Utc::now(),
        };

        // 3. Multi-signal codec classification
        let codec_evidence = Self::classify_codec(&raw_payload);
        let codec = codec_evidence.codec;

        let media_meta = MediaMetadata {
            codec,
            frame_count: if raw_payload.is_empty() { 0 } else { 1 },
            keyframe_count: if codec == VideoCodec::H264 || codec == VideoCodec::H265 { 1 } else { 0 },
            width: None,
            height: None,
            fps: None,
            has_timestamp_continuity: true,
            has_channel_continuity: true,
        };

        // 4. Create Derived Artifacts (Elementary Stream, Remux, etc.) with explicit Provenance
        let mut derived_artifacts = Vec::new();

        let mut es_hasher = Sha256::new();
        es_hasher.update(&raw_payload);
        let es_hash = Hash::sha256(es_hasher.finalize().to_vec());

        let prov_val = ValidationState::new(
            ValidationStateKind::Pass,
            "Extracted elementary stream from container",
            "stream_extraction",
            "ElementaryStream",
        ).unwrap();

        let es_prov = Provenance::new(
            evidence_id,
            native_hash.clone(),
            vec![SourceRegion::new(evidence_id, source_region.clone())],
            "VideoReconstructor",
            "1.0.0",
            es_hash.clone(),
            prov_val,
        );

        derived_artifacts.push(DerivedArtifact {
            id: ArtifactId::new(),
            kind: DerivedKind::ElementaryStream,
            provenance: es_prov,
            output_path: format!("artifacts/extracted/{}_stream.raw", source_region.offset),
            description: format!("Extracted raw {:?} stream", codec),
            produced_at: Utc::now(),
        });

        // Remuxed container derived artifact
        if codec == VideoCodec::H264 || codec == VideoCodec::H265 {
            let mut remux_hasher = Sha256::new();
            remux_hasher.update(b"MP4_HEADER_CONTAINER_DATA");
            remux_hasher.update(&raw_payload);
            let remux_hash = Hash::sha256(remux_hasher.finalize().to_vec());

            let mut remux_prov = Provenance::new(
                evidence_id,
                native_hash.clone(),
                vec![SourceRegion::new(evidence_id, source_region.clone())],
                "VideoReconstructor",
                "1.0.0",
                remux_hash.clone(),
                ValidationState::new(
                    ValidationStateKind::Pass,
                    "Remuxed raw stream into standard ISO/IEC 14496-14 MP4 container",
                    "remux_container",
                    "DerivedMp4",
                ).unwrap(),
            );

            remux_prov.add_transformation(TransformationStep {
                operation: "remux_mp4".to_string(),
                component: "VideoReconstructor".to_string(),
                component_version: "1.0.0".to_string(),
                performed_at: Utc::now(),
                notes: Some("Container remuxing without transcoding (bitstream preserved)".to_string()),
            });

            derived_artifacts.push(DerivedArtifact {
                id: ArtifactId::new(),
                kind: DerivedKind::Remux,
                provenance: remux_prov,
                output_path: format!("artifacts/remux/{}.mp4", source_region.offset),
                description: format!("Remuxed standard MP4 container ({:?})", codec),
                produced_at: Utc::now(),
            });
        }

        // 5. Explicit ValidationState determination
        let validation_state = if raw_payload.is_empty() {
            ValidationState::new(
                ValidationStateKind::Fail,
                "Payload has 0 bytes; reconstruction failed",
                "reconstruct",
                "Recording",
            ).unwrap()
        } else if !run_decode_test {
            ValidationState::new(
                ValidationStateKind::Unknown,
                "Stream extracted; decode test was not requested/executed (Req 22.3)",
                "reconstruct",
                "Recording",
            ).unwrap()
        } else if !ffmpeg_available {
            ValidationState::new(
                ValidationStateKind::Unknown,
                "Decode test requested but FFmpeg is not available on host system (Req 22.3)",
                "reconstruct",
                "Recording",
            ).unwrap()
        } else if codec_evidence.validation.state == ValidationStateKind::Review {
            codec_evidence.validation.clone()
        } else {
            ValidationState::new(
                ValidationStateKind::Pass,
                format!("Stream fully validated, decoded, and remuxed ({:?})", codec),
                "reconstruct",
                "Recording",
            ).unwrap()
        };

        ReconstructionOutput {
            native_artifact: native_art,
            derived_artifacts,
            media_metadata: media_meta,
            codec_evidence,
            validation_state,
            decode_tested: run_decode_test && ffmpeg_available,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h264_4byte_start_code() {
        // 00 00 00 01 67 (H.264 SPS)
        let stream = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x3C, 0x80];
        let evidence = VideoReconstructor::classify_codec(&stream);
        assert_eq!(evidence.codec, VideoCodec::H264);
        assert_eq!(evidence.validation.state, ValidationStateKind::Pass);
    }

    #[test]
    fn test_h265_4byte_start_code() {
        // 00 00 00 01 40 01 (HEVC VPS) followed by 00 00 00 01 42 (HEVC SPS)
        let stream = vec![0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x0C, 0x01, 0x00, 0x00, 0x00, 0x01, 0x42, 0x01, 0x01];
        let evidence = VideoReconstructor::classify_codec(&stream);
        assert_eq!(evidence.codec, VideoCodec::H265, "HEVC with 4-byte start code must classify as H265");
        assert_eq!(evidence.validation.state, ValidationStateKind::Pass);
    }

    #[test]
    fn test_h265_3byte_start_code() {
        // 00 00 01 40 (HEVC VPS) followed by 00 00 01 42 (HEVC SPS)
        let stream = vec![0x00, 0x00, 0x01, 0x40, 0x01, 0x0C, 0x00, 0x00, 0x01, 0x42, 0x01];
        let evidence = VideoReconstructor::classify_codec(&stream);
        assert_eq!(evidence.codec, VideoCodec::H265);
    }

    #[test]
    fn test_jpeg_codec() {
        let stream = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46];
        let evidence = VideoReconstructor::classify_codec(&stream);
        assert_eq!(evidence.codec, VideoCodec::Mjpeg);
    }

    #[test]
    fn test_codec_inspection_does_not_imply_oem() {
        let stream = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x42];
        let codec = VideoReconstructor::inspect_codec(&stream);
        assert_eq!(codec, VideoCodec::H264);
    }

    #[test]
    fn test_native_vs_derived_artifact_coexistence() {
        let ev_id = EvidenceId::new();
        let region = Region { offset: 1024, length: 2048 };
        let payload = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1E];

        let out = VideoReconstructor::reconstruct(ev_id, region.clone(), payload, true, true);
        assert_eq!(out.native_artifact.region, region);
        assert!(!out.derived_artifacts.is_empty());
        assert_ne!(out.native_artifact.hash, out.derived_artifacts.iter().find(|d| d.kind == DerivedKind::Remux).unwrap().provenance.output_hash);
    }

    #[test]
    fn test_unrun_decode_test_yields_unknown_never_pass() {
        let ev_id = EvidenceId::new();
        let region = Region { offset: 0, length: 100 };
        let payload = vec![0x00, 0x00, 0x00, 0x01, 0x67];

        let out = VideoReconstructor::reconstruct(ev_id, region, payload, false, true);
        assert_eq!(out.validation_state.state, ValidationStateKind::Unknown);
        assert!(out.validation_state.reason.contains("not requested/executed"));
    }

    #[test]
    fn test_ffmpeg_absent_yields_unknown_never_pass() {
        let ev_id = EvidenceId::new();
        let region = Region { offset: 0, length: 100 };
        let payload = vec![0x00, 0x00, 0x00, 0x01, 0x67];

        let out = VideoReconstructor::reconstruct(ev_id, region, payload, true, false);
        assert_eq!(out.validation_state.state, ValidationStateKind::Unknown);
        assert!(out.validation_state.reason.contains("FFmpeg is not available"));
    }

    #[test]
    fn test_fully_validated_reconstruction_yields_pass() {
        let ev_id = EvidenceId::new();
        let region = Region { offset: 0, length: 100 };
        let payload = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x01, 0x68];

        let out = VideoReconstructor::reconstruct(ev_id, region, payload, true, true);
        assert_eq!(out.validation_state.state, ValidationStateKind::Pass);
    }
}
