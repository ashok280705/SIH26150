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
    ArtifactId, DerivedArtifact, DerivedKind, EvidenceId, Hash, NativeArtifact, Provenance, Region,
    SourceRegion, ValidationState, ValidationStateKind,
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

/// Media metadata established from the stream bytes themselves.
///
/// Every field is optional because every field is a *measurement*. A property this function
/// did not measure is `None` — which reports as UNKNOWN — and is never defaulted to a
/// plausible value. Resolution, frame rate and a true frame count require a decoder; they are
/// established downstream by the `media` crate's ffprobe/decode stages and stay `None` here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediaMetadata {
    pub codec: VideoCodec,
    /// Total pictures in the stream. Establishing this requires decoding, so it is `None`
    /// until the media pipeline decodes the artifact.
    pub frame_count: Option<u64>,
    /// Keyframes counted from the IDR/keyframe NAL units actually observed in the bytes.
    pub keyframe_count: Option<u64>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub fps: Option<f64>,
    /// Whether timestamps run continuously. Determining this needs the OEM index, which this
    /// layer does not read, so it is `None`.
    pub has_timestamp_continuity: Option<bool>,
    /// Whether the stream stays on one channel. Same reason: `None` until upstream says.
    pub has_channel_continuity: Option<bool>,
}

/// Evidence that a decode test genuinely ran and what it produced.
///
/// This type exists so that `decode_tested` can only be true when something actually decoded:
/// it is constructed by the component that ran the decoder, carrying the frame count it
/// observed. It cannot be satisfied by checking whether an executable is on PATH.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodeTestEvidence {
    /// Frames the decoder actually emitted. Zero means the decode failed.
    pub frames_decoded: u64,
    /// The decoder that ran, e.g. `"ffmpeg 6.0 rawvideo"`.
    pub decoder: String,
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
                )
                .unwrap(),
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
            let (is_start_code, header_offset) =
                if stream_bytes[i..i + 4] == [0x00, 0x00, 0x00, 0x01] {
                    (true, i + 4)
                } else if stream_bytes[i..i + 3] == [0x00, 0x00, 0x01] {
                    (true, i + 3)
                } else {
                    (false, 0)
                };

            if is_start_code && header_offset < len {
                let header = stream_bytes[header_offset];

                // H.264 NAL parsing: 1-byte header, type in bits 0..4
                let h264_type = header & 0x1F;
                let h264_forbidden = (header & 0x80) != 0;

                // H.265 NAL parsing: the header is TWO bytes, not one:
                //   byte0: forbidden_zero_bit(1) | nal_unit_type(6) | nuh_layer_id high bit(1)
                //   byte1: nuh_layer_id low(5)   | nuh_temporal_id_plus1(3)
                //
                // Validating only byte0 produces a systematic false positive: the
                // H.264 P-slice header 0x41 — one of the most common bytes in any
                // real AVC stream — reinterprets to nal_unit_type 32, i.e. an HEVC
                // VPS. Every P-slice would then vote for HEVC. Checking the second
                // byte's spec constraints removes that whole class of misreads.
                let h265_type = (header >> 1) & 0x3F;
                let h265_forbidden = (header & 0x80) != 0;
                let h265_byte1 = if header_offset + 1 < len {
                    Some(stream_bytes[header_offset + 1])
                } else {
                    None
                };
                // nuh_temporal_id_plus1 must be non-zero for any valid HEVC NAL.
                let h265_tid_plus1 = h265_byte1.map(|b| b & 0x07).unwrap_or(0);
                let h265_layer_id = h265_byte1
                    .map(|b| (((header & 0x01) as u16) << 5) | ((b >> 3) & 0x1F) as u16)
                    .unwrap_or(u16::MAX);
                // A structurally valid base-layer HEVC NAL header.
                let h265_header_valid =
                    !h265_forbidden && h265_tid_plus1 != 0 && h265_layer_id == 0;
                // VPS and SPS must carry TemporalId == 0 (H.265 §7.4.2.2), so for a
                // base-layer stream the second header byte is exactly 0x01.
                let h265_param_set_valid = h265_header_valid && h265_tid_plus1 == 1;

                // Evaluate H.265 exclusive parameter sets
                if h265_header_valid {
                    match h265_type {
                        32 if h265_param_set_valid => {
                            // VPS (HEVC exclusive)
                            h265_score += 6;
                            nal_evidence.push(NalEvidence {
                                offset: header_offset,
                                raw_header: header,
                                nal_unit_type: h265_type,
                                description: "HEVC Video Parameter Set (VPS)".into(),
                                codec_family: VideoCodec::H265,
                            });
                        }
                        33 if h265_param_set_valid => {
                            // SPS (HEVC Sequence Parameter Set)
                            h265_score += 5;
                            nal_evidence.push(NalEvidence {
                                offset: header_offset,
                                raw_header: header,
                                nal_unit_type: h265_type,
                                description: "HEVC Sequence Parameter Set (SPS)".into(),
                                codec_family: VideoCodec::H265,
                            });
                        }
                        34 => {
                            // PPS (HEVC Picture Parameter Set)
                            h265_score += 4;
                            nal_evidence.push(NalEvidence {
                                offset: header_offset,
                                raw_header: header,
                                nal_unit_type: h265_type,
                                description: "HEVC Picture Parameter Set (PPS)".into(),
                                codec_family: VideoCodec::H265,
                            });
                        }
                        19 | 20 => {
                            // IDR keyframe
                            h265_score += 3;
                        }
                        _ => {}
                    }
                }

                // Evaluate H.264 parameter sets
                if !h264_forbidden {
                    match h264_type {
                        7 => {
                            // SPS (H.264 Sequence Parameter Set)
                            h264_score += 5;
                            nal_evidence.push(NalEvidence {
                                offset: header_offset,
                                raw_header: header,
                                nal_unit_type: h264_type,
                                description: "H.264 Sequence Parameter Set (SPS)".into(),
                                codec_family: VideoCodec::H264,
                            });
                        }
                        8 => {
                            // PPS (H.264 Picture Parameter Set)
                            h264_score += 4;
                            nal_evidence.push(NalEvidence {
                                offset: header_offset,
                                raw_header: header,
                                nal_unit_type: h264_type,
                                description: "H.264 Picture Parameter Set (PPS)".into(),
                                codec_family: VideoCodec::H264,
                            });
                        }
                        5 => {
                            // IDR keyframe
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
                )
                .unwrap(),
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
                    format!(
                        "HEVC/H.265 confirmed via VPS/SPS NAL headers (score: {})",
                        h265_score
                    ),
                    "classify_codec",
                    "StreamBytes",
                )
                .unwrap(),
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
                    format!(
                        "H.264/AVC confirmed via SPS/PPS NAL headers (score: {})",
                        h264_score
                    ),
                    "classify_codec",
                    "StreamBytes",
                )
                .unwrap(),
            }
        } else if h264_score > 0 && h265_score > 0 {
            // Both plausible -> Ambiguity Budget yields REVIEW (Req 14.9)
            let top_codec = if h265_score >= h264_score {
                VideoCodec::H265
            } else {
                VideoCodec::H264
            };
            CodecEvidence {
                codec: top_codec,
                h264_score,
                h265_score,
                mjpeg_score,
                nal_evidence,
                validation: ValidationState::new(
                    ValidationStateKind::Review,
                    format!(
                        "Ambiguous codec stream: H.264 (score: {}) vs H.265 (score: {})",
                        h264_score, h265_score
                    ),
                    "classify_codec",
                    "StreamBytes",
                )
                .unwrap(),
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
                )
                .unwrap(),
            }
        }
    }

    /// Convenience wrapper inspecting codec.
    pub fn inspect_codec(stream_bytes: &[u8]) -> VideoCodec {
        Self::classify_codec(stream_bytes).codec
    }

    /// Counts IDR (keyframe) NAL units present in an Annex-B stream.
    ///
    /// This is a measurement of the bytes, not an estimate: Annex-B emulation prevention makes
    /// the three-byte start code impossible inside a NAL payload, so every match is a real NAL
    /// boundary. It counts keyframes only — the total picture count needs a decoder and is
    /// established downstream by the media pipeline, not guessed here.
    ///
    /// Returns `None` for a codec whose keyframes this scan does not describe.
    pub fn count_keyframe_nals(stream_bytes: &[u8], codec: VideoCodec) -> Option<u64> {
        let mut count = 0u64;
        let len = stream_bytes.len();
        let mut i = 0usize;
        while i + 4 <= len {
            let header_offset = if stream_bytes[i..i + 4] == [0x00, 0x00, 0x00, 0x01] {
                i + 4
            } else if stream_bytes[i..i + 3] == [0x00, 0x00, 0x01] {
                i + 3
            } else {
                i += 1;
                continue;
            };
            if header_offset >= len {
                break;
            }
            let header = stream_bytes[header_offset];
            match codec {
                // H.264: 1-byte header, nal_unit_type 5 is an IDR slice.
                VideoCodec::H264 => {
                    if (header & 0x80) == 0 && (header & 0x1F) == 5 {
                        count += 1;
                    }
                }
                // H.265: 2-byte header, nal_unit_type 19/20 are IDR_W_RADL / IDR_N_LP.
                VideoCodec::H265 => {
                    let t = (header >> 1) & 0x3F;
                    if (header & 0x80) == 0 && (t == 19 || t == 20) {
                        count += 1;
                    }
                }
                _ => return None,
            }
            i = header_offset;
        }
        Some(count)
    }

    /// Reconstructs a recording into native and derived artifacts.
    ///
    /// `decode_test` is the outcome of a decode that **actually ran**, normally supplied by the
    /// downstream `media` pipeline after it decoded the materialized artifact. `None` means no
    /// decode was performed, and the result is `UNKNOWN` — never `PASS`. There is deliberately
    /// no "ffmpeg is installed" parameter: the presence of a binary is not evidence that a
    /// stream decoded.
    pub fn reconstruct(
        evidence_id: EvidenceId,
        source_region: Region,
        raw_payload: Vec<u8>,
        decode_test: Option<DecodeTestEvidence>,
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
            region: source_region,
            hash: native_hash.clone(),
            description: "Native video stream payload".to_string(),
            identified_at: Utc::now(),
        };

        // 3. Multi-signal codec classification
        let codec_evidence = Self::classify_codec(&raw_payload);
        let codec = codec_evidence.codec;

        // Only what the bytes themselves establish. Resolution, frame rate and the picture
        // count all need a decoder; the media pipeline measures them from ffprobe and from
        // actual decoding, and until it does they are UNKNOWN rather than invented here.
        let media_meta = MediaMetadata {
            codec,
            frame_count: None,
            keyframe_count: Self::count_keyframe_nals(&raw_payload, codec),
            width: None,
            height: None,
            fps: None,
            has_timestamp_continuity: None,
            has_channel_continuity: None,
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
        )
        .unwrap();

        let es_prov = Provenance::new(
            evidence_id,
            native_hash.clone(),
            vec![SourceRegion::new(evidence_id, source_region)],
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

        // A Remux derived artifact is deliberately NOT produced here.
        //
        // This function classifies bytes; it runs no FFmpeg and writes no container. The
        // previous implementation emitted a `DerivedKind::Remux` artifact whose SHA-256 was
        // taken over the literal string "MP4_HEADER_CONTAINER_DATA" concatenated with the
        // payload, pointing at `artifacts/remux/<offset>.mp4` — a digest of bytes that were
        // never written, for a file that never existed, carrying a PASS that claimed the
        // remux had happened. That is a fabricated artifact and a fabricated hash.
        //
        // The real remux artifact is produced where the remux actually occurs: the API's
        // export path runs FFmpeg, writes the container, hashes the file's own bytes and
        // records the process exit status and ffprobe result on its provenance.

        // 5. Explicit ValidationState determination.
        //
        // PASS requires evidence that a decoder actually produced pictures. FFmpeg merely
        // being installed is not that evidence, and this function does not decode, so the
        // only way to reach PASS is for the caller to hand over the result of a decode that
        // really ran.
        let decode_ran = decode_test.is_some();
        let validation_state = if raw_payload.is_empty() {
            ValidationState::new(
                ValidationStateKind::Fail,
                "Payload has 0 bytes; reconstruction failed",
                "reconstruct",
                "Recording",
            )
            .unwrap()
        } else {
            match &decode_test {
                None => ValidationState::new(
                    ValidationStateKind::Unknown,
                    "Stream extracted and codec classified; no decode test was performed \
                     by this call (Req 22.3)",
                    "reconstruct",
                    "Recording",
                )
                .unwrap(),
                Some(evidence) if evidence.frames_decoded == 0 => ValidationState::new(
                    ValidationStateKind::Fail,
                    format!(
                        "A decode test ran via {} and produced no frames",
                        evidence.decoder
                    ),
                    "reconstruct",
                    "Recording",
                )
                .unwrap(),
                Some(_) if codec_evidence.validation.state == ValidationStateKind::Review => {
                    codec_evidence.validation.clone()
                }
                Some(evidence) => ValidationState::new(
                    ValidationStateKind::Pass,
                    format!(
                        "Stream extracted and decoded: {} produced {} frame(s) of {:?}",
                        evidence.decoder, evidence.frames_decoded, codec
                    ),
                    "reconstruct",
                    "Recording",
                )
                .unwrap(),
            }
        };

        ReconstructionOutput {
            native_artifact: native_art,
            derived_artifacts,
            media_metadata: media_meta,
            codec_evidence,
            validation_state,
            decode_tested: decode_ran,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h264_4byte_start_code() {
        // 00 00 00 01 67 (H.264 SPS)
        let stream = vec![
            0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x01, 0x68, 0xCE,
            0x3C, 0x80,
        ];
        let evidence = VideoReconstructor::classify_codec(&stream);
        assert_eq!(evidence.codec, VideoCodec::H264);
        assert_eq!(evidence.validation.state, ValidationStateKind::Pass);
    }

    #[test]
    fn test_h265_4byte_start_code() {
        // 00 00 00 01 40 01 (HEVC VPS) followed by 00 00 00 01 42 (HEVC SPS)
        let stream = vec![
            0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x0C, 0x01, 0x00, 0x00, 0x00, 0x01, 0x42, 0x01,
            0x01,
        ];
        let evidence = VideoReconstructor::classify_codec(&stream);
        assert_eq!(
            evidence.codec,
            VideoCodec::H265,
            "HEVC with 4-byte start code must classify as H265"
        );
        assert_eq!(evidence.validation.state, ValidationStateKind::Pass);
    }

    #[test]
    fn test_h265_3byte_start_code() {
        // 00 00 01 40 (HEVC VPS) followed by 00 00 01 42 (HEVC SPS)
        let stream = vec![
            0x00, 0x00, 0x01, 0x40, 0x01, 0x0C, 0x00, 0x00, 0x01, 0x42, 0x01,
        ];
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
        let region = Region {
            offset: 1024,
            length: 2048,
        };
        let payload = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1E];

        let out = VideoReconstructor::reconstruct(ev_id, region, payload, None);
        assert_eq!(out.native_artifact.region, region);
        assert!(!out.derived_artifacts.is_empty());
        // This call runs no FFmpeg, so it must not claim a remux artifact. The remux is
        // produced only where the container is actually written and hashed.
        assert!(
            !out.derived_artifacts
                .iter()
                .any(|d| d.kind == DerivedKind::Remux),
            "a remux artifact must not be emitted by a call that performed no remux"
        );
        // The elementary stream artifact's digest covers the payload bytes themselves.
        let es = out
            .derived_artifacts
            .iter()
            .find(|d| d.kind == DerivedKind::ElementaryStream)
            .expect("the extracted elementary stream artifact");
        assert_eq!(es.provenance.source_evidence_id, ev_id);
    }

    #[test]
    fn test_unrun_decode_test_yields_unknown_never_pass() {
        let ev_id = EvidenceId::new();
        let region = Region {
            offset: 0,
            length: 100,
        };
        let payload = vec![0x00, 0x00, 0x00, 0x01, 0x67];

        let out = VideoReconstructor::reconstruct(ev_id, region, payload, None);
        assert_eq!(out.validation_state.state, ValidationStateKind::Unknown);
        assert!(out
            .validation_state
            .reason
            .contains("no decode test was performed"));
        assert!(!out.decode_tested);
    }

    #[test]
    fn a_decode_that_produced_no_frames_is_a_failure_not_an_unknown() {
        let ev_id = EvidenceId::new();
        let region = Region {
            offset: 0,
            length: 100,
        };
        let payload = vec![0x00, 0x00, 0x00, 0x01, 0x67];

        let out = VideoReconstructor::reconstruct(
            ev_id,
            region,
            payload,
            Some(DecodeTestEvidence {
                frames_decoded: 0,
                decoder: "ffmpeg 6.0 rawvideo".into(),
            }),
        );
        assert_eq!(out.validation_state.state, ValidationStateKind::Fail);
        assert!(out.decode_tested, "the decode did run; it produced nothing");
    }

    #[test]
    fn pass_requires_evidence_that_a_decoder_actually_produced_frames() {
        let ev_id = EvidenceId::new();
        let region = Region {
            offset: 0,
            length: 100,
        };
        let payload = vec![
            0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x01, 0x68,
        ];

        let out = VideoReconstructor::reconstruct(
            ev_id,
            region,
            payload,
            Some(DecodeTestEvidence {
                frames_decoded: 42,
                decoder: "ffmpeg 6.0 rawvideo".into(),
            }),
        );
        assert_eq!(out.validation_state.state, ValidationStateKind::Pass);
        assert!(out.validation_state.reason.contains("42 frame(s)"));
        assert!(out.decode_tested);
    }

    #[test]
    fn unmeasured_media_properties_are_unknown_rather_than_plausible_defaults() {
        let ev_id = EvidenceId::new();
        let region = Region {
            offset: 0,
            length: 100,
        };
        // Two IDR NAL units (type 5) among parameter sets.
        let payload = vec![
            0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x00, 0x00,
            0x00, 0x01, 0x65, 0x88, 0x00, 0x00, 0x00, 0x01, 0x65, 0x88,
        ];
        let out = VideoReconstructor::reconstruct(ev_id, region, payload, None);
        let m = &out.media_metadata;
        assert_eq!(m.frame_count, None, "a picture count needs a decoder");
        assert_eq!(m.width, None);
        assert_eq!(m.height, None);
        assert_eq!(m.fps, None);
        assert_eq!(m.has_timestamp_continuity, None);
        assert_eq!(m.has_channel_continuity, None);
        // Keyframes, by contrast, are counted from the bytes that are actually present.
        assert_eq!(m.keyframe_count, Some(2));
    }
}
