//! # The Hikvision clip container: MPEG-PS-like framing
//!
//! A Hikvision clip's bytes are an MPEG Program Stream-like sequence of parts, each
//! introduced by a standard four-byte start code:
//!
//! ```text
//!   00 00 01 BA   pack header          0x1BA   fixed 20 bytes, serial u32BE at +16
//!   00 00 01 BB   system header        0x1BB   PES-style length
//!   00 00 01 BC   program stream map   0x1BC
//!   00 00 01 BD   private stream 1     0x1BD
//!   00 00 01 C0   audio stream 0       0x1C0
//!   00 00 01 E0   video stream 0       0x1E0
//!   00 00 01 E1   video stream 1       0x1E1
//!   4F 46 4E 49   "OFNI" info part             i32 LE length at +4
//! ```
//!
//! For the PES-style parts:
//!
//! ```text
//!   partLength    = u16BE at +4, plus 6   (start code + length field)
//!   payloadOffset = (u16BE at +7 & 0xFFF) + 9
//! ```
//!
//! ## Why this is a real container walk, not a signature hunt
//!
//! Two failure modes this module exists to avoid:
//!
//! 1. **Treating the clip as Annex-B because NAL bytes appear in it.** Elementary-stream
//!    start codes occur inside PES payloads, and also by coincidence inside PES headers,
//!    timestamps and padding. Codec identity is therefore decided only from bytes that the
//!    walk established are *video PES payload* — see [`classify_codec`], which is fed from
//!    [`ClipStream::codec_sample_regions`], never from the raw clip.
//! 2. **Trusting a declared length.** Every part length and payload offset is checked
//!    against the part itself and against the clip bounds. A part that declares more than
//!    the clip holds is rejected and recorded; it is never clamped so the walk can
//!    continue past it, because a clamped length silently invents a boundary.
//!
//! ## Reads stay bounded
//!
//! [`walk_clip`] streams the clip through a sliding window sized from the profile. It reads
//! part headers, not payloads: a 900 MB clip costs a few hundred window reads, not 900 MB
//! of memory. Codec classification samples a bounded prefix of the video payload.

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, OemProfile, Region, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::layout::{
    hex_ascii, i32_at, key, magic, sig, u16_be_at, u32_be_at, u64_from, usize_from, vs,
};

/// What a stream part is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartKind {
    /// Pack header (`0x1BA`): a fixed-size structure carrying a sequence serial.
    PackHeader {
        /// The big-endian serial at `+16`. Used for ordering, never for timing.
        serial: u32,
    },
    /// System header (`0x1BB`).
    SystemHeader,
    /// Program stream map (`0x1BC`).
    ProgramStreamMap,
    /// Private stream 1 (`0x1BD`).
    PrivateStream1,
    /// Audio stream 0 (`0x1C0`).
    AudioStream0,
    /// Video stream (`0x1E0` / `0x1E1`). Only these payloads feed codec classification.
    VideoStream {
        /// 0 for `0x1E0`, 1 for `0x1E1`.
        stream_index: u8,
    },
    /// The `OFNI` information part. Not an MPEG start code: a tag with its own
    /// little-endian length.
    Ofni {
        /// The declared length, exactly as stored.
        declared_length: i32,
    },
}

impl PartKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::PackHeader { .. } => "pack-header",
            Self::SystemHeader => "system-header",
            Self::ProgramStreamMap => "program-stream-map",
            Self::PrivateStream1 => "private-stream-1",
            Self::AudioStream0 => "audio-stream-0",
            Self::VideoStream { .. } => "video-stream",
            Self::Ofni { .. } => "ofni-information",
        }
    }

    /// Whether this part's payload is video elementary stream.
    pub fn is_video(&self) -> bool {
        matches!(self, Self::VideoStream { .. })
    }
}

/// One part located by the container walk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StreamPart {
    pub kind: PartKind,
    /// The 32-bit start code value, for MPEG parts. `None` for `OFNI`.
    pub tag: Option<u32>,
    /// Absolute physical offset of the part's first byte.
    pub offset: u64,
    /// Total length of the part, framing included.
    pub length: u64,
    /// Absolute payload sub-range, when the framing located one.
    pub payload: Option<Region>,
}

impl StreamPart {
    /// Absolute physical extent of the whole part.
    pub fn region(&self) -> Option<Region> {
        Region::new(self.offset, self.length).ok()
    }

    /// The offset the walk should continue at.
    pub fn next_offset(&self) -> u64 {
        self.offset.saturating_add(self.length)
    }
}

/// Why a candidate part was not accepted.
///
/// A rejection is *data*, not an error: it describes bytes that are present but do not form
/// a valid part, which is exactly what an examiner needs for a damaged clip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartRejection {
    /// No recognised start code or `OFNI` tag at this offset.
    NoStartCode { observed: String },
    /// A `00 00 01` prefix whose stream id this platform does not interpret.
    UnknownStreamId { stream_id: u8 },
    /// The declared length is outside the structurally possible range.
    ImplausibleLength { declared: u64, min: u64, max: u64 },
    /// The declared length would run past the end of the clip.
    LengthExceedsClip { declared: u64, remaining: u64 },
    /// The payload offset field points outside its own part.
    PayloadOutsidePart {
        payload_offset: u64,
        part_length: u64,
    },
    /// Not enough bytes remain to hold even the part header.
    Truncated { available: u64, required: u64 },
}

impl PartRejection {
    pub fn reason(&self, offset: u64) -> String {
        match self {
            Self::NoStartCode { observed } => format!(
                "offset {offset} (0x{offset:X}) carries {observed}, which is neither an MPEG-PS \
                 start code this platform interprets nor an OFNI tag"
            ),
            Self::UnknownStreamId { stream_id } => format!(
                "offset {offset} (0x{offset:X}) carries a 00 00 01 prefix with stream id \
                 0x{stream_id:02X}, which this platform has no structural evidence for; the part \
                 was not interpreted"
            ),
            Self::ImplausibleLength { declared, min, max } => format!(
                "the part at {offset} (0x{offset:X}) declares length {declared}, outside the \
                 structurally possible range [{min}, {max}]; the declared length was not replaced"
            ),
            Self::LengthExceedsClip {
                declared,
                remaining,
            } => format!(
                "the part at {offset} (0x{offset:X}) declares length {declared} but only \
                 {remaining} byte(s) remain in the clip; the part was not truncated to fit"
            ),
            Self::PayloadOutsidePart {
                payload_offset,
                part_length,
            } => format!(
                "the part at {offset} (0x{offset:X}) places its payload at +{payload_offset}, \
                 outside its own {part_length}-byte extent"
            ),
            Self::Truncated {
                available,
                required,
            } => format!(
                "only {available} byte(s) remain at {offset} (0x{offset:X}) but {required} are \
                 required to read a part header"
            ),
        }
    }
}

/// An `OFNI` information part, preserved as metadata evidence.
///
/// Its interior meaning is not established by this platform, so the bytes are recorded
/// rather than interpreted. Discarding them would lose recoverable metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OfniRecord {
    /// Absolute offset of the `OFNI` tag.
    pub offset: u64,
    /// The declared length, exactly as stored.
    pub declared_length: i32,
    /// Total part length actually accepted.
    pub total_length: u64,
    /// Absolute extent of the part's body, after the tag and length field.
    pub body: Option<Region>,
    /// A short hex/ASCII rendering of the body's first bytes, so a report carries something
    /// an examiner can recognise without re-reading the disk.
    pub body_preview: String,
}

// ── Codec detection ─────────────────────────────────────────────────────────────

/// The codec a clip's video payload carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HikCodec {
    H264,
    H265,
    /// The payload did not establish a codec. Reported honestly rather than defaulted:
    /// remuxing as the wrong codec produces an artifact that will not decode.
    Unknown,
}

impl HikCodec {
    pub fn label(&self) -> &'static str {
        match self {
            Self::H264 => "H.264",
            Self::H265 => "H.265",
            Self::Unknown => "Unknown",
        }
    }

    /// The elementary-stream file extension for this codec, when one is known.
    pub fn extension(&self) -> Option<&'static str> {
        match self {
            Self::H264 => Some("h264"),
            Self::H265 => Some("hevc"),
            Self::Unknown => None,
        }
    }
}

/// The NAL observations behind a codec decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodecEvidence {
    pub codec: HikCodec,
    /// Confidence in the decision, 0.0 to 1.0. Not a probability; a monotone score.
    pub confidence: f64,
    /// H.264 NAL types observed, with how many of each.
    pub h264_nals: BTreeMap<String, usize>,
    /// H.265 NAL types observed, with how many of each.
    pub h265_nals: BTreeMap<String, usize>,
    /// Whether H.264 parameter sets (SPS/PPS) were seen in the sampled payload.
    pub h264_parameter_sets: bool,
    /// Whether H.265 parameter sets (VPS/SPS/PPS) were seen.
    pub h265_parameter_sets: bool,
    /// Bytes of video payload that were examined.
    pub bytes_sampled: u64,
    pub reason: String,
}

impl CodecEvidence {
    /// An honest "no codec established", with the reason an examiner needs.
    ///
    /// Public so the reconstruction and carving paths can report the same shape when they
    /// have no payload to classify, instead of inventing a placeholder codec.
    pub fn unknown(reason: impl Into<String>, bytes_sampled: u64) -> Self {
        Self {
            codec: HikCodec::Unknown,
            confidence: 0.0,
            h264_nals: BTreeMap::new(),
            h265_nals: BTreeMap::new(),
            h264_parameter_sets: false,
            h265_parameter_sets: false,
            bytes_sampled,
            reason: reason.into(),
        }
    }

    /// Whether parameter sets needed for a decodable stream were located.
    pub fn has_parameter_sets(&self) -> bool {
        match self.codec {
            HikCodec::H264 => self.h264_parameter_sets,
            HikCodec::H265 => self.h265_parameter_sets,
            HikCodec::Unknown => false,
        }
    }

    pub fn validation(&self) -> ValidationState {
        let kind = match (self.codec, self.confidence) {
            (HikCodec::Unknown, _) => ValidationStateKind::Unknown,
            (_, c) if c >= 0.7 => ValidationStateKind::Pass,
            _ => ValidationStateKind::Review,
        };
        vs(
            kind,
            self.reason.clone(),
            "hikvision_codec_detection",
            "video_payload",
        )
    }
}

/// Classify the codec of video elementary-stream bytes.
///
/// `sample` must be bytes the container walk established are **video PES payload**. Passing
/// a whole clip here would reinstate the "NAL bytes appear somewhere, so it must be
/// Annex-B" defect this module exists to avoid.
///
/// The decision needs several agreeing NAL observations, not one signature. In particular
/// the H.265 branch validates the full two-byte NAL header — `forbidden_zero_bit`,
/// `nuh_layer_id` and `nuh_temporal_id_plus1` — because a plain H.264 P-slice header byte
/// (`0x41`) decodes to "H.265 VPS" if only the type field is examined.
pub fn classify_codec(profile: &OemProfile, sample: &[u8]) -> CodecEvidence {
    let min_agreeing = usize_from(profile, key::CODEC_MIN_AGREEING_NALS, 2);
    let bytes = sample.len() as u64;

    if sample.len() < 5 {
        return CodecEvidence::unknown(
            format!(
                "only {bytes} byte(s) of video payload were available, too few to establish a \
                 codec; no codec was assumed"
            ),
            bytes,
        );
    }

    let h264_mask = crate::layout::u8_from(profile, key::NAL_H264_TYPE_MASK, 0x1F);
    let h265_mask = crate::layout::u8_from(profile, key::NAL_H265_TYPE_MASK, 0x7E);
    let h265_shift = crate::layout::u8_from(profile, key::NAL_H265_TYPE_SHIFT, 1);

    let h264_sps = crate::layout::u8_from(profile, key::NAL_H264_TYPE_SPS, 7);
    let h264_pps = crate::layout::u8_from(profile, key::NAL_H264_TYPE_PPS, 8);
    let h264_idr = crate::layout::u8_from(profile, key::NAL_H264_TYPE_IDR, 5);
    let h264_non_idr = crate::layout::u8_from(profile, key::NAL_H264_TYPE_NON_IDR, 1);
    let h264_sei = crate::layout::u8_from(profile, key::NAL_H264_TYPE_SEI, 6);
    let h264_aud = crate::layout::u8_from(profile, key::NAL_H264_TYPE_AUD, 9);

    let h265_vps = crate::layout::u8_from(profile, key::NAL_H265_TYPE_VPS, 32);
    let h265_sps = crate::layout::u8_from(profile, key::NAL_H265_TYPE_SPS, 33);
    let h265_pps = crate::layout::u8_from(profile, key::NAL_H265_TYPE_PPS, 34);
    let h265_idr_w_radl = crate::layout::u8_from(profile, key::NAL_H265_TYPE_IDR_W_RADL, 19);
    let h265_idr_n_lp = crate::layout::u8_from(profile, key::NAL_H265_TYPE_IDR_N_LP, 20);
    let h265_trail_r = crate::layout::u8_from(profile, key::NAL_H265_TYPE_TRAIL_R, 1);
    let h265_aud = crate::layout::u8_from(profile, key::NAL_H265_TYPE_AUD, 35);

    let mut h264: BTreeMap<String, usize> = BTreeMap::new();
    let mut h265: BTreeMap<String, usize> = BTreeMap::new();
    let mut h264_score = 0.0f64;
    let mut h265_score = 0.0f64;
    let mut h264_params = false;
    let mut h265_params = false;
    let mut starts = 0usize;

    let mut i = 0usize;
    while i + 4 <= sample.len() {
        // Annex-B start code: 00 00 01 or 00 00 00 01.
        let (nal_at, step) = if sample[i] == 0 && sample[i + 1] == 0 && sample[i + 2] == 1 {
            (i + 3, 3)
        } else if i + 5 <= sample.len()
            && sample[i] == 0
            && sample[i + 1] == 0
            && sample[i + 2] == 0
            && sample[i + 3] == 1
        {
            (i + 4, 4)
        } else {
            i += 1;
            continue;
        };
        if nal_at >= sample.len() {
            break;
        }
        starts += 1;
        let b0 = sample[nal_at];
        let b1 = sample.get(nal_at + 1).copied();

        // ── H.264 reading ────────────────────────────────────────────────────────
        //
        // forbidden_zero_bit must be clear; nal_unit_type occupies the low 5 bits.
        if b0 & 0x80 == 0 {
            let t = b0 & h264_mask;
            let (name, weight) = if t == h264_sps {
                ("SPS", 3.0)
            } else if t == h264_pps {
                ("PPS", 3.0)
            } else if t == h264_idr {
                ("IDR", 2.0)
            } else if t == h264_non_idr {
                ("non-IDR", 1.0)
            } else if t == h264_sei {
                ("SEI", 0.5)
            } else if t == h264_aud {
                ("AUD", 0.5)
            } else if (1..=23).contains(&t) {
                ("other-slice", 0.25)
            } else {
                ("", 0.0)
            };
            if weight > 0.0 {
                *h264.entry(name.to_string()).or_insert(0) += 1;
                h264_score += weight;
                if t == h264_sps || t == h264_pps {
                    h264_params = true;
                }
            }
        }

        // ── H.265 reading ────────────────────────────────────────────────────────
        //
        // The two-byte header is validated in full. Without the temporal-id and layer-id
        // checks, an H.264 P-slice byte 0x41 reads as an H.265 VPS and a plain H.264 stream
        // gets reported as HEVC.
        if let Some(b1v) = b1 {
            let forbidden_clear = b0 & 0x80 == 0;
            let t = (b0 & h265_mask) >> h265_shift;
            let layer_id = ((b0 & 0x01) << 5) | (b1v >> 3);
            let tid_plus1 = b1v & 0x07;
            if forbidden_clear && tid_plus1 >= 1 && layer_id == 0 {
                let (name, weight) = if t == h265_vps {
                    ("VPS", 3.0)
                } else if t == h265_sps {
                    ("SPS", 3.0)
                } else if t == h265_pps {
                    ("PPS", 3.0)
                } else if t == h265_idr_w_radl || t == h265_idr_n_lp {
                    ("IDR", 2.0)
                } else if t == h265_trail_r {
                    ("TRAIL_R", 1.0)
                } else if t == h265_aud {
                    ("AUD", 0.5)
                } else {
                    ("", 0.0)
                };
                if weight > 0.0 {
                    *h265.entry(name.to_string()).or_insert(0) += 1;
                    h265_score += weight;
                    if t == h265_vps || t == h265_sps || t == h265_pps {
                        h265_params = true;
                    }
                }
            }
        }

        // Advance past the NAL header so the same start code is not re-counted. `step` is
        // the start-code length actually matched; it is not needed again beyond that.
        debug_assert!(step == 3 || step == 4);
        i = nal_at + 1;
    }

    let h264_count: usize = h264.values().sum();
    let h265_count: usize = h265.values().sum();

    if starts == 0 {
        return CodecEvidence::unknown(
            format!(
                "no Annex-B start code was found in {bytes} byte(s) of video payload, so no NAL \
                 structure could be examined and no codec was assumed"
            ),
            bytes,
        );
    }

    // Parameter sets are the decisive signal: a stream carrying VPS/SPS/PPS in one codec's
    // encoding and not the other's is that codec.
    let (codec, confidence, reason) = match (h265_params, h264_params) {
        (true, false) if h265_count >= min_agreeing => (
            HikCodec::H265,
            0.9,
            format!(
                "H.265 parameter sets were located in {bytes} byte(s) of video payload with \
                 {h265_count} agreeing NAL(s) whose two-byte headers validated (layer id 0, \
                 temporal id set); no H.264 parameter set was present"
            ),
        ),
        (false, true) if h264_count >= min_agreeing => (
            HikCodec::H264,
            0.9,
            format!(
                "H.264 parameter sets were located in {bytes} byte(s) of video payload with \
                 {h264_count} agreeing NAL(s); no valid H.265 parameter set was present"
            ),
        ),
        // Both codecs' parameter sets appear to be present. That is contradictory, so the
        // stronger score wins but the confidence is reduced and the conflict is stated.
        (true, true) => {
            if h265_score > h264_score * 1.5 {
                (
                    HikCodec::H265,
                    0.6,
                    format!(
                        "both H.264 and H.265 parameter-set patterns appear in {bytes} byte(s) of \
                         video payload; the H.265 reading scored {h265_score:.2} against \
                         {h264_score:.2} and was reported with reduced confidence"
                    ),
                )
            } else if h264_score > h265_score * 1.5 {
                (
                    HikCodec::H264,
                    0.6,
                    format!(
                        "both H.264 and H.265 parameter-set patterns appear in {bytes} byte(s) of \
                         video payload; the H.264 reading scored {h264_score:.2} against \
                         {h265_score:.2} and was reported with reduced confidence"
                    ),
                )
            } else {
                (
                    HikCodec::Unknown,
                    0.0,
                    format!(
                        "the H.264 reading scored {h264_score:.2} and the H.265 reading \
                         {h265_score:.2} over {bytes} byte(s) of video payload, too close to \
                         separate; no codec was fabricated"
                    ),
                )
            }
        }
        // No parameter set either way: decide on slice NALs only, at lower confidence.
        _ => {
            if h264_count >= min_agreeing && h264_score > h265_score * 1.5 {
                (
                    HikCodec::H264,
                    0.5,
                    format!(
                        "no parameter set was present in the sampled {bytes} byte(s), but \
                         {h264_count} H.264 slice NAL(s) scored {h264_score:.2} against \
                         {h265_score:.2} for H.265"
                    ),
                )
            } else if h265_count >= min_agreeing && h265_score > h264_score * 1.5 {
                (
                    HikCodec::H265,
                    0.5,
                    format!(
                        "no parameter set was present in the sampled {bytes} byte(s), but \
                         {h265_count} H.265 NAL(s) with valid two-byte headers scored \
                         {h265_score:.2} against {h264_score:.2} for H.264"
                    ),
                )
            } else {
                (
                    HikCodec::Unknown,
                    0.0,
                    format!(
                        "{starts} Annex-B start code(s) were found in {bytes} byte(s) of video \
                         payload but the NAL structure did not reach {min_agreeing} agreeing \
                         observation(s) for either codec (H.264 {h264_score:.2}, H.265 \
                         {h265_score:.2}); the codec is reported Unknown rather than guessed"
                    ),
                )
            }
        }
    };

    CodecEvidence {
        codec,
        confidence,
        h264_nals: h264,
        h265_nals: h265,
        h264_parameter_sets: h264_params,
        h265_parameter_sets: h265_params,
        bytes_sampled: bytes,
        reason,
    }
}

// ── Clip walk ───────────────────────────────────────────────────────────────────

/// The result of walking one clip's container.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClipStream {
    /// The clip range that was walked.
    pub region: Region,
    /// Parts located, in physical order.
    pub parts: Vec<StreamPart>,
    /// Video payload sub-ranges, in order. Concatenating these yields the elementary
    /// stream.
    pub payload_regions: Vec<Region>,
    /// Pack serials, in the order the packs appeared.
    pub pack_serials: Vec<u32>,
    /// `OFNI` parts, preserved as metadata.
    pub ofni_parts: Vec<OfniRecord>,
    /// Codec evidence from the sampled video payload.
    pub codec: CodecEvidence,
    /// Bytes of the clip the walk accounted for.
    pub bytes_walked: u64,
    /// Offsets where the walk had to resynchronise to the next start code.
    pub resyncs: Vec<String>,
    /// Candidate parts that did not validate.
    pub rejections: Vec<String>,
    /// Whether the walk reached the end of the clip.
    pub reached_end: bool,
    pub evidence: ValidationState,
}

impl ClipStream {
    pub fn video_parts(&self) -> impl Iterator<Item = &StreamPart> {
        self.parts.iter().filter(|p| p.kind.is_video())
    }

    /// Total video payload bytes located.
    pub fn payload_bytes(&self) -> u64 {
        self.payload_regions
            .iter()
            .fold(0u64, |a, r| a.saturating_add(r.length))
    }

    /// Whether the container walk found real framing.
    pub fn has_framing(&self) -> bool {
        !self.parts.is_empty()
    }

    /// Fraction of the clip the walk accounted for, as a coverage signal.
    pub fn coverage(&self) -> f64 {
        if self.region.length == 0 {
            return 0.0;
        }
        self.bytes_walked as f64 / self.region.length as f64
    }

    /// The leading payload ranges to sample for codec classification.
    ///
    /// Bounded so classification never pulls a whole clip into memory.
    pub fn codec_sample_regions(&self, max_bytes: u64) -> Vec<Region> {
        sample_regions(&self.payload_regions, max_bytes)
    }

    /// Metadata for the generic fragment/index types.
    pub fn oem_metadata(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("hikvision_ps_parts".into(), self.parts.len().to_string());
        m.insert(
            "hikvision_ps_video_parts".into(),
            self.video_parts().count().to_string(),
        );
        m.insert(
            "hikvision_ps_payload_bytes".into(),
            self.payload_bytes().to_string(),
        );
        m.insert(
            "hikvision_ps_bytes_walked".into(),
            self.bytes_walked.to_string(),
        );
        m.insert(
            "hikvision_ps_coverage".into(),
            format!("{:.4}", self.coverage()),
        );
        m.insert(
            "hikvision_codec".into(),
            self.codec.codec.label().to_string(),
        );
        m.insert(
            "hikvision_codec_confidence".into(),
            format!("{:.2}", self.codec.confidence),
        );
        m.insert("hikvision_codec_evidence".into(), self.codec.reason.clone());
        m.insert(
            "hikvision_codec_parameter_sets_present".into(),
            self.codec.has_parameter_sets().to_string(),
        );
        if !self.pack_serials.is_empty() {
            m.insert(
                "hikvision_ps_first_pack_serial".into(),
                self.pack_serials[0].to_string(),
            );
            m.insert(
                "hikvision_ps_last_pack_serial".into(),
                self.pack_serials[self.pack_serials.len() - 1].to_string(),
            );
            m.insert(
                "hikvision_ps_pack_count".into(),
                self.pack_serials.len().to_string(),
            );
        }
        if !self.ofni_parts.is_empty() {
            m.insert(
                "hikvision_ofni_part_count".into(),
                self.ofni_parts.len().to_string(),
            );
            // Preserve the OFNI evidence rather than dropping it on the floor.
            for (i, o) in self.ofni_parts.iter().enumerate().take(4) {
                m.insert(format!("hikvision_ofni_{i}_offset"), o.offset.to_string());
                m.insert(
                    format!("hikvision_ofni_{i}_declared_length"),
                    o.declared_length.to_string(),
                );
                m.insert(
                    format!("hikvision_ofni_{i}_body_preview"),
                    o.body_preview.clone(),
                );
            }
        }
        if !self.resyncs.is_empty() {
            m.insert(
                "hikvision_ps_resyncs".into(),
                self.resyncs.len().to_string(),
            );
        }
        if !self.rejections.is_empty() {
            m.insert(
                "hikvision_ps_rejected_parts".into(),
                self.rejections.len().to_string(),
            );
        }
        m
    }
}

/// Take at most `max_bytes` from the front of `regions`, clipping the last one.
///
/// Free function rather than a method so the clip walk can bound its codec sample before a
/// [`ClipStream`] exists, without building a throwaway one.
pub fn sample_regions(regions: &[Region], max_bytes: u64) -> Vec<Region> {
    let mut out = Vec::new();
    let mut taken = 0u64;
    for r in regions {
        if taken >= max_bytes {
            break;
        }
        let want = (max_bytes - taken).min(r.length);
        if want == 0 {
            continue;
        }
        if let Ok(clipped) = Region::new(r.offset, want) {
            out.push(clipped);
            taken = taken.saturating_add(want);
        }
    }
    out
}

/// A sliding read window over a clip, so a walk never loads the whole clip.
struct StreamWindow<'a> {
    reader: &'a dyn EvidenceReader,
    region_end: u64,
    window_size: usize,
    start: u64,
    bytes: Vec<u8>,
}

impl<'a> StreamWindow<'a> {
    fn new(reader: &'a dyn EvidenceReader, region_end: u64, window_size: usize) -> Self {
        Self {
            reader,
            region_end,
            window_size: window_size.max(4096),
            start: 0,
            bytes: Vec::new(),
        }
    }

    /// Bytes available from `offset` to the end of the loaded window.
    ///
    /// Reloads when `offset` is outside the window or when fewer than `need` bytes are
    /// loaded after it, so a part header straddling a window boundary is still read whole.
    fn at(&mut self, offset: u64, need: usize) -> Result<&[u8], ForensicError> {
        let loaded_end = self.start.saturating_add(self.bytes.len() as u64);
        let have_after = loaded_end.saturating_sub(offset);
        let want = (need as u64).min(self.region_end.saturating_sub(offset));
        if offset < self.start || offset >= loaded_end || have_after < want {
            self.reload(offset)?;
        }
        let rel = offset.saturating_sub(self.start) as usize;
        Ok(self.bytes.get(rel..).unwrap_or_default())
    }

    fn reload(&mut self, offset: u64) -> Result<(), ForensicError> {
        let remaining = self.region_end.saturating_sub(offset);
        let want = remaining.min(self.window_size as u64) as usize;
        let mut buf = vec![0u8; want];
        if want == 0 {
            self.start = offset;
            self.bytes = buf;
            return Ok(());
        }
        // A short read is not an error here: the clip may be truncated by the acquisition,
        // and the walk should describe what is present.
        let n = self.reader.read_at(offset, &mut buf).unwrap_or_default();
        buf.truncate(n);
        self.start = offset;
        self.bytes = buf;
        Ok(())
    }
}

/// Parse one part at `offset`, given `buf` starting at that offset.
///
/// `remaining` is how many bytes of the clip are left, so a part that declares more than
/// the clip holds is rejected instead of silently reading past the clip.
pub fn parse_part_at(
    profile: &OemProfile,
    offset: u64,
    buf: &[u8],
    remaining: u64,
) -> Result<StreamPart, PartRejection> {
    let start_code_len = usize_from(profile, key::PS_START_CODE_LENGTH, 4);
    let ofni_tag = magic(profile, sig::OFNI_PART).unwrap_or_else(|| b"OFNI".to_vec());

    if buf.len() < start_code_len {
        return Err(PartRejection::Truncated {
            available: buf.len() as u64,
            required: start_code_len as u64,
        });
    }

    // ── OFNI ─────────────────────────────────────────────────────────────────────
    if buf.starts_with(&ofni_tag) {
        let len_rel = usize_from(profile, key::OFNI_LENGTH_OFFSET, 4);
        let addend = u64_from(profile, key::OFNI_LENGTH_ADDEND, 8);
        let max = u64_from(profile, key::OFNI_MAX_LENGTH, 65_536);
        let declared_length = i32_at(buf, len_rel).ok_or(PartRejection::Truncated {
            available: buf.len() as u64,
            required: (len_rel + 4) as u64,
        })?;
        if declared_length < 0 || declared_length as u64 > max {
            return Err(PartRejection::ImplausibleLength {
                declared: declared_length.unsigned_abs() as u64,
                min: 0,
                max,
            });
        }
        let total = (declared_length as u64).saturating_add(addend);
        if total > remaining {
            return Err(PartRejection::LengthExceedsClip {
                declared: total,
                remaining,
            });
        }
        let payload = if declared_length > 0 {
            Region::new(offset.saturating_add(addend), declared_length as u64).ok()
        } else {
            None
        };
        return Ok(StreamPart {
            kind: PartKind::Ofni { declared_length },
            tag: None,
            offset,
            length: total,
            payload,
        });
    }

    // ── MPEG start code ──────────────────────────────────────────────────────────
    let prefix_len = usize_from(profile, key::PS_START_CODE_PREFIX_LENGTH, 3);
    if !(buf.len() > prefix_len
        && buf[..prefix_len].iter().enumerate().all(|(i, b)| {
            // The prefix is 00 00 01.
            if i + 1 == prefix_len {
                *b == 0x01
            } else {
                *b == 0x00
            }
        }))
    {
        return Err(PartRejection::NoStartCode {
            observed: hex_ascii(&buf[..start_code_len.min(buf.len())]),
        });
    }

    let stream_id = buf[prefix_len];
    let tag = u32_be_at(buf, 0).unwrap_or(0);

    let t_pack = u64_from(profile, key::PS_TAG_PACK_HEADER, 0x1BA) as u32;
    let t_system = u64_from(profile, key::PS_TAG_SYSTEM_HEADER, 0x1BB) as u32;
    let t_psm = u64_from(profile, key::PS_TAG_PROGRAM_STREAM_MAP, 0x1BC) as u32;
    let t_priv1 = u64_from(profile, key::PS_TAG_PRIVATE_STREAM_1, 0x1BD) as u32;
    let t_audio = u64_from(profile, key::PS_TAG_AUDIO_STREAM_0, 0x1C0) as u32;
    let t_video0 = u64_from(profile, key::PS_TAG_VIDEO_STREAM_0, 0x1E0) as u32;
    let t_video1 = u64_from(profile, key::PS_TAG_VIDEO_STREAM_1, 0x1E1) as u32;

    // ── Pack header: a fixed-size structure, not a PES ───────────────────────────
    if tag == t_pack {
        let size = u64_from(profile, key::PS_PACK_HEADER_SIZE, 20);
        if size > remaining {
            return Err(PartRejection::LengthExceedsClip {
                declared: size,
                remaining,
            });
        }
        let serial_rel = usize_from(profile, key::PS_PACK_SERIAL_OFFSET, 16);
        let serial = u32_be_at(buf, serial_rel).ok_or(PartRejection::Truncated {
            available: buf.len() as u64,
            required: (serial_rel + 4) as u64,
        })?;
        return Ok(StreamPart {
            kind: PartKind::PackHeader { serial },
            tag: Some(tag),
            offset,
            length: size,
            payload: None,
        });
    }

    let kind = if tag == t_system {
        PartKind::SystemHeader
    } else if tag == t_psm {
        PartKind::ProgramStreamMap
    } else if tag == t_priv1 {
        PartKind::PrivateStream1
    } else if tag == t_audio {
        PartKind::AudioStream0
    } else if tag == t_video0 {
        PartKind::VideoStream { stream_index: 0 }
    } else if tag == t_video1 {
        PartKind::VideoStream { stream_index: 1 }
    } else {
        return Err(PartRejection::UnknownStreamId { stream_id });
    };

    // ── PES length ───────────────────────────────────────────────────────────────
    let len_rel = usize_from(profile, key::PS_PES_LENGTH_OFFSET, 4);
    let len_addend = u64_from(profile, key::PS_PES_LENGTH_ADDEND, 6);
    let min_len = u64_from(profile, key::PS_PES_MIN_PART_LENGTH, 6);
    let max_len = u64_from(profile, key::PS_PES_MAX_PART_LENGTH, 1 << 20);

    let declared = u16_be_at(buf, len_rel).ok_or(PartRejection::Truncated {
        available: buf.len() as u64,
        required: (len_rel + 2) as u64,
    })?;
    let part_length = (declared as u64).saturating_add(len_addend);

    if part_length < min_len || part_length > max_len {
        return Err(PartRejection::ImplausibleLength {
            declared: part_length,
            min: min_len,
            max: max_len,
        });
    }
    if part_length > remaining {
        return Err(PartRejection::LengthExceedsClip {
            declared: part_length,
            remaining,
        });
    }

    // ── Payload offset ───────────────────────────────────────────────────────────
    let po_rel = usize_from(profile, key::PS_PES_PAYLOAD_OFFSET_FIELD, 7);
    let po_mask = u64_from(profile, key::PS_PES_PAYLOAD_OFFSET_MASK, 0xFFF);
    let po_addend = u64_from(profile, key::PS_PES_PAYLOAD_OFFSET_ADDEND, 9);

    let payload = match u16_be_at(buf, po_rel) {
        Some(raw) => {
            let payload_offset = ((raw as u64) & po_mask).saturating_add(po_addend);
            if payload_offset >= part_length {
                return Err(PartRejection::PayloadOutsidePart {
                    payload_offset,
                    part_length,
                });
            }
            let payload_len = part_length - payload_offset;
            Region::new(offset.saturating_add(payload_offset), payload_len).ok()
        }
        // The part is valid but too short to carry a payload-offset field; the part's extent
        // stands and its payload is simply not located.
        None => None,
    };

    Ok(StreamPart {
        kind,
        tag: Some(tag),
        offset,
        length: part_length,
        payload,
    })
}

/// How a walk reacts to bytes that do not form a valid part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkMode {
    /// Skip to the next start code and keep going.
    ///
    /// Correct for a clip whose extent the filesystem already established: damage in the
    /// middle of a known clip does not make its later parts unrecoverable.
    Resync,
    /// Stop at the first byte that does not continue the container.
    ///
    /// Correct for carving, where the end of valid framing *is* the end of the candidate.
    /// Resyncing here would merge two unrelated recordings into one.
    StopAtFirstRejection,
}

/// Walk a clip's container, locating every part and its video payload.
///
/// Reads through a bounded sliding window; never materialises the clip. Resynchronises past
/// damage, because the clip's extent is already known from the filesystem.
pub fn walk_clip(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    region: Region,
) -> Result<ClipStream, ForensicError> {
    walk_parts(reader, profile, region, WalkMode::Resync)
}

/// Walk the longest run of valid container framing starting at `region.offset`.
///
/// Stops at the first byte that does not continue the container, so the returned
/// [`ClipStream::region`] is the candidate's own extent rather than the whole search range.
pub fn walk_contiguous(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    region: Region,
) -> Result<ClipStream, ForensicError> {
    walk_parts(reader, profile, region, WalkMode::StopAtFirstRejection)
}

/// Walk a container range under an explicit [`WalkMode`].
pub fn walk_parts(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    region: Region,
    mode: WalkMode,
) -> Result<ClipStream, ForensicError> {
    let window_size = usize_from(profile, key::READ_WINDOW_BYTES, 4 << 20);
    let max_parts = u64_from(profile, key::PS_MAX_PARTS_PER_CLIP, 1 << 20) as usize;
    let prefix_len = usize_from(profile, key::PS_START_CODE_PREFIX_LENGTH, 3);
    // Enough to cover the largest fixed part header plus the PES payload-offset field.
    let header_need = usize_from(profile, key::PS_PACK_HEADER_SIZE, 20).max(16) + 8;

    let region_end = region
        .offset
        .saturating_add(region.length)
        .min(reader.len());
    let mut window = StreamWindow::new(reader, region_end, window_size);

    let mut parts: Vec<StreamPart> = Vec::new();
    let mut payload_regions: Vec<Region> = Vec::new();
    let mut pack_serials: Vec<u32> = Vec::new();
    let mut ofni_parts: Vec<OfniRecord> = Vec::new();
    let mut rejections: Vec<String> = Vec::new();
    let mut resyncs: Vec<String> = Vec::new();
    let mut bytes_walked = 0u64;

    let mut cursor = region.offset;
    while cursor < region_end && parts.len() < max_parts {
        let remaining = region_end - cursor;
        let buf = window.at(cursor, header_need)?.to_vec();
        if buf.is_empty() {
            break;
        }

        match parse_part_at(profile, cursor, &buf, remaining) {
            Ok(part) => {
                if let PartKind::PackHeader { serial } = &part.kind {
                    pack_serials.push(*serial);
                }
                if let PartKind::Ofni { declared_length } = &part.kind {
                    let preview = part
                        .payload
                        .and_then(|p| {
                            let n = p.length.min(16) as usize;
                            buf.get(
                                (p.offset.saturating_sub(cursor) as usize)
                                    ..(p.offset.saturating_sub(cursor) as usize + n),
                            )
                            .map(hex_ascii)
                        })
                        .unwrap_or_else(|| "(empty)".to_string());
                    ofni_parts.push(OfniRecord {
                        offset: part.offset,
                        declared_length: *declared_length,
                        total_length: part.length,
                        body: part.payload,
                        body_preview: preview,
                    });
                }
                if part.kind.is_video() {
                    if let Some(p) = part.payload {
                        payload_regions.push(p);
                    }
                }
                bytes_walked = bytes_walked.saturating_add(part.length);
                let next = part.next_offset();
                parts.push(part);
                // A zero-length part would not advance the cursor; guard against a hostile
                // structure turning the walk into an infinite loop.
                if next <= cursor {
                    rejections.push(format!(
                        "the part at {cursor} (0x{cursor:X}) does not advance the walk; the walk \
                         stopped rather than looping"
                    ));
                    break;
                }
                cursor = next;
            }
            Err(rejection) => {
                rejections.push(rejection.reason(cursor));
                if mode == WalkMode::StopAtFirstRejection {
                    // Carving: valid framing has ended, and that boundary is the finding.
                    break;
                }
                // Resynchronise to the next start-code prefix rather than abandoning the
                // clip: damage in the middle of a clip does not make its later parts
                // unrecoverable.
                match next_start_code(&buf, prefix_len) {
                    Some(delta) if delta > 0 => {
                        let to = cursor.saturating_add(delta as u64);
                        resyncs.push(format!(
                            "resynchronised from {cursor} (0x{cursor:X}) to {to} (0x{to:X}), \
                             skipping {delta} byte(s) that carry no valid part"
                        ));
                        cursor = to;
                    }
                    _ => {
                        // No further start code in this window. Advance past it and keep
                        // looking, so one damaged window does not end the walk.
                        let advance = buf.len().max(1) as u64;
                        let to = cursor.saturating_add(advance);
                        if to >= region_end {
                            cursor = region_end;
                        } else {
                            resyncs.push(format!(
                                "no start code found between {cursor} (0x{cursor:X}) and {to} \
                                 (0x{to:X}); the walk continued past the gap"
                            ));
                            cursor = to;
                        }
                    }
                }
            }
        }
    }

    let reached_end = cursor >= region_end;

    // In carving mode the walk's own extent is the finding: the candidate runs from the
    // start to wherever valid framing stopped. Reporting the whole search range here would
    // claim bytes the walk never validated.
    let region = match (mode, parts.is_empty()) {
        (WalkMode::StopAtFirstRejection, false) => {
            Region::new(region.offset, cursor.saturating_sub(region.offset)).unwrap_or(region)
        }
        _ => region,
    };

    // ── Codec, from video payload only ───────────────────────────────────────────
    let sample_budget = u64_from(profile, key::CARVE_WINDOW_BYTES, 4 << 20).min(1 << 20);
    let mut sample: Vec<u8> = Vec::new();
    for r in sample_regions(&payload_regions, sample_budget) {
        if let Ok(mut b) = reader.read_exact_at(r.offset, r.length as usize) {
            sample.append(&mut b);
        }
    }
    let codec = if payload_regions.is_empty() {
        CodecEvidence::unknown(
            format!(
                "the container walk located no video PES payload in the {}-byte clip at {} \
                 (0x{:X}), so no bytes were eligible for codec classification. The clip was NOT \
                 classified by scanning it for NAL signatures, because a signature outside a \
                 located video payload establishes nothing",
                region.length, region.offset, region.offset
            ),
            0,
        )
    } else {
        classify_codec(profile, &sample)
    };

    let evidence = walk_evidence(
        &region,
        &parts,
        &payload_regions,
        &rejections,
        &resyncs,
        bytes_walked,
        reached_end,
        &codec,
    );

    Ok(ClipStream {
        region,
        parts,
        payload_regions,
        pack_serials,
        ofni_parts,
        codec,
        bytes_walked,
        resyncs,
        rejections,
        reached_end,
        evidence,
    })
}

/// Offset of the next `00 00 01` prefix strictly after position 0, if any.
fn next_start_code(buf: &[u8], prefix_len: usize) -> Option<usize> {
    if buf.len() <= prefix_len {
        return None;
    }
    (1..=buf.len().saturating_sub(prefix_len)).find(|&i| {
        buf[i..i + prefix_len].iter().enumerate().all(|(j, b)| {
            if j + 1 == prefix_len {
                *b == 1
            } else {
                *b == 0
            }
        })
    })
}

#[allow(clippy::too_many_arguments)]
fn walk_evidence(
    region: &Region,
    parts: &[StreamPart],
    payloads: &[Region],
    rejections: &[String],
    resyncs: &[String],
    bytes_walked: u64,
    reached_end: bool,
    codec: &CodecEvidence,
) -> ValidationState {
    if parts.is_empty() {
        return vs(
            ValidationStateKind::Unknown,
            format!(
                "no MPEG-PS part could be located in the {}-byte clip at {} (0x{:X}); the range \
                 carries no framing this platform interprets",
                region.length, region.offset, region.offset
            ),
            "hikvision_ps_walk",
            "clip",
        );
    }

    let coverage = if region.length == 0 {
        0.0
    } else {
        bytes_walked as f64 / region.length as f64
    };
    let base = format!(
        "walked {} part(s) over {bytes_walked} of {} clip byte(s) ({:.1}% coverage), locating {} \
         video payload range(s) totalling {} byte(s); codec {} ({})",
        parts.len(),
        region.length,
        coverage * 100.0,
        payloads.len(),
        payloads.iter().fold(0u64, |a, r| a + r.length),
        codec.codec.label(),
        codec.reason,
    );

    let mut notes: Vec<String> = Vec::new();
    if !rejections.is_empty() {
        notes.push(format!("{} part(s) rejected", rejections.len()));
    }
    if !resyncs.is_empty() {
        notes.push(format!("{} resynchronisation(s)", resyncs.len()));
    }
    if !reached_end {
        notes.push("the walk stopped before the end of the clip".into());
    }

    if notes.is_empty() && codec.codec != HikCodec::Unknown {
        vs(ValidationStateKind::Pass, base, "hikvision_ps_walk", "clip")
    } else {
        vs(
            ValidationStateKind::Review,
            format!("{base}. Qualifications: {}", notes.join("; ")),
            "hikvision_ps_walk",
            "clip",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::tests_support::hikvision_profile;
    use crate::testing::MemReader;

    use crate::testing::build::{h264_es, h265_es, ofni, pack, pes};

    fn reader_of(parts: Vec<Vec<u8>>) -> (MemReader, Region) {
        let mut data = Vec::new();
        for p in parts {
            data.extend_from_slice(&p);
        }
        let len = data.len() as u64;
        (MemReader::new(data), Region::new(0, len).unwrap())
    }

    // ── Part parsing ────────────────────────────────────────────────────────────

    #[test]
    fn a_pack_header_is_a_fixed_twenty_byte_structure_with_a_big_endian_serial() {
        let p = hikvision_profile();
        let buf = pack(0x1234_5678);
        let part = parse_part_at(&p, 0, &buf, buf.len() as u64).unwrap();
        assert_eq!(
            part.length, 20,
            "the pack header is fixed size, not PES-length"
        );
        assert_eq!(part.tag, Some(0x1BA));
        assert_eq!(
            part.kind,
            PartKind::PackHeader {
                serial: 0x1234_5678
            }
        );
        assert!(part.payload.is_none());
        assert_eq!(part.next_offset(), 20);
    }

    #[test]
    fn the_pack_serial_is_read_big_endian_not_little_endian() {
        let p = hikvision_profile();
        let buf = pack(1);
        let part = parse_part_at(&p, 0, &buf, buf.len() as u64).unwrap();
        // Little-endian misreading would give 0x01000000.
        assert_eq!(part.kind, PartKind::PackHeader { serial: 1 });
    }

    #[test]
    fn every_recognised_start_code_is_parsed_with_the_documented_length_formula() {
        let p = hikvision_profile();
        let cases: Vec<(u8, u32, PartKind)> = vec![
            (0xBB, 0x1BB, PartKind::SystemHeader),
            (0xBC, 0x1BC, PartKind::ProgramStreamMap),
            (0xBD, 0x1BD, PartKind::PrivateStream1),
            (0xC0, 0x1C0, PartKind::AudioStream0),
            (0xE0, 0x1E0, PartKind::VideoStream { stream_index: 0 }),
            (0xE1, 0x1E1, PartKind::VideoStream { stream_index: 1 }),
        ];
        for (id, tag, expected) in cases {
            let payload = vec![0xAAu8; 32];
            let buf = pes(id, &payload, 14);
            let part = parse_part_at(&p, 0x1000, &buf, buf.len() as u64)
                .unwrap_or_else(|e| panic!("0x{id:02X} rejected: {e:?}"));
            assert_eq!(part.kind, expected, "stream id 0x{id:02X}");
            assert_eq!(part.tag, Some(tag));
            // partLength = u16BE@+4 + 6
            assert_eq!(part.length, buf.len() as u64);
            let pl = part.payload.expect("a payload range");
            // payload begins at (u16BE@+7 & 0xFFF) + 9, at an absolute offset.
            assert_eq!(pl.offset, 0x1000 + 14);
            assert_eq!(pl.length, 32);
        }
    }

    #[test]
    fn a_pes_payload_offset_outside_its_own_part_is_rejected() {
        let p = hikvision_profile();
        let mut buf = pes(0xE0, &[0xAA; 16], 14);
        // Push the payload-offset field past the part's declared length.
        let field = (buf.len() as u16).saturating_add(100);
        buf[7..9].copy_from_slice(&field.to_be_bytes());
        let err = parse_part_at(&p, 0, &buf, buf.len() as u64).unwrap_err();
        assert!(matches!(err, PartRejection::PayloadOutsidePart { .. }));
        assert!(err.reason(0).contains("outside its own"));
    }

    #[test]
    fn a_pes_length_beyond_the_clip_is_rejected_not_clamped() {
        let p = hikvision_profile();
        let buf = pes(0xE0, &[0xAA; 64], 14);
        // Claim only 20 bytes remain in the clip.
        let err = parse_part_at(&p, 0, &buf, 20).unwrap_err();
        match err {
            PartRejection::LengthExceedsClip {
                declared,
                remaining,
            } => {
                assert_eq!(declared, buf.len() as u64);
                assert_eq!(remaining, 20);
            }
            other => panic!("expected LengthExceedsClip, got {other:?}"),
        }
        assert!(err.reason(0).contains("not truncated to fit"));
    }

    /// `partLength = u16BE + 6` cannot fall below the profile minimum or above its maximum,
    /// whatever the declared field holds. Pinning that here documents *why* the only
    /// reachable PES length failures are "exceeds the clip" and "payload outside the part",
    /// which are covered by their own tests.
    #[test]
    fn the_pes_length_formula_cannot_produce_an_out_of_range_part_length() {
        let p = hikvision_profile();
        let min = u64_from(&p, key::PS_PES_MIN_PART_LENGTH, 6);
        let max = u64_from(&p, key::PS_PES_MAX_PART_LENGTH, 1 << 20);
        let addend = u64_from(&p, key::PS_PES_LENGTH_ADDEND, 6);
        for declared in [0u16, 1, 0x00FF, 0x7FFF, u16::MAX] {
            let computed = declared as u64 + addend;
            assert!(
                computed >= min && computed <= max,
                "declared {declared} yields {computed}, outside [{min}, {max}]"
            );
        }
    }

    /// A PES part whose declared length is internally inconsistent with its payload-offset
    /// field is rejected. This is the "malformed PES length" case in practice: the length
    /// and the payload offset disagree about where the part ends.
    #[test]
    fn a_pes_whose_length_and_payload_offset_disagree_is_rejected() {
        let p = hikvision_profile();
        let mut buf = vec![0u8; 64];
        buf[..4].copy_from_slice(&[0x00, 0x00, 0x01, 0xE0]);
        // partLength = 6, but the payload-offset field demands at least +9.
        buf[4..6].copy_from_slice(&0u16.to_be_bytes());
        buf[7..9].copy_from_slice(&0u16.to_be_bytes());
        let err = parse_part_at(&p, 0, &buf, 64).unwrap_err();
        match err {
            PartRejection::PayloadOutsidePart {
                payload_offset,
                part_length,
            } => {
                assert_eq!(part_length, 6, "declared 0 + addend 6");
                assert_eq!(payload_offset, 9);
                assert!(
                    payload_offset > part_length,
                    "the disagreement is what makes the part malformed"
                );
            }
            other => panic!("expected PayloadOutsidePart, got {other:?}"),
        }
    }

    #[test]
    fn a_zero_length_pes_cannot_place_a_payload_and_is_rejected_for_it() {
        let p = hikvision_profile();
        let mut buf = vec![0u8; 32];
        buf[..4].copy_from_slice(&[0x00, 0x00, 0x01, 0xE0]);
        buf[4..6].copy_from_slice(&0u16.to_be_bytes()); // partLength 6
        buf[7..9].copy_from_slice(&0u16.to_be_bytes()); // payload at +9, past the 6-byte part
        let err = parse_part_at(&p, 0, &buf, 32).unwrap_err();
        assert!(matches!(err, PartRejection::PayloadOutsidePart { .. }));
    }

    #[test]
    fn an_unknown_stream_id_is_not_interpreted() {
        let p = hikvision_profile();
        let mut buf = vec![0u8; 32];
        buf[..4].copy_from_slice(&[0x00, 0x00, 0x01, 0x7F]); // not a recognised id
        buf[4..6].copy_from_slice(&26u16.to_be_bytes());
        let err = parse_part_at(&p, 0, &buf, 32).unwrap_err();
        assert!(matches!(
            err,
            PartRejection::UnknownStreamId { stream_id: 0x7F }
        ));
    }

    #[test]
    fn bytes_with_no_start_code_are_rejected_rather_than_interpreted() {
        let p = hikvision_profile();
        let buf = vec![0xDEu8; 64];
        let err = parse_part_at(&p, 0x500, &buf, 64).unwrap_err();
        assert!(matches!(err, PartRejection::NoStartCode { .. }));
        assert!(err.reason(0x500).contains("neither an MPEG-PS start code"));
    }

    #[test]
    fn an_ofni_part_is_recognised_and_its_length_read_little_endian() {
        let p = hikvision_profile();
        let body = b"CAM01 metadata".to_vec();
        let buf = ofni(&body);
        let part = parse_part_at(&p, 0x200, &buf, buf.len() as u64).unwrap();
        assert_eq!(
            part.kind,
            PartKind::Ofni {
                declared_length: body.len() as i32
            }
        );
        assert_eq!(part.tag, None, "OFNI is not an MPEG start code");
        assert_eq!(part.length, body.len() as u64 + 8);
        let b = part.payload.unwrap();
        assert_eq!(b.offset, 0x200 + 8);
        assert_eq!(b.length, body.len() as u64);
    }

    #[test]
    fn an_ofni_part_with_an_absurd_length_is_rejected() {
        let p = hikvision_profile();
        let mut buf = vec![0u8; 32];
        buf[..4].copy_from_slice(b"OFNI");
        buf[4..8].copy_from_slice(&i32::MAX.to_le_bytes());
        let err = parse_part_at(&p, 0, &buf, 1 << 30).unwrap_err();
        assert!(matches!(err, PartRejection::ImplausibleLength { .. }));
    }

    #[test]
    fn a_negative_ofni_length_is_rejected() {
        let p = hikvision_profile();
        let mut buf = vec![0u8; 32];
        buf[..4].copy_from_slice(b"OFNI");
        buf[4..8].copy_from_slice(&(-8i32).to_le_bytes());
        assert!(parse_part_at(&p, 0, &buf, 1024).is_err());
    }

    #[test]
    fn a_truncated_header_is_reported_truncated() {
        let p = hikvision_profile();
        let err = parse_part_at(&p, 0, &[0x00, 0x00], 2).unwrap_err();
        assert!(matches!(err, PartRejection::Truncated { .. }));
    }

    // ── Clip walk ───────────────────────────────────────────────────────────────

    #[test]
    fn a_clip_of_pack_and_video_parts_walks_end_to_end() {
        let p = hikvision_profile();
        let es = h264_es();
        let (r, region) = reader_of(vec![
            pack(1),
            pes(0xBB, &[0x11; 8], 14),
            pes(0xE0, &es, 14),
            pack(2),
            pes(0xE0, &es, 14),
        ]);
        let s = walk_clip(&r, &p, region).unwrap();

        assert_eq!(s.parts.len(), 5);
        assert_eq!(s.pack_serials, vec![1, 2]);
        assert_eq!(s.video_parts().count(), 2);
        assert_eq!(s.payload_regions.len(), 2);
        assert_eq!(s.payload_bytes(), 2 * es.len() as u64);
        assert!(s.reached_end);
        assert!(s.rejections.is_empty(), "{:?}", s.rejections);
        assert_eq!(
            s.bytes_walked, region.length,
            "the walk must account for every byte"
        );
        assert!((s.coverage() - 1.0).abs() < 1e-9);
        assert_eq!(s.evidence.state, ValidationStateKind::Pass);
    }

    #[test]
    fn payload_regions_are_absolute_offsets_not_clip_relative() {
        let p = hikvision_profile();
        let es = h264_es();
        let mut data = vec![0xFFu8; 0x1000];
        let clip_start = 0x1000u64;
        data.extend_from_slice(&pack(7));
        data.extend_from_slice(&pes(0xE0, &es, 14));
        let clip_len = data.len() as u64 - clip_start;
        let r = MemReader::new(data);
        let s = walk_clip(&r, &p, Region::new(clip_start, clip_len).unwrap()).unwrap();
        let pl = s.payload_regions[0];
        assert_eq!(
            pl.offset,
            clip_start + 20 + 14,
            "payload offsets must be absolute in the evidence"
        );
    }

    #[test]
    fn ofni_parts_inside_a_clip_are_preserved_as_metadata() {
        let p = hikvision_profile();
        let (r, region) = reader_of(vec![
            pack(1),
            ofni(b"DS-7208 ch1"),
            pes(0xE0, &h264_es(), 14),
        ]);
        let s = walk_clip(&r, &p, region).unwrap();
        assert_eq!(s.ofni_parts.len(), 1);
        let o = &s.ofni_parts[0];
        assert_eq!(o.offset, 20);
        assert_eq!(o.declared_length, 11);
        assert!(o.body_preview.contains("DS-7208"), "{}", o.body_preview);
        let m = s.oem_metadata();
        assert_eq!(
            m.get("hikvision_ofni_part_count").map(String::as_str),
            Some("1")
        );
        assert!(m.contains_key("hikvision_ofni_0_body_preview"));
    }

    #[test]
    fn the_walk_resynchronises_past_damage_instead_of_abandoning_the_clip() {
        let p = hikvision_profile();
        let es = h264_es();
        let mut parts = vec![pack(1)];
        parts.push(vec![0xDEu8; 200]); // garbage in the middle
        parts.push(pes(0xE0, &es, 14));
        let (r, region) = reader_of(parts);
        let s = walk_clip(&r, &p, region).unwrap();

        assert!(!s.rejections.is_empty(), "the damage must be recorded");
        assert!(!s.resyncs.is_empty(), "the resync must be recorded");
        assert_eq!(
            s.video_parts().count(),
            1,
            "the part after the damage must still be found"
        );
        assert_eq!(s.evidence.state, ValidationStateKind::Review);
    }

    #[test]
    fn a_clip_with_no_framing_yields_no_parts_and_no_codec() {
        let p = hikvision_profile();
        let r = MemReader::new(vec![0xAAu8; 8192]);
        let s = walk_clip(&r, &p, Region::new(0, 8192).unwrap()).unwrap();
        assert!(!s.has_framing());
        assert_eq!(s.codec.codec, HikCodec::Unknown);
        assert_eq!(s.evidence.state, ValidationStateKind::Unknown);
        assert_eq!(s.payload_bytes(), 0);
    }

    #[test]
    fn a_walk_never_loops_forever_on_hostile_bytes() {
        let p = hikvision_profile();
        // Repeated bare start-code prefixes with zero lengths.
        let mut data = Vec::new();
        for _ in 0..2000 {
            data.extend_from_slice(&[0x00, 0x00, 0x01, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }
        let len = data.len() as u64;
        let r = MemReader::new(data);
        let s = walk_clip(&r, &p, Region::new(0, len).unwrap()).unwrap();
        // Either rejected or advanced; the only unacceptable outcome is not returning.
        assert!(s.reached_end || !s.rejections.is_empty());
    }

    #[test]
    fn a_part_straddling_the_read_window_is_still_parsed() {
        let p = hikvision_profile();
        // Force a small window so parts must straddle it.
        let mut profile = p.clone();
        profile
            .layout
            .insert(key::READ_WINDOW_BYTES.to_string(), 4096);
        let es = h264_es();
        let mut parts = Vec::new();
        for i in 0..400u32 {
            parts.push(pack(i));
            parts.push(pes(0xE0, &es, 14));
        }
        let (r, region) = reader_of(parts);
        let s = walk_clip(&r, &profile, region).unwrap();
        assert_eq!(
            s.pack_serials.len(),
            400,
            "no part may be lost at a window edge"
        );
        assert_eq!(s.video_parts().count(), 400);
        assert!(s.reached_end);
        assert!(
            s.rejections.is_empty(),
            "{:?}",
            &s.rejections[..s.rejections.len().min(3)]
        );
    }

    // ── Codec detection ─────────────────────────────────────────────────────────

    #[test]
    fn h264_parameter_sets_identify_h264() {
        let p = hikvision_profile();
        let e = classify_codec(&p, &h264_es());
        assert_eq!(e.codec, HikCodec::H264);
        assert!(e.h264_parameter_sets);
        assert!(!e.h265_parameter_sets);
        assert!(e.confidence >= 0.7);
        assert!(e.has_parameter_sets());
        assert_eq!(e.codec.extension(), Some("h264"));
    }

    #[test]
    fn h265_parameter_sets_identify_h265() {
        let p = hikvision_profile();
        let e = classify_codec(&p, &h265_es());
        assert_eq!(e.codec, HikCodec::H265);
        assert!(e.h265_parameter_sets);
        assert!(e.confidence >= 0.7);
        assert_eq!(e.codec.extension(), Some("hevc"));
    }

    #[test]
    fn an_h264_p_slice_is_not_mistaken_for_an_h265_vps() {
        let p = hikvision_profile();
        // 0x41 has H.265 type (0x41 >> 1) & 0x3F == 32 == VPS. Only the full two-byte
        // header check keeps this from being reported as HEVC.
        let mut es = Vec::new();
        for _ in 0..6 {
            es.extend_from_slice(&[0x00, 0x00, 0x01, 0x41, 0x9A, 0x02, 0x04, 0x11, 0x22]);
        }
        let e = classify_codec(&p, &es);
        assert_ne!(
            e.codec,
            HikCodec::H265,
            "an H.264 P-slice must not be classified as H.265: {}",
            e.reason
        );
    }

    #[test]
    fn a_codec_is_never_fabricated_from_too_few_bytes() {
        let p = hikvision_profile();
        for sample in [vec![], vec![0u8; 1], vec![0u8; 4]] {
            let e = classify_codec(&p, &sample);
            assert_eq!(e.codec, HikCodec::Unknown);
            assert_eq!(e.confidence, 0.0);
            assert!(e.codec.extension().is_none());
        }
    }

    #[test]
    fn payload_without_any_start_code_yields_unknown() {
        let p = hikvision_profile();
        let e = classify_codec(&p, &vec![0xAAu8; 4096]);
        assert_eq!(e.codec, HikCodec::Unknown);
        assert!(e.reason.contains("no Annex-B start code"));
        assert_eq!(e.validation().state, ValidationStateKind::Unknown);
    }

    #[test]
    fn a_single_isolated_nal_does_not_reach_the_agreement_threshold() {
        let p = hikvision_profile();
        // One lone non-IDR slice: real, but not enough to name a codec.
        let e = classify_codec(&p, &[0x00, 0x00, 0x01, 0x41, 0x9A, 0x02, 0x04, 0x11]);
        assert_eq!(
            e.codec,
            HikCodec::Unknown,
            "one NAL must not decide a codec: {}",
            e.reason
        );
    }

    #[test]
    fn the_codec_is_classified_only_from_located_video_payload() {
        let p = hikvision_profile();
        // A clip whose *audio* part contains H.264-looking bytes, and which has no video
        // part at all. Scanning the clip would find NALs; the walk must not.
        let (r, region) = reader_of(vec![pack(1), pes(0xC0, &h264_es(), 14)]);
        let s = walk_clip(&r, &p, region).unwrap();
        assert_eq!(s.video_parts().count(), 0);
        assert!(s.payload_regions.is_empty());
        assert_eq!(
            s.codec.codec,
            HikCodec::Unknown,
            "NAL bytes outside a video payload must not establish a codec"
        );
        assert!(s.codec.reason.contains("NOT classified by scanning"));
    }

    #[test]
    fn codec_sample_regions_are_bounded() {
        let p = hikvision_profile();
        let es = vec![0u8; 4096];
        let mut parts = Vec::new();
        for _ in 0..20 {
            parts.push(pes(0xE0, &es, 14));
        }
        let (r, region) = reader_of(parts);
        let s = walk_clip(&r, &p, region).unwrap();
        let sampled: u64 = s.codec_sample_regions(8192).iter().map(|r| r.length).sum();
        assert_eq!(sampled, 8192, "sampling must respect the budget");
        assert!(
            s.payload_bytes() > 8192,
            "there was more payload than was sampled"
        );
    }

    #[test]
    fn the_metadata_map_carries_the_codec_decision_and_its_reason() {
        let p = hikvision_profile();
        let (r, region) = reader_of(vec![pack(9), pes(0xE0, &h264_es(), 14)]);
        let s = walk_clip(&r, &p, region).unwrap();
        let m = s.oem_metadata();
        assert_eq!(m.get("hikvision_codec").map(String::as_str), Some("H.264"));
        assert!(m.contains_key("hikvision_codec_evidence"));
        assert!(m.contains_key("hikvision_codec_confidence"));
        assert_eq!(
            m.get("hikvision_ps_first_pack_serial").map(String::as_str),
            Some("9")
        );
    }
}
