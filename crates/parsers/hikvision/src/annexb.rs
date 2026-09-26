//! # Annex-B normalization of a reconstructed Hikvision stream
//!
//! A reconstruction yields the ordered **PES payload** ranges of a recording. Concatenating
//! them removes the MPEG-PS framing, and Hikvision carries H.264/H.265 inside that payload in
//! Annex-B form, so the concatenation is already an Annex-B byte stream. Two things can still
//! stop it decoding, and this module checks and repairs exactly those two:
//!
//! 1. **A leading partial NAL.** A clip whose first payload range begins mid-NAL (a truncated
//!    or overwritten clip start) puts bytes in front of the first start code that no decoder
//!    can use. They are trimmed from the export and the trim is recorded.
//! 2. **Parameter sets after the first picture.** A decoder needs SPS/PPS (and a VPS for
//!    H.265) before the first slice. When the recording carries them only *later* in the
//!    stream, the physical ranges of the first instance of each are placed ahead of the
//!    payload.
//!
//! ## Nothing is synthesised
//!
//! Every byte of the normalized export is a byte of the evidence, identified by a physical
//! range. A parameter set is never generated, guessed or copied from another recording. When
//! none exists anywhere in the scanned stream, the absence is reported and the export is left
//! as it is, so a decoder failure stays attributable to missing evidence rather than to this
//! module.
//!
//! ## Bounded
//!
//! Only a prefix of the stream is scanned (the profile's normalization budget). That prefix
//! is where a decoder needs its parameter sets, and scanning it does not require holding a
//! whole recording in memory.

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, OemProfile, Region, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};

use crate::layout::{key, u64_from, u8_from, vs};
use crate::ps::HikCodec;

/// What role a NAL unit plays for a decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NalRole {
    /// H.265 video parameter set.
    Vps,
    /// Sequence parameter set.
    Sps,
    /// Picture parameter set.
    Pps,
    /// A coded slice (VCL NAL).
    Slice,
    /// Anything else (SEI, AUD, filler...).
    Other,
}

impl NalRole {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Vps => "VPS",
            Self::Sps => "SPS",
            Self::Pps => "PPS",
            Self::Slice => "slice",
            Self::Other => "other",
        }
    }

    pub fn is_parameter_set(&self) -> bool {
        matches!(self, Self::Vps | Self::Sps | Self::Pps)
    }
}

/// One NAL unit located in the scanned stream prefix.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocatedNal {
    pub role: NalRole,
    /// Raw `nal_unit_type` as decoded for the stream's codec.
    pub nal_type: u8,
    /// Offset of the start code within the concatenated payload.
    pub stream_offset: u64,
    /// Length from the start code to the next start code.
    pub stream_length: u64,
    /// The physical ranges holding this NAL. More than one when the NAL straddles two PES
    /// payload ranges.
    pub physical: Vec<Region>,
}

/// The normalized export plan for a reconstructed stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnnexBNormalization {
    pub codec: HikCodec,
    /// Bytes before the first start code, trimmed from the export.
    pub leading_bytes_trimmed: u64,
    /// Whether a start code was found at all in the scanned prefix.
    pub start_code_found: bool,
    /// Stream offset of the first slice NAL, when one was found.
    pub first_slice_offset: Option<u64>,
    /// Parameter-set roles that already precede the first slice.
    pub parameter_sets_in_place: Vec<NalRole>,
    /// Parameter sets placed ahead of the payload, with their evidence ranges.
    pub relocated_parameter_sets: Vec<LocatedNal>,
    /// Parameter-set roles the codec needs that were not found anywhere in the scan.
    pub missing_parameter_sets: Vec<NalRole>,
    /// The ordered physical ranges to concatenate for a decodable Annex-B stream.
    pub export_regions: Vec<Region>,
    /// Payload bytes actually scanned.
    pub bytes_scanned: u64,
    pub notes: Vec<String>,
    pub evidence: ValidationState,
}

impl AnnexBNormalization {
    /// Whether the export differs from the plain payload concatenation.
    pub fn changed_layout(&self) -> bool {
        self.leading_bytes_trimmed > 0 || !self.relocated_parameter_sets.is_empty()
    }

    /// One line an export record can carry.
    pub fn summary(&self) -> String {
        format!(
            "Annex-B normalization ({}): {} leading byte(s) trimmed, parameter sets in place [{}], \
             relocated [{}], missing [{}]; {} export range(s)",
            self.codec.label(),
            self.leading_bytes_trimmed,
            roles(&self.parameter_sets_in_place),
            self.relocated_parameter_sets
                .iter()
                .map(|n| format!(
                    "{}@{}",
                    n.role.label(),
                    n.physical
                        .iter()
                        .map(|r| r.to_string())
                        .collect::<Vec<_>>()
                        .join("+")
                ))
                .collect::<Vec<_>>()
                .join(", "),
            roles(&self.missing_parameter_sets),
            self.export_regions.len(),
        )
    }
}

fn roles(r: &[NalRole]) -> String {
    r.iter().map(|n| n.label()).collect::<Vec<_>>().join(",")
}

/// The parameter-set roles a decoder needs for `codec`, in the order they must appear.
fn required_roles(codec: HikCodec) -> &'static [NalRole] {
    match codec {
        HikCodec::H264 => &[NalRole::Sps, NalRole::Pps],
        HikCodec::H265 => &[NalRole::Vps, NalRole::Sps, NalRole::Pps],
        HikCodec::Unknown => &[],
    }
}

/// Decode a NAL header's role for `codec`, using the profile's NAL type table.
fn classify(profile: &OemProfile, codec: HikCodec, b0: u8, b1: Option<u8>) -> (NalRole, u8) {
    match codec {
        HikCodec::H264 => {
            let t = b0 & u8_from(profile, key::NAL_H264_TYPE_MASK, 0x1F);
            let role = if b0 & 0x80 != 0 {
                NalRole::Other
            } else if t == u8_from(profile, key::NAL_H264_TYPE_SPS, 7) {
                NalRole::Sps
            } else if t == u8_from(profile, key::NAL_H264_TYPE_PPS, 8) {
                NalRole::Pps
            } else if (1..=5).contains(&t) {
                // ITU-T H.264 Table 7-1: types 1..=5 are coded slices.
                NalRole::Slice
            } else {
                NalRole::Other
            };
            (role, t)
        }
        HikCodec::H265 => {
            let mask = u8_from(profile, key::NAL_H265_TYPE_MASK, 0x7E);
            let shift = u8_from(profile, key::NAL_H265_TYPE_SHIFT, 1);
            let t = (b0 & mask) >> shift;
            let header_ok = b0 & 0x80 == 0
                && b1.is_some_and(|b| b & 0x07 >= 1 && (((b0 & 0x01) << 5) | (b >> 3)) == 0);
            let role = if !header_ok {
                NalRole::Other
            } else if t == u8_from(profile, key::NAL_H265_TYPE_VPS, 32) {
                NalRole::Vps
            } else if t == u8_from(profile, key::NAL_H265_TYPE_SPS, 33) {
                NalRole::Sps
            } else if t == u8_from(profile, key::NAL_H265_TYPE_PPS, 34) {
                NalRole::Pps
            } else if t <= 31 {
                // ITU-T H.265 Table 7-1: types 0..=31 are VCL NAL units.
                NalRole::Slice
            } else {
                NalRole::Other
            };
            (role, t)
        }
        HikCodec::Unknown => (NalRole::Other, 0),
    }
}

/// Map a range of the concatenated stream back onto the physical ranges that hold it.
///
/// `segments` is `(stream offset, physical region)` for each payload range, in stream order.
fn map_to_physical(segments: &[(u64, Region)], start: u64, length: u64) -> Vec<Region> {
    let end = start.saturating_add(length);
    let mut out = Vec::new();
    for (seg_start, region) in segments {
        let seg_end = seg_start.saturating_add(region.length);
        if seg_end <= start || *seg_start >= end {
            continue;
        }
        let from = start.max(*seg_start);
        let to = end.min(seg_end);
        out.push(Region {
            offset: region.offset + (from - seg_start),
            length: to - from,
        });
    }
    out
}

/// Drop the first `n` bytes of an ordered range list.
fn trim_front(regions: &[Region], mut n: u64) -> Vec<Region> {
    let mut out = Vec::with_capacity(regions.len());
    for r in regions {
        if n == 0 {
            out.push(*r);
        } else if n >= r.length {
            n -= r.length;
        } else {
            out.push(Region {
                offset: r.offset + n,
                length: r.length - n,
            });
            n = 0;
        }
    }
    out
}

/// Position of the next Annex-B start code (`00 00 01`) at or after `from`, reported as the
/// offset of its first zero — or of the extra leading zero when it is a 4-byte code.
fn next_start_code(buf: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut i = from;
    while i + 3 <= buf.len() {
        if buf[i] == 0 && buf[i + 1] == 0 && buf[i + 2] == 1 {
            // (start of the code, offset of the NAL header byte)
            let code_start = if i > from && buf[i - 1] == 0 {
                i - 1
            } else {
                i
            };
            return Some((code_start, i + 3));
        }
        i += 1;
    }
    None
}

/// Plan a decodable Annex-B export for `payload_regions` of a stream in `codec`.
pub fn normalize(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    payload_regions: &[Region],
    codec: HikCodec,
) -> Result<AnnexBNormalization, ForensicError> {
    let op = "hikvision_annexb_normalize";
    let subject = "elementary_stream";

    if codec == HikCodec::Unknown || payload_regions.is_empty() {
        let why = if payload_regions.is_empty() {
            "no payload ranges were supplied, so there is no stream to normalize"
        } else {
            "the codec was not established, so NAL roles cannot be decoded and the payload is \
             exported exactly as concatenated"
        };
        return Ok(AnnexBNormalization {
            codec,
            leading_bytes_trimmed: 0,
            start_code_found: false,
            first_slice_offset: None,
            parameter_sets_in_place: Vec::new(),
            relocated_parameter_sets: Vec::new(),
            missing_parameter_sets: Vec::new(),
            export_regions: payload_regions.to_vec(),
            bytes_scanned: 0,
            notes: vec![why.to_string()],
            evidence: vs(ValidationStateKind::Unknown, why, op, subject),
        });
    }

    // ── Read a bounded prefix, remembering where each byte came from ───────────
    let budget = u64_from(profile, key::ANNEXB_NORMALIZE_SCAN_BYTES, 8 << 20).max(4096);
    let mut buf: Vec<u8> = Vec::new();
    let mut segments: Vec<(u64, Region)> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    for r in payload_regions {
        let used = buf.len() as u64;
        if used >= budget {
            break;
        }
        let take = r.length.min(budget - used);
        match reader.read_exact_at(r.offset, take as usize) {
            Ok(bytes) => {
                segments.push((
                    used,
                    Region {
                        offset: r.offset,
                        length: take,
                    },
                ));
                buf.extend_from_slice(&bytes);
            }
            Err(e) => {
                // A read failure ends the scan: skipping the range would silently splice the
                // bytes either side of it together in the analysis.
                notes.push(format!(
                    "payload range {r} could not be read ({e}); the normalization scan stopped \
                     there"
                ));
                break;
            }
        }
    }
    let bytes_scanned = buf.len() as u64;

    // ── Locate NAL units ─────────────────────────────────────────────────────
    let mut nals: Vec<LocatedNal> = Vec::new();
    let mut cursor = next_start_code(&buf, 0);
    let first_code = cursor.map(|(s, _)| s as u64);
    while let Some((code_start, header_at)) = cursor {
        if header_at >= buf.len() {
            break;
        }
        let next = next_start_code(&buf, header_at);
        let end = match next {
            Some((s, _)) => s,
            // The last NAL in the prefix may continue past the scan budget; only accept it
            // when the scan reached the true end of the stream.
            None if bytes_scanned
                == payload_regions
                    .iter()
                    .fold(0u64, |a, r| a.saturating_add(r.length)) =>
            {
                buf.len()
            }
            None => break,
        };
        let (role, nal_type) = classify(
            profile,
            codec,
            buf[header_at],
            buf.get(header_at + 1).copied(),
        );
        let stream_offset = code_start as u64;
        let stream_length = (end - code_start) as u64;
        nals.push(LocatedNal {
            role,
            nal_type,
            stream_offset,
            stream_length,
            physical: map_to_physical(&segments, stream_offset, stream_length),
        });
        cursor = next;
    }

    let Some(first_code) = first_code else {
        let why = format!(
            "no Annex-B start code was found in the first {bytes_scanned} byte(s) of {} payload; \
             the payload is exported as concatenated and is unlikely to decode",
            codec.label()
        );
        notes.push(why.clone());
        return Ok(AnnexBNormalization {
            codec,
            leading_bytes_trimmed: 0,
            start_code_found: false,
            first_slice_offset: None,
            parameter_sets_in_place: Vec::new(),
            relocated_parameter_sets: Vec::new(),
            missing_parameter_sets: required_roles(codec).to_vec(),
            export_regions: payload_regions.to_vec(),
            bytes_scanned,
            notes,
            evidence: vs(ValidationStateKind::Review, why, op, subject),
        });
    };

    if first_code > 0 {
        notes.push(format!(
            "{first_code} byte(s) precede the first start code (a partial NAL at the start of the \
             recording) and were trimmed from the export"
        ));
    }

    // ── Parameter sets relative to the first slice ─────────────────────────────
    let first_slice = nals.iter().position(|n| n.role == NalRole::Slice);
    let first_slice_offset = first_slice.map(|i| nals[i].stream_offset);
    let before: &[LocatedNal] = match first_slice {
        Some(i) => &nals[..i],
        None => &nals[..],
    };

    let mut in_place: Vec<NalRole> = Vec::new();
    let mut relocated: Vec<LocatedNal> = Vec::new();
    let mut missing: Vec<NalRole> = Vec::new();
    for role in required_roles(codec) {
        if before.iter().any(|n| n.role == *role) {
            in_place.push(*role);
        } else if let Some(later) = nals.iter().find(|n| n.role == *role) {
            relocated.push(later.clone());
        } else {
            missing.push(*role);
        }
    }

    // Relocation only makes sense when every missing-in-place role can be supplied; a partial
    // set in front of the first slice decodes no better than none and hides the gap.
    if !missing.is_empty() && !relocated.is_empty() {
        notes.push(format!(
            "parameter set(s) [{}] occur after the first slice but [{}] occur nowhere in the \
             scanned {bytes_scanned} byte(s); none were relocated, because a partial set does not \
             make the stream decodable",
            roles(&relocated.iter().map(|n| n.role).collect::<Vec<_>>()),
            roles(&missing)
        ));
        relocated.clear();
    }

    for n in &relocated {
        notes.push(format!(
            "{} (nal type {}) first occurs at stream offset {} after the first slice; its evidence \
             range(s) {} were placed ahead of the payload so a decoder can initialise",
            n.role.label(),
            n.nal_type,
            n.stream_offset,
            n.physical
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<_>>()
                .join("+")
        ));
    }
    if !missing.is_empty() {
        notes.push(format!(
            "no {} {} was found in the scanned {bytes_scanned} byte(s); nothing was synthesised, \
             so a decoder may need parameter sets supplied separately",
            codec.label(),
            roles(&missing)
        ));
    }
    if first_slice.is_none() {
        notes.push("no coded slice NAL was found in the scanned prefix".into());
    }

    // ── Export plan ──────────────────────────────────────────────────────────
    let mut export_regions: Vec<Region> = Vec::new();
    for n in &relocated {
        export_regions.extend(n.physical.iter().copied());
    }
    export_regions.extend(trim_front(payload_regions, first_code));

    let kind = if missing.is_empty() && first_slice.is_some() {
        ValidationStateKind::Pass
    } else {
        ValidationStateKind::Review
    };
    let reason = format!(
        "{} stream: {} NAL(s) located in {bytes_scanned} scanned byte(s); parameter sets in place \
         [{}], relocated [{}], missing [{}]; {first_code} leading byte(s) trimmed",
        codec.label(),
        nals.len(),
        roles(&in_place),
        roles(&relocated.iter().map(|n| n.role).collect::<Vec<_>>()),
        roles(&missing),
    );

    Ok(AnnexBNormalization {
        codec,
        leading_bytes_trimmed: first_code,
        start_code_found: true,
        first_slice_offset,
        parameter_sets_in_place: in_place,
        relocated_parameter_sets: relocated,
        missing_parameter_sets: missing,
        export_regions,
        bytes_scanned,
        notes,
        evidence: vs(kind, reason, op, subject),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::tests_support::hikvision_profile;
    use crate::testing::build::{h264_es, h265_es};
    use crate::testing::MemReader;

    fn whole(data: &[u8]) -> Vec<Region> {
        vec![Region::new(0, data.len() as u64).unwrap()]
    }

    fn concat(reader: &MemReader, regions: &[Region]) -> Vec<u8> {
        let mut out = Vec::new();
        for r in regions {
            out.extend(reader.read_exact_at(r.offset, r.length as usize).unwrap());
        }
        out
    }

    #[test]
    fn a_stream_that_already_leads_with_parameter_sets_is_left_unchanged() {
        let p = hikvision_profile();
        let es = h264_es();
        let r = MemReader::new(es.clone());
        let n = normalize(&r, &p, &whole(&es), HikCodec::H264).unwrap();
        assert!(!n.changed_layout());
        assert_eq!(n.parameter_sets_in_place, vec![NalRole::Sps, NalRole::Pps]);
        assert!(n.missing_parameter_sets.is_empty());
        assert_eq!(concat(&r, &n.export_regions), es);
        assert_eq!(n.evidence.state, ValidationStateKind::Pass);
    }

    #[test]
    fn leading_partial_nal_bytes_are_trimmed_not_exported() {
        let p = hikvision_profile();
        let mut data = vec![0xAB, 0xCD, 0xEF];
        data.extend(h264_es());
        let r = MemReader::new(data.clone());
        let n = normalize(&r, &p, &whole(&data), HikCodec::H264).unwrap();
        assert_eq!(n.leading_bytes_trimmed, 3);
        assert_eq!(concat(&r, &n.export_regions), h264_es());
    }

    #[test]
    fn late_parameter_sets_are_relocated_from_their_own_evidence_ranges() {
        let p = hikvision_profile();
        // A slice first, then SPS/PPS: the recording started mid-GOP.
        let slice = [0x00, 0x00, 0x01, 0x41, 0x9A, 0x02, 0x04, 0x11];
        let mut data = slice.to_vec();
        data.extend(h264_es());
        let r = MemReader::new(data.clone());
        let n = normalize(&r, &p, &whole(&data), HikCodec::H264).unwrap();
        assert_eq!(n.relocated_parameter_sets.len(), 2);
        assert_eq!(n.relocated_parameter_sets[0].role, NalRole::Sps);
        // Every exported byte is an evidence byte; the stream now opens with the SPS.
        let out = concat(&r, &n.export_regions);
        assert_eq!(&out[..5], &[0x00, 0x00, 0x00, 0x01, 0x67]);
        assert_eq!(
            out.len(),
            data.len() + 10 + 8,
            "SPS and PPS ranges were prepended"
        );
    }

    #[test]
    fn a_nal_straddling_two_payload_ranges_maps_to_both() {
        let p = hikvision_profile();
        let es = h265_es();
        // Split the stream in the middle of the VPS, with a gap of framing between the halves.
        let mut data = es[..6].to_vec();
        data.extend([0xEE; 16]);
        data.extend(&es[6..]);
        let regions = vec![
            Region::new(0, 6).unwrap(),
            Region::new(22, (es.len() - 6) as u64).unwrap(),
        ];
        let r = MemReader::new(data);
        let n = normalize(&r, &p, &regions, HikCodec::H265).unwrap();
        assert_eq!(
            n.parameter_sets_in_place,
            vec![NalRole::Vps, NalRole::Sps, NalRole::Pps]
        );
        assert_eq!(concat(&r, &n.export_regions), es);
    }

    #[test]
    fn missing_parameter_sets_are_reported_and_never_synthesised() {
        let p = hikvision_profile();
        let data = vec![
            0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x00, 0x00, 0x01, 0x41, 0x9A,
        ];
        let r = MemReader::new(data.clone());
        let n = normalize(&r, &p, &whole(&data), HikCodec::H264).unwrap();
        assert_eq!(n.missing_parameter_sets, vec![NalRole::Sps, NalRole::Pps]);
        assert!(n.relocated_parameter_sets.is_empty());
        assert_eq!(concat(&r, &n.export_regions), data);
        assert_eq!(n.evidence.state, ValidationStateKind::Review);
    }

    #[test]
    fn an_unknown_codec_is_passed_through_untouched() {
        let p = hikvision_profile();
        let data = vec![0x11u8; 64];
        let r = MemReader::new(data.clone());
        let n = normalize(&r, &p, &whole(&data), HikCodec::Unknown).unwrap();
        assert_eq!(n.export_regions, whole(&data));
        assert_eq!(n.evidence.state, ValidationStateKind::Unknown);
    }
}
