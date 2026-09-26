//! # The authoritative Dahua DHAV frame parser
//!
//! This is the **only** DHAV reader in the platform. There used to be two divergent ones —
//! a 64-byte-header scanner in the parser and a tag-plus-length probe in the filesystem
//! reader — which disagreed about where the payload started and what the timestamp meant.
//! Both are gone; everything that needs a DHAV frame comes through here.
//!
//! ## Frame layout
//!
//! ```text
//!   +0   "DHAV"                        44 48 41 56
//!   +4   u8    frame type              0xFD key, 0xFC delta, 0xF0 audio, 0xF1 info
//!   +5   u8    subtype
//!   +6         channel field, 0-based  (width from the profile)
//!   +8   u32   frame number
//!   +12  i32   total length            DHAV .. trailer inclusive
//!   +16  u32   packed timestamp        base year 2000
//!   +20  u16   sub-second counter
//!   +22  u8    extra header length
//!   +23  u8    checksum
//!   +24        extra header            `extra header length` bytes of TLV
//!   ...        elementary stream payload
//!   end-8      "dhav" + u32(total length - 8)
//! ```
//!
//! Payload therefore begins at `24 + extraHeaderLength`, and the payload length is
//! `total_length - payload_start - 8`.
//!
//! ## What this parser refuses to do
//!
//! * **No substituted lengths.** A declared length outside the structural bounds makes the
//!   frame a rejection with a recorded reason. It is never replaced with a sector, a
//!   fixed default, or the distance to the next tag — any of which would export the wrong
//!   bytes under a valid-looking provenance record.
//! * **No silent acceptance.** A frame whose trailer does not verify is returned with a
//!   `Review` state that names the mismatch, so it can be recovered *and* be known to be
//!   damaged.
//! * **No semantic scan cap.** [`carve_region`] streams a region in profile-configured
//!   windows with overlap. The window is a memory bound, not a limit on frame size: a frame
//!   larger than the window is described in full from its header and trailer, and scanning
//!   resumes at its end.

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, OemProfile, Region, ValidationState, ValidationStateKind};
use parsers_core::storage::ContainerRecord;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::channel::DahuaChannel;
use crate::layout::{
    i32_at, key, magic, u16_at, u32_at, u32_from, u64_from, u8_at, u8_from, usize_from, vs,
};
use crate::timestamp::{DahuaTimestamp, TimestampStructure};

/// What kind of frame the type byte describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DhavFrameKind {
    /// Video key frame.
    VideoKeyFrame,
    /// Video inter-coded frame.
    VideoDeltaFrame,
    /// Audio frame.
    Audio,
    /// Informational frame; carries no elementary-stream payload.
    Info,
    /// A type byte this platform has no evidence for. Retained verbatim.
    Other(u8),
}

impl DhavFrameKind {
    fn from_byte(b: u8, profile: &OemProfile) -> Self {
        if b == u8_from(profile, key::DHAV_TYPE_VIDEO_KEY, 0xFD) {
            Self::VideoKeyFrame
        } else if b == u8_from(profile, key::DHAV_TYPE_VIDEO_DELTA, 0xFC) {
            Self::VideoDeltaFrame
        } else if b == u8_from(profile, key::DHAV_TYPE_AUDIO, 0xF0) {
            Self::Audio
        } else if b == u8_from(profile, key::DHAV_TYPE_INFO, 0xF1) {
            Self::Info
        } else {
            Self::Other(b)
        }
    }

    /// Stable label for provenance and reports.
    pub fn label(&self) -> String {
        match self {
            Self::VideoKeyFrame => "video-key-frame".into(),
            Self::VideoDeltaFrame => "video-delta-frame".into(),
            Self::Audio => "audio-frame".into(),
            Self::Info => "info-frame".into(),
            Self::Other(b) => format!("unrecognised-type-0x{b:02X}"),
        }
    }

    /// Whether the frame carries video elementary-stream bytes.
    pub fn is_video(&self) -> bool {
        matches!(self, Self::VideoKeyFrame | Self::VideoDeltaFrame)
    }
}

/// One parsed DHAV frame, with absolute physical offsets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DhavFrame {
    /// Absolute offset of the `DHAV` tag.
    pub physical_offset: u64,
    /// Declared total length, `DHAV` through trailer inclusive.
    pub total_length: u64,
    /// The whole frame's physical region.
    pub region: Region,
    /// Absolute offset where the elementary stream begins.
    pub payload_offset: u64,
    /// Payload length in bytes. Zero for frames that carry none.
    pub payload_length: u64,
    /// The payload's physical region, when non-empty.
    pub payload_region: Option<Region>,
    pub frame_type: u8,
    pub kind: DhavFrameKind,
    pub subtype: u8,
    /// The channel field as read, before normalization.
    pub raw_channel: u32,
    /// Normalized channel with its encoding evidence.
    pub channel: DahuaChannel,
    pub frame_number: u32,
    /// Decoded wall-clock timestamp, or an explicit non-value.
    pub timestamp: DahuaTimestamp,
    /// Intra-second counter from `+20`. Not a wall-clock value on its own.
    pub sub_timestamp: u16,
    pub extra_header_length: u8,
    pub checksum: u8,
    /// Whether the `dhav` trailer tag was found at the declared position.
    pub trailer_tag_verified: bool,
    /// The trailer's back-reference length, when readable.
    pub declared_trailing_length: Option<u32>,
    /// Whether that back-reference agreed with the header's declared length.
    pub trailer_length_agrees: bool,
    /// Resolution from the extra header, when it carries one.
    pub width: Option<u32>,
    pub height: Option<u32>,
    /// Codec label from the extra header, when it carries one.
    pub codec: Option<String>,
    /// Frame rate from the extra header, when it carries one.
    pub frame_rate: Option<u32>,
    /// Extra-header tags seen, including ones this platform does not interpret.
    pub extra_header_tags: Vec<String>,
    pub evidence: ValidationState,
}

impl DhavFrame {
    /// Whether every structural check passed.
    pub fn is_fully_verified(&self) -> bool {
        self.evidence.state == ValidationStateKind::Pass
    }

    /// Normalize into the OEM-neutral [`ContainerRecord`] the recovery engine consumes.
    ///
    /// Everything the engine needs travels in the record; everything OEM-specific travels in
    /// `oem_metadata` as verbatim strings, so the engine never has to interpret DHAV.
    pub fn to_container_record(&self) -> ContainerRecord {
        let mut meta: BTreeMap<String, String> = BTreeMap::new();
        meta.insert(
            "dhav_frame_type".into(),
            format!("0x{:02X}", self.frame_type),
        );
        meta.insert("dhav_frame_kind".into(), self.kind.label());
        meta.insert("dhav_subtype".into(), format!("0x{:02X}", self.subtype));
        meta.insert(
            "dhav_declared_total_length".into(),
            self.total_length.to_string(),
        );
        meta.insert(
            "dhav_extra_header_length".into(),
            self.extra_header_length.to_string(),
        );
        meta.insert("dhav_frame_number".into(), self.frame_number.to_string());
        meta.insert("dhav_sub_timestamp".into(), self.sub_timestamp.to_string());
        meta.insert("dhav_checksum".into(), format!("0x{:02X}", self.checksum));
        meta.insert(
            "dhav_raw_channel_field".into(),
            format!("0x{:04X}", self.raw_channel),
        );
        meta.insert(
            "dahua_channel_encoding".into(),
            self.channel.encoding.label().into(),
        );
        meta.insert(
            "dahua_channel_evidence".into(),
            self.channel.evidence.clone(),
        );
        meta.insert(
            "dahua_timestamp_raw".into(),
            format!("0x{:08X}", self.timestamp.raw),
        );
        meta.insert(
            "dahua_timestamp_evidence".into(),
            self.timestamp.evidence.clone(),
        );
        if let Some(wall) = &self.timestamp.recorder_wall_clock {
            meta.insert("dahua_recorder_wall_clock".into(), wall.clone());
        }
        meta.insert(
            "dhav_trailer_tag_verified".into(),
            self.trailer_tag_verified.to_string(),
        );
        meta.insert(
            "dhav_trailer_length_agrees".into(),
            self.trailer_length_agrees.to_string(),
        );
        if let (Some(w), Some(h)) = (self.width, self.height) {
            meta.insert("dhav_resolution".into(), format!("{w}x{h}"));
        }
        if let Some(fps) = self.frame_rate {
            meta.insert("dhav_declared_frame_rate".into(), fps.to_string());
        }
        if !self.extra_header_tags.is_empty() {
            meta.insert(
                "dhav_extra_header_tags".into(),
                self.extra_header_tags.join(","),
            );
        }

        ContainerRecord {
            physical_region: self.region,
            payload_region: self.payload_region,
            channel: Some(self.channel.normalized),
            // Only a decoded timestamp is offered. An absent or implausible packed field
            // stays absent rather than becoming the epoch.
            start_time_unix: self.timestamp.unix_seconds,
            frame_type: Some(self.kind.label()),
            codec_hint: self.codec.clone(),
            oem_metadata: meta,
            evidence: self.evidence.clone(),
        }
    }
}

/// Why a candidate at a given offset was not a frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhavRejection {
    /// Absolute offset the `DHAV` tag was found at.
    pub offset: u64,
    pub reason: String,
}

/// The result of carving a physical range.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CarveResult {
    /// Frames found, in ascending physical offset order.
    pub frames: Vec<DhavFrame>,
    /// Tag matches that did not validate as frames, with reasons.
    pub rejections: Vec<DhavRejection>,
    /// Whether the frame cap for the region was reached, so more may exist.
    pub truncated: bool,
    /// Bytes actually read.
    pub bytes_read: u64,
    pub evidence: ValidationState,
}

impl CarveResult {
    /// Frames carrying video elementary-stream bytes.
    pub fn video_frames(&self) -> impl Iterator<Item = &DhavFrame> {
        self.frames.iter().filter(|f| f.kind.is_video())
    }
}

/// Parse the DHAV frame whose tag begins at `offset`.
///
/// `bound_end` is the exclusive upper bound the frame must fit inside — normally the end of
/// the evidence, or the end of the block/region being examined. A frame that would extend
/// past it is a rejection, not a truncated frame.
///
/// Returns `Ok(Err(reason))` for "there is no valid frame here", which is a normal negative
/// answer during carving, and `Ok(Ok(frame))` for a frame. I/O failures propagate.
#[allow(clippy::result_large_err)]
pub fn parse_frame_at(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    offset: u64,
    bound_end: u64,
) -> Result<Result<DhavFrame, DhavRejection>, ForensicError> {
    let reject = |reason: String| Ok(Err(DhavRejection { offset, reason }));

    let header_tag = match magic(profile, "dhav_tag") {
        Some(t) => t,
        None => {
            return reject(
                "the profile declares no DHAV frame tag, so frames cannot be verified".to_string(),
            )
        }
    };
    let fixed = u64_from(profile, key::DHAV_FIXED_HEADER_SIZE, 24);
    let f_type = usize_from(profile, key::DHAV_FRAME_TYPE_OFFSET, 4);
    let f_subtype = usize_from(profile, key::DHAV_SUBTYPE_OFFSET, 5);
    let f_channel = usize_from(profile, key::DHAV_CHANNEL_OFFSET, 6);
    let channel_width = u64_from(profile, key::DHAV_CHANNEL_FIELD_SIZE, 2).clamp(1, 4) as usize;
    let f_frame_no = usize_from(profile, key::DHAV_FRAME_NUMBER_OFFSET, 8);
    let f_total = usize_from(profile, key::DHAV_TOTAL_LENGTH_OFFSET, 12);
    let f_ts = usize_from(profile, key::DHAV_PACKED_TIMESTAMP_OFFSET, 16);
    let f_sub_ts = usize_from(profile, key::DHAV_SUB_TIMESTAMP_OFFSET, 20);
    let f_ext_len = usize_from(profile, key::DHAV_EXTRA_HEADER_LENGTH_OFFSET, 22);
    let f_checksum = usize_from(profile, key::DHAV_CHECKSUM_OFFSET, 23);
    let trailer_size = u64_from(profile, key::DHAV_TRAILER_SIZE, 8);
    let min_total = u64_from(profile, key::DHAV_MIN_TOTAL_LENGTH, 32);
    let max_total = u64_from(profile, key::DHAV_MAX_TOTAL_LENGTH, 64 * 1024 * 1024);

    if offset >= bound_end || bound_end - offset < fixed {
        return reject(format!(
            "only {} byte(s) remain before the 0x{bound_end:X} bound, fewer than the {fixed}-byte \
             fixed header",
            bound_end.saturating_sub(offset)
        ));
    }

    let head = match reader.read_exact_at(offset, fixed as usize) {
        Ok(b) => b,
        Err(e) => return reject(format!("fixed header could not be read: {e}")),
    };
    if !head.starts_with(&header_tag) {
        return reject("no DHAV tag at this offset".to_string());
    }

    let frame_type = u8_at(&head, f_type).unwrap_or(0);
    let subtype = u8_at(&head, f_subtype).unwrap_or(0);
    let raw_channel = read_channel_field(&head, f_channel, channel_width);
    let frame_number = u32_at(&head, f_frame_no).unwrap_or(0);
    let raw_total = i32_at(&head, f_total).unwrap_or(0);
    let packed_ts = u32_at(&head, f_ts).unwrap_or(0);
    let sub_timestamp = u16_at(&head, f_sub_ts).unwrap_or(0);
    let extra_header_length = u8_at(&head, f_ext_len).unwrap_or(0);
    let checksum = u8_at(&head, f_checksum).unwrap_or(0);

    // ── Declared-length validation. No substitution, ever. ──────────────────
    if raw_total <= 0 {
        return reject(format!(
            "declared total length is {raw_total}; a frame cannot be empty or negative and the \
             length is not substituted"
        ));
    }
    let total_length = raw_total as u64;
    if total_length < min_total {
        return reject(format!(
            "declared total length {total_length} is below the {min_total}-byte structural minimum \
             (a {fixed}-byte header plus a {trailer_size}-byte trailer)"
        ));
    }
    if total_length > max_total {
        return reject(format!(
            "declared total length {total_length} exceeds the {max_total}-byte structural bound"
        ));
    }
    let frame_end = match offset.checked_add(total_length) {
        Some(v) => v,
        None => return reject("frame offset plus declared length overflows u64".to_string()),
    };
    if frame_end > bound_end {
        return reject(format!(
            "declared total length {total_length} would end at 0x{frame_end:X}, past the \
             0x{bound_end:X} bound; the frame is not truncated to fit"
        ));
    }

    // ── Payload boundaries ──────────────────────────────────────────────────
    let payload_start_rel = fixed.saturating_add(extra_header_length as u64);
    let framing = payload_start_rel.saturating_add(trailer_size);
    if framing > total_length {
        return reject(format!(
            "a {fixed}-byte header plus a {extra_header_length}-byte extra header plus a \
             {trailer_size}-byte trailer is {framing} byte(s), more than the declared total length \
             {total_length}"
        ));
    }
    let payload_offset = offset.saturating_add(payload_start_rel);
    let payload_length = total_length - framing;

    let mut problems: Vec<String> = Vec::new();
    let kind = DhavFrameKind::from_byte(frame_type, profile);

    // An info frame legitimately carries no payload. Any other kind with a zero-length
    // payload is a structural oddity worth surfacing.
    if payload_length == 0 && kind != DhavFrameKind::Info {
        problems.push(format!(
            "a {} frame declares a zero-length payload",
            kind.label()
        ));
    }
    if let DhavFrameKind::Other(b) = kind {
        problems.push(format!(
            "frame type 0x{b:02X} is not one this platform has evidence for; the frame is described \
             but its payload is not treated as video"
        ));
    }

    // ── Extra header ────────────────────────────────────────────────────────
    let mut ext = ExtraHeader::default();
    if extra_header_length > 0 {
        match reader.read_exact_at(offset.saturating_add(fixed), extra_header_length as usize) {
            Ok(bytes) => ext = parse_extra_header(&bytes, profile),
            Err(e) => problems.push(format!(
                "the {extra_header_length}-byte extra header could not be read: {e}"
            )),
        }
        problems.extend(ext.problems.iter().cloned());
    }

    // ── Trailer ─────────────────────────────────────────────────────────────
    let footer_tag = magic(profile, "dhav_footer_tag");
    let trailer_at = frame_end.saturating_sub(trailer_size);
    let mut trailer_tag_verified = false;
    let mut declared_trailing_length = None;
    let mut trailer_length_agrees = false;
    match reader.read_exact_at(trailer_at, trailer_size as usize) {
        Ok(bytes) => {
            match footer_tag.as_ref() {
                Some(tag) if bytes.starts_with(tag) => trailer_tag_verified = true,
                Some(tag) => problems.push(format!(
                    "the trailer at 0x{trailer_at:X} does not start with the declared {} tag",
                    String::from_utf8_lossy(tag)
                )),
                None => problems.push(
                    "the profile declares no DHAV trailer tag, so the frame's end could not be \
                     corroborated"
                        .to_string(),
                ),
            }
            // The trailer's back-reference is an independent statement of the frame's length.
            if let Some(back) = u32_at(&bytes, 4) {
                declared_trailing_length = Some(back);
                let expected = total_length.saturating_sub(trailer_size);
                if back as u64 == expected {
                    trailer_length_agrees = true;
                } else {
                    problems.push(format!(
                        "the trailer's back-reference length {back} disagrees with the header's \
                         declared length ({total_length} - {trailer_size} = {expected})"
                    ));
                }
            }
        }
        Err(e) => problems.push(format!(
            "the trailer at 0x{trailer_at:X} could not be read: {e}"
        )),
    }

    let timestamp = DahuaTimestamp::decode(packed_ts, TimestampStructure::DhavFrameHeader, profile);
    let channel = DahuaChannel::from_dhav_field(raw_channel);
    if !timestamp.is_decoded() {
        problems.push(format!(
            "the packed timestamp field did not decode to an instant: {}",
            timestamp.evidence
        ));
    }

    let region = match Region::new(offset, total_length) {
        Ok(r) => r,
        Err(e) => return reject(format!("frame region could not be formed: {e}")),
    };
    let payload_region = if payload_length > 0 {
        Region::new(payload_offset, payload_length).ok()
    } else {
        None
    };

    let mut reason = format!(
        "DHAV {} at 0x{offset:X}: declared total length {total_length}, extra header \
         {extra_header_length} byte(s), payload [0x{payload_offset:X}..0x{:X}) ({payload_length} \
         byte(s)), channel {} ({}), frame number {frame_number}, trailer {}",
        kind.label(),
        payload_offset.saturating_add(payload_length),
        channel.normalized,
        channel.encoding.label(),
        if trailer_tag_verified && trailer_length_agrees {
            "verified"
        } else if trailer_tag_verified {
            "tag verified, length disagrees"
        } else {
            "not verified"
        }
    );
    if let Some(wall) = &timestamp.recorder_wall_clock {
        reason.push_str(&format!("; recorder clock {wall}"));
    }
    if let (Some(w), Some(h)) = (ext.width, ext.height) {
        reason.push_str(&format!("; {w}x{h}"));
    }
    if let Some(codec) = &ext.codec {
        reason.push_str(&format!("; codec {codec}"));
    }
    if !problems.is_empty() {
        reason.push_str("; ");
        reason.push_str(&problems.join("; "));
    }

    // Fully verified means: header validated, trailer tag found, back-reference agreed, no
    // problems recorded. Anything less is Review — recoverable, and known to be imperfect.
    let verified = problems.is_empty() && trailer_tag_verified && trailer_length_agrees;

    Ok(Ok(DhavFrame {
        physical_offset: offset,
        total_length,
        region,
        payload_offset,
        payload_length,
        payload_region,
        frame_type,
        kind,
        subtype,
        raw_channel,
        channel,
        frame_number,
        timestamp,
        sub_timestamp,
        extra_header_length,
        checksum,
        trailer_tag_verified,
        declared_trailing_length,
        trailer_length_agrees,
        width: ext.width,
        height: ext.height,
        codec: ext.codec,
        frame_rate: ext.frame_rate,
        extra_header_tags: ext.tags,
        evidence: vs(
            if verified {
                ValidationStateKind::Pass
            } else {
                ValidationStateKind::Review
            },
            reason,
            "dhav_frame",
            &format!("frame@0x{offset:X}"),
        ),
    }))
}

/// Read the channel field at the profile-declared width.
fn read_channel_field(head: &[u8], offset: usize, width: usize) -> u32 {
    match width {
        1 => u8_at(head, offset).map(u32::from).unwrap_or(0),
        2 => u16_at(head, offset).map(u32::from).unwrap_or(0),
        _ => u32_at(head, offset).unwrap_or(0),
    }
}

/// Values recovered from a frame's extra header.
#[derive(Debug, Default, Clone)]
struct ExtraHeader {
    width: Option<u32>,
    height: Option<u32>,
    codec: Option<String>,
    frame_rate: Option<u32>,
    tags: Vec<String>,
    problems: Vec<String>,
}

/// Walk the extra header's tag/length/value records.
///
/// The record sizes are part of the format. A tag this platform does not know consumes the
/// remainder, which is the documented behaviour and stops the walk from desynchronising and
/// reporting nonsense resolutions.
fn parse_extra_header(bytes: &[u8], profile: &OemProfile) -> ExtraHeader {
    let mut out = ExtraHeader::default();
    let short = u64_from(profile, key::DHAV_EXT_RECORD_SIZE_SHORT, 4) as usize;
    let long = u64_from(profile, key::DHAV_EXT_RECORD_SIZE_LONG, 8) as usize;
    let t_res_scaled = u8_from(profile, key::DHAV_EXT_TAG_RESOLUTION_SCALED, 0x80);
    let t_codec = u8_from(profile, key::DHAV_EXT_TAG_CODEC, 0x81);
    let t_res_exact = u8_from(profile, key::DHAV_EXT_TAG_RESOLUTION_EXACT, 0x82);
    let t_audio = u8_from(profile, key::DHAV_EXT_TAG_AUDIO, 0x83);

    // Tags whose records are a fixed size but whose contents this platform does not read.
    const LONG_OPAQUE: [u8; 9] = [0x88, 0x8C, 0x91, 0x92, 0x93, 0x95, 0x9A, 0x9B, 0xB3];
    const SHORT_OPAQUE: [u8; 8] = [0x84, 0x85, 0x8B, 0x94, 0x96, 0xA0, 0xB2, 0xB4];

    let mut i = 0usize;
    while i < bytes.len() {
        let tag = bytes[i];
        out.tags.push(format!("0x{tag:02X}"));

        let record = if tag == t_res_scaled || tag == t_codec || SHORT_OPAQUE.contains(&tag) {
            short
        } else if tag == t_res_exact || tag == t_audio || LONG_OPAQUE.contains(&tag) {
            long
        } else {
            out.problems.push(format!(
                "extra header tag 0x{tag:02X} at +{i} is not one this platform can size, so the \
                 remaining {} byte(s) of the extra header were not interpreted",
                bytes.len() - i
            ));
            break;
        };

        if i + record > bytes.len() {
            out.problems.push(format!(
                "extra header tag 0x{tag:02X} at +{i} declares a {record}-byte record but only {} \
                 byte(s) remain",
                bytes.len() - i
            ));
            break;
        }
        let rec = &bytes[i..i + record];

        if tag == t_res_scaled {
            // tag, reserved, width/8, height/8
            if let (Some(w), Some(h)) = (u8_at(rec, 2), u8_at(rec, 3)) {
                out.width = Some(w as u32 * 8);
                out.height = Some(h as u32 * 8);
            }
        } else if tag == t_codec {
            // tag, reserved, codec id, frame rate
            if let Some(id) = u8_at(rec, 2) {
                out.codec = Some(codec_label(id, profile));
            }
            if let Some(fps) = u8_at(rec, 3) {
                if fps > 0 {
                    out.frame_rate = Some(fps as u32);
                }
            }
        } else if tag == t_res_exact {
            // tag, reserved ×3, width u16, height u16
            if let (Some(w), Some(h)) = (u16_at(rec, 4), u16_at(rec, 6)) {
                out.width = Some(w as u32);
                out.height = Some(h as u32);
            }
        }

        i += record;
    }

    // A zero dimension is not a resolution. Report the absence rather than 0x0.
    if out.width == Some(0) || out.height == Some(0) {
        out.problems.push(format!(
            "the extra header declared a degenerate resolution {}x{}; it is reported as unknown",
            out.width.unwrap_or(0),
            out.height.unwrap_or(0)
        ));
        out.width = None;
        out.height = None;
    }
    out
}

/// Map an extra-header codec id to a label.
fn codec_label(id: u8, profile: &OemProfile) -> String {
    let m = |k: &str, d: u32| u32_from(profile, k, d) as u8;
    if id == m(key::DHAV_CODEC_MPEG4, 1) {
        "MPEG-4".into()
    } else if id == m(key::DHAV_CODEC_MJPEG, 3) {
        "MJPEG".into()
    } else if id == m(key::DHAV_CODEC_H264_A, 2)
        || id == m(key::DHAV_CODEC_H264_B, 4)
        || id == m(key::DHAV_CODEC_H264_C, 8)
    {
        "H.264".into()
    } else if id == m(key::DHAV_CODEC_H265, 12) {
        "H.265".into()
    } else {
        // Reported verbatim rather than guessed: the codec label is evidence, and a wrong
        // guess here would misdescribe the stream.
        format!("unrecognised-codec-id-0x{id:02X}")
    }
}

/// Carve every DHAV frame out of a physical range.
///
/// Reads in profile-configured windows with an overlap of at least one fixed header, so
/// framing that straddles a window boundary is still found. When a frame's declared length
/// exceeds the window, the frame is still described in full — its header and trailer are read
/// directly — and scanning resumes at the frame's end rather than inside it.
pub fn carve_region(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    region: Region,
) -> Result<CarveResult, ForensicError> {
    const OP: &str = "dhav_carve";
    let subject = format!("region@0x{:X}", region.offset);

    let tag = match magic(profile, "dhav_tag") {
        Some(t) => t,
        None => {
            return Ok(CarveResult {
                frames: Vec::new(),
                rejections: Vec::new(),
                truncated: false,
                bytes_read: 0,
                evidence: vs(
                    ValidationStateKind::Unknown,
                    "the profile declares no DHAV frame tag, so no carving was attempted",
                    OP,
                    &subject,
                ),
            })
        }
    };

    let disk_len = reader.len();
    let region_end = region.end().unwrap_or(u64::MAX).min(disk_len);
    let fixed = u64_from(profile, key::DHAV_FIXED_HEADER_SIZE, 24);
    let window = u64_from(profile, key::DHAV_CARVE_WINDOW_BYTES, 4 * 1024 * 1024).max(fixed * 2);
    let overlap = u64_from(profile, key::DHAV_CARVE_WINDOW_OVERLAP_BYTES, 64).max(fixed);
    let max_frames = u64_from(profile, key::DHAV_CARVE_MAX_FRAMES_PER_REGION, 4096) as usize;

    let mut frames: Vec<DhavFrame> = Vec::new();
    let mut rejections: Vec<DhavRejection> = Vec::new();
    let mut truncated = false;
    let mut bytes_read = 0u64;
    let mut cursor = region.offset;

    while cursor < region_end {
        if frames.len() >= max_frames {
            truncated = true;
            break;
        }
        let want = window.min(region_end - cursor);
        if want < tag.len() as u64 {
            break;
        }
        let mut buf = vec![0u8; want as usize];
        let n = match reader.read_at(cursor, &mut buf) {
            Ok(n) => n,
            // An unreadable window ends the carve for this region; what was already found
            // stands. Absolute offsets mean nothing found so far is invalidated.
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        bytes_read = bytes_read.saturating_add(n as u64);
        let slice = &buf[..n];

        // Where in this window we stop looking for new tags: leave the overlap for the next
        // window unless this is the final one.
        let is_final = cursor.saturating_add(n as u64) >= region_end;
        let search_end = if is_final {
            n
        } else {
            n.saturating_sub(overlap as usize)
        };

        let mut i = 0usize;
        let mut next_cursor = cursor.saturating_add(search_end.max(1) as u64);
        while i + tag.len() <= n {
            if i >= search_end && !is_final {
                break;
            }
            if &slice[i..i + tag.len()] != tag.as_slice() {
                i += 1;
                continue;
            }
            let absolute = cursor.saturating_add(i as u64);
            match parse_frame_at(reader, profile, absolute, region_end)? {
                Ok(frame) => {
                    let end = frame.region.end().unwrap_or(region_end);
                    frames.push(frame);
                    if frames.len() >= max_frames {
                        truncated = true;
                        next_cursor = end;
                        break;
                    }
                    // Resume after the frame. A frame longer than the window is therefore
                    // still skipped over correctly rather than re-scanned from inside.
                    if end > absolute {
                        if end >= cursor.saturating_add(n as u64) {
                            next_cursor = end;
                            break;
                        }
                        i = (end - cursor) as usize;
                        continue;
                    }
                    i += 1;
                }
                Err(rejection) => {
                    // "No DHAV tag here" cannot happen at a confirmed tag match, so every
                    // rejection at this point is a real structural failure worth recording.
                    rejections.push(rejection);
                    i += 1;
                }
            }
        }
        if next_cursor <= cursor {
            next_cursor = cursor.saturating_add(search_end.max(1) as u64);
        }
        cursor = next_cursor;
    }

    let verified = frames.iter().filter(|f| f.is_fully_verified()).count();
    let mut reason = format!(
        "carved {} byte(s) of {region}: {} frame(s) described ({verified} fully verified), {} tag \
         match(es) rejected",
        bytes_read,
        frames.len(),
        rejections.len()
    );
    if truncated {
        reason.push_str(&format!(
            "; the {max_frames}-frame cap for one region was reached, so more frames may be present"
        ));
    }
    if !rejections.is_empty() {
        reason.push_str("; rejections: ");
        reason.push_str(
            &rejections
                .iter()
                .take(8)
                .map(|r| format!("0x{:X}: {}", r.offset, r.reason))
                .collect::<Vec<_>>()
                .join(" | "),
        );
    }

    Ok(CarveResult {
        frames,
        rejections,
        truncated,
        bytes_read,
        evidence: vs(
            if truncated {
                ValidationStateKind::Review
            } else {
                ValidationStateKind::Pass
            },
            reason,
            OP,
            &subject,
        ),
    })
}

/// Whether a window carries DHAV framing.
///
/// This is a pure format question used by `Parser::recognize_candidate`. It requires a tag
/// **and** a structurally valid frame behind it, so four coincidental bytes in random data
/// do not read as a container.
pub fn window_carries_dhav_framing(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    probe_bytes: u64,
) -> Result<bool, ForensicError> {
    let region = Region::new(0, reader.len().min(probe_bytes))?;
    if region.is_empty() {
        return Ok(false);
    }
    let result = carve_region(reader, profile, region)?;
    Ok(!result.frames.is_empty())
}

#[cfg(test)]
pub(crate) mod builder {
    //! Byte-accurate DHAV frame builder.
    //!
    //! It writes the real framing — 24-byte fixed header, TLV extra header, payload, and the
    //! 8-byte trailer with its back-reference — so a test that passes against it is testing
    //! the documented structure rather than a convenient stand-in.

    use crate::timestamp::pack;

    /// A DHAV frame under construction.
    #[derive(Debug, Clone)]
    pub struct FrameBuilder {
        frame_type: u8,
        subtype: u8,
        channel_0_based: u16,
        frame_number: u32,
        packed_timestamp: u32,
        sub_timestamp: u16,
        checksum: u8,
        extra: Vec<u8>,
        payload: Vec<u8>,
        /// Override the declared total length, for malformed-frame tests.
        declared_total_override: Option<i32>,
        /// Corrupt the trailer tag.
        break_trailer_tag: bool,
        /// Corrupt the trailer back-reference.
        trailer_length_override: Option<u32>,
    }

    impl FrameBuilder {
        /// A video key frame on channel 1 at a fixed representable instant.
        pub fn video_key(payload: Vec<u8>) -> Self {
            Self {
                frame_type: 0xFD,
                subtype: 0x01,
                channel_0_based: 0,
                frame_number: 1,
                packed_timestamp: pack(2026, 9, 22, 12, 0, 0, 2000).expect("representable"),
                sub_timestamp: 0,
                checksum: 0,
                extra: Vec::new(),
                payload,
                declared_total_override: None,
                break_trailer_tag: false,
                trailer_length_override: None,
            }
        }

        pub fn frame_type(mut self, v: u8) -> Self {
            self.frame_type = v;
            self
        }

        pub fn channel_0_based(mut self, v: u16) -> Self {
            self.channel_0_based = v;
            self
        }

        pub fn frame_number(mut self, v: u32) -> Self {
            self.frame_number = v;
            self
        }

        pub fn at(mut self, y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> Self {
            self.packed_timestamp = pack(y, mo, d, h, mi, s, 2000).expect("representable");
            self
        }

        pub fn raw_timestamp(mut self, packed: u32) -> Self {
            self.packed_timestamp = packed;
            self
        }

        pub fn sub_timestamp(mut self, v: u16) -> Self {
            self.sub_timestamp = v;
            self
        }

        /// Append a `0x82` exact-resolution record to the extra header.
        pub fn resolution(mut self, width: u16, height: u16) -> Self {
            self.extra.extend_from_slice(&[0x82, 0, 0, 0]);
            self.extra.extend_from_slice(&width.to_le_bytes());
            self.extra.extend_from_slice(&height.to_le_bytes());
            self
        }

        /// Append a `0x80` scaled-resolution record (width/8, height/8).
        pub fn scaled_resolution(mut self, width_div8: u8, height_div8: u8) -> Self {
            self.extra
                .extend_from_slice(&[0x80, 0, width_div8, height_div8]);
            self
        }

        /// Append a `0x81` codec record.
        pub fn codec(mut self, codec_id: u8, fps: u8) -> Self {
            self.extra.extend_from_slice(&[0x81, 0, codec_id, fps]);
            self
        }

        /// Append an arbitrary raw record to the extra header.
        pub fn raw_extra(mut self, bytes: &[u8]) -> Self {
            self.extra.extend_from_slice(bytes);
            self
        }

        /// Pad the extra header to an exact length with a sized opaque record.
        pub fn pad_extra_to(mut self, target: usize) -> Self {
            // 0xB4 is a 4-byte opaque record; 0xB3 is 8 bytes. Use them to reach `target`.
            while self.extra.len() + 8 <= target {
                self.extra.extend_from_slice(&[0xB3, 0, 0, 0, 0, 0, 0, 0]);
            }
            while self.extra.len() + 4 <= target {
                self.extra.extend_from_slice(&[0xB4, 0, 0, 0]);
            }
            assert_eq!(
                self.extra.len(),
                target,
                "extra header padding must land exactly on the target"
            );
            self
        }

        pub fn declared_total_length(mut self, v: i32) -> Self {
            self.declared_total_override = Some(v);
            self
        }

        pub fn break_trailer_tag(mut self) -> Self {
            self.break_trailer_tag = true;
            self
        }

        pub fn trailer_length(mut self, v: u32) -> Self {
            self.trailer_length_override = Some(v);
            self
        }

        /// The extra header's length as it will be declared.
        pub fn extra_length(&self) -> usize {
            self.extra.len()
        }

        /// The frame's real total length.
        pub fn total_length(&self) -> usize {
            24 + self.extra.len() + self.payload.len() + 8
        }

        /// Serialize the frame.
        pub fn build(&self) -> Vec<u8> {
            let total = self.total_length();
            let mut out = Vec::with_capacity(total);
            out.extend_from_slice(b"DHAV");
            out.push(self.frame_type);
            out.push(self.subtype);
            out.extend_from_slice(&self.channel_0_based.to_le_bytes());
            out.extend_from_slice(&self.frame_number.to_le_bytes());
            let declared = self.declared_total_override.unwrap_or(total as i32);
            out.extend_from_slice(&declared.to_le_bytes());
            out.extend_from_slice(&self.packed_timestamp.to_le_bytes());
            out.extend_from_slice(&self.sub_timestamp.to_le_bytes());
            out.push(self.extra.len() as u8);
            out.push(self.checksum);
            debug_assert_eq!(out.len(), 24, "the fixed header is 24 bytes");
            out.extend_from_slice(&self.extra);
            out.extend_from_slice(&self.payload);
            if self.break_trailer_tag {
                out.extend_from_slice(b"XXXX");
            } else {
                out.extend_from_slice(b"dhav");
            }
            let back = self.trailer_length_override.unwrap_or((total - 8) as u32);
            out.extend_from_slice(&back.to_le_bytes());
            debug_assert_eq!(out.len(), total);
            out
        }
    }

    /// A small but genuine H.264 Annex-B payload: SPS, PPS, IDR, then P-slices.
    ///
    /// Real parameter sets matter: the platform's codec classifier only passes on actual
    /// SPS/PPS NAL headers, so a test using fabricated bytes could not reach a validated
    /// state.
    pub fn h264_payload(seed: u8) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1F, 0x96, 0x54, 0x0A, 0x0F,
        ]);
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x3C, 0x80]);
        v.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x01, 0x65, 0xB8, 0x00, 0x04, seed, 0x11, 0x22, 0x33,
        ]);
        for i in 0..8u8 {
            v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x41, 0x9A, seed, i]);
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::builder::{h264_payload, FrameBuilder};
    use super::*;
    use crate::layout::tests_support::dahua_profile;
    use crate::testing::MemReader;

    const AT: u64 = 0x1000;

    /// Place frames sequentially starting at `AT` inside a zero-filled image.
    fn image(frames: &[Vec<u8>], total: usize) -> (MemReader, Vec<u64>) {
        let mut b = vec![0u8; total];
        let mut offsets = Vec::new();
        let mut cursor = AT as usize;
        for f in frames {
            offsets.push(cursor as u64);
            b[cursor..cursor + f.len()].copy_from_slice(f);
            cursor += f.len();
        }
        (MemReader::new(b), offsets)
    }

    fn parse_one(frame: Vec<u8>) -> Result<DhavFrame, DhavRejection> {
        let p = dahua_profile();
        let len = frame.len();
        let (r, offsets) = image(&[frame], (AT as usize) + len + 4096);
        parse_frame_at(&r, &p, offsets[0], r.len()).unwrap()
    }

    // ── Valid frames ────────────────────────────────────────────────────────

    #[test]
    fn a_valid_frame_parses_with_exact_payload_boundaries() {
        let payload = h264_payload(0x11);
        let f = FrameBuilder::video_key(payload.clone());
        let expected_total = f.total_length() as u64;
        let frame = parse_one(f.build()).expect("valid frame");

        assert_eq!(frame.physical_offset, AT);
        assert_eq!(frame.total_length, expected_total);
        assert_eq!(frame.region, Region::new(AT, expected_total).unwrap());
        // No extra header, so the payload starts at the 24-byte fixed header.
        assert_eq!(frame.extra_header_length, 0);
        assert_eq!(frame.payload_offset, AT + 24);
        assert_eq!(frame.payload_length, payload.len() as u64);
        assert_eq!(
            frame.payload_region,
            Some(Region::new(AT + 24, payload.len() as u64).unwrap())
        );
        assert_eq!(frame.kind, DhavFrameKind::VideoKeyFrame);
        assert!(frame.is_fully_verified());
    }

    #[test]
    fn the_extra_header_shifts_the_payload_by_its_own_length() {
        let payload = h264_payload(0x22);
        let f = FrameBuilder::video_key(payload.clone())
            .resolution(1920, 1080)
            .codec(0x04, 25);
        let ext_len = f.extra_length() as u64;
        assert_eq!(ext_len, 12, "one 8-byte and one 4-byte record");
        let frame = parse_one(f.build()).expect("valid frame");

        assert_eq!(frame.extra_header_length, 12);
        assert_eq!(frame.payload_offset, AT + 24 + 12, "payload = 24 + extra");
        assert_eq!(frame.payload_length, payload.len() as u64);
        assert_eq!(frame.width, Some(1920));
        assert_eq!(frame.height, Some(1080));
        assert_eq!(frame.codec.as_deref(), Some("H.264"));
        assert_eq!(frame.frame_rate, Some(25));
        assert!(frame.is_fully_verified());
    }

    #[test]
    fn the_scaled_resolution_record_multiplies_by_eight() {
        let f = FrameBuilder::video_key(h264_payload(1)).scaled_resolution(160, 90);
        let frame = parse_one(f.build()).unwrap();
        assert_eq!(frame.width, Some(1280));
        assert_eq!(frame.height, Some(720));
    }

    #[test]
    fn a_degenerate_resolution_is_reported_as_unknown_not_zero_by_zero() {
        let f = FrameBuilder::video_key(h264_payload(1)).resolution(0, 0);
        let frame = parse_one(f.build()).unwrap();
        assert!(frame.width.is_none());
        assert!(frame.height.is_none());
        assert!(frame.evidence.reason.contains("degenerate resolution"));
        assert_eq!(frame.evidence.state, ValidationStateKind::Review);
    }

    #[test]
    fn every_documented_codec_id_maps_to_a_label_and_unknown_ids_stay_verbatim() {
        for (id, label) in [
            (0x01u8, "MPEG-4"),
            (0x02, "H.264"),
            (0x03, "MJPEG"),
            (0x04, "H.264"),
            (0x08, "H.264"),
            (0x0C, "H.265"),
        ] {
            let f = FrameBuilder::video_key(h264_payload(1)).codec(id, 25);
            let frame = parse_one(f.build()).unwrap();
            assert_eq!(frame.codec.as_deref(), Some(label), "codec id 0x{id:02X}");
        }
        let f = FrameBuilder::video_key(h264_payload(1)).codec(0x77, 25);
        let frame = parse_one(f.build()).unwrap();
        assert_eq!(
            frame.codec.as_deref(),
            Some("unrecognised-codec-id-0x77"),
            "an unknown codec id is reported, not guessed"
        );
    }

    // ── Trailer validation ──────────────────────────────────────────────────

    #[test]
    fn the_trailer_tag_and_back_reference_are_both_verified() {
        let f = FrameBuilder::video_key(h264_payload(3));
        let total = f.total_length();
        let frame = parse_one(f.build()).unwrap();
        assert!(frame.trailer_tag_verified);
        assert_eq!(frame.declared_trailing_length, Some((total - 8) as u32));
        assert!(frame.trailer_length_agrees);
        assert!(frame.evidence.reason.contains("trailer verified"));
    }

    #[test]
    fn a_broken_trailer_tag_downgrades_to_review_without_losing_the_frame() {
        let f = FrameBuilder::video_key(h264_payload(4)).break_trailer_tag();
        let frame = parse_one(f.build()).expect("the frame is still described");
        assert!(!frame.trailer_tag_verified);
        assert!(!frame.is_fully_verified());
        assert_eq!(frame.evidence.state, ValidationStateKind::Review);
        assert!(frame
            .evidence
            .reason
            .contains("does not start with the declared dhav tag"));
        // The payload is still located exactly, so the frame remains recoverable.
        assert!(frame.payload_region.is_some());
    }

    #[test]
    fn a_disagreeing_trailer_back_reference_is_reported() {
        let f = FrameBuilder::video_key(h264_payload(5)).trailer_length(999_999);
        let frame = parse_one(f.build()).unwrap();
        assert!(frame.trailer_tag_verified);
        assert!(!frame.trailer_length_agrees);
        assert_eq!(frame.declared_trailing_length, Some(999_999));
        assert!(frame
            .evidence
            .reason
            .contains("disagrees with the header's declared length"));
    }

    // ── Declared-length validation ──────────────────────────────────────────

    #[test]
    fn a_zero_or_negative_declared_length_is_rejected_never_substituted() {
        for declared in [0i32, -100] {
            let f = FrameBuilder::video_key(h264_payload(6)).declared_total_length(declared);
            let r = parse_one(f.build()).expect_err("must be rejected");
            assert!(
                r.reason.contains("not substituted"),
                "declared {declared}: {}",
                r.reason
            );
        }
    }

    #[test]
    fn a_declared_length_below_the_structural_minimum_is_rejected() {
        let f = FrameBuilder::video_key(h264_payload(7)).declared_total_length(20);
        let r = parse_one(f.build()).expect_err("must be rejected");
        assert!(
            r.reason.contains("below the 32-byte structural minimum"),
            "{}",
            r.reason
        );
    }

    #[test]
    fn a_declared_length_beyond_the_structural_bound_is_rejected() {
        let f = FrameBuilder::video_key(h264_payload(8)).declared_total_length(i32::MAX);
        let r = parse_one(f.build()).expect_err("must be rejected");
        assert!(
            r.reason
                .contains("exceeds the 67108864-byte structural bound")
                || r.reason.contains("past the"),
            "{}",
            r.reason
        );
    }

    #[test]
    fn a_frame_that_would_run_past_the_bound_is_rejected_not_truncated() {
        let p = dahua_profile();
        let payload = h264_payload(9);
        let f = FrameBuilder::video_key(payload).build();
        let len = f.len();
        // Give the image only half the frame.
        let mut b = vec![0u8; AT as usize + len / 2];
        b[AT as usize..].copy_from_slice(&f[..len / 2]);
        let r = MemReader::new(b);
        let rejection = parse_frame_at(&r, &p, AT, r.len())
            .unwrap()
            .expect_err("must be rejected");
        assert!(
            rejection.reason.contains("not truncated to fit"),
            "{}",
            rejection.reason
        );
    }

    #[test]
    fn an_extra_header_longer_than_the_frame_is_rejected() {
        // Declare a total length that cannot hold header + extra + trailer.
        let f = FrameBuilder::video_key(Vec::new())
            .pad_extra_to(64)
            .declared_total_length(40);
        let r = parse_one(f.build()).expect_err("must be rejected");
        assert!(
            r.reason.contains("more than the declared total length"),
            "{}",
            r.reason
        );
    }

    #[test]
    fn bytes_without_the_tag_are_not_a_frame() {
        let p = dahua_profile();
        let r = MemReader::new(vec![0u8; 8192]);
        let rej = parse_frame_at(&r, &p, 0, r.len())
            .unwrap()
            .expect_err("no frame");
        assert!(rej.reason.contains("no DHAV tag"));
    }

    // ── Header field decoding ───────────────────────────────────────────────

    #[test]
    fn the_channel_field_is_zero_based_and_normalized_to_one_based() {
        for ch0 in [0u16, 1, 7, 15] {
            let f = FrameBuilder::video_key(h264_payload(1)).channel_0_based(ch0);
            let frame = parse_one(f.build()).unwrap();
            assert_eq!(frame.raw_channel, ch0 as u32);
            assert_eq!(frame.channel.normalized, ch0 as u32 + 1);
            assert_eq!(
                frame.channel.encoding,
                crate::channel::ChannelEncoding::DhavFrameHeader
            );
        }
    }

    #[test]
    fn the_packed_timestamp_decodes_to_the_recorders_wall_clock() {
        let f = FrameBuilder::video_key(h264_payload(1)).at(2026, 9, 22, 14, 35, 7);
        let frame = parse_one(f.build()).unwrap();
        assert_eq!(
            frame.timestamp.recorder_wall_clock.as_deref(),
            Some("2026-09-22T14:35:07")
        );
        assert_eq!(
            frame.timestamp.confidence,
            crate::timestamp::TimestampConfidence::Decoded
        );
        assert!(frame.timestamp.unix_seconds.is_some());
    }

    #[test]
    fn an_implausible_packed_timestamp_downgrades_the_frame_and_reports_no_instant() {
        // month field 0.
        let f = FrameBuilder::video_key(h264_payload(1))
            .raw_timestamp((26u32 << 26) | (5 << 17) | (10 << 12));
        let frame = parse_one(f.build()).unwrap();
        assert!(frame.timestamp.unix_seconds.is_none());
        assert!(!frame.is_fully_verified());
        assert!(frame
            .evidence
            .reason
            .contains("did not decode to an instant"));
    }

    #[test]
    fn the_intra_second_counter_is_read_but_is_not_a_wall_clock_value() {
        let f = FrameBuilder::video_key(h264_payload(1))
            .at(2026, 9, 22, 11, 0, 0)
            .sub_timestamp(4321);
        let frame = parse_one(f.build()).unwrap();
        assert_eq!(frame.sub_timestamp, 4321);
        // The second-resolution wall clock comes from the packed date field alone; the
        // intra-second counter must not shift it.
        assert_eq!(
            frame.timestamp.recorder_wall_clock.as_deref(),
            Some("2026-09-22T11:00:00")
        );
        let rec = frame.to_container_record();
        assert_eq!(
            rec.oem_metadata
                .get("dhav_sub_timestamp")
                .map(|s| s.as_str()),
            Some("4321"),
            "it is retained as OEM evidence rather than folded into the timestamp"
        );
    }

    #[test]
    fn frame_kinds_are_classified_from_the_type_byte() {
        for (byte, kind) in [
            (0xFDu8, DhavFrameKind::VideoKeyFrame),
            (0xFC, DhavFrameKind::VideoDeltaFrame),
            (0xF0, DhavFrameKind::Audio),
            (0xF1, DhavFrameKind::Info),
        ] {
            let f = FrameBuilder::video_key(h264_payload(1)).frame_type(byte);
            let frame = parse_one(f.build()).unwrap();
            assert_eq!(frame.kind, kind, "type 0x{byte:02X}");
        }
        let f = FrameBuilder::video_key(h264_payload(1)).frame_type(0x42);
        let frame = parse_one(f.build()).unwrap();
        assert_eq!(frame.kind, DhavFrameKind::Other(0x42));
        assert!(!frame.kind.is_video());
        assert!(frame
            .evidence
            .reason
            .contains("not one this platform has evidence for"));
    }

    #[test]
    fn an_info_frame_may_legitimately_carry_no_payload() {
        let f = FrameBuilder::video_key(Vec::new()).frame_type(0xF1);
        let frame = parse_one(f.build()).unwrap();
        assert_eq!(frame.payload_length, 0);
        assert!(frame.payload_region.is_none());
        assert!(
            frame.is_fully_verified(),
            "an empty info frame is structurally fine: {}",
            frame.evidence.reason
        );
    }

    #[test]
    fn a_video_frame_with_no_payload_is_flagged() {
        let f = FrameBuilder::video_key(Vec::new());
        let frame = parse_one(f.build()).unwrap();
        assert_eq!(frame.payload_length, 0);
        assert!(frame.evidence.reason.contains("zero-length payload"));
        assert!(!frame.is_fully_verified());
    }

    #[test]
    fn an_unsizeable_extra_header_tag_stops_the_walk_and_is_reported() {
        let f = FrameBuilder::video_key(h264_payload(1)).raw_extra(&[0x01, 0x02, 0x03, 0x04]);
        let frame = parse_one(f.build()).unwrap();
        assert!(frame
            .evidence
            .reason
            .contains("is not one this platform can size"));
        assert!(frame.extra_header_tags.contains(&"0x01".to_string()));
        // Boundaries are still exact, because they come from the declared lengths.
        assert_eq!(frame.payload_offset, AT + 24 + 4);
    }

    // ── Carving ─────────────────────────────────────────────────────────────

    #[test]
    fn several_frames_in_one_region_are_all_found_with_absolute_offsets() {
        let p = dahua_profile();
        let frames: Vec<Vec<u8>> = (0..5)
            .map(|i| {
                FrameBuilder::video_key(h264_payload(i as u8))
                    .frame_number(i + 1)
                    .channel_0_based((i % 2) as u16)
                    .build()
            })
            .collect();
        let total: usize = frames.iter().map(|f| f.len()).sum();
        let (r, offsets) = image(&frames, AT as usize + total + 8192);

        let result = carve_region(&r, &p, Region::new(0, r.len()).unwrap()).unwrap();
        assert_eq!(
            result.frames.len(),
            5,
            "one region must be able to yield many frames: {}",
            result.evidence.reason
        );
        assert_eq!(
            result
                .frames
                .iter()
                .map(|f| f.physical_offset)
                .collect::<Vec<_>>(),
            offsets,
            "offsets must be absolute and in order"
        );
        assert!(result.frames.iter().all(|f| f.is_fully_verified()));
        assert!(result.rejections.is_empty());
        assert!(!result.truncated);
        assert_eq!(result.evidence.state, ValidationStateKind::Pass);
        // Channels alternate, decoded from each frame's own header.
        assert_eq!(
            result
                .frames
                .iter()
                .map(|f| f.channel.normalized)
                .collect::<Vec<_>>(),
            vec![1, 2, 1, 2, 1]
        );
    }

    #[test]
    fn carving_only_covers_the_region_it_was_given() {
        let p = dahua_profile();
        let frames: Vec<Vec<u8>> = (0..3)
            .map(|i| FrameBuilder::video_key(h264_payload(i as u8)).build())
            .collect();
        let total: usize = frames.iter().map(|f| f.len()).sum();
        let (r, offsets) = image(&frames, AT as usize + total + 4096);

        // A region that starts after the first frame must not report it.
        let region = Region::new(offsets[1], r.len() - offsets[1]).unwrap();
        let result = carve_region(&r, &p, region).unwrap();
        assert_eq!(result.frames.len(), 2);
        assert_eq!(result.frames[0].physical_offset, offsets[1]);
    }

    #[test]
    fn a_frame_larger_than_the_carve_window_is_still_described_in_full() {
        let p = dahua_profile();
        // The profile's carve window is 4 MiB; make one frame bigger than that.
        let big = 5 * 1024 * 1024usize;
        let mut payload = h264_payload(0x33);
        payload.resize(big, 0x5A);
        let first = FrameBuilder::video_key(payload.clone()).build();
        let second = FrameBuilder::video_key(h264_payload(0x44))
            .frame_number(2)
            .build();
        let total = first.len() + second.len();
        let (r, offsets) = image(&[first.clone(), second], AT as usize + total + 4096);

        let result = carve_region(&r, &p, Region::new(0, r.len()).unwrap()).unwrap();
        assert_eq!(
            result.frames.len(),
            2,
            "a frame beyond the window must not hide the frames after it: {}",
            result.evidence.reason
        );
        assert_eq!(result.frames[0].total_length, first.len() as u64);
        assert_eq!(result.frames[0].payload_length, payload.len() as u64);
        assert_eq!(result.frames[1].physical_offset, offsets[1]);
        assert!(result.frames.iter().all(|f| f.is_fully_verified()));
    }

    #[test]
    fn framing_straddling_a_window_boundary_is_still_found() {
        let p = dahua_profile();
        // Place a frame so its header crosses the 4 MiB window boundary.
        let window = 4 * 1024 * 1024usize;
        let frame = FrameBuilder::video_key(h264_payload(0x55)).build();
        let at = window - 8;
        let mut b = vec![0u8; at + frame.len() + 4096];
        b[at..at + frame.len()].copy_from_slice(&frame);
        let r = MemReader::new(b);

        let result = carve_region(&r, &p, Region::new(0, r.len()).unwrap()).unwrap();
        assert_eq!(result.frames.len(), 1, "{}", result.evidence.reason);
        assert_eq!(result.frames[0].physical_offset, at as u64);
    }

    #[test]
    fn a_malformed_tag_match_is_recorded_as_a_rejection_not_accepted() {
        let p = dahua_profile();
        let good = FrameBuilder::video_key(h264_payload(1)).build();
        // A bare tag with a nonsense length.
        let mut bad = vec![0u8; 64];
        bad[..4].copy_from_slice(b"DHAV");
        bad[12..16].copy_from_slice(&7u32.to_le_bytes());
        let total = good.len() + bad.len();
        let (r, _) = image(&[good, bad], AT as usize + total + 4096);

        let result = carve_region(&r, &p, Region::new(0, r.len()).unwrap()).unwrap();
        assert_eq!(result.frames.len(), 1, "only the valid frame is a frame");
        assert_eq!(result.rejections.len(), 1);
        assert!(result.rejections[0].reason.contains("structural minimum"));
        assert!(result.evidence.reason.contains("1 tag match(es) rejected"));
    }

    #[test]
    fn carving_a_region_with_no_framing_finds_nothing_and_asserts_nothing() {
        let p = dahua_profile();
        let r = MemReader::new(vec![0u8; 1 << 20]);
        let result = carve_region(&r, &p, Region::new(0, r.len()).unwrap()).unwrap();
        assert!(result.frames.is_empty());
        assert!(result.rejections.is_empty());
        assert_eq!(result.evidence.state, ValidationStateKind::Pass);
    }

    #[test]
    fn an_empty_region_reads_nothing() {
        let p = dahua_profile();
        let r = MemReader::new(vec![0u8; 4096]);
        let result = carve_region(&r, &p, Region::point(100)).unwrap();
        assert!(result.frames.is_empty());
        assert_eq!(result.bytes_read, 0);
    }

    #[test]
    fn format_recognition_requires_a_valid_frame_not_just_the_tag() {
        let p = dahua_profile();
        // A window holding only the four tag bytes is not container framing.
        let mut b = vec![0u8; 65536];
        b[1000..1004].copy_from_slice(b"DHAV");
        let r = MemReader::new(b);
        assert!(!window_carries_dhav_framing(&r, &p, 65536).unwrap());

        let frame = FrameBuilder::video_key(h264_payload(1)).build();
        let (r2, _) = image(&[frame], AT as usize + 8192);
        assert!(window_carries_dhav_framing(&r2, &p, 65536).unwrap());
    }

    // ── Normalization to the OEM-neutral record ─────────────────────────────

    #[test]
    fn container_records_carry_absolute_offsets_and_oem_evidence() {
        let payload = h264_payload(0x66);
        let f = FrameBuilder::video_key(payload.clone())
            .channel_0_based(2)
            .at(2026, 9, 22, 6, 30, 0)
            .resolution(1920, 1080)
            .codec(0x0C, 30);
        let frame = parse_one(f.build()).unwrap();
        let rec = frame.to_container_record();

        assert_eq!(rec.physical_region, frame.region);
        assert_eq!(rec.payload_region, frame.payload_region);
        assert_eq!(rec.channel, Some(3), "0-based 2 normalizes to channel 3");
        assert_eq!(rec.start_time_unix, frame.timestamp.unix_seconds);
        assert_eq!(rec.frame_type.as_deref(), Some("video-key-frame"));
        assert_eq!(rec.codec_hint.as_deref(), Some("H.265"));
        // OEM-specific facts survive as verbatim strings.
        assert_eq!(
            rec.oem_metadata.get("dhav_frame_type").map(|s| s.as_str()),
            Some("0xFD")
        );
        assert_eq!(
            rec.oem_metadata.get("dhav_resolution").map(|s| s.as_str()),
            Some("1920x1080")
        );
        assert!(rec.oem_metadata.contains_key("dahua_timestamp_raw"));
        assert!(rec.oem_metadata.contains_key("dahua_channel_evidence"));
        assert_eq!(
            rec.oem_metadata
                .get("dhav_trailer_tag_verified")
                .map(|s| s.as_str()),
            Some("true")
        );
        assert_eq!(rec.evidence.state, ValidationStateKind::Pass);
    }

    #[test]
    fn a_record_from_an_undecodable_timestamp_has_no_time_rather_than_the_epoch() {
        let f = FrameBuilder::video_key(h264_payload(1)).raw_timestamp(0);
        let frame = parse_one(f.build()).unwrap();
        let rec = frame.to_container_record();
        assert!(
            rec.start_time_unix.is_none(),
            "an absent packed field must not become 1970"
        );
        assert_eq!(
            rec.oem_metadata
                .get("dahua_timestamp_raw")
                .map(|s| s.as_str()),
            Some("0x00000000")
        );
    }
}
