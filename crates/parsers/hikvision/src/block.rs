//! # Video blocks and the footer clip index
//!
//! The boot structure's `VideoStartOffset`, `BlockSize` and `NumberOfBlocks` divide the
//! disk into fixed-size video blocks. Each block ends with a footer region that holds the
//! block's own clip index:
//!
//! ```text
//!   block N                                                 
//!   ├─ video data  [off,                    off + size - footer)
//!   └─ footer      [off + size - footer,    off + size)
//!                   ├─ +13  reject byte          (255 => not an index)
//!                   ├─ +20  u16 ClipCount        (must be > 0)
//!                   ├─ +32  u32 epoch start
//!                   ├─ +36  u32 epoch end
//!                   └─ +512 clip slots, 512 bytes apart
//! ```
//!
//! ## The footer is never video
//!
//! Splitting the block into two named regions is load-bearing. Scanning the footer as
//! ordinary video data would carve the index's own bytes as if they were a recording, and a
//! clip whose computed range reaches into the footer is a damaged clip, not a long one.
//! [`BlockGeometry`] therefore exposes the two ranges separately and
//! [`BlockGeometry::video_data_region`] is the only range clips are validated against.
//!
//! ## Reads stay bounded
//!
//! A block is normally 1 GiB and its footer 1 MiB. Nothing here reads either in full: the
//! index header is a single 512-byte read, and the clip slots are read as one span sized
//! from the declared clip count. A block with three clips costs 512 + 1536 bytes, not a
//! gigabyte.
//!
//! ## Clip slot fields are validated, never repaired
//!
//! A slot is accepted only if its channel is plausible, its end time decodes, its offsets
//! are ordered, and the resulting range lies inside the block's video data. A slot that
//! fails is recorded as a [`RejectedSlot`] with the reason — it is never adjusted to fit,
//! and the fields this platform has not interpreted (`+108`, `+112`) are preserved verbatim
//! rather than discarded.

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, OemProfile, Region, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::channel::{self, ChannelEvidence};
use crate::layout::{key, u16_at, u32_at, u64_from, u8_at, usize_from, vs};
use crate::timestamp::{self, HikTimestamp, TimestampStructure};

/// Physical geometry of one video block.
///
/// Every range is clipped to the evidence, so a recorder that declares more blocks than the
/// acquired image holds yields the bytes actually present rather than a range past the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockGeometry {
    pub block_number: u32,
    /// First byte of the block.
    pub block_offset: u64,
    /// Declared block size, footer included.
    pub block_size: u64,
    /// Declared footer size.
    pub footer_size: u64,
    /// Byte length of the evidence, for clipping.
    pub physical_size: u64,
}

impl BlockGeometry {
    /// Build the geometry for block `block_number`.
    ///
    /// Returns `None` when the block's first byte lies outside the evidence, or when the
    /// declared block size does not exceed the footer — a block with no video data is not
    /// a usable geometry, and reporting one would let a clip be validated against an empty
    /// range.
    pub fn new(
        block_number: u32,
        block_offset: u64,
        block_size: u64,
        footer_size: u64,
        physical_size: u64,
    ) -> Option<Self> {
        if block_offset >= physical_size || block_size <= footer_size {
            return None;
        }
        Some(Self {
            block_number,
            block_offset,
            block_size,
            footer_size,
            physical_size,
        })
    }

    /// The whole block, clipped to the evidence.
    pub fn block_region(&self) -> Option<Region> {
        let available = self.physical_size.saturating_sub(self.block_offset);
        Region::new(self.block_offset, self.block_size.min(available)).ok()
    }

    /// The video payload portion of the block. Clips live here and nowhere else.
    pub fn video_data_region(&self) -> Option<Region> {
        let length = self.block_size - self.footer_size;
        let available = self.physical_size.saturating_sub(self.block_offset);
        let clipped = length.min(available);
        if clipped == 0 {
            return None;
        }
        Region::new(self.block_offset, clipped).ok()
    }

    /// Absolute offset of the footer region's first byte.
    pub fn footer_offset(&self) -> u64 {
        // `new` guarantees block_size > footer_size, so this cannot underflow.
        self.block_offset + (self.block_size - self.footer_size)
    }

    /// The footer / index portion of the block, clipped to the evidence.
    ///
    /// `None` when the image ends before the footer begins, which is the truncated-image
    /// case: the block's video data may still be present and recoverable even though its
    /// index is gone.
    pub fn footer_region(&self) -> Option<Region> {
        let start = self.footer_offset();
        if start >= self.physical_size {
            return None;
        }
        let available = self.physical_size - start;
        Region::new(start, self.footer_size.min(available)).ok()
    }

    /// Whether an absolute offset falls in this block's video data.
    pub fn contains_video_offset(&self, offset: u64) -> bool {
        self.video_data_region()
            .map(|r| r.contains(offset))
            .unwrap_or(false)
    }

    /// Whether an absolute offset falls in this block's footer.
    pub fn contains_footer_offset(&self, offset: u64) -> bool {
        self.footer_region()
            .map(|r| r.contains(offset))
            .unwrap_or(false)
    }

    /// Whether a whole range lies inside this block's video data.
    ///
    /// This is the check a clip must pass: a range that starts in video data but ends in
    /// the footer is rejected, not truncated.
    pub fn video_data_contains_range(&self, offset: u64, length: u64) -> bool {
        let Some(video) = self.video_data_region() else {
            return false;
        };
        let Some(end) = offset.checked_add(length) else {
            return false;
        };
        offset >= video.offset && end <= video.offset.saturating_add(video.length)
    }
}

/// Whether a block footer holds a usable clip index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockIndexRecognition {
    /// The header passed its structural checks.
    Verified,
    /// The `+13` byte holds the reject value, so this footer is not a clip index.
    ///
    /// A legitimate structural statement about an unused block, not a damage finding.
    RejectByte { observed: u8 },
    /// The header declares no clips.
    ZeroClipCount,
    /// The declared clip count exceeds what the footer can physically hold.
    ClipCountImplausible { declared: u16, capacity: u64 },
    /// The footer lies outside the acquired image.
    FooterOutOfBounds { reason: String },
    /// The footer bytes could not be read.
    Unreadable { reason: String },
}

impl BlockIndexRecognition {
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::RejectByte { .. } => "reject-byte",
            Self::ZeroClipCount => "zero-clip-count",
            Self::ClipCountImplausible { .. } => "clip-count-implausible",
            Self::FooterOutOfBounds { .. } => "footer-out-of-bounds",
            Self::Unreadable { .. } => "unreadable",
        }
    }

    fn reason(&self, geometry: &BlockGeometry) -> String {
        let n = geometry.block_number;
        let footer = geometry.footer_offset();
        match self {
            Self::Verified => {
                format!("block {n} footer at {footer} (0x{footer:X}) carries a verified clip index")
            }
            Self::RejectByte { observed } => format!(
                "block {n} footer at {footer} (0x{footer:X}) holds {observed} in the index marker \
                 byte, which marks the footer as carrying no clip index. This is a statement about \
                 the block, not evidence of damage"
            ),
            Self::ZeroClipCount => format!(
                "block {n} footer at {footer} (0x{footer:X}) declares zero clips, so it indexes no \
                 recording"
            ),
            Self::ClipCountImplausible { declared, capacity } => format!(
                "block {n} footer at {footer} (0x{footer:X}) declares {declared} clips but only \
                 {capacity} slots fit in the footer; the declared count was not trusted"
            ),
            Self::FooterOutOfBounds { reason } => format!("block {n} footer: {reason}"),
            Self::Unreadable { reason } => format!("block {n} footer: {reason}"),
        }
    }
}

/// A clip slot that failed validation, with the reason it failed.
///
/// Kept rather than dropped: a footer whose slots do not validate is a different finding
/// from a footer with no slots, and the difference matters when deciding whether a block's
/// video data is worth carving.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RejectedSlot {
    pub slot_index: usize,
    /// Absolute physical offset of the slot.
    pub slot_offset: u64,
    pub reason: String,
}

/// One validated clip from a block footer's index.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClipRecord {
    pub block_number: u32,
    /// Index of the slot within the footer's slot array.
    pub slot_index: usize,
    /// Absolute physical offset of the slot that described this clip.
    pub slot_offset: u64,
    /// Absolute offset of the block the clip lives in, so a clip is self-locating.
    pub block_offset: u64,
    pub channel: ChannelEvidence,
    /// Start time, after the documented `time A` fallback.
    pub start_time: HikTimestamp,
    /// End time.
    pub end_time: HikTimestamp,
    /// Whether the start time came from the `+40` fallback rather than `+56`.
    pub start_from_fallback: bool,
    /// The `+72` start offset, exactly as stored (relative to the block).
    pub declared_start_offset: u32,
    /// The `+76` end offset, exactly as stored (relative to the block).
    pub declared_end_offset: u32,
    /// The clip's absolute physical range: `block_offset + startOffset`, length
    /// `endOffset - startOffset`.
    pub clip_region: Region,
    /// The `+88` frame rate byte, when it is non-zero.
    pub frame_rate: Option<u8>,
    /// The `+108` field. Meaning not established by this platform; preserved verbatim.
    pub unknown_a: u32,
    /// The `+112` field. Meaning not established by this platform; preserved verbatim.
    pub unknown_b: u32,
    /// Why this clip is or is not trustworthy.
    pub evidence: ValidationState,
}

impl ClipRecord {
    /// A stable identifier derived from the clip's own physical position.
    pub fn clip_id(&self) -> String {
        format!(
            "hikclip:b{}:s{}:{:#x}",
            self.block_number, self.slot_index, self.clip_region.offset
        )
    }

    /// Duration in seconds, when both ends decoded.
    pub fn duration_seconds(&self) -> Option<i64> {
        let s = self.start_time.unix_seconds?;
        let e = self.end_time.unix_seconds?;
        Some(e.saturating_sub(s))
    }

    /// OEM metadata for the generic index/fragment types, as plain strings.
    ///
    /// Everything here was read from the slot. The two uninterpreted fields are included
    /// under names that say so, so a later revision can interpret them from an existing
    /// report rather than needing the disk again.
    pub fn oem_metadata(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("hikvision_clip_id".into(), self.clip_id());
        m.insert(
            "hikvision_block_number".into(),
            self.block_number.to_string(),
        );
        m.insert(
            "hikvision_block_offset".into(),
            self.block_offset.to_string(),
        );
        m.insert(
            "hikvision_clip_slot_index".into(),
            self.slot_index.to_string(),
        );
        m.insert(
            "hikvision_clip_slot_offset".into(),
            self.slot_offset.to_string(),
        );
        m.insert(
            "hikvision_clip_declared_start_offset".into(),
            self.declared_start_offset.to_string(),
        );
        m.insert(
            "hikvision_clip_declared_end_offset".into(),
            self.declared_end_offset.to_string(),
        );
        m.insert(
            "hikvision_clip_physical_region".into(),
            self.clip_region.to_string(),
        );
        m.insert("hikvision_channel_raw".into(), self.channel.raw.to_string());
        m.insert(
            "hikvision_channel_evidence".into(),
            self.channel.note.clone(),
        );
        m.insert(
            "hikvision_clip_start_raw".into(),
            self.start_time.raw.to_string(),
        );
        m.insert(
            "hikvision_clip_end_raw".into(),
            self.end_time.raw.to_string(),
        );
        m.insert(
            "hikvision_clip_start_from_fallback_field".into(),
            self.start_from_fallback.to_string(),
        );
        if let Some(fr) = self.frame_rate {
            m.insert("hikvision_clip_frame_rate".into(), fr.to_string());
        }
        // Named "uninterpreted" so nobody mistakes a preserved value for a decoded one.
        m.insert(
            "hikvision_clip_uninterpreted_field_108".into(),
            self.unknown_a.to_string(),
        );
        m.insert(
            "hikvision_clip_uninterpreted_field_112".into(),
            self.unknown_b.to_string(),
        );
        if let Some(d) = self.duration_seconds() {
            m.insert("hikvision_clip_duration_seconds".into(), d.to_string());
        }
        m
    }
}

/// A block footer's parsed clip index.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockIndex {
    pub geometry: BlockGeometry,
    /// Physical extent of the footer, when it is present in the evidence.
    pub footer_region: Option<Region>,
    pub recognition: BlockIndexRecognition,
    /// The `+20` clip count, exactly as stored.
    pub declared_clip_count: Option<u16>,
    /// The `+13` marker byte, exactly as stored.
    pub marker_byte: Option<u8>,
    /// The `+32` epoch start.
    pub epoch_start: Option<HikTimestamp>,
    /// The `+36` epoch end.
    pub epoch_end: Option<HikTimestamp>,
    /// Slots that validated.
    pub clips: Vec<ClipRecord>,
    /// Slots that did not, with reasons.
    pub rejected_slots: Vec<RejectedSlot>,
    /// Why this index is or is not trustworthy.
    pub evidence: ValidationState,
}

impl BlockIndex {
    /// Whether this footer yielded at least one usable clip.
    pub fn has_clips(&self) -> bool {
        !self.clips.is_empty()
    }

    /// Whether the footer declared clips but none validated.
    ///
    /// A distinct condition from "no clips declared": it says the index is damaged, which
    /// is a reason to carve the block's video data rather than to skip it.
    pub fn declared_but_none_valid(&self) -> bool {
        self.clips.is_empty() && !self.rejected_slots.is_empty()
    }

    /// Physical ranges of every validated clip.
    pub fn clip_regions(&self) -> Vec<Region> {
        self.clips.iter().map(|c| c.clip_region).collect()
    }
}

/// Read one block's footer clip index.
///
/// Reads the index header, then only as many slot bytes as the declared count needs. Never
/// reads the block's video data, and never reads the whole footer.
///
/// Never fails on a damaged or absent footer: an unusable index comes back as a
/// [`BlockIndexRecognition`] variant, because "this block has no index" is a result the
/// orphan analysis needs rather than an error.
pub fn read_block_index(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    geometry: BlockGeometry,
) -> Result<BlockIndex, ForensicError> {
    let header_size = usize_from(profile, key::BLOCK_INDEX_HEADER_SIZE, 512);
    let footer_region = geometry.footer_region();

    let Some(footer) = footer_region else {
        return Ok(unusable(
            geometry,
            None,
            BlockIndexRecognition::FooterOutOfBounds {
                reason: format!(
                    "the footer would begin at {} (0x{:X}), past the end of this {}-byte image; the \
                     block's index is not present in the acquisition",
                    geometry.footer_offset(),
                    geometry.footer_offset(),
                    geometry.physical_size
                ),
            },
        ));
    };

    if footer.length < header_size as u64 {
        return Ok(unusable(
            geometry,
            footer_region,
            BlockIndexRecognition::FooterOutOfBounds {
                reason: format!(
                    "only {} footer byte(s) are present but the index header is {header_size} \
                     bytes; the image is truncated inside the footer",
                    footer.length
                ),
            },
        ));
    }

    let header = match reader.read_exact_at(footer.offset, header_size) {
        Ok(b) => b,
        Err(e) => {
            return Ok(unusable(
                geometry,
                footer_region,
                BlockIndexRecognition::Unreadable {
                    reason: format!("the index header could not be read: {e}"),
                },
            ))
        }
    };

    // ── Marker byte ──────────────────────────────────────────────────────────────
    let marker_rel = usize_from(profile, key::BLOCK_INDEX_REJECT_BYTE_OFFSET, 13);
    let reject_value = crate::layout::u8_from(profile, key::BLOCK_INDEX_REJECT_BYTE_VALUE, 255);
    let marker_byte = u8_at(&header, marker_rel);
    if marker_byte == Some(reject_value) {
        return Ok(unusable_with(
            geometry,
            footer_region,
            BlockIndexRecognition::RejectByte {
                observed: reject_value,
            },
            marker_byte,
            None,
        ));
    }

    // ── Clip count ───────────────────────────────────────────────────────────────
    let count_rel = usize_from(profile, key::BLOCK_INDEX_CLIP_COUNT_OFFSET, 20);
    let declared_clip_count = u16_at(&header, count_rel);
    let slot_base = u64_from(profile, key::BLOCK_INDEX_CLIP_BASE_OFFSET, 512);
    let stride = u64_from(profile, key::BLOCK_INDEX_CLIP_STRIDE, 512).max(1);
    let declared_capacity = u64_from(profile, key::BLOCK_INDEX_CLIP_COUNT_MAX, 2047);
    // The footer present in *this* image may be shorter than the declared footer size.
    let physical_capacity = footer.length.saturating_sub(slot_base) / stride;
    let capacity = declared_capacity.min(physical_capacity);

    let count = match declared_clip_count {
        None | Some(0) => {
            return Ok(unusable_with(
                geometry,
                footer_region,
                BlockIndexRecognition::ZeroClipCount,
                marker_byte,
                declared_clip_count,
            ))
        }
        Some(c) if c as u64 > capacity => {
            return Ok(unusable_with(
                geometry,
                footer_region,
                BlockIndexRecognition::ClipCountImplausible {
                    declared: c,
                    capacity,
                },
                marker_byte,
                declared_clip_count,
            ))
        }
        Some(c) => c as usize,
    };

    // ── Epoch span ───────────────────────────────────────────────────────────────
    let epoch_start_rel = usize_from(profile, key::BLOCK_INDEX_EPOCH_START_OFFSET, 32);
    let epoch_end_rel = usize_from(profile, key::BLOCK_INDEX_EPOCH_END_OFFSET, 36);
    let epoch_start = Some(HikTimestamp::decode(
        u32_at(&header, epoch_start_rel)
            .map(|v| v as i64)
            .unwrap_or(0),
        TimestampStructure::BlockIndexEpochStart,
        footer.offset.saturating_add(epoch_start_rel as u64),
        profile,
    ));
    let epoch_end = Some(HikTimestamp::decode(
        u32_at(&header, epoch_end_rel)
            .map(|v| v as i64)
            .unwrap_or(0),
        TimestampStructure::BlockIndexEpochEnd,
        footer.offset.saturating_add(epoch_end_rel as u64),
        profile,
    ));

    // ── Slot array ───────────────────────────────────────────────────────────────
    //
    // One bounded read sized from the declared count, rather than the whole 1 MiB footer.
    let slots_offset = footer.offset.saturating_add(slot_base);
    let slots_len = (count as u64).saturating_mul(stride);
    let available = footer
        .offset
        .saturating_add(footer.length)
        .saturating_sub(slots_offset);
    let to_read = slots_len.min(available) as usize;

    let slot_bytes = match reader.read_exact_at(slots_offset, to_read) {
        Ok(b) => b,
        Err(e) => {
            return Ok(unusable_with(
                geometry,
                footer_region,
                BlockIndexRecognition::Unreadable {
                    reason: format!("the clip slot array could not be read: {e}"),
                },
                marker_byte,
                declared_clip_count,
            ))
        }
    };

    let mut clips = Vec::new();
    let mut rejected = Vec::new();
    for i in 0..count {
        let rel = (i as u64).saturating_mul(stride) as usize;
        let slot_offset = slots_offset.saturating_add(rel as u64);
        let Some(slot) = slot_bytes.get(rel..rel.saturating_add(stride as usize)) else {
            rejected.push(RejectedSlot {
                slot_index: i,
                slot_offset,
                reason: format!(
                    "slot {i} lies past the end of the readable footer; the declared clip count \
                     exceeds the bytes present"
                ),
            });
            break;
        };
        match parse_clip_slot(profile, &geometry, i, slot_offset, slot) {
            Ok(clip) => clips.push(clip),
            Err(reason) => rejected.push(RejectedSlot {
                slot_index: i,
                slot_offset,
                reason,
            }),
        }
    }

    let evidence = index_evidence(&geometry, count, &clips, &rejected);

    Ok(BlockIndex {
        geometry,
        footer_region,
        recognition: BlockIndexRecognition::Verified,
        declared_clip_count,
        marker_byte,
        epoch_start,
        epoch_end,
        clips,
        rejected_slots: rejected,
        evidence,
    })
}

fn unusable(
    geometry: BlockGeometry,
    footer_region: Option<Region>,
    recognition: BlockIndexRecognition,
) -> BlockIndex {
    unusable_with(geometry, footer_region, recognition, None, None)
}

fn unusable_with(
    geometry: BlockGeometry,
    footer_region: Option<Region>,
    recognition: BlockIndexRecognition,
    marker_byte: Option<u8>,
    declared_clip_count: Option<u16>,
) -> BlockIndex {
    let reason = recognition.reason(&geometry);
    // None of these is a damage finding by itself, so none is a Fail. An unused block and a
    // truncated acquisition are both facts an examiner needs stated plainly.
    let kind = match &recognition {
        BlockIndexRecognition::Verified => ValidationStateKind::Pass,
        BlockIndexRecognition::RejectByte { .. } | BlockIndexRecognition::ZeroClipCount => {
            ValidationStateKind::Unknown
        }
        _ => ValidationStateKind::Review,
    };
    let evidence = vs(kind, reason, "hikvision_block_index", "block_footer");
    BlockIndex {
        geometry,
        footer_region,
        recognition,
        declared_clip_count,
        marker_byte,
        epoch_start: None,
        epoch_end: None,
        clips: Vec::new(),
        rejected_slots: Vec::new(),
        evidence,
    }
}

/// Parse and validate one 512-byte clip slot.
///
/// `Err(reason)` means the slot does not describe a usable clip. Rejection reasons are
/// sentences, because they end up in front of an examiner.
fn parse_clip_slot(
    profile: &OemProfile,
    geometry: &BlockGeometry,
    slot_index: usize,
    slot_offset: u64,
    slot: &[u8],
) -> Result<ClipRecord, String> {
    let ch_rel = usize_from(profile, key::CLIP_CHANNEL_OFFSET, 13);
    let time_a_rel = usize_from(profile, key::CLIP_TIME_A_OFFSET, 40);
    let end_rel = usize_from(profile, key::CLIP_END_TIME_OFFSET, 48);
    let start_rel = usize_from(profile, key::CLIP_START_TIME_OFFSET, 56);
    let start_off_rel = usize_from(profile, key::CLIP_START_OFFSET_OFFSET, 72);
    let end_off_rel = usize_from(profile, key::CLIP_END_OFFSET_OFFSET, 76);
    let fps_rel = usize_from(profile, key::CLIP_FRAME_RATE_OFFSET, 88);
    let unk_a_rel = usize_from(profile, key::CLIP_UNKNOWN_A_OFFSET, 108);
    let unk_b_rel = usize_from(profile, key::CLIP_UNKNOWN_B_OFFSET, 112);
    let min_length = u64_from(profile, key::CLIP_MIN_LENGTH_BYTES, 1);

    // ── Channel ──────────────────────────────────────────────────────────────────
    let raw_channel = u8_at(slot, ch_rel)
        .ok_or_else(|| format!("the channel byte at +{ch_rel} is not present in the slot"))?;
    let channel = channel::normalize(
        profile,
        raw_channel,
        slot_offset.saturating_add(ch_rel as u64),
        "clip slot +13",
        key::CLIP_CHANNEL_MAX,
    );
    if !channel.is_known() {
        return Err(channel.note);
    }

    // ── Times ────────────────────────────────────────────────────────────────────
    let end_raw = u32_at(slot, end_rel)
        .ok_or_else(|| format!("the end time at +{end_rel} is not present in the slot"))?;
    let end_time = HikTimestamp::decode(
        end_raw as i64,
        TimestampStructure::ClipEnd,
        slot_offset.saturating_add(end_rel as u64),
        profile,
    );
    if !end_time.is_decoded() {
        // The end time is the one required field: without it the clip has no interval.
        return Err(format!(
            "the clip's end time is required but established no instant — {}",
            end_time.evidence
        ));
    }

    let primary_start = HikTimestamp::decode(
        u32_at(slot, start_rel).map(|v| v as i64).unwrap_or(0),
        TimestampStructure::ClipStart,
        slot_offset.saturating_add(start_rel as u64),
        profile,
    );
    let fallback_start = HikTimestamp::decode(
        u32_at(slot, time_a_rel).map(|v| v as i64).unwrap_or(0),
        TimestampStructure::ClipTimeA,
        slot_offset.saturating_add(time_a_rel as u64),
        profile,
    );
    let (start_time, start_from_fallback) =
        timestamp::resolve_clip_start(primary_start, fallback_start);

    // A span over the limit is rejected. `None` (an undecodable pair) and `Some(true)` both
    // keep the clip, so only the over-limit case needs handling.
    if let Some(false) = timestamp::span_within_limit(&start_time, &end_time, profile) {
        {
            let limit = u64_from(profile, key::CLIP_MAX_DURATION_SECONDS, 604_800);
            return Err(format!(
                "the clip declares the interval {} -> {} ({}s), which is not within the maximum \
                 plausible clip duration of {limit}s; the slot was not accepted rather than being \
                 adjusted to fit",
                start_time
                    .iso_8601_utc
                    .clone()
                    .unwrap_or_else(|| "unknown".into()),
                end_time
                    .iso_8601_utc
                    .clone()
                    .unwrap_or_else(|| "unknown".into()),
                end_time.unix_seconds.unwrap_or(0) - start_time.unix_seconds.unwrap_or(0),
            ));
        }
    }
    // Otherwise the span is within the limit, or one end was undecodable — in which case the
    // clip still has a location and an end, so it is kept with the missing start recorded.

    // ── Byte range ───────────────────────────────────────────────────────────────
    let declared_start_offset = u32_at(slot, start_off_rel).ok_or_else(|| {
        format!("the start offset at +{start_off_rel} is not present in the slot")
    })?;
    let declared_end_offset = u32_at(slot, end_off_rel)
        .ok_or_else(|| format!("the end offset at +{end_off_rel} is not present in the slot"))?;

    if declared_end_offset <= declared_start_offset {
        return Err(format!(
            "the clip declares start offset {declared_start_offset} and end offset \
             {declared_end_offset}; the end must exceed the start, so the slot describes no range"
        ));
    }

    let length = (declared_end_offset - declared_start_offset) as u64;
    if length < min_length {
        return Err(format!(
            "the clip declares a {length}-byte range, below the minimum {min_length}"
        ));
    }

    let clip_start = geometry
        .block_offset
        .checked_add(declared_start_offset as u64)
        .ok_or_else(|| {
            format!(
                "block offset {} plus start offset {declared_start_offset} overflows",
                geometry.block_offset
            )
        })?;

    // The decisive check: a clip lives in video data, never in the footer.
    if !geometry.video_data_contains_range(clip_start, length) {
        let video = geometry
            .video_data_region()
            .map(|r| r.to_string())
            .unwrap_or_else(|| "no video-data region".into());
        return Err(format!(
            "the clip's computed range {clip_start}..{} (0x{clip_start:X}, {length} bytes) does not \
             lie inside block {}'s video data {video}. A range reaching into the {}-byte footer, or \
             past the acquired bytes, is a damaged clip and was not truncated to fit",
            clip_start.saturating_add(length),
            geometry.block_number,
            geometry.footer_size
        ));
    }

    let clip_region = Region::new(clip_start, length)
        .map_err(|e| format!("the clip's computed range is not a valid region: {e}"))?;

    // ── Preserved fields ─────────────────────────────────────────────────────────
    let frame_rate = u8_at(slot, fps_rel).filter(|v| *v != 0);
    let unknown_a = u32_at(slot, unk_a_rel).unwrap_or(0);
    let unknown_b = u32_at(slot, unk_b_rel).unwrap_or(0);

    // ── Verdict ──────────────────────────────────────────────────────────────────
    let mut notes: Vec<String> = Vec::new();
    if !start_time.is_decoded() {
        notes.push(
            "no start time could be decoded from either the dedicated start field or the fallback \
             field; the clip's interval is open at the start"
                .into(),
        );
    }
    if start_from_fallback {
        notes.push(
            "the start time came from the fallback field rather than the dedicated start field"
                .into(),
        );
    }
    if frame_rate.is_none() {
        notes.push("the frame rate byte is zero, so no frame rate was established".into());
    }
    if let (Some(s), Some(e)) = (start_time.unix_seconds, end_time.unix_seconds) {
        if e < s {
            notes.push(format!(
                "the end time {e} precedes the start time {s}; the interval is reported as stored"
            ));
        }
    }

    let kind = if notes.is_empty() {
        ValidationStateKind::Pass
    } else {
        ValidationStateKind::Review
    };
    let reason = if notes.is_empty() {
        format!(
            "block {} clip slot {slot_index} at {slot_offset} (0x{slot_offset:X}) validated: \
             channel {}, {} -> {}, physical range {clip_region}",
            geometry.block_number,
            channel.label(),
            start_time
                .iso_8601_utc
                .clone()
                .unwrap_or_else(|| "unknown".into()),
            end_time
                .iso_8601_utc
                .clone()
                .unwrap_or_else(|| "unknown".into()),
        )
    } else {
        format!(
            "block {} clip slot {slot_index} at {slot_offset} (0x{slot_offset:X}) validated with \
             qualifications (physical range {clip_region}): {}",
            geometry.block_number,
            notes.join("; ")
        )
    };

    Ok(ClipRecord {
        block_number: geometry.block_number,
        slot_index,
        slot_offset,
        block_offset: geometry.block_offset,
        channel,
        start_time,
        end_time,
        start_from_fallback,
        declared_start_offset,
        declared_end_offset,
        clip_region,
        frame_rate,
        unknown_a,
        unknown_b,
        evidence: vs(kind, reason, "hikvision_clip_slot", "clip_slot"),
    })
}

fn index_evidence(
    geometry: &BlockGeometry,
    declared: usize,
    clips: &[ClipRecord],
    rejected: &[RejectedSlot],
) -> ValidationState {
    let n = geometry.block_number;
    let footer = geometry.footer_offset();
    let base = format!(
        "block {n} footer index at {footer} (0x{footer:X}) declared {declared} clip(s); {} \
         validated, {} rejected",
        clips.len(),
        rejected.len()
    );
    if rejected.is_empty() && !clips.is_empty() {
        vs(
            ValidationStateKind::Pass,
            base,
            "hikvision_block_index",
            "block_footer",
        )
    } else if clips.is_empty() {
        vs(
            ValidationStateKind::Review,
            format!(
                "{base}. No clip in this block's index validated, so the block's video data is a \
                 candidate for structural carving rather than indexed extraction: {}",
                rejected
                    .iter()
                    .map(|r| format!("slot {}: {}", r.slot_index, r.reason))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            "hikvision_block_index",
            "block_footer",
        )
    } else {
        vs(
            ValidationStateKind::Review,
            format!(
                "{base}. Rejected slots: {}",
                rejected
                    .iter()
                    .map(|r| format!("slot {}: {}", r.slot_index, r.reason))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            "hikvision_block_index",
            "block_footer",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::tests_support::hikvision_profile;
    use crate::testing::MemReader;

    const MIB: u64 = 1 << 20;
    const T_2026: u32 = 1_774_224_000;

    /// A small but structurally faithful block: video data + a 1 MiB footer.
    const VIDEO: u64 = 4 * MIB;
    const BLOCK: u64 = VIDEO + MIB;

    fn put_u16(b: &mut [u8], at: usize, v: u16) {
        b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    struct ClipSpec {
        channel: u8,
        start: u32,
        end: u32,
        time_a: u32,
        start_offset: u32,
        end_offset: u32,
        frame_rate: u8,
    }

    impl Default for ClipSpec {
        fn default() -> Self {
            Self {
                channel: 0,
                start: T_2026,
                end: T_2026 + 600,
                time_a: T_2026,
                start_offset: 0,
                end_offset: 0x10000,
                frame_rate: 25,
            }
        }
    }

    fn slot_bytes(spec: &ClipSpec) -> Vec<u8> {
        let mut s = vec![0u8; 512];
        s[13] = spec.channel;
        put_u32(&mut s, 40, spec.time_a);
        put_u32(&mut s, 48, spec.end);
        put_u32(&mut s, 56, spec.start);
        put_u32(&mut s, 72, spec.start_offset);
        put_u32(&mut s, 76, spec.end_offset);
        s[88] = spec.frame_rate;
        put_u32(&mut s, 108, 0xAAAA_1111);
        put_u32(&mut s, 112, 0xBBBB_2222);
        s
    }

    /// Build an image holding one block at offset 0 with the given clip slots.
    fn block_image(marker: u8, declared_count: u16, slots: &[ClipSpec]) -> Vec<u8> {
        let mut data = vec![0u8; BLOCK as usize];
        let footer = VIDEO as usize;
        data[footer + 13] = marker;
        put_u16(&mut data, footer + 20, declared_count);
        put_u32(&mut data, footer + 32, T_2026);
        put_u32(&mut data, footer + 36, T_2026 + 3600);
        for (i, spec) in slots.iter().enumerate() {
            let at = footer + 512 + i * 512;
            data[at..at + 512].copy_from_slice(&slot_bytes(spec));
        }
        data
    }

    fn geometry() -> BlockGeometry {
        BlockGeometry::new(0, 0, BLOCK, MIB, BLOCK).expect("valid geometry")
    }

    // ── Geometry ────────────────────────────────────────────────────────────────

    #[test]
    fn a_one_gib_block_splits_into_video_data_and_a_one_mib_footer() {
        let gib = 1u64 << 30;
        let g = BlockGeometry::new(3, 0x1000, gib, MIB, 0x1000 + 4 * gib).unwrap();
        let video = g.video_data_region().unwrap();
        let footer = g.footer_region().unwrap();

        assert_eq!(video.offset, 0x1000);
        assert_eq!(video.length, gib - MIB);
        assert_eq!(footer.offset, 0x1000 + gib - MIB);
        assert_eq!(footer.length, MIB);
        // The two ranges must tile the block exactly, with no gap and no overlap.
        assert_eq!(video.offset + video.length, footer.offset);
        assert_eq!(footer.offset + footer.length, 0x1000 + gib);
        assert_eq!(g.footer_offset(), footer.offset);
    }

    #[test]
    fn the_footer_is_not_part_of_the_video_data_region() {
        let g = geometry();
        let footer_start = g.footer_offset();
        assert!(g.contains_video_offset(footer_start - 1));
        assert!(
            !g.contains_video_offset(footer_start),
            "the first footer byte must never be treated as video data"
        );
        assert!(g.contains_footer_offset(footer_start));
        assert!(!g.contains_footer_offset(footer_start - 1));
    }

    #[test]
    fn a_range_crossing_into_the_footer_is_not_inside_video_data() {
        let g = geometry();
        assert!(g.video_data_contains_range(0, VIDEO));
        assert!(
            !g.video_data_contains_range(0, VIDEO + 1),
            "a range one byte into the footer must be rejected, not truncated"
        );
        assert!(!g.video_data_contains_range(VIDEO - 10, 100));
        assert!(!g.video_data_contains_range(u64::MAX, 1), "no overflow");
    }

    #[test]
    fn a_block_no_larger_than_its_footer_has_no_usable_geometry() {
        assert!(BlockGeometry::new(0, 0, MIB, MIB, 10 * MIB).is_none());
        assert!(BlockGeometry::new(0, 0, MIB - 1, MIB, 10 * MIB).is_none());
        assert!(BlockGeometry::new(0, 0, MIB + 1, MIB, 10 * MIB).is_some());
    }

    #[test]
    fn a_block_beginning_past_the_image_has_no_geometry() {
        assert!(BlockGeometry::new(5, 1000, BLOCK, MIB, 500).is_none());
    }

    #[test]
    fn a_truncated_image_clips_the_block_and_may_lose_the_footer_entirely() {
        // Image ends inside the video data: the footer is simply not there.
        let g = BlockGeometry::new(0, 0, BLOCK, MIB, VIDEO / 2).unwrap();
        assert!(g.footer_region().is_none());
        let video = g.video_data_region().unwrap();
        assert_eq!(video.length, VIDEO / 2, "clipped to the acquired bytes");
        assert_eq!(g.block_region().unwrap().length, VIDEO / 2);
    }

    // ── Footer index header ─────────────────────────────────────────────────────

    #[test]
    fn one_clip_is_parsed_with_exact_physical_offsets() {
        let p = hikvision_profile();
        let data = block_image(0, 1, &[ClipSpec::default()]);
        let r = MemReader::new(data);
        let idx = read_block_index(&r, &p, geometry()).unwrap();

        assert!(idx.recognition.is_verified());
        assert_eq!(idx.declared_clip_count, Some(1));
        assert_eq!(idx.clips.len(), 1);
        assert!(idx.rejected_slots.is_empty());
        assert_eq!(idx.evidence.state, ValidationStateKind::Pass);

        let c = &idx.clips[0];
        assert_eq!(c.clip_region.offset, 0, "block_offset + startOffset");
        assert_eq!(c.clip_region.length, 0x10000, "endOffset - startOffset");
        assert_eq!(c.channel.normalized, Some(1));
        assert_eq!(c.start_time.unix_seconds, Some(T_2026 as i64));
        assert_eq!(c.end_time.unix_seconds, Some(T_2026 as i64 + 600));
        assert_eq!(c.frame_rate, Some(25));
        assert_eq!(c.declared_start_offset, 0);
        assert_eq!(c.declared_end_offset, 0x10000);
        // The slot offset must be the real physical position of the slot.
        assert_eq!(c.slot_offset, VIDEO + 512);
    }

    #[test]
    fn the_epoch_span_in_the_index_header_is_decoded() {
        let p = hikvision_profile();
        let data = block_image(0, 1, &[ClipSpec::default()]);
        let r = MemReader::new(data);
        let idx = read_block_index(&r, &p, geometry()).unwrap();
        assert_eq!(
            idx.epoch_start.as_ref().unwrap().unix_seconds,
            Some(T_2026 as i64)
        );
        assert_eq!(
            idx.epoch_end.as_ref().unwrap().unix_seconds,
            Some(T_2026 as i64 + 3600)
        );
    }

    #[test]
    fn multiple_clips_are_read_at_the_declared_stride() {
        let p = hikvision_profile();
        let specs: Vec<ClipSpec> = (0..4)
            .map(|i| ClipSpec {
                channel: i as u8,
                start: T_2026 + i * 600,
                end: T_2026 + (i + 1) * 600,
                time_a: T_2026 + i * 600,
                start_offset: i * 0x10000,
                end_offset: (i + 1) * 0x10000,
                ..Default::default()
            })
            .collect();
        let data = block_image(0, 4, &specs);
        let r = MemReader::new(data);
        let idx = read_block_index(&r, &p, geometry()).unwrap();

        assert_eq!(idx.clips.len(), 4);
        for (i, c) in idx.clips.iter().enumerate() {
            assert_eq!(c.slot_index, i);
            assert_eq!(
                c.slot_offset,
                VIDEO + 512 + i as u64 * 512,
                "512-byte stride"
            );
            assert_eq!(c.clip_region.offset, i as u64 * 0x10000);
            assert_eq!(c.channel.normalized, Some(i as u32 + 1));
        }
        // Clip ids must be distinct so two clips can never collapse in a report.
        let ids: std::collections::BTreeSet<_> = idx.clips.iter().map(|c| c.clip_id()).collect();
        assert_eq!(ids.len(), 4);
    }

    #[test]
    fn the_reject_marker_byte_means_this_footer_is_not_an_index() {
        let p = hikvision_profile();
        let data = block_image(255, 3, &[ClipSpec::default()]);
        let r = MemReader::new(data);
        let idx = read_block_index(&r, &p, geometry()).unwrap();
        assert!(!idx.recognition.is_verified());
        assert!(matches!(
            idx.recognition,
            BlockIndexRecognition::RejectByte { observed: 255 }
        ));
        assert!(idx.clips.is_empty());
        assert_eq!(idx.marker_byte, Some(255), "the raw marker survives");
        // Not a damage finding.
        assert_eq!(idx.evidence.state, ValidationStateKind::Unknown);
        assert!(idx.evidence.reason.contains("not evidence of damage"));
    }

    #[test]
    fn a_zero_clip_count_indexes_nothing() {
        let p = hikvision_profile();
        let data = block_image(0, 0, &[]);
        let r = MemReader::new(data);
        let idx = read_block_index(&r, &p, geometry()).unwrap();
        assert!(matches!(
            idx.recognition,
            BlockIndexRecognition::ZeroClipCount
        ));
        assert!(idx.clips.is_empty());
        assert!(!idx.declared_but_none_valid());
    }

    #[test]
    fn a_clip_count_beyond_the_footer_capacity_is_not_trusted() {
        let p = hikvision_profile();
        let data = block_image(0, 60_000, &[ClipSpec::default()]);
        let r = MemReader::new(data);
        let idx = read_block_index(&r, &p, geometry()).unwrap();
        match idx.recognition {
            BlockIndexRecognition::ClipCountImplausible { declared, capacity } => {
                assert_eq!(declared, 60_000);
                assert!(capacity <= 2047);
            }
            other => panic!("expected an implausible count, got {other:?}"),
        }
        assert!(idx.clips.is_empty(), "no slot may be read on a bad count");
    }

    #[test]
    fn a_footer_outside_the_image_is_reported_rather_than_fabricated() {
        let p = hikvision_profile();
        // Image ends inside the video data.
        let g = BlockGeometry::new(0, 0, BLOCK, MIB, VIDEO).unwrap();
        let r = MemReader::new(vec![0u8; VIDEO as usize]);
        let idx = read_block_index(&r, &p, g).unwrap();
        assert!(matches!(
            idx.recognition,
            BlockIndexRecognition::FooterOutOfBounds { .. }
        ));
        assert_eq!(idx.evidence.state, ValidationStateKind::Review);
    }

    // ── Clip slot validation ────────────────────────────────────────────────────

    #[test]
    fn a_clip_whose_end_offset_does_not_exceed_its_start_is_rejected() {
        let p = hikvision_profile();
        for (start, end) in [(0x1000u32, 0x1000u32), (0x2000, 0x1000)] {
            let data = block_image(
                0,
                1,
                &[ClipSpec {
                    start_offset: start,
                    end_offset: end,
                    ..Default::default()
                }],
            );
            let r = MemReader::new(data);
            let idx = read_block_index(&r, &p, geometry()).unwrap();
            assert!(
                idx.clips.is_empty(),
                "start {start} end {end} must be rejected"
            );
            assert_eq!(idx.rejected_slots.len(), 1);
            assert!(idx.rejected_slots[0].reason.contains("must exceed"));
            assert!(idx.declared_but_none_valid());
        }
    }

    #[test]
    fn a_clip_reaching_into_the_footer_is_rejected_not_truncated() {
        let p = hikvision_profile();
        let data = block_image(
            0,
            1,
            &[ClipSpec {
                start_offset: (VIDEO - 1024) as u32,
                end_offset: (VIDEO + 4096) as u32, // crosses into the footer
                ..Default::default()
            }],
        );
        let r = MemReader::new(data);
        let idx = read_block_index(&r, &p, geometry()).unwrap();
        assert!(idx.clips.is_empty());
        let reason = &idx.rejected_slots[0].reason;
        assert!(reason.contains("video data"), "{reason}");
        assert!(reason.contains("not truncated to fit"), "{reason}");
    }

    #[test]
    fn a_clip_starting_past_the_video_data_is_rejected() {
        let p = hikvision_profile();
        let data = block_image(
            0,
            1,
            &[ClipSpec {
                start_offset: (VIDEO + 2048) as u32,
                end_offset: (VIDEO + 4096) as u32,
                ..Default::default()
            }],
        );
        let r = MemReader::new(data);
        let idx = read_block_index(&r, &p, geometry()).unwrap();
        assert!(idx.clips.is_empty());
    }

    #[test]
    fn a_clip_spanning_more_than_seven_days_is_rejected() {
        let p = hikvision_profile();
        let data = block_image(
            0,
            1,
            &[ClipSpec {
                start: T_2026,
                time_a: T_2026,
                end: T_2026 + 8 * 86_400,
                ..Default::default()
            }],
        );
        let r = MemReader::new(data);
        let idx = read_block_index(&r, &p, geometry()).unwrap();
        assert!(idx.clips.is_empty());
        let reason = &idx.rejected_slots[0].reason;
        assert!(
            reason.contains("maximum plausible clip duration"),
            "{reason}"
        );
        assert!(reason.contains("not accepted"), "{reason}");
    }

    #[test]
    fn exactly_seven_days_is_still_accepted() {
        let p = hikvision_profile();
        let data = block_image(
            0,
            1,
            &[ClipSpec {
                start: T_2026,
                time_a: T_2026,
                end: T_2026 + 604_800,
                ..Default::default()
            }],
        );
        let r = MemReader::new(data);
        let idx = read_block_index(&r, &p, geometry()).unwrap();
        assert_eq!(
            idx.clips.len(),
            1,
            "the boundary value must not be rejected"
        );
    }

    #[test]
    fn a_clip_with_no_end_time_is_rejected_because_the_end_is_required() {
        let p = hikvision_profile();
        let data = block_image(
            0,
            1,
            &[ClipSpec {
                end: 0,
                ..Default::default()
            }],
        );
        let r = MemReader::new(data);
        let idx = read_block_index(&r, &p, geometry()).unwrap();
        assert!(idx.clips.is_empty());
        assert!(idx.rejected_slots[0].reason.contains("required"));
    }

    #[test]
    fn a_clip_with_no_dedicated_start_falls_back_to_time_a() {
        let p = hikvision_profile();
        let data = block_image(
            0,
            1,
            &[ClipSpec {
                start: 0, // dedicated start field empty
                time_a: T_2026,
                end: T_2026 + 600,
                ..Default::default()
            }],
        );
        let r = MemReader::new(data);
        let idx = read_block_index(&r, &p, geometry()).unwrap();
        assert_eq!(idx.clips.len(), 1);
        let c = &idx.clips[0];
        assert!(c.start_from_fallback);
        assert_eq!(c.start_time.unix_seconds, Some(T_2026 as i64));
        assert_eq!(
            c.evidence.state,
            ValidationStateKind::Review,
            "a fallback reading must be visible"
        );
    }

    #[test]
    fn an_implausible_channel_rejects_the_slot() {
        let p = hikvision_profile();
        let data = block_image(
            0,
            1,
            &[ClipSpec {
                channel: 200,
                ..Default::default()
            }],
        );
        let r = MemReader::new(data);
        let idx = read_block_index(&r, &p, geometry()).unwrap();
        assert!(idx.clips.is_empty());
        assert!(idx.rejected_slots[0].reason.contains("plausible maximum"));
    }

    #[test]
    fn uninterpreted_clip_fields_are_preserved_not_discarded() {
        let p = hikvision_profile();
        let data = block_image(0, 1, &[ClipSpec::default()]);
        let r = MemReader::new(data);
        let idx = read_block_index(&r, &p, geometry()).unwrap();
        let c = &idx.clips[0];
        assert_eq!(c.unknown_a, 0xAAAA_1111);
        assert_eq!(c.unknown_b, 0xBBBB_2222);
        let m = c.oem_metadata();
        assert_eq!(
            m.get("hikvision_clip_uninterpreted_field_108")
                .map(String::as_str),
            Some(0xAAAA_1111u32.to_string().as_str())
        );
        assert_eq!(
            m.get("hikvision_clip_uninterpreted_field_112")
                .map(String::as_str),
            Some(0xBBBB_2222u32.to_string().as_str())
        );
        // The raw channel byte and the raw timestamps must be in the metadata too.
        assert!(m.contains_key("hikvision_channel_raw"));
        assert!(m.contains_key("hikvision_clip_start_raw"));
        assert!(m.contains_key("hikvision_clip_end_raw"));
    }

    #[test]
    fn a_zero_frame_rate_yields_no_frame_rate_rather_than_zero_fps() {
        let p = hikvision_profile();
        let data = block_image(
            0,
            1,
            &[ClipSpec {
                frame_rate: 0,
                ..Default::default()
            }],
        );
        let r = MemReader::new(data);
        let idx = read_block_index(&r, &p, geometry()).unwrap();
        assert_eq!(idx.clips[0].frame_rate, None);
        assert_eq!(idx.clips[0].evidence.state, ValidationStateKind::Review);
    }

    #[test]
    fn valid_and_invalid_slots_in_one_footer_are_separated() {
        let p = hikvision_profile();
        let specs = vec![
            ClipSpec {
                start_offset: 0,
                end_offset: 0x10000,
                ..Default::default()
            },
            ClipSpec {
                // invalid: end <= start
                start_offset: 0x20000,
                end_offset: 0x20000,
                ..Default::default()
            },
            ClipSpec {
                start_offset: 0x30000,
                end_offset: 0x40000,
                ..Default::default()
            },
        ];
        let data = block_image(0, 3, &specs);
        let r = MemReader::new(data);
        let idx = read_block_index(&r, &p, geometry()).unwrap();
        assert_eq!(idx.clips.len(), 2);
        assert_eq!(idx.rejected_slots.len(), 1);
        assert_eq!(idx.rejected_slots[0].slot_index, 1);
        assert_eq!(idx.evidence.state, ValidationStateKind::Review);
        assert!(idx.has_clips());
        assert!(!idx.declared_but_none_valid());
    }

    #[test]
    fn reading_an_index_never_errors_on_hostile_footer_bytes() {
        let p = hikvision_profile();
        for fill in [0x00u8, 0xFF, 0xAA] {
            let data = vec![fill; BLOCK as usize];
            let r = MemReader::new(data);
            assert!(
                read_block_index(&r, &p, geometry()).is_ok(),
                "fill 0x{fill:02X} must produce a result, not an error"
            );
        }
    }

    #[test]
    fn a_clip_is_located_relative_to_its_own_block_not_to_offset_zero() {
        let p = hikvision_profile();
        // Place the block at a non-zero offset and confirm the clip follows it.
        let block_offset = 0x40000u64;
        let mut data = vec![0u8; (block_offset + BLOCK) as usize];
        let footer = (block_offset + VIDEO) as usize;
        put_u16(&mut data, footer + 20, 1);
        let slot = slot_bytes(&ClipSpec {
            start_offset: 0x8000,
            end_offset: 0x18000,
            ..Default::default()
        });
        data[footer + 512..footer + 1024].copy_from_slice(&slot);

        let g = BlockGeometry::new(7, block_offset, BLOCK, MIB, block_offset + BLOCK).unwrap();
        let r = MemReader::new(data);
        let idx = read_block_index(&r, &p, g).unwrap();
        assert_eq!(idx.clips.len(), 1);
        assert_eq!(
            idx.clips[0].clip_region.offset,
            block_offset + 0x8000,
            "clipStart must be blockOffset + startOffset"
        );
        assert_eq!(idx.clips[0].block_number, 7);
        assert_eq!(idx.clips[0].block_offset, block_offset);
    }
}
