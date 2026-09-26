//! # Dahua DHFS 4.1 fixture builders
//!
//! Reusable, **format-accurate** builders for every Dahua structure, plus a composer that lays
//! them out into a complete synthetic DHFS 4.1 disk image.
//!
//! ```text
//!   pack_timestamp        packed base-2000 wall clock
//!   build_dhav_frame      24-byte header + TLV extra header + payload + 8-byte trailer
//!   build_dhii            "DHII" + header array + frame-index arrays
//!   build_block_entry     the 32-byte block-table entry
//!   build_partition_table the 0x3C00 table with its AA55AA55 identifier
//!   build_dhfs41_image    all of the above, laid out and offset-reported
//! ```
//!
//! ## Why builders rather than byte arrays
//!
//! A hand-written byte array encodes one layout at one moment and drifts silently the first
//! time a field moves. These builders write the structures from their field definitions, and
//! [`build_dhfs41_image`] returns a [`DhfsImage`] carrying the **exact offsets** it produced, so
//! a test asserts against the layout that was actually built rather than against copied
//! constants.
//!
//! ## These are synthetic, and that is a limitation
//!
//! Everything here is labelled `synthetic`. A synthetic image proves the parser reads the
//! structures it is given; it does **not** prove compatibility with any particular Dahua
//! firmware. Only an image from a real recorder can do that. Tests that need that distinction
//! should say which they are using.

use std::collections::BTreeMap;

/// The label every fixture from this module carries. Never real OEM evidence.
pub const LABEL: &str = "synthetic";

/// DHFS addresses its structures in 512-byte sectors.
pub const SECTOR: u64 = 512;
/// One video block.
pub const VIDEO_BLOCK: u64 = 2 * 1024 * 1024;
/// One block-table entry.
pub const BLOCK_ENTRY_SIZE: u64 = 32;
/// Primary partition-table offset.
pub const PARTITION_TABLE_PRIMARY: u64 = 0x3C00;
/// Secondary partition-table candidate offsets.
pub const PARTITION_TABLE_SECONDARY_A: u64 = 0x3E00;
pub const PARTITION_TABLE_SECONDARY_B: u64 = 0x7C00;
/// Byte offset of the partition-table identifier within the table.
pub const PARTITION_TABLE_IDENTIFIER_OFFSET: u64 = 304;
/// Stride between partition-table entries.
pub const PARTITION_ENTRY_STRIDE: u64 = 64;
/// The recognised DHFS 4.1 volume signature.
pub const DHFS41_SIGNATURE: &[u8] = b"DHFS4.1\0";
/// The two known partition-table identifiers.
pub const PARTITION_ID_GEN0: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0xAA, 0x55, 0xAA, 0x55];
pub const PARTITION_ID_GEN1: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0xAA, 0x55, 0xAA, 0x55];
/// Base year of the packed timestamp encoding.
pub const TIMESTAMP_BASE_YEAR: i32 = 2000;

/// Frame type discriminators.
pub const FRAME_TYPE_VIDEO_KEY: u8 = 0xFD;
pub const FRAME_TYPE_VIDEO_DELTA: u8 = 0xFC;
pub const FRAME_TYPE_AUDIO: u8 = 0xF0;
pub const FRAME_TYPE_INFO: u8 = 0xF1;

/// Extra-header codec identifiers.
pub const CODEC_MPEG4: u8 = 0x01;
pub const CODEC_H264: u8 = 0x04;
pub const CODEC_MJPEG: u8 = 0x03;
pub const CODEC_H265: u8 = 0x0C;

/// DHII entry-array types.
pub const DHII_TYPE_REFERENCE_FRAMES: u32 = 1;
pub const DHII_TYPE_JPEG_FRAMES: u32 = 3;
pub const DHII_TYPE_JSON_JPEG: u32 = 4;
pub const DHII_TYPE_UNKNOWN_ENTRIES: u32 = 6;

// ── Timestamps ───────────────────────────────────────────────────────────────

/// Encode wall-clock digits into the packed base-2000 representation.
///
/// Panics on digits the encoding cannot represent, so a fixture can never silently claim a time
/// it does not encode. Use [`try_pack_timestamp`] where an invalid value is the point of the
/// test.
pub fn pack_timestamp(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> u32 {
    try_pack_timestamp(year, month, day, hour, minute, second).unwrap_or_else(|| {
        panic!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02} is not representable"
        )
    })
}

/// Fallible form of [`pack_timestamp`].
pub fn try_pack_timestamp(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<u32> {
    let year_field = year.checked_sub(TIMESTAMP_BASE_YEAR)?;
    if !(0..=63).contains(&year_field)
        || !(1..=15).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 31
        || minute > 63
        || second > 63
    {
        return None;
    }
    Some(
        ((year_field as u32) << 26)
            | (month << 22)
            | (day << 17)
            | (hour << 12)
            | (minute << 6)
            | second,
    )
}

// ── Elementary stream payloads ───────────────────────────────────────────────

/// A genuine H.264 Annex-B payload: SPS, PPS, IDR, then P-slices.
///
/// Real parameter sets are required, not decorative: the platform's codec classifier only
/// reports `Pass` on actual SPS/PPS NAL headers, so a fixture built from arbitrary bytes could
/// never reach a validated state and a test using one would prove nothing.
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

/// A genuine H.265 Annex-B payload: VPS, SPS, PPS, IDR.
pub fn h265_payload(seed: u8) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x0C, 0x01, seed]);
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x42, 0x01, 0x01, 0x01, 0x60]);
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x44, 0x01, 0xC1, 0x72]);
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x26, 0x01, seed, 0x00]);
    v
}

// ── DHAV frames ──────────────────────────────────────────────────────────────

/// A DHAV frame's fields. Every corruption knob is explicit, so a malformed fixture is
/// malformed on purpose and says how.
#[derive(Debug, Clone)]
pub struct DhavFrameSpec {
    pub frame_type: u8,
    pub subtype: u8,
    /// Channel as stored: 0-based.
    pub channel_0_based: u16,
    pub frame_number: u32,
    pub packed_timestamp: u32,
    pub sub_timestamp: u16,
    pub checksum: u8,
    /// Extra-header TLV records, already encoded. Use the `with_*` helpers.
    pub extra: Vec<u8>,
    pub payload: Vec<u8>,
    /// Override the declared total length, to build a structurally invalid frame.
    pub declared_total_length: Option<i32>,
    /// Write a wrong trailer tag.
    pub corrupt_trailer_tag: bool,
    /// Write a wrong trailer back-reference length.
    pub trailer_length_override: Option<u32>,
}

impl DhavFrameSpec {
    /// A video key frame carrying real H.264, on 1-based `channel`, at the given wall clock.
    #[allow(clippy::too_many_arguments)]
    pub fn video_key(
        channel_1_based: u32,
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
        seed: u8,
    ) -> Self {
        Self {
            frame_type: FRAME_TYPE_VIDEO_KEY,
            subtype: 0x01,
            channel_0_based: channel_1_based.saturating_sub(1) as u16,
            frame_number: 1,
            packed_timestamp: pack_timestamp(year, month, day, hour, minute, second),
            sub_timestamp: 0,
            checksum: 0,
            extra: Vec::new(),
            payload: h264_payload(seed),
            declared_total_length: None,
            corrupt_trailer_tag: false,
            trailer_length_override: None,
        }
    }

    pub fn frame_type(mut self, v: u8) -> Self {
        self.frame_type = v;
        self
    }

    pub fn frame_number(mut self, v: u32) -> Self {
        self.frame_number = v;
        self
    }

    pub fn sub_timestamp(mut self, v: u16) -> Self {
        self.sub_timestamp = v;
        self
    }

    pub fn payload(mut self, bytes: Vec<u8>) -> Self {
        self.payload = bytes;
        self
    }

    pub fn raw_timestamp(mut self, packed: u32) -> Self {
        self.packed_timestamp = packed;
        self
    }

    /// Append the `0x82` exact-resolution record.
    pub fn with_resolution(mut self, width: u16, height: u16) -> Self {
        self.extra.extend_from_slice(&[0x82, 0, 0, 0]);
        self.extra.extend_from_slice(&width.to_le_bytes());
        self.extra.extend_from_slice(&height.to_le_bytes());
        self
    }

    /// Append the `0x81` codec record.
    pub fn with_codec(mut self, codec_id: u8, fps: u8) -> Self {
        self.extra.extend_from_slice(&[0x81, 0, codec_id, fps]);
        self
    }

    /// Declare a total length the frame does not have.
    pub fn with_declared_total_length(mut self, v: i32) -> Self {
        self.declared_total_length = Some(v);
        self
    }

    pub fn with_corrupt_trailer_tag(mut self) -> Self {
        self.corrupt_trailer_tag = true;
        self
    }

    pub fn with_trailer_length(mut self, v: u32) -> Self {
        self.trailer_length_override = Some(v);
        self
    }

    /// The frame's real serialized length.
    pub fn total_length(&self) -> usize {
        24 + self.extra.len() + self.payload.len() + 8
    }

    /// Byte offset of the payload from the frame start: `24 + extra header length`.
    pub fn payload_offset(&self) -> usize {
        24 + self.extra.len()
    }
}

/// Serialize a DHAV frame.
pub fn build_dhav_frame(spec: &DhavFrameSpec) -> Vec<u8> {
    let total = spec.total_length();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(b"DHAV");
    out.push(spec.frame_type);
    out.push(spec.subtype);
    out.extend_from_slice(&spec.channel_0_based.to_le_bytes());
    out.extend_from_slice(&spec.frame_number.to_le_bytes());
    out.extend_from_slice(
        &spec
            .declared_total_length
            .unwrap_or(total as i32)
            .to_le_bytes(),
    );
    out.extend_from_slice(&spec.packed_timestamp.to_le_bytes());
    out.extend_from_slice(&spec.sub_timestamp.to_le_bytes());
    out.push(spec.extra.len() as u8);
    out.push(spec.checksum);
    assert_eq!(out.len(), 24, "the DHAV fixed header is 24 bytes");
    out.extend_from_slice(&spec.extra);
    out.extend_from_slice(&spec.payload);
    if spec.corrupt_trailer_tag {
        out.extend_from_slice(b"XXXX");
    } else {
        out.extend_from_slice(b"dhav");
    }
    out.extend_from_slice(
        &spec
            .trailer_length_override
            .unwrap_or((total - 8) as u32)
            .to_le_bytes(),
    );
    assert_eq!(out.len(), total);
    out
}

// ── DHII frame index ─────────────────────────────────────────────────────────

/// One entry array inside a DHII index.
#[derive(Debug, Clone)]
pub struct DhiiArraySpec {
    pub raw_type: u32,
    /// `(clip_relative_frame_offset, frame_length, packed_timestamp)` per entry.
    pub entries: Vec<(u32, i32, u32)>,
}

/// Serialize a DHII index destined for clip-relative offset `base`.
///
/// Array offsets are written clip-relative, as the format specifies, which is why `base` has to
/// be supplied rather than assumed to be zero.
pub fn build_dhii(arrays: &[DhiiArraySpec], base: u32) -> Vec<u8> {
    let header_size = 12usize;
    let hdr_entry_size = 12usize;
    let entry_size = 12usize;
    let header_total = header_size + arrays.len() * hdr_entry_size;
    let arrays_total: usize = arrays.iter().map(|a| a.entries.len() * entry_size).sum();
    let index_length = header_total + arrays_total;

    let mut out = vec![0u8; index_length];
    out[..4].copy_from_slice(b"DHII");
    out[4..8].copy_from_slice(&(index_length as u32).to_le_bytes());
    out[8..12].copy_from_slice(&(arrays.len() as i32).to_le_bytes());

    let mut cursor = header_total;
    for (i, array) in arrays.iter().enumerate() {
        let h = header_size + i * hdr_entry_size;
        let len = array.entries.len() * entry_size;
        out[h..h + 4].copy_from_slice(&array.raw_type.to_le_bytes());
        out[h + 4..h + 8].copy_from_slice(&(base + cursor as u32).to_le_bytes());
        out[h + 8..h + 12].copy_from_slice(&(len as u32).to_le_bytes());
        for (j, (off, length, ts)) in array.entries.iter().enumerate() {
            let e = cursor + j * entry_size;
            out[e..e + 4].copy_from_slice(&off.to_le_bytes());
            out[e + 4..e + 8].copy_from_slice(&length.to_le_bytes());
            out[e + 8..e + 12].copy_from_slice(&ts.to_le_bytes());
        }
        cursor += len;
    }
    out
}

// ── Block table ──────────────────────────────────────────────────────────────

/// A block-table entry's fields.
#[derive(Debug, Clone)]
pub struct BlockEntrySpec {
    pub type_byte: u8,
    /// Legacy channel as stored: the nibble is `channel - 1`.
    pub legacy_channel_1_based: u8,
    /// When set, the extended-channel flag is raised and this value is written at `+31`.
    pub extended_channel: Option<u8>,
    pub start_timestamp: u32,
    pub end_timestamp: u32,
    pub next_block: i32,
    pub sector_count: i16,
    pub previous_block: i32,
    pub first_block: i32,
}

impl BlockEntrySpec {
    /// An unused slot.
    pub fn empty() -> Self {
        Self {
            type_byte: 0xFE,
            legacy_channel_1_based: 1,
            extended_channel: None,
            start_timestamp: 0,
            end_timestamp: 0,
            next_block: 0,
            sector_count: 0,
            previous_block: 0,
            first_block: 0,
        }
    }

    /// An occupied slot on `channel` (1-based).
    pub fn occupied(channel_1_based: u8) -> Self {
        Self {
            type_byte: 0x01,
            legacy_channel_1_based: channel_1_based,
            extended_channel: None,
            start_timestamp: 0,
            end_timestamp: 0,
            next_block: 0,
            sector_count: 0,
            previous_block: 0,
            first_block: 0,
        }
    }

    pub fn is_empty_slot(&self) -> bool {
        self.type_byte == 0xFE || self.type_byte == 0x00
    }

    pub fn extended_channel(mut self, channel: u8) -> Self {
        self.extended_channel = Some(channel);
        self
    }

    pub fn span(mut self, start: u32, end: u32) -> Self {
        self.start_timestamp = start;
        self.end_timestamp = end;
        self
    }

    pub fn links(mut self, first: i32, previous: i32, next: i32) -> Self {
        self.first_block = first;
        self.previous_block = previous;
        self.next_block = next;
        self
    }

    pub fn sector_count(mut self, v: i16) -> Self {
        self.sector_count = v;
        self
    }

    pub fn type_byte(mut self, v: u8) -> Self {
        self.type_byte = v;
        self
    }
}

/// Serialize a 32-byte block-table entry.
pub fn build_block_entry(spec: &BlockEntrySpec) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = spec.type_byte;
    b[1] = spec.legacy_channel_1_based.saturating_sub(1) & 0x0F;
    b[4..8].copy_from_slice(&spec.start_timestamp.to_le_bytes());
    b[8..12].copy_from_slice(&spec.end_timestamp.to_le_bytes());
    b[12..16].copy_from_slice(&spec.next_block.to_le_bytes());
    b[16..18].copy_from_slice(&spec.sector_count.to_le_bytes());
    b[20..24].copy_from_slice(&spec.previous_block.to_le_bytes());
    b[24..28].copy_from_slice(&spec.first_block.to_le_bytes());
    if let Some(ext) = spec.extended_channel {
        b[29] |= 0x01;
        b[31] = ext & 0x1F;
    }
    b
}

/// Serialize a 512-byte partition table with one entry per partition.
pub fn build_partition_table(identifier: [u8; 8], entries: &[(i32, i64)]) -> Vec<u8> {
    let mut t = vec![0u8; 512];
    t[PARTITION_TABLE_IDENTIFIER_OFFSET as usize..PARTITION_TABLE_IDENTIFIER_OFFSET as usize + 8]
        .copy_from_slice(&identifier);
    for (slot, (info_sector, start_sector)) in entries.iter().enumerate() {
        let e = slot * PARTITION_ENTRY_STRIDE as usize;
        assert!(
            e + 56 <= t.len(),
            "a partition table holds at most 4 entries"
        );
        t[e + 20..e + 24].copy_from_slice(&info_sector.to_le_bytes());
        t[e + 48..e + 56].copy_from_slice(&start_sector.to_le_bytes());
    }
    t
}

// ── Whole-image composition ──────────────────────────────────────────────────

/// What a video block holds.
#[derive(Debug, Clone)]
pub enum BlockContent {
    /// Nothing; the block's bytes stay zero.
    Empty,
    /// Frames written back to back from the block start.
    Frames(Vec<DhavFrameSpec>),
    /// A DHII index at the block start, then frames at explicit block-relative offsets.
    ///
    /// `index_types` declares which arrays the index carries; the reference-frame array is
    /// populated from `frames`, and any other declared type gets an empty array, which is how a
    /// real multi-type index looks when only reference frames are present.
    IndexedFrames {
        /// `(block_relative_offset, frame)` — offsets must clear the index structure.
        frames: Vec<(u32, DhavFrameSpec)>,
        index_types: Vec<u32>,
    },
}

/// One block's table entry plus its payload.
#[derive(Debug, Clone)]
pub struct BlockSpec {
    pub entry: BlockEntrySpec,
    pub content: BlockContent,
}

impl BlockSpec {
    pub fn empty() -> Self {
        Self {
            entry: BlockEntrySpec::empty(),
            content: BlockContent::Empty,
        }
    }

    pub fn new(entry: BlockEntrySpec, content: BlockContent) -> Self {
        Self { entry, content }
    }
}

/// One partition's geometry and blocks.
#[derive(Debug, Clone)]
pub struct PartitionSpec {
    /// `SectorOfPartitionStart`.
    pub start_sector: i64,
    /// `SectorOfPartitionInfoInPartition`.
    pub info_sector: i32,
    /// `IndexStartSector`.
    pub index_start_sector: i32,
    /// `VideoStartSector`.
    pub video_start_sector: i32,
    /// Override the declared `BlockCount`, to build an inconsistent partition.
    pub declared_block_count: Option<i32>,
    pub blocks: Vec<BlockSpec>,
}

impl PartitionSpec {
    /// A partition at `start_sector` with a conventional internal layout.
    pub fn new(start_sector: i64, blocks: Vec<BlockSpec>) -> Self {
        Self {
            start_sector,
            info_sector: 1,
            index_start_sector: 2,
            video_start_sector: 64,
            declared_block_count: None,
            blocks,
        }
    }

    pub fn with_declared_block_count(mut self, v: i32) -> Self {
        self.declared_block_count = Some(v);
        self
    }

    pub fn with_internal_layout(
        mut self,
        info_sector: i32,
        index_start_sector: i32,
        video_start_sector: i32,
    ) -> Self {
        self.info_sector = info_sector;
        self.index_start_sector = index_start_sector;
        self.video_start_sector = video_start_sector;
        self
    }
}

/// A whole synthetic DHFS 4.1 image.
#[derive(Debug, Clone)]
pub struct DhfsImageSpec {
    /// Volume signature. Override to build an unsupported variant or a malformed header.
    pub signature: Vec<u8>,
    pub model: String,
    pub serial: String,
    pub volume_label: String,
    /// Write the primary partition table.
    pub primary_partition_table: bool,
    /// Identifier for the primary table.
    pub primary_identifier: [u8; 8],
    /// Also write a secondary partition table, which downgrades every chain to available.
    pub secondary_partition_table: bool,
    pub partitions: Vec<PartitionSpec>,
    /// Frames placed outside any partition's video region — unindexed video in slack.
    ///
    /// `(absolute_offset, frame)`. The composer grows the image to hold them.
    pub loose_frames: Vec<(u64, DhavFrameSpec)>,
    /// Extra zeroed bytes appended after everything else.
    pub trailing_slack: u64,
}

impl Default for DhfsImageSpec {
    fn default() -> Self {
        Self {
            signature: DHFS41_SIGNATURE.to_vec(),
            model: "DHI-XVR5216AN".to_string(),
            serial: "SYNTH0000000001".to_string(),
            volume_label: "DVR_REC_VOL0".to_string(),
            primary_partition_table: true,
            primary_identifier: PARTITION_ID_GEN1,
            secondary_partition_table: false,
            partitions: Vec::new(),
            loose_frames: Vec::new(),
            trailing_slack: 0,
        }
    }
}

/// Where one block ended up, and what is inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockLayout {
    pub block_number: u32,
    /// Absolute offset of the block's payload area.
    pub offset: u64,
    /// Absolute offset of the block's 32-byte table entry.
    pub entry_offset: u64,
    /// Bytes of the block the entry says belong to its recording. `None` for an empty slot or an
    /// entry whose length the format leaves undetermined.
    pub claimed_length: Option<u64>,
    /// Absolute offsets of the frames written into the block, in write order.
    pub frame_offsets: Vec<u64>,
    /// Absolute offset of the block's DHII index, when it carries one.
    pub dhii_offset: Option<u64>,
}

/// Where one partition ended up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionLayout {
    pub number: u32,
    pub start_offset: u64,
    pub info_offset: u64,
    pub block_table_offset: u64,
    pub video_base: u64,
    pub declared_block_count: i32,
    pub blocks: Vec<BlockLayout>,
}

impl PartitionLayout {
    /// The block layout for a block number.
    pub fn block(&self, block_number: u32) -> Option<&BlockLayout> {
        self.blocks.iter().find(|b| b.block_number == block_number)
    }
}

/// A built synthetic DHFS 4.1 image and the exact layout it produced.
#[derive(Debug, Clone)]
pub struct DhfsImage {
    /// Always `"synthetic"`. This is not real OEM evidence.
    pub label: &'static str,
    pub bytes: Vec<u8>,
    pub partitions: Vec<PartitionLayout>,
    /// Absolute offsets of the frames placed outside any partition.
    pub loose_frame_offsets: Vec<u64>,
    /// Offsets the partition tables were written at.
    pub partition_table_offsets: Vec<u64>,
}

impl DhfsImage {
    pub fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Write the image to a directory and return the path.
    pub fn write_to_dir(
        &self,
        dir: &std::path::Path,
        name: &str,
    ) -> std::io::Result<std::path::PathBuf> {
        let path = dir.join(name);
        std::fs::write(&path, &self.bytes)?;
        Ok(path)
    }

    /// The layout for a partition number.
    pub fn partition(&self, number: u32) -> Option<&PartitionLayout> {
        self.partitions.iter().find(|p| p.number == number)
    }

    /// Every block that carries a claimed length, as `(absolute_offset, length)`.
    pub fn claimed_block_regions(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        for p in &self.partitions {
            for b in &p.blocks {
                if let Some(len) = b.claimed_length {
                    out.push((b.offset, len));
                }
            }
        }
        out.sort_unstable();
        out
    }
}

/// Lay out a complete synthetic DHFS 4.1 image.
///
/// Offsets are computed from the spec's own sector numbers, and the returned [`DhfsImage`]
/// reports every one of them, so a test never has to recompute the layout it asked for.
pub fn build_dhfs41_image(spec: &DhfsImageSpec) -> DhfsImage {
    // ── Size the image from the spec ─────────────────────────────────────────
    let mut required: u64 = PARTITION_TABLE_SECONDARY_B + 512;
    let mut partition_bases: Vec<(u64, u64, u64, u64, i32)> = Vec::new();
    for p in &spec.partitions {
        let base = p.start_sector.max(0) as u64 * SECTOR;
        let info = base + p.info_sector.max(0) as u64 * SECTOR;
        let table = base + p.index_start_sector.max(0) as u64 * SECTOR;
        let video = base + p.video_start_sector.max(0) as u64 * SECTOR;
        let declared = p.declared_block_count.unwrap_or(p.blocks.len() as i32);
        required = required
            .max(info + 512)
            .max(table + p.blocks.len() as u64 * BLOCK_ENTRY_SIZE)
            .max(video + p.blocks.len() as u64 * VIDEO_BLOCK);
        partition_bases.push((base, info, table, video, declared));
    }
    for (offset, frame) in &spec.loose_frames {
        required = required.max(offset + frame.total_length() as u64);
    }
    required += spec.trailing_slack;
    // Round up to a whole sector so the image looks like a block device dump.
    let total = required.div_ceil(SECTOR) * SECTOR;
    let mut b = vec![0u8; total as usize];

    // ── Volume signature and descriptors ────────────────────────────────────
    let sig_len = spec.signature.len().min(b.len());
    b[..sig_len].copy_from_slice(&spec.signature[..sig_len]);
    write_ascii(&mut b, 48, 16, &spec.model);
    write_ascii(&mut b, 64, 32, &spec.serial);
    write_ascii(&mut b, 96, 16, &spec.volume_label);

    // ── Partition tables ────────────────────────────────────────────────────
    let entries: Vec<(i32, i64)> = spec
        .partitions
        .iter()
        .map(|p| (p.info_sector, p.start_sector))
        .collect();
    let mut partition_table_offsets = Vec::new();
    if spec.primary_partition_table {
        let table = build_partition_table(spec.primary_identifier, &entries);
        let at = PARTITION_TABLE_PRIMARY as usize;
        b[at..at + table.len()].copy_from_slice(&table);
        partition_table_offsets.push(PARTITION_TABLE_PRIMARY);
    }
    if spec.secondary_partition_table {
        let table = build_partition_table(PARTITION_ID_GEN0, &entries);
        let at = PARTITION_TABLE_SECONDARY_A as usize;
        b[at..at + table.len()].copy_from_slice(&table);
        partition_table_offsets.push(PARTITION_TABLE_SECONDARY_A);
    }

    // ── Partition information, block tables, and video blocks ───────────────
    let mut partitions: Vec<PartitionLayout> = Vec::new();
    for (i, p) in spec.partitions.iter().enumerate() {
        let (base, info_offset, table_offset, video_base, declared) = partition_bases[i];

        let io = info_offset as usize;
        b[io + 68..io + 72].copy_from_slice(&p.index_start_sector.to_le_bytes());
        b[io + 72..io + 76].copy_from_slice(&p.video_start_sector.to_le_bytes());
        b[io + 76..io + 80].copy_from_slice(&declared.to_le_bytes());

        let mut blocks: Vec<BlockLayout> = Vec::new();
        for (n, block) in p.blocks.iter().enumerate() {
            let entry_offset = table_offset + n as u64 * BLOCK_ENTRY_SIZE;
            let eo = entry_offset as usize;
            b[eo..eo + 32].copy_from_slice(&build_block_entry(&block.entry));

            let block_offset = video_base + n as u64 * VIDEO_BLOCK;
            let (frame_offsets, dhii_offset) =
                write_block_content(&mut b, block_offset, &block.content);

            // The claimed length follows the format's own rule: a last block is
            // `sectorCount * 512`, every other block is a whole block.
            let claimed_length = if block.entry.is_empty_slot() {
                None
            } else if block.entry.next_block == 0 {
                if block.entry.sector_count > 0 {
                    Some((block.entry.sector_count as u64 * SECTOR).min(VIDEO_BLOCK))
                } else {
                    None
                }
            } else {
                Some(VIDEO_BLOCK)
            };

            blocks.push(BlockLayout {
                block_number: n as u32,
                offset: block_offset,
                entry_offset,
                claimed_length,
                frame_offsets,
                dhii_offset,
            });
        }

        partitions.push(PartitionLayout {
            number: i as u32,
            start_offset: base,
            info_offset,
            block_table_offset: table_offset,
            video_base,
            declared_block_count: declared,
            blocks,
        });
    }

    // ── Loose frames outside any partition ──────────────────────────────────
    let mut loose_frame_offsets = Vec::new();
    for (offset, frame) in &spec.loose_frames {
        let bytes = build_dhav_frame(frame);
        let at = *offset as usize;
        b[at..at + bytes.len()].copy_from_slice(&bytes);
        loose_frame_offsets.push(*offset);
    }

    DhfsImage {
        label: LABEL,
        bytes: b,
        partitions,
        loose_frame_offsets,
        partition_table_offsets,
    }
}

/// Write a block's content and report where its frames and index landed.
fn write_block_content(
    b: &mut [u8],
    block_offset: u64,
    content: &BlockContent,
) -> (Vec<u64>, Option<u64>) {
    match content {
        BlockContent::Empty => (Vec::new(), None),
        BlockContent::Frames(frames) => {
            let mut offsets = Vec::new();
            let mut cursor = block_offset as usize;
            for f in frames {
                let bytes = build_dhav_frame(f);
                assert!(
                    cursor + bytes.len() <= (block_offset + VIDEO_BLOCK) as usize,
                    "block at 0x{block_offset:X} overflows: frames do not fit in one video block"
                );
                b[cursor..cursor + bytes.len()].copy_from_slice(&bytes);
                offsets.push(cursor as u64);
                cursor += bytes.len();
            }
            (offsets, None)
        }
        BlockContent::IndexedFrames {
            frames,
            index_types,
        } => {
            let arrays: Vec<DhiiArraySpec> = index_types
                .iter()
                .map(|t| DhiiArraySpec {
                    raw_type: *t,
                    entries: if *t == DHII_TYPE_REFERENCE_FRAMES {
                        frames
                            .iter()
                            .map(|(off, f)| (*off, f.total_length() as i32, f.packed_timestamp))
                            .collect()
                    } else {
                        Vec::new()
                    },
                })
                .collect();
            let index = build_dhii(&arrays, 0);
            let base = block_offset as usize;
            b[base..base + index.len()].copy_from_slice(&index);

            let mut offsets = Vec::new();
            for (off, f) in frames {
                assert!(
                    *off as usize >= index.len(),
                    "a frame at block-relative {off} would overlap the {}-byte DHII index",
                    index.len()
                );
                let bytes = build_dhav_frame(f);
                let at = base + *off as usize;
                assert!(
                    at + bytes.len() <= (block_offset + VIDEO_BLOCK) as usize,
                    "a frame at block-relative {off} overflows its video block"
                );
                b[at..at + bytes.len()].copy_from_slice(&bytes);
                offsets.push(at as u64);
            }
            (offsets, Some(block_offset))
        }
    }
}

fn write_ascii(b: &mut [u8], offset: usize, width: usize, text: &str) {
    let bytes = text.as_bytes();
    let n = bytes.len().min(width);
    if offset + n <= b.len() {
        b[offset..offset + n].copy_from_slice(&bytes[..n]);
    }
}

// ── Ready-made scenarios ─────────────────────────────────────────────────────

/// A realistic single-partition XVR volume:
///
/// * channel 1: a two-block recording, blocks 1 → 2, the second partially filled;
/// * channel 2: a one-block recording in block 3, carrying a DHII reference index;
/// * block 4: occupied and fully described, but reachable from no first block — the
///   *available* case;
/// * block 5: an empty slot;
/// * one loose frame in trailing slack, outside every partition — unindexed video.
///
/// Returns the image plus a description of what each element is for, so a test that asserts on
/// it does not have to restate the intent.
pub fn realistic_xvr_volume() -> DhfsImage {
    let ch1_start = pack_timestamp(2026, 9, 22, 8, 0, 0);
    let ch1_mid = pack_timestamp(2026, 9, 22, 8, 5, 0);
    let ch1_end = pack_timestamp(2026, 9, 22, 8, 10, 0);
    let ch2_start = pack_timestamp(2026, 9, 22, 9, 0, 0);
    let ch2_end = pack_timestamp(2026, 9, 22, 9, 3, 0);
    let ch3_start = pack_timestamp(2026, 9, 22, 7, 0, 0);
    let ch3_end = pack_timestamp(2026, 9, 22, 7, 2, 0);

    let ch2_frames = vec![
        (
            0x1_0000u32,
            DhavFrameSpec::video_key(2, 2026, 9, 22, 9, 0, 0, 0x21)
                .frame_number(1)
                .with_resolution(1920, 1080)
                .with_codec(CODEC_H264, 25),
        ),
        (
            0x2_0000u32,
            DhavFrameSpec::video_key(2, 2026, 9, 22, 9, 1, 30, 0x22)
                .frame_number(2)
                .with_resolution(1920, 1080)
                .with_codec(CODEC_H264, 25),
        ),
    ];

    let blocks = vec![
        // Block 0: unused.
        BlockSpec::empty(),
        // Block 1: head of the channel-1 recording, full block.
        BlockSpec::new(
            BlockEntrySpec::occupied(1)
                .span(ch1_start, ch1_mid)
                .links(1, 0, 2),
            BlockContent::Frames(vec![
                DhavFrameSpec::video_key(1, 2026, 9, 22, 8, 0, 0, 0x11)
                    .frame_number(1)
                    .with_resolution(1280, 720)
                    .with_codec(CODEC_H264, 15),
                DhavFrameSpec::video_key(1, 2026, 9, 22, 8, 2, 30, 0x12)
                    .frame_number(2)
                    .with_resolution(1280, 720)
                    .with_codec(CODEC_H264, 15),
            ]),
        ),
        // Block 2: tail of the channel-1 recording, partially filled (512 sectors).
        BlockSpec::new(
            BlockEntrySpec::occupied(1)
                .span(ch1_mid, ch1_end)
                .links(1, 1, 0)
                .sector_count(512),
            BlockContent::Frames(vec![DhavFrameSpec::video_key(
                1, 2026, 9, 22, 8, 7, 0, 0x13,
            )
            .frame_number(3)
            .with_resolution(1280, 720)
            .with_codec(CODEC_H264, 15)]),
        ),
        // Block 3: a one-block channel-2 recording carrying its own DHII index.
        BlockSpec::new(
            BlockEntrySpec::occupied(2)
                .span(ch2_start, ch2_end)
                .links(3, 0, 0)
                .sector_count(1024),
            BlockContent::IndexedFrames {
                frames: ch2_frames,
                index_types: vec![DHII_TYPE_REFERENCE_FRAMES, DHII_TYPE_JPEG_FRAMES],
            },
        ),
        // Block 4: occupied, fully described, but no first-block traversal reaches it.
        BlockSpec::new(
            BlockEntrySpec::occupied(3)
                .span(ch3_start, ch3_end)
                // PreviousBlock points at a block that is not part of any chain, so this block
                // is a valid member of a recording whose head is gone.
                .links(0, 9, 0)
                .sector_count(256),
            BlockContent::Frames(vec![DhavFrameSpec::video_key(
                3, 2026, 9, 22, 7, 0, 0, 0x31,
            )
            .frame_number(1)
            .with_resolution(704, 576)
            .with_codec(CODEC_H264, 12)]),
        ),
        // Block 5: an unused slot, which is not a deletion marker.
        BlockSpec::empty(),
    ];

    let partition = PartitionSpec::new(128, blocks);
    // Somewhere past the partition's video region: video with no metadata describing it.
    let loose_at = 128 * SECTOR + 64 * SECTOR + 6 * VIDEO_BLOCK + 0x1000;
    let spec = DhfsImageSpec {
        partitions: vec![partition],
        loose_frames: vec![(
            loose_at,
            DhavFrameSpec::video_key(4, 2026, 9, 22, 6, 30, 0, 0x41)
                .frame_number(1)
                .with_codec(CODEC_H264, 15),
        )],
        trailing_slack: 4 * SECTOR,
        ..Default::default()
    };
    build_dhfs41_image(&spec)
}

/// Descriptive names for the elements of [`realistic_xvr_volume`], so tests can refer to them
/// without magic block numbers.
pub mod realistic {
    /// Head block of the accessible channel-1 recording.
    pub const CH1_HEAD_BLOCK: u32 = 1;
    /// Tail block of the accessible channel-1 recording.
    pub const CH1_TAIL_BLOCK: u32 = 2;
    /// The accessible channel-2 recording, which carries a DHII index.
    pub const CH2_BLOCK: u32 = 3;
    /// The available (surviving metadata, unreachable) channel-3 recording.
    pub const AVAILABLE_BLOCK: u32 = 4;
    /// An unused block-table slot.
    pub const EMPTY_BLOCK: u32 = 5;
    /// Chain id the parser assigns the channel-1 recording.
    pub const CH1_CHAIN_ID: &str = "dahua:p0:blk1";
    /// Chain id the parser assigns the channel-2 recording.
    pub const CH2_CHAIN_ID: &str = "dahua:p0:blk3";
    /// Chain id the parser assigns the recovered available recording.
    pub const AVAILABLE_CHAIN_ID: &str = "dahua:p0:blk4";
}

/// Aggregate `(offsets, lengths)` of the blocks belonging to each accessible chain in
/// [`realistic_xvr_volume`].
pub fn realistic_accessible_regions(image: &DhfsImage) -> BTreeMap<&'static str, Vec<(u64, u64)>> {
    let p = image.partition(0).expect("partition 0");
    let mut out: BTreeMap<&'static str, Vec<(u64, u64)>> = BTreeMap::new();
    let push = |id: &'static str, n: u32, map: &mut BTreeMap<&'static str, Vec<(u64, u64)>>| {
        if let Some(b) = p.block(n) {
            if let Some(len) = b.claimed_length {
                map.entry(id).or_default().push((b.offset, len));
            }
        }
    };
    push(realistic::CH1_CHAIN_ID, realistic::CH1_HEAD_BLOCK, &mut out);
    push(realistic::CH1_CHAIN_ID, realistic::CH1_TAIL_BLOCK, &mut out);
    push(realistic::CH2_CHAIN_ID, realistic::CH2_BLOCK, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_packed_timestamp_uses_the_documented_bit_layout() {
        let raw = pack_timestamp(2026, 9, 22, 14, 35, 7);
        assert_eq!((raw >> 26) & 0x3F, 26, "year field is year - 2000");
        assert_eq!((raw >> 22) & 0x0F, 9);
        assert_eq!((raw >> 17) & 0x1F, 22);
        assert_eq!((raw >> 12) & 0x1F, 14);
        assert_eq!((raw >> 6) & 0x3F, 35);
        assert_eq!(raw & 0x3F, 7);
    }

    #[test]
    fn a_built_dhav_frame_has_the_documented_framing() {
        let spec = DhavFrameSpec::video_key(1, 2026, 9, 22, 8, 0, 0, 1)
            .with_resolution(1920, 1080)
            .with_codec(CODEC_H264, 25);
        let bytes = build_dhav_frame(&spec);

        assert_eq!(&bytes[..4], b"DHAV");
        assert_eq!(bytes[4], FRAME_TYPE_VIDEO_KEY);
        assert_eq!(
            u16::from_le_bytes([bytes[6], bytes[7]]),
            0,
            "channel 1 is 0-based 0"
        );
        assert_eq!(
            u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize,
            bytes.len(),
            "the declared total length is the real length"
        );
        assert_eq!(bytes[22] as usize, spec.extra.len(), "extra header length");
        assert_eq!(spec.payload_offset(), 24 + 12);
        // The trailer is "dhav" plus a back-reference of total - 8.
        let n = bytes.len();
        assert_eq!(&bytes[n - 8..n - 4], b"dhav");
        assert_eq!(
            u32::from_le_bytes([bytes[n - 4], bytes[n - 3], bytes[n - 2], bytes[n - 1]]) as usize,
            n - 8
        );
    }

    #[test]
    fn a_built_block_entry_has_the_documented_field_layout() {
        let spec = BlockEntrySpec::occupied(3)
            .span(0x1111_1111, 0x2222_2222)
            .links(5, 4, 6)
            .sector_count(1024);
        let b = build_block_entry(&spec);
        assert_eq!(b[0], 0x01);
        assert_eq!(b[1] & 0x0F, 2, "channel 3 is stored as nibble 2");
        assert_eq!(u32::from_le_bytes([b[4], b[5], b[6], b[7]]), 0x1111_1111);
        assert_eq!(u32::from_le_bytes([b[8], b[9], b[10], b[11]]), 0x2222_2222);
        assert_eq!(i32::from_le_bytes([b[12], b[13], b[14], b[15]]), 6);
        assert_eq!(i16::from_le_bytes([b[16], b[17]]), 1024);
        assert_eq!(i32::from_le_bytes([b[20], b[21], b[22], b[23]]), 4);
        assert_eq!(i32::from_le_bytes([b[24], b[25], b[26], b[27]]), 5);
        assert_eq!(b[29] & 0x01, 0, "the extended flag is clear by default");
    }

    #[test]
    fn an_extended_channel_entry_raises_the_flag_and_writes_the_value() {
        let b = build_block_entry(&BlockEntrySpec::occupied(1).extended_channel(21));
        assert_eq!(b[29] & 0x01, 1);
        assert_eq!(b[31] & 0x1F, 21);
    }

    #[test]
    fn a_built_partition_table_carries_its_identifier_and_entries() {
        let t = build_partition_table(PARTITION_ID_GEN1, &[(1, 128), (3, 4096)]);
        assert_eq!(&t[304..312], &PARTITION_ID_GEN1);
        assert_eq!(i32::from_le_bytes([t[20], t[21], t[22], t[23]]), 1);
        assert_eq!(
            i64::from_le_bytes([t[48], t[49], t[50], t[51], t[52], t[53], t[54], t[55]]),
            128
        );
        // Slot 1 lives 64 bytes on.
        assert_eq!(i32::from_le_bytes([t[84], t[85], t[86], t[87]]), 3);
    }

    #[test]
    fn a_built_dhii_index_declares_its_own_length_and_arrays() {
        let arrays = vec![
            DhiiArraySpec {
                raw_type: DHII_TYPE_REFERENCE_FRAMES,
                entries: vec![(0x1000, 500, 1), (0x2000, 600, 2)],
            },
            DhiiArraySpec {
                raw_type: DHII_TYPE_JPEG_FRAMES,
                entries: vec![],
            },
        ];
        let idx = build_dhii(&arrays, 0);
        assert_eq!(&idx[..4], b"DHII");
        assert_eq!(
            u32::from_le_bytes([idx[4], idx[5], idx[6], idx[7]]) as usize,
            idx.len()
        );
        assert_eq!(i32::from_le_bytes([idx[8], idx[9], idx[10], idx[11]]), 2);
        // First header entry: type 1, array right after the header array, 24 bytes.
        assert_eq!(u32::from_le_bytes([idx[12], idx[13], idx[14], idx[15]]), 1);
        assert_eq!(u32::from_le_bytes([idx[16], idx[17], idx[18], idx[19]]), 36);
        assert_eq!(u32::from_le_bytes([idx[20], idx[21], idx[22], idx[23]]), 24);
    }

    #[test]
    fn dhii_array_offsets_are_written_clip_relative() {
        let arrays = vec![DhiiArraySpec {
            raw_type: DHII_TYPE_REFERENCE_FRAMES,
            entries: vec![(0x1000, 100, 1)],
        }];
        let at_zero = build_dhii(&arrays, 0);
        let at_base = build_dhii(&arrays, 0x8000);
        assert_eq!(
            u32::from_le_bytes([at_zero[16], at_zero[17], at_zero[18], at_zero[19]]) + 0x8000,
            u32::from_le_bytes([at_base[16], at_base[17], at_base[18], at_base[19]])
        );
    }

    #[test]
    fn the_realistic_volume_reports_the_layout_it_built() {
        let image = realistic_xvr_volume();
        assert_eq!(image.label, "synthetic");
        assert_eq!(&image.bytes[..8], DHFS41_SIGNATURE);
        assert_eq!(image.partition_table_offsets, vec![PARTITION_TABLE_PRIMARY]);

        let p = image.partition(0).expect("one partition");
        let base = 128 * SECTOR;
        assert_eq!(p.start_offset, base);
        assert_eq!(p.info_offset, base + SECTOR);
        assert_eq!(p.block_table_offset, base + 2 * SECTOR);
        assert_eq!(p.video_base, base + 64 * SECTOR);
        assert_eq!(p.declared_block_count, 6);
        assert_eq!(p.blocks.len(), 6);

        // Block offsets follow the documented addressing.
        for (n, b) in p.blocks.iter().enumerate() {
            assert_eq!(b.offset, p.video_base + n as u64 * VIDEO_BLOCK);
            assert_eq!(
                b.entry_offset,
                p.block_table_offset + n as u64 * BLOCK_ENTRY_SIZE
            );
        }

        // The two-block chain: full block then a 256 KiB tail.
        assert_eq!(
            p.block(realistic::CH1_HEAD_BLOCK).unwrap().claimed_length,
            Some(VIDEO_BLOCK)
        );
        assert_eq!(
            p.block(realistic::CH1_TAIL_BLOCK).unwrap().claimed_length,
            Some(512 * SECTOR)
        );
        // The DHII-bearing block reports its index offset.
        assert_eq!(
            p.block(realistic::CH2_BLOCK).unwrap().dhii_offset,
            Some(p.video_base + 3 * VIDEO_BLOCK)
        );
        assert_eq!(
            p.block(realistic::CH2_BLOCK).unwrap().frame_offsets.len(),
            2
        );
        // The empty slot holds nothing.
        assert!(p
            .block(realistic::EMPTY_BLOCK)
            .unwrap()
            .claimed_length
            .is_none());
        assert!(p
            .block(realistic::EMPTY_BLOCK)
            .unwrap()
            .frame_offsets
            .is_empty());

        // One loose frame outside every partition.
        assert_eq!(image.loose_frame_offsets.len(), 1);
        assert!(image.loose_frame_offsets[0] > p.video_base + 6 * VIDEO_BLOCK);
        assert!(image.len() > image.loose_frame_offsets[0]);
    }

    #[test]
    fn the_realistic_volume_is_deterministic() {
        assert_eq!(realistic_xvr_volume().bytes, realistic_xvr_volume().bytes);
    }

    #[test]
    fn accessible_region_helper_groups_blocks_by_chain() {
        let image = realistic_xvr_volume();
        let regions = realistic_accessible_regions(&image);
        assert_eq!(regions[realistic::CH1_CHAIN_ID].len(), 2);
        assert_eq!(regions[realistic::CH2_CHAIN_ID].len(), 1);
        // The available block is not in the accessible set.
        assert!(!regions.contains_key(realistic::AVAILABLE_CHAIN_ID));
    }

    #[test]
    fn a_secondary_table_can_be_requested() {
        let spec = DhfsImageSpec {
            partitions: vec![PartitionSpec::new(128, vec![BlockSpec::empty()])],
            secondary_partition_table: true,
            ..Default::default()
        };
        let image = build_dhfs41_image(&spec);
        assert_eq!(
            image.partition_table_offsets,
            vec![PARTITION_TABLE_PRIMARY, PARTITION_TABLE_SECONDARY_A]
        );
        assert_eq!(
            &image.bytes[PARTITION_TABLE_SECONDARY_A as usize + 304
                ..PARTITION_TABLE_SECONDARY_A as usize + 312],
            &PARTITION_ID_GEN0
        );
    }

    #[test]
    fn an_unsupported_signature_can_be_requested() {
        let spec = DhfsImageSpec {
            signature: b"DHFS9.9\0".to_vec(),
            partitions: vec![PartitionSpec::new(128, vec![BlockSpec::empty()])],
            ..Default::default()
        };
        let image = build_dhfs41_image(&spec);
        assert_eq!(&image.bytes[..8], b"DHFS9.9\0");
    }

    #[test]
    fn multiple_partitions_get_independent_geometry() {
        let spec = DhfsImageSpec {
            partitions: vec![
                PartitionSpec::new(128, vec![BlockSpec::empty()]),
                PartitionSpec::new(8192, vec![BlockSpec::empty(), BlockSpec::empty()])
                    .with_internal_layout(3, 8, 128),
            ],
            ..Default::default()
        };
        let image = build_dhfs41_image(&spec);
        assert_eq!(image.partitions.len(), 2);
        assert_eq!(image.partitions[0].start_offset, 128 * SECTOR);
        assert_eq!(image.partitions[1].start_offset, 8192 * SECTOR);
        assert_eq!(
            image.partitions[1].block_table_offset,
            8192 * SECTOR + 8 * SECTOR
        );
        assert_eq!(image.partitions[1].video_base, 8192 * SECTOR + 128 * SECTOR);
    }
}
