//! # DHFS 4.1 block table
//!
//! Each partition owns a block table: one 32-byte entry per 2 MiB video block, in block
//! order. The entry is both the allocation record and the link structure for recordings.
//!
//! ```text
//!   entry[n] @ block_table_base + n * 32
//!     +0   u8    type                 0xFE / 0x00 => empty
//!     +1   u8    legacy channel       (value & 0x0F) + 1
//!     +4   u32   start timestamp      packed, base year 2000
//!     +8   u32   end timestamp        packed, base year 2000
//!     +12  i32   NextBlock            -1 normalises to 0; < -1 is malformed
//!     +16  i16   sectorCount          length of a LAST block, in 512-byte sectors
//!     +20  i32   PreviousBlock
//!     +24  i32   FirstBlock
//!     +29  u8    extended-channel flag (bit 0)
//!     +31  u8    extended channel      (value & 0x1F)
//!
//!   block n payload @ video_base + n * 2097152
//! ```
//!
//! ## The rules this module encodes, verbatim
//!
//! * `IsLastBlock` ⇔ `NextBlock == 0`. Only the last block of a chain is partially filled.
//! * A last block's length is `sectorCount * 512`, capped at the 2 MiB block size.
//! * Every non-last block occupies its full 2 MiB.
//! * `IsFirstBlock` ⇔ `FirstBlock > 0 && BlockNumber == FirstBlock`.
//! * A block is valid ⇔ `IsFirstBlock || PreviousBlock != 0`.
//!
//! The last rule is why an unlinked-but-populated block is not discarded: it is
//! *invalid as a chain member* while still being physically present video. This module
//! classifies it and leaves the recovery decision to [`crate::chain`].

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, OemProfile, Region, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};

use crate::channel::DahuaChannel;
use crate::layout::{i16_at, i32_at, key, u32_at, u64_from, u8_at, u8_from, usize_from, vs};
use crate::timestamp::{DahuaTimestamp, TimestampStructure};

/// What the block table says about one block's occupancy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockState {
    /// The type byte marks the slot as empty/unused. No recording metadata applies.
    ///
    /// This is **not** a deletion marker. An empty slot is one the recorder has not
    /// written, or has returned to its pool; DHFS 4.1 as understood here carries no
    /// tombstone that distinguishes "never used" from "freed", so no deletion conclusion
    /// is available from this field.
    Empty { type_byte: u8 },
    /// The entry describes a block that participates in a chain.
    Occupied,
    /// The entry is populated but internally inconsistent. Retained, never trusted.
    Malformed { reason: String },
}

impl BlockState {
    pub fn is_empty(&self) -> bool {
        matches!(self, BlockState::Empty { .. })
    }
    pub fn is_occupied(&self) -> bool {
        matches!(self, BlockState::Occupied)
    }
    pub fn is_malformed(&self) -> bool {
        matches!(self, BlockState::Malformed { .. })
    }
}

/// One decoded 32-byte block-table entry.
///
/// Raw fields are kept alongside the normalized ones so an examiner can see, for example,
/// that `NextBlock` was stored as `-1` and normalized to `0` rather than wonder why a
/// terminator appeared.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockTableEntry {
    /// Block number within the partition, 0-based; also the table slot index.
    pub block_number: u32,
    /// Physical offset of the 32-byte entry, for provenance.
    pub entry_offset: u64,
    /// Physical offset of the block's 2 MiB payload area, when in bounds.
    pub block_offset: Option<u64>,
    /// The type byte at `+0`.
    pub type_byte: u8,
    /// Occupancy/consistency verdict.
    pub state: BlockState,
    /// Normalized channel, with the encoding that produced it.
    pub channel: DahuaChannel,
    /// Start timestamp, decoded or explicitly not.
    pub start_time: DahuaTimestamp,
    /// End timestamp, decoded or explicitly not.
    pub end_time: DahuaTimestamp,
    /// `NextBlock` as stored.
    pub raw_next_block: i32,
    /// `NextBlock` normalized: `-1` becomes `0` (chain terminator).
    pub next_block: i32,
    /// `sectorCount` as stored.
    pub sector_count: i16,
    pub previous_block: i32,
    pub first_block: i32,
    /// The extended-channel flag byte at `+29`.
    pub extended_flag_byte: u8,
    /// The extended-channel byte at `+31`.
    pub extended_channel_byte: u8,
    /// Physical length this block contributes to its recording, when determinable.
    pub physical_length: Option<u64>,
    /// The exact physical region this block contributes, when determinable.
    pub region: Option<Region>,
    pub evidence: ValidationState,
}

impl BlockTableEntry {
    /// Whether the slot is unused.
    pub fn is_empty(&self) -> bool {
        self.state.is_empty()
    }

    /// `IsLastBlock`: the chain terminates here.
    pub fn is_last_block(&self) -> bool {
        self.next_block == 0
    }

    /// `IsFirstBlock`: `FirstBlock > 0 && BlockNumber == FirstBlock`.
    ///
    /// Note the `> 0` guard is part of the rule, not a defensive addition: a zeroed
    /// `FirstBlock` in block 0 would otherwise make every unused block 0 look like the head
    /// of a recording.
    pub fn is_first_block(&self) -> bool {
        self.first_block > 0 && self.block_number as i64 == self.first_block as i64
    }

    /// Whether this entry is valid as a chain member: `IsFirstBlock || PreviousBlock != 0`.
    pub fn is_valid_block(&self) -> bool {
        self.is_first_block() || self.previous_block != 0
    }

    /// Whether the entry can contribute recoverable bytes.
    pub fn has_payload(&self) -> bool {
        self.region.map(|r| !r.is_empty()).unwrap_or(false)
    }
}

/// A partition's whole block table, decoded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockMap {
    /// Partition number this table belongs to.
    pub partition: u32,
    /// Physical offset of entry 0.
    pub table_offset: u64,
    /// Physical offset of video block 0.
    pub video_base: u64,
    /// Size of one video block in bytes.
    pub block_size: u64,
    /// Entries in block order. Index equals block number.
    pub entries: Vec<BlockTableEntry>,
    /// Slot counts, for the run summary.
    pub occupied_count: usize,
    pub empty_count: usize,
    pub malformed_count: usize,
    pub evidence: ValidationState,
}

impl BlockMap {
    /// The entry for a block number, if the table describes it.
    pub fn get(&self, block_number: i32) -> Option<&BlockTableEntry> {
        if block_number < 0 {
            return None;
        }
        self.entries.get(block_number as usize)
    }

    /// Whether a block number is inside this table.
    pub fn in_range(&self, block_number: i32) -> bool {
        block_number >= 0 && (block_number as usize) < self.entries.len()
    }

    /// Physical offset of a block's payload area.
    pub fn block_offset(&self, block_number: u32) -> Option<u64> {
        (block_number as u64)
            .checked_mul(self.block_size)
            .and_then(|d| self.video_base.checked_add(d))
    }

    /// Entries that head a recording chain.
    pub fn first_blocks(&self) -> impl Iterator<Item = &BlockTableEntry> {
        self.entries
            .iter()
            .filter(|e| !e.is_empty() && e.is_first_block())
    }
}

/// Read a partition's block table.
///
/// `block_count` bounds the read: the table is exactly one entry per declared block, and
/// the caller has already reduced a declared count that exceeded the evidence.
pub fn read_block_map(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    partition: u32,
    table_offset: u64,
    video_base: u64,
    block_count: u32,
) -> Result<BlockMap, ForensicError> {
    const OP: &str = "dhfs41_block_table";
    let subject = format!("partition{partition}_block_table");
    let disk_len = reader.len();
    let entry_size = u64_from(profile, key::BT_ENTRY_SIZE, 32);
    let block_size = u64_from(profile, key::VIDEO_BLOCK_SIZE, 2 * 1024 * 1024);

    let empty = |reason: String| BlockMap {
        partition,
        table_offset,
        video_base,
        block_size,
        entries: Vec::new(),
        occupied_count: 0,
        empty_count: 0,
        malformed_count: 0,
        evidence: vs(ValidationStateKind::Review, reason, OP, &subject),
    };

    if entry_size == 0 || block_size == 0 {
        return Ok(empty(format!(
            "the profile declares block_table_entry_size={entry_size} and video_block_size={block_size}; \
             neither may be zero, so no block table was read"
        )));
    }

    let want = (block_count as u64).saturating_mul(entry_size);
    if want == 0 {
        return Ok(empty(format!(
            "partition {partition} declares zero blocks, so its block table is empty"
        )));
    }
    if table_offset >= disk_len {
        return Ok(empty(format!(
            "partition {partition} block table base 0x{table_offset:X} lies outside the \
             {disk_len}-byte evidence"
        )));
    }

    // Read only what is present. A table truncated by the image end still describes the
    // blocks it covers, and those are real evidence; the shortfall is recorded.
    let available = disk_len - table_offset;
    let read_len = want.min(available);
    let readable_entries = (read_len / entry_size) as usize;
    let buf = match reader.read_exact_at(
        table_offset,
        (readable_entries as u64 * entry_size) as usize,
    ) {
        Ok(b) => b,
        Err(e) => {
            return Ok(empty(format!(
                "partition {partition} block table at 0x{table_offset:X} could not be read: {e}"
            )))
        }
    };

    let mut entries = Vec::with_capacity(readable_entries);
    for n in 0..readable_entries {
        let rel = n * entry_size as usize;
        let slice = match buf.get(rel..rel + entry_size as usize) {
            Some(s) => s,
            None => break,
        };
        entries.push(decode_entry(
            slice,
            n as u32,
            table_offset.saturating_add(rel as u64),
            video_base,
            block_size,
            disk_len,
            profile,
        ));
    }

    let occupied_count = entries.iter().filter(|e| e.state.is_occupied()).count();
    let empty_count = entries.iter().filter(|e| e.state.is_empty()).count();
    let malformed_count = entries.iter().filter(|e| e.state.is_malformed()).count();

    let truncated = readable_entries < block_count as usize;
    let mut reason = format!(
        "partition {partition} block table at 0x{table_offset:X}: {} of {block_count} declared \
         entr{} decoded ({occupied_count} occupied, {empty_count} empty, {malformed_count} malformed); \
         video base 0x{video_base:X}, block size {block_size}",
        entries.len(),
        if block_count == 1 { "y" } else { "ies" }
    );
    if truncated {
        reason.push_str(&format!(
            "; the table is truncated by the end of the evidence at 0x{:X}, so blocks {}..{} were \
             not described",
            disk_len, readable_entries, block_count
        ));
    }

    Ok(BlockMap {
        partition,
        table_offset,
        video_base,
        block_size,
        entries,
        occupied_count,
        empty_count,
        malformed_count,
        evidence: vs(
            if truncated || malformed_count > 0 {
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

/// Decode one 32-byte entry.
fn decode_entry(
    slice: &[u8],
    block_number: u32,
    entry_offset: u64,
    video_base: u64,
    block_size: u64,
    disk_len: u64,
    profile: &OemProfile,
) -> BlockTableEntry {
    const OP: &str = "dhfs41_block_entry";
    let subject = format!("block{block_number}");

    let f_type = usize_from(profile, key::BE_TYPE_OFFSET, 0);
    let f_legacy = usize_from(profile, key::BE_LEGACY_CHANNEL_OFFSET, 1);
    let f_start = usize_from(profile, key::BE_START_TIME_OFFSET, 4);
    let f_end = usize_from(profile, key::BE_END_TIME_OFFSET, 8);
    let f_next = usize_from(profile, key::BE_NEXT_BLOCK_OFFSET, 12);
    let f_sectors = usize_from(profile, key::BE_SECTOR_COUNT_OFFSET, 16);
    let f_prev = usize_from(profile, key::BE_PREVIOUS_BLOCK_OFFSET, 20);
    let f_first = usize_from(profile, key::BE_FIRST_BLOCK_OFFSET, 24);
    let f_ext_flag = usize_from(profile, key::BE_EXT_CHANNEL_FLAG_OFFSET, 29);
    let f_ext = usize_from(profile, key::BE_EXT_CHANNEL_OFFSET, 31);

    let type_byte = u8_at(slice, f_type).unwrap_or(0);
    let legacy_byte = u8_at(slice, f_legacy).unwrap_or(0);
    let ext_flag_byte = u8_at(slice, f_ext_flag).unwrap_or(0);
    let ext_byte = u8_at(slice, f_ext).unwrap_or(0);
    let raw_next = i32_at(slice, f_next).unwrap_or(0);
    let sector_count = i16_at(slice, f_sectors).unwrap_or(0);
    let previous_block = i32_at(slice, f_prev).unwrap_or(0);
    let first_block = i32_at(slice, f_first).unwrap_or(0);

    let channel = DahuaChannel::from_block_entry(legacy_byte, ext_flag_byte, ext_byte, profile);
    let start_time = DahuaTimestamp::decode(
        u32_at(slice, f_start).unwrap_or(0),
        TimestampStructure::BlockTableStart,
        profile,
    );
    let end_time = DahuaTimestamp::decode(
        u32_at(slice, f_end).unwrap_or(0),
        TimestampStructure::BlockTableEnd,
        profile,
    );

    let mut problems: Vec<String> = Vec::new();

    // NextBlock normalization. -1 is the recorder's alternative spelling of "no next
    // block"; anything below that is not a block reference at all.
    let next_block = if raw_next == -1 {
        0
    } else if raw_next < -1 {
        problems.push(format!(
            "NextBlock is {raw_next}, which is neither a block number nor the -1 terminator"
        ));
        0
    } else {
        raw_next
    };
    if previous_block < -1 {
        problems.push(format!(
            "PreviousBlock is {previous_block}, which is not a block number"
        ));
    }
    if first_block < 0 {
        problems.push(format!(
            "FirstBlock is {first_block}, which is not a block number"
        ));
    }

    let empty_primary = u8_from(profile, key::BE_TYPE_EMPTY_PRIMARY, 0xFE);
    let empty_secondary = u8_from(profile, key::BE_TYPE_EMPTY_SECONDARY, 0x00);
    let is_empty_type = type_byte == empty_primary || type_byte == empty_secondary;

    // ── Length determination ────────────────────────────────────────────────
    // Only the last block is partially filled. Its length comes from sectorCount; every
    // other block occupies its whole 2 MiB. An invalid sectorCount is NOT replaced with a
    // convenient default — the length becomes unknown and the block is marked malformed,
    // because a substituted length would silently truncate or over-read real video.
    let sector_size = u64_from(profile, key::SECTOR_SIZE, 512);
    let is_last = next_block == 0;
    let physical_length = if is_empty_type {
        None
    } else if is_last {
        if sector_count <= 0 {
            problems.push(format!(
                "this is the last block of its chain (NextBlock == 0) but sectorCount is \
                 {sector_count}, so its filled length cannot be determined"
            ));
            None
        } else {
            let declared = (sector_count as u64).saturating_mul(sector_size);
            if declared > block_size {
                problems.push(format!(
                    "sectorCount {sector_count} declares {declared} byte(s), more than the \
                     {block_size}-byte block; capped at the block size"
                ));
                Some(block_size)
            } else {
                Some(declared)
            }
        }
    } else {
        Some(block_size)
    };

    // ── Physical placement ──────────────────────────────────────────────────
    let block_offset = (block_number as u64)
        .checked_mul(block_size)
        .and_then(|d| video_base.checked_add(d))
        .filter(|off| *off < disk_len);
    if block_offset.is_none() && !is_empty_type {
        problems.push(format!(
            "block {block_number} would sit at video base 0x{video_base:X} + {block_number} * \
             {block_size}, outside the {disk_len}-byte evidence"
        ));
    }

    let region = match (block_offset, physical_length) {
        (Some(off), Some(len)) => {
            let clipped = len.min(disk_len.saturating_sub(off));
            if clipped < len {
                problems.push(format!(
                    "block {block_number} declares {len} byte(s) but only {clipped} are present \
                     before the end of the evidence"
                ));
            }
            Region::new(off, clipped).ok()
        }
        _ => None,
    };

    let state = if is_empty_type {
        BlockState::Empty { type_byte }
    } else if !problems.is_empty() {
        BlockState::Malformed {
            reason: problems.join("; "),
        }
    } else {
        BlockState::Occupied
    };

    let mut reason = format!(
        "block {block_number} entry at 0x{entry_offset:X}: type 0x{type_byte:02X}, channel {} ({}), \
         first={first_block}, prev={previous_block}, next={next_block} (raw {raw_next}), \
         sectorCount={sector_count}, {}",
        channel.normalized,
        channel.encoding.label(),
        region
            .map(|r| format!("occupies {r}"))
            .unwrap_or_else(|| "no physical extent established".into())
    );
    match &state {
        BlockState::Empty { .. } => reason
            .push_str("; type byte marks the slot as empty/unused, which is not a deletion marker"),
        BlockState::Malformed { reason: r } => {
            reason.push_str("; malformed: ");
            reason.push_str(r);
        }
        BlockState::Occupied => {}
    }

    BlockTableEntry {
        block_number,
        entry_offset,
        block_offset,
        type_byte,
        state: state.clone(),
        channel,
        start_time,
        end_time,
        raw_next_block: raw_next,
        next_block,
        sector_count,
        previous_block,
        first_block,
        extended_flag_byte: ext_flag_byte,
        extended_channel_byte: ext_byte,
        physical_length,
        region,
        evidence: vs(
            match state {
                BlockState::Occupied => ValidationStateKind::Pass,
                BlockState::Empty { .. } => ValidationStateKind::Unknown,
                BlockState::Malformed { .. } => ValidationStateKind::Review,
            },
            reason,
            OP,
            &subject,
        ),
    }
}

#[cfg(test)]
pub(crate) mod builder {
    //! Entry builder shared by this module's tests and the chain module's tests.
    //!
    //! It writes the real 32-byte layout rather than a convenient stand-in, so a test that
    //! passes here is testing the documented structure.

    use crate::timestamp::pack;

    /// A 32-byte block-table entry, built field by field.
    #[derive(Debug, Clone)]
    pub struct EntryBuilder {
        pub bytes: [u8; 32],
    }

    impl EntryBuilder {
        /// An occupied entry: type 0x01, channel 1 via the legacy nibble.
        pub fn occupied() -> Self {
            let mut bytes = [0u8; 32];
            bytes[0] = 0x01;
            Self { bytes }
        }

        /// An empty slot, using the primary empty marker.
        pub fn empty() -> Self {
            let mut bytes = [0u8; 32];
            bytes[0] = 0xFE;
            Self { bytes }
        }

        pub fn type_byte(mut self, v: u8) -> Self {
            self.bytes[0] = v;
            self
        }

        /// Legacy channel nibble; the stored byte is `channel - 1`.
        pub fn legacy_channel(mut self, channel_1_based: u8) -> Self {
            self.bytes[1] = channel_1_based.saturating_sub(1) & 0x0F;
            self
        }

        /// Extended channel: sets bit 0 of +29 and writes the value at +31.
        pub fn extended_channel(mut self, channel: u8) -> Self {
            self.bytes[29] |= 0x01;
            self.bytes[31] = channel & 0x1F;
            self
        }

        pub fn start_time(mut self, y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> Self {
            let packed = pack(y, mo, d, h, mi, s, 2000).expect("representable");
            self.bytes[4..8].copy_from_slice(&packed.to_le_bytes());
            self
        }

        pub fn end_time(mut self, y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> Self {
            let packed = pack(y, mo, d, h, mi, s, 2000).expect("representable");
            self.bytes[8..12].copy_from_slice(&packed.to_le_bytes());
            self
        }

        pub fn raw_start_time(mut self, packed: u32) -> Self {
            self.bytes[4..8].copy_from_slice(&packed.to_le_bytes());
            self
        }

        pub fn next_block(mut self, v: i32) -> Self {
            self.bytes[12..16].copy_from_slice(&v.to_le_bytes());
            self
        }

        pub fn sector_count(mut self, v: i16) -> Self {
            self.bytes[16..18].copy_from_slice(&v.to_le_bytes());
            self
        }

        pub fn previous_block(mut self, v: i32) -> Self {
            self.bytes[20..24].copy_from_slice(&v.to_le_bytes());
            self
        }

        pub fn first_block(mut self, v: i32) -> Self {
            self.bytes[24..28].copy_from_slice(&v.to_le_bytes());
            self
        }

        pub fn build(self) -> [u8; 32] {
            self.bytes
        }
    }
}

#[cfg(test)]
mod tests {
    use super::builder::EntryBuilder;
    use super::*;
    use crate::layout::tests_support::dahua_profile;
    use crate::testing::MemReader;

    const BLOCK: u64 = 2 * 1024 * 1024;
    const TABLE_AT: u64 = 4096;

    /// Lay a block table at `TABLE_AT` and video blocks right after it.
    fn volume(entries: &[[u8; 32]]) -> (MemReader, u64) {
        let video_base = TABLE_AT + 64 * 1024;
        let total = (video_base + entries.len() as u64 * BLOCK) as usize;
        let mut b = vec![0u8; total];
        b[..8].copy_from_slice(b"DHFS4.1\0");
        for (i, e) in entries.iter().enumerate() {
            let at = (TABLE_AT as usize) + i * 32;
            b[at..at + 32].copy_from_slice(e);
        }
        (MemReader::new(b), video_base)
    }

    fn read(entries: &[[u8; 32]]) -> BlockMap {
        let p = dahua_profile();
        let (r, video_base) = volume(entries);
        read_block_map(&r, &p, 0, TABLE_AT, video_base, entries.len() as u32).unwrap()
    }

    #[test]
    fn an_empty_slot_is_empty_and_carries_no_recording_metadata() {
        for marker in [0xFEu8, 0x00u8] {
            let map = read(&[EntryBuilder::empty().type_byte(marker).build()]);
            let e = &map.entries[0];
            assert!(e.is_empty(), "type 0x{marker:02X} must read as empty");
            assert_eq!(e.state, BlockState::Empty { type_byte: marker });
            assert!(e.physical_length.is_none(), "an empty slot has no length");
            assert!(e.region.is_none());
            // Unused is Unknown, not a Pass and certainly not a deletion finding.
            assert_eq!(e.evidence.state, ValidationStateKind::Unknown);
            assert!(e.evidence.reason.contains("not a deletion marker"));
        }
        let map = read(&[EntryBuilder::empty().build()]);
        assert_eq!(map.empty_count, 1);
        assert_eq!(map.occupied_count, 0);
    }

    #[test]
    fn a_single_block_recording_is_both_first_and_last() {
        // FirstBlock = 0 is not usable for block 0, so a one-block recording at block 1.
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(0)
                .sector_count(8)
                .build(),
        ];
        let map = read(&entries);
        let e = &map.entries[1];
        assert!(e.is_first_block());
        assert!(e.is_last_block());
        assert!(e.is_valid_block());
        assert_eq!(e.physical_length, Some(8 * 512), "sectorCount * 512");
        assert_eq!(e.region.unwrap().length, 8 * 512);
        assert_eq!(e.region.unwrap().offset, map.block_offset(1).unwrap());
        assert_eq!(e.evidence.state, ValidationStateKind::Pass);
    }

    #[test]
    fn a_middle_block_occupies_the_whole_block_regardless_of_sector_count() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(2)
                .build(),
            // sectorCount is meaningless on a non-last block and must be ignored.
            EntryBuilder::occupied()
                .first_block(1)
                .previous_block(1)
                .next_block(3)
                .sector_count(3)
                .build(),
            EntryBuilder::occupied()
                .first_block(1)
                .previous_block(2)
                .next_block(0)
                .sector_count(16)
                .build(),
        ];
        let map = read(&entries);
        assert_eq!(map.entries[1].physical_length, Some(BLOCK));
        assert_eq!(
            map.entries[2].physical_length,
            Some(BLOCK),
            "a middle block is always full"
        );
        assert_eq!(map.entries[3].physical_length, Some(16 * 512));
        assert!(!map.entries[2].is_last_block());
        assert!(map.entries[3].is_last_block());
    }

    #[test]
    fn next_block_minus_one_normalises_to_the_terminator() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(-1)
                .sector_count(4)
                .build(),
        ];
        let map = read(&entries);
        let e = &map.entries[1];
        assert_eq!(e.raw_next_block, -1, "the raw value is retained");
        assert_eq!(e.next_block, 0);
        assert!(e.is_last_block());
        assert!(e.state.is_occupied(), "-1 is valid, not malformed");
        assert!(e.evidence.reason.contains("raw -1"));
    }

    #[test]
    fn a_next_block_below_minus_one_is_malformed() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(-42)
                .sector_count(4)
                .build(),
        ];
        let map = read(&entries);
        let e = &map.entries[1];
        assert!(e.state.is_malformed(), "{:?}", e.state);
        assert_eq!(e.raw_next_block, -42);
        assert_eq!(e.evidence.state, ValidationStateKind::Review);
        assert!(e
            .evidence
            .reason
            .contains("neither a block number nor the -1 terminator"));
        assert_eq!(map.malformed_count, 1);
        // Malformed does not mean discarded: the physical extent is still described.
        assert!(e.region.is_some());
    }

    #[test]
    fn a_previous_block_below_minus_one_is_malformed() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .previous_block(-99)
                .next_block(0)
                .sector_count(4)
                .build(),
        ];
        let map = read(&entries);
        assert!(map.entries[1].state.is_malformed());
        assert!(map.entries[1]
            .evidence
            .reason
            .contains("PreviousBlock is -99"));
    }

    #[test]
    fn an_invalid_sector_count_on_a_last_block_leaves_the_length_unknown() {
        for count in [0i16, -7] {
            let entries = [
                EntryBuilder::empty().build(),
                EntryBuilder::occupied()
                    .first_block(1)
                    .next_block(0)
                    .sector_count(count)
                    .build(),
            ];
            let map = read(&entries);
            let e = &map.entries[1];
            assert!(
                e.physical_length.is_none(),
                "sectorCount {count} must not be replaced with a default length"
            );
            assert!(e.region.is_none());
            assert!(e.state.is_malformed());
            assert!(e.evidence.reason.contains("cannot be determined"));
        }
    }

    #[test]
    fn a_sector_count_larger_than_a_block_is_capped_and_reported() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(0)
                // 8192 sectors = 4 MiB, twice a block.
                .sector_count(8192)
                .build(),
        ];
        let map = read(&entries);
        let e = &map.entries[1];
        assert_eq!(e.physical_length, Some(BLOCK), "capped at the block size");
        assert!(e.evidence.reason.contains("capped at the block size"));
        assert!(e.state.is_malformed(), "the inconsistency is surfaced");
    }

    #[test]
    fn first_block_rules_require_a_positive_first_block_matching_the_block_number() {
        let entries = [
            // block 0 with FirstBlock 0: NOT a first block, by the > 0 rule.
            EntryBuilder::occupied()
                .next_block(0)
                .sector_count(4)
                .build(),
            // block 1 pointing at itself: a first block.
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(0)
                .sector_count(4)
                .build(),
            // block 2 pointing at block 1: a member, not a head.
            EntryBuilder::occupied()
                .first_block(1)
                .previous_block(1)
                .next_block(0)
                .sector_count(4)
                .build(),
        ];
        let map = read(&entries);
        assert!(!map.entries[0].is_first_block());
        assert!(map.entries[1].is_first_block());
        assert!(!map.entries[2].is_first_block());
        assert_eq!(map.first_blocks().count(), 1);
    }

    #[test]
    fn validity_is_first_block_or_a_non_zero_previous_block() {
        let entries = [
            // Occupied but unlinked: not a first block, PreviousBlock 0 -> invalid member.
            EntryBuilder::occupied()
                .next_block(0)
                .sector_count(4)
                .build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(0)
                .sector_count(4)
                .build(),
            EntryBuilder::occupied()
                .previous_block(1)
                .next_block(0)
                .sector_count(4)
                .build(),
        ];
        let map = read(&entries);
        assert!(
            !map.entries[0].is_valid_block(),
            "unlinked block is not a valid member"
        );
        assert!(map.entries[1].is_valid_block(), "first block is valid");
        assert!(
            map.entries[2].is_valid_block(),
            "non-zero PreviousBlock is valid"
        );
        // An invalid member is still physically present video.
        assert!(map.entries[0].has_payload());
    }

    #[test]
    fn the_extended_channel_flag_selects_the_extended_field() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .legacy_channel(3)
                .extended_channel(21)
                .first_block(1)
                .next_block(0)
                .sector_count(4)
                .build(),
        ];
        let map = read(&entries);
        let e = &map.entries[1];
        assert_eq!(e.channel.normalized, 21);
        assert_eq!(
            e.channel.encoding,
            crate::channel::ChannelEncoding::BlockTableExtended
        );
        assert_eq!(e.extended_flag_byte & 0x01, 1);
        assert_eq!(e.extended_channel_byte, 21);
    }

    #[test]
    fn the_legacy_channel_applies_when_the_extended_flag_is_clear() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .legacy_channel(9)
                .first_block(1)
                .next_block(0)
                .sector_count(4)
                .build(),
        ];
        let map = read(&entries);
        assert_eq!(map.entries[1].channel.normalized, 9);
        assert_eq!(
            map.entries[1].channel.encoding,
            crate::channel::ChannelEncoding::BlockTableLegacyNibble
        );
    }

    #[test]
    fn timestamps_are_decoded_from_the_packed_fields() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(0)
                .sector_count(4)
                .start_time(2026, 9, 22, 8, 0, 0)
                .end_time(2026, 9, 22, 8, 5, 30)
                .build(),
        ];
        let map = read(&entries);
        let e = &map.entries[1];
        assert_eq!(
            e.start_time.recorder_wall_clock.as_deref(),
            Some("2026-09-22T08:00:00")
        );
        assert_eq!(
            e.end_time.recorder_wall_clock.as_deref(),
            Some("2026-09-22T08:05:30")
        );
        assert!(e.start_time.unix_seconds.unwrap() < e.end_time.unix_seconds.unwrap());
    }

    #[test]
    fn an_implausible_timestamp_does_not_become_a_fabricated_instant() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(0)
                .sector_count(4)
                // month field 0.
                .raw_start_time((26u32 << 26) | (5 << 17) | (10 << 12))
                .build(),
        ];
        let map = read(&entries);
        let e = &map.entries[1];
        assert!(e.start_time.unix_seconds.is_none());
        assert!(!e.start_time.is_decoded());
        assert_ne!(e.start_time.raw, 0, "the raw field is still reported");
    }

    #[test]
    fn block_offsets_follow_the_documented_addressing() {
        let map = read(&[
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(0)
                .sector_count(1)
                .build(),
        ]);
        assert_eq!(map.block_offset(0), Some(map.video_base));
        assert_eq!(map.block_offset(1), Some(map.video_base + BLOCK));
        assert_eq!(map.entries[1].block_offset, Some(map.video_base + BLOCK));
    }

    #[test]
    fn a_table_truncated_by_the_image_end_describes_what_is_present_and_says_so() {
        let p = dahua_profile();
        // Declare 8 blocks but give the image room for only 3 entries.
        let mut b = vec![0u8; (TABLE_AT + 3 * 32) as usize];
        b[..8].copy_from_slice(b"DHFS4.1\0");
        for i in 0..3 {
            let at = TABLE_AT as usize + i * 32;
            b[at..at + 32].copy_from_slice(
                &EntryBuilder::occupied()
                    .next_block(0)
                    .sector_count(1)
                    .build(),
            );
        }
        let r = MemReader::new(b);
        let map = read_block_map(&r, &p, 0, TABLE_AT, TABLE_AT + 3 * 32, 8).unwrap();
        assert_eq!(map.entries.len(), 3);
        assert_eq!(map.evidence.state, ValidationStateKind::Review);
        assert!(map.evidence.reason.contains("truncated"));
    }

    #[test]
    fn a_block_table_beyond_the_evidence_yields_no_entries() {
        let p = dahua_profile();
        let r = MemReader::new(vec![0u8; 4096]);
        let map = read_block_map(&r, &p, 1, 1 << 30, 1 << 31, 4).unwrap();
        assert!(map.entries.is_empty());
        assert_eq!(map.evidence.state, ValidationStateKind::Review);
        assert!(map.evidence.reason.contains("outside"));
    }

    #[test]
    fn a_zero_block_count_yields_an_empty_table_not_an_error() {
        let p = dahua_profile();
        let r = MemReader::new(vec![0u8; 1 << 16]);
        let map = read_block_map(&r, &p, 0, 512, 4096, 0).unwrap();
        assert!(map.entries.is_empty());
        assert!(map.evidence.reason.contains("declares zero blocks"));
    }

    #[test]
    fn out_of_range_lookups_are_none_never_a_panic() {
        let map = read(&[EntryBuilder::empty().build()]);
        assert!(map.get(-1).is_none());
        assert!(map.get(5).is_none());
        assert!(!map.in_range(-1));
        assert!(!map.in_range(1));
        assert!(map.in_range(0));
    }
}
