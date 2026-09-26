//! # Synthetic Hikvision volume builder
//!
//! Builds complete, format-accurate Hikvision disk images from the documented on-disk layout:
//!
//! ```text
//!   boot structure     identifier at +16, geometry at +120..+176
//!   HIKBTREE (primary) header page, then internal/leaf pages, 48-byte entries
//!   HIKBTREE (backup)  same shape, at BackupBTreeOffset
//!   video blocks       video data + a trailing footer holding the clip index
//!     ├─ footer        marker byte, clip count, epoch span, 512-byte clip slots
//!     └─ video data    MPEG-PS clips: pack header, PES parts, H.264/H.265 payload
//! ```
//!
//! ## Builders, not byte arrays
//!
//! Every structure is assembled from the same field offsets the parser reads, and the returned
//! [`HikvisionImage`] reports the offsets it **actually produced**. Tests assert against those,
//! never against a second copy of the constants — so a fixture cannot silently drift into
//! agreeing with a parser that reads the wrong offsets.
//!
//! ## Block size
//!
//! Real Hikvision blocks are 1 GiB. A test cannot allocate several of those, so the default
//! spec declares a 2 MiB block (1 MiB of video data plus the format's fixed 1 MiB footer). The
//! footer geometry, the clip-slot stride and every field offset are the real ones; only the
//! block's total size differs, and it is declared in the boot structure exactly as a recorder
//! would declare 1 GiB.
//!
//! [`HikvisionImageSpec::declared_block_count`] can declare more blocks than the image holds,
//! which is how the "declared blocks absent from the acquisition" path is exercised without
//! building a terabyte.
//!
//! ## This is synthetic
//!
//! [`LABEL`] is `"synthetic"` on every image. A synthetic image proves the parser reads the
//! layout it was built from. It does **not** prove compatibility with any firmware.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Every image produced here is explicitly labelled synthetic.
pub const LABEL: &str = "synthetic";

/// The Hikvision filesystem identifier string, as it appears in the profile.
pub const IDENTIFIER: &[u8] = b"HIKVISION@HANGZHOU";
/// The HIKBTREE page magic.
pub const HIKBTREE_MAGIC: &[u8] = b"HIKBTREE";
/// The structural sentinel the raw carver treats as one corroborating clue.
pub const CARVE_SENTINEL: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFB];

/// Fixed format constants. These mirror the profile; the tests assert the two agree.
pub const BOOT_STRUCTURE_SIZE: u64 = 512;
pub const BTREE_PAGE_SIZE: u64 = 4096;
pub const BTREE_ENTRY_SIZE: usize = 48;
pub const BTREE_LEAF_ENTRIES_OFFSET: usize = 96;
pub const BLOCK_FOOTER_SIZE: u64 = 1 << 20;
pub const BLOCK_INDEX_CLIP_BASE: u64 = 512;
pub const BLOCK_INDEX_CLIP_STRIDE: u64 = 512;

/// Default boot position (`0x200`).
pub const DEFAULT_BOOT_OFFSET: u64 = 512;
/// The second observed boot position (`0x4C56000`).
pub const SECONDARY_BOOT_OFFSET: u64 = 80_044_032;

/// A plausible recorder clock: 2026-09-23T00:00:00Z.
pub const T_BASE: u32 = 1_774_224_000;

// ── Small byte helpers ──────────────────────────────────────────────────────────

fn put_u16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_i32(b: &mut [u8], at: usize, v: i32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_i64(b: &mut [u8], at: usize, v: i64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

// ── Clip payload ────────────────────────────────────────────────────────────────

/// Which codec a clip's video payload carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureCodec {
    H264,
    H265,
    /// Video PES parts whose payload is not Annex-B at all, so no codec can be established.
    /// Used to prove the parser reports `Unknown` rather than guessing.
    Indeterminate,
}

impl FixtureCodec {
    fn elementary_stream(&self) -> Vec<u8> {
        match self {
            Self::H264 => parser_hikvision::testing::build::h264_es(),
            Self::H265 => parser_hikvision::testing::build::h265_es(),
            Self::Indeterminate => vec![0xAAu8; 64],
        }
    }
}

/// One clip to place in a block's video data and describe in its footer index.
#[derive(Debug, Clone)]
pub struct HikClipSpec {
    /// Raw channel byte, as stored (0-based).
    pub channel_raw: u8,
    /// Clip start, unix seconds. Zero leaves the dedicated start field unwritten.
    pub start_time: u32,
    /// Clip end, unix seconds. This is the required field.
    pub end_time: u32,
    /// The `+40` time field. Used as the fallback start when `start_time` is zero.
    pub time_a: u32,
    /// Number of video PES parts in the clip's container.
    pub video_parts: usize,
    pub codec: FixtureCodec,
    /// Whether to include an `OFNI` information part.
    pub include_ofni: bool,
    /// Frame rate byte. Zero means "not established".
    pub frame_rate: u8,
    /// Whether to write the structural sentinel immediately before the clip's bytes.
    pub sentinel_before: bool,
    /// Override the footer slot's declared start offset, in bytes from the block start.
    ///
    /// `None` uses the clip's real position, which is the correct case. `Some` is how a test
    /// produces a slot whose declared range does not describe the clip.
    pub declared_start_offset: Option<u32>,
    /// Override the footer slot's declared end offset.
    pub declared_end_offset: Option<u32>,
}

impl Default for HikClipSpec {
    fn default() -> Self {
        Self {
            channel_raw: 0,
            start_time: T_BASE,
            end_time: T_BASE + 600,
            time_a: T_BASE,
            video_parts: 3,
            codec: FixtureCodec::H264,
            include_ofni: false,
            frame_rate: 25,
            sentinel_before: false,
            declared_start_offset: None,
            declared_end_offset: None,
        }
    }
}

impl HikClipSpec {
    /// The clip's container bytes: pack header, optional OFNI, system header, video PES parts.
    fn bytes(&self, serial: u32) -> Vec<u8> {
        use parser_hikvision::testing::build;
        let es = self.codec.elementary_stream();
        let mut v = build::pack(serial);
        if self.include_ofni {
            v.extend_from_slice(&build::ofni(
                format!("synthetic ch{} clip", self.channel_raw).as_bytes(),
            ));
        }
        v.extend_from_slice(&build::pes(0xBB, &[0x11; 8], 14));
        for _ in 0..self.video_parts {
            v.extend_from_slice(&build::pes(0xE0, &es, 14));
        }
        v
    }
}

/// A clip placed in video data but **not** described by the footer index.
///
/// This is the carving target: real container framing that no metadata claims.
#[derive(Debug, Clone)]
pub struct LooseClipSpec {
    pub codec: FixtureCodec,
    pub video_parts: usize,
    pub sentinel_before: bool,
}

impl Default for LooseClipSpec {
    fn default() -> Self {
        Self {
            codec: FixtureCodec::H264,
            video_parts: 2,
            sentinel_before: true,
        }
    }
}

// ── Blocks ──────────────────────────────────────────────────────────────────────

/// How a block's footer index should be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FooterMode {
    /// A normal, verifiable clip index.
    Valid,
    /// The marker byte holds the reject value, so the footer carries no index.
    RejectByte,
    /// The declared clip count is zero.
    ZeroClipCount,
    /// The declared clip count exceeds what the footer can hold.
    ImplausibleClipCount,
    /// The footer is filled with noise, so nothing in it validates.
    Corrupt,
}

/// One video block.
#[derive(Debug, Clone)]
pub struct HikBlockSpec {
    /// Clips described by the footer index.
    pub clips: Vec<HikClipSpec>,
    /// Clips present in video data but absent from the footer index.
    pub loose_clips: Vec<LooseClipSpec>,
    pub footer: FooterMode,
}

impl Default for HikBlockSpec {
    fn default() -> Self {
        Self {
            clips: vec![HikClipSpec::default()],
            loose_clips: Vec::new(),
            footer: FooterMode::Valid,
        }
    }
}

// ── B-tree ──────────────────────────────────────────────────────────────────────

/// What a 48-byte entry's state sentinel declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntrySentinel {
    /// In use (`0`).
    Populated,
    /// Never written (`0xFFFFFFFFFFFFFFFF`).
    Blank,
    /// Neither known value, so the entry is malformed.
    Malformed(u64),
}

/// One HIKBTREE entry.
#[derive(Debug, Clone)]
pub struct HikEntrySpec {
    pub sentinel: EntrySentinel,
    /// Raw channel byte.
    pub channel_raw: u8,
    /// Start time. `i32::MAX` marks an unfinished recording.
    pub start_time: i32,
    pub end_time: i32,
    /// Which block, and which of its footer-described clips, this entry points at.
    ///
    /// `Some((block, clip))` resolves to that clip's real physical offset once the blocks are
    /// laid out. `None` writes `data_offset` verbatim, which is how a dangling entry is built.
    pub target: Option<(u32, usize)>,
    /// Data offset used when `target` is `None`.
    pub data_offset: i64,
    /// The `+40` status field, preserved raw by the parser.
    pub status: i32,
    /// The `+44` field, preserved raw by the parser.
    pub unknown: i32,
}

impl Default for HikEntrySpec {
    fn default() -> Self {
        Self {
            sentinel: EntrySentinel::Populated,
            channel_raw: 0,
            start_time: T_BASE as i32,
            end_time: T_BASE as i32 + 600,
            target: Some((0, 0)),
            data_offset: 0,
            status: 1,
            unknown: 0,
        }
    }
}

impl HikEntrySpec {
    /// A populated entry pointing at block `block`, clip `clip`, on channel `channel_raw`.
    pub fn at(block: u32, clip: usize, channel_raw: u8) -> Self {
        Self {
            channel_raw,
            target: Some((block, clip)),
            ..Default::default()
        }
    }

    /// A never-written slot.
    pub fn blank() -> Self {
        Self {
            sentinel: EntrySentinel::Blank,
            target: None,
            ..Default::default()
        }
    }

    /// A slot whose state sentinel is neither known value.
    pub fn malformed() -> Self {
        Self {
            sentinel: EntrySentinel::Malformed(0xDEAD_BEEF_DEAD_BEEF),
            target: None,
            ..Default::default()
        }
    }
}

/// One HIKBTREE page.
#[derive(Debug, Clone)]
pub enum HikPageSpec {
    /// A leaf page carrying entries, optionally chaining to the page at `next_page_index`.
    Leaf {
        entries: Vec<HikEntrySpec>,
        /// Index into [`HikTreeSpec::pages`] (page 0 is the header page).
        next_page_index: Option<usize>,
        /// Override the declared entry count, to build a damaged count field.
        declared_entry_count: Option<i32>,
    },
    /// An internal page pointing at two children by page index.
    Internal {
        other_page_index: Option<usize>,
        next_page_index: Option<usize>,
    },
    /// A page whose type discriminator is neither leaf nor internal.
    UnknownType { discriminator: i32 },
    /// A leaf page whose `next` pointer is a raw byte offset, for cycle and out-of-range tests.
    LeafWithRawNext {
        entries: Vec<HikEntrySpec>,
        raw_next: i64,
    },
}

/// A HIKBTREE. Page 0 is always the header page; `pages` are the pages after it.
#[derive(Debug, Clone)]
pub struct HikTreeSpec {
    pub pages: Vec<HikPageSpec>,
    /// Index into `pages` for `FirstLeafPageOffset`. Page indices here are 1-based
    /// (page 0 is the header), matching `next_page_index`.
    pub first_leaf_page_index: Option<usize>,
    /// Index into `pages` for `FirstPointerPageOffset`.
    pub first_pointer_page_index: Option<usize>,
    /// Override the declared page count, to build a count that disagrees with reality.
    pub declared_page_count: Option<i32>,
    /// Write something other than `HIKBTREE` as the header magic.
    pub magic: Option<Vec<u8>>,
    /// The `+60` tree timestamp.
    pub tree_timestamp: i32,
}

impl Default for HikTreeSpec {
    fn default() -> Self {
        Self {
            pages: Vec::new(),
            first_leaf_page_index: Some(1),
            first_pointer_page_index: None,
            declared_page_count: None,
            magic: None,
            tree_timestamp: T_BASE as i32,
        }
    }
}

impl HikTreeSpec {
    /// A single-leaf tree holding `entries`.
    pub fn single_leaf(entries: Vec<HikEntrySpec>) -> Self {
        Self {
            pages: vec![HikPageSpec::Leaf {
                entries,
                next_page_index: None,
                declared_entry_count: None,
            }],
            ..Default::default()
        }
    }
}

// ── Image spec ──────────────────────────────────────────────────────────────────

/// A whole synthetic Hikvision volume.
#[derive(Debug, Clone)]
pub struct HikvisionImageSpec {
    /// Which boot position to write the boot structure at.
    pub boot_offset: u64,
    /// Override the identifier bytes, for a wrong-identifier fixture.
    pub identifier: Option<Vec<u8>>,
    /// Real block size used to lay the image out.
    pub block_size: u64,
    /// Value written into the boot structure's `BlockSize` field.
    ///
    /// `None` writes `block_size`. `Some(0)` exercises the documented zero-means-default path.
    pub declared_block_size: Option<i64>,
    /// Value written into `NumberOfBlocks`. `None` writes the real block count.
    pub declared_block_count: Option<i32>,
    /// Value written into `VideoStartOffset`. `None` writes the real video start.
    pub declared_video_start: Option<i64>,
    pub blocks: Vec<HikBlockSpec>,
    pub primary_tree: Option<HikTreeSpec>,
    pub backup_tree: Option<HikTreeSpec>,
    /// Clips placed outside every block, in slack space, for whole-image carving tests.
    pub slack_clips: Vec<LooseClipSpec>,
    pub trailing_slack: u64,
}

impl Default for HikvisionImageSpec {
    fn default() -> Self {
        Self {
            boot_offset: DEFAULT_BOOT_OFFSET,
            identifier: None,
            // 1 MiB of video data plus the format's fixed 1 MiB footer.
            block_size: 2 * (1 << 20),
            declared_block_size: None,
            declared_block_count: None,
            declared_video_start: None,
            blocks: Vec::new(),
            primary_tree: None,
            backup_tree: None,
            slack_clips: Vec::new(),
            trailing_slack: 0,
        }
    }
}

// ── Produced layout ─────────────────────────────────────────────────────────────

/// Where a clip actually ended up, and what its footer slot declares.
#[derive(Debug, Clone)]
pub struct HikClipLayout {
    pub slot_index: usize,
    /// Absolute offset of the 512-byte footer slot.
    pub slot_offset: u64,
    /// Absolute offset of the clip's container bytes.
    pub clip_offset: u64,
    /// Length of the clip's container bytes.
    pub clip_length: u64,
    pub channel_raw: u8,
    /// 1-based channel the parser should derive.
    pub channel: u32,
    pub start_time: u32,
    pub end_time: u32,
    pub codec: FixtureCodec,
    /// The clip id [`parser_hikvision::ClipRecord::clip_id`] should produce for this clip.
    pub expected_clip_id: String,
}

/// Where a block actually ended up.
#[derive(Debug, Clone)]
pub struct HikBlockLayout {
    pub block_number: u32,
    pub offset: u64,
    /// First byte of the footer region.
    pub footer_offset: u64,
    /// End of the video-data region (== `footer_offset`).
    pub video_data_end: u64,
    pub clips: Vec<HikClipLayout>,
    /// Offsets of clips present in video data but absent from the footer index.
    pub loose_clip_offsets: Vec<u64>,
    pub footer: FooterMode,
}

/// A built synthetic Hikvision image.
#[derive(Debug, Clone)]
pub struct HikvisionImage {
    /// Always [`LABEL`].
    pub label: &'static str,
    pub bytes: Vec<u8>,
    pub boot_offset: u64,
    pub video_start: u64,
    pub block_size: u64,
    pub footer_size: u64,
    pub primary_tree_offset: Option<u64>,
    pub primary_tree_size: u64,
    pub backup_tree_offset: Option<u64>,
    pub backup_tree_size: u64,
    pub blocks: Vec<HikBlockLayout>,
    /// Offsets of clips written into slack space outside every block.
    pub slack_clip_offsets: Vec<u64>,
}

impl HikvisionImage {
    pub fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn block(&self, number: u32) -> Option<&HikBlockLayout> {
        self.blocks.iter().find(|b| b.block_number == number)
    }

    /// Every clip across every block, with its block.
    pub fn clips(&self) -> impl Iterator<Item = (&HikBlockLayout, &HikClipLayout)> {
        self.blocks
            .iter()
            .flat_map(|b| b.clips.iter().map(move |c| (b, c)))
    }

    /// The first clip in the image, for a test that needs any valid one.
    pub fn first_clip(&self) -> Option<(&HikBlockLayout, &HikClipLayout)> {
        self.clips().next()
    }

    /// Physical ranges of every footer-described clip, sorted.
    pub fn described_clip_regions(&self) -> Vec<(u64, u64)> {
        let mut out: Vec<(u64, u64)> = self
            .clips()
            .map(|(_, c)| (c.clip_offset, c.clip_length))
            .collect();
        out.sort_unstable();
        out
    }

    /// Write the image to `dir/name` and return the path.
    pub fn write_to_dir(&self, dir: &Path, name: &str) -> std::io::Result<PathBuf> {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path)?;
        f.write_all(&self.bytes)?;
        f.flush()?;
        Ok(path)
    }
}

// ── Builder ─────────────────────────────────────────────────────────────────────

/// Build a synthetic Hikvision image from `spec`.
///
/// Layout order, chosen so each structure can reference the ones before it:
///
/// 1. size the image from the spec's own geometry;
/// 2. write the video blocks, recording where every clip landed;
/// 3. write each block's footer clip index, pointing at those real offsets;
/// 4. write the trees, whose entries point at those real clip offsets;
/// 5. write the boot structure, whose pointers address the trees and the video region.
pub fn build_hikvision_image(spec: &HikvisionImageSpec) -> HikvisionImage {
    let footer_size = BLOCK_FOOTER_SIZE;
    assert!(
        spec.block_size > footer_size,
        "a block must be larger than its own {footer_size}-byte footer"
    );

    // ── 1. Offsets ───────────────────────────────────────────────────────────────
    let boot_end = spec.boot_offset + BOOT_STRUCTURE_SIZE;

    let primary_pages = spec.primary_tree.as_ref().map(|t| t.pages.len() as u64 + 1);
    let backup_pages = spec.backup_tree.as_ref().map(|t| t.pages.len() as u64 + 1);

    // Trees are page-aligned after the boot structure.
    let primary_tree_offset = primary_pages.map(|_| align_up(boot_end, BTREE_PAGE_SIZE));
    let primary_tree_size = primary_pages.unwrap_or(0) * BTREE_PAGE_SIZE;
    let after_primary = primary_tree_offset
        .map(|o| o + primary_tree_size)
        .unwrap_or(boot_end);

    let backup_tree_offset = backup_pages.map(|_| align_up(after_primary, BTREE_PAGE_SIZE));
    let backup_tree_size = backup_pages.unwrap_or(0) * BTREE_PAGE_SIZE;
    let after_backup = backup_tree_offset
        .map(|o| o + backup_tree_size)
        .unwrap_or(after_primary);

    // Slack between the index region and the video region: real volumes have one, and it gives
    // whole-image carving somewhere to find unindexed clips.
    let slack_start = align_up(after_backup, BTREE_PAGE_SIZE);
    let slack_bytes: u64 = if spec.slack_clips.is_empty() {
        BTREE_PAGE_SIZE
    } else {
        // Enough room for each slack clip plus separation.
        spec.slack_clips
            .iter()
            .map(|c| loose_clip_len(c) + 4096)
            .sum::<u64>()
            .max(BTREE_PAGE_SIZE)
    };

    let video_start = align_up(slack_start + slack_bytes, BTREE_PAGE_SIZE);
    let real_block_count = spec.blocks.len() as u64;
    let total = video_start + real_block_count * spec.block_size + spec.trailing_slack;

    let mut bytes = vec![0u8; total as usize];

    // ── 2 + 3. Video blocks and their footers ────────────────────────────────────
    let mut block_layouts: Vec<HikBlockLayout> = Vec::new();
    for (i, block_spec) in spec.blocks.iter().enumerate() {
        let block_number = i as u32;
        let block_offset = video_start + block_number as u64 * spec.block_size;
        let footer_offset = block_offset + spec.block_size - footer_size;

        // Place the footer-described clips back to back from the block start, the way a
        // recorder writes them.
        let mut cursor = block_offset;
        let mut clip_layouts: Vec<HikClipLayout> = Vec::new();
        for (slot_index, clip_spec) in block_spec.clips.iter().enumerate() {
            if clip_spec.sentinel_before {
                write_at(&mut bytes, cursor, CARVE_SENTINEL);
                cursor += CARVE_SENTINEL.len() as u64;
            }
            let serial = (block_number as u32) * 1000 + slot_index as u32 + 1;
            let clip_bytes = clip_spec.bytes(serial);
            assert!(
                cursor + clip_bytes.len() as u64 <= footer_offset,
                "clip {slot_index} of block {block_number} does not fit in the block's video data"
            );
            write_at(&mut bytes, cursor, &clip_bytes);

            let slot_offset =
                footer_offset + BLOCK_INDEX_CLIP_BASE + slot_index as u64 * BLOCK_INDEX_CLIP_STRIDE;
            clip_layouts.push(HikClipLayout {
                slot_index,
                slot_offset,
                clip_offset: cursor,
                clip_length: clip_bytes.len() as u64,
                channel_raw: clip_spec.channel_raw,
                channel: clip_spec.channel_raw as u32 + 1,
                start_time: if clip_spec.start_time != 0 {
                    clip_spec.start_time
                } else {
                    clip_spec.time_a
                },
                end_time: clip_spec.end_time,
                codec: clip_spec.codec,
                expected_clip_id: format!("hikclip:b{block_number}:s{slot_index}:{:#x}", cursor),
            });
            // Separate clips so a carver's candidates are unambiguous.
            cursor += clip_bytes.len() as u64 + 512;
        }

        // Unindexed clips after the described ones, still inside video data.
        let mut loose_offsets: Vec<u64> = Vec::new();
        for loose in &block_spec.loose_clips {
            if loose.sentinel_before {
                write_at(&mut bytes, cursor, CARVE_SENTINEL);
                cursor += CARVE_SENTINEL.len() as u64;
            }
            let lb = loose_clip_bytes(loose, 9000 + loose_offsets.len() as u32);
            assert!(
                cursor + lb.len() as u64 <= footer_offset,
                "a loose clip does not fit in block {block_number}'s video data"
            );
            write_at(&mut bytes, cursor, &lb);
            loose_offsets.push(cursor);
            cursor += lb.len() as u64 + 512;
        }

        write_footer(
            &mut bytes,
            footer_offset,
            block_offset,
            block_spec,
            &clip_layouts,
        );

        block_layouts.push(HikBlockLayout {
            block_number,
            offset: block_offset,
            footer_offset,
            video_data_end: footer_offset,
            clips: match block_spec.footer {
                // A footer that carries no usable index describes no clip, so the layout must
                // not claim any — otherwise a test would assert against clips the parser is
                // correctly refusing to report.
                FooterMode::Valid => clip_layouts,
                _ => Vec::new(),
            },
            loose_clip_offsets: loose_offsets,
            footer: block_spec.footer,
        });
    }

    // ── Slack clips, outside every block ─────────────────────────────────────────
    let mut slack_clip_offsets = Vec::new();
    {
        let mut cursor = slack_start;
        for loose in &spec.slack_clips {
            if loose.sentinel_before {
                write_at(&mut bytes, cursor, CARVE_SENTINEL);
                cursor += CARVE_SENTINEL.len() as u64;
            }
            let lb = loose_clip_bytes(loose, 7000 + slack_clip_offsets.len() as u32);
            write_at(&mut bytes, cursor, &lb);
            slack_clip_offsets.push(cursor);
            cursor += lb.len() as u64 + 2048;
        }
    }

    // ── 4. Trees ─────────────────────────────────────────────────────────────────
    if let (Some(tree), Some(offset)) = (spec.primary_tree.as_ref(), primary_tree_offset) {
        write_tree(&mut bytes, offset, tree, &block_layouts);
    }
    if let (Some(tree), Some(offset)) = (spec.backup_tree.as_ref(), backup_tree_offset) {
        write_tree(&mut bytes, offset, tree, &block_layouts);
    }

    // ── 5. Boot structure ────────────────────────────────────────────────────────
    {
        let boot = spec.boot_offset as usize;
        let identifier = spec
            .identifier
            .clone()
            .unwrap_or_else(|| IDENTIFIER.to_vec());
        let end = (boot + 16 + identifier.len()).min(bytes.len());
        bytes[boot + 16..end].copy_from_slice(&identifier[..end - (boot + 16)]);

        let b = &mut bytes[boot..boot + BOOT_STRUCTURE_SIZE as usize];
        put_i64(
            b,
            120,
            spec.declared_video_start.unwrap_or(video_start as i64),
        );
        put_i64(
            b,
            136,
            spec.declared_block_size.unwrap_or(spec.block_size as i64),
        );
        put_i32(
            b,
            144,
            spec.declared_block_count.unwrap_or(real_block_count as i32),
        );
        put_i64(b, 152, primary_tree_offset.unwrap_or(0) as i64);
        put_i64(b, 160, primary_tree_size as i64);
        put_i64(b, 168, backup_tree_offset.unwrap_or(0) as i64);
        put_i64(b, 176, backup_tree_size as i64);
    }

    HikvisionImage {
        label: LABEL,
        bytes,
        boot_offset: spec.boot_offset,
        video_start,
        block_size: spec.block_size,
        footer_size,
        primary_tree_offset,
        primary_tree_size,
        backup_tree_offset,
        backup_tree_size,
        blocks: block_layouts,
        slack_clip_offsets,
    }
}

fn align_up(v: u64, to: u64) -> u64 {
    if to == 0 {
        return v;
    }
    v.div_ceil(to) * to
}

fn write_at(bytes: &mut [u8], offset: u64, data: &[u8]) {
    let start = offset as usize;
    let end = (start + data.len()).min(bytes.len());
    assert!(
        end > start,
        "write at {offset} falls outside the {}-byte image",
        bytes.len()
    );
    bytes[start..end].copy_from_slice(&data[..end - start]);
}

fn loose_clip_bytes(spec: &LooseClipSpec, serial: u32) -> Vec<u8> {
    parser_hikvision::testing::build::clip(
        serial,
        &spec.codec.elementary_stream(),
        spec.video_parts,
    )
}

fn loose_clip_len(spec: &LooseClipSpec) -> u64 {
    loose_clip_bytes(spec, 0).len() as u64
}

/// Write a block's footer clip index.
fn write_footer(
    bytes: &mut [u8],
    footer_offset: u64,
    block_offset: u64,
    spec: &HikBlockSpec,
    clips: &[HikClipLayout],
) {
    let f = footer_offset as usize;

    if spec.footer == FooterMode::Corrupt {
        // Deterministic noise, so the fixture stays reproducible.
        for i in 0..(BLOCK_INDEX_CLIP_BASE as usize + clips.len().max(1) * 512) {
            if f + i < bytes.len() {
                bytes[f + i] = ((i as u32).wrapping_mul(2_654_435_761) >> 11) as u8;
            }
        }
        // Force the marker byte to something that is not the reject value, so the parser gets
        // past the marker and has to reject the slots on their own merits.
        bytes[f + 13] = 0x01;
        return;
    }

    let header_end = f + BLOCK_INDEX_CLIP_BASE as usize;
    let header = &mut bytes[f..header_end];

    header[13] = match spec.footer {
        FooterMode::RejectByte => 0xFF,
        _ => 0x00,
    };

    let declared_count: u16 = match spec.footer {
        FooterMode::ZeroClipCount => 0,
        FooterMode::ImplausibleClipCount => 60_000,
        _ => spec.clips.len() as u16,
    };
    put_u16(header, 20, declared_count);

    // Epoch span across the block's clips.
    let epoch_start = spec
        .clips
        .iter()
        .map(|c| c.start_time.max(c.time_a))
        .min()
        .unwrap_or(T_BASE);
    let epoch_end = spec
        .clips
        .iter()
        .map(|c| c.end_time)
        .max()
        .unwrap_or(T_BASE);
    put_u32(header, 32, epoch_start);
    put_u32(header, 36, epoch_end);

    if matches!(
        spec.footer,
        FooterMode::RejectByte | FooterMode::ZeroClipCount | FooterMode::ImplausibleClipCount
    ) {
        // The header alone decides the outcome; slots are irrelevant and are left unwritten so
        // the fixture cannot accidentally pass through a path the header should have blocked.
        return;
    }

    for (spec_clip, layout) in spec.clips.iter().zip(clips) {
        let slot_start = layout.slot_offset as usize;
        let slot = &mut bytes[slot_start..slot_start + BLOCK_INDEX_CLIP_STRIDE as usize];

        slot[13] = spec_clip.channel_raw;
        put_u32(slot, 40, spec_clip.time_a);
        put_u32(slot, 48, spec_clip.end_time);
        put_u32(slot, 56, spec_clip.start_time);

        // Offsets are relative to the block start, which is what the parser adds back.
        let real_start = (layout.clip_offset - block_offset) as u32;
        let real_end = real_start + layout.clip_length as u32;
        put_u32(
            slot,
            72,
            spec_clip.declared_start_offset.unwrap_or(real_start),
        );
        put_u32(slot, 76, spec_clip.declared_end_offset.unwrap_or(real_end));
        slot[88] = spec_clip.frame_rate;
        // The two fields whose meaning is not established. Distinct values so a test can prove
        // they are preserved verbatim rather than zeroed or swapped.
        put_u32(slot, 108, 0xA1A2_A3A4);
        put_u32(slot, 112, 0xB1B2_B3B4);
    }
}

/// Write a HIKBTREE: header page, then the spec's pages.
fn write_tree(bytes: &mut [u8], tree_offset: u64, spec: &HikTreeSpec, blocks: &[HikBlockLayout]) {
    let page_at = |index: usize| tree_offset + index as u64 * BTREE_PAGE_SIZE;

    // ── Header page ──────────────────────────────────────────────────────────────
    {
        let h = tree_offset as usize;
        let magic = spec
            .magic
            .clone()
            .unwrap_or_else(|| HIKBTREE_MAGIC.to_vec());
        write_at(bytes, tree_offset, &magic);
        let header = &mut bytes[h..h + BTREE_PAGE_SIZE as usize];
        put_i32(header, 60, spec.tree_timestamp);
        put_i64(
            header,
            64,
            spec.first_pointer_page_index
                .map(|i| page_at(i) as i64)
                .unwrap_or(0),
        );
        put_i64(header, 72, 0);
        put_i64(header, 80, 0);
        put_i64(
            header,
            88,
            spec.first_leaf_page_index
                .map(|i| page_at(i) as i64)
                .unwrap_or(0),
        );
        put_i32(
            header,
            96,
            spec.declared_page_count.unwrap_or(spec.pages.len() as i32),
        );
    }

    // ── Pages ────────────────────────────────────────────────────────────────────
    for (i, page_spec) in spec.pages.iter().enumerate() {
        // Page index 0 is the header, so the spec's page i lives at index i + 1.
        let page_offset = page_at(i + 1);
        let p = page_offset as usize;

        match page_spec {
            HikPageSpec::Leaf {
                entries,
                next_page_index,
                declared_entry_count,
            } => {
                write_leaf(
                    bytes,
                    p,
                    page_offset,
                    entries,
                    declared_entry_count.unwrap_or(entries.len() as i32),
                    next_page_index.map(|n| page_at(n) as i64).unwrap_or(0),
                    blocks,
                );
            }
            HikPageSpec::LeafWithRawNext { entries, raw_next } => {
                write_leaf(
                    bytes,
                    p,
                    page_offset,
                    entries,
                    entries.len() as i32,
                    *raw_next,
                    blocks,
                );
            }
            HikPageSpec::Internal {
                other_page_index,
                next_page_index,
            } => {
                let page = &mut bytes[p..p + BTREE_PAGE_SIZE as usize];
                put_i32(page, 0, 3);
                put_i64(
                    page,
                    16,
                    other_page_index.map(|n| page_at(n) as i64).unwrap_or(0),
                );
                put_i64(
                    page,
                    24,
                    next_page_index.map(|n| page_at(n) as i64).unwrap_or(0),
                );
            }
            HikPageSpec::UnknownType { discriminator } => {
                let page = &mut bytes[p..p + BTREE_PAGE_SIZE as usize];
                put_i32(page, 0, *discriminator);
                // Plant plausible-looking leaf fields that a correct parser must not read.
                put_i32(page, 16, 1);
                put_i64(page, 32, 0);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn write_leaf(
    bytes: &mut [u8],
    p: usize,
    page_offset: u64,
    entries: &[HikEntrySpec],
    declared_count: i32,
    next: i64,
    blocks: &[HikBlockLayout],
) {
    {
        let page = &mut bytes[p..p + BTREE_PAGE_SIZE as usize];
        put_i32(page, 0, 2); // leaf
        put_i32(page, 16, declared_count);
        put_i64(page, 24, 0); // otherPageOffset
        put_i64(page, 32, next);
    }

    for (i, e) in entries.iter().enumerate() {
        let at = p + BTREE_LEAF_ENTRIES_OFFSET + i * BTREE_ENTRY_SIZE;
        if at + BTREE_ENTRY_SIZE > bytes.len() {
            break;
        }
        // Resolve the entry's data offset to the clip it targets, so the entry really points
        // into the bytes the footer describes.
        let data_offset = match e.target {
            Some((block, clip)) => blocks
                .iter()
                .find(|b| b.block_number == block)
                .and_then(|b| b.clips.get(clip))
                .map(|c| c.clip_offset as i64)
                .unwrap_or(e.data_offset),
            None => e.data_offset,
        };

        let entry = &mut bytes[at..at + BTREE_ENTRY_SIZE];
        put_i64(entry, 0, page_offset as i64);
        match e.sentinel {
            EntrySentinel::Populated => put_u64(entry, 8, 0),
            EntrySentinel::Blank => put_u64(entry, 8, u64::MAX),
            EntrySentinel::Malformed(v) => put_u64(entry, 8, v),
        }
        entry[17] = e.channel_raw;
        put_i32(entry, 24, e.start_time);
        put_i32(entry, 28, e.end_time);
        put_i64(entry, 32, data_offset);
        put_i32(entry, 40, e.status);
        put_i32(entry, 44, e.unknown);
    }
}

// ── Ready-made scenarios ────────────────────────────────────────────────────────

/// A complete, healthy two-block Hikvision volume.
///
/// Block 0 is referenced by the primary tree and holds two H.264 clips on channels 1 and 2.
/// Block 1 is **not** referenced by any entry, so its clips are the orphan-candidate set. Both
/// blocks also carry an unindexed clip in video data for the carver, and the tree includes a
/// blank slot so the blank-versus-populated distinction is exercised on a real volume.
pub fn realistic_dvr_volume() -> HikvisionImage {
    let spec = HikvisionImageSpec {
        blocks: vec![
            HikBlockSpec {
                clips: vec![
                    HikClipSpec {
                        channel_raw: 0,
                        start_time: T_BASE,
                        end_time: T_BASE + 600,
                        time_a: T_BASE,
                        include_ofni: true,
                        sentinel_before: true,
                        ..Default::default()
                    },
                    HikClipSpec {
                        channel_raw: 1,
                        start_time: T_BASE + 600,
                        end_time: T_BASE + 1200,
                        time_a: T_BASE + 600,
                        ..Default::default()
                    },
                ],
                loose_clips: vec![LooseClipSpec::default()],
                footer: FooterMode::Valid,
            },
            HikBlockSpec {
                clips: vec![HikClipSpec {
                    channel_raw: 2,
                    start_time: T_BASE + 2000,
                    end_time: T_BASE + 2600,
                    time_a: T_BASE + 2000,
                    codec: FixtureCodec::H265,
                    ..Default::default()
                }],
                loose_clips: Vec::new(),
                footer: FooterMode::Valid,
            },
        ],
        primary_tree: Some(HikTreeSpec::single_leaf(vec![
            HikEntrySpec::at(0, 0, 0),
            HikEntrySpec::at(0, 1, 1),
            HikEntrySpec::blank(),
        ])),
        backup_tree: Some(HikTreeSpec::single_leaf(vec![
            HikEntrySpec::at(0, 0, 0),
            HikEntrySpec::at(0, 1, 1),
            HikEntrySpec::blank(),
        ])),
        slack_clips: vec![LooseClipSpec::default()],
        ..Default::default()
    };
    build_hikvision_image(&spec)
}

/// A volume whose recording continues across a block boundary on one channel.
///
/// Block 0's clip ends where block 1's clip begins in time, both on channel 1, so the two must
/// reconstruct as a single multi-block recording.
pub fn multi_block_recording_volume() -> HikvisionImage {
    let spec = HikvisionImageSpec {
        blocks: vec![
            HikBlockSpec {
                clips: vec![HikClipSpec {
                    channel_raw: 0,
                    start_time: T_BASE,
                    end_time: T_BASE + 600,
                    time_a: T_BASE,
                    ..Default::default()
                }],
                ..Default::default()
            },
            HikBlockSpec {
                clips: vec![HikClipSpec {
                    channel_raw: 0,
                    start_time: T_BASE + 600,
                    end_time: T_BASE + 1200,
                    time_a: T_BASE + 600,
                    ..Default::default()
                }],
                ..Default::default()
            },
        ],
        primary_tree: Some(HikTreeSpec::single_leaf(vec![
            HikEntrySpec::at(0, 0, 0),
            HikEntrySpec::at(1, 0, 0),
        ])),
        ..Default::default()
    };
    build_hikvision_image(&spec)
}

/// A volume with a single block, a single clip and a single-entry primary tree.
///
/// The smallest image that exercises the whole production path end to end.
pub fn minimal_volume() -> HikvisionImage {
    let spec = HikvisionImageSpec {
        blocks: vec![HikBlockSpec::default()],
        primary_tree: Some(HikTreeSpec::single_leaf(vec![HikEntrySpec::at(0, 0, 0)])),
        ..Default::default()
    };
    build_hikvision_image(&spec)
}

/// A volume carrying the identifier but no usable index tree.
pub fn no_index_volume() -> HikvisionImage {
    let spec = HikvisionImageSpec {
        blocks: vec![HikBlockSpec::default()],
        primary_tree: None,
        backup_tree: None,
        ..Default::default()
    };
    build_hikvision_image(&spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_built_image_is_labelled_synthetic() {
        assert_eq!(minimal_volume().label, "synthetic");
        assert_eq!(LABEL, "synthetic");
    }

    #[test]
    fn the_identifier_lands_at_the_boot_position_plus_sixteen() {
        let img = minimal_volume();
        let at = (img.boot_offset + 16) as usize;
        assert_eq!(&img.bytes[at..at + IDENTIFIER.len()], IDENTIFIER);
    }

    #[test]
    fn the_boot_structure_declares_the_offsets_the_builder_actually_used() {
        let img = minimal_volume();
        let b = &img.bytes[img.boot_offset as usize..][..512];
        let read_i64 = |at: usize| {
            i64::from_le_bytes([
                b[at],
                b[at + 1],
                b[at + 2],
                b[at + 3],
                b[at + 4],
                b[at + 5],
                b[at + 6],
                b[at + 7],
            ])
        };
        assert_eq!(read_i64(120) as u64, img.video_start);
        assert_eq!(read_i64(136) as u64, img.block_size);
        assert_eq!(read_i64(152) as u64, img.primary_tree_offset.unwrap());
        assert_eq!(read_i64(160) as u64, img.primary_tree_size);
    }

    #[test]
    fn the_tree_magic_lands_at_the_declared_tree_offset() {
        let img = minimal_volume();
        let at = img.primary_tree_offset.unwrap() as usize;
        assert_eq!(&img.bytes[at..at + 8], HIKBTREE_MAGIC);
    }

    #[test]
    fn a_clip_is_written_inside_its_blocks_video_data_never_in_the_footer() {
        let img = realistic_dvr_volume();
        for (block, clip) in img.clips() {
            assert!(clip.clip_offset >= block.offset);
            assert!(
                clip.clip_offset + clip.clip_length <= block.footer_offset,
                "clip {} runs into block {}'s footer",
                clip.expected_clip_id,
                block.block_number
            );
            // The slot describing it must be in the footer, not in video data.
            assert!(clip.slot_offset >= block.footer_offset);
        }
    }

    #[test]
    fn footer_slots_are_512_bytes_apart_starting_512_into_the_footer() {
        let img = realistic_dvr_volume();
        let block = img.block(0).unwrap();
        for (i, clip) in block.clips.iter().enumerate() {
            assert_eq!(
                clip.slot_offset,
                block.footer_offset + 512 + i as u64 * 512,
                "slot {i} is not at the declared stride"
            );
        }
    }

    #[test]
    fn the_footer_slot_declares_the_clips_real_offsets_relative_to_the_block() {
        let img = minimal_volume();
        let block = img.block(0).unwrap();
        let clip = &block.clips[0];
        let slot = &img.bytes[clip.slot_offset as usize..][..512];
        let read_u32 =
            |at: usize| u32::from_le_bytes([slot[at], slot[at + 1], slot[at + 2], slot[at + 3]]);
        assert_eq!(
            read_u32(72) as u64,
            clip.clip_offset - block.offset,
            "startOffset must be relative to the block"
        );
        assert_eq!(
            read_u32(76) as u64 - read_u32(72) as u64,
            clip.clip_length,
            "endOffset - startOffset must be the clip length"
        );
    }

    #[test]
    fn a_btree_entry_points_at_the_clips_real_physical_offset() {
        let img = minimal_volume();
        let clip = &img.block(0).unwrap().clips[0];
        let tree = img.primary_tree_offset.unwrap();
        let entry_at = (tree + BTREE_PAGE_SIZE) as usize + BTREE_LEAF_ENTRIES_OFFSET;
        let e = &img.bytes[entry_at..entry_at + BTREE_ENTRY_SIZE];
        let data_offset =
            i64::from_le_bytes([e[32], e[33], e[34], e[35], e[36], e[37], e[38], e[39]]);
        assert_eq!(data_offset as u64, clip.clip_offset);
        // The sentinel must be the populated value.
        let sentinel = u64::from_le_bytes([e[8], e[9], e[10], e[11], e[12], e[13], e[14], e[15]]);
        assert_eq!(sentinel, 0);
    }

    #[test]
    fn a_block_whose_footer_is_unusable_reports_no_clips_in_the_layout() {
        for mode in [
            FooterMode::RejectByte,
            FooterMode::ZeroClipCount,
            FooterMode::ImplausibleClipCount,
            FooterMode::Corrupt,
        ] {
            let img = build_hikvision_image(&HikvisionImageSpec {
                blocks: vec![HikBlockSpec {
                    footer: mode,
                    ..Default::default()
                }],
                ..Default::default()
            });
            assert!(
                img.block(0).unwrap().clips.is_empty(),
                "{mode:?} must not claim clips the parser will reject"
            );
        }
    }

    #[test]
    fn the_builder_is_deterministic() {
        let a = realistic_dvr_volume();
        let b = realistic_dvr_volume();
        assert_eq!(a.bytes, b.bytes);
    }

    #[test]
    fn the_realistic_volume_has_referenced_and_unreferenced_blocks() {
        let img = realistic_dvr_volume();
        assert_eq!(img.blocks.len(), 2);
        // Block 0's clips are the ones the tree entries target.
        assert_eq!(img.block(0).unwrap().clips.len(), 2);
        assert_eq!(img.block(1).unwrap().clips.len(), 1);
        // Unindexed clips exist for the carver, inside a block and in slack.
        assert_eq!(img.block(0).unwrap().loose_clip_offsets.len(), 1);
        assert_eq!(img.slack_clip_offsets.len(), 1);
    }

    #[test]
    fn a_secondary_boot_position_image_is_buildable() {
        let img = build_hikvision_image(&HikvisionImageSpec {
            boot_offset: SECONDARY_BOOT_OFFSET,
            blocks: vec![HikBlockSpec::default()],
            primary_tree: Some(HikTreeSpec::single_leaf(vec![HikEntrySpec::at(0, 0, 0)])),
            ..Default::default()
        });
        let at = (SECONDARY_BOOT_OFFSET + 16) as usize;
        assert_eq!(&img.bytes[at..at + IDENTIFIER.len()], IDENTIFIER);
    }

    #[test]
    fn expected_clip_ids_match_the_parsers_derivation_format() {
        let img = minimal_volume();
        let clip = &img.block(0).unwrap().clips[0];
        assert_eq!(
            clip.expected_clip_id,
            format!("hikclip:b0:s0:{:#x}", clip.clip_offset)
        );
    }
}
