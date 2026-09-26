//! Shared deterministic Dahua **DHFS 4.1** fixture for the recovery integration tests.
//!
//! The fixture writes the real structure set — volume signature, partition table, partition
//! information, block table, video blocks, and DHAV frames — using the field layout the
//! `profiles/dahua/dahua-dhfs-v1.0.toml` `[layout]` table declares. Nothing bypasses the parser:
//! it has to walk the partition table and the block table for a test to observe any claim at all.
//!
//! It is self-contained rather than reusing `forensic_tests::dahua_fixtures`, so the recovery
//! crate's tests do not depend on the cross-crate test crate that in turn depends on recovery.
//!
//! ## What it contains, and which recovery path each element exercises
//!
//! | Block | Contents                                            | Expected finding                      |
//! |-------|-----------------------------------------------------|---------------------------------------|
//! | 0     | an **unused** table slot that physically holds video | `Orphaned` via unclaimed-in-scope     |
//! | 1 → 2 | an accessible two-block chain, channel 1            | `Active`                              |
//! | 3     | an accessible one-block chain, channel 2            | `Active`                              |
//! | 4     | occupied, fully described, unreachable, channel 3   | `Orphaned` via available-metadata     |
//! | 5     | an unused slot holding nothing                      | no candidate                          |
//! | slack | one DHAV frame past the video region                | `Unindexed`                           |
//!
//! Block 1 is a whole 2 MiB block, so the planner's probe-vs-sweep saving is measurable on the
//! real path rather than only in a unit test.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use evidence_reader::RawReader;
use forensic_core::{CancelToken, OemProfile, ProfileRegistry, RecoveryBounds, Region};

pub const SECTOR: u64 = 512;
pub const VIDEO_BLOCK: u64 = 2 * 1024 * 1024;
pub const BLOCK_ENTRY_SIZE: u64 = 32;
pub const PARTITION_TABLE_PRIMARY: u64 = 0x3C00;
pub const PARTITION_TABLE_IDENTIFIER_OFFSET: u64 = 304;
pub const PARTITION_ID_GEN1: [u8; 8] = [0x01, 0, 0, 0, 0xAA, 0x55, 0xAA, 0x55];
pub const DHFS41_SIGNATURE: &[u8] = b"DHFS4.1\0";

pub const PARTITION_START_SECTOR: i64 = 128;
pub const PARTITION_INFO_SECTOR: i32 = 1;
pub const INDEX_START_SECTOR: i32 = 2;
pub const VIDEO_START_SECTOR: i32 = 64;

/// Encode wall-clock digits into Dahua's packed base-2000 field.
pub fn pack_timestamp(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> u32 {
    let year_field = (year - 2000) as u32;
    assert!(year_field <= 63, "year outside the packed encoding's range");
    (year_field << 26) | (month << 22) | (day << 17) | (hour << 12) | (minute << 6) | second
}

/// A short but genuine H.264 Annex-B clip: SPS + PPS + IDR + a few P-slices.
///
/// Real parameter sets matter: the codec classifier only returns PASS on actual SPS/PPS NAL
/// headers, so a fabricated byte pattern would fail validation and could never reach an Active or
/// Orphaned classification. The tests therefore cannot pass on fake data.
pub fn h264_clip(seed: u8) -> Vec<u8> {
    h264_clip_of_len(seed, 0)
}

/// As [`h264_clip`], padded with additional P-slice NALs until at least `min_len` bytes.
pub fn h264_clip_of_len(seed: u8, min_len: usize) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1F, 0x96, 0x54, 0x0A, 0x0F,
    ]);
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x3C, 0x80]);
    v.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x01, 0x65, 0xB8, 0x00, 0x04, seed, 0x11, 0x22, 0x33,
    ]);
    let mut i = 0u32;
    while v.len() < min_len || i < 6 {
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x41, 0x9A, seed, (i & 0xFF) as u8]);
        i += 1;
    }
    v
}

pub fn align_up(v: u64, a: u64) -> u64 {
    v.div_ceil(a) * a
}

/// One recorded segment in the fixture, and where it ended up.
pub struct Segment {
    /// 0-based channel as stored in the DHAV header.
    pub channel0: u16,
    /// 1-based channel as stored in the block-table entry.
    pub channel1: u8,
    pub packed_timestamp: u32,
    pub payload: Vec<u8>,
    /// Which block holds it, when a block-table entry describes it.
    pub block_number: Option<u32>,
    /// Whether a first-block traversal reaches its chain.
    pub accessible: bool,
    /// Absolute offset of its DHAV frame.
    pub frame_offset: u64,
    /// Total DHAV frame length.
    pub frame_total: u64,
}

/// The fixture's computed layout, so tests assert against derived offsets rather than constants.
pub struct Fixture {
    pub bytes: Vec<u8>,
    pub segments: Vec<Segment>,
    pub partition_base: u64,
    pub info_offset: u64,
    pub block_table_offset: u64,
    pub video_base: u64,
    pub block_count: u32,
    /// Offset of the DHAV frame placed in slack past the video region.
    pub loose_frame_offset: u64,
    pub loose_frame_len: u64,
    pub disk_size: u64,
}

impl Fixture {
    pub fn segment(&self, i: usize) -> &Segment {
        &self.segments[i]
    }

    /// Absolute offset of a block's payload area.
    pub fn block_offset(&self, block_number: u32) -> u64 {
        self.video_base + block_number as u64 * VIDEO_BLOCK
    }

    /// The whole frame region for a segment.
    pub fn frame_region(&self, i: usize) -> Region {
        let s = self.segment(i);
        Region::new(s.frame_offset, s.frame_total).unwrap()
    }

    /// The video region the partition declares.
    pub fn video_region(&self) -> Region {
        Region::new(self.video_base, self.block_count as u64 * VIDEO_BLOCK).unwrap()
    }
}

/// Serialize one DHAV frame with the real framing, and return it.
///
///   `DHAV` | type | subtype | u16 channel | u32 frame no | i32 total | u32 packed date
///          | u16 sub-ts | u8 ext len | u8 checksum | ext header | payload | `dhav` + u32
pub fn build_dhav_frame(
    channel0: u16,
    frame_number: u32,
    packed_timestamp: u32,
    payload: &[u8],
) -> Vec<u8> {
    // Extra header: 0x82 exact resolution (8 bytes) then 0x81 codec + fps (4 bytes).
    let mut extra: Vec<u8> = Vec::new();
    extra.extend_from_slice(&[0x82, 0, 0, 0]);
    extra.extend_from_slice(&1280u16.to_le_bytes());
    extra.extend_from_slice(&720u16.to_le_bytes());
    extra.extend_from_slice(&[0x81, 0, 0x04, 15]);

    let total = 24 + extra.len() + payload.len() + 8;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(b"DHAV");
    out.push(0xFD); // video key frame
    out.push(0x01); // subtype
    out.extend_from_slice(&channel0.to_le_bytes());
    out.extend_from_slice(&frame_number.to_le_bytes());
    out.extend_from_slice(&(total as u32).to_le_bytes());
    out.extend_from_slice(&packed_timestamp.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // intra-second counter
    out.push(extra.len() as u8);
    out.push(0); // checksum
    assert_eq!(out.len(), 24, "the DHAV fixed header is 24 bytes");
    out.extend_from_slice(&extra);
    out.extend_from_slice(payload);
    out.extend_from_slice(b"dhav");
    out.extend_from_slice(&((total - 8) as u32).to_le_bytes());
    assert_eq!(out.len(), total);
    out
}

/// Serialize a 32-byte block-table entry.
#[allow(clippy::too_many_arguments)]
pub fn build_block_entry(
    type_byte: u8,
    channel1: u8,
    start_ts: u32,
    end_ts: u32,
    next_block: i32,
    sector_count: i16,
    previous_block: i32,
    first_block: i32,
) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = type_byte;
    b[1] = (channel1.saturating_sub(1)) & 0x0F;
    b[4..8].copy_from_slice(&start_ts.to_le_bytes());
    b[8..12].copy_from_slice(&end_ts.to_le_bytes());
    b[12..16].copy_from_slice(&next_block.to_le_bytes());
    b[16..18].copy_from_slice(&sector_count.to_le_bytes());
    b[20..24].copy_from_slice(&previous_block.to_le_bytes());
    b[24..28].copy_from_slice(&first_block.to_le_bytes());
    b
}

/// Build the deterministic DHFS 4.1 fixture described in the module docs.
pub fn build_fixture() -> Fixture {
    let base = pack_timestamp(2026, 9, 22, 8, 0, 0);
    let plus = |mins: u32| pack_timestamp(2026, 9, 22, 8 + mins / 60, mins % 60, 0);

    let partition_base = PARTITION_START_SECTOR as u64 * SECTOR;
    let info_offset = partition_base + PARTITION_INFO_SECTOR as u64 * SECTOR;
    let block_table_offset = partition_base + INDEX_START_SECTOR as u64 * SECTOR;
    let video_base = partition_base + VIDEO_START_SECTOR as u64 * SECTOR;
    let block_count: u32 = 6;

    let loose_frame_offset = video_base + block_count as u64 * VIDEO_BLOCK + 0x1000;
    let mut segments: Vec<Segment> = Vec::new();

    // Frames, in block order. Block 0 holds video that no entry claims.
    let planned: Vec<(u32, u16, u8, u32, Vec<u8>, bool)> = vec![
        // (block, channel0, channel1, timestamp, payload, described-by-an-entry)
        (0, 0, 1, base, h264_clip(0xA0), false),
        (1, 0, 1, base, h264_clip_of_len(0xA1, 4096), true),
        (2, 0, 1, plus(5), h264_clip(0xA2), true),
        (3, 1, 2, plus(60), h264_clip(0xB3), true),
        (4, 2, 3, plus(120), h264_clip(0xC4), true),
    ];

    let mut disk_size = loose_frame_offset;
    let loose_payload = h264_clip(0xE5);
    let loose_frame = build_dhav_frame(3, 1, plus(180), &loose_payload);
    disk_size = align_up(disk_size + loose_frame.len() as u64 + SECTOR, SECTOR);

    let mut buf = vec![0u8; disk_size as usize];

    // ── Volume signature and descriptors ────────────────────────────────────
    buf[..DHFS41_SIGNATURE.len()].copy_from_slice(DHFS41_SIGNATURE);
    buf[48..48 + 13].copy_from_slice(b"DHI-XVR5216AN");
    buf[64..64 + 22].copy_from_slice(b"DH-SN-2026-XVR-ORPHAN1");
    buf[96..96 + 12].copy_from_slice(b"DVR_REC_VOL0");

    // ── Partition table with one entry ──────────────────────────────────────
    let t = PARTITION_TABLE_PRIMARY as usize;
    buf[t + PARTITION_TABLE_IDENTIFIER_OFFSET as usize
        ..t + PARTITION_TABLE_IDENTIFIER_OFFSET as usize + 8]
        .copy_from_slice(&PARTITION_ID_GEN1);
    buf[t + 20..t + 24].copy_from_slice(&PARTITION_INFO_SECTOR.to_le_bytes());
    buf[t + 48..t + 56].copy_from_slice(&PARTITION_START_SECTOR.to_le_bytes());

    // ── Partition information ───────────────────────────────────────────────
    let i = info_offset as usize;
    buf[i + 68..i + 72].copy_from_slice(&INDEX_START_SECTOR.to_le_bytes());
    buf[i + 72..i + 76].copy_from_slice(&VIDEO_START_SECTOR.to_le_bytes());
    buf[i + 76..i + 80].copy_from_slice(&(block_count as i32).to_le_bytes());

    // ── Frames into their blocks ────────────────────────────────────────────
    for (idx, (block, channel0, channel1, ts, payload, described)) in planned.iter().enumerate() {
        let frame = build_dhav_frame(*channel0, idx as u32 + 1, *ts, payload);
        let at = (video_base + *block as u64 * VIDEO_BLOCK) as usize;
        buf[at..at + frame.len()].copy_from_slice(&frame);
        segments.push(Segment {
            channel0: *channel0,
            channel1: *channel1,
            packed_timestamp: *ts,
            payload: payload.clone(),
            block_number: if *described { Some(*block) } else { None },
            // Filled in below once the chain shape is known.
            accessible: false,
            frame_offset: at as u64,
            frame_total: frame.len() as u64,
        });
    }

    // ── Block table ─────────────────────────────────────────────────────────
    // Block 0: an unused slot. It physically holds video, which is exactly the
    // unclaimed-within-index-scope case: the block table governs these bytes and does not
    // claim them.
    let entries: Vec<[u8; 32]> = vec![
        build_block_entry(0xFE, 1, 0, 0, 0, 0, 0, 0),
        // Block 1: head of the accessible two-block chain, a whole block.
        build_block_entry(0x01, 1, base, plus(5), 2, 0, 0, 1),
        // Block 2: its tail, partially filled.
        build_block_entry(0x01, 1, plus(5), plus(10), 0, 512, 1, 1),
        // Block 3: an accessible one-block chain.
        build_block_entry(0x01, 2, plus(60), plus(63), 0, 256, 0, 3),
        // Block 4: occupied and fully described, but PreviousBlock points outside any chain and
        // it declares no FirstBlock, so no traversal reaches it — the available case.
        build_block_entry(0x01, 3, plus(120), plus(123), 0, 128, 99, 0),
        // Block 5: an unused slot holding nothing.
        build_block_entry(0xFE, 1, 0, 0, 0, 0, 0, 0),
    ];
    for (n, e) in entries.iter().enumerate() {
        let at = block_table_offset as usize + n * BLOCK_ENTRY_SIZE as usize;
        buf[at..at + 32].copy_from_slice(e);
    }

    // Blocks 1, 2 and 3 are reachable from a declared first block; block 4 is not.
    for seg in segments.iter_mut() {
        seg.accessible = matches!(seg.block_number, Some(1) | Some(2) | Some(3));
    }

    // ── A loose frame in slack, past the declared video region ──────────────
    let lf = loose_frame_offset as usize;
    buf[lf..lf + loose_frame.len()].copy_from_slice(&loose_frame);

    Fixture {
        bytes: buf,
        segments,
        partition_base,
        info_offset,
        block_table_offset,
        video_base,
        block_count,
        loose_frame_offset,
        loose_frame_len: loose_frame.len() as u64,
        disk_size,
    }
}

/// Locate `profiles/` from wherever cargo runs the test.
pub fn profiles_dir() -> PathBuf {
    for p in [
        "profiles",
        "../profiles",
        "../../profiles",
        "../../../profiles",
    ] {
        if Path::new(p).exists() {
            return PathBuf::from(p);
        }
    }
    panic!("could not locate the profiles/ directory");
}

pub fn dahua_profile(registry: &ProfileRegistry) -> &OemProfile {
    registry
        .find_applicable("dahua", None, None, None)
        .expect("the real Dahua profile must load from profiles/dahua/")
}

pub fn bounds() -> RecoveryBounds {
    RecoveryBounds {
        max_scan_bytes: u64::MAX,
        max_scan_regions: u32::MAX,
        max_candidates: u32::MAX,
        max_hypotheses: 1024,
        max_search_depth: None,
        cancel: CancelToken::new(),
        time_limit: None,
    }
}

/// Write the fixture to a temp file and open it through the production `RawReader`, so the test
/// exercises the same read path as a real acquired image.
pub fn open_fixture(fx: &Fixture) -> (tempfile::TempDir, RawReader) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("dahua_dhfs41_fixture.raw");
    std::fs::write(&path, &fx.bytes).expect("write fixture");
    let reader = RawReader::open(path.to_str().unwrap()).expect("open fixture read-only");
    (dir, reader)
}
