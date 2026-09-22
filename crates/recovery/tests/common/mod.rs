//! Shared deterministic Dahua DHFS fixture for the recovery integration tests.
//!
//! The fixture writes real DHFS/DHAV/DIDX structures using the field layout the
//! `profiles/dahua/dahua-dhfs-v1.0.toml` `[layout]` table declares — the same layout
//! `generate_dahua_raw.py` produces. Nothing here bypasses the parser: the parser must
//! read the superblock and walk the index for a test to observe any claims at all.
//!
//! It contains four physically present H.264 recordings and a DIDX index that references
//! only three of them, plus a trailing H.264 blob past the index region. That gives one
//! orphan-eligible recording (present, governed by the index, unreferenced) and one region
//! the index makes no statement about.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use evidence_reader::RawReader;
use forensic_core::{CancelToken, OemProfile, ProfileRegistry, RecoveryBounds, Region};
pub const SECTOR: u64 = 512;
pub const DHAV_HEADER: u64 = 64;
pub const DHAV_FOOTER: u64 = 4;
pub const BLOCK_SIZE: u32 = 65536;
pub const BASE_UNIX: u64 = 1_790_000_000;

/// A short but genuine H.264 Annex-B clip: SPS + PPS + IDR + a few P-slices.
///
/// Real parameter sets matter: the codec classifier only returns PASS on actual SPS/PPS
/// NAL headers, so a fabricated byte pattern would fail validation and could never reach
/// an Active or Orphaned classification. The test therefore cannot pass on fake data.
pub fn h264_clip(seed: u8) -> Vec<u8> {
    h264_clip_of_len(seed, 0)
}

/// As [`h264_clip`], padded with additional P-slice NALs until the clip is at least
/// `min_len` bytes.
///
/// A realistically long recording matters for one assertion: index-aware planning probes
/// a claimed range instead of sweeping it, and that saving is only measurable when a claim
/// is larger than the probe cap.
pub fn h264_clip_of_len(seed: u8, min_len: usize) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1F, 0x96, 0x54, 0x0A, 0x0F]);
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x3C, 0x80]);
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x65, 0xB8, 0x00, 0x04, seed, 0x11, 0x22, 0x33]);
    let mut i = 0u32;
    while v.len() < min_len || i < 6 {
        v.extend_from_slice(&[
            0x00,
            0x00,
            0x00,
            0x01,
            0x41,
            0x9A,
            seed,
            (i & 0xFF) as u8,
        ]);
        i += 1;
    }
    v
}

pub fn align_up(v: u64, a: u64) -> u64 {
    ((v + a - 1) / a) * a
}

pub fn put_u32(buf: &mut [u8], at: u64, v: u32) {
    let at = at as usize;
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

pub fn put_u64(buf: &mut [u8], at: u64, v: u64) {
    let at = at as usize;
    buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// One recorded segment in the fixture.
pub struct Segment {
    /// 0-based channel as stored on disk.
    pub channel0: u8,
    pub timestamp: u64,
    pub payload: Vec<u8>,
    /// Whether the DIDX index references this segment.
    pub indexed: bool,
    // Filled in during layout.
    pub offset: u64,
    pub total: u64,
}

/// The fixture's computed layout, so the test asserts against derived offsets rather
/// than hard-coded numbers.
pub struct Fixture {
    pub bytes: Vec<u8>,
    pub segments: Vec<Segment>,
    pub video_start: u64,
    pub index_offset: u64,
    pub index_len: u64,
    /// Offset of the trailing H.264 blob placed after the index region.
    pub trailing_video_offset: u64,
    pub trailing_video_len: u64,
    pub disk_size: u64,
}

impl Fixture {
    pub fn segment(&self, i: usize) -> &Segment {
        &self.segments[i]
    }

    /// Physical region the DIDX index claims for a segment (whole DHAV packet).
    pub fn packet_region(&self, i: usize) -> Region {
        let s = self.segment(i);
        Region::new(s.offset, s.total).unwrap()
    }
}

/// Write one DHAV packet and return its total length.
pub fn write_dhav(buf: &mut [u8], at: u64, seg: &Segment, seq: u32) -> u64 {
    let total = DHAV_HEADER + seg.payload.len() as u64 + DHAV_FOOTER;
    let a = at as usize;
    buf[a..a + 4].copy_from_slice(b"DHAV");
    buf[a + 4] = 0xFD; // I-frame
    buf[a + 5] = seg.channel0;
    put_u32(buf, at + 8, seq);
    put_u32(buf, at + 12, total as u32);
    put_u64(buf, at + 16, seg.timestamp);
    put_u32(buf, at + 24, 0x2026_0922);
    buf[a + 28..a + 30].copy_from_slice(&1280u16.to_le_bytes());
    buf[a + 30..a + 32].copy_from_slice(&720u16.to_le_bytes());
    let codec = b"H.264/AVC";
    buf[a + 32..a + 32 + codec.len()].copy_from_slice(codec);
    let name = format!("CH{:02}", seg.channel0 + 1).into_bytes();
    buf[a + 48..a + 48 + name.len()].copy_from_slice(&name);

    let p = a + DHAV_HEADER as usize;
    buf[p..p + seg.payload.len()].copy_from_slice(&seg.payload);
    let f = p + seg.payload.len();
    buf[f..f + 4].copy_from_slice(b"dhav");
    total
}

/// Build the deterministic DHFS fixture described in the module docs.
pub fn build_fixture() -> Fixture {
    // Four physically present recordings; segment index 2 is deliberately NOT indexed.
    let mut segments = vec![
        Segment { channel0: 0, timestamp: BASE_UNIX, payload: h264_clip(0xA1), indexed: true, offset: 0, total: 0 },
        Segment { channel0: 1, timestamp: BASE_UNIX + 300, payload: h264_clip(0xB2), indexed: true, offset: 0, total: 0 },
        // The orphan: real video, no index entry.
        Segment { channel0: 0, timestamp: BASE_UNIX + 600, payload: h264_clip(0xC3), indexed: false, offset: 0, total: 0 },
        // A long indexed recording, so the probe-vs-sweep saving is measurable on the
        // real path rather than only in a unit test.
        Segment {
            channel0: 1,
            timestamp: BASE_UNIX + 900,
            payload: h264_clip_of_len(0xD4, 3 * 1024 * 1024),
            indexed: true,
            offset: 0,
            total: 0,
        },
    ];

    // Lay segments out on sector-aligned boundaries, spaced so each short segment lands in
    // its own planner chunk and the claimed/unclaimed split is unambiguous. The slot is
    // wide enough to hold the longest segment.
    let video_start = SECTOR;
    let slot = 4 * 1024 * 1024u64;
    for (i, seg) in segments.iter_mut().enumerate() {
        seg.offset = align_up(video_start + (i as u64) * slot, SECTOR);
        seg.total = DHAV_HEADER + seg.payload.len() as u64 + DHAV_FOOTER;
    }

    let indexed_count = segments.iter().filter(|s| s.indexed).count() as u64;
    let last_end = segments.last().map(|s| s.offset + s.total).unwrap_or(video_start);
    let index_offset = align_up(last_end + slot, SECTOR);
    let index_len = 16 + indexed_count * 32;

    // A trailing H.264 blob past the index region: physically present video that no
    // authoritative index statement covers.
    let trailing_video = h264_clip(0xE5);
    let trailing_video_offset = align_up(index_offset + index_len + SECTOR, SECTOR);
    let trailing_video_len = trailing_video.len() as u64;

    let disk_size = align_up(trailing_video_offset + trailing_video_len + SECTOR, slot);
    let mut buf = vec![0u8; disk_size as usize];

    // ── DHFS superblock, using the field layout the profile declares ─────────
    buf[0..4].copy_from_slice(b"DHFS");
    put_u32(&mut buf, 4, 0x0001_0000); // version
    put_u32(&mut buf, 8, SECTOR as u32); // sector_size
    put_u32(&mut buf, 12, BLOCK_SIZE); // block_size
    put_u64(&mut buf, 16, disk_size / BLOCK_SIZE as u64); // total_blocks
    put_u64(&mut buf, 24, video_start); // dhav_start
    put_u64(&mut buf, 32, index_offset); // index_offset
    put_u64(&mut buf, 40, BASE_UNIX); // ctime
    buf[48..48 + 13].copy_from_slice(b"DHI-XVR5216AN");
    buf[64..64 + 22].copy_from_slice(b"DH-SN-2026-XVR-ORPHAN1");
    buf[96..96 + 12].copy_from_slice(b"DVR_REC_VOL0");

    // ── DHAV packets ────────────────────────────────────────────────────────
    for (i, seg) in segments.iter().enumerate() {
        write_dhav(&mut buf, seg.offset, seg, i as u32 + 1);
    }

    // ── DIDX index: only the indexed segments ───────────────────────────────
    buf[index_offset as usize..index_offset as usize + 4].copy_from_slice(b"DIDX");
    put_u32(&mut buf, index_offset + 4, indexed_count as u32);
    let mut e = index_offset + 16;
    for seg in segments.iter().filter(|s| s.indexed) {
        buf[e as usize] = seg.channel0;
        buf[e as usize + 1] = 0xFD;
        put_u64(&mut buf, e + 4, seg.offset);
        put_u64(&mut buf, e + 12, seg.total);
        put_u64(&mut buf, e + 20, seg.timestamp);
        put_u32(&mut buf, e + 28, 0x1A2B_3C4D);
        e += 32;
    }

    // ── Trailing video outside the governed region ───────────────────────────
    let tv = trailing_video_offset as usize;
    buf[tv..tv + trailing_video.len()].copy_from_slice(&trailing_video);

    Fixture {
        bytes: buf,
        segments,
        video_start,
        index_offset,
        index_len,
        trailing_video_offset,
        trailing_video_len,
        disk_size,
    }
}

/// Locate `profiles/` from wherever cargo runs the test.
pub fn profiles_dir() -> PathBuf {
    for p in ["profiles", "../profiles", "../../profiles", "../../../profiles"] {
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

/// Write the fixture to a temp file and open it through the production `RawReader`, so
/// the test exercises the same read path as a real acquired image.
pub fn open_fixture(fx: &Fixture) -> (tempfile::TempDir, RawReader) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("dahua_dhfs_orphan_fixture.raw");
    std::fs::write(&path, &fx.bytes).expect("write fixture");
    let reader = RawReader::open(path.to_str().unwrap()).expect("open fixture read-only");
    (dir, reader)
}

