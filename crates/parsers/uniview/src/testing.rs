//! # Sparse in-memory evidence and Uniview structure builders
//!
//! A NEW-generation Uniview disk puts its first unit at `0x10014000` (256 MiB in), so a
//! realistic test image cannot be a dense `Vec<u8>`. [`SparseReader`] presents a declared
//! length through the read-only [`EvidenceReader`] trait, returning the bytes that were placed
//! and zeros everywhere else.
//!
//! Compiled unconditionally (not behind `#[cfg(test)]`) so this crate's integration tests can
//! use it. It exposes no write path to real evidence: it owns its own segments and implements
//! the same read-only trait every production reader does.
//!
//! The builders in [`build`] encode structures from the same documented field layout the
//! parser reads, so a test asserts against structure rather than against a copied byte array.

use std::collections::BTreeMap;

use evidence_reader::{EvidenceReader, SourceKind};
use forensic_core::ForensicError;

/// A declared-length image made of placed byte segments over a zero background.
#[derive(Debug, Clone)]
pub struct SparseReader {
    len: u64,
    segments: BTreeMap<u64, Vec<u8>>,
    path: String,
}

impl SparseReader {
    pub fn new(len: u64) -> Self {
        Self {
            len,
            segments: BTreeMap::new(),
            path: "mem://uniview-structure-test".to_string(),
        }
    }

    /// Place `bytes` at `offset`. Bytes past the declared length are dropped, so a builder
    /// cannot accidentally make an image longer than it claims to be.
    pub fn with(mut self, offset: u64, bytes: &[u8]) -> Self {
        self.place(offset, bytes);
        self
    }

    pub fn place(&mut self, offset: u64, bytes: &[u8]) {
        if offset >= self.len || bytes.is_empty() {
            return;
        }
        let keep = usize::try_from((self.len - offset).min(bytes.len() as u64)).unwrap_or(0);
        self.segments.insert(offset, bytes[..keep].to_vec());
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }
}

impl EvidenceReader for SparseReader {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
        // Out-of-bounds is an error, not a zero-fill, so a reader bug cannot masquerade as an
        // empty DI region.
        if offset >= self.len {
            return Err(ForensicError::out_of_bounds(
                "SparseReader::read_at",
                offset,
                buf.len() as u64,
                self.len,
            ));
        }
        let n = usize::try_from((self.len - offset).min(buf.len() as u64)).unwrap_or(0);
        let out = &mut buf[..n];
        out.fill(0);
        let end = offset + n as u64;
        // Segments may start before `offset`, so walk from the start; segment counts in tests
        // are small.
        for (&seg_off, seg) in self.segments.range(..end) {
            let seg_end = seg_off + seg.len() as u64;
            if seg_end <= offset {
                continue;
            }
            let from = offset.max(seg_off);
            let to = end.min(seg_end);
            let dst = (from - offset) as usize..(to - offset) as usize;
            let src = (from - seg_off) as usize..(to - seg_off) as usize;
            out[dst].copy_from_slice(&seg[src]);
        }
        Ok(n)
    }

    fn source_kind(&self) -> SourceKind {
        SourceKind::Raw
    }

    fn source_path(&self) -> &str {
        &self.path
    }
}

/// Byte builders for Uniview structures, following the documented layout exactly.
pub mod build {
    pub use crate::timestamp::encode as timestamp;

    /// SUPER block (`0x4000` bytes).
    pub fn super_block(
        magic: u32,
        last_write: Option<[u8; 5]>,
        start_storage: Option<[u8; 5]>,
        ec_port_id: Option<[u8; 64]>,
    ) -> Vec<u8> {
        let mut b = vec![0u8; 0x4000];
        b[0..4].copy_from_slice(&magic.to_le_bytes());
        if let Some(t) = last_write {
            b[0x14..0x19].copy_from_slice(&t);
        }
        if let Some(t) = start_storage {
            b[0x1C..0x21].copy_from_slice(&t);
        }
        if let Some(p) = ec_port_id {
            b[0x2C..0x6C].copy_from_slice(&p);
        }
        b
    }

    /// One 8-byte time-index entry: packed timestamp with the 26-bit lock spread over
    /// `b4[7:6]`, `b5`, `b6`, `b7`.
    pub fn time_index_entry(ts: [u8; 5], lock: u32) -> [u8; 8] {
        let mut e = [0u8; 8];
        e[..5].copy_from_slice(&ts);
        e[4] = (e[4] & 0x3F) | (((lock & 0x3) as u8) << 6);
        e[5] = ((lock >> 2) & 0xFF) as u8;
        e[6] = ((lock >> 10) & 0xFF) as u8;
        e[7] = ((lock >> 18) & 0xFF) as u8;
        e
    }

    /// OLD-generation UI region (`0x10000` bytes).
    pub fn old_ui(current_unit: u32, field_04: u16, rewrited: u8, entries: &[[u8; 8]]) -> Vec<u8> {
        let mut b = vec![0u8; 0x10000];
        b[0..4].copy_from_slice(&current_unit.to_le_bytes());
        b[4..6].copy_from_slice(&field_04.to_le_bytes());
        b[6] = rewrited;
        for (i, e) in entries.iter().enumerate() {
            let off = 8 + i * 8;
            if off + 8 <= b.len() {
                b[off..off + 8].copy_from_slice(e);
            }
        }
        b
    }

    /// NEW-generation UI-CTL region (`0x10000` bytes).
    pub fn new_ui_ctl(current_unit: u32, count: u32, rewrited: u32, entries: &[[u8; 8]]) -> Vec<u8> {
        let mut b = vec![0u8; 0x10000];
        b[0..4].copy_from_slice(&current_unit.to_le_bytes());
        b[4..8].copy_from_slice(&count.to_le_bytes());
        b[0x0C..0x10].copy_from_slice(&rewrited.to_le_bytes());
        for (i, e) in entries.iter().enumerate() {
            let off = 0x10 + i * 8;
            if off + 8 <= b.len() {
                b[off..off + 8].copy_from_slice(e);
            }
        }
        b
    }

    /// One UI-DATA unit (`0x10000` bytes, `0x2000` 8-byte entries).
    pub fn ui_data_unit(entries: &[[u8; 8]]) -> Vec<u8> {
        let mut b = vec![0u8; 0x10000];
        for (i, e) in entries.iter().enumerate().take(0x2000) {
            b[i * 8..i * 8 + 8].copy_from_slice(e);
        }
        b
    }

    /// One 16-byte DI entry: timestamp, 10-bit field A and 14-bit SPtoI packed into
    /// `+0x05..+0x07`, then the eight unknown trailing bytes verbatim.
    pub fn di_entry(ts: [u8; 5], field_a: u16, sptoi: u16, tail: [u8; 8]) -> [u8; 16] {
        let mut e = [0u8; 16];
        e[..5].copy_from_slice(&ts);
        e[5] = (field_a & 0xFF) as u8;
        e[6] = (((field_a >> 8) & 0x03) as u8) | (((sptoi & 0x3F) as u8) << 2);
        e[7] = ((sptoi >> 6) & 0xFF) as u8;
        e[8..16].copy_from_slice(&tail);
        e
    }

    /// DI header + entries, sized to hold exactly what was written (the rest of the 256 KiB
    /// region is the sparse reader's zero background).
    pub fn di_region(write_bytes: u32, declared_count: u32, entries: &[[u8; 16]]) -> Vec<u8> {
        let mut b = vec![0u8; 0x10 + entries.len() * 16];
        b[0..4].copy_from_slice(&write_bytes.to_le_bytes());
        b[4..8].copy_from_slice(&declared_count.to_le_bytes());
        for (i, e) in entries.iter().enumerate() {
            b[0x10 + i * 16..0x10 + (i + 1) * 16].copy_from_slice(e);
        }
        b
    }

    /// A 16 KiB DATA block filled with a recognisable, position-dependent pattern.
    pub fn data_block(tag: u8) -> Vec<u8> {
        (0..0x4000u32)
            .map(|i| tag ^ (i as u8).wrapping_mul(31))
            .collect()
    }
}

impl SparseReader {
    /// Every byte of the image, densely. For writing a small fixture to a real file so it can
    /// be opened through the production `RawReader`.
    pub fn materialize(&self) -> Vec<u8> {
        let mut out = vec![0u8; usize::try_from(self.len).unwrap_or(0)];
        if !out.is_empty() {
            let _ = self.read_at(0, &mut out);
        }
        out
    }
}

/// Whole-image fixture builders, driven by the same [`UniviewLayout`] the parser resolves.
pub mod image {
    use super::{build, SparseReader};
    use crate::layout::{Generation, UniviewLayout};

    /// One unit's DI and the DATA blocks it references.
    #[derive(Debug, Clone)]
    pub struct UnitSpec {
        pub unit: u32,
        pub write_bytes: u32,
        pub declared_count: u32,
        pub entries: Vec<[u8; 16]>,
        /// `(SPtoI, bytes)` placed at `unit_base + SPtoI * block`.
        pub blocks: Vec<(u16, Vec<u8>)>,
    }

    impl UnitSpec {
        /// A unit whose declared count equals the entries given.
        pub fn new(unit: u32, write_bytes: u32, entries: Vec<[u8; 16]>) -> Self {
            Self {
                unit,
                write_bytes,
                declared_count: entries.len() as u32,
                entries,
                blocks: Vec::new(),
            }
        }

        pub fn with_block(mut self, sptoi: u16, bytes: Vec<u8>) -> Self {
            self.blocks.push((sptoi, bytes));
            self
        }

        pub fn with_declared_count(mut self, n: u32) -> Self {
            self.declared_count = n;
            self
        }
    }

    /// Place a unit's DI region and DATA blocks.
    pub fn place_unit(r: &mut SparseReader, l: &UniviewLayout, generation: Generation, spec: &UnitSpec) {
        let base = l.unit_base(generation, spec.unit).expect("unit base");
        r.place(
            base + l.di_offset_in_unit,
            &build::di_region(spec.write_bytes, spec.declared_count, &spec.entries),
        );
        for (sptoi, bytes) in &spec.blocks {
            r.place(base + u64::from(*sptoi) * l.data_block_size, bytes);
        }
    }

    /// A SUPER block with plausible timestamps and a printable EcPortId.
    pub fn super_for(magic: u32) -> Vec<u8> {
        let mut port = [0u8; 64];
        port[..6].copy_from_slice(b"EC1001");
        build::super_block(
            magic,
            Some(build::timestamp(2024, 5, 3, 18, 30, 0)),
            Some(build::timestamp(2024, 4, 1, 8, 0, 0)),
            Some(port),
        )
    }

    /// A small OLD-generation image: SUPER, UI (current unit 1, rewrited set) and unit 1
    /// holding three DI entries (SPtoI 16, 20, 25), each referenced block carrying a
    /// distinct pattern, and one residual slot beyond the declared count. The image ends
    /// 64 DATA blocks into unit 1, so it is small enough to write to disk.
    pub fn small_old_volume(l: &UniviewLayout) -> SparseReader {
        let base = l.unit_base(Generation::Old, 1).unwrap();
        let len = base + l.di_size + 64 * l.data_block_size;
        let mut r = SparseReader::new(len).with(0, &super_for(0x1367));
        let ui_entries = [
            build::time_index_entry(build::timestamp(2024, 5, 3, 10, 0, 0), 11),
            build::time_index_entry(build::timestamp(2024, 5, 3, 10, 5, 0), 12),
        ];
        r.place(l.ui_offset, &build::old_ui(1, 0x0002, 1, &ui_entries));
        let ts = |m: u8| build::timestamp(2024, 5, 3, 10, m, 0);
        let tail = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mut entries = vec![
            build::di_entry(ts(0), 1, 16, tail),
            build::di_entry(ts(1), 1, 20, tail),
            build::di_entry(ts(2), 1, 25, tail),
        ];
        // Residue beyond the declared count of 3.
        entries.push(build::di_entry(build::timestamp(2024, 4, 30, 23, 59, 0), 1, 40, tail));
        let spec = UnitSpec::new(1, 9 * 0x4000, entries)
            .with_declared_count(3)
            .with_block(16, build::data_block(0x16))
            .with_block(20, build::data_block(0x20))
            .with_block(25, build::data_block(0x25))
            .with_block(40, build::data_block(0x40))
            .with_block(50, build::data_block(0x50));
        place_unit(&mut r, l, Generation::Old, &spec);
        r
    }

    /// A NEW-generation image with UI-CTL, two populated UI-DATA units and two storage units.
    pub fn new_volume(l: &UniviewLayout) -> SparseReader {
        let len = l.unit_base(Generation::New, 2).unwrap() + l.di_size + 64 * l.data_block_size;
        let mut r = SparseReader::new(len).with(0, &super_for(0x1587));
        let ctl = [build::time_index_entry(build::timestamp(2024, 6, 1, 0, 0, 0), 5)];
        r.place(l.ui_offset, &build::new_ui_ctl(2, 1, 0, &ctl));
        for n in [0u64, 1] {
            let unit = build::ui_data_unit(&[
                build::time_index_entry(build::timestamp(2024, 6, 1, n as u8, 0, 0), 100 + n as u32),
                build::time_index_entry(build::timestamp(2024, 6, 1, n as u8, 30, 0), 200 + n as u32),
            ]);
            r.place(l.ui_data_offset(n).unwrap(), &unit);
        }
        let ts = |h: u8, m: u8| build::timestamp(2024, 6, 1, h, m, 0);
        let u1 = UnitSpec::new(
            1,
            20 * 0x4000,
            vec![
                build::di_entry(ts(0, 0), 3, 16, [0; 8]),
                build::di_entry(ts(0, 10), 3, 26, [0; 8]),
                build::di_entry(ts(0, 20), 3, 36, [0; 8]),
            ],
        )
        .with_block(16, build::data_block(1))
        .with_block(26, build::data_block(2))
        .with_block(36, build::data_block(3));
        let u2 = UnitSpec::new(2, 0x4000, vec![build::di_entry(ts(1, 0), 4, 16, [0; 8])])
            .with_block(16, build::data_block(4));
        place_unit(&mut r, l, Generation::New, &u1);
        place_unit(&mut r, l, Generation::New, &u2);
        r
    }
}
