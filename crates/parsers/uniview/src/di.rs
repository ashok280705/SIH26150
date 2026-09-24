//! # DI — the per-unit data index
//!
//! Every 256 MiB unit starts with a 256 KiB DI region:
//!
//! ```text
//!   DI header
//!     +0x00  u32  per-unit write-data byte count                    CONFIRMED
//!     +0x04  u32  DI entry count                                    CONFIRMED
//!     +0x08  8 bytes                                                UNKNOWN
//!   entries at +0x10, stride 0x10:
//!     +0x00..+0x04  packed 5-byte timestamp                         CONFIRMED
//!     +0x05 + +0x06[1:0]      field A = b5 | ((b6 & 3) << 8)        UNKNOWN meaning
//!     +0x06[7:2] + +0x07      SPtoI   = (b7 << 6) | (b6 >> 2)       CONFIRMED: DATA block index
//!     +0x08..+0x0E  7 bytes                                         UNKNOWN
//!     +0x0F         1 byte (vendor-used)                            UNKNOWN
//! ```
//!
//! SPtoI is a **block index**: `data_offset = unit_base + SPtoI * 0x4000`. It is never a
//! byte offset.
//!
//! ## Spans are an inference
//!
//! The vendor tooling derives a DATA extent from adjacent SPtoI values
//! (`span ≈ SPtoI_next - SPtoI_current`). That is reproduced here as [`DataSpan`] with an
//! explicit [`SpanBasis`], and it is a *storage-span* inference — not proof of a video
//! recording boundary. Where no adjacent value supports an extent (the last entry, a
//! wraparound, a duplicate, an unusable neighbour) only the single block the SPtoI selects is
//! claimed, and the basis says so.

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, Region};
use serde::{Deserialize, Serialize};

use crate::field::FieldEvidence;
use crate::layout::{bytes_at, u32_at, Confidence, Generation, UniviewLayout};
use crate::timestamp::UnvTimestamp;

/// The 16-byte DI header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiHeader {
    /// Physical offset of the header.
    pub offset: u64,
    /// +0x00: per-unit write-data byte count. Summed across units into the calculated FLOW
    /// statistic.
    pub write_bytes: u32,
    /// +0x04: declared DI entry count.
    pub declared_count: u32,
    /// +0x08..+0x0F: preserved raw, meaning unknown.
    pub unknown_08_0f: [u8; 8],
}

impl DiHeader {
    pub fn fields(&self) -> Vec<FieldEvidence> {
        vec![
            FieldEvidence::new(
                "di.write_data_bytes",
                self.offset,
                32,
                None,
                &self.write_bytes.to_le_bytes(),
                Some(u64::from(self.write_bytes)),
                format!("{} byte(s) written to this unit", self.write_bytes),
                Confidence::Confirmed,
            ),
            FieldEvidence::new(
                "di.entry_count",
                self.offset + 4,
                32,
                None,
                &self.declared_count.to_le_bytes(),
                Some(u64::from(self.declared_count)),
                format!("{} DI entr(y/ies) declared", self.declared_count),
                Confidence::Confirmed,
            ),
            FieldEvidence::unknown("di.header_08_0f", self.offset + 8, &self.unknown_08_0f),
        ]
    }
}

/// What the DI header says about its unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DiHeaderState {
    /// All 16 header bytes are zero: the unit has not been written (or was cleared).
    Empty,
    /// The declared count fits the DI region.
    Valid,
    /// The declared count exceeds what a 256 KiB DI region can physically hold. The entries
    /// are not parsed as indexed: a garbage count would turn garbage into index entries.
    CountExceedsCapacity { declared: u32, capacity: u64 },
    /// The image ends inside the header or the declared entry array.
    Truncated { available_entries: u64 },
    /// The unit's DI region is not in the image at all.
    NotPresent,
}

impl DiHeaderState {
    pub fn label(&self) -> String {
        match self {
            Self::Empty => "empty".into(),
            Self::Valid => "valid".into(),
            Self::CountExceedsCapacity { declared, capacity } => {
                format!("declared entry count {declared} exceeds the DI capacity of {capacity}")
            }
            Self::Truncated { available_entries } => format!(
                "truncated by the end of the image ({available_entries} declared entr(y/ies) readable)"
            ),
            Self::NotPresent => "not present in the image".into(),
        }
    }
}

/// Where an SPtoI points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SptoiState {
    /// Inside the unit's DATA area and inside the image.
    Data,
    /// Below the DI block count: `unit_base + SPtoI * block` would land inside the DI
    /// region, which is not DATA.
    PointsIntoDi,
    /// A DATA block the geometry allows but the image does not contain.
    OutsideImage,
}

/// One parsed 16-byte DI entry, raw bytes preserved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiEntry {
    /// Entry index within the unit's DI array.
    pub index: u32,
    /// Physical offset of the entry.
    pub offset: u64,
    pub raw: [u8; 16],
    pub timestamp: UnvTimestamp,
    /// 10-bit field A. Semantics UNKNOWN — never interpreted as a channel.
    pub field_a: u16,
    /// 14-bit SPtoI DATA block index.
    pub sptoi: u16,
    /// +0x08..+0x0E, meaning unknown.
    pub unknown_08_0e: [u8; 7],
    /// +0x0F, vendor-used byte of unknown meaning.
    pub byte_0f: u8,
    /// `unit_base + SPtoI * data_block_size`.
    pub data_offset: Option<u64>,
    pub sptoi_state: SptoiState,
}

impl DiEntry {
    /// Decode one 16-byte entry. `None` only when fewer than 16 bytes are present.
    #[allow(clippy::too_many_arguments)]
    pub fn decode(
        raw: &[u8],
        offset: u64,
        index: u32,
        layout: &UniviewLayout,
        generation: Generation,
        unit: u32,
        image_len: u64,
    ) -> Option<Self> {
        let b = bytes_at(raw, 0, 16)?;
        let mut arr = [0u8; 16];
        arr.copy_from_slice(b);
        let field_a = u16::from(arr[5]) | (u16::from(arr[6] & 0x03) << 8);
        let sptoi = (u16::from(arr[7]) << 6) | (u16::from(arr[6]) >> 2);
        let data_offset = layout.data_offset(generation, unit, u32::from(sptoi));
        let sptoi_state = if u64::from(sptoi) < layout.di_blocks() {
            SptoiState::PointsIntoDi
        } else if data_offset
            .and_then(|o| o.checked_add(layout.data_block_size))
            .is_none_or(|end| end > image_len)
        {
            SptoiState::OutsideImage
        } else {
            SptoiState::Data
        };
        let mut unknown = [0u8; 7];
        unknown.copy_from_slice(&arr[8..15]);
        Some(Self {
            index,
            offset,
            raw: arr,
            timestamp: UnvTimestamp::decode(
                &arr[..5],
                offset,
                layout.timestamp_plausible_min_year,
                layout.timestamp_plausible_max_year,
            ),
            field_a,
            sptoi,
            unknown_08_0e: unknown,
            byte_0f: arr[15],
            data_offset,
            sptoi_state,
        })
    }

    /// Whether this entry's timestamp decoded and its SPtoI selects a readable DATA block.
    pub fn is_usable(&self) -> bool {
        self.timestamp.is_decoded() && self.sptoi_state == SptoiState::Data
    }

    /// Whether the entry is internally consistent — decodable timestamp and an SPtoI that
    /// selects a DATA block — regardless of whether the image still holds that block. Used
    /// for a neighbour's SPtoI when inferring a span: the extent is geometry, and clipping to
    /// the image is a separate step.
    pub fn is_structurally_valid(&self) -> bool {
        self.timestamp.is_decoded() && self.sptoi_state != SptoiState::PointsIntoDi
    }

    pub fn is_blank(&self) -> bool {
        self.raw.iter().all(|&b| b == 0)
    }

    /// Field-level evidence for every part of the entry.
    pub fn fields(&self) -> Vec<FieldEvidence> {
        vec![
            FieldEvidence::new(
                "di.entry.timestamp",
                self.offset,
                40,
                Some("+0x00..+0x04"),
                &self.raw[..5],
                Some(self.timestamp.raw_value()),
                self.timestamp.label(),
                Confidence::Confirmed,
            ),
            FieldEvidence::new(
                "di.entry.field_a",
                self.offset + 5,
                10,
                Some("+0x05 | (+0x06[1:0] << 8)"),
                &self.raw[5..7],
                Some(u64::from(self.field_a)),
                format!("10-bit value {} (semantics unknown)", self.field_a),
                Confidence::Unknown,
            ),
            FieldEvidence::new(
                "di.entry.sptoi",
                self.offset + 6,
                14,
                Some("(+0x07 << 6) | (+0x06[7:2])"),
                &self.raw[6..8],
                Some(u64::from(self.sptoi)),
                match (self.data_offset, self.sptoi_state) {
                    (Some(o), SptoiState::Data) => {
                        format!("DATA block index {} -> physical 0x{o:X}", self.sptoi)
                    }
                    (Some(o), SptoiState::OutsideImage) => format!(
                        "DATA block index {} -> physical 0x{o:X}, outside the image",
                        self.sptoi
                    ),
                    (_, SptoiState::PointsIntoDi) => format!(
                        "block index {} lands inside the DI region, not DATA",
                        self.sptoi
                    ),
                    (None, _) => format!("block index {} (offset overflow)", self.sptoi),
                },
                Confidence::Confirmed,
            ),
            FieldEvidence::unknown("di.entry.bytes_08_0e", self.offset + 8, &self.unknown_08_0e),
            FieldEvidence::unknown("di.entry.byte_0f", self.offset + 15, &[self.byte_0f]),
        ]
    }
}

/// How a DATA span's extent was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanBasis {
    /// The next entry's SPtoI is greater: extent = `next - current` blocks (inference).
    AdjacentSptoi,
    /// The last usable entry in the unit; only the selected block is claimed.
    TerminalEntry,
    /// The next SPtoI is smaller (wraparound); only the selected block is claimed.
    Wraparound,
    /// The next SPtoI is equal; only the selected block is claimed.
    DuplicateSptoi,
    /// The next entry is unusable (corrupt timestamp or SPtoI); only the selected block is
    /// claimed.
    NextEntryUnusable,
    /// `next - current` would run past the unit; only the selected block is claimed.
    ExceedsUnit,
}

impl SpanBasis {
    pub fn label(&self) -> &'static str {
        match self {
            Self::AdjacentSptoi => "adjacent_sptoi",
            Self::TerminalEntry => "terminal_entry",
            Self::Wraparound => "wraparound",
            Self::DuplicateSptoi => "duplicate_sptoi",
            Self::NextEntryUnusable => "next_entry_unusable",
            Self::ExceedsUnit => "exceeds_unit",
        }
    }

    /// Whether the extent is a lower bound (one block) rather than an adjacent-SPtoI span.
    pub fn is_lower_bound(&self) -> bool {
        !matches!(self, Self::AdjacentSptoi)
    }
}

/// The DATA extent inferred for one usable DI entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataSpan {
    pub entry_index: u32,
    pub start_sptoi: u16,
    /// Blocks claimed (the inferred span, or 1 for a lower bound).
    pub blocks: u64,
    pub basis: SpanBasis,
    /// Physical range, clipped to the image. `None` if nothing of it is in the image.
    pub region: Option<Region>,
    /// Whether the image ended before the span did.
    pub truncated_by_image: bool,
}

/// Compute a DATA span for every usable entry, in DI order.
pub fn compute_spans(
    entries: &[DiEntry],
    layout: &UniviewLayout,
    image_len: u64,
) -> Vec<DataSpan> {
    let blocks_per_unit = layout.blocks_per_unit();
    let mut out = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        if !e.is_usable() {
            continue;
        }
        let Some(start) = e.data_offset else { continue };
        let cur = u64::from(e.sptoi);
        let (blocks, basis) = match entries.get(i + 1) {
            None => (1, SpanBasis::TerminalEntry),
            Some(n) if !n.is_structurally_valid() => (1, SpanBasis::NextEntryUnusable),
            Some(n) => {
                let next = u64::from(n.sptoi);
                if next > cur {
                    if next > blocks_per_unit {
                        (1, SpanBasis::ExceedsUnit)
                    } else {
                        (next - cur, SpanBasis::AdjacentSptoi)
                    }
                } else if next == cur {
                    (1, SpanBasis::DuplicateSptoi)
                } else {
                    (1, SpanBasis::Wraparound)
                }
            }
        };
        let want = blocks.saturating_mul(layout.data_block_size);
        let end = start.saturating_add(want).min(image_len);
        let region = (end > start).then(|| Region::new(start, end - start).ok()).flatten();
        out.push(DataSpan {
            entry_index: e.index,
            start_sptoi: e.sptoi,
            blocks,
            basis,
            region,
            truncated_by_image: start.saturating_add(want) > image_len,
        });
    }
    out
}

/// Everything read from one unit's DI region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitDi {
    pub generation: Generation,
    /// 1-based unit number.
    pub unit: u32,
    pub unit_base: u64,
    pub di_offset: u64,
    pub header_state: DiHeaderState,
    pub header: Option<DiHeader>,
    /// Declared entries that were readable, in DI order. Empty unless the header is
    /// `Valid` or `Truncated`.
    pub entries: Vec<DiEntry>,
}

impl UnitDi {
    pub fn spans(&self, layout: &UniviewLayout, image_len: u64) -> Vec<DataSpan> {
        compute_spans(&self.entries, layout, image_len)
    }
}

fn read_bytes(
    reader: &dyn EvidenceReader,
    offset: u64,
    len: u64,
) -> Result<Vec<u8>, ForensicError> {
    if offset >= reader.len() || len == 0 {
        return Ok(Vec::new());
    }
    let want = usize::try_from((reader.len() - offset).min(len)).unwrap_or(0);
    let mut buf = vec![0u8; want];
    let n = reader.read_at(offset, &mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

/// Read one unit's DI header and its declared entries.
pub fn read_unit_di(
    reader: &dyn EvidenceReader,
    layout: &UniviewLayout,
    generation: Generation,
    unit: u32,
) -> Result<UnitDi, ForensicError> {
    let image_len = reader.len();
    let unit_base = layout
        .unit_base(generation, unit)
        .ok_or_else(|| ForensicError::corrupt("uniview_di", format!("unit {unit} has no base")))?;
    let di_offset = layout
        .di_offset(generation, unit)
        .ok_or_else(|| ForensicError::corrupt("uniview_di", format!("unit {unit} DI overflows")))?;
    let mut out = UnitDi {
        generation,
        unit,
        unit_base,
        di_offset,
        header_state: DiHeaderState::NotPresent,
        header: None,
        entries: Vec::new(),
    };
    if di_offset >= image_len {
        return Ok(out);
    }

    let head = read_bytes(reader, di_offset, layout.di_entries_offset as u64)?;
    let header = (|| {
        let mut unk = [0u8; 8];
        unk.copy_from_slice(bytes_at(&head, layout.di_header_unknown_offset, 8)?);
        Some(DiHeader {
            offset: di_offset,
            write_bytes: u32_at(&head, layout.di_write_bytes_offset)?,
            declared_count: u32_at(&head, layout.di_entry_count_offset)?,
            unknown_08_0f: unk,
        })
    })();
    let Some(header) = header else {
        out.header_state = DiHeaderState::Truncated { available_entries: 0 };
        return Ok(out);
    };
    if head.iter().all(|&b| b == 0) {
        out.header_state = DiHeaderState::Empty;
        out.header = Some(header);
        return Ok(out);
    }

    let capacity = layout.di_max_entries();
    let declared = u64::from(header.declared_count);
    if declared > capacity {
        out.header_state = DiHeaderState::CountExceedsCapacity {
            declared: header.declared_count,
            capacity,
        };
        out.header = Some(header);
        return Ok(out);
    }

    let entries_at = di_offset.saturating_add(layout.di_entries_offset as u64);
    let buf = read_bytes(reader, entries_at, declared.saturating_mul(layout.di_entry_size as u64))?;
    let readable = if layout.di_entry_size == 0 {
        0
    } else {
        buf.len() as u64 / layout.di_entry_size as u64
    };
    for i in 0..readable.min(declared) {
        let off = (i as usize) * layout.di_entry_size;
        if let Some(e) = bytes_at(&buf, off, 16).and_then(|raw| {
            DiEntry::decode(
                raw,
                entries_at + off as u64,
                i as u32,
                layout,
                generation,
                unit,
                image_len,
            )
        }) {
            out.entries.push(e);
        }
    }
    out.header_state = if readable < declared {
        DiHeaderState::Truncated { available_entries: readable }
    } else {
        DiHeaderState::Valid
    };
    out.header = Some(header);
    Ok(out)
}

/// **HEURISTIC.** DI slots beyond the declared count (or every slot, when the header count
/// is unusable) that still decode to a real timestamp and a DATA SPtoI.
///
/// Such slots may be residue of an earlier write cycle. Nothing in the Uniview structures
/// marks them as deleted or as live; they are candidates for examination only and are never
/// reported as indexed recordings.
pub fn scan_residual_slots(
    reader: &dyn EvidenceReader,
    layout: &UniviewLayout,
    di: &UnitDi,
) -> Result<Vec<DiEntry>, ForensicError> {
    let first = match &di.header_state {
        DiHeaderState::Valid => di.header.as_ref().map_or(0, |h| u64::from(h.declared_count)),
        DiHeaderState::CountExceedsCapacity { .. } => 0,
        // Empty, truncated or absent headers give no footing for a residual scan.
        _ => return Ok(Vec::new()),
    };
    let capacity = layout.di_max_entries();
    if first >= capacity {
        return Ok(Vec::new());
    }
    let entries_at = di.di_offset.saturating_add(layout.di_entries_offset as u64);
    let from = entries_at.saturating_add(first.saturating_mul(layout.di_entry_size as u64));
    let buf = read_bytes(
        reader,
        from,
        (capacity - first).saturating_mul(layout.di_entry_size as u64),
    )?;
    let image_len = reader.len();
    let mut out = Vec::new();
    for (k, raw) in buf.chunks_exact(layout.di_entry_size.max(1)).enumerate() {
        if raw.iter().all(|&b| b == 0) {
            continue;
        }
        let idx = first + k as u64;
        if let Some(e) = DiEntry::decode(
            raw,
            from + (k * layout.di_entry_size) as u64,
            idx as u32,
            layout,
            di.generation,
            di.unit,
            image_len,
        ) {
            if e.timestamp.status == crate::timestamp::TimestampStatus::Valid
                && e.sptoi_state == SptoiState::Data
            {
                out.push(e);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::tests_support::uniview_profile;
    use crate::testing::{build, SparseReader};
    use crate::timestamp::{encode, TimestampStatus};

    fn layout() -> UniviewLayout {
        UniviewLayout::from_profile(&uniview_profile())
    }

    const OLD_U1: u64 = 0x0001_4000;

    fn entry(sptoi: u16, sec: u8) -> [u8; 16] {
        build::di_entry(encode(2024, 5, 1, 12, 0, sec), 0x155, sptoi, [0xA0, 1, 2, 3, 4, 5, 6, 0x7F])
    }

    #[test]
    fn sptoi_and_field_a_bit_extraction() {
        let l = layout();
        for (a, s) in [(0u16, 0u16), (0x3FF, 0x3FFF), (0x155, 0x2AAA), (1, 16), (0x200, 0x2000)] {
            let raw = build::di_entry(encode(2024, 1, 1, 0, 0, 0), a, s, [0; 8]);
            let e = DiEntry::decode(&raw, 0, 0, &l, Generation::Old, 1, u64::MAX).unwrap();
            assert_eq!((e.field_a, e.sptoi), (a, s));
        }
        // Raw-byte check of the documented formulas.
        let mut raw = [0u8; 16];
        raw[5] = 0x12;
        raw[6] = 0b1010_1101;
        raw[7] = 0xC3;
        let e = DiEntry::decode(&raw, 0, 0, &l, Generation::Old, 1, u64::MAX).unwrap();
        assert_eq!(e.field_a, 0x12 | (0b01 << 8));
        assert_eq!(e.sptoi, (0xC3 << 6) | (0b1010_1101 >> 2));
        assert!(e.sptoi < 0x4000);
    }

    #[test]
    fn sptoi_resolves_to_the_physical_data_block() {
        let l = layout();
        for (gen, base) in [(Generation::Old, 0x0001_4000u64), (Generation::New, 0x1001_4000u64)] {
            let raw = build::di_entry(encode(2024, 1, 1, 0, 0, 0), 0, 100, [0; 8]);
            let e = DiEntry::decode(&raw, 0, 0, &l, gen, 3, u64::MAX).unwrap();
            assert_eq!(e.data_offset, Some(base + 2 * 0x1000_0000 + 100 * 0x4000));
            assert_eq!(e.sptoi_state, SptoiState::Data);
        }
        let raw = build::di_entry(encode(2024, 1, 1, 0, 0, 0), 0, 15, [0; 8]);
        let e = DiEntry::decode(&raw, 0, 0, &l, Generation::Old, 1, u64::MAX).unwrap();
        assert_eq!(e.sptoi_state, SptoiState::PointsIntoDi, "block 15 is inside the 256 KiB DI");
        let raw = build::di_entry(encode(2024, 1, 1, 0, 0, 0), 0, 16, [0; 8]);
        let e = DiEntry::decode(&raw, 0, 0, &l, Generation::Old, 1, 0x40000).unwrap();
        assert_eq!(e.sptoi_state, SptoiState::OutsideImage);
    }

    #[test]
    fn header_and_entries_are_parsed_at_their_offsets() {
        let l = layout();
        let di = build::di_region(0x12345, 3, &[entry(16, 1), entry(20, 2), entry(25, 3)]);
        let r = SparseReader::new(OLD_U1 + 0x1000_0000).with(OLD_U1, &di);
        let u = read_unit_di(&r, &l, Generation::Old, 1).unwrap();
        assert_eq!(u.header_state, DiHeaderState::Valid);
        let h = u.header.as_ref().unwrap();
        assert_eq!((h.write_bytes, h.declared_count), (0x12345, 3));
        assert_eq!(u.entries.len(), 3);
        assert_eq!(u.entries[1].offset, OLD_U1 + 0x10 + 0x10);
        assert_eq!(u.entries[2].timestamp.second, 3);
        assert_eq!(u.entries[0].unknown_08_0e, [0xA0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(u.entries[0].byte_0f, 0x7F);

        let f = u.entries[0].fields();
        let sp = f.iter().find(|f| f.name == "di.entry.sptoi").unwrap();
        assert_eq!((sp.physical_offset, sp.size_bits, sp.confidence), (OLD_U1 + 0x16, 14, Confidence::Confirmed));
        let a = f.iter().find(|f| f.name == "di.entry.field_a").unwrap();
        assert_eq!(a.confidence, Confidence::Unknown);
    }

    #[test]
    fn spans_follow_adjacent_sptoi_and_degrade_to_one_block() {
        let l = layout();
        let entries = [
            entry(16, 1),
            entry(20, 2), // +4
            entry(20, 3), // duplicate
            entry(18, 4), // wrap
            build::di_entry([0xFF; 5], 0, 30, [0; 8]), // unusable timestamp
            entry(40, 5),
        ];
        let di = build::di_region(0, entries.len() as u32, &entries);
        let r = SparseReader::new(OLD_U1 + 0x1000_0000).with(OLD_U1, &di);
        let u = read_unit_di(&r, &l, Generation::Old, 1).unwrap();
        let spans = u.spans(&l, r.len());
        let basis: Vec<_> = spans.iter().map(|s| (s.entry_index, s.blocks, s.basis)).collect();
        assert_eq!(
            basis,
            vec![
                (0, 4, SpanBasis::AdjacentSptoi),
                (1, 1, SpanBasis::DuplicateSptoi),
                (2, 1, SpanBasis::Wraparound),
                (3, 1, SpanBasis::NextEntryUnusable),
                (5, 1, SpanBasis::TerminalEntry),
            ]
        );
        assert_eq!(spans[0].region, Some(Region::new(OLD_U1 + 16 * 0x4000, 4 * 0x4000).unwrap()));
    }

    #[test]
    fn a_span_past_the_image_is_clipped_and_flagged() {
        let l = layout();
        let di = build::di_region(0, 2, &[entry(16, 1), entry(100, 2)]);
        let len = OLD_U1 + 20 * 0x4000;
        let r = SparseReader::new(len).with(OLD_U1, &di);
        let u = read_unit_di(&r, &l, Generation::Old, 1).unwrap();
        let spans = u.spans(&l, r.len());
        assert_eq!(spans.len(), 1, "the second entry's block is outside the image");
        assert!(spans[0].truncated_by_image);
        assert_eq!(spans[0].region.unwrap().end(), Some(len));
    }

    #[test]
    fn corrupt_headers_are_classified_without_panicking() {
        let l = layout();
        // Invalid count.
        let di = build::di_region(0, 0xFFFF_FFFF, &[entry(16, 1)]);
        let r = SparseReader::new(OLD_U1 + 0x40000).with(OLD_U1, &di);
        let u = read_unit_di(&r, &l, Generation::Old, 1).unwrap();
        assert!(matches!(u.header_state, DiHeaderState::CountExceedsCapacity { .. }));
        assert!(u.entries.is_empty());
        // Empty header.
        let r = SparseReader::new(OLD_U1 + 0x40000);
        assert_eq!(read_unit_di(&r, &l, Generation::Old, 1).unwrap().header_state, DiHeaderState::Empty);
        // Truncated inside the entry array.
        let di = build::di_region(0, 10, &[entry(16, 1), entry(17, 2)]);
        let r = SparseReader::new(OLD_U1 + 0x10 + 0x20).with(OLD_U1, &di);
        let u = read_unit_di(&r, &l, Generation::Old, 1).unwrap();
        assert_eq!(u.header_state, DiHeaderState::Truncated { available_entries: 2 });
        assert_eq!(u.entries.len(), 2);
        // Truncated inside the header.
        let r = SparseReader::new(OLD_U1 + 6).with(OLD_U1, &[1, 2, 3, 4, 5, 6]);
        let u = read_unit_di(&r, &l, Generation::Old, 1).unwrap();
        assert_eq!(u.header_state, DiHeaderState::Truncated { available_entries: 0 });
        // Unit not in the image.
        let r = SparseReader::new(OLD_U1);
        assert_eq!(read_unit_di(&r, &l, Generation::Old, 1).unwrap().header_state, DiHeaderState::NotPresent);
    }

    #[test]
    fn residual_slots_are_found_only_with_valid_time_and_data_sptoi() {
        let l = layout();
        let entries = [
            entry(16, 1),
            entry(20, 2), // residue: beyond declared count 1
            build::di_entry([0xFF; 5], 0, 30, [0; 8]), // garbage time: ignored
            build::di_entry(encode(2024, 1, 1, 0, 0, 0), 0, 3, [0; 8]), // into DI: ignored
        ];
        let di = build::di_region(0, 1, &entries);
        let r = SparseReader::new(OLD_U1 + 0x1000_0000).with(OLD_U1, &di);
        let u = read_unit_di(&r, &l, Generation::Old, 1).unwrap();
        let res = scan_residual_slots(&r, &l, &u).unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!((res[0].index, res[0].sptoi), (1, 20));
        assert_eq!(res[0].timestamp.status, TimestampStatus::Valid);
    }
}
