//! # UI (OLD), UI-CTL (NEW) and UI-DATA (NEW)
//!
//! ```text
//!   OLD  0x4000  UI       +0x00 u32 current writing unit index      CONFIRMED
//!                         +0x04 u16 (meaning not established)       UNKNOWN
//!                         +0x06 u8  rewrited flag                   CONFIRMED location
//!                         +0x08 8-byte entries                      TENTATIVE base
//!
//!   NEW  0x4000  UI-CTL   +0x00 u32 current unit index              CONFIRMED
//!                         +0x04 u32 count/scaling field             CONFIRMED location, raw
//!                         +0x08 4 bytes                             UNKNOWN
//!                         +0x0C u32 rewrited flag                   CONFIRMED location
//!                         +0x10 8-byte time-index entries           CONFIRMED location
//!
//!   NEW  0x14000 + n*0x10000  UI-DATA unit n: 0x2000 8-byte entries
//!        entry: 5-byte packed timestamp                             CONFIRMED
//!               lock = (b5<<2) | (b4>>6) | (b6<<10) | (b7<<18)       CONFIRMED extraction
//!                                                                   UNKNOWN meaning
//! ```
//!
//! ## What is deliberately not claimed
//!
//! * The lock value is reported as a "lock / time-index value". It is **not** claimed to be
//!   a channel number or a unit reference.
//! * The mapping from a UI / UI-DATA entry to a DI entry is not established, so nothing here
//!   links a time-index entry to a unit or a DATA block.
//! * The rewrited flag strongly indicates the recorder has wrapped its circular storage at
//!   least once. It does **not** say which recordings were overwritten or which survive.
//!
//! UI-DATA is large (up to 4096 units of 64 KiB). It is summarised per unit; the individual
//! entries of any one unit are available on demand through [`read_ui_data_unit`].

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};

use crate::field::FieldEvidence;
use crate::layout::{bytes_at, u16_at, u32_at, u8_at, vs, Confidence, Generation, UniviewLayout};
use crate::timestamp::{TimestampStatus, UnvTimestamp};

/// Extract the 26-bit lock / time-index value from an 8-byte entry (CONFIRMED extraction,
/// UNKNOWN meaning).
pub fn lock_value(raw: &[u8]) -> Option<u32> {
    let b = bytes_at(raw, 0, 8)?;
    Some(
        (u32::from(b[5]) << 2)
            | (u32::from(b[4]) >> 6)
            | (u32::from(b[6]) << 10)
            | (u32::from(b[7]) << 18),
    )
}

/// One 8-byte time-index entry, decoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeIndexEntry {
    /// Entry index within its table.
    pub index: u32,
    /// Absolute physical offset of the entry.
    pub offset: u64,
    /// The 8 raw bytes, verbatim.
    pub raw: [u8; 8],
    pub timestamp: UnvTimestamp,
    /// 26-bit lock / time-index value. Meaning UNKNOWN.
    pub lock: u32,
}

impl TimeIndexEntry {
    fn decode(raw: &[u8], offset: u64, index: u32, layout: &UniviewLayout) -> Option<Self> {
        let b = bytes_at(raw, 0, 8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(b);
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
            lock: lock_value(&arr)?,
        })
    }

    /// Field-level evidence for this entry, with the table's timestamp confidence.
    pub fn fields(&self, prefix: &str, ts_confidence: Confidence) -> Vec<FieldEvidence> {
        vec![
            FieldEvidence::new(
                format!("{prefix}.timestamp"),
                self.offset,
                40,
                Some("+0x00..+0x04 (b4[5:0] seconds)"),
                &self.raw[..5],
                Some(self.timestamp.raw_value()),
                self.timestamp.label(),
                ts_confidence,
            ),
            FieldEvidence::new(
                format!("{prefix}.lock"),
                self.offset + 4,
                26,
                Some("(b5<<2) | (b4>>6) | (b6<<10) | (b7<<18)"),
                &self.raw[4..8],
                Some(u64::from(self.lock)),
                format!("lock / time-index value {} (semantics unknown)", self.lock),
                Confidence::Unknown,
            ),
        ]
    }
}

/// Aggregate over a table of 8-byte time-index entries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeIndexSummary {
    /// Entry slots in the table.
    pub capacity: u64,
    /// Slots holding any non-zero byte.
    pub populated: u64,
    pub valid_timestamps: u64,
    pub implausible_timestamps: u64,
    pub invalid_timestamps: u64,
    pub first_populated_index: Option<u32>,
    pub last_populated_index: Option<u32>,
    /// Earliest and latest decodable timestamps, by instant.
    pub earliest: Option<UnvTimestamp>,
    pub latest: Option<UnvTimestamp>,
    pub lock_min: Option<u32>,
    pub lock_max: Option<u32>,
}

impl TimeIndexSummary {
    fn absorb(&mut self, e: &TimeIndexEntry) {
        if e.raw.iter().all(|&b| b == 0) {
            return;
        }
        self.populated += 1;
        self.first_populated_index.get_or_insert(e.index);
        self.last_populated_index = Some(e.index);
        match e.timestamp.status {
            TimestampStatus::Valid => self.valid_timestamps += 1,
            TimestampStatus::Implausible => self.implausible_timestamps += 1,
            TimestampStatus::Invalid | TimestampStatus::Truncated => self.invalid_timestamps += 1,
            TimestampStatus::Empty => {}
        }
        if let Some(t) = e.timestamp.unix_seconds_as_utc() {
            if self.earliest.as_ref().and_then(|x| x.unix_seconds_as_utc()).is_none_or(|x| t < x) {
                self.earliest = Some(e.timestamp.clone());
            }
            if self.latest.as_ref().and_then(|x| x.unix_seconds_as_utc()).is_none_or(|x| t > x) {
                self.latest = Some(e.timestamp.clone());
            }
        }
        self.lock_min = Some(self.lock_min.map_or(e.lock, |m| m.min(e.lock)));
        self.lock_max = Some(self.lock_max.map_or(e.lock, |m| m.max(e.lock)));
    }
}

fn summarise(
    buf: &[u8],
    table_offset_in_buf: usize,
    physical_base: u64,
    capacity: usize,
    layout: &UniviewLayout,
) -> TimeIndexSummary {
    let mut s = TimeIndexSummary {
        capacity: capacity as u64,
        ..Default::default()
    };
    for i in 0..capacity {
        let off = table_offset_in_buf + i * layout.ui_entry_size;
        let Some(raw) = bytes_at(buf, off, 8) else { break };
        if let Some(e) = TimeIndexEntry::decode(raw, physical_base + off as u64, i as u32, layout) {
            s.absorb(&e);
        }
    }
    s
}

fn decode_table(
    buf: &[u8],
    table_offset_in_buf: usize,
    physical_base: u64,
    capacity: usize,
    layout: &UniviewLayout,
) -> Vec<TimeIndexEntry> {
    (0..capacity)
        .filter_map(|i| {
            let off = table_offset_in_buf + i * layout.ui_entry_size;
            let raw = bytes_at(buf, off, 8)?;
            if raw.iter().all(|&b| b == 0) {
                return None;
            }
            TimeIndexEntry::decode(raw, physical_base + off as u64, i as u32, layout)
        })
        .collect()
}

/// The UI (OLD) or UI-CTL (NEW) header fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UiHeader {
    Old {
        /// +0x00: current writing unit index.
        current_unit: u32,
        /// +0x04: u16 whose meaning is not established.
        field_04: u16,
        /// +0x06: rewrited flag, raw byte.
        rewrited_raw: u8,
        /// +0x07: byte whose meaning is not established.
        byte_07: u8,
    },
    New {
        /// +0x00: current unit index.
        current_unit: u32,
        /// +0x04: count/scaling field, preserved raw.
        count_scaling: u32,
        /// +0x08..+0x0B: bytes whose meaning is not established.
        bytes_08_0b: [u8; 4],
        /// +0x0C: rewrited flag, raw u32.
        rewrited_raw: u32,
    },
}

/// The parsed UI / UI-CTL region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniviewUi {
    pub generation: Generation,
    pub offset: u64,
    pub size: u64,
    /// Bytes of the region actually present in the image.
    pub available: u64,
    pub header: Option<UiHeader>,
    /// Aggregate over the region's 8-byte entry table.
    pub entries: TimeIndexSummary,
    /// How well the entry table's location and decoding are established.
    pub entries_confidence: Confidence,
    pub evidence: ValidationState,
}

impl UniviewUi {
    pub fn current_unit(&self) -> Option<u32> {
        match self.header.as_ref()? {
            UiHeader::Old { current_unit, .. } | UiHeader::New { current_unit, .. } => {
                Some(*current_unit)
            }
        }
    }

    /// Whether the rewrited flag is set (non-zero). `None` if the header was not readable.
    pub fn rewrited(&self) -> Option<bool> {
        match self.header.as_ref()? {
            UiHeader::Old { rewrited_raw, .. } => Some(*rewrited_raw != 0),
            UiHeader::New { rewrited_raw, .. } => Some(*rewrited_raw != 0),
        }
    }

    pub fn region_name(&self) -> &'static str {
        match self.generation {
            Generation::Old => "UI",
            Generation::New => "UI-CTL",
        }
    }

    /// Field-level evidence for the header.
    pub fn fields(&self, layout: &UniviewLayout) -> Vec<FieldEvidence> {
        let base = self.offset;
        let rewrite_note = |set: bool| {
            if set {
                "set: strongly indicates the circular storage has been overwritten at least once; \
                 which recordings were overwritten is not recorded here"
            } else {
                "clear"
            }
        };
        match &self.header {
            None => Vec::new(),
            Some(UiHeader::Old { current_unit, field_04, rewrited_raw, byte_07 }) => vec![
                FieldEvidence::new(
                    "ui.current_writing_unit",
                    base + layout.old_ui_current_unit_offset as u64,
                    32,
                    None,
                    &current_unit.to_le_bytes(),
                    Some(u64::from(*current_unit)),
                    format!("current writing unit index {current_unit}"),
                    Confidence::Confirmed,
                ),
                FieldEvidence::new(
                    "ui.field_04",
                    base + layout.old_ui_field_04_offset as u64,
                    16,
                    None,
                    &field_04.to_le_bytes(),
                    Some(u64::from(*field_04)),
                    "u16 field; meaning not established",
                    Confidence::Unknown,
                ),
                FieldEvidence::new(
                    "ui.rewrited",
                    base + layout.old_ui_rewrited_offset as u64,
                    8,
                    None,
                    &[*rewrited_raw],
                    Some(u64::from(*rewrited_raw)),
                    rewrite_note(*rewrited_raw != 0),
                    Confidence::StrongInference,
                ),
                FieldEvidence::unknown(
                    "ui.byte_07",
                    base + layout.old_ui_rewrited_offset as u64 + 1,
                    &[*byte_07],
                ),
            ],
            Some(UiHeader::New { current_unit, count_scaling, bytes_08_0b, rewrited_raw }) => vec![
                FieldEvidence::new(
                    "ui_ctl.current_unit",
                    base + layout.new_uictl_current_unit_offset as u64,
                    32,
                    None,
                    &current_unit.to_le_bytes(),
                    Some(u64::from(*current_unit)),
                    format!("current unit index {current_unit}"),
                    Confidence::Confirmed,
                ),
                FieldEvidence::new(
                    "ui_ctl.count_scaling",
                    base + layout.new_uictl_count_offset as u64,
                    32,
                    None,
                    &count_scaling.to_le_bytes(),
                    Some(u64::from(*count_scaling)),
                    format!("count/scaling field, raw {count_scaling}; not reinterpreted"),
                    Confidence::StrongInference,
                ),
                FieldEvidence::unknown(
                    "ui_ctl.bytes_08_0b",
                    base + layout.new_uictl_count_offset as u64 + 4,
                    bytes_08_0b,
                ),
                FieldEvidence::new(
                    "ui_ctl.rewrited",
                    base + layout.new_uictl_rewrited_offset as u64,
                    32,
                    None,
                    &rewrited_raw.to_le_bytes(),
                    Some(u64::from(*rewrited_raw)),
                    rewrite_note(*rewrited_raw != 0),
                    Confidence::StrongInference,
                ),
            ],
        }
    }
}

/// Byte offset of the entry table within the UI region, per generation.
fn entries_offset(layout: &UniviewLayout, generation: Generation) -> usize {
    match generation {
        Generation::Old => layout.old_ui_entries_offset,
        Generation::New => layout.new_uictl_entries_offset,
    }
}

fn read_region(
    reader: &dyn EvidenceReader,
    offset: u64,
    size: u64,
) -> Result<Vec<u8>, ForensicError> {
    let len = reader.len();
    if offset >= len {
        return Ok(Vec::new());
    }
    let want = usize::try_from((len - offset).min(size)).unwrap_or(0);
    let mut buf = vec![0u8; want];
    let n = reader.read_at(offset, &mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

/// Read and parse the UI (OLD) or UI-CTL (NEW) region.
pub fn read_ui(
    reader: &dyn EvidenceReader,
    layout: &UniviewLayout,
    generation: Generation,
) -> Result<UniviewUi, ForensicError> {
    let buf = read_region(reader, layout.ui_offset, layout.ui_size)?;
    let region = match generation {
        Generation::Old => "UI",
        Generation::New => "UI-CTL",
    };

    let header = match generation {
        Generation::Old => (|| {
            Some(UiHeader::Old {
                current_unit: u32_at(&buf, layout.old_ui_current_unit_offset)?,
                field_04: u16_at(&buf, layout.old_ui_field_04_offset)?,
                rewrited_raw: u8_at(&buf, layout.old_ui_rewrited_offset)?,
                byte_07: u8_at(&buf, layout.old_ui_rewrited_offset + 1)?,
            })
        })(),
        Generation::New => (|| {
            let mut b = [0u8; 4];
            b.copy_from_slice(bytes_at(&buf, layout.new_uictl_count_offset + 4, 4)?);
            Some(UiHeader::New {
                current_unit: u32_at(&buf, layout.new_uictl_current_unit_offset)?,
                count_scaling: u32_at(&buf, layout.new_uictl_count_offset)?,
                bytes_08_0b: b,
                rewrited_raw: u32_at(&buf, layout.new_uictl_rewrited_offset)?,
            })
        })(),
    };

    let table = entries_offset(layout, generation);
    let capacity = if layout.ui_entry_size == 0 {
        0
    } else {
        (layout.ui_size as usize).saturating_sub(table) / layout.ui_entry_size
    };
    let entries = summarise(&buf, table, layout.ui_offset, capacity, layout);

    let available = buf.len() as u64;
    let evidence = if header.is_none() {
        vs(
            ValidationStateKind::Review,
            format!("the {region} header at 0x{:X} is not readable ({available} byte(s) present)", layout.ui_offset),
            "read_ui",
            "uniview_ui",
        )
    } else if available < layout.ui_size {
        vs(
            ValidationStateKind::Review,
            format!(
                "the {region} region is truncated: {available} of {} byte(s) present",
                layout.ui_size
            ),
            "read_ui",
            "uniview_ui",
        )
    } else {
        vs(
            ValidationStateKind::Pass,
            format!(
                "{region} parsed at 0x{:X}: {} populated 8-byte entr(y/ies) of {}",
                layout.ui_offset, entries.populated, entries.capacity
            ),
            "read_ui",
            "uniview_ui",
        )
    };

    Ok(UniviewUi {
        generation,
        offset: layout.ui_offset,
        size: layout.ui_size,
        available,
        header,
        entries,
        entries_confidence: match generation {
            // The OLD entry table's base offset is not established by the research; entries
            // are reported for inspection only.
            Generation::Old => Confidence::Tentative,
            Generation::New => Confidence::StrongInference,
        },
        evidence,
    })
}

/// The individual populated entries of the UI / UI-CTL table.
pub fn read_ui_entries(
    reader: &dyn EvidenceReader,
    layout: &UniviewLayout,
    generation: Generation,
) -> Result<Vec<TimeIndexEntry>, ForensicError> {
    let buf = read_region(reader, layout.ui_offset, layout.ui_size)?;
    let table = entries_offset(layout, generation);
    let capacity = if layout.ui_entry_size == 0 {
        0
    } else {
        (layout.ui_size as usize).saturating_sub(table) / layout.ui_entry_size
    };
    Ok(decode_table(&buf, table, layout.ui_offset, capacity, layout))
}

/// Summary of one populated UI-DATA unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiDataUnitSummary {
    /// UI-DATA unit number `n` (0-based), as in `0x14000 + n * 0x10000`.
    pub n: u64,
    pub offset: u64,
    /// Whether the image ends inside this unit.
    pub truncated: bool,
    pub summary: TimeIndexSummary,
}

/// The NEW-generation UI-DATA area.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiDataArea {
    pub base: u64,
    /// Units the geometry allows between the UI-DATA base and the first storage unit.
    pub capacity: u64,
    /// Units actually examined (bounded by the image and the profile scan cap).
    pub examined: u64,
    /// Units that hold at least one populated entry.
    pub populated_units: Vec<UiDataUnitSummary>,
    pub empty_units: u64,
    /// Whether the profile scan cap stopped the walk before the geometry did.
    pub capped: bool,
    pub evidence: ValidationState,
}

impl UiDataArea {
    pub fn populated_entries(&self) -> u64 {
        self.populated_units.iter().map(|u| u.summary.populated).sum()
    }
}

/// Walk the UI-DATA area and summarise every unit that is present in the image.
pub fn read_ui_data(
    reader: &dyn EvidenceReader,
    layout: &UniviewLayout,
) -> Result<UiDataArea, ForensicError> {
    let capacity = layout.ui_data_capacity();
    let limit = capacity.min(layout.ui_data_scan_max_units);
    let mut populated_units = Vec::new();
    let mut empty_units = 0u64;
    let mut examined = 0u64;

    for n in 0..limit {
        let Some(offset) = layout.ui_data_offset(n) else { break };
        if offset >= reader.len() {
            break;
        }
        let buf = read_region(reader, offset, layout.ui_data_unit_size)?;
        examined += 1;
        if buf.iter().all(|&b| b == 0) {
            empty_units += 1;
            continue;
        }
        let summary = summarise(&buf, 0, offset, layout.ui_data_entries_per_unit, layout);
        populated_units.push(UiDataUnitSummary {
            n,
            offset,
            truncated: (buf.len() as u64) < layout.ui_data_unit_size,
            summary,
        });
    }

    let capped = limit < capacity && examined == limit;
    let entries: u64 = populated_units.iter().map(|u| u.summary.populated).sum();
    let evidence = vs(
        if capped || populated_units.iter().any(|u| u.truncated) {
            ValidationStateKind::Review
        } else {
            ValidationStateKind::Pass
        },
        format!(
            "UI-DATA at 0x{:X}: {examined} of {capacity} unit(s) examined, {} populated \
             ({entries} populated entr(y/ies)), {empty_units} empty{}. The UI-DATA → DI mapping is \
             not established, so these entries are not linked to units or DATA blocks",
            layout.ui_data_base,
            populated_units.len(),
            if capped { "; the profile scan cap stopped the walk" } else { "" }
        ),
        "read_ui_data",
        "uniview_ui_data",
    );

    Ok(UiDataArea {
        base: layout.ui_data_base,
        capacity,
        examined,
        populated_units,
        empty_units,
        capped,
        evidence,
    })
}

/// The populated entries of one UI-DATA unit. `Ok(None)` when the unit is outside the
/// geometry or the image.
pub fn read_ui_data_unit(
    reader: &dyn EvidenceReader,
    layout: &UniviewLayout,
    n: u64,
) -> Result<Option<Vec<TimeIndexEntry>>, ForensicError> {
    if n >= layout.ui_data_capacity() {
        return Ok(None);
    }
    let Some(offset) = layout.ui_data_offset(n) else { return Ok(None) };
    if offset >= reader.len() {
        return Ok(None);
    }
    let buf = read_region(reader, offset, layout.ui_data_unit_size)?;
    Ok(Some(decode_table(&buf, 0, offset, layout.ui_data_entries_per_unit, layout)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::tests_support::uniview_profile;
    use crate::testing::{build, SparseReader};
    use crate::timestamp::encode;

    fn layout() -> UniviewLayout {
        UniviewLayout::from_profile(&uniview_profile())
    }

    #[test]
    fn lock_extraction_matches_the_vendor_formula() {
        let e = build::time_index_entry(encode(2024, 1, 2, 3, 4, 5), 0x3FF_FFFF);
        assert_eq!(lock_value(&e), Some(0x3FF_FFFF));
        let e = build::time_index_entry(encode(2024, 1, 2, 3, 4, 5), 0x123_4567);
        assert_eq!(lock_value(&e), Some(0x123_4567));
        // Direct formula check on raw bytes.
        let raw = [0, 0, 0, 0, 0b1100_0000, 0x01, 0x02, 0x03];
        assert_eq!(lock_value(&raw), Some((1 << 2) | 3 | (2 << 10) | (3 << 18)));
        assert_eq!(lock_value(&raw[..7]), None);
        // The lock's low bits never disturb the timestamp's seconds.
        let t = UnvTimestamp::decode(&e[..5], 0, 2000, 2100);
        assert_eq!(t.second, 5);
    }

    #[test]
    fn old_ui_header_and_flag() {
        let l = layout();
        let entries = [build::time_index_entry(encode(2021, 5, 6, 7, 8, 9), 42)];
        let r = SparseReader::new(0x20000).with(0x4000, &build::old_ui(3, 0xBEEF, 1, &entries));
        let ui = read_ui(&r, &l, Generation::Old).unwrap();
        assert_eq!(ui.current_unit(), Some(3));
        assert_eq!(ui.rewrited(), Some(true));
        assert_eq!(
            ui.header,
            Some(UiHeader::Old { current_unit: 3, field_04: 0xBEEF, rewrited_raw: 1, byte_07: 0 })
        );
        assert_eq!(ui.entries.populated, 1);
        assert_eq!(ui.entries_confidence, Confidence::Tentative);
        assert_eq!(ui.evidence.state, ValidationStateKind::Pass);
        let f = ui.fields(&l);
        assert_eq!(f.iter().find(|f| f.name == "ui.field_04").unwrap().confidence, Confidence::Unknown);
        assert_eq!(f.iter().find(|f| f.name == "ui.rewrited").unwrap().physical_offset, 0x4006);
    }

    #[test]
    fn new_ui_ctl_header_and_entries() {
        let l = layout();
        let entries = [
            build::time_index_entry(encode(2024, 6, 1, 0, 0, 0), 7),
            build::time_index_entry(encode(2024, 6, 2, 0, 0, 0), 9),
        ];
        let r = SparseReader::new(0x20000).with(0x4000, &build::new_ui_ctl(2, 100, 0, &entries));
        let ui = read_ui(&r, &l, Generation::New).unwrap();
        assert_eq!(ui.current_unit(), Some(2));
        assert_eq!(ui.rewrited(), Some(false));
        assert_eq!(ui.entries.populated, 2);
        assert_eq!(ui.entries.capacity, (0x10000 - 0x10) / 8);
        assert_eq!(ui.entries.lock_min, Some(7));
        assert_eq!(ui.entries.lock_max, Some(9));
        assert_eq!(ui.entries.earliest.as_ref().unwrap().day, 1);
        assert_eq!(ui.entries.latest.as_ref().unwrap().day, 2);
        let listed = read_ui_entries(&r, &l, Generation::New).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[1].offset, 0x4000 + 0x10 + 8);
    }

    #[test]
    fn a_truncated_ui_region_is_review_and_does_not_panic() {
        let l = layout();
        let r = SparseReader::new(0x4003).with(0x4000, &[1, 2, 3]);
        let ui = read_ui(&r, &l, Generation::New).unwrap();
        assert!(ui.header.is_none());
        assert_eq!(ui.evidence.state, ValidationStateKind::Review);
        let r = SparseReader::new(0x4000);
        let ui = read_ui(&r, &l, Generation::Old).unwrap();
        assert!(ui.header.is_none());
    }

    #[test]
    fn ui_data_units_are_addressed_and_summarised() {
        let l = layout();
        let unit = build::ui_data_unit(&[
            build::time_index_entry(encode(2024, 1, 1, 1, 1, 1), 1),
            [0xFF; 8],
        ]);
        let r = SparseReader::new(0x14000 + 3 * 0x10000)
            .with(0x14000 + 0x10000, &unit);
        let area = read_ui_data(&r, &l).unwrap();
        assert_eq!(area.capacity, 4096);
        assert_eq!(area.examined, 3);
        assert_eq!(area.populated_units.len(), 1);
        let u = &area.populated_units[0];
        assert_eq!((u.n, u.offset), (1, 0x24000));
        assert_eq!(u.summary.populated, 2);
        assert_eq!(u.summary.valid_timestamps, 1);
        assert_eq!(u.summary.invalid_timestamps, 1);
        assert_eq!(area.empty_units, 2);

        let entries = read_ui_data_unit(&r, &l, 1).unwrap().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].offset, 0x24008);
        assert_eq!(read_ui_data_unit(&r, &l, 4096).unwrap(), None);
        assert_eq!(read_ui_data_unit(&r, &l, 10).unwrap(), None, "outside the image");
    }
}
