//! # UI (OLD), UI-CTL (NEW) and UI-DATA (NEW)
//!
//! Layouts as established from the disktool listing (`FUN_00011b74` display and export
//! paths, `FUN_00013600` FLOW):
//!
//! ```text
//!   OLD  0x4000  UI       +0x00 u32  current-unit raw value              CONFIRMED location
//!                         +0x04 u16  (meaning not established)           UNKNOWN
//!                         +0x06 u16  rewrited flag (== 1 "been rewrited") CONFIRMED (ldrh)
//!                         unit u's 8-byte time-index entry at UI + (u + 1) * 8
//!                                                                         CONFIRMED addressing
//!                         written units = raw - 1                         CONFIRMED (FLOW)
//!
//!   NEW  0x4000  UI-CTL   +0x00 u32  current-unit raw value              CONFIRMED location
//!                         +0x04 u32  count base: UI-CTL entries = (v >> 13) + 1
//!                                                                         CONFIRMED arithmetic
//!                         +0x08 4 bytes, +0x0E 2 bytes                    UNKNOWN
//!                         +0x0C u16  rewrited flag                        CONFIRMED (ldrh)
//!                         +0x10 8-byte entries, numbered 0 .. count-1     CONFIRMED loop
//!                         written units = raw + 1                         CONFIRMED (FLOW)
//!
//!   NEW  0x14000 + n*0x10000  UI-DATA unit n: 0x2000 8-byte entries
//!        global entry index of unit u = u - 1  ->  n = (u-1) >> 13, slot = (u-1) & 0x1FFF
//!                                                                         CONFIRMED addressing
//!
//!   8-byte entry: 5-byte packed timestamp                                 CONFIRMED
//!                 lock = (b5<<2) | (b4>>6) | (b6<<10) | (b7<<18)           CONFIRMED extraction
//!                                                                         UNKNOWN meaning
//! ```
//!
//! ## What is established, and what is not
//!
//! * Each storage unit has **one** 8-byte time-index entry (OLD in UI, NEW in UI-DATA). The
//!   disktool export copies exactly that entry as "the unit's" entry, and the UI-DATA display
//!   is clamped to the current unit when the disk has not wrapped. The link *unit ↔ entry* is
//!   therefore confirmed addressing; what the timestamp denotes for the unit is a strong
//!   inference, and no link from an entry to an individual DI entry is established.
//! * The lock value is reported as a "lock / time-index value". It is **not** a channel.
//! * The rewrited flag indicates the ring has wrapped. It does **not** say which recordings
//!   were overwritten.
//! * The raw current-unit values are preserved; the generation-specific adjustments are
//!   applied only where the vendor applies them (written-unit count), never silently.

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};

use crate::field::FieldEvidence;
use crate::layout::{bytes_at, u16_at, u32_at, vs, Confidence, Generation, UniviewLayout};
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
    /// The vendor's number for the entry: the unit number (OLD UI), the 0-based entry number
    /// (NEW UI-CTL), or the 0-based global UI-DATA index (NEW UI-DATA).
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
    pub fn decode(raw: &[u8], offset: u64, index: u32, layout: &UniviewLayout) -> Option<Self> {
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

    pub fn is_blank(&self) -> bool {
        self.raw.iter().all(|&b| b == 0)
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
    /// Entry slots summarised.
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
        if e.is_blank() {
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

/// A run of 8-byte entries inside a buffer: entry `k` (0-based within the run) sits at buffer
/// offset `first + k * entry_size` and carries the vendor number `label0 + k`.
#[derive(Debug, Clone, Copy)]
struct Run {
    first: usize,
    len: u64,
    label0: u64,
}

fn run_entries<'a>(
    buf: &'a [u8],
    buf_base: u64,
    run: Run,
    layout: &'a UniviewLayout,
) -> impl Iterator<Item = TimeIndexEntry> + 'a {
    (0..run.len).map_while(move |k| {
        let off = run
            .first
            .checked_add(usize::try_from(k).ok()?.checked_mul(layout.ui_entry_size)?)?;
        let raw = bytes_at(buf, off, 8)?;
        let label = u32::try_from(run.label0.checked_add(k)?).ok()?;
        TimeIndexEntry::decode(raw, buf_base + off as u64, label, layout)
    })
}

fn summarise_run(buf: &[u8], buf_base: u64, run: Run, layout: &UniviewLayout) -> TimeIndexSummary {
    let mut s = TimeIndexSummary {
        capacity: run.len,
        ..Default::default()
    };
    for e in run_entries(buf, buf_base, run, layout) {
        s.absorb(&e);
    }
    s
}

/// The UI (OLD) or UI-CTL (NEW) header fields, raw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UiHeader {
    Old {
        /// +0x00: current-unit raw value (written units = raw - 1).
        current_unit_raw: u32,
        /// +0x04: u16 whose meaning is not established.
        field_04: u16,
        /// +0x06: rewrited flag, u16.
        rewrited_raw: u16,
    },
    New {
        /// +0x00: current-unit raw value (written units = raw + 1).
        current_unit_raw: u32,
        /// +0x04: count base, raw (UI-CTL entries = (raw >> 13) + 1).
        count_raw: u32,
        /// +0x08..+0x0B: bytes whose meaning is not established.
        bytes_08_0b: [u8; 4],
        /// +0x0C: rewrited flag, u16.
        rewrited_raw: u16,
        /// +0x0E..+0x0F: bytes whose meaning is not established.
        bytes_0e_0f: [u8; 2],
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
    /// Entries the header declares: OLD one per written unit (1..=raw-1), NEW the UI-CTL
    /// count `(raw_04 >> 13) + 1`. Clamped to what the region can hold.
    pub declared_entries: Option<u64>,
    /// Aggregate over the declared entries.
    pub entries: TimeIndexSummary,
    /// Populated slots beyond the declared entries (residue; not interpreted).
    pub populated_beyond_declared: u64,
    /// How well the meaning of the entry table is established.
    pub entries_confidence: Confidence,
    pub evidence: ValidationState,
}

impl UniviewUi {
    /// The raw `+0x00` value, exactly as stored.
    pub fn current_unit_raw(&self) -> Option<u32> {
        match self.header.as_ref()? {
            UiHeader::Old { current_unit_raw, .. } | UiHeader::New { current_unit_raw, .. } => {
                Some(*current_unit_raw)
            }
        }
    }

    /// Written unit count with the vendor's adjustment (OLD raw - 1, NEW raw + 1).
    pub fn unit_count(&self, layout: &UniviewLayout) -> Option<i64> {
        Some(layout.unit_count_from_raw(self.generation, self.current_unit_raw()?))
    }

    pub fn rewrited_raw(&self) -> Option<u16> {
        match self.header.as_ref()? {
            UiHeader::Old { rewrited_raw, .. } | UiHeader::New { rewrited_raw, .. } => {
                Some(*rewrited_raw)
            }
        }
    }

    /// Whether the rewrited flag is non-zero. `None` if the header was not readable.
    pub fn rewrited(&self) -> Option<bool> {
        self.rewrited_raw().map(|v| v != 0)
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
        let rewrite_note = |raw: u16| match raw {
            0 => "0: not rewrited".to_string(),
            1 => "1: been rewrited; the circular storage has wrapped at least once (which \
                  recordings were overwritten is not recorded here)"
                .to_string(),
            v => format!(
                "{v}: non-zero, so disktool refuses FLOW; outside the {{0, 1}} values the vendor \
                 display distinguishes"
            ),
        };
        let count_note = |raw: u32| {
            format!(
                "raw {raw}; written unit count = {} (vendor adjustment, {})",
                layout.unit_count_from_raw(self.generation, raw),
                match self.generation {
                    Generation::Old => "raw - 1",
                    Generation::New => "raw + 1",
                }
            )
        };
        match &self.header {
            None => Vec::new(),
            Some(UiHeader::Old { current_unit_raw, field_04, rewrited_raw }) => vec![
                FieldEvidence::new(
                    "ui.current_unit_raw",
                    base + layout.old_ui_current_unit_offset as u64,
                    32,
                    None,
                    &current_unit_raw.to_le_bytes(),
                    Some(u64::from(*current_unit_raw)),
                    count_note(*current_unit_raw),
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
                    16,
                    None,
                    &rewrited_raw.to_le_bytes(),
                    Some(u64::from(*rewrited_raw)),
                    rewrite_note(*rewrited_raw),
                    Confidence::StrongInference,
                ),
            ],
            Some(UiHeader::New { current_unit_raw, count_raw, bytes_08_0b, rewrited_raw, bytes_0e_0f }) => {
                vec![
                    FieldEvidence::new(
                        "ui_ctl.current_unit_raw",
                        base + layout.new_uictl_current_unit_offset as u64,
                        32,
                        None,
                        &current_unit_raw.to_le_bytes(),
                        Some(u64::from(*current_unit_raw)),
                        count_note(*current_unit_raw),
                        Confidence::Confirmed,
                    ),
                    FieldEvidence::new(
                        "ui_ctl.count_raw",
                        base + layout.new_uictl_count_offset as u64,
                        32,
                        None,
                        &count_raw.to_le_bytes(),
                        Some(u64::from(*count_raw)),
                        format!(
                            "raw {count_raw}; UI-CTL entry count = (raw >> {}) + 1 = {}; also the \
                             vendor's upper bound on the displayed UI-DATA index (semantics \
                             TENTATIVE)",
                            layout.new_uictl_count_shift,
                            layout.uictl_entry_count(*count_raw)
                        ),
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
                        16,
                        None,
                        &rewrited_raw.to_le_bytes(),
                        Some(u64::from(*rewrited_raw)),
                        rewrite_note(*rewrited_raw),
                        Confidence::StrongInference,
                    ),
                    FieldEvidence::unknown(
                        "ui_ctl.bytes_0e_0f",
                        base + layout.new_uictl_rewrited_offset as u64 + 2,
                        bytes_0e_0f,
                    ),
                ]
            }
        }
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

/// Highest OLD unit whose entry `UI + (u + 1) * 8` still fits in the UI region.
fn old_max_units(layout: &UniviewLayout) -> u64 {
    if layout.ui_entry_size == 0 {
        return 0;
    }
    (layout.ui_size / layout.ui_entry_size as u64)
        .saturating_sub(1)
        .saturating_sub(layout.old_ui_unit_entry_slot_addend)
}

/// NEW UI-CTL entry-table capacity from +0x10.
fn new_capacity(layout: &UniviewLayout) -> u64 {
    if layout.ui_entry_size == 0 {
        return 0;
    }
    layout.ui_size.saturating_sub(layout.new_uictl_entries_offset as u64) / layout.ui_entry_size as u64
}

/// `(declared run, beyond-declared run, declared count)` for the region's entry table.
fn entry_runs(layout: &UniviewLayout, generation: Generation, header: &UiHeader) -> (Run, Run, u64) {
    match (generation, header) {
        (Generation::Old, UiHeader::Old { current_unit_raw, .. }) => {
            let max = old_max_units(layout);
            let declared = layout
                .unit_count_from_raw(Generation::Old, *current_unit_raw)
                .clamp(0, max as i64) as u64;
            let slot = |u: u64| {
                usize::try_from(u.saturating_add(layout.old_ui_unit_entry_slot_addend))
                    .unwrap_or(usize::MAX)
                    .saturating_mul(layout.ui_entry_size)
            };
            (
                Run { first: slot(1), len: declared, label0: 1 },
                Run { first: slot(declared + 1), len: max - declared, label0: declared + 1 },
                declared,
            )
        }
        (_, UiHeader::New { count_raw, .. }) => {
            let cap = new_capacity(layout);
            let declared = layout.uictl_entry_count(*count_raw).min(cap);
            let at = |k: u64| {
                layout.new_uictl_entries_offset.saturating_add(
                    usize::try_from(k).unwrap_or(usize::MAX).saturating_mul(layout.ui_entry_size),
                )
            };
            (
                Run { first: at(0), len: declared, label0: 0 },
                Run { first: at(declared), len: cap - declared, label0: declared },
                declared,
            )
        }
        // An OLD header is only ever built for the OLD generation; this arm is unreachable in
        // practice and yields empty runs rather than a panic.
        (_, UiHeader::Old { .. }) => (
            Run { first: 0, len: 0, label0: 0 },
            Run { first: 0, len: 0, label0: 0 },
            0,
        ),
    }
}

fn parse_header(buf: &[u8], layout: &UniviewLayout, generation: Generation) -> Option<UiHeader> {
    match generation {
        Generation::Old => Some(UiHeader::Old {
            current_unit_raw: u32_at(buf, layout.old_ui_current_unit_offset)?,
            field_04: u16_at(buf, layout.old_ui_field_04_offset)?,
            rewrited_raw: u16_at(buf, layout.old_ui_rewrited_offset)?,
        }),
        Generation::New => {
            let mut b08 = [0u8; 4];
            b08.copy_from_slice(bytes_at(buf, layout.new_uictl_count_offset + 4, 4)?);
            let mut b0e = [0u8; 2];
            b0e.copy_from_slice(bytes_at(buf, layout.new_uictl_rewrited_offset + 2, 2)?);
            Some(UiHeader::New {
                current_unit_raw: u32_at(buf, layout.new_uictl_current_unit_offset)?,
                count_raw: u32_at(buf, layout.new_uictl_count_offset)?,
                bytes_08_0b: b08,
                rewrited_raw: u16_at(buf, layout.new_uictl_rewrited_offset)?,
                bytes_0e_0f: b0e,
            })
        }
    }
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
    let header = parse_header(&buf, layout, generation);

    let (entries, populated_beyond_declared, declared_entries) = match &header {
        Some(h) => {
            let (declared, beyond, n) = entry_runs(layout, generation, h);
            let s = summarise_run(&buf, layout.ui_offset, declared, layout);
            let b = summarise_run(&buf, layout.ui_offset, beyond, layout).populated;
            (s, b, Some(n))
        }
        None => (TimeIndexSummary::default(), 0, None),
    };

    let available = buf.len() as u64;
    let evidence = if header.is_none() {
        vs(
            ValidationStateKind::Review,
            format!(
                "the {region} header at 0x{:X} is not readable ({available} byte(s) present)",
                layout.ui_offset
            ),
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
                "{region} parsed at 0x{:X}: {} declared 8-byte entr(y/ies), {} populated{}",
                layout.ui_offset,
                declared_entries.unwrap_or(0),
                entries.populated,
                if populated_beyond_declared > 0 {
                    format!("; {populated_beyond_declared} populated slot(s) beyond the declared entries")
                } else {
                    String::new()
                }
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
        declared_entries,
        entries,
        populated_beyond_declared,
        entries_confidence: Confidence::StrongInference,
        evidence,
    })
}

/// The declared, populated entries of the UI / UI-CTL table, with vendor numbering.
pub fn read_ui_entries(
    reader: &dyn EvidenceReader,
    layout: &UniviewLayout,
    generation: Generation,
) -> Result<Vec<TimeIndexEntry>, ForensicError> {
    let buf = read_region(reader, layout.ui_offset, layout.ui_size)?;
    let Some(header) = parse_header(&buf, layout, generation) else {
        return Ok(Vec::new());
    };
    let (declared, _, _) = entry_runs(layout, generation, &header);
    Ok(run_entries(&buf, layout.ui_offset, declared, layout)
        .filter(|e| !e.is_blank())
        .collect())
}

/// Unit `u`'s own 8-byte time-index entry (OLD `UI + (u+1)*8`, NEW UI-DATA global index
/// `u - 1`), exactly as stored — blank entries included. `Ok(None)` when the geometry has no
/// slot for the unit or the image does not hold it.
pub fn unit_time_entry(
    reader: &dyn EvidenceReader,
    layout: &UniviewLayout,
    generation: Generation,
    unit: u32,
) -> Result<Option<TimeIndexEntry>, ForensicError> {
    let (offset, label) = match generation {
        Generation::Old => match layout.old_ui_unit_entry_offset(unit) {
            Some(o) => (o, unit),
            None => return Ok(None),
        },
        Generation::New => match layout.new_ui_data_unit_entry(unit) {
            Some((_, _, o)) => (o, unit - 1),
            None => return Ok(None),
        },
    };
    let Some(end) = offset.checked_add(8) else { return Ok(None) };
    if end > reader.len() {
        return Ok(None);
    }
    let raw = reader.read_exact_at(offset, 8)?;
    Ok(TimeIndexEntry::decode(&raw, offset, label, layout))
}

/// Summary of one populated UI-DATA unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiDataUnitSummary {
    /// UI-DATA unit number `n` (0-based), as in `0x14000 + n * 0x10000`.
    pub n: u64,
    pub offset: u64,
    /// Whether the image ends inside this unit.
    pub truncated: bool,
    /// Entries labelled by their 0-based global UI-DATA index (`n * 0x2000 + slot`), which is
    /// `storage unit - 1`.
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
    /// The highest global index the vendor display shows: `UI-CTL[+0x04]`, further limited to
    /// `UI-CTL[+0x00]` when the rewrited flag is clear. CONFIRMED arithmetic (disktool
    /// `ui-data` display); its meaning is TENTATIVE. `None` without a UI-CTL header.
    pub vendor_display_last_index: Option<u64>,
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
    ui_ctl: Option<&UniviewUi>,
) -> Result<UiDataArea, ForensicError> {
    let capacity = layout.ui_data_capacity();
    let limit = capacity.min(layout.ui_data_scan_max_units);
    let per = layout.ui_data_entries_per_unit as u64;
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
        let run = Run { first: 0, len: per, label0: n.saturating_mul(per) };
        let summary = summarise_run(&buf, offset, run, layout);
        populated_units.push(UiDataUnitSummary {
            n,
            offset,
            truncated: (buf.len() as u64) < layout.ui_data_unit_size,
            summary,
        });
    }

    let vendor_display_last_index = ui_ctl.and_then(|u| match &u.header {
        Some(UiHeader::New { current_unit_raw, count_raw, rewrited_raw, .. }) => {
            let mut last = u64::from(*count_raw);
            if *rewrited_raw == 0 {
                last = last.min(u64::from(*current_unit_raw));
            }
            Some(last)
        }
        _ => None,
    });

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
             ({entries} populated entr(y/ies)), {empty_units} empty{}. Global entry index i is \
             storage unit i + 1; no link from an entry to an individual DI entry is established",
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
        vendor_display_last_index,
        evidence,
    })
}

/// The populated entries of one UI-DATA unit, labelled by global index. `Ok(None)` when the
/// unit is outside the geometry or the image.
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
    let per = layout.ui_data_entries_per_unit as u64;
    let run = Run { first: 0, len: per, label0: n.saturating_mul(per) };
    Ok(Some(
        run_entries(&buf, offset, run, layout)
            .filter(|e| !e.is_blank())
            .collect(),
    ))
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
        let raw = [0, 0, 0, 0, 0b1100_0000, 0x01, 0x02, 0x03];
        assert_eq!(lock_value(&raw), Some((1 << 2) | 3 | (2 << 10) | (3 << 18)));
        assert_eq!(lock_value(&raw[..7]), None);
        let t = UnvTimestamp::decode(&e[..5], 0, 2000, 2100);
        assert_eq!(t.second, 5, "the lock's low bits never disturb the seconds");
    }

    #[test]
    fn old_ui_u16_rewrited_numbering_and_unit_entries() {
        let l = layout();
        let e1 = build::time_index_entry(encode(2021, 5, 6, 7, 8, 9), 42);
        let e2 = build::time_index_entry(encode(2021, 5, 7, 7, 8, 9), 43);
        // raw 3 -> written units 1..=2; entries at UI + (u+1)*8. A stray slot for unit 5.
        let stray = build::time_index_entry(encode(2020, 1, 1, 0, 0, 0), 1);
        let ui = build::old_ui(3, 0xBEEF, 0x0100, &[(1, e1), (2, e2), (5, stray)]);
        let r = SparseReader::new(0x20000).with(0x4000, &ui);
        let parsed = read_ui(&r, &l, Generation::Old).unwrap();
        assert_eq!(
            parsed.header,
            Some(UiHeader::Old { current_unit_raw: 3, field_04: 0xBEEF, rewrited_raw: 0x0100 })
        );
        assert_eq!(parsed.rewrited_raw(), Some(0x0100), "the flag is a u16, not one byte");
        assert_eq!(parsed.rewrited(), Some(true));
        assert_eq!(parsed.unit_count(&l), Some(2), "OLD written units = raw - 1");
        assert_eq!(parsed.declared_entries, Some(2));
        assert_eq!(parsed.entries.populated, 2);
        assert_eq!(parsed.populated_beyond_declared, 1);
        let listed = read_ui_entries(&r, &l, Generation::Old).unwrap();
        assert_eq!(listed.iter().map(|e| (e.index, e.offset)).collect::<Vec<_>>(), vec![(1, 0x4010), (2, 0x4018)]);
        let u2 = unit_time_entry(&r, &l, Generation::Old, 2).unwrap().unwrap();
        assert_eq!((u2.offset, u2.lock, u2.index), (0x4000 + 3 * 8, 43, 2));
        let f = parsed.fields(&l);
        let rw = f.iter().find(|f| f.name == "ui.rewrited").unwrap();
        assert_eq!((rw.physical_offset, rw.size_bits), (0x4006, 16));
        assert_eq!(f.iter().find(|f| f.name == "ui.field_04").unwrap().confidence, Confidence::Unknown);
    }

    #[test]
    fn new_ui_ctl_u16_rewrited_numbering_and_entry_count() {
        let l = layout();
        let entries = [
            build::time_index_entry(encode(2024, 6, 1, 0, 0, 0), 7),
            build::time_index_entry(encode(2024, 6, 2, 0, 0, 0), 9),
        ];
        // count_raw 0x2000 -> (0x2000 >> 13) + 1 = 2 entries, numbered 0 and 1.
        let mut ctl = build::new_ui_ctl(4, 0x2000, 1, &entries);
        ctl[0x0E] = 0xAB; // beyond the u16 flag: not part of it
        let r = SparseReader::new(0x20000).with(0x4000, &ctl);
        let ui = read_ui(&r, &l, Generation::New).unwrap();
        assert_eq!(ui.current_unit_raw(), Some(4));
        assert_eq!(ui.unit_count(&l), Some(5), "NEW written units = raw + 1");
        assert_eq!(ui.rewrited_raw(), Some(1), "u16 at +0x0C; +0x0E is not part of the flag");
        assert_eq!(ui.declared_entries, Some(2));
        assert_eq!(ui.entries.populated, 2);
        assert_eq!(ui.entries.first_populated_index, Some(0));
        let listed = read_ui_entries(&r, &l, Generation::New).unwrap();
        assert_eq!(listed[1].offset, 0x4000 + 0x10 + 8);
        assert!(matches!(ui.header, Some(UiHeader::New { bytes_0e_0f: [0xAB, 0], .. })));
    }

    #[test]
    fn a_truncated_ui_region_is_review_and_does_not_panic() {
        let l = layout();
        let r = SparseReader::new(0x4003).with(0x4000, &[1, 2, 3]);
        let ui = read_ui(&r, &l, Generation::New).unwrap();
        assert!(ui.header.is_none());
        assert_eq!(ui.evidence.state, ValidationStateKind::Review);
        let r = SparseReader::new(0x4000);
        assert!(read_ui(&r, &l, Generation::Old).unwrap().header.is_none());
        // Absurd raw values are reported, not trusted.
        let r = SparseReader::new(0x20000).with(0x4000, &build::old_ui(0xFFFF_FFFF, 0, 0, &[]));
        let ui = read_ui(&r, &l, Generation::Old).unwrap();
        assert_eq!(ui.unit_count(&l), Some(0xFFFF_FFFE));
        assert_eq!(ui.declared_entries, Some(old_max_units(&l)), "clamped to what the UI holds");
        assert_eq!(unit_time_entry(&r, &l, Generation::Old, 0).unwrap(), None);
    }

    #[test]
    fn ui_data_units_are_addressed_by_global_index() {
        let l = layout();
        let unit = build::ui_data_unit(&[
            build::time_index_entry(encode(2024, 1, 1, 1, 1, 1), 1),
            [0xFF; 8],
        ]);
        let r = SparseReader::new(0x14000 + 3 * 0x10000).with(0x14000 + 0x10000, &unit);
        let area = read_ui_data(&r, &l, None).unwrap();
        assert_eq!(area.capacity, 4096);
        assert_eq!(area.examined, 3);
        assert_eq!(area.populated_units.len(), 1);
        let u = &area.populated_units[0];
        assert_eq!((u.n, u.offset), (1, 0x24000));
        assert_eq!(u.summary.first_populated_index, Some(0x2000), "global index n * 0x2000 + slot");
        assert_eq!(u.summary.valid_timestamps, 1);
        assert_eq!(u.summary.invalid_timestamps, 1);
        assert_eq!(area.empty_units, 2);
        assert_eq!(area.vendor_display_last_index, None);

        let entries = read_ui_data_unit(&r, &l, 1).unwrap().unwrap();
        assert_eq!(entries.iter().map(|e| (e.index, e.offset)).collect::<Vec<_>>(), vec![(0x2000, 0x24000), (0x2001, 0x24008)]);
        assert_eq!(read_ui_data_unit(&r, &l, 4096).unwrap(), None);
        assert_eq!(read_ui_data_unit(&r, &l, 10).unwrap(), None, "outside the image");

        // Storage unit 0x2001 is UI-DATA unit 1, slot 0.
        let e = unit_time_entry(&r, &l, Generation::New, 0x2001).unwrap().unwrap();
        assert_eq!((e.offset, e.index, e.lock), (0x24000, 0x2000, 1));
        let e = unit_time_entry(&r, &l, Generation::New, 0x2002).unwrap().unwrap();
        assert_eq!(e.offset, 0x24008);
        assert_eq!(unit_time_entry(&r, &l, Generation::New, 3 * 0x2000 + 1).unwrap(), None, "not in image");
    }

    #[test]
    fn the_vendor_ui_data_display_bound_follows_the_rewrited_flag() {
        let l = layout();
        let clear = SparseReader::new(0x20000).with(0x4000, &build::new_ui_ctl(5, 100, 0, &[]));
        let ctl = read_ui(&clear, &l, Generation::New).unwrap();
        assert_eq!(read_ui_data(&clear, &l, Some(&ctl)).unwrap().vendor_display_last_index, Some(5));
        let set = SparseReader::new(0x20000).with(0x4000, &build::new_ui_ctl(5, 100, 1, &[]));
        let ctl = read_ui(&set, &l, Generation::New).unwrap();
        assert_eq!(read_ui_data(&set, &l, Some(&ctl)).unwrap().vendor_display_last_index, Some(100));
    }
}
