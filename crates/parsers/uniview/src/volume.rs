//! # Volume composition
//!
//! [`read_volume`] walks the whole Uniview structure set once:
//!
//! ```text
//!   SUPER ──► generation
//!     ├─ UI (OLD) / UI-CTL (NEW)       current unit, rewrited flag, time-index table
//!     ├─ UI-DATA (NEW)                 per-unit summaries
//!     └─ units 1..N (256 MiB each)
//!          └─ DI header + entries      write bytes, SPtoI ──► DATA spans
//! ```
//!
//! and turns it into the platform's [`StorageGeometry`] and [`RecordingIndex`].
//!
//! ## One index group per storage unit
//!
//! A unit holds up to 16 383 DI entries, and a full disk tens of thousands of units, so the
//! volume keeps a compact [`UnitRecord`] per unit (counts, time range, merged DATA regions,
//! a capped anomaly list) and re-reads a unit's entries on demand through [`unit_detail`].
//!
//! The index therefore reports **one entry per storage unit**, identified `unv:u<unit>`. That
//! grouping is structural — it is the unit the DI describes — and is **not** a claim that the
//! unit is one video recording. The mapping from UI / UI-DATA time-index entries to DI
//! entries is not established, so no finer "recording" boundary is fabricated.
//!
//! ## Authority is always `Partial`
//!
//! DI carries no checksum, spans are an adjacent-SPtoI inference, and the last entry of a
//! unit only claims the one block its SPtoI selects. Absence from this index is therefore
//! not evidence of absence, and the index never claims to be authoritative. That keeps the
//! generic engine from reporting unclaimed DATA as orphaned on the strength of an inference.
//!
//! ## FLOW is calculated, not read
//!
//! There is no on-disk FLOW region. The vendor tooling derives FLOW by summing every unit's
//! DI `+0x00` write-data counter; [`UniviewVolume::flow_total_write_bytes`] is exactly that.

use std::collections::BTreeMap;

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, OemProfile, Region, ValidationState, ValidationStateKind};
use parsers_core::storage::{
    AllocationEvidence, CircularBufferEvidence, IndexAuthority, IndexedRecording, RecordingIndex,
    StorageGeometry,
};
use serde::{Deserialize, Serialize};

use crate::di::{self, DataSpan, DiHeader, DiHeaderState, SptoiState, UnitDi};
use crate::layout::{vs, Generation, UniviewLayout};
use crate::superblock::{self, SuperRecognition, UniviewSuper};
use crate::timestamp::{TimestampStatus, UnvTimestamp};
use crate::ui::{self, UiDataArea, UniviewUi};

/// Prefix of every Uniview recording/index-group id.
pub const RECORDING_ID_PREFIX: &str = "unv:u";

/// Why an index group is not a recording claim.
pub const GROUPING_NOTE: &str =
    "storage-unit index group: the DI entries of one 256 MiB unit. This is a structural \
     grouping, not a proven video recording boundary; the UI/UI-DATA -> DI mapping is not \
     established";

/// Why the index is never authoritative.
pub const PARTIAL_AUTHORITY_REASON: &str =
    "Uniview DI carries no integrity marker, DATA extents are inferred from adjacent SPtoI \
     values, and a unit's last entry claims only the block its SPtoI selects. Absence from \
     this index is therefore not evidence of absence";

/// Compact per-unit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitRecord {
    /// 1-based unit number.
    pub unit: u32,
    pub unit_base: u64,
    pub di_offset: u64,
    /// Bytes of this unit that are present in the image.
    pub bytes_in_image: u64,
    pub header_state: DiHeaderState,
    pub header: Option<DiHeader>,
    pub entries_parsed: u64,
    /// Entries with a decodable timestamp and an in-image DATA SPtoI.
    pub usable_entries: u64,
    pub blank_entries: u64,
    pub invalid_timestamps: u64,
    pub implausible_timestamps: u64,
    pub sptoi_into_di: u64,
    pub sptoi_outside_image: u64,
    /// Adjacent entries whose timestamp goes backwards. Reported, not "fixed".
    pub timestamp_regressions: u64,
    pub earliest: Option<UnvTimestamp>,
    pub latest: Option<UnvTimestamp>,
    /// Count of spans per [`crate::di::SpanBasis`] label.
    pub span_basis_counts: BTreeMap<String, u64>,
    pub spans_truncated_by_image: u64,
    /// Union of the inferred DATA spans, merged, ascending.
    pub data_regions: Vec<Region>,
    pub anomalies: Vec<String>,
    pub anomalies_suppressed: u64,
}

impl UnitRecord {
    pub fn recording_id(&self) -> String {
        format!("{RECORDING_ID_PREFIX}{}", self.unit)
    }

    /// Whether the unit contributes at least one usable DI entry to the index.
    pub fn is_indexed(&self) -> bool {
        self.usable_entries > 0 && !self.data_regions.is_empty()
    }

    pub fn indexed_bytes(&self) -> u64 {
        self.data_regions.iter().fold(0u64, |a, r| a.saturating_add(r.length))
    }

    /// Whether the header or entries carry anything an examiner should look at.
    pub fn has_problems(&self) -> bool {
        !matches!(self.header_state, DiHeaderState::Valid | DiHeaderState::Empty)
            || self.invalid_timestamps > 0
            || self.sptoi_into_di > 0
            || self.sptoi_outside_image > 0
    }

    fn note(&mut self, cap: usize, msg: String) {
        if self.anomalies.len() < cap {
            self.anomalies.push(msg);
        } else {
            self.anomalies_suppressed += 1;
        }
    }
}

/// Merge overlapping or touching regions into an ascending, disjoint list.
pub fn merge_regions(mut regions: Vec<Region>) -> Vec<Region> {
    regions.sort_by_key(|r| (r.offset, r.length));
    let mut out: Vec<Region> = Vec::with_capacity(regions.len());
    for r in regions {
        let r_end = r.offset.saturating_add(r.length);
        if let Some(last) = out.last_mut() {
            let last_end = last.offset.saturating_add(last.length);
            if r.offset <= last_end {
                if r_end > last_end {
                    last.length = r_end - last.offset;
                }
                continue;
            }
        }
        out.push(r);
    }
    out
}

fn summarise_unit(
    di: &UnitDi,
    spans: &[DataSpan],
    layout: &UniviewLayout,
    image_len: u64,
) -> UnitRecord {
    let cap = layout.max_anomalies_per_unit;
    let unit_end = di.unit_base.saturating_add(layout.unit_size).min(image_len);
    let mut rec = UnitRecord {
        unit: di.unit,
        unit_base: di.unit_base,
        di_offset: di.di_offset,
        bytes_in_image: unit_end.saturating_sub(di.unit_base),
        header_state: di.header_state.clone(),
        header: di.header.clone(),
        entries_parsed: di.entries.len() as u64,
        usable_entries: 0,
        blank_entries: 0,
        invalid_timestamps: 0,
        implausible_timestamps: 0,
        sptoi_into_di: 0,
        sptoi_outside_image: 0,
        timestamp_regressions: 0,
        earliest: None,
        latest: None,
        span_basis_counts: BTreeMap::new(),
        spans_truncated_by_image: 0,
        data_regions: Vec::new(),
        anomalies: Vec::new(),
        anomalies_suppressed: 0,
    };

    match &di.header_state {
        DiHeaderState::Valid | DiHeaderState::Empty | DiHeaderState::NotPresent => {}
        other => rec.note(cap, format!("DI header at 0x{:X}: {}", di.di_offset, other.label())),
    }

    let mut prev_time: Option<i64> = None;
    for e in &di.entries {
        if e.is_blank() {
            rec.blank_entries += 1;
            rec.note(cap, format!("DI entry {} at 0x{:X} is blank inside the declared count", e.index, e.offset));
            continue;
        }
        match e.timestamp.status {
            TimestampStatus::Invalid | TimestampStatus::Truncated | TimestampStatus::Empty => {
                rec.invalid_timestamps += 1;
                rec.note(
                    cap,
                    format!("DI entry {} at 0x{:X}: timestamp {}", e.index, e.offset, e.timestamp.label()),
                );
            }
            TimestampStatus::Implausible => rec.implausible_timestamps += 1,
            TimestampStatus::Valid => {}
        }
        match e.sptoi_state {
            SptoiState::PointsIntoDi => {
                rec.sptoi_into_di += 1;
                rec.note(
                    cap,
                    format!("DI entry {} SPtoI {} selects a block inside the DI region", e.index, e.sptoi),
                );
            }
            SptoiState::OutsideImage => {
                rec.sptoi_outside_image += 1;
                rec.note(
                    cap,
                    format!("DI entry {} SPtoI {} selects a DATA block outside the image", e.index, e.sptoi),
                );
            }
            SptoiState::Data => {}
        }
        if let Some(t) = e.timestamp.unix_seconds_as_utc() {
            if prev_time.is_some_and(|p| t < p) {
                rec.timestamp_regressions += 1;
            }
            prev_time = Some(t);
            if rec.earliest.as_ref().and_then(UnvTimestamp::unix_seconds_as_utc).is_none_or(|x| t < x) {
                rec.earliest = Some(e.timestamp.clone());
            }
            if rec.latest.as_ref().and_then(UnvTimestamp::unix_seconds_as_utc).is_none_or(|x| t > x) {
                rec.latest = Some(e.timestamp.clone());
            }
        }
        if e.is_usable() {
            rec.usable_entries += 1;
        }
    }

    let mut regions = Vec::with_capacity(spans.len());
    for s in spans {
        *rec.span_basis_counts.entry(s.basis.label().to_string()).or_default() += 1;
        if s.truncated_by_image {
            rec.spans_truncated_by_image += 1;
        }
        if let Some(r) = s.region {
            regions.push(r);
        }
    }
    rec.data_regions = merge_regions(regions);
    rec
}

/// Everything the Uniview structures establish about one evidence source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UniviewVolume {
    pub layout: UniviewLayout,
    pub image_len: u64,
    pub source_path: String,
    pub super_block: UniviewSuper,
    pub ui: Option<UniviewUi>,
    pub ui_data: Option<UiDataArea>,
    pub units: Vec<UnitRecord>,
    /// Whether the profile's unit cap stopped enumeration before the image did.
    pub units_capped: bool,
    pub evidence: ValidationState,
}

impl UniviewVolume {
    pub fn generation(&self) -> Option<Generation> {
        self.super_block.generation()
    }

    /// Whether a Uniview SUPER magic was found (complete or truncated).
    pub fn is_uniview(&self) -> bool {
        self.generation().is_some()
    }

    /// Whether the structures were established well enough to act on.
    pub fn is_usable(&self) -> bool {
        matches!(self.super_block.recognition, SuperRecognition::Recognized { .. })
    }

    pub fn indexed_units(&self) -> impl Iterator<Item = &UnitRecord> {
        self.units.iter().filter(|u| u.is_indexed())
    }

    pub fn find_unit(&self, recording_id: &str) -> Option<&UnitRecord> {
        let n: u32 = recording_id.strip_prefix(RECORDING_ID_PREFIX)?.parse().ok()?;
        self.units.iter().find(|u| u.unit == n)
    }

    /// FLOW: the sum of every unit's DI `+0x00` write-data counter. A calculated statistic,
    /// not an on-disk region. Only units whose header count is usable contribute.
    pub fn flow_total_write_bytes(&self) -> u64 {
        self.units
            .iter()
            .filter(|u| matches!(u.header_state, DiHeaderState::Valid | DiHeaderState::Truncated { .. }))
            .filter_map(|u| u.header.as_ref())
            .fold(0u64, |a, h| a.saturating_add(u64::from(h.write_bytes)))
    }

    pub fn declared_entries(&self) -> u64 {
        self.units
            .iter()
            .filter(|u| matches!(u.header_state, DiHeaderState::Valid | DiHeaderState::Truncated { .. }))
            .filter_map(|u| u.header.as_ref())
            .map(|h| u64::from(h.declared_count))
            .sum()
    }

    pub fn usable_entries(&self) -> u64 {
        self.units.iter().map(|u| u.usable_entries).sum()
    }

    /// The UI/UI-CTL current-unit value interpreted 1-based against the enumerated units.
    ///
    /// TENTATIVE: the research does not state whether the index is 0- or 1-based.
    pub fn current_unit_consistency(&self) -> Option<String> {
        let cur = self.ui.as_ref()?.current_unit()?;
        let n = self.units.len() as u64;
        Some(if cur >= 1 && u64::from(cur) <= n {
            format!("current unit {cur} is within the {n} enumerated unit(s) (1-based reading, TENTATIVE)")
        } else {
            format!(
                "current unit {cur} is outside the {n} enumerated unit(s) under a 1-based reading \
                 (TENTATIVE); the image may be truncated or the index 0-based"
            )
        })
    }
}

/// Read the whole Uniview structure set. Malformed evidence never fails the read; only a
/// reader-level I/O failure does.
pub fn read_volume(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
) -> Result<UniviewVolume, ForensicError> {
    let layout = UniviewLayout::from_profile(profile);
    let image_len = reader.len();
    let super_block = superblock::read_super(reader, &layout)?;

    let Some(generation) = super_block.generation() else {
        let evidence = super_block.recognition.validation();
        return Ok(UniviewVolume {
            layout,
            image_len,
            source_path: reader.source_path().to_string(),
            super_block,
            ui: None,
            ui_data: None,
            units: Vec::new(),
            units_capped: false,
            evidence,
        });
    };

    let ui = ui::read_ui(reader, &layout, generation)?;
    let ui_data = match generation {
        Generation::New => Some(ui::read_ui_data(reader, &layout)?),
        Generation::Old => None,
    };

    let mut units = Vec::new();
    let mut units_capped = false;
    let mut unit: u32 = 1;
    loop {
        if u64::from(unit) > layout.max_units {
            units_capped = layout
                .unit_base(generation, unit)
                .is_some_and(|b| b < image_len);
            break;
        }
        let Some(base) = layout.unit_base(generation, unit) else { break };
        if base >= image_len {
            break;
        }
        let d = di::read_unit_di(reader, &layout, generation, unit)?;
        let spans = d.spans(&layout, image_len);
        units.push(summarise_unit(&d, &spans, &layout, image_len));
        let Some(next) = unit.checked_add(1) else { break };
        unit = next;
    }

    let mut findings: Vec<String> = vec![format!("SUPER {}", super_block.recognition.label())];
    findings.push(ui.evidence.reason.clone());
    if let Some(d) = &ui_data {
        findings.push(d.evidence.reason.clone());
    }
    let indexed = units.iter().filter(|u| u.is_indexed()).count();
    let problem_units = units.iter().filter(|u| u.has_problems()).count();
    findings.push(format!(
        "{} unit(s) enumerated from 0x{:X} (stride 0x{:X}); {indexed} carry usable DI entries, \
         {problem_units} carry DI anomalies",
        units.len(),
        layout.generation_unit_base(generation),
        layout.unit_stride
    ));
    if units_capped {
        findings.push(format!(
            "the profile unit cap ({}) stopped enumeration before the end of the image",
            layout.max_units
        ));
    }

    let state = if !matches!(super_block.recognition, SuperRecognition::Recognized { .. })
        || ui.header.is_none()
        || ui.evidence.state != ValidationStateKind::Pass
        || problem_units > 0
        || units_capped
        || units.is_empty()
        || ui_data.as_ref().is_some_and(|d| d.evidence.state != ValidationStateKind::Pass)
    {
        ValidationStateKind::Review
    } else {
        ValidationStateKind::Pass
    };

    Ok(UniviewVolume {
        layout,
        image_len,
        source_path: reader.source_path().to_string(),
        super_block,
        ui: Some(ui),
        ui_data,
        units,
        units_capped,
        evidence: vs(state, findings.join(". "), "read_volume", "uniview_volume"),
    })
}

/// Full DI detail for one unit: every declared entry and its inferred span.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitDetail {
    pub di: UnitDi,
    pub spans: Vec<DataSpan>,
}

/// Re-read one unit's DI entries on demand. `Ok(None)` for a unit the volume does not have.
pub fn unit_detail(
    reader: &dyn EvidenceReader,
    volume: &UniviewVolume,
    unit: u32,
) -> Result<Option<UnitDetail>, ForensicError> {
    let Some(generation) = volume.generation() else { return Ok(None) };
    if !volume.units.iter().any(|u| u.unit == unit) {
        return Ok(None);
    }
    let di = di::read_unit_di(reader, &volume.layout, generation, unit)?;
    let spans = di.spans(&volume.layout, reader.len());
    Ok(Some(UnitDetail { di, spans }))
}

/// OEM-specific descriptive fields, as plain strings.
pub fn volume_summary(volume: &UniviewVolume) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let sb = &volume.super_block;
    m.insert("uniview.super.recognition".into(), sb.recognition.label());
    if let Some(g) = volume.generation() {
        m.insert("uniview.generation".into(), g.label().into());
    }
    if let Some(v) = sb.magic_raw {
        m.insert("uniview.super.magic".into(), format!("0x{v:04X}"));
    }
    if let Some(t) = &sb.last_write_time {
        m.insert("uniview.super.last_write_super_data_time".into(), t.label());
    }
    if let Some(t) = &sb.start_storage_time {
        m.insert("uniview.super.start_storage_time".into(), t.label());
    }
    if let Some(p) = &sb.ec_port_id {
        m.insert("uniview.super.ec_port_id_hex".into(), hex::encode(p));
    }
    if let Some(ui) = &volume.ui {
        let name = ui.region_name().to_ascii_lowercase().replace('-', "_");
        if let Some(c) = ui.current_unit() {
            m.insert(format!("uniview.{name}.current_unit"), c.to_string());
        }
        if let Some(r) = ui.rewrited() {
            m.insert(
                format!("uniview.{name}.rewrited"),
                if r {
                    "set (circular overwrite strongly indicated; overwritten recordings unknown)".into()
                } else {
                    "clear".into()
                },
            );
        }
        m.insert(format!("uniview.{name}.populated_entries"), ui.entries.populated.to_string());
        m.insert(
            format!("uniview.{name}.entries_confidence"),
            ui.entries_confidence.label().into(),
        );
    }
    if let Some(c) = volume.current_unit_consistency() {
        m.insert("uniview.current_unit_consistency".into(), c);
    }
    if let Some(d) = &volume.ui_data {
        m.insert("uniview.ui_data.units_examined".into(), d.examined.to_string());
        m.insert("uniview.ui_data.populated_units".into(), d.populated_units.len().to_string());
        m.insert("uniview.ui_data.populated_entries".into(), d.populated_entries().to_string());
        m.insert("uniview.ui_data.lock_semantics".into(), "UNKNOWN".into());
    }
    m.insert("uniview.units.enumerated".into(), volume.units.len().to_string());
    m.insert("uniview.units.indexed".into(), volume.indexed_units().count().to_string());
    m.insert(
        "uniview.units.empty".into(),
        volume.units.iter().filter(|u| u.header_state == DiHeaderState::Empty).count().to_string(),
    );
    m.insert(
        "uniview.units.with_anomalies".into(),
        volume.units.iter().filter(|u| u.has_problems()).count().to_string(),
    );
    m.insert("uniview.di.declared_entries".into(), volume.declared_entries().to_string());
    m.insert("uniview.di.usable_entries".into(), volume.usable_entries().to_string());
    m.insert(
        "uniview.flow.total_write_bytes".into(),
        format!(
            "{} (calculated: sum of DI +0x00 write-data counters; not an on-disk region)",
            volume.flow_total_write_bytes()
        ),
    );
    m.insert(
        "uniview.data.block_size".into(),
        volume.layout.data_block_size.to_string(),
    );
    m.insert("uniview.data.codec".into(), "UNKNOWN (no format is claimed)".into());
    m
}

/// The platform storage geometry. `Ok(None)` when the evidence is not Uniview.
pub fn storage_geometry(volume: &UniviewVolume) -> Result<Option<StorageGeometry>, ForensicError> {
    let Some(generation) = volume.generation() else { return Ok(None) };
    let l = &volume.layout;
    let clip = |offset: u64, len: u64| -> Option<Region> {
        if offset >= volume.image_len {
            return None;
        }
        Region::new(offset, len.min(volume.image_len - offset)).ok()
    };
    let first_unit = l.generation_unit_base(generation);
    let units_end = volume
        .units
        .last()
        .map(|u| u.unit_base.saturating_add(u.bytes_in_image))
        .unwrap_or(first_unit);
    let video_region = (units_end > first_unit)
        .then(|| clip(first_unit, units_end - first_unit))
        .flatten();

    let mut oem_fields = volume_summary(volume);
    oem_fields.insert(
        "uniview.geometry.video_region_note".into(),
        "the units region; every unit's first 256 KiB is its DI index, the rest DATA".into(),
    );
    oem_fields.insert(
        "uniview.geometry.index_region_note".into(),
        "UI (OLD) or UI-CTL + UI-DATA (NEW); per-unit DI regions lie inside the units region".into(),
    );

    let state = if volume.is_usable() && !volume.units.is_empty() {
        ValidationStateKind::Pass
    } else {
        ValidationStateKind::Review
    };
    Ok(Some(StorageGeometry {
        physical_size: volume.image_len,
        video_region,
        index_region: clip(l.ui_offset, first_unit.saturating_sub(l.ui_offset)),
        metadata_region: clip(l.super_offset, l.super_size),
        block_size: Some(l.data_block_size),
        sector_size: None,
        // The rewrited flag indicates a wrap happened, but no write-cursor offset is recorded
        // in a form this platform can place; the flag is reported in `oem_fields` instead.
        circular_buffer: CircularBufferEvidence::Unknown,
        oem_fields,
        evidence: vs(
            state,
            format!(
                "Uniview {} geometry: SUPER 0x{:X}+0x{:X}, first unit at 0x{first_unit:X}, stride \
                 0x{:X}, DATA block 0x{:X}. The SUPER magic carries no checksum, so geometry rests on \
                 the magic and the documented layout",
                generation.label(),
                l.super_offset,
                l.super_size,
                l.unit_stride,
                l.data_block_size
            ),
            "storage_geometry",
            "uniview_geometry",
        ),
    }))
}

/// The platform recording index. `Ok(None)` when the evidence is not Uniview.
pub fn recording_index(volume: &UniviewVolume) -> Result<Option<RecordingIndex>, ForensicError> {
    let Some(generation) = volume.generation() else { return Ok(None) };
    let mut recordings = Vec::new();
    for u in volume.indexed_units() {
        let mut md = BTreeMap::new();
        md.insert("uniview.generation".into(), generation.label().to_string());
        md.insert("uniview.unit".into(), u.unit.to_string());
        md.insert("uniview.unit_base".into(), format!("0x{:X}", u.unit_base));
        md.insert("uniview.di_offset".into(), format!("0x{:X}", u.di_offset));
        if let Some(h) = &u.header {
            md.insert("uniview.di.write_data_bytes".into(), h.write_bytes.to_string());
            md.insert("uniview.di.declared_entries".into(), h.declared_count.to_string());
            md.insert("uniview.di.header_08_0f_hex".into(), hex::encode(h.unknown_08_0f));
        }
        md.insert("uniview.di.header_state".into(), u.header_state.label());
        md.insert("uniview.di.usable_entries".into(), u.usable_entries.to_string());
        md.insert("uniview.di.invalid_timestamps".into(), u.invalid_timestamps.to_string());
        md.insert("uniview.di.timestamp_regressions".into(), u.timestamp_regressions.to_string());
        for (k, v) in &u.span_basis_counts {
            md.insert(format!("uniview.span_basis.{k}"), v.to_string());
        }
        if let Some(t) = &u.earliest {
            md.insert("uniview.earliest_wall_clock".into(), t.wall_clock().unwrap_or_default());
        }
        if let Some(t) = &u.latest {
            md.insert("uniview.latest_wall_clock".into(), t.wall_clock().unwrap_or_default());
        }
        md.insert("uniview.timestamp_timezone".into(), "unknown; wall clock read as UTC".into());
        md.insert("uniview.grouping".into(), GROUPING_NOTE.into());
        md.insert("uniview.channel".into(), "not recorded in any established field".into());
        md.insert("uniview.codec".into(), "UNKNOWN".into());

        let problems = u.has_problems() || u.spans_truncated_by_image > 0;
        recordings.push(IndexedRecording {
            recording_id: u.recording_id(),
            partition: None,
            // Field A is not established as a channel; nothing else records one.
            channel: None,
            start_time_unix: u.earliest.as_ref().and_then(UnvTimestamp::unix_seconds_as_utc),
            end_time_unix: u.latest.as_ref().and_then(UnvTimestamp::unix_seconds_as_utc),
            physical_regions: u.data_regions.clone(),
            // Framing inside DATA is unknown, so no payload sub-range can be separated.
            payload_regions: Vec::new(),
            codec_hint: None,
            allocation: AllocationEvidence::Unknown,
            oem_metadata: md,
            evidence: vs(
                if problems { ValidationStateKind::Review } else { ValidationStateKind::Pass },
                format!(
                    "unit {}: {} usable DI entr(y/ies) -> {} merged DATA region(s), {} byte(s); \
                     spans inferred from adjacent SPtoI{}",
                    u.unit,
                    u.usable_entries,
                    u.data_regions.len(),
                    u.indexed_bytes(),
                    if problems {
                        format!("; anomalies: {}", u.anomalies.join("; "))
                    } else {
                        String::new()
                    }
                ),
                "recording_index",
                "uniview_di",
            ),
        });
    }

    let authority = if volume.units.is_empty() {
        IndexAuthority::NotFound {
            reason: "no Uniview unit is present in the image, so no DI region could be read".into(),
        }
    } else {
        IndexAuthority::Partial {
            reason: PARTIAL_AUTHORITY_REASON.into(),
        }
    };
    // Never `Pass`: a partial index is, by construction, something an examiner must weigh.
    let evidence = vs(
        ValidationStateKind::Review,
        format!(
            "Uniview DI index: {} unit(s) read, {} with usable entries, {} declared / {} usable \
             DI entr(y/ies). {PARTIAL_AUTHORITY_REASON}",
            volume.units.len(),
            recordings.len(),
            volume.declared_entries(),
            volume.usable_entries()
        ),
        "recording_index",
        "uniview_di",
    );

    Ok(Some(RecordingIndex {
        authority,
        recordings,
        unreferenced_recordings: Vec::new(),
        declared_entry_count: usize::try_from(volume.declared_entries()).ok(),
        // DI is distributed: one 256 KiB region at the start of every unit. No single region
        // describes it.
        index_region: None,
        evidence,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merging_regions_is_order_independent_and_joins_touching_ranges() {
        let r = |o, l| Region::new(o, l).unwrap();
        assert_eq!(
            merge_regions(vec![r(100, 10), r(0, 10), r(10, 5), r(105, 20), r(200, 1)]),
            vec![r(0, 15), r(100, 25), r(200, 1)]
        );
        assert!(merge_regions(Vec::new()).is_empty());
    }
}
