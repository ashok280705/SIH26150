//! # Forensic report
//!
//! A serialisable, examiner-facing statement of everything the Uniview structures
//! established, with field-level evidence (physical offset, width, raw bytes, decoded value,
//! confidence) and the platform's known limitations stated explicitly.

use forensic_core::{OemProfile, Region, ValidationState};
use serde::{Deserialize, Serialize};

use crate::field::FieldEvidence;
use crate::layout::{Confidence, Generation};
use crate::recovery::UniviewRecoveryReport;
use crate::ui::{TimeIndexSummary, UiDataArea};
use crate::ui::TimeIndexEntry;
use crate::volume::{UniviewVolume, VendorFlow, PARTIAL_AUTHORITY_REASON};

/// One row per enumerated unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitReportRow {
    pub unit: u32,
    pub recording_id: String,
    pub unit_base: u64,
    pub di_offset: u64,
    pub di_header_state: String,
    pub di_header_fields: Vec<FieldEvidence>,
    pub declared_entries: Option<u32>,
    pub usable_entries: u64,
    pub earliest_wall_clock: Option<String>,
    pub latest_wall_clock: Option<String>,
    pub data_regions: Vec<Region>,
    pub anomalies: Vec<String>,
    pub anomalies_suppressed: u64,
    /// The unit's own 8-byte time-index entry, raw and decoded; lock semantics UNKNOWN.
    pub time_index: Option<TimeIndexEntry>,
    pub time_index_fields: Vec<FieldEvidence>,
}

/// The Uniview forensic report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UniviewForensicReport {
    pub parser_id: String,
    pub parser_version: String,
    pub profile_id: String,
    pub profile_version: String,
    pub source_path: String,
    /// Raw disk image, or a disktool `.h3crd` export (a normalized artifact).
    pub source_kind: String,
    pub image_len: u64,
    pub generation: Option<Generation>,
    pub super_recognition: String,
    pub super_fields: Vec<FieldEvidence>,
    pub ui_region: Option<String>,
    pub ui_fields: Vec<FieldEvidence>,
    pub ui_entries: Option<TimeIndexSummary>,
    pub ui_entries_confidence: Option<Confidence>,
    pub ui_data: Option<UiDataArea>,
    pub current_unit_consistency: Option<String>,
    pub units: Vec<UnitReportRow>,
    /// FLOW as disktool computes it (refused on a rewrited disk).
    pub vendor_flow: VendorFlow,
    /// Filesystem-scan statistic over every unit in the image; NOT the vendor FLOW.
    pub scan_total_write_bytes: u64,
    pub flow_note: String,
    pub index_authority: String,
    pub recovery: Option<UniviewRecoveryReport>,
    pub known_limitations: Vec<String>,
    pub evidence: ValidationState,
}

/// Uniview behaviour the platform has **not** established. Reported in every report.
pub fn known_limitations() -> Vec<String> {
    [
        "each unit's own 8-byte time-index entry is located (OLD UI + (u+1)*8, NEW UI-DATA \
         global index u-1), but no link from a time-index entry to an individual DI entry is \
         established; index groups are per storage unit, not per recording",
        "the meaning of the UI-DATA 26-bit lock / time-index value is unknown; it is not a \
         channel number",
        "the meaning of DI field A (10 bits) is unknown; no channel is derived from it",
        "the codec, container and framing inside DATA blocks are unknown; DATA is extracted as \
         raw bytes and no format is claimed",
        "no deletion structure is known; unreferenced DATA is reported as unreferenced, never as \
         deleted",
        "the rewrited flag indicates a wrapped ring but not which recordings were overwritten",
        "DATA extents are inferred from adjacent SPtoI values; a unit's last entry claims only \
         the block its SPtoI selects",
        "the meaning of the UI / UI-CTL raw current-unit value beyond the vendor's written-unit \
         arithmetic (OLD raw - 1, NEW raw + 1) is not established",
        "the meaning of UI-CTL +0x04 beyond the entry-count arithmetic ((v >> 13) + 1) and the \
         UI-DATA display bound is TENTATIVE",
        "DI header bytes +0x08..+0x0F and DI entry bytes +0x08..+0x0F are UNKNOWN",
        "the .h3crd header constant offset (+0x64) is a strong inference from the export \
         routine's stack layout; .h3crd recognition rests on the header tag",
        "the SUPER, UI and DI structures carry no known checksum",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Build the report from a volume (and optionally a recovery report).
pub fn build_report(
    volume: &UniviewVolume,
    profile: &OemProfile,
    parser_id: &str,
    parser_version: &str,
    recovery: Option<UniviewRecoveryReport>,
) -> UniviewForensicReport {
    let units = volume
        .units
        .iter()
        .map(|u| UnitReportRow {
            unit: u.unit,
            recording_id: u.recording_id(),
            unit_base: u.unit_base,
            di_offset: u.di_offset,
            di_header_state: u.header_state.label(),
            di_header_fields: u.header.as_ref().map(|h| h.fields()).unwrap_or_default(),
            declared_entries: u.header.as_ref().map(|h| h.declared_count),
            usable_entries: u.usable_entries,
            earliest_wall_clock: u.earliest.as_ref().and_then(|t| t.wall_clock()),
            latest_wall_clock: u.latest.as_ref().and_then(|t| t.wall_clock()),
            data_regions: u.data_regions.clone(),
            anomalies: u.anomalies.clone(),
            anomalies_suppressed: u.anomalies_suppressed,
            time_index: u.time_index.clone(),
            time_index_fields: u
                .time_index
                .as_ref()
                .map(|t| t.fields("unit.time_index", Confidence::StrongInference))
                .unwrap_or_default(),
        })
        .collect();

    UniviewForensicReport {
        parser_id: parser_id.to_string(),
        parser_version: parser_version.to_string(),
        profile_id: profile.profile_id.clone(),
        profile_version: profile.profile_version.clone(),
        source_path: volume.source_path.clone(),
        source_kind: volume.source_label().to_string(),
        image_len: volume.image_len,
        generation: volume.generation(),
        super_recognition: volume.super_block.recognition.label(),
        super_fields: volume.super_block.fields(&volume.layout),
        ui_region: volume.ui.as_ref().map(|u| u.region_name().to_string()),
        ui_fields: volume.ui.as_ref().map(|u| u.fields(&volume.layout)).unwrap_or_default(),
        ui_entries: volume.ui.as_ref().map(|u| u.entries.clone()),
        ui_entries_confidence: volume.ui.as_ref().map(|u| u.entries_confidence),
        ui_data: volume.ui_data.clone(),
        current_unit_consistency: volume.current_unit_consistency(),
        units,
        vendor_flow: volume.vendor_flow(),
        scan_total_write_bytes: volume.scan_total_write_bytes(),
        flow_note: "FLOW is not an on-disk region. vendor_flow reproduces disktool: the sum of DI \
                    +0x00 over the UI-declared units (OLD raw - 1, NEW raw + 1), refused on a \
                    rewrited disk. scan_total_write_bytes sums every unit found in the image and \
                    is a filesystem-scan statistic only"
            .into(),
        index_authority: format!("PARTIAL: {PARTIAL_AUTHORITY_REASON}"),
        recovery,
        known_limitations: known_limitations(),
        evidence: volume.evidence.clone(),
    }
}
