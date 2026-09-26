//! # The composed Dahua volume model
//!
//! This module is the OEM/generic boundary. It walks the whole DHFS 4.1 structure set and
//! emits only [`StorageGeometry`] and [`RecordingIndex`] — physical byte ranges plus
//! explicitly-optional metadata — so the recovery engine never learns what DHFS, DHII or
//! DHAV mean.
//!
//! ```text
//!   signature → partition table → partition info → block table → chains
//!                                                                  │
//!                                            ┌─────────────────────┴──────────────────┐
//!                                            ▼                                        ▼
//!                           RecordingIndex::recordings            RecordingIndex::unreferenced
//!                              (accessible)                          (available / orphaned)
//! ```
//!
//! ## Accessible versus available
//!
//! A chain is **accessible** when all three hold:
//!
//! 1. it was reached by traversing from a block that declares itself a recording's first block;
//! 2. the traversal completed at a terminator;
//! 3. the volume carries exactly one verified partition table.
//!
//! Everything else whose metadata survives is **available**: unreachable block groups,
//! chains whose traversal broke, and — because the volume's partitioning has changed —
//! every chain on a volume with a secondary partition table.
//!
//! Available is not deleted. The block table's empty marker does not distinguish "never
//! written" from "freed", so [`AllocationEvidence`] stays `Unknown` and no entry here can
//! produce a `Deleted` finding downstream.
//!
//! ## Fallback, not substitute
//!
//! When the volume is not a recognised DHFS 4.1, [`read_volume`] falls back to the
//! provisional flat-superblock + `DIDX` model in [`crate::dhfs`] — but only if a `DIDX`
//! header actually verifies, and the fallback is named in the evidence so it is never
//! mistaken for the real filesystem.

use std::collections::BTreeMap;

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, OemProfile, Region, ValidationState, ValidationStateKind};
use parsers_core::storage::{
    AllocationEvidence, CircularBufferEvidence, IndexAuthority, IndexedRecording, RecordingIndex,
    StorageGeometry,
};
use serde::{Deserialize, Serialize};

use crate::block_table::{read_block_map, BlockMap};
use crate::chain::{build_chains, ChainOrigin, RecordingChain};
use crate::layout::{key, u64_from, vs};
use crate::partition::{read_partition_tables, PartitionTableSet};
use crate::superblock::{self, DhfsRecognition, VolumeDescriptors};

/// Which structural model was used to interpret the volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VolumeModel {
    /// The DHFS 4.1 partition/block-table model.
    Dhfs41,
    /// The provisional flat-superblock + `DIDX` model, used because DHFS 4.1 structures
    /// were not found but a `DIDX` header verified.
    FlatDidxFallback { reason: String },
    /// Neither model applies. No geometry or index is claimed.
    NotApplicable { reason: String },
}

impl VolumeModel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Dhfs41 => "dhfs-4.1-partitioned",
            Self::FlatDidxFallback { .. } => "flat-didx-fallback",
            Self::NotApplicable { .. } => "not-applicable",
        }
    }
}

/// Whether a chain is part of the recorder's current accessible recording set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainAccessibility {
    /// Reached from a declared first block, traversed to a terminator, on a volume with a
    /// single verified partition table.
    Accessible,
    /// The metadata survives and describes real bytes, but the recorder does not reach the
    /// recording through its current structures.
    ///
    /// This is **not** a deletion finding.
    Available { reason: String },
}

impl ChainAccessibility {
    pub fn is_accessible(&self) -> bool {
        matches!(self, Self::Accessible)
    }
}

/// One chain plus its accessibility verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassifiedChain {
    pub chain: RecordingChain,
    pub accessibility: ChainAccessibility,
}

/// The fully walked Dahua volume.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DahuaVolume {
    /// Byte length of the evidence the volume was read from.
    pub physical_size: u64,
    pub recognition: DhfsRecognition,
    pub descriptors: VolumeDescriptors,
    pub model: VolumeModel,
    /// Partition tables found, when the DHFS 4.1 model applied.
    pub partition_tables: Option<PartitionTableSet>,
    /// One block map per usable partition.
    pub block_maps: Vec<BlockMap>,
    /// Every chain found, with its accessibility verdict.
    pub chains: Vec<ClassifiedChain>,
    pub evidence: ValidationState,
}

impl DahuaVolume {
    /// Chains the recorder currently reaches.
    pub fn accessible_chains(&self) -> impl Iterator<Item = &ClassifiedChain> {
        self.chains
            .iter()
            .filter(|c| c.accessibility.is_accessible())
    }

    /// Chains whose metadata survives but which the recorder does not reach.
    pub fn available_chains(&self) -> impl Iterator<Item = &ClassifiedChain> {
        self.chains
            .iter()
            .filter(|c| !c.accessibility.is_accessible())
    }

    /// Whether the DHFS 4.1 structure set was used.
    pub fn is_dhfs41(&self) -> bool {
        self.model == VolumeModel::Dhfs41
    }

    /// The span the volume's video blocks occupy, across all partitions.
    ///
    /// A span rather than a set: [`StorageGeometry`] carries one video region, and the
    /// per-partition detail travels in `oem_fields` so nothing is lost.
    pub fn video_span(&self) -> Option<Region> {
        let mut min = u64::MAX;
        let mut max = 0u64;
        for p in self
            .partition_tables
            .as_ref()
            .map(|s| s.partitions())
            .unwrap_or_default()
        {
            if let Some(r) = p.video_region {
                min = min.min(r.offset);
                max = max.max(r.end().unwrap_or(u64::MAX));
            }
        }
        if min == u64::MAX || max <= min {
            return None;
        }
        Region::new(min, max - min).ok()
    }

    /// The span the volume's block tables occupy, across all partitions.
    pub fn index_span(&self) -> Option<Region> {
        let mut min = u64::MAX;
        let mut max = 0u64;
        for p in self
            .partition_tables
            .as_ref()
            .map(|s| s.partitions())
            .unwrap_or_default()
        {
            if let Some(r) = p.block_table_region {
                min = min.min(r.offset);
                max = max.max(r.end().unwrap_or(u64::MAX));
            }
        }
        if min == u64::MAX || max <= min {
            return None;
        }
        Region::new(min, max - min).ok()
    }
}

/// Walk a Dahua volume end to end.
///
/// Never fails on a non-Dahua or damaged volume: those are findings, recorded in
/// [`DahuaVolume::model`] and [`DahuaVolume::evidence`]. Only genuine I/O errors propagate.
pub fn read_volume(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
) -> Result<DahuaVolume, ForensicError> {
    const OP: &str = "dahua_volume";
    const SUBJECT: &str = "volume";

    let physical_size = reader.len();
    let recognition = superblock::recognize(reader, profile)?;
    let descriptors = superblock::read_descriptors(reader, profile);

    // A volume that is not a recognised DHFS 4.1 does not get its structures interpreted as
    // if it were. The flat fallback is attempted only because some volumes in this
    // platform's corpus present it, and it announces itself as a fallback.
    if !recognition.is_dhfs41() {
        let reason = match &recognition {
            DhfsRecognition::UnsupportedVariant { version_label, .. } => format!(
                "the volume declares DHFS version '{version_label}', for which no partition-table \
                 layout is established; the DHFS 4.1 structure set was not applied"
            ),
            DhfsRecognition::Malformed { reason, .. } => format!(
                "the volume header is malformed ({reason}); the DHFS 4.1 structure set was not \
                 applied"
            ),
            DhfsRecognition::NotDhfs { reason } => reason.clone(),
            DhfsRecognition::Dhfs41 { .. } => unreachable!("handled below"),
        };
        return Ok(DahuaVolume {
            physical_size,
            recognition: recognition.clone(),
            descriptors,
            model: VolumeModel::NotApplicable {
                reason: reason.clone(),
            },
            partition_tables: None,
            block_maps: Vec::new(),
            chains: Vec::new(),
            evidence: vs(
                match recognition {
                    DhfsRecognition::NotDhfs { .. } => ValidationStateKind::Unknown,
                    _ => ValidationStateKind::Review,
                },
                reason,
                OP,
                SUBJECT,
            ),
        });
    }

    // ── DHFS 4.1 ────────────────────────────────────────────────────────────
    let tables = read_partition_tables(reader, profile)?;
    let downgrade = tables.downgrade_accessible_to_available;

    // No partition table verified. Before giving up, check whether this volume presents the
    // provisional flat structures instead — some in this platform's corpus do. The fallback is
    // gated on a `DIDX` header actually verifying, so it can never be entered speculatively,
    // and it names itself in the evidence so it is not mistaken for the real filesystem.
    if tables.used.is_none() && crate::dhfs::didx_header_verifies(reader, profile)? {
        let reason = format!(
            "the volume carries the DHFS 4.1 signature but no partition table verified at any \
             declared candidate offset, while a DIDX header did verify at the flat \
             superblock-declared offset. The provisional flat model was used instead; it is not the \
             DHFS 4.1 structure set. Partition table probe: {}",
            tables.probe_log.join(" | ")
        );
        return Ok(DahuaVolume {
            physical_size,
            recognition,
            descriptors,
            model: VolumeModel::FlatDidxFallback {
                reason: reason.clone(),
            },
            partition_tables: Some(tables),
            block_maps: Vec::new(),
            chains: Vec::new(),
            evidence: vs(ValidationStateKind::Review, reason, OP, SUBJECT),
        });
    }

    let mut block_maps: Vec<BlockMap> = Vec::new();
    for partition in tables.partitions() {
        let (Some(table_offset), Some(video_base), Some(block_count)) = (
            partition.block_table_offset,
            partition.video_base_offset,
            partition.block_count,
        ) else {
            continue;
        };
        block_maps.push(read_block_map(
            reader,
            profile,
            partition.number,
            table_offset,
            video_base,
            block_count,
        )?);
    }

    let mut chains: Vec<ClassifiedChain> = Vec::new();
    for map in &block_maps {
        for chain in build_chains(map, profile) {
            let accessibility = classify_accessibility(&chain, downgrade, &tables);
            chains.push(ClassifiedChain {
                chain,
                accessibility,
            });
        }
    }

    let accessible = chains
        .iter()
        .filter(|c| c.accessibility.is_accessible())
        .count();
    let available = chains.len() - accessible;
    let table_truncated = block_maps
        .iter()
        .any(|m| m.evidence.state != ValidationStateKind::Pass);

    let mut reason = format!(
        "DHFS 4.1 volume of {physical_size} byte(s): {} partition table(s) verified, {} partition(s) \
         with usable geometry, {} block table(s) read, {} chain(s) reconstructed ({accessible} \
         accessible, {available} available). {}",
        tables.all_tables().len(),
        tables.partitions().iter().filter(|p| p.is_usable()).count(),
        block_maps.len(),
        chains.len(),
        tables.evidence.reason
    );
    if downgrade {
        reason.push_str(
            " Every chain is reported as available for that reason; availability is not evidence of \
             deletion.",
        );
    }
    if table_truncated {
        reason.push_str(" At least one block table was incomplete; see its own evidence.");
    }

    Ok(DahuaVolume {
        physical_size,
        recognition,
        descriptors,
        model: VolumeModel::Dhfs41,
        partition_tables: Some(tables),
        block_maps,
        chains,
        evidence: vs(
            if downgrade || table_truncated || available > 0 {
                ValidationStateKind::Review
            } else {
                ValidationStateKind::Pass
            },
            reason,
            OP,
            SUBJECT,
        ),
    })
}

/// Decide whether a chain is accessible or available.
fn classify_accessibility(
    chain: &RecordingChain,
    downgrade: bool,
    tables: &PartitionTableSet,
) -> ChainAccessibility {
    if downgrade {
        return ChainAccessibility::Available {
            reason: format!(
                "the chain was reached through partition metadata, but {} Availability describes \
                 whether the recorder still reaches the recording; it is not evidence of deletion.",
                tables.downgrade_reason
            ),
        };
    }
    if chain.origin == ChainOrigin::UnreachableBlockGroup {
        return ChainAccessibility::Available {
            reason: chain
                .validity
                .reason()
                .unwrap_or("no traversal from a declared first block reached these blocks")
                .to_string(),
        };
    }
    if !chain.validity.is_complete() {
        return ChainAccessibility::Available {
            reason: format!(
                "traversal from the declared first block did not complete ({}): {}. The blocks that \
                 were reached remain physically present and recoverable; this is not evidence of \
                 deletion.",
                chain.validity.label(),
                chain.validity.reason().unwrap_or("no terminator was reached")
            ),
        };
    }
    ChainAccessibility::Accessible
}

/// Derive [`StorageGeometry`] from a walked volume.
///
/// Returns `None` only when neither structural model applied, which is the honest answer:
/// the recovery engine then degrades to an unindexed sweep.
pub fn storage_geometry(
    volume: &DahuaVolume,
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
) -> Result<Option<StorageGeometry>, ForensicError> {
    match &volume.model {
        VolumeModel::Dhfs41 => {}
        VolumeModel::FlatDidxFallback { .. } => {
            return crate::dhfs::read_storage_geometry(reader, profile)
        }
        VolumeModel::NotApplicable { .. } => return Ok(None),
    }

    let mut oem_fields: BTreeMap<String, String> = BTreeMap::new();
    oem_fields.insert("dhfs_variant".into(), "DHFS4.1".into());
    oem_fields.insert("structural_model".into(), volume.model.label().into());
    if let Some(v) = &volume.descriptors.model {
        oem_fields.insert("model".into(), v.clone());
    }
    if let Some(v) = &volume.descriptors.serial {
        oem_fields.insert("serial".into(), v.clone());
    }
    if let Some(v) = &volume.descriptors.volume_label {
        oem_fields.insert("volume_label".into(), v.clone());
    }

    if let Some(tables) = &volume.partition_tables {
        oem_fields.insert(
            "partition_table_count".into(),
            tables.all_tables().len().to_string(),
        );
        if let Some(used) = &tables.used {
            oem_fields.insert("partition_table_role".into(), used.role.label().into());
            oem_fields.insert(
                "partition_table_offset".into(),
                format!("0x{:X}", used.offset),
            );
        }
        oem_fields.insert(
            "secondary_partition_table_present".into(),
            tables.downgrade_accessible_to_available.to_string(),
        );
        if tables.downgrade_accessible_to_available {
            oem_fields.insert(
                "accessibility_downgrade_reason".into(),
                tables.downgrade_reason.clone(),
            );
        }
        oem_fields.insert(
            "partition_count".into(),
            tables.partitions().len().to_string(),
        );
        // Per-partition geometry, so collapsing the regions into one span loses nothing.
        for p in tables.partitions() {
            let n = p.number;
            oem_fields.insert(
                format!("partition{n}_start_sector"),
                p.entry.start_sector.to_string(),
            );
            if let Some(info) = p.info {
                oem_fields.insert(
                    format!("partition{n}_index_start_sector"),
                    info.index_start_sector.to_string(),
                );
                oem_fields.insert(
                    format!("partition{n}_video_start_sector"),
                    info.video_start_sector.to_string(),
                );
                oem_fields.insert(
                    format!("partition{n}_declared_block_count"),
                    info.block_count.to_string(),
                );
            }
            if let Some(r) = p.block_table_region {
                oem_fields.insert(
                    format!("partition{n}_block_table_region"),
                    format!("{}:{}", r.offset, r.length),
                );
            }
            if let Some(r) = p.video_region {
                oem_fields.insert(
                    format!("partition{n}_video_region"),
                    format!("{}:{}", r.offset, r.length),
                );
            }
            oem_fields.insert(format!("partition{n}_evidence"), p.evidence.reason.clone());
        }
    }
    for map in &volume.block_maps {
        oem_fields.insert(
            format!("partition{}_block_slots", map.partition),
            format!(
                "{} occupied, {} empty, {} malformed",
                map.occupied_count, map.empty_count, map.malformed_count
            ),
        );
    }
    oem_fields.insert(
        "chain_counts".into(),
        format!(
            "{} accessible, {} available",
            volume.accessible_chains().count(),
            volume.available_chains().count()
        ),
    );

    let video_region = volume.video_span();
    let index_region = volume.index_span();
    let metadata_region = volume
        .recognition
        .signature_region()
        .or_else(|| Region::new(0, u64_from(profile, key::SUPERBLOCK_SIZE, 512)).ok())
        .filter(|r| r.end().unwrap_or(u64::MAX) <= volume.physical_size);

    let evidence = if video_region.is_some() && index_region.is_some() {
        vs(
            ValidationStateKind::Pass,
            format!(
                "DHFS 4.1 geometry derived from the partition table: video span {}, block table span \
                 {}, block size {}, sector size {}. {}",
                video_region.map(|r| r.to_string()).unwrap_or_default(),
                index_region.map(|r| r.to_string()).unwrap_or_default(),
                u64_from(profile, key::VIDEO_BLOCK_SIZE, 2 * 1024 * 1024),
                u64_from(profile, key::SECTOR_SIZE, 512),
                volume.evidence.reason
            ),
            "dahua_storage_geometry",
            "dhfs41_geometry",
        )
    } else {
        vs(
            ValidationStateKind::Review,
            format!(
                "DHFS 4.1 volume recognised but its partition geometry could not be fully resolved, \
                 so the video and/or block-table span is unknown. {}",
                volume.evidence.reason
            ),
            "dahua_storage_geometry",
            "dhfs41_geometry",
        )
    };

    Ok(Some(StorageGeometry {
        physical_size: volume.physical_size,
        video_region,
        index_region,
        metadata_region,
        block_size: Some(u64_from(profile, key::VIDEO_BLOCK_SIZE, 2 * 1024 * 1024)),
        sector_size: Some(u64_from(profile, key::SECTOR_SIZE, 512)),
        // DHFS 4.1 block tables carry no write cursor or wrap flag. Reporting anything but
        // Unknown here would be fabrication, even though these recorders do overwrite.
        circular_buffer: CircularBufferEvidence::Unknown,
        oem_fields,
        evidence,
    }))
}

/// Derive [`RecordingIndex`] from a walked volume.
pub fn recording_index(
    volume: &DahuaVolume,
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
) -> Result<Option<RecordingIndex>, ForensicError> {
    match &volume.model {
        VolumeModel::Dhfs41 => {}
        VolumeModel::FlatDidxFallback { .. } => {
            return crate::dhfs::read_recording_index(reader, profile)
        }
        VolumeModel::NotApplicable { reason } => {
            return Ok(Some(RecordingIndex {
                authority: IndexAuthority::NotFound {
                    reason: reason.clone(),
                },
                recordings: Vec::new(),
                unreferenced_recordings: Vec::new(),
                declared_entry_count: None,
                index_region: None,
                evidence: vs(
                    ValidationStateKind::Unknown,
                    format!("no Dahua recording metadata was read: {reason}"),
                    "dahua_recording_index",
                    "dhfs41_index",
                ),
            }))
        }
    }

    let mut recordings: Vec<IndexedRecording> = Vec::new();
    let mut unreferenced: Vec<IndexedRecording> = Vec::new();
    for classified in &volume.chains {
        let entry = chain_to_indexed_recording(classified);
        if classified.accessibility.is_accessible() {
            recordings.push(entry);
        } else {
            unreferenced.push(entry);
        }
    }

    let declared_blocks: usize = volume.block_maps.iter().map(|m| m.entries.len()).sum();

    // ── Authority ───────────────────────────────────────────────────────────
    // The block table describes every block in its partition, so a completely read block
    // table is a complete statement about that partition's video region: absence from it is
    // meaningful, which is what licenses an orphan finding. A truncated or unreadable table
    // is not, so absence proves nothing there.
    let all_tables_clean = !volume.block_maps.is_empty()
        && volume
            .block_maps
            .iter()
            .all(|m| m.evidence.state == ValidationStateKind::Pass);
    let governs = volume.video_span();

    let (authority, evidence) = match (all_tables_clean, governs) {
        (true, Some(span)) => {
            let reason = format!(
                "DHFS 4.1 block tables fully read across {} partition(s), describing {declared_blocks} \
                 block(s) and {} chain(s); authoritative over the video span {span}. {} accessible \
                 recording(s), {} available. {}",
                volume.block_maps.len(),
                volume.chains.len(),
                recordings.len(),
                unreferenced.len(),
                volume.evidence.reason
            );
            (
                IndexAuthority::Authoritative { governs: span },
                vs(
                    if unreferenced.is_empty() {
                        ValidationStateKind::Pass
                    } else {
                        ValidationStateKind::Review
                    },
                    reason,
                    "dahua_recording_index",
                    "dhfs41_index",
                ),
            )
        }
        _ => {
            let reason =
                format!(
                "DHFS 4.1 block metadata was only partially established ({} block table(s), {} \
                 clean, video span {}), so absence from it is not evidence of absence. {}",
                volume.block_maps.len(),
                volume
                    .block_maps
                    .iter()
                    .filter(|m| m.evidence.state == ValidationStateKind::Pass)
                    .count(),
                governs.map(|r| r.to_string()).unwrap_or_else(|| "unknown".into()),
                volume.evidence.reason
            );
            (
                IndexAuthority::Partial {
                    reason: reason.clone(),
                },
                vs(
                    ValidationStateKind::Review,
                    reason,
                    "dahua_recording_index",
                    "dhfs41_index",
                ),
            )
        }
    };

    Ok(Some(RecordingIndex {
        authority,
        recordings,
        unreferenced_recordings: unreferenced,
        declared_entry_count: Some(declared_blocks),
        index_region: volume.index_span(),
        evidence,
    }))
}

/// Normalize one classified chain into an OEM-neutral index entry.
fn chain_to_indexed_recording(classified: &ClassifiedChain) -> IndexedRecording {
    let chain = &classified.chain;
    let mut meta: BTreeMap<String, String> = BTreeMap::new();
    meta.insert("dahua_structural_model".into(), "DHFS4.1".into());
    meta.insert("dahua_chain_id".into(), chain.chain_id.clone());
    meta.insert("dahua_partition".into(), chain.partition.to_string());
    meta.insert("dahua_head_block".into(), chain.head_block.to_string());
    meta.insert("dahua_block_count".into(), chain.blocks.len().to_string());
    meta.insert(
        "dahua_block_numbers".into(),
        chain
            .blocks
            .iter()
            .map(|b| b.block_number.to_string())
            .collect::<Vec<_>>()
            .join(","),
    );
    meta.insert(
        "dahua_block_table_entry_offsets".into(),
        chain
            .blocks
            .iter()
            .map(|b| format!("0x{:X}", b.entry_offset))
            .collect::<Vec<_>>()
            .join(","),
    );
    meta.insert("dahua_chain_validity".into(), chain.validity.label().into());
    if let Some(r) = chain.validity.reason() {
        meta.insert("dahua_chain_validity_reason".into(), r.to_string());
    }
    meta.insert("dahua_chain_ordering".into(), chain.ordering.label().into());
    meta.insert(
        "dahua_chain_origin".into(),
        match chain.origin {
            ChainOrigin::FirstBlockTraversal => "first-block-traversal".into(),
            ChainOrigin::UnreachableBlockGroup => "unreachable-block-group".into(),
        },
    );
    meta.insert(
        "dahua_physically_contiguous".into(),
        chain.is_physically_contiguous().to_string(),
    );
    meta.insert(
        "dahua_channel_encoding".into(),
        chain.channel.encoding.label().into(),
    );
    meta.insert(
        "dahua_channel_raw_value".into(),
        chain.channel.raw_value.to_string(),
    );
    meta.insert(
        "dahua_channel_evidence".into(),
        chain.channel.evidence.clone(),
    );
    if let Some(t) = &chain.start_time {
        meta.insert(
            "dahua_start_timestamp_raw".into(),
            format!("0x{:08X}", t.raw),
        );
        meta.insert("dahua_start_timestamp_evidence".into(), t.evidence.clone());
        if let Some(w) = &t.recorder_wall_clock {
            meta.insert("dahua_start_recorder_wall_clock".into(), w.clone());
        }
    }
    if let Some(t) = &chain.end_time {
        meta.insert("dahua_end_timestamp_raw".into(), format!("0x{:08X}", t.raw));
        meta.insert("dahua_end_timestamp_evidence".into(), t.evidence.clone());
        if let Some(w) = &t.recorder_wall_clock {
            meta.insert("dahua_end_recorder_wall_clock".into(), w.clone());
        }
    }
    if !chain.channel_disagreements.is_empty() {
        meta.insert(
            "dahua_channel_disagreements".into(),
            chain.channel_disagreements.join("; "),
        );
    }
    match &classified.accessibility {
        ChainAccessibility::Accessible => {
            meta.insert("dahua_accessibility".into(), "accessible".into());
        }
        ChainAccessibility::Available { reason } => {
            meta.insert("dahua_accessibility".into(), "available".into());
            meta.insert("dahua_availability_reason".into(), reason.clone());
        }
    }
    // Stated explicitly so no consumer has to infer it from silence.
    meta.insert(
        "dahua_deletion_evidence".into(),
        "none: the DHFS 4.1 block table carries no free/deallocated marker that distinguishes an \
         unwritten slot from a freed one, so no deletion conclusion is available from this structure"
            .into(),
    );
    meta.insert(
        "dahua_payload_regions_note".into(),
        "empty by design: a 2 MiB video block holds many DHAV frames, so there is no single payload \
         sub-range per block. Frame-accurate payload ranges come from reconstruct_chain, which walks \
         the block's DHII index and DHAV framing"
            .into(),
    );

    IndexedRecording {
        recording_id: chain.chain_id.clone(),
        partition: Some(chain.partition),
        channel: Some(chain.channel.normalized),
        start_time_unix: chain.start_time.as_ref().and_then(|t| t.unix_seconds),
        end_time_unix: chain.end_time.as_ref().and_then(|t| t.unix_seconds),
        physical_regions: chain.regions(),
        // See `dahua_payload_regions_note` above.
        payload_regions: Vec::new(),
        // The block table carries no codec label; the DHAV frame header does, and reading it
        // is the frame walker's job.
        codec_hint: None,
        // DHFS 4.1 has no per-block tombstone, so no allocation state can be asserted.
        allocation: AllocationEvidence::Unknown,
        oem_metadata: meta,
        evidence: chain.evidence.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_table::builder::EntryBuilder;
    use crate::layout::tests_support::dahua_profile;
    use crate::testing::MemReader;

    const SECTOR: u64 = 512;
    const PRIMARY: u64 = 0x3C00;
    const SECONDARY: u64 = 0x3E00;
    const BLOCK: u64 = 2 * 1024 * 1024;
    const START_SECTOR: i64 = 128;
    const INFO_SECTOR: i32 = 1;
    const INDEX_SECTOR: i32 = 2;
    const VIDEO_SECTOR: i32 = 64;

    fn base() -> u64 {
        START_SECTOR as u64 * SECTOR
    }

    /// Build a one-partition DHFS 4.1 volume carrying `entries` as its block table.
    fn volume_bytes(entries: &[[u8; 32]], secondary_table: bool) -> Vec<u8> {
        let b0 = base();
        let video_base = b0 + VIDEO_SECTOR as u64 * SECTOR;
        let total = (video_base + entries.len() as u64 * BLOCK) as usize;
        let mut b = vec![0u8; total];
        b[..8].copy_from_slice(b"DHFS4.1\0");
        b[48..48 + 13].copy_from_slice(b"DHI-XVR5216AN");
        b[96..96 + 12].copy_from_slice(b"DVR_REC_VOL0");

        let write_table = |b: &mut Vec<u8>, at: u64, id: &[u8]| {
            let a = at as usize;
            b[a + 304..a + 312].copy_from_slice(id);
            b[a + 20..a + 24].copy_from_slice(&INFO_SECTOR.to_le_bytes());
            b[a + 48..a + 56].copy_from_slice(&START_SECTOR.to_le_bytes());
        };
        write_table(&mut b, PRIMARY, &[0x01, 0, 0, 0, 0xAA, 0x55, 0xAA, 0x55]);
        if secondary_table {
            write_table(&mut b, SECONDARY, &[0x00, 0, 0, 0, 0xAA, 0x55, 0xAA, 0x55]);
        }

        let info_at = (b0 + INFO_SECTOR as u64 * SECTOR) as usize;
        b[info_at + 68..info_at + 72].copy_from_slice(&INDEX_SECTOR.to_le_bytes());
        b[info_at + 72..info_at + 76].copy_from_slice(&VIDEO_SECTOR.to_le_bytes());
        b[info_at + 76..info_at + 80].copy_from_slice(&(entries.len() as i32).to_le_bytes());

        let table_at = (b0 + INDEX_SECTOR as u64 * SECTOR) as usize;
        for (i, e) in entries.iter().enumerate() {
            let at = table_at + i * 32;
            b[at..at + 32].copy_from_slice(e);
        }
        b
    }

    /// Two accessible-shaped chains: blocks 1→2 on channel 1, block 3 on channel 2.
    fn two_chains() -> Vec<[u8; 32]> {
        vec![
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .legacy_channel(1)
                .first_block(1)
                .next_block(2)
                .start_time(2026, 9, 22, 8, 0, 0)
                .end_time(2026, 9, 22, 8, 5, 0)
                .build(),
            EntryBuilder::occupied()
                .legacy_channel(1)
                .first_block(1)
                .previous_block(1)
                .next_block(0)
                .sector_count(512)
                .start_time(2026, 9, 22, 8, 5, 0)
                .end_time(2026, 9, 22, 8, 10, 0)
                .build(),
            EntryBuilder::occupied()
                .legacy_channel(2)
                .first_block(3)
                .next_block(0)
                .sector_count(256)
                .start_time(2026, 9, 22, 9, 0, 0)
                .end_time(2026, 9, 22, 9, 3, 0)
                .build(),
        ]
    }

    fn read(entries: &[[u8; 32]], secondary: bool) -> (MemReader, DahuaVolume) {
        let p = dahua_profile();
        let r = MemReader::new(volume_bytes(entries, secondary));
        let v = read_volume(&r, &p).unwrap();
        (r, v)
    }

    #[test]
    fn a_dhfs41_volume_is_walked_end_to_end() {
        let (_r, v) = read(&two_chains(), false);
        assert!(v.is_dhfs41());
        assert_eq!(v.model, VolumeModel::Dhfs41);
        assert_eq!(v.descriptors.model.as_deref(), Some("DHI-XVR5216AN"));
        assert_eq!(v.block_maps.len(), 1);
        assert_eq!(v.chains.len(), 2);
        assert_eq!(v.accessible_chains().count(), 2);
        assert_eq!(v.available_chains().count(), 0);
    }

    #[test]
    fn geometry_comes_from_the_partition_table_not_from_superblock_fields() {
        let p = dahua_profile();
        let (r, v) = read(&two_chains(), false);
        let g = storage_geometry(&v, &r, &p).unwrap().expect("geometry");

        let b0 = base();
        assert_eq!(g.physical_size, r.len());
        assert_eq!(g.block_size, Some(BLOCK));
        assert_eq!(g.sector_size, Some(SECTOR));
        assert_eq!(
            g.index_region.map(|x| x.offset),
            Some(b0 + INDEX_SECTOR as u64 * SECTOR),
            "block table located via IndexStartSector"
        );
        assert_eq!(
            g.video_region.map(|x| x.offset),
            Some(b0 + VIDEO_SECTOR as u64 * SECTOR),
            "video region located via VideoStartSector"
        );
        assert_eq!(g.video_region.map(|x| x.length), Some(4 * BLOCK));
        assert_eq!(g.circular_buffer, CircularBufferEvidence::Unknown);
        assert_eq!(g.evidence.state, ValidationStateKind::Pass);
        // Per-partition geometry survives the collapse into one span.
        assert_eq!(
            g.oem_fields.get("dhfs_variant").map(|s| s.as_str()),
            Some("DHFS4.1")
        );
        assert_eq!(
            g.oem_fields.get("partition_count").map(|s| s.as_str()),
            Some("1")
        );
        assert!(g.oem_fields.contains_key("partition0_video_region"));
        assert!(g.oem_fields.contains_key("partition0_index_start_sector"));
    }

    #[test]
    fn accessible_chains_become_index_entries_with_partition_and_block_provenance() {
        let p = dahua_profile();
        let (r, v) = read(&two_chains(), false);
        let idx = recording_index(&v, &r, &p).unwrap().expect("index");

        assert!(idx.authority.is_authoritative());
        assert_eq!(idx.recordings.len(), 2);
        assert!(idx.unreferenced_recordings.is_empty());

        let first = &idx.recordings[0];
        assert_eq!(first.recording_id, "dahua:p0:blk1");
        assert_eq!(first.partition, Some(0));
        assert_eq!(first.channel, Some(1));
        assert_eq!(first.physical_regions.len(), 2, "a two-block recording");
        assert_eq!(first.allocation, AllocationEvidence::Unknown);
        assert_eq!(
            first
                .oem_metadata
                .get("dahua_block_numbers")
                .map(|s| s.as_str()),
            Some("1,2")
        );
        assert_eq!(
            first
                .oem_metadata
                .get("dahua_accessibility")
                .map(|s| s.as_str()),
            Some("accessible")
        );
        assert!(first
            .oem_metadata
            .contains_key("dahua_block_table_entry_offsets"));
        assert!(first
            .oem_metadata
            .get("dahua_deletion_evidence")
            .unwrap()
            .contains("no deletion conclusion"));
        // The recorder's own clock reached the entry, decoded not assumed.
        assert!(first.start_time_unix.is_some());
        assert!(first.end_time_unix.is_some());
    }

    #[test]
    fn claimed_regions_are_the_exact_block_extents() {
        let p = dahua_profile();
        let (r, v) = read(&two_chains(), false);
        let idx = recording_index(&v, &r, &p).unwrap().unwrap();
        let video_base = base() + VIDEO_SECTOR as u64 * SECTOR;

        let regions = idx.claimed_regions();
        assert_eq!(
            regions,
            vec![
                // Block 1: full, because it is not the last block of its chain.
                Region::new(video_base + BLOCK, BLOCK).unwrap(),
                // Block 2: last block, sectorCount 512 -> 256 KiB.
                Region::new(video_base + 2 * BLOCK, 512 * SECTOR).unwrap(),
                // Block 3: its own one-block chain, sectorCount 256 -> 128 KiB.
                Region::new(video_base + 3 * BLOCK, 256 * SECTOR).unwrap(),
            ]
        );
    }

    #[test]
    fn an_unreachable_block_becomes_an_available_entry_never_a_deleted_one() {
        let mut entries = two_chains();
        // Block 3 keeps its metadata but stops declaring itself a first block, so no
        // traversal reaches it.
        entries[3] = EntryBuilder::occupied()
            .legacy_channel(2)
            .previous_block(7)
            .next_block(0)
            .sector_count(256)
            .start_time(2026, 9, 22, 9, 0, 0)
            .end_time(2026, 9, 22, 9, 3, 0)
            .build();

        let p = dahua_profile();
        let (r, v) = read(&entries, false);
        let idx = recording_index(&v, &r, &p).unwrap().unwrap();

        assert_eq!(
            idx.recordings.len(),
            1,
            "only the traversable chain is accessible"
        );
        assert_eq!(idx.unreferenced_recordings.len(), 1);
        let avail = &idx.unreferenced_recordings[0];
        assert_eq!(avail.channel, Some(2));
        assert_eq!(
            avail
                .oem_metadata
                .get("dahua_accessibility")
                .map(|s| s.as_str()),
            Some("available")
        );
        assert!(avail
            .oem_metadata
            .get("dahua_availability_reason")
            .unwrap()
            .contains("not evidence of deletion"));
        assert_eq!(
            avail.allocation,
            AllocationEvidence::Unknown,
            "no allocation state may be asserted, so nothing downstream can call it deleted"
        );
        // Its bytes are still described exactly.
        assert_eq!(avail.physical_regions.len(), 1);
        // The authoritative index still governs, which is what licenses an orphan finding.
        assert!(idx.authority.is_authoritative());
    }

    #[test]
    fn a_secondary_partition_table_downgrades_every_chain_to_available() {
        let p = dahua_profile();
        let (r, v) = read(&two_chains(), true);
        let idx = recording_index(&v, &r, &p).unwrap().unwrap();

        assert!(
            idx.recordings.is_empty(),
            "nothing is accessible when the partitioning has changed"
        );
        assert_eq!(idx.unreferenced_recordings.len(), 2);
        for e in &idx.unreferenced_recordings {
            let reason = e.oem_metadata.get("dahua_availability_reason").unwrap();
            assert!(reason.contains("available rather than accessible"));
            assert!(reason.contains("not evidence of deletion"));
        }
        // Authority is unaffected: the block tables were still read completely.
        assert!(idx.authority.is_authoritative());

        let g = storage_geometry(&v, &r, &p).unwrap().unwrap();
        assert_eq!(
            g.oem_fields
                .get("secondary_partition_table_present")
                .map(|s| s.as_str()),
            Some("true")
        );
        assert!(g.oem_fields.contains_key("accessibility_downgrade_reason"));
    }

    #[test]
    fn a_broken_chain_is_available_and_keeps_the_blocks_it_reached() {
        let mut entries = two_chains();
        // Block 1 points at block 9, which does not exist.
        entries[1] = EntryBuilder::occupied()
            .legacy_channel(1)
            .first_block(1)
            .next_block(9)
            .build();

        let p = dahua_profile();
        let (r, v) = read(&entries, false);
        let idx = recording_index(&v, &r, &p).unwrap().unwrap();

        let broken = idx
            .unreferenced_recordings
            .iter()
            .find(|e| e.recording_id == "dahua:p0:blk1")
            .expect("the broken chain is retained as available");
        assert_eq!(
            broken.physical_regions.len(),
            1,
            "the reached block is kept"
        );
        assert_eq!(
            broken
                .oem_metadata
                .get("dahua_chain_validity")
                .map(|s| s.as_str()),
            Some("out-of-range-link")
        );
        assert!(broken
            .oem_metadata
            .get("dahua_availability_reason")
            .unwrap()
            .contains("not evidence of deletion"));
    }

    #[test]
    fn a_non_dahua_volume_yields_no_geometry_and_no_index_claim() {
        let p = dahua_profile();
        let r = MemReader::new({
            let mut b = vec![0u8; 1 << 20];
            b[..4].copy_from_slice(b"NTFS");
            b
        });
        let v = read_volume(&r, &p).unwrap();
        assert!(matches!(v.model, VolumeModel::NotApplicable { .. }));
        assert!(v.chains.is_empty());
        assert!(storage_geometry(&v, &r, &p).unwrap().is_none());
        let idx = recording_index(&v, &r, &p).unwrap().unwrap();
        assert!(matches!(idx.authority, IndexAuthority::NotFound { .. }));
        assert!(idx.recordings.is_empty());
        assert!(idx.unreferenced_recordings.is_empty());
    }

    #[test]
    fn an_unsupported_dhfs_variant_is_not_interpreted_as_dhfs41() {
        let p = dahua_profile();
        let mut bytes = volume_bytes(&two_chains(), false);
        bytes[..8].copy_from_slice(b"DHFS9.9\0");
        let r = MemReader::new(bytes);
        let v = read_volume(&r, &p).unwrap();

        assert!(matches!(v.model, VolumeModel::NotApplicable { .. }));
        assert!(
            v.chains.is_empty(),
            "no chain may be produced from a version whose layout is not established"
        );
        assert_eq!(v.evidence.state, ValidationStateKind::Review);
        assert!(v.evidence.reason.contains("DHFS version '9.9'"));
    }

    #[test]
    fn a_dhfs41_volume_with_no_partition_table_is_not_authoritative() {
        let p = dahua_profile();
        let mut bytes = volume_bytes(&two_chains(), false);
        // Destroy the partition table identifier.
        let at = PRIMARY as usize + 304;
        bytes[at..at + 8].copy_from_slice(&[0u8; 8]);
        let r = MemReader::new(bytes);
        let v = read_volume(&r, &p).unwrap();

        assert!(v.is_dhfs41(), "the volume is still recognised as DHFS 4.1");
        assert!(v.block_maps.is_empty());
        assert!(v.chains.is_empty());
        let idx = recording_index(&v, &r, &p).unwrap().unwrap();
        assert!(
            !idx.authority.is_authoritative(),
            "with no block table read, absence proves nothing"
        );
        let g = storage_geometry(&v, &r, &p).unwrap().unwrap();
        assert!(g.video_region.is_none());
        assert_eq!(g.evidence.state, ValidationStateKind::Review);
    }

    #[test]
    fn an_empty_block_table_claims_nothing_and_asserts_no_deletion() {
        let p = dahua_profile();
        let entries = vec![EntryBuilder::empty().build(); 4];
        let (r, v) = read(&entries, false);
        let idx = recording_index(&v, &r, &p).unwrap().unwrap();

        assert!(idx.recordings.is_empty());
        assert!(idx.unreferenced_recordings.is_empty());
        // The table was read cleanly, so it IS authoritative — it just claims nothing.
        assert!(idx.authority.is_authoritative());
        assert_eq!(idx.declared_entry_count, Some(4));
    }

    #[test]
    fn the_volume_walk_is_deterministic() {
        let p = dahua_profile();
        let r = MemReader::new(volume_bytes(&two_chains(), false));
        let a = read_volume(&r, &p).unwrap();
        let b = read_volume(&r, &p).unwrap();
        assert_eq!(a, b, "two walks over the same evidence must agree exactly");
    }
}
