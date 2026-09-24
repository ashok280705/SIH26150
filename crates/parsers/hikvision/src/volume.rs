//! # Composing the Hikvision structure set into the generic contracts
//!
//! This module is where OEM-specific reading stops and the generic recovery vocabulary
//! begins. It walks
//!
//! ```text
//!   boot structure → primary HIKBTREE → backup HIKBTREE → authority selection
//!                  → video blocks → block footers → clip records
//! ```
//!
//! and produces exactly two generic outputs: a [`StorageGeometry`] and a
//! [`RecordingIndex`]. Everything downstream — claim mapping, `DataState`, orphan
//! findings, export — is driven from those, and none of it learns anything about HIKBTREE.
//!
//! ## Four kinds of block, kept apart
//!
//! [`BlockClassification`] is the heart of the orphan analysis, and the distinctions are
//! deliberate:
//!
//! | Classification | Meaning | Licenses |
//! |---|---|---|
//! | `Referenced`   | an authoritative B-tree entry points into this block | accessible recordings |
//! | `Unreferenced` | inside the video-block domain, no authoritative entry points at it | orphan **candidate** |
//! | `Malformed`    | the block's own footer index is damaged | carving, no index claim |
//! | `OutOfScope`   | outside the declared video-block domain, or not in the acquisition | nothing |
//!
//! ## Unreferenced is not deleted
//!
//! This is the single most important rule in the module. A block the B-tree does not
//! reference has surviving footer metadata describing real bytes; that supports an
//! *orphaned* finding, and only when the tree that failed to reference it was complete
//! enough for its silence to mean something. It never supports `Deleted`.
//!
//! Hikvision's structures, as read here, carry **no** allocation, free or tombstone
//! marker. So every entry reports [`AllocationEvidence::Unknown`], and
//! `DataState::Deleted` is unreachable from this parser by construction rather than by
//! convention. The profile records that as `uncertainty_allocation_state_available = 0`.
//!
//! ## Authority is hierarchical, not a magic check
//!
//! [`IndexAuthority::Authoritative`] is returned only when the chosen tree reached
//! [`crate::hikbtree::TreeIntegrity::CompleteTraversal`], the boot geometry is complete, the two trees do
//! not contradict each other, and every block in the domain was examined. Anything less is
//! `Partial`, because absence from a partially-read index is not evidence of absence.

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, OemProfile, Region, ValidationState, ValidationStateKind};
use parsers_core::storage::{
    AllocationEvidence, CircularBufferEvidence, IndexAuthority, IndexedRecording, RecordingIndex,
    StorageGeometry,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::block::{self, BlockGeometry, BlockIndex, ClipRecord};
use crate::boot::{self, BootRecognition, HikBoot};
use crate::hikbtree::{self, AuthoritySelection, BTreeEntry, HikBTree, TreeAgreement, TreeRole};
use crate::layout::{flag_from, key, u64_from, vs};

/// Reason text used wherever an unreferenced region is described, so the
/// "not deleted" qualification can never be dropped by one call site.
pub const UNREFERENCED_REASON: &str =
    "the Hikvision B-tree does not reference this block, but the block's own footer metadata \
     survives and describes real bytes. This is a statement about reachability from the index, \
     not evidence of deletion: these structures carry no allocation or free marker, so no \
     deletion finding is available from them";

/// Why a block is not part of the Hikvision video-block domain.
pub const OUT_OF_SCOPE_REASON: &str =
    "this range lies outside the video-block domain the boot structure declares, so the Hikvision \
     index makes no statement about it either way";

/// How a video block relates to the authoritative index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockClassification {
    /// At least one populated entry in the authoritative tree points into this block.
    Referenced {
        /// Ids of the entries that reference it, for provenance.
        entry_ids: Vec<String>,
        /// The data offsets those entries declared.
        data_offsets: Vec<u64>,
    },
    /// Inside the declared video-block domain, with no authoritative entry pointing at it.
    ///
    /// An orphan *candidate*. Whether an orphan finding is licensed depends on how complete
    /// the tree was, which is carried by [`RecordingIndex::authority`], not here.
    Unreferenced { reason: String },
    /// The block is in the domain but its own footer index could not be interpreted.
    ///
    /// Distinct from `Unreferenced`: the index said nothing *and* the block cannot describe
    /// itself, so its video data is a carving target rather than a metadata-backed finding.
    Malformed { reason: String },
    /// Outside the declared domain, or not present in the acquisition.
    OutOfScope { reason: String },
}

impl BlockClassification {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Referenced { .. } => "referenced",
            Self::Unreferenced { .. } => "unreferenced",
            Self::Malformed { .. } => "malformed",
            Self::OutOfScope { .. } => "out-of-scope",
        }
    }

    pub fn is_referenced(&self) -> bool {
        matches!(self, Self::Referenced { .. })
    }

    /// Whether this block's clips describe bytes the recorder still reaches.
    pub fn is_accessible(&self) -> bool {
        self.is_referenced()
    }
}

/// One video block, with its footer index and its relationship to the index.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassifiedBlock {
    pub geometry: BlockGeometry,
    pub classification: BlockClassification,
    /// The block's own footer clip index.
    pub index: BlockIndex,
    pub evidence: ValidationState,
}

impl ClassifiedBlock {
    pub fn block_number(&self) -> u32 {
        self.geometry.block_number
    }

    /// Clips this block's footer described and validated.
    pub fn clips(&self) -> &[ClipRecord] {
        &self.index.clips
    }

    /// Whether this block's video data should be offered to the structural carver.
    ///
    /// True when the block is in the domain but its index yielded nothing usable: the bytes
    /// may still hold recoverable video that no metadata describes.
    pub fn is_carving_candidate(&self) -> bool {
        !matches!(self.classification, BlockClassification::OutOfScope { .. })
            && self.index.clips.is_empty()
    }
}

/// A read Hikvision volume.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HikvisionVolume {
    pub physical_size: u64,
    pub boot: HikBoot,
    /// The tree at `BTreeOffset`.
    pub primary_tree: HikBTree,
    /// The tree at `BackupBTreeOffset`.
    pub backup_tree: HikBTree,
    /// Which tree governs, and how the two relate.
    pub authority: AuthoritySelection,
    /// Blocks examined, in block-number order.
    pub blocks: Vec<ClassifiedBlock>,
    /// Blocks the boot structure declared that the acquisition does not contain.
    pub blocks_absent_from_image: u32,
    /// Whether the block-enumeration guard stopped the walk early.
    pub block_guard_reached: bool,
    /// Authoritative entries whose data offset resolves to no block in the domain.
    pub dangling_entries: Vec<String>,
    pub evidence: ValidationState,
}

impl HikvisionVolume {
    /// Whether the Hikvision structure set applies to this evidence at all.
    pub fn is_hikvision(&self) -> bool {
        self.boot.recognition.identifier_found()
    }

    /// Whether enough structure was read to interpret recordings.
    pub fn is_usable(&self) -> bool {
        self.boot.recognition.is_recognized()
    }

    /// The tree selected as the authority, if any.
    pub fn authoritative_tree(&self) -> Option<&HikBTree> {
        match self.authority.authority? {
            TreeRole::Primary => Some(&self.primary_tree),
            TreeRole::Backup => Some(&self.backup_tree),
        }
    }

    pub fn referenced_blocks(&self) -> impl Iterator<Item = &ClassifiedBlock> {
        self.blocks
            .iter()
            .filter(|b| b.classification.is_referenced())
    }

    pub fn unreferenced_blocks(&self) -> impl Iterator<Item = &ClassifiedBlock> {
        self.blocks
            .iter()
            .filter(|b| matches!(b.classification, BlockClassification::Unreferenced { .. }))
    }

    pub fn malformed_blocks(&self) -> impl Iterator<Item = &ClassifiedBlock> {
        self.blocks
            .iter()
            .filter(|b| matches!(b.classification, BlockClassification::Malformed { .. }))
    }

    /// Every validated clip across every block, with its block's accessibility.
    pub fn clips(&self) -> impl Iterator<Item = (&ClassifiedBlock, &ClipRecord)> {
        self.blocks
            .iter()
            .flat_map(|b| b.clips().iter().map(move |c| (b, c)))
    }

    /// Clips in blocks the index references.
    pub fn accessible_clips(&self) -> impl Iterator<Item = (&ClassifiedBlock, &ClipRecord)> {
        self.clips()
            .filter(|(b, _)| b.classification.is_accessible())
    }

    /// Clips whose footer metadata survives in a block the index does not reference.
    pub fn unreferenced_clips(&self) -> impl Iterator<Item = (&ClassifiedBlock, &ClipRecord)> {
        self.clips()
            .filter(|(b, _)| !b.classification.is_accessible())
    }

    /// Locate a clip by the id [`ClipRecord::clip_id`] assigned it.
    pub fn find_clip(&self, clip_id: &str) -> Option<(&ClassifiedBlock, &ClipRecord)> {
        self.clips().find(|(_, c)| c.clip_id() == clip_id)
    }

    /// The video-block domain: the span the index makes statements about.
    pub fn video_span(&self) -> Option<Region> {
        self.boot.video_region()
    }

    /// The index region, preferring whichever tree is the authority.
    pub fn index_span(&self) -> Option<Region> {
        match self.authority.authority {
            Some(TreeRole::Backup) => self.backup_tree.tree_region,
            _ => self
                .primary_tree
                .tree_region
                .or(self.backup_tree.tree_region),
        }
    }

    /// Authoritative entries that reference a given block.
    pub fn entries_for_block(&self, block_number: u32) -> Vec<&BTreeEntry> {
        let Some(tree) = self.authoritative_tree() else {
            return Vec::new();
        };
        tree.populated_entries()
            .filter(|e| {
                e.data_offset_physical()
                    .and_then(|o| self.boot.block_number_at(o))
                    == Some(block_number)
            })
            .collect()
    }
}

/// Read a Hikvision volume.
///
/// Never fails on non-Hikvision or damaged input: an unrecognised volume comes back with a
/// [`BootRecognition`] that says so and no blocks, because "this is not Hikvision" is a
/// result the pipeline needs rather than an error. Genuine I/O failures still propagate.
///
/// Reads performed: one boot structure, the pages of each tree, and one footer header plus
/// one bounded slot-array read per block present. No block's video data is read here.
pub fn read_volume(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
) -> Result<HikvisionVolume, ForensicError> {
    let physical_size = reader.len();
    let boot = boot::read_boot(reader, profile)?;

    // Both trees are read even when the primary is fine: the backup is corroborating
    // evidence, and a disagreement between them is a finding in its own right.
    let primary_tree = hikbtree::read_tree(
        reader,
        profile,
        TreeRole::Primary,
        boot.btree_offset.value,
        boot.btree_size.value,
    )?;
    let backup_tree = hikbtree::read_tree(
        reader,
        profile,
        TreeRole::Backup,
        boot.backup_btree_offset.value,
        boot.backup_btree_size.value,
    )?;
    let authority = hikbtree::select_authority(&primary_tree, &backup_tree);

    // Without a recognised boot structure there is no video-block domain to enumerate.
    if !boot.recognition.is_recognized() {
        let evidence = boot.recognition.validation();
        return Ok(HikvisionVolume {
            physical_size,
            boot,
            primary_tree,
            backup_tree,
            authority,
            blocks: Vec::new(),
            blocks_absent_from_image: 0,
            block_guard_reached: false,
            dangling_entries: Vec::new(),
            evidence,
        });
    }

    let (blocks, blocks_absent_from_image, block_guard_reached, dangling_entries) =
        enumerate_blocks(
            reader,
            profile,
            &boot,
            &authority,
            &primary_tree,
            &backup_tree,
        )?;

    let evidence = volume_evidence(
        &boot,
        &primary_tree,
        &backup_tree,
        &authority,
        &blocks,
        blocks_absent_from_image,
        block_guard_reached,
        &dangling_entries,
    );

    Ok(HikvisionVolume {
        physical_size,
        boot,
        primary_tree,
        backup_tree,
        authority,
        blocks,
        blocks_absent_from_image,
        block_guard_reached,
        dangling_entries,
        evidence,
    })
}

/// Enumerate the declared video blocks, read their footers, and classify each one.
#[allow(clippy::type_complexity)]
fn enumerate_blocks(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    boot: &HikBoot,
    authority: &AuthoritySelection,
    primary: &HikBTree,
    backup: &HikBTree,
) -> Result<(Vec<ClassifiedBlock>, u32, bool, Vec<String>), ForensicError> {
    let physical_size = boot.physical_size;
    let footer_size = u64_from(profile, key::BLOCK_FOOTER_SIZE, 1 << 20);
    let guard = u64_from(profile, key::MAX_BLOCKS_EXAMINED, 1 << 20);

    let (Some(video_start), Some(block_size)) =
        (boot.video_start_offset.value, boot.block_size.value)
    else {
        // No usable geometry: no block can be located, which is different from there being
        // no blocks. The caller reports that through the boot evidence.
        return Ok((Vec::new(), 0, false, Vec::new()));
    };

    let declared_count = boot.number_of_blocks.value.unwrap_or(0) as u64;

    // The real bound on what can be examined is the acquisition, not the declared count.
    // Blocks the recorder declares but the image does not hold are counted, not skipped
    // silently: a truncated acquisition is a fact the examiner needs.
    let holdable = if physical_size > video_start {
        (physical_size - video_start).div_ceil(block_size)
    } else {
        0
    };
    let to_examine = declared_count.min(holdable).min(guard);
    let block_guard_reached = declared_count.min(holdable) > guard;
    let blocks_absent_from_image =
        declared_count.saturating_sub(holdable).min(u32::MAX as u64) as u32;

    // The authoritative tree's references. When no tree qualifies, this is empty, and every
    // block is therefore unreferenced — correctly, because an index that was not established
    // references nothing. Whether that licenses an orphan finding is decided by
    // `IndexAuthority`, not here.
    let authoritative_tree = match authority.authority {
        Some(TreeRole::Primary) => Some(primary),
        Some(TreeRole::Backup) => Some(backup),
        None => None,
    };

    // Map block number -> referencing entries, so classification is one pass rather than a
    // scan of the whole tree per block.
    let mut by_block: BTreeMap<u32, (Vec<String>, Vec<u64>)> = BTreeMap::new();
    let mut dangling: Vec<String> = Vec::new();
    if let Some(tree) = authoritative_tree {
        for e in tree.populated_entries() {
            match e.data_offset_physical() {
                Some(offset) => match boot.block_number_at(offset) {
                    Some(n) => {
                        let slot = by_block.entry(n).or_default();
                        slot.0.push(e.entry_id());
                        slot.1.push(offset);
                    }
                    None => dangling.push(format!(
                        "{} declares data offset {offset} (0x{offset:X}), which falls outside the \
                         declared video-block domain starting at {video_start} with {declared_count} \
                         block(s) of {block_size} bytes",
                        e.entry_id()
                    )),
                },
                None => dangling.push(format!(
                    "{} is populated but declares data offset {}, which does not address bytes in \
                     the evidence",
                    e.entry_id(),
                    e.data_offset
                )),
            }
        }
    }

    let mut blocks = Vec::new();
    for n in 0..to_examine {
        let block_number = match u32::try_from(n) {
            Ok(v) => v,
            Err(_) => break,
        };
        let Some(block_offset) = boot.block_offset(block_number) else {
            continue;
        };
        let Some(geometry) = BlockGeometry::new(
            block_number,
            block_offset,
            block_size,
            footer_size,
            physical_size,
        ) else {
            continue;
        };

        let index = block::read_block_index(reader, profile, geometry)?;

        let classification = match by_block.get(&block_number) {
            Some((entry_ids, data_offsets)) => BlockClassification::Referenced {
                entry_ids: entry_ids.clone(),
                data_offsets: data_offsets.clone(),
            },
            None => {
                // A block with no usable footer cannot describe itself. That is a different
                // finding from "the index does not reference it", so it gets its own
                // classification and its own remedy (carving, not a metadata claim).
                if index.clips.is_empty() && !index.recognition.is_verified() {
                    BlockClassification::Malformed {
                        reason: format!(
                            "no authoritative index entry references block {block_number}, and the \
                             block's own footer index is not usable ({}). Its video data is a \
                             structural carving target; no metadata-backed claim was made for it",
                            index.evidence.reason
                        ),
                    }
                } else if index.declared_but_none_valid() {
                    BlockClassification::Malformed {
                        reason: format!(
                            "no authoritative index entry references block {block_number}, and \
                             every clip slot in its footer failed validation ({}). Its video data \
                             is a structural carving target",
                            index.evidence.reason
                        ),
                    }
                } else {
                    BlockClassification::Unreferenced {
                        reason: UNREFERENCED_REASON.to_string(),
                    }
                }
            }
        };

        let evidence = block_evidence(&geometry, &classification, &index);
        blocks.push(ClassifiedBlock {
            geometry,
            classification,
            index,
            evidence,
        });
    }

    Ok((
        blocks,
        blocks_absent_from_image,
        block_guard_reached,
        dangling,
    ))
}

fn block_evidence(
    geometry: &BlockGeometry,
    classification: &BlockClassification,
    index: &BlockIndex,
) -> ValidationState {
    let n = geometry.block_number;
    let base = format!(
        "block {n} at {} (0x{:X}), {} byte(s) with a {}-byte footer, classified {}: {} clip(s) \
         validated from its footer index",
        geometry.block_offset,
        geometry.block_offset,
        geometry.block_size,
        geometry.footer_size,
        classification.label(),
        index.clips.len()
    );
    match classification {
        BlockClassification::Referenced { entry_ids, .. } => vs(
            ValidationStateKind::Pass,
            format!("{base}; referenced by {}", entry_ids.join(", ")),
            "hikvision_block_classification",
            "video_block",
        ),
        BlockClassification::Unreferenced { reason } => vs(
            // Not a failure: an unreferenced block is a normal, expected finding on a
            // recorder that has been running for a while.
            ValidationStateKind::Review,
            format!("{base}. {reason}"),
            "hikvision_block_classification",
            "video_block",
        ),
        BlockClassification::Malformed { reason } => vs(
            ValidationStateKind::Review,
            format!("{base}. {reason}"),
            "hikvision_block_classification",
            "video_block",
        ),
        BlockClassification::OutOfScope { reason } => vs(
            ValidationStateKind::Unknown,
            format!("{base}. {reason}"),
            "hikvision_block_classification",
            "video_block",
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn volume_evidence(
    boot: &HikBoot,
    primary: &HikBTree,
    backup: &HikBTree,
    authority: &AuthoritySelection,
    blocks: &[ClassifiedBlock],
    blocks_absent: u32,
    guard_reached: bool,
    dangling: &[String],
) -> ValidationState {
    let referenced = blocks
        .iter()
        .filter(|b| b.classification.is_referenced())
        .count();
    let unreferenced = blocks
        .iter()
        .filter(|b| matches!(b.classification, BlockClassification::Unreferenced { .. }))
        .count();
    let malformed = blocks
        .iter()
        .filter(|b| matches!(b.classification, BlockClassification::Malformed { .. }))
        .count();
    let clips: usize = blocks.iter().map(|b| b.clips().len()).sum();

    let base = format!(
        "Hikvision volume: {}; primary tree {} ({}), backup tree {} ({}); {}. {} block(s) examined \
         ({referenced} referenced, {unreferenced} unreferenced, {malformed} malformed) yielding \
         {clips} clip(s)",
        boot.evidence.reason,
        primary.recognition.label(),
        primary.integrity.label(),
        backup.recognition.label(),
        backup.integrity.label(),
        authority.reason,
        blocks.len(),
    );

    let mut notes: Vec<String> = Vec::new();
    if blocks_absent > 0 {
        notes.push(format!(
            "{blocks_absent} declared block(s) are not present in this acquisition, so the index \
             makes statements about bytes that were not captured"
        ));
    }
    if guard_reached {
        notes.push(
            "the block-enumeration guard stopped the walk before every declared block was examined"
                .into(),
        );
    }
    if !dangling.is_empty() {
        notes.push(format!(
            "{} authoritative entry/entries reference data outside the declared block domain: {}",
            dangling.len(),
            dangling.join("; ")
        ));
    }
    if let TreeAgreement::Disagree { reason, .. } = &authority.agreement {
        notes.push(reason.clone());
    }
    if authority.substituted {
        notes.push("the backup tree stood in for the primary".into());
    }

    let clean = notes.is_empty()
        && malformed == 0
        && authority.authority.is_some()
        && boot.evidence.state == ValidationStateKind::Pass;

    if clean {
        vs(
            ValidationStateKind::Pass,
            base,
            "hikvision_volume",
            "volume",
        )
    } else if !boot.recognition.identifier_found() {
        vs(
            ValidationStateKind::Unknown,
            base,
            "hikvision_volume",
            "volume",
        )
    } else {
        vs(
            ValidationStateKind::Review,
            format!("{base}. Qualifications: {}", notes.join("; ")),
            "hikvision_volume",
            "volume",
        )
    }
}

// ── Generic contract: StorageGeometry ───────────────────────────────────────────

/// Build the generic [`StorageGeometry`] from a read volume.
///
/// `Ok(None)` when the evidence is not a Hikvision volume — the honest answer that makes the
/// recovery engine degrade to an unindexed sweep rather than reason from invented geometry.
pub fn storage_geometry(
    volume: &HikvisionVolume,
    profile: &OemProfile,
) -> Result<Option<StorageGeometry>, ForensicError> {
    if !volume.is_hikvision() {
        return Ok(None);
    }

    let mut oem_fields: BTreeMap<String, String> = volume.boot.oem_fields();

    // ── Tree facts ───────────────────────────────────────────────────────────────
    for tree in [&volume.primary_tree, &volume.backup_tree] {
        let p = tree.role.label();
        oem_fields.insert(
            format!("hikvision_{p}_tree_recognition"),
            tree.recognition.label().to_string(),
        );
        oem_fields.insert(
            format!("hikvision_{p}_tree_integrity"),
            tree.integrity.label().to_string(),
        );
        oem_fields.insert(
            format!("hikvision_{p}_tree_pages_traversed"),
            tree.traversal.pages_visited.to_string(),
        );
        if let Some(declared) = tree.traversal.declared_page_count {
            oem_fields.insert(
                format!("hikvision_{p}_tree_declared_page_count"),
                declared.to_string(),
            );
        }
        oem_fields.insert(
            format!("hikvision_{p}_tree_populated_entries"),
            tree.populated_entries().count().to_string(),
        );
        oem_fields.insert(
            format!("hikvision_{p}_tree_blank_entries"),
            tree.blank_entries().count().to_string(),
        );
        oem_fields.insert(
            format!("hikvision_{p}_tree_malformed_entries"),
            tree.malformed_entries().count().to_string(),
        );
        if let Some(region) = tree.tree_region {
            oem_fields.insert(format!("hikvision_{p}_tree_region"), region.to_string());
        }
        if let Some(header) = &tree.header {
            if let Some(iso) = &header.tree_timestamp.iso_8601_utc {
                oem_fields.insert(format!("hikvision_{p}_tree_timestamp"), iso.clone());
            }
            oem_fields.insert(
                format!("hikvision_{p}_tree_timestamp_raw"),
                header.tree_timestamp.raw.to_string(),
            );
        }
        let problems = tree.traversal.problems();
        if !problems.is_empty() {
            oem_fields.insert(
                format!("hikvision_{p}_tree_traversal_problems"),
                problems.join("; "),
            );
        }
    }

    // ── Authority ────────────────────────────────────────────────────────────────
    oem_fields.insert(
        "hikvision_index_authority_tree".into(),
        volume
            .authority
            .authority
            .map(|r| r.label().to_string())
            .unwrap_or_else(|| "none".into()),
    );
    oem_fields.insert(
        "hikvision_index_authority_substituted".into(),
        volume.authority.substituted.to_string(),
    );
    oem_fields.insert(
        "hikvision_tree_agreement".into(),
        volume.authority.agreement.label().to_string(),
    );
    oem_fields.insert(
        "hikvision_index_authority_reason".into(),
        volume.authority.reason.clone(),
    );
    if let TreeAgreement::Disagree {
        primary_only,
        backup_only,
        ..
    } = &volume.authority.agreement
    {
        // The disagreement is preserved in the geometry so a report can show it without
        // re-reading the disk.
        oem_fields.insert(
            "hikvision_tree_disagreement_primary_only".into(),
            primary_only
                .iter()
                .take(32)
                .map(|o| o.to_string())
                .collect::<Vec<_>>()
                .join(","),
        );
        oem_fields.insert(
            "hikvision_tree_disagreement_backup_only".into(),
            backup_only
                .iter()
                .take(32)
                .map(|o| o.to_string())
                .collect::<Vec<_>>()
                .join(","),
        );
    }

    // ── Block classification counts ──────────────────────────────────────────────
    oem_fields.insert(
        "hikvision_blocks_examined".into(),
        volume.blocks.len().to_string(),
    );
    oem_fields.insert(
        "hikvision_blocks_referenced".into(),
        volume.referenced_blocks().count().to_string(),
    );
    oem_fields.insert(
        "hikvision_blocks_unreferenced".into(),
        volume.unreferenced_blocks().count().to_string(),
    );
    oem_fields.insert(
        "hikvision_blocks_malformed".into(),
        volume.malformed_blocks().count().to_string(),
    );
    oem_fields.insert(
        "hikvision_blocks_absent_from_image".into(),
        volume.blocks_absent_from_image.to_string(),
    );
    oem_fields.insert(
        "hikvision_clips_total".into(),
        volume.clips().count().to_string(),
    );
    oem_fields.insert(
        "hikvision_clips_accessible".into(),
        volume.accessible_clips().count().to_string(),
    );
    oem_fields.insert(
        "hikvision_clips_unreferenced".into(),
        volume.unreferenced_clips().count().to_string(),
    );
    oem_fields.insert(
        "hikvision_block_footer_size".into(),
        u64_from(profile, key::BLOCK_FOOTER_SIZE, 1 << 20).to_string(),
    );
    if !volume.dangling_entries.is_empty() {
        oem_fields.insert(
            "hikvision_dangling_entries".into(),
            volume.dangling_entries.join("; "),
        );
    }

    // ── Firmware / layout uncertainty, surfaced so a report can state it ─────────
    for (field, k) in [
        ("boot_identifier", key::UNCERTAINTY_BOOT_IDENTIFIER),
        ("btree_page_layout", key::UNCERTAINTY_BTREE_PAGE_LAYOUT),
        ("entry_layout", key::UNCERTAINTY_ENTRY_LAYOUT),
        (
            "block_footer_geometry",
            key::UNCERTAINTY_BLOCK_FOOTER_GEOMETRY,
        ),
        ("ps_framing", key::UNCERTAINTY_PS_FRAMING),
        ("channel_encoding", key::UNCERTAINTY_CHANNEL_ENCODING),
        ("clip_slot_semantics", key::UNCERTAINTY_CLIP_SLOT_SEMANTICS),
        (
            "entry_status_semantics",
            key::UNCERTAINTY_ENTRY_STATUS_SEMANTICS,
        ),
        (
            "carve_sentinel_semantics",
            key::UNCERTAINTY_CARVE_SENTINEL_SEMANTICS,
        ),
        ("allocation_state", key::UNCERTAINTY_ALLOCATION_STATE),
    ] {
        oem_fields.insert(
            format!("hikvision_established_{field}"),
            flag_from(profile, k).to_string(),
        );
    }
    // The load-bearing consequence of the allocation flag, stated in words.
    oem_fields.insert(
        "hikvision_allocation_evidence".into(),
        "the Hikvision structures this parser reads carry no allocation, free or tombstone marker, \
         so every index entry reports AllocationEvidence::Unknown and no deletion finding is \
         available from this OEM path"
            .into(),
    );

    Ok(Some(StorageGeometry {
        physical_size: volume.physical_size,
        video_region: volume.video_span(),
        index_region: volume.index_span(),
        metadata_region: volume.boot.boot_region,
        block_size: volume.boot.block_size.value,
        // The Hikvision boot structure declares no logical sector size. Reporting a guess
        // here would be fabrication, so it stays None.
        sector_size: None,
        // These structures carry no write cursor and no wrap flag. Hikvision recorders do
        // overwrite oldest-first in practice, but that is knowledge about the product, not
        // a fact read from this disk, so it cannot be reported as evidence.
        circular_buffer: CircularBufferEvidence::Unknown,
        oem_fields,
        evidence: volume.evidence.clone(),
    }))
}

// ── Generic contract: RecordingIndex ────────────────────────────────────────────

/// Build the generic [`RecordingIndex`] from a read volume.
///
/// One [`IndexedRecording`] per validated clip. The clip is the finest unit the filesystem
/// itself delimits, so using it avoids both extremes: one entry per whole block would lose
/// real boundaries, and one per scan chunk would invent them.
///
/// Clips from referenced blocks go to `recordings` (accessible). Clips from unreferenced or
/// malformed blocks go to `unreferenced_recordings` (available), each carrying the
/// "not deleted" reason.
pub fn recording_index(
    volume: &HikvisionVolume,
    profile: &OemProfile,
) -> Result<Option<RecordingIndex>, ForensicError> {
    if !volume.is_hikvision() {
        return Ok(None);
    }

    let mut recordings: Vec<IndexedRecording> = Vec::new();
    let mut unreferenced: Vec<IndexedRecording> = Vec::new();

    for (block, clip) in volume.clips() {
        let entry = matching_entry(volume, block, clip);
        let indexed = clip_to_indexed(volume, block, clip, entry, profile);
        if block.classification.is_accessible() {
            recordings.push(indexed);
        } else {
            unreferenced.push(indexed);
        }
    }

    // Entries the index declares that produced no clip are a real finding: the recorder
    // references bytes its own block footer does not describe.
    let mut entry_gaps: Vec<String> = Vec::new();
    if let Some(tree) = volume.authoritative_tree() {
        for e in tree.populated_entries() {
            let covered = e.data_offset_physical().is_some_and(|offset| {
                volume
                    .blocks
                    .iter()
                    .any(|b| b.clips().iter().any(|c| c.clip_region.contains(offset)))
            });
            if !covered && e.data_offset_physical().is_some() {
                entry_gaps.push(format!(
                    "{} references data offset {} (0x{:X}) which no validated clip describes",
                    e.entry_id(),
                    e.data_offset,
                    e.data_offset
                ));
            }
        }
    }

    let declared_entry_count = volume
        .authoritative_tree()
        .map(|t| t.entries().count())
        .or_else(|| Some(volume.primary_tree.entries().count()));

    let authority = decide_authority(volume, &entry_gaps);
    let evidence = index_evidence(volume, &recordings, &unreferenced, &authority, &entry_gaps);

    Ok(Some(RecordingIndex {
        authority,
        recordings,
        unreferenced_recordings: unreferenced,
        declared_entry_count,
        index_region: volume.index_span(),
        evidence,
    }))
}

/// The authoritative entry that best corroborates a clip, if any.
///
/// Preferred match: an entry whose data offset falls inside the clip's own range — that is
/// the index pointing directly at these bytes. Fallback: an entry in the same block whose
/// channel and interval are consistent with the clip. No match is a legitimate outcome.
fn matching_entry<'a>(
    volume: &'a HikvisionVolume,
    block: &ClassifiedBlock,
    clip: &ClipRecord,
) -> Option<&'a BTreeEntry> {
    let candidates = volume.entries_for_block(block.block_number());

    if let Some(direct) = candidates.iter().find(|e| {
        e.data_offset_physical()
            .is_some_and(|o| clip.clip_region.contains(o))
    }) {
        return Some(direct);
    }

    candidates.into_iter().find(|e| {
        let channel_ok = match (e.channel.normalized, clip.channel.normalized) {
            (Some(a), Some(b)) => a == b,
            // An unknown channel on either side is not a contradiction, so it does not
            // veto the match; it simply cannot support it.
            _ => true,
        };
        let time_ok = match (
            e.start_time.unix_seconds,
            e.end_time.unix_seconds,
            clip.start_time.unix_seconds,
            clip.end_time.unix_seconds,
        ) {
            (Some(es), Some(ee), Some(cs), Some(ce)) => es <= ce && cs <= ee,
            _ => true,
        };
        channel_ok && time_ok
    })
}

/// Convert one clip into the generic index entry.
fn clip_to_indexed(
    volume: &HikvisionVolume,
    block: &ClassifiedBlock,
    clip: &ClipRecord,
    entry: Option<&BTreeEntry>,
    profile: &OemProfile,
) -> IndexedRecording {
    let mut oem_metadata = clip.oem_metadata();
    oem_metadata.insert(
        "hikvision_block_classification".into(),
        block.classification.label().to_string(),
    );
    oem_metadata.insert(
        "hikvision_block_video_data_region".into(),
        block
            .geometry
            .video_data_region()
            .map(|r| r.to_string())
            .unwrap_or_else(|| "none".into()),
    );
    oem_metadata.insert(
        "hikvision_block_footer_region".into(),
        block
            .geometry
            .footer_region()
            .map(|r| r.to_string())
            .unwrap_or_else(|| "none".into()),
    );
    // Volume-level provenance, so a single exported recording still records which boot
    // structure and which tree the claim about it came from.
    if let Some(boot_offset) = volume.boot.recognition.boot_offset() {
        oem_metadata.insert("hikvision_boot_offset".into(), boot_offset.to_string());
    }
    oem_metadata.insert(
        "hikvision_index_authority_tree".into(),
        volume
            .authority
            .authority
            .map(|r| r.label().to_string())
            .unwrap_or_else(|| "none".into()),
    );
    oem_metadata.insert(
        "hikvision_index_authority_substituted".into(),
        volume.authority.substituted.to_string(),
    );

    // ── Source B-tree evidence ───────────────────────────────────────────────────
    match entry {
        Some(e) => {
            oem_metadata.insert("hikvision_btree_entry_id".into(), e.entry_id());
            oem_metadata.insert("hikvision_btree_entry_role".into(), e.role.label().into());
            oem_metadata.insert(
                "hikvision_btree_entry_offset".into(),
                e.entry_offset.to_string(),
            );
            oem_metadata.insert(
                "hikvision_btree_page_offset".into(),
                e.page_offset.to_string(),
            );
            oem_metadata.insert(
                "hikvision_btree_entry_index_in_page".into(),
                e.index_in_page.to_string(),
            );
            oem_metadata.insert(
                "hikvision_btree_entry_data_offset".into(),
                e.data_offset.to_string(),
            );
            // Preserved raw: this platform has not established what the bits mean, and a
            // decoded-looking label would imply it had.
            oem_metadata.insert(
                "hikvision_btree_entry_status_raw".into(),
                e.status_raw.to_string(),
            );
            oem_metadata.insert(
                "hikvision_btree_entry_uninterpreted_field_44".into(),
                e.unknown_raw.to_string(),
            );
            oem_metadata.insert(
                "hikvision_btree_entry_sentinel".into(),
                format!("0x{:016X}", e.sentinel),
            );
            oem_metadata.insert(
                "hikvision_btree_entry_state".into(),
                e.state.label().to_string(),
            );
            oem_metadata.insert(
                "hikvision_btree_entry_start_raw".into(),
                e.start_time.raw.to_string(),
            );
            oem_metadata.insert(
                "hikvision_btree_entry_end_raw".into(),
                e.end_time.raw.to_string(),
            );
            if e.is_incomplete() {
                oem_metadata.insert(
                    "hikvision_recording_incomplete".into(),
                    "the referencing B-tree entry carries the incomplete-recording sentinel; the \
                     recorder had not finished writing this recording"
                        .into(),
                );
            }
        }
        None => {
            oem_metadata.insert("hikvision_btree_entry_id".into(), "none".into());
            oem_metadata.insert(
                "hikvision_btree_correlation".into(),
                format!(
                    "no authoritative B-tree entry corroborates this clip; it was located from \
                     block {}'s own footer index",
                    block.block_number()
                ),
            );
        }
    }

    // ── Discovery method, in the parser's own words ──────────────────────────────
    oem_metadata.insert(
        "hikvision_discovery_method".into(),
        if entry.is_some() {
            "btree-entry-and-block-footer-clip-index"
        } else {
            "block-footer-clip-index"
        }
        .into(),
    );
    oem_metadata.insert(
        "hikvision_parser_evidence".into(),
        clip.evidence.reason.clone(),
    );

    // ── Availability ─────────────────────────────────────────────────────────────
    //
    // Both the generic key the claim layer reads and an OEM-named copy, so the wording
    // survives even if a consumer only knows one of them.
    if !block.classification.is_accessible() {
        let reason = match &block.classification {
            BlockClassification::Unreferenced { reason }
            | BlockClassification::Malformed { reason }
            | BlockClassification::OutOfScope { reason } => reason.clone(),
            BlockClassification::Referenced { .. } => unreachable!("guarded by is_accessible"),
        };
        oem_metadata.insert("availability_reason".into(), reason.clone());
        oem_metadata.insert("hikvision_availability_reason".into(), reason);
    }

    let evidence = if block.classification.is_accessible() {
        clip.evidence.clone()
    } else {
        vs(
            ValidationStateKind::Review,
            format!(
                "{} The block it lives in is classified {}, so this recording is reported as \
                 available rather than accessible. {UNREFERENCED_REASON}",
                clip.evidence.reason,
                block.classification.label()
            ),
            "hikvision_indexed_recording",
            "clip",
        )
    };

    IndexedRecording {
        recording_id: clip.clip_id(),
        // Hikvision's structures describe one flat video-block domain, not partitions.
        // `None` is an accurate statement about the format, not a missing value.
        partition: None,
        channel: clip.channel.normalized,
        start_time_unix: clip.start_time.unix_seconds,
        end_time_unix: clip.end_time.unix_seconds,
        physical_regions: vec![clip.clip_region],
        // The container framing is separated during reconstruction, where the clip's
        // MPEG-PS parts are actually walked. Claiming payload sub-ranges here would mean
        // walking every clip on the volume just to build an index.
        payload_regions: Vec::new(),
        // The clip index declares no codec. Codec identity comes from the payload bytes at
        // reconstruction time, and is never guessed here.
        codec_hint: None,
        // See the module docs: these structures carry no allocation state, so this is the
        // only honest value, and it is what makes `DataState::Deleted` unreachable.
        allocation: allocation_evidence(profile),
        oem_metadata,
        evidence,
    }
}

/// Allocation evidence available from the Hikvision structures.
///
/// Always [`AllocationEvidence::Unknown`], and deliberately so. The boot structure, the
/// HIKBTREE entries and the block footer clip slots this parser reads contain no allocation
/// bit, no free list and no tombstone. `AllocationEvidence::FreeMarked` is the only route to
/// `DataState::Deleted` in the generic classifier, so returning `Unknown` here is what makes
/// a deletion finding structurally unreachable from the Hikvision path rather than merely
/// discouraged.
///
/// A single function rather than an inline literal so that if a future revision establishes a
/// free marker, this is the one place that changes — and the profile flag it would key off
/// (`uncertainty_allocation_state_available`) is asserted against here.
fn allocation_evidence(profile: &OemProfile) -> AllocationEvidence {
    debug_assert!(
        !flag_from(profile, key::UNCERTAINTY_ALLOCATION_STATE),
        "the profile claims Hikvision allocation state is established, but this parser has no \
         reader for it; reporting anything but Unknown would be a claim it cannot support"
    );
    AllocationEvidence::Unknown
}

/// Decide how much weight the index may carry.
///
/// Hierarchical, as the brief requires: filesystem recognised → tree recognised → traversal
/// valid → leaf coverage → entry validity → primary/backup. Each stage can only downgrade.
fn decide_authority(volume: &HikvisionVolume, entry_gaps: &[String]) -> IndexAuthority {
    let Some(tree) = volume.authoritative_tree() else {
        return IndexAuthority::NotFound {
            reason: format!(
                "no Hikvision index tree was established: {}. Absence from an index that was never \
                 read is not evidence of absence, so no orphan conclusion is licensed anywhere on \
                 this volume",
                volume.authority.reason
            ),
        };
    };

    let mut downgrades: Vec<String> = Vec::new();

    if !tree.integrity.is_complete() {
        downgrades.push(format!(
            "the {} tree reached only {} ({})",
            tree.role.label(),
            tree.integrity.label(),
            tree.traversal.problems().join("; ")
        ));
    }
    if tree.malformed_entries().count() > 0 {
        downgrades.push(format!(
            "{} entry/entries carry a state sentinel that is neither blank nor populated, so the \
             index's own statement about those slots is unreadable",
            tree.malformed_entries().count()
        ));
    }
    if !volume.boot.geometry_is_complete() {
        downgrades.push(format!(
            "the boot structure does not establish complete block geometry ({}), so the extent the \
             index governs cannot be fixed",
            volume.boot.evidence.reason
        ));
    }
    if volume.blocks_absent_from_image > 0 {
        downgrades.push(format!(
            "{} declared block(s) are absent from this acquisition, so the index describes bytes \
             that were not captured",
            volume.blocks_absent_from_image
        ));
    }
    if volume.block_guard_reached {
        downgrades.push(
            "the block-enumeration guard stopped before every declared block was examined".into(),
        );
    }
    if let TreeAgreement::Disagree { reason, .. } = &volume.authority.agreement {
        downgrades.push(reason.clone());
    }
    if !volume.dangling_entries.is_empty() {
        downgrades.push(format!(
            "{} entry/entries point outside the declared block domain",
            volume.dangling_entries.len()
        ));
    }
    if !entry_gaps.is_empty() {
        downgrades.push(format!(
            "{} entry/entries reference bytes no validated clip describes",
            entry_gaps.len()
        ));
    }

    let Some(governs) = volume.video_span() else {
        return IndexAuthority::Partial {
            reason: format!(
                "the {} tree was read but no video-block domain could be established, so there is \
                 no region it can make a complete statement about. Absence from it is not evidence \
                 of absence",
                tree.role.label()
            ),
        };
    };

    if downgrades.is_empty() {
        IndexAuthority::Authoritative { governs }
    } else {
        IndexAuthority::Partial {
            reason: format!(
                "the {} Hikvision index tree was located and parsed but is not a complete \
                 statement over {governs}: {}. Absence from it is therefore not evidence of \
                 absence, and no orphan finding may rest on it alone",
                tree.role.label(),
                downgrades.join("; ")
            ),
        }
    }
}

fn index_evidence(
    volume: &HikvisionVolume,
    recordings: &[IndexedRecording],
    unreferenced: &[IndexedRecording],
    authority: &IndexAuthority,
    entry_gaps: &[String],
) -> ValidationState {
    let authority_label = match authority {
        IndexAuthority::Authoritative { governs } => {
            format!("authoritative over {governs}")
        }
        IndexAuthority::Partial { .. } => "partial".to_string(),
        IndexAuthority::NotFound { .. } => "not found".to_string(),
    };

    let base = format!(
        "Hikvision recording index is {authority_label}: {} accessible and {} available \
         recording(s) from {} block(s) ({} referenced, {} unreferenced, {} malformed)",
        recordings.len(),
        unreferenced.len(),
        volume.blocks.len(),
        volume.referenced_blocks().count(),
        volume.unreferenced_blocks().count(),
        volume.malformed_blocks().count(),
    );

    let mut notes: Vec<String> = Vec::new();
    if let IndexAuthority::Partial { reason } | IndexAuthority::NotFound { reason } = authority {
        notes.push(reason.clone());
    }
    if !entry_gaps.is_empty() {
        notes.push(entry_gaps.join("; "));
    }
    if !unreferenced.is_empty() {
        notes.push(format!(
            "{} recording(s) are reported available rather than accessible. {UNREFERENCED_REASON}",
            unreferenced.len()
        ));
    }

    let kind = match authority {
        IndexAuthority::Authoritative { .. } if notes.is_empty() => ValidationStateKind::Pass,
        IndexAuthority::NotFound { .. } => ValidationStateKind::Unknown,
        _ => ValidationStateKind::Review,
    };

    let reason = if notes.is_empty() {
        base
    } else {
        format!("{base}. {}", notes.join(". "))
    };

    vs(kind, reason, "hikvision_recording_index", "recording_index")
}

/// Ranges the volume's own metadata accounts for, as a set.
///
/// Used by the carver to avoid re-reporting bytes an index entry already describes.
pub fn described_regions(volume: &HikvisionVolume) -> BTreeSet<(u64, u64)> {
    volume
        .clips()
        .map(|(_, c)| (c.clip_region.offset, c.clip_region.length))
        .collect()
}

/// OEM-specific descriptive fields for a report, as plain strings.
pub fn volume_summary(volume: &HikvisionVolume) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    out.insert(
        "hikvision_recognition".into(),
        volume.boot.recognition.label().into(),
    );
    out.insert(
        "primary_tree_integrity".into(),
        volume.primary_tree.integrity.label().into(),
    );
    out.insert(
        "backup_tree_integrity".into(),
        volume.backup_tree.integrity.label().into(),
    );
    out.insert(
        "index_authority".into(),
        volume
            .authority
            .authority
            .map(|r| r.label().to_string())
            .unwrap_or_else(|| "none".into()),
    );
    out.insert(
        "tree_agreement".into(),
        volume.authority.agreement.label().into(),
    );
    out.insert("blocks_examined".into(), volume.blocks.len().to_string());
    out.insert(
        "blocks_referenced".into(),
        volume.referenced_blocks().count().to_string(),
    );
    out.insert(
        "blocks_unreferenced".into(),
        volume.unreferenced_blocks().count().to_string(),
    );
    out.insert(
        "clips_accessible".into(),
        volume.accessible_clips().count().to_string(),
    );
    out.insert(
        "clips_unreferenced".into(),
        volume.unreferenced_clips().count().to_string(),
    );
    if let Some(boot_offset) = volume.boot.recognition.boot_offset() {
        out.insert("boot_offset".into(), boot_offset.to_string());
    }
    out
}

/// Whether the Hikvision structure set applies, without building the whole volume.
///
/// Cheap: reads only the boot structure. Used by the detector-adjacent paths and by
/// `recognize_candidate` to avoid a full volume read when the answer is already no.
pub fn recognizes(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
) -> Result<BootRecognition, ForensicError> {
    Ok(boot::read_boot(reader, profile)?.recognition)
}
