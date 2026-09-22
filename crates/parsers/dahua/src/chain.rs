//! # DHFS 4.1 recording chain reconstruction
//!
//! A Dahua recording is a **chain of 2 MiB video blocks**, not a contiguous run of bytes.
//! The block table links them:
//!
//! ```text
//!   FirstBlock ──NextBlock──▶ block ──NextBlock──▶ block ──NextBlock──▶ 0 (terminator)
//!        ▲                      │                     │
//!        └──────── FirstBlock ──┴─── PreviousBlock ───┘
//! ```
//!
//! Forward traversal reconstructs the recording; the `PreviousBlock` back-links are a
//! second, independent statement of the same relationship, so disagreement between them is
//! real evidence about the filesystem's integrity and is recorded rather than smoothed over.
//!
//! ## Bounded traversal
//!
//! A damaged or hostile block table can describe a cycle, a self-reference, or a link past
//! the end of the table. Traversal therefore:
//!
//! * carries a visited set, so a cycle terminates at its first repeat;
//! * range-checks every link against the table before following it;
//! * stops at a declared maximum length, which can never exceed the table size.
//!
//! A malformed chain is **never** discarded. The blocks that were reached are real bytes
//! and stay recoverable; the failure becomes [`ChainValidity`] and an evidence string.
//!
//! ## Reachability is not deletion
//!
//! Occupied blocks that no `FirstBlock` traversal reaches are grouped into chains of their
//! own using their declared `FirstBlock` value — the recorder's own relationship, not a
//! heuristic. Those chains are marked [`ChainOrigin::UnreachableBlockGroup`], which is the
//! evidentiary basis for reporting them as *available/orphaned*. It is not, on its own,
//! evidence that anything was deleted.

use std::collections::{BTreeMap, BTreeSet};

use forensic_core::{OemProfile, Region, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};

use crate::block_table::{BlockMap, BlockTableEntry};
use crate::channel::DahuaChannel;
use crate::layout::{key, u64_from, vs};
use crate::timestamp::DahuaTimestamp;

/// One physical block's contribution to a recording.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VideoBlock {
    /// Partition the block belongs to.
    pub partition: u32,
    /// Block number within the partition.
    pub block_number: u32,
    /// Physical offset of the block's payload area.
    pub physical_offset: u64,
    /// Bytes of this block that belong to the recording. Full block size except on the
    /// last block of a chain, which is `sectorCount * 512`.
    pub physical_length: u64,
    /// The exact physical region, for claims and export.
    pub region: Region,
    /// Physical offset of the 32-byte block-table entry that described it.
    pub entry_offset: u64,
    /// Channel, with the encoding that produced it.
    pub channel: DahuaChannel,
    pub start_time: DahuaTimestamp,
    pub end_time: DahuaTimestamp,
    pub first_block: i32,
    pub previous_block: i32,
    pub next_block: i32,
    /// Whether this is the chain terminator.
    pub is_last: bool,
    /// The block-table entry's own validation outcome.
    pub evidence: ValidationState,
}

/// How a chain's traversal ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainValidity {
    /// Traversal reached a terminator and every link checked out.
    Complete,
    /// Traversal reached a terminator, but the forward and backward links disagreed
    /// somewhere. The blocks are real; the filesystem's integrity is not.
    CompleteWithInconsistentBackLinks { reason: String },
    /// A `NextBlock` pointed outside the block table.
    OutOfRangeLink { reason: String },
    /// A `NextBlock` pointed at a block already in this chain.
    Looped { reason: String },
    /// A block's `NextBlock` pointed at itself.
    SelfReference { reason: String },
    /// A `NextBlock` pointed at an empty slot, so the recording's continuation is gone.
    BrokenAtEmptySlot { reason: String },
    /// Traversal hit the declared maximum length without finding a terminator.
    Unbounded { reason: String },
    /// The chain was assembled from blocks no traversal reached.
    RecoveredFromUnreachableBlocks { reason: String },
}

impl ChainValidity {
    /// Whether the chain was traversed end to end.
    pub fn is_complete(&self) -> bool {
        matches!(
            self,
            ChainValidity::Complete | ChainValidity::CompleteWithInconsistentBackLinks { .. }
        )
    }

    /// Stable label for logs and reports.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::CompleteWithInconsistentBackLinks { .. } => "complete-inconsistent-back-links",
            Self::OutOfRangeLink { .. } => "out-of-range-link",
            Self::Looped { .. } => "looped",
            Self::SelfReference { .. } => "self-reference",
            Self::BrokenAtEmptySlot { .. } => "broken-at-empty-slot",
            Self::Unbounded { .. } => "unbounded",
            Self::RecoveredFromUnreachableBlocks { .. } => "recovered-from-unreachable-blocks",
        }
    }

    /// The failure description, when there is one.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Complete => None,
            Self::CompleteWithInconsistentBackLinks { reason }
            | Self::OutOfRangeLink { reason }
            | Self::Looped { reason }
            | Self::SelfReference { reason }
            | Self::BrokenAtEmptySlot { reason }
            | Self::Unbounded { reason }
            | Self::RecoveredFromUnreachableBlocks { reason } => Some(reason),
        }
    }
}

/// How the chain's block order was established.
///
/// Ordering priority is fixed by the format: the OEM block-chain relationship first, then
/// the declared `FirstBlock` grouping, and only then anything weaker. Timestamps are never
/// used to order blocks when a link relationship exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainOrdering {
    /// Followed `NextBlock` from the head. The strongest available relationship.
    OemBlockChain,
    /// Assembled from blocks sharing a declared `FirstBlock`, then linked where possible.
    DeclaredFirstBlockGroup,
    /// Fell back to ascending block number because no link relationship survived.
    BlockNumberFallback,
}

impl ChainOrdering {
    pub fn label(&self) -> &'static str {
        match self {
            Self::OemBlockChain => "oem-block-chain",
            Self::DeclaredFirstBlockGroup => "declared-first-block-group",
            Self::BlockNumberFallback => "block-number-fallback",
        }
    }
}

/// Where the chain came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainOrigin {
    /// Reached by traversing from a block that declares itself the first of a recording.
    FirstBlockTraversal,
    /// Assembled from occupied blocks that no traversal reached.
    UnreachableBlockGroup,
}

/// One reconstructed recording: an ordered chain of physical video blocks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordingChain {
    /// Stable identifier derived from the structure itself — partition and head block —
    /// so the same evidence always yields the same id.
    pub chain_id: String,
    pub partition: u32,
    /// Block number the chain starts at.
    pub head_block: u32,
    /// Channel, taken from the head block and cross-checked against the rest.
    pub channel: DahuaChannel,
    /// Blocks in recording order.
    pub blocks: Vec<VideoBlock>,
    /// Earliest decoded start timestamp across the chain's blocks.
    pub start_time: Option<DahuaTimestamp>,
    /// Latest decoded end timestamp across the chain's blocks.
    pub end_time: Option<DahuaTimestamp>,
    pub validity: ChainValidity,
    pub ordering: ChainOrdering,
    pub origin: ChainOrigin,
    /// Blocks whose channel disagreed with the head block's, if any.
    pub channel_disagreements: Vec<String>,
    pub evidence: ValidationState,
}

impl RecordingChain {
    /// Total recoverable bytes across the chain.
    pub fn total_bytes(&self) -> u64 {
        self.blocks
            .iter()
            .fold(0u64, |a, b| a.saturating_add(b.physical_length))
    }

    /// Physical regions in recording order.
    pub fn regions(&self) -> Vec<Region> {
        self.blocks.iter().map(|b| b.region).collect()
    }

    /// Whether the chain's blocks are physically contiguous.
    ///
    /// Reported, never required: physical non-contiguity is normal block allocation and is
    /// not frame loss.
    pub fn is_physically_contiguous(&self) -> bool {
        self.blocks
            .windows(2)
            .all(|w| w[0].region.end() == Some(w[1].region.offset))
    }

    /// Whether the chain was traversed end to end from a declared head.
    pub fn is_fully_reconstructed(&self) -> bool {
        self.origin == ChainOrigin::FirstBlockTraversal && self.validity.is_complete()
    }
}

/// Reconstruct every recording chain described by a partition's block table.
///
/// Chains reached from a declared first block come first, in head-block order, followed by
/// chains recovered from unreachable blocks. The ordering is deterministic so two runs over
/// the same evidence produce identical output.
pub fn build_chains(map: &BlockMap, profile: &OemProfile) -> Vec<RecordingChain> {
    let max_len = u64_from(profile, key::BLOCK_CHAIN_MAX_LENGTH, 262_144)
        .min(map.entries.len() as u64)
        .max(1) as usize;

    let mut visited: BTreeSet<u32> = BTreeSet::new();
    let mut chains: Vec<RecordingChain> = Vec::new();

    // ── Pass 1: traverse from every declared first block ────────────────────
    let heads: Vec<u32> = map.first_blocks().map(|e| e.block_number).collect();
    for head in heads {
        if visited.contains(&head) {
            // Two heads cannot share a block. If one does, the later head is left to the
            // unreachable pass rather than silently duplicating bytes across two chains.
            continue;
        }
        let chain = traverse(map, head, max_len, &mut visited);
        chains.push(chain);
    }

    // ── Pass 2: recover occupied blocks no traversal reached ────────────────
    // Grouped by their declared FirstBlock, which is the recorder's own statement about
    // which recording they belonged to.
    let mut groups: BTreeMap<i32, Vec<u32>> = BTreeMap::new();
    let mut ungrouped: Vec<u32> = Vec::new();
    for entry in &map.entries {
        if entry.is_empty() || visited.contains(&entry.block_number) {
            continue;
        }
        if entry.first_block > 0 {
            groups
                .entry(entry.first_block)
                .or_default()
                .push(entry.block_number);
        } else {
            ungrouped.push(entry.block_number);
        }
    }
    for (first_block, members) in groups {
        chains.push(recover_group(map, first_block, &members));
    }
    for block in ungrouped {
        chains.push(recover_group(map, -1, std::slice::from_ref(&block)));
    }

    chains
}

/// Follow `NextBlock` from `head`, validating every link.
fn traverse(
    map: &BlockMap,
    head: u32,
    max_len: usize,
    visited: &mut BTreeSet<u32>,
) -> RecordingChain {
    let mut blocks: Vec<VideoBlock> = Vec::new();
    let mut local: BTreeSet<u32> = BTreeSet::new();
    let mut back_link_problems: Vec<String> = Vec::new();
    let mut validity: Option<ChainValidity> = None;
    let mut current = head as i32;

    while let Some(entry) = map.get(current) {
        let block_number = entry.block_number;
        if let Some(block) = to_video_block(map.partition, entry) {
            blocks.push(block);
        } else {
            back_link_problems.push(format!(
                "block {block_number} has no established physical extent, so it contributes no bytes"
            ));
        }
        local.insert(block_number);
        visited.insert(block_number);

        if blocks.len() >= max_len && !entry.is_last_block() {
            validity = Some(ChainValidity::Unbounded {
                reason: format!(
                    "traversal from block {head} reached the {max_len}-block bound without finding a \
                     terminator; the chain is reported as far as it was followed"
                ),
            });
            break;
        }

        if entry.is_last_block() {
            break;
        }

        let next = entry.next_block;
        if next == block_number as i32 {
            validity = Some(ChainValidity::SelfReference {
                reason: format!("block {block_number} lists itself as its own NextBlock"),
            });
            break;
        }
        if !map.in_range(next) {
            validity = Some(ChainValidity::OutOfRangeLink {
                reason: format!(
                    "block {block_number} points to NextBlock {next}, which is outside the {}-entry \
                     block table",
                    map.entries.len()
                ),
            });
            break;
        }
        if local.contains(&(next as u32)) {
            validity = Some(ChainValidity::Looped {
                reason: format!(
                    "block {block_number} points back to block {next}, which is already part of this \
                     chain; traversal stopped to avoid an unbounded walk"
                ),
            });
            break;
        }
        let next_entry = match map.get(next) {
            Some(e) => e,
            None => {
                validity = Some(ChainValidity::OutOfRangeLink {
                    reason: format!("NextBlock {next} has no block table entry"),
                });
                break;
            }
        };
        if next_entry.is_empty() {
            validity = Some(ChainValidity::BrokenAtEmptySlot {
                reason: format!(
                    "block {block_number} points to block {next}, whose table entry is marked \
                     empty; the recording's continuation is no longer described. This is a broken \
                     link, not evidence of deletion"
                ),
            });
            break;
        }
        // Independent cross-check: the next block must point back here.
        if next_entry.previous_block != block_number as i32 {
            back_link_problems.push(format!(
                "block {next} lists PreviousBlock {} but was reached from block {block_number}",
                next_entry.previous_block
            ));
        }
        current = next;
    }

    let validity = validity.unwrap_or_else(|| {
        if back_link_problems.is_empty() {
            ChainValidity::Complete
        } else {
            ChainValidity::CompleteWithInconsistentBackLinks {
                reason: back_link_problems.join("; "),
            }
        }
    });

    finish_chain(
        map,
        head,
        blocks,
        validity,
        ChainOrdering::OemBlockChain,
        ChainOrigin::FirstBlockTraversal,
        back_link_problems,
    )
}

/// Assemble a chain from blocks no traversal reached.
fn recover_group(map: &BlockMap, declared_first: i32, members: &[u32]) -> RecordingChain {
    // Prefer the OEM link relationship even here: start at the member with no in-group
    // predecessor and follow NextBlock while it stays inside the group. Only if that fails
    // to cover the group do we fall back to ascending block number.
    let member_set: BTreeSet<u32> = members.iter().copied().collect();
    let mut ordered: Vec<u32> = Vec::new();
    let mut ordering = ChainOrdering::BlockNumberFallback;

    let start = members.iter().copied().find(|b| {
        map.get(*b as i32)
            .map(|e| !member_set.contains(&(e.previous_block.max(0) as u32)))
            .unwrap_or(false)
    });
    if let Some(start) = start {
        let mut seen: BTreeSet<u32> = BTreeSet::new();
        let mut cursor = start as i32;
        while let Some(entry) = map.get(cursor) {
            if !member_set.contains(&entry.block_number) || !seen.insert(entry.block_number) {
                break;
            }
            ordered.push(entry.block_number);
            if entry.is_last_block() {
                break;
            }
            cursor = entry.next_block;
        }
        if ordered.len() == members.len() {
            ordering = ChainOrdering::DeclaredFirstBlockGroup;
        } else {
            ordered.clear();
        }
    }
    if ordered.is_empty() {
        ordered = members.to_vec();
        ordered.sort_unstable();
    }

    let blocks: Vec<VideoBlock> = ordered
        .iter()
        .filter_map(|b| map.get(*b as i32))
        .filter_map(|e| to_video_block(map.partition, e))
        .collect();

    let head = ordered.first().copied().unwrap_or(0);
    let reason = if declared_first > 0 {
        format!(
            "block(s) {} declare FirstBlock {declared_first} but no traversal from a first block \
             reached them, so they were grouped by that declared relationship. Their metadata \
             survives and the bytes are physically present; they are reported as available, which \
             is not evidence of deletion",
            ordered
                .iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        format!(
            "block {head} is occupied but declares no FirstBlock and no traversal reached it, so it \
             stands alone. Its bytes are physically present; it is reported as available, which is \
             not evidence of deletion"
        )
    };

    finish_chain(
        map,
        head,
        blocks,
        ChainValidity::RecoveredFromUnreachableBlocks { reason },
        ordering,
        ChainOrigin::UnreachableBlockGroup,
        Vec::new(),
    )
}

/// Convert a validated block-table entry into a chain member.
fn to_video_block(partition: u32, entry: &BlockTableEntry) -> Option<VideoBlock> {
    let region = entry.region?;
    if region.is_empty() {
        return None;
    }
    Some(VideoBlock {
        partition,
        block_number: entry.block_number,
        physical_offset: region.offset,
        physical_length: region.length,
        region,
        entry_offset: entry.entry_offset,
        channel: entry.channel.clone(),
        start_time: entry.start_time.clone(),
        end_time: entry.end_time.clone(),
        first_block: entry.first_block,
        previous_block: entry.previous_block,
        next_block: entry.next_block,
        is_last: entry.is_last_block(),
        evidence: entry.evidence.clone(),
    })
}

/// Derive the chain's channel, time span and evidence from its blocks.
fn finish_chain(
    map: &BlockMap,
    head: u32,
    blocks: Vec<VideoBlock>,
    validity: ChainValidity,
    ordering: ChainOrdering,
    origin: ChainOrigin,
    _back_link_problems: Vec<String>,
) -> RecordingChain {
    const OP: &str = "dhfs41_recording_chain";
    let partition = map.partition;
    let chain_id = format!("dahua:p{partition}:blk{head}");

    // The head block's channel is the recording's channel. Disagreement downstream is a
    // real anomaly — a chain should not span cameras — so it is recorded, not averaged.
    let channel = blocks
        .first()
        .map(|b| b.channel.clone())
        .or_else(|| map.get(head as i32).map(|e| e.channel.clone()))
        .unwrap_or_else(|| DahuaChannel::from_dhav_field(0));

    let channel_disagreements: Vec<String> = blocks
        .iter()
        .filter(|b| !b.channel.agrees_with(&channel))
        .map(|b| {
            format!(
                "block {} reports channel {} ({}) while the chain head reports {}",
                b.block_number,
                b.channel.normalized,
                b.channel.encoding.label(),
                channel.normalized
            )
        })
        .collect();

    let start_time = blocks
        .iter()
        .filter(|b| b.start_time.is_decoded())
        .min_by_key(|b| b.start_time.unix_seconds.unwrap_or(i64::MAX))
        .map(|b| b.start_time.clone());
    let end_time = blocks
        .iter()
        .filter(|b| b.end_time.is_decoded())
        .max_by_key(|b| b.end_time.unix_seconds.unwrap_or(i64::MIN))
        .map(|b| b.end_time.clone());

    let mut notes: Vec<String> = Vec::new();
    if let Some(r) = validity.reason() {
        notes.push(r.to_string());
    }
    notes.extend(channel_disagreements.iter().cloned());

    // An end before its start is impossible; report it rather than presenting a negative
    // duration as a fact.
    if let (Some(s), Some(e)) = (&start_time, &end_time) {
        if let (Some(su), Some(eu)) = (s.unix_seconds, e.unix_seconds) {
            if eu < su {
                notes.push(format!(
                    "the chain's latest end timestamp ({eu}) precedes its earliest start ({su}); the \
                     recorded time span is not usable as a duration"
                ));
            }
        }
    }

    let total: u64 = blocks
        .iter()
        .fold(0u64, |a, b| a.saturating_add(b.physical_length));

    let mut reason = format!(
        "chain {chain_id}: {} block(s), {total} byte(s), channel {}, ordered by {}, traversal {}",
        blocks.len(),
        channel.normalized,
        ordering.label(),
        validity.label(),
    );
    if let (Some(s), Some(e)) = (
        start_time
            .as_ref()
            .and_then(|t| t.recorder_wall_clock.clone()),
        end_time
            .as_ref()
            .and_then(|t| t.recorder_wall_clock.clone()),
    ) {
        reason.push_str(&format!("; recorder clock {s} .. {e}"));
    }
    if !notes.is_empty() {
        reason.push_str("; ");
        reason.push_str(&notes.join("; "));
    }

    let kind = if blocks.is_empty() {
        ValidationStateKind::Review
    } else if matches!(validity, ChainValidity::Complete) && notes.is_empty() {
        ValidationStateKind::Pass
    } else {
        ValidationStateKind::Review
    };

    RecordingChain {
        chain_id,
        partition,
        head_block: head,
        channel,
        blocks,
        start_time,
        end_time,
        validity,
        ordering,
        origin,
        channel_disagreements,
        evidence: vs(kind, reason, OP, &format!("chain_p{partition}_blk{head}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_table::{builder::EntryBuilder, read_block_map};
    use crate::layout::tests_support::dahua_profile;
    use crate::testing::MemReader;

    const BLOCK: u64 = 2 * 1024 * 1024;
    const TABLE_AT: u64 = 4096;

    fn map_from(entries: &[[u8; 32]]) -> BlockMap {
        let p = dahua_profile();
        let video_base = TABLE_AT + 64 * 1024;
        let total = (video_base + entries.len() as u64 * BLOCK) as usize;
        let mut b = vec![0u8; total];
        b[..8].copy_from_slice(b"DHFS4.1\0");
        for (i, e) in entries.iter().enumerate() {
            let at = TABLE_AT as usize + i * 32;
            b[at..at + 32].copy_from_slice(e);
        }
        let r = MemReader::new(b);
        read_block_map(&r, &p, 0, TABLE_AT, video_base, entries.len() as u32).unwrap()
    }

    fn chains_of(entries: &[[u8; 32]]) -> Vec<RecordingChain> {
        let p = dahua_profile();
        build_chains(&map_from(entries), &p)
    }

    #[test]
    fn a_one_block_recording_is_one_chain() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .legacy_channel(2)
                .first_block(1)
                .next_block(0)
                .sector_count(64)
                .start_time(2026, 9, 22, 7, 0, 0)
                .end_time(2026, 9, 22, 7, 0, 30)
                .build(),
        ];
        let chains = chains_of(&entries);
        assert_eq!(chains.len(), 1);
        let c = &chains[0];
        assert_eq!(c.chain_id, "dahua:p0:blk1");
        assert_eq!(c.blocks.len(), 1);
        assert_eq!(c.validity, ChainValidity::Complete);
        assert_eq!(c.ordering, ChainOrdering::OemBlockChain);
        assert_eq!(c.origin, ChainOrigin::FirstBlockTraversal);
        assert_eq!(c.channel.normalized, 2);
        assert_eq!(c.total_bytes(), 64 * 512);
        assert!(c.is_fully_reconstructed());
        assert_eq!(c.evidence.state, ValidationStateKind::Pass);
    }

    #[test]
    fn a_multi_block_recording_is_traversed_in_link_order() {
        // Chain 1 -> 3 -> 2, deliberately not in ascending block order, so the test proves
        // the link relationship is followed rather than the block numbers sorted.
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(3)
                .build(),
            EntryBuilder::occupied()
                .first_block(1)
                .previous_block(3)
                .next_block(0)
                .sector_count(100)
                .build(),
            EntryBuilder::occupied()
                .first_block(1)
                .previous_block(1)
                .next_block(2)
                .build(),
        ];
        let chains = chains_of(&entries);
        assert_eq!(chains.len(), 1);
        let c = &chains[0];
        let order: Vec<u32> = c.blocks.iter().map(|b| b.block_number).collect();
        assert_eq!(order, vec![1, 3, 2], "block-chain order, not numeric order");
        assert_eq!(c.validity, ChainValidity::Complete);
        assert_eq!(c.total_bytes(), BLOCK + BLOCK + 100 * 512);
        assert!(c.blocks[0].region.offset < c.blocks[1].region.offset);
    }

    #[test]
    fn a_fragmented_recording_keeps_its_order_and_reports_non_contiguity() {
        // 1 -> 5 -> 2: physically scattered.
        let mut entries = vec![EntryBuilder::empty().build(); 6];
        entries[1] = EntryBuilder::occupied()
            .first_block(1)
            .next_block(5)
            .build();
        entries[5] = EntryBuilder::occupied()
            .first_block(1)
            .previous_block(1)
            .next_block(2)
            .build();
        entries[2] = EntryBuilder::occupied()
            .first_block(1)
            .previous_block(5)
            .next_block(0)
            .sector_count(8)
            .build();

        let chains = chains_of(&entries);
        let c = chains
            .iter()
            .find(|c| c.origin == ChainOrigin::FirstBlockTraversal)
            .unwrap();
        assert_eq!(
            c.blocks.iter().map(|b| b.block_number).collect::<Vec<_>>(),
            vec![1, 5, 2]
        );
        assert!(!c.is_physically_contiguous(), "blocks 1,5,2 are scattered");
        // Physical non-contiguity is not a validity failure.
        assert_eq!(c.validity, ChainValidity::Complete);
    }

    #[test]
    fn a_circular_reference_terminates_and_is_recorded() {
        // 1 -> 2 -> 1
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(2)
                .build(),
            EntryBuilder::occupied()
                .first_block(1)
                .previous_block(1)
                .next_block(1)
                .build(),
        ];
        let chains = chains_of(&entries);
        let c = &chains[0];
        assert!(
            matches!(c.validity, ChainValidity::Looped { .. }),
            "{:?}",
            c.validity
        );
        assert_eq!(c.blocks.len(), 2, "traversal stopped at the repeat");
        // Not discarded: the two blocks reached are still recoverable bytes.
        assert_eq!(c.total_bytes(), 2 * BLOCK);
        assert_eq!(c.evidence.state, ValidationStateKind::Review);
        assert!(c.evidence.reason.contains("already part of this chain"));
    }

    #[test]
    fn a_self_reference_terminates_immediately() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(1)
                .build(),
        ];
        let chains = chains_of(&entries);
        let c = &chains[0];
        assert!(matches!(c.validity, ChainValidity::SelfReference { .. }));
        assert_eq!(c.blocks.len(), 1);
        assert!(c.evidence.reason.contains("itself as its own NextBlock"));
    }

    #[test]
    fn an_out_of_range_next_block_is_recorded_and_the_chain_retained() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(9999)
                .build(),
        ];
        let chains = chains_of(&entries);
        let c = &chains[0];
        assert!(matches!(c.validity, ChainValidity::OutOfRangeLink { .. }));
        assert_eq!(c.blocks.len(), 1, "the reachable block is kept");
        assert!(c
            .evidence
            .reason
            .contains("outside the 2-entry block table"));
    }

    #[test]
    fn inconsistent_back_links_are_reported_without_breaking_the_chain() {
        // 1 -> 2, but block 2 claims PreviousBlock 7.
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(2)
                .build(),
            EntryBuilder::occupied()
                .first_block(1)
                .previous_block(7)
                .next_block(0)
                .sector_count(4)
                .build(),
        ];
        let chains = chains_of(&entries);
        let c = &chains[0];
        assert!(
            matches!(
                c.validity,
                ChainValidity::CompleteWithInconsistentBackLinks { .. }
            ),
            "{:?}",
            c.validity
        );
        assert_eq!(c.blocks.len(), 2, "both blocks are still recovered");
        assert_eq!(c.evidence.state, ValidationStateKind::Review);
        assert!(c.evidence.reason.contains("lists PreviousBlock 7"));
    }

    #[test]
    fn a_link_into_an_empty_slot_breaks_the_chain_without_asserting_deletion() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(2)
                .build(),
            EntryBuilder::empty().build(),
        ];
        let chains = chains_of(&entries);
        let c = &chains[0];
        assert!(matches!(
            c.validity,
            ChainValidity::BrokenAtEmptySlot { .. }
        ));
        assert!(
            c.evidence.reason.contains("not evidence of deletion"),
            "a broken link must not read as a deletion finding: {}",
            c.evidence.reason
        );
    }

    #[test]
    fn traversal_is_bounded_by_the_table_size_so_it_cannot_run_forever() {
        // Every block points to the next, and the last points to block 1 — a long cycle.
        let n = 8usize;
        let mut entries = vec![EntryBuilder::empty().build(); n];
        entries[1] = EntryBuilder::occupied()
            .first_block(1)
            .next_block(2)
            .build();
        for (i, entry) in entries.iter_mut().enumerate().take(n - 1).skip(2) {
            *entry = EntryBuilder::occupied()
                .first_block(1)
                .previous_block(i as i32 - 1)
                .next_block(i as i32 + 1)
                .build();
        }
        entries[n - 1] = EntryBuilder::occupied()
            .first_block(1)
            .previous_block(n as i32 - 2)
            .next_block(1)
            .build();

        let chains = chains_of(&entries);
        let c = &chains[0];
        assert!(matches!(c.validity, ChainValidity::Looped { .. }));
        assert!(c.blocks.len() <= n, "traversal cannot exceed the table");
    }

    #[test]
    fn unreachable_occupied_blocks_are_recovered_as_available_chains() {
        // Block 3 is occupied and declares FirstBlock 3, but its type/links make it
        // reachable only on its own; block 1's chain does not include it.
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(0)
                .sector_count(4)
                .build(),
            // Occupied, PreviousBlock set (so it is a "valid" member) but nothing links to it.
            EntryBuilder::occupied()
                .legacy_channel(4)
                .previous_block(9)
                .next_block(0)
                .sector_count(16)
                .build(),
        ];
        let chains = chains_of(&entries);
        assert_eq!(chains.len(), 2);
        let recovered = chains
            .iter()
            .find(|c| c.origin == ChainOrigin::UnreachableBlockGroup)
            .expect("the unreachable block is recovered, not dropped");
        assert_eq!(recovered.blocks.len(), 1);
        assert_eq!(recovered.blocks[0].block_number, 2);
        assert_eq!(recovered.channel.normalized, 4);
        assert!(matches!(
            recovered.validity,
            ChainValidity::RecoveredFromUnreachableBlocks { .. }
        ));
        assert!(recovered
            .evidence
            .reason
            .contains("not evidence of deletion"));
        assert!(!recovered.is_fully_reconstructed());
    }

    #[test]
    fn unreachable_blocks_sharing_a_declared_first_block_are_grouped_in_link_order() {
        // Blocks 2 and 3 both declare FirstBlock 2, linked 2 -> 3, but block 2's own entry
        // does not satisfy IsFirstBlock because FirstBlock(2) != BlockNumber(3)... it does
        // for block 2. Make the head unreachable by pointing FirstBlock at block 5, which
        // is empty, so no traversal starts.
        let mut entries = vec![EntryBuilder::empty().build(); 6];
        entries[2] = EntryBuilder::occupied()
            .legacy_channel(1)
            .first_block(5)
            .previous_block(5)
            .next_block(3)
            .build();
        entries[3] = EntryBuilder::occupied()
            .legacy_channel(1)
            .first_block(5)
            .previous_block(2)
            .next_block(0)
            .sector_count(32)
            .build();

        let chains = chains_of(&entries);
        assert_eq!(
            chains.len(),
            1,
            "no first block exists, so nothing is traversed"
        );
        let c = &chains[0];
        assert_eq!(c.origin, ChainOrigin::UnreachableBlockGroup);
        assert_eq!(
            c.blocks.iter().map(|b| b.block_number).collect::<Vec<_>>(),
            vec![2, 3],
            "grouped by declared FirstBlock and ordered by the link relationship"
        );
        assert_eq!(c.ordering, ChainOrdering::DeclaredFirstBlockGroup);
        assert_eq!(c.total_bytes(), BLOCK + 32 * 512);
    }

    #[test]
    fn empty_slots_never_become_chains() {
        let chains = chains_of(&[EntryBuilder::empty().build(); 4]);
        assert!(chains.is_empty(), "an empty table describes no recordings");
    }

    #[test]
    fn two_independent_recordings_produce_two_chains_deterministically() {
        let mut entries = vec![EntryBuilder::empty().build(); 5];
        entries[1] = EntryBuilder::occupied()
            .legacy_channel(1)
            .first_block(1)
            .next_block(2)
            .build();
        entries[2] = EntryBuilder::occupied()
            .legacy_channel(1)
            .first_block(1)
            .previous_block(1)
            .next_block(0)
            .sector_count(4)
            .build();
        entries[3] = EntryBuilder::occupied()
            .legacy_channel(2)
            .first_block(3)
            .next_block(0)
            .sector_count(8)
            .build();

        let p = dahua_profile();
        let map = map_from(&entries);
        let a = build_chains(&map, &p);
        let b = build_chains(&map, &p);
        assert_eq!(a.len(), 2);
        assert_eq!(
            a.iter().map(|c| c.chain_id.clone()).collect::<Vec<_>>(),
            b.iter().map(|c| c.chain_id.clone()).collect::<Vec<_>>(),
            "chain construction must be deterministic"
        );
        assert_eq!(a[0].channel.normalized, 1);
        assert_eq!(a[1].channel.normalized, 2);
        assert!(a.iter().all(|c| c.validity == ChainValidity::Complete));
    }

    #[test]
    fn a_channel_disagreement_inside_a_chain_is_recorded() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .legacy_channel(1)
                .first_block(1)
                .next_block(2)
                .build(),
            EntryBuilder::occupied()
                .legacy_channel(7)
                .first_block(1)
                .previous_block(1)
                .next_block(0)
                .sector_count(4)
                .build(),
        ];
        let chains = chains_of(&entries);
        let c = &chains[0];
        assert_eq!(
            c.channel.normalized, 1,
            "the head block defines the channel"
        );
        assert_eq!(c.channel_disagreements.len(), 1);
        assert!(c.evidence.reason.contains("reports channel 7"));
        assert_eq!(c.evidence.state, ValidationStateKind::Review);
    }

    #[test]
    fn an_end_before_its_start_is_flagged_rather_than_presented_as_a_duration() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(0)
                .sector_count(4)
                .start_time(2026, 9, 22, 10, 0, 0)
                .end_time(2026, 9, 22, 9, 0, 0)
                .build(),
        ];
        let chains = chains_of(&entries);
        assert!(chains[0]
            .evidence
            .reason
            .contains("precedes its earliest start"));
        assert_eq!(chains[0].evidence.state, ValidationStateKind::Review);
    }

    #[test]
    fn a_chain_time_span_comes_from_the_blocks_not_from_wall_clock() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(2)
                .start_time(2026, 9, 22, 6, 0, 0)
                .end_time(2026, 9, 22, 6, 10, 0)
                .build(),
            EntryBuilder::occupied()
                .first_block(1)
                .previous_block(1)
                .next_block(0)
                .sector_count(4)
                .start_time(2026, 9, 22, 6, 10, 0)
                .end_time(2026, 9, 22, 6, 20, 0)
                .build(),
        ];
        let chains = chains_of(&entries);
        let c = &chains[0];
        assert_eq!(
            c.start_time
                .as_ref()
                .unwrap()
                .recorder_wall_clock
                .as_deref(),
            Some("2026-09-22T06:00:00")
        );
        assert_eq!(
            c.end_time.as_ref().unwrap().recorder_wall_clock.as_deref(),
            Some("2026-09-22T06:20:00")
        );
    }

    #[test]
    fn a_chain_with_no_decodable_timestamps_has_none_rather_than_the_epoch() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(0)
                .sector_count(4)
                .build(),
        ];
        let chains = chains_of(&entries);
        assert!(chains[0].start_time.is_none());
        assert!(chains[0].end_time.is_none());
    }
}
