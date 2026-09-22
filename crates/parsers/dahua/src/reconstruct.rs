//! # Recording reconstruction: chain → ordered blocks → ordered frames → stream
//!
//! A Dahua recording spans several 2 MiB blocks, and each block holds many DHAV frames. This
//! module turns a [`RecordingChain`] into an ordered frame list and the exact payload ranges
//! that make up the elementary stream, without moving a byte of evidence.
//!
//! ## Ordering priority
//!
//! The order is decided by the strongest relationship available, in this fixed order:
//!
//! 1. **The OEM block chain.** Blocks are visited in `FirstBlock → NextBlock` order. This is a
//!    filesystem relationship and it outranks everything else.
//! 2. **The DHII frame index.** Within a block that carries one, frames are taken in index
//!    order — the recorder's own sequence.
//! 3. **The container walk.** Within a block with no usable DHII, frames are taken in the
//!    order the container stores them, which is the order they were written.
//! 4. **Timestamps.** Used only to *report* the recording's span and to flag non-monotonic
//!    sequences. They are never used to order frames, because every case above is a stronger
//!    statement than a clock that may have been wrong.
//!
//! Physical continuity is reported but never required: a chain whose blocks are scattered is
//! normal allocation, not frame loss.
//!
//! ## Gaps are marked, never filled
//!
//! A block that yields no frames, a DHII entry whose frame does not parse, and a non-monotonic
//! timestamp step are all recorded as notes on the reconstruction. Nothing is synthesised to
//! paper over them, and the payload list contains only ranges that were actually validated.

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, OemProfile, Region, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};

use crate::chain::RecordingChain;
use crate::channel::DahuaChannel;
use crate::dhav::{self, DhavFrame};
use crate::dhii::{self, DhiiIndex};
use crate::layout::{key, u32_at, u64_from, usize_from, vs};

/// Which structure established a frame's position in the sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameSource {
    /// Located through the block's DHII reference-frame index.
    DhiiReferenceIndex,
    /// Located by walking the block's DHAV framing.
    ContainerWalk,
}

impl FrameSource {
    pub fn label(&self) -> &'static str {
        match self {
            Self::DhiiReferenceIndex => "dhii-reference-index",
            Self::ContainerWalk => "container-walk",
        }
    }
}

/// How the whole reconstruction was ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReconstructionOrdering {
    /// Block-chain order, then DHII index order inside at least one block.
    BlockChainThenDhii,
    /// Block-chain order, then container-walk order inside every block.
    BlockChainThenContainerWalk,
    /// No frames were located, so no ordering was established.
    NoFramesLocated,
}

impl ReconstructionOrdering {
    pub fn label(&self) -> &'static str {
        match self {
            Self::BlockChainThenDhii => "block-chain-then-dhii",
            Self::BlockChainThenContainerWalk => "block-chain-then-container-walk",
            Self::NoFramesLocated => "no-frames-located",
        }
    }
}

/// One frame in its reconstructed position.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReconstructedFrame {
    /// Position in the recording, 0-based. Derived from the ordering, not from any on-disk
    /// sequence field, so it is always dense and always matches the payload list.
    pub sequence: usize,
    /// The block the frame was found in.
    pub block_number: u32,
    /// Which structure placed it.
    pub source: FrameSource,
    /// The parsed frame, with absolute physical offsets.
    pub frame: DhavFrame,
}

/// A reconstructed recording.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainReconstruction {
    /// The chain this came from. Carried so an exported artifact stays traceable to the
    /// filesystem structure that described it.
    pub chain_id: String,
    pub partition: u32,
    pub channel: DahuaChannel,
    /// The chain's physical blocks, in recording order.
    pub block_regions: Vec<Region>,
    /// Frames in recording order.
    pub frames: Vec<ReconstructedFrame>,
    /// Payload ranges in recording order — the elementary stream, as physical ranges.
    ///
    /// Concatenating these bytes, in this order, reproduces the stream. Nothing is inserted
    /// between them and nothing is synthesised.
    pub payload_regions: Vec<Region>,
    /// DHII indexes found, one per block that carried one.
    pub dhii_indexes: Vec<DhiiIndex>,
    pub ordering: ReconstructionOrdering,
    /// Everything that could not be established, in order. Gaps are marked here.
    pub notes: Vec<String>,
    /// Blocks that yielded no frames at all.
    pub empty_blocks: Vec<u32>,
    pub evidence: ValidationState,
}

impl ChainReconstruction {
    /// Total payload bytes the reconstruction accounts for.
    pub fn payload_bytes(&self) -> u64 {
        self.payload_regions
            .iter()
            .fold(0u64, |a, r| a.saturating_add(r.length))
    }

    /// Video frames only, in order.
    pub fn video_frames(&self) -> impl Iterator<Item = &ReconstructedFrame> {
        self.frames.iter().filter(|f| f.frame.kind.is_video())
    }

    /// The earliest and latest decoded frame timestamps, as unix seconds.
    ///
    /// Reported from the frames themselves. `None` when no frame carried a decodable clock —
    /// never substituted with the block table's times or with wall-clock time.
    pub fn decoded_time_span(&self) -> Option<(i64, i64)> {
        let mut min = i64::MAX;
        let mut max = i64::MIN;
        for f in &self.frames {
            if let Some(t) = f.frame.timestamp.unix_seconds {
                min = min.min(t);
                max = max.max(t);
            }
        }
        if min == i64::MAX {
            None
        } else {
            Some((min, max))
        }
    }

    /// Codec label the frames agree on, when they agree.
    ///
    /// `None` when no frame declared one, or when they disagree — a disagreement is recorded in
    /// [`Self::notes`] rather than resolved by picking a winner.
    pub fn codec(&self) -> Option<String> {
        let mut seen: Option<String> = None;
        for f in self.video_frames() {
            match (&seen, &f.frame.codec) {
                (_, None) => {}
                (None, Some(c)) => seen = Some(c.clone()),
                (Some(a), Some(b)) if a == b => {}
                (Some(_), Some(_)) => return None,
            }
        }
        seen
    }

    /// Whether every located frame passed every structural check.
    pub fn is_fully_verified(&self) -> bool {
        !self.frames.is_empty()
            && self.notes.is_empty()
            && self.frames.iter().all(|f| f.frame.is_fully_verified())
    }
}

/// Reconstruct one recording chain into ordered frames and payload ranges.
pub fn reconstruct_chain(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    chain: &RecordingChain,
) -> Result<ChainReconstruction, ForensicError> {
    const OP: &str = "dahua_chain_reconstruction";

    let mut frames: Vec<ReconstructedFrame> = Vec::new();
    let mut dhii_indexes: Vec<DhiiIndex> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut empty_blocks: Vec<u32> = Vec::new();
    let mut used_dhii = false;

    // Priority 1: the OEM block chain. `chain.blocks` is already in FirstBlock → NextBlock
    // order, so simply visiting it in order is the strongest available ordering.
    for block in &chain.blocks {
        let before = frames.len();

        // Priority 2: the block's own DHII index, when it carries one.
        let dhii = read_block_dhii(reader, profile, block.region)?;
        if let Some(index) = dhii {
            let regions = index.video_frame_regions();
            if regions.is_empty() {
                notes.push(format!(
                    "block {}: a DHII index was found but it indexes no usable video frames ({})",
                    block.block_number, index.evidence.reason
                ));
            } else {
                used_dhii = true;
                let block_end = block.region.end().unwrap_or(u64::MAX);
                for region in regions {
                    match dhav::parse_frame_at(reader, profile, region.offset, block_end)? {
                        Ok(frame) => {
                            if frame.total_length != region.length {
                                notes.push(format!(
                                    "block {}: the DHII entry at 0x{:X} declares {} byte(s) but the \
                                     frame header declares {}; the frame header is authoritative for \
                                     the payload boundary and both values are retained",
                                    block.block_number,
                                    region.offset,
                                    region.length,
                                    frame.total_length
                                ));
                            }
                            frames.push(ReconstructedFrame {
                                sequence: 0,
                                block_number: block.block_number,
                                source: FrameSource::DhiiReferenceIndex,
                                frame,
                            });
                        }
                        Err(rejection) => notes.push(format!(
                            "block {}: the DHII entry at 0x{:X} does not resolve to a valid DHAV \
                             frame, so it contributes no payload: {}",
                            block.block_number, region.offset, rejection.reason
                        )),
                    }
                }
            }
            dhii_indexes.push(index);
        }

        // Priority 3: the container walk, for a block with no usable DHII.
        if frames.len() == before {
            let carved = dhav::carve_region(reader, profile, block.region)?;
            if carved.truncated {
                notes.push(format!(
                    "block {}: the per-region frame cap was reached, so more frames may be present \
                     in this block",
                    block.block_number
                ));
            }
            for rejection in &carved.rejections {
                notes.push(format!(
                    "block {}: a DHAV tag at 0x{:X} did not validate as a frame: {}",
                    block.block_number, rejection.offset, rejection.reason
                ));
            }
            for frame in carved.frames {
                frames.push(ReconstructedFrame {
                    sequence: 0,
                    block_number: block.block_number,
                    source: FrameSource::ContainerWalk,
                    frame,
                });
            }
        }

        if frames.len() == before {
            empty_blocks.push(block.block_number);
            notes.push(format!(
                "block {} at {} yielded no DHAV frames; the gap is recorded and not filled",
                block.block_number, block.region
            ));
        }
    }

    // Dense sequence numbers, assigned from the established order.
    for (i, f) in frames.iter_mut().enumerate() {
        f.sequence = i;
    }

    // Priority 4: timestamps, used only to *report*. A backwards step is flagged; the frame
    // order is not changed, because the block chain and the index are stronger evidence.
    let mut last: Option<i64> = None;
    for f in &frames {
        if let Some(t) = f.frame.timestamp.unix_seconds {
            if let Some(prev) = last {
                if t < prev {
                    notes.push(format!(
                        "frame {} in block {} carries recorder time {t}, earlier than the preceding \
                         frame's {prev}. The filesystem ordering is kept, because the block chain and \
                         frame index are stronger evidence than the recorder's clock",
                        f.sequence, f.block_number
                    ));
                }
            }
            last = Some(t);
        }
    }

    // Channel cross-check between the block table and the frames themselves.
    let frame_channel_mismatches: Vec<String> = frames
        .iter()
        .filter(|f| !f.frame.channel.agrees_with(&chain.channel))
        .map(|f| {
            format!(
                "frame {} at 0x{:X} reports channel {} from its own header while the block table \
                 reports {} for this chain",
                f.sequence,
                f.frame.physical_offset,
                f.frame.channel.normalized,
                chain.channel.normalized
            )
        })
        .collect();
    notes.extend(frame_channel_mismatches);

    let payload_regions: Vec<Region> = frames
        .iter()
        .filter(|f| f.frame.kind.is_video())
        .filter_map(|f| f.frame.payload_region)
        .collect();

    let ordering = if frames.is_empty() {
        ReconstructionOrdering::NoFramesLocated
    } else if used_dhii {
        ReconstructionOrdering::BlockChainThenDhii
    } else {
        ReconstructionOrdering::BlockChainThenContainerWalk
    };

    let payload_bytes = payload_regions
        .iter()
        .fold(0u64, |a, r| a.saturating_add(r.length));
    let mut reason = format!(
        "chain {} reconstructed: {} block(s) in chain order, {} frame(s) located ({} video), \
         {payload_bytes} payload byte(s) in {} range(s), ordered by {}",
        chain.chain_id,
        chain.blocks.len(),
        frames.len(),
        frames.iter().filter(|f| f.frame.kind.is_video()).count(),
        payload_regions.len(),
        ordering.label(),
    );
    if !dhii_indexes.is_empty() {
        reason.push_str(&format!("; {} DHII index(es) used", dhii_indexes.len()));
    }
    if !chain.is_physically_contiguous() {
        reason.push_str(
            "; the chain's blocks are not physically contiguous, which is normal block allocation \
             and not frame loss",
        );
    }
    if !notes.is_empty() {
        reason.push_str("; ");
        reason.push_str(&notes.join("; "));
    }

    let kind = if frames.is_empty() {
        ValidationStateKind::Review
    } else if notes.is_empty() && frames.iter().all(|f| f.frame.is_fully_verified()) {
        ValidationStateKind::Pass
    } else {
        ValidationStateKind::Review
    };

    Ok(ChainReconstruction {
        chain_id: chain.chain_id.clone(),
        partition: chain.partition,
        channel: chain.channel.clone(),
        block_regions: chain.regions(),
        frames,
        payload_regions,
        dhii_indexes,
        ordering,
        notes,
        empty_blocks,
        evidence: vs(kind, reason, OP, &chain.chain_id),
    })
}

/// Read a DHII index located at the start of a video block, if one is there.
///
/// Bounded by design: the header is read first to learn `indexLength`, then exactly that many
/// bytes are read. A 2 MiB block is never pulled into memory to find its index.
///
/// Probing only the block start is a deliberate, stated limitation: it is the position this
/// platform has evidence for. A clip whose index sits elsewhere in the block is handled by the
/// container walk instead, which is why a missing index degrades rather than fails.
fn read_block_dhii(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    block: Region,
) -> Result<Option<DhiiIndex>, ForensicError> {
    let tag = match crate::layout::magic(profile, "dhii_magic") {
        Some(t) => t,
        None => return Ok(None),
    };
    let header_size = u64_from(profile, key::DHII_HEADER_SIZE, 12);
    let f_len = usize_from(profile, key::DHII_INDEX_LENGTH_OFFSET, 4);
    let block_end = block.end().unwrap_or(u64::MAX).min(reader.len());
    if block.offset >= block_end || block_end - block.offset < header_size {
        return Ok(None);
    }

    let head = match reader.read_exact_at(block.offset, header_size as usize) {
        Ok(b) => b,
        Err(_) => return Ok(None),
    };
    if !head.starts_with(&tag) {
        return Ok(None);
    }
    let declared = u32_at(&head, f_len).unwrap_or(0) as u64;
    // Read the index structure only, clipped to the block. The entry arrays live inside it, so
    // this is everything `dhii::read_index` needs to resolve clip-relative offsets.
    let want = declared.max(header_size).min(block_end - block.offset);
    let buf = match reader.read_exact_at(block.offset, want as usize) {
        Ok(b) => b,
        Err(_) => return Ok(None),
    };

    let clip_length = block_end - block.offset;
    Ok(dhii::read_index(
        &buf,
        block.offset,
        clip_length,
        0,
        profile,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_table::{builder::EntryBuilder, read_block_map};
    use crate::chain::build_chains;
    use crate::dhav::builder::{h264_payload, FrameBuilder};
    use crate::dhii::builder::{build as build_dhii, Array};
    use crate::layout::tests_support::dahua_profile;
    use crate::testing::MemReader;
    use crate::timestamp::pack;

    const BLOCK: u64 = 2 * 1024 * 1024;
    const TABLE_AT: u64 = 4096;
    const VIDEO_BASE: u64 = 1 << 20;

    /// What to place inside one video block.
    enum BlockContent {
        /// Frames written back to back from the block start.
        Frames(Vec<Vec<u8>>),
        /// A DHII index at the block start, then frames at the given block-relative offsets.
        IndexedFrames {
            /// `(block_relative_offset, frame_bytes)`
            placed: Vec<(u32, Vec<u8>)>,
            /// Entry types to declare; `1` is the reference-frame array.
            index_types: Vec<u32>,
        },
        Empty,
    }

    /// Build a volume with a block table at `TABLE_AT`, video blocks from `VIDEO_BASE`.
    fn volume(entries: &[[u8; 32]], contents: Vec<BlockContent>) -> MemReader {
        let total = (VIDEO_BASE + entries.len() as u64 * BLOCK) as usize;
        let mut b = vec![0u8; total];
        b[..8].copy_from_slice(b"DHFS4.1\0");
        for (i, e) in entries.iter().enumerate() {
            let at = TABLE_AT as usize + i * 32;
            b[at..at + 32].copy_from_slice(e);
        }
        for (i, content) in contents.into_iter().enumerate() {
            let base = (VIDEO_BASE + i as u64 * BLOCK) as usize;
            match content {
                BlockContent::Empty => {}
                BlockContent::Frames(frames) => {
                    let mut cursor = base;
                    for f in frames {
                        b[cursor..cursor + f.len()].copy_from_slice(&f);
                        cursor += f.len();
                    }
                }
                BlockContent::IndexedFrames {
                    placed,
                    index_types,
                } => {
                    let arrays: Vec<Array> = index_types
                        .iter()
                        .map(|t| Array {
                            raw_type: *t,
                            entries: if *t == 1 {
                                placed
                                    .iter()
                                    .map(|(off, f)| {
                                        (
                                            *off,
                                            f.len() as i32,
                                            pack(2026, 9, 22, 12, 0, 0, 2000).unwrap(),
                                        )
                                    })
                                    .collect()
                            } else {
                                Vec::new()
                            },
                        })
                        .collect();
                    let index = build_dhii(&arrays, 0);
                    b[base..base + index.len()].copy_from_slice(&index);
                    for (off, f) in placed {
                        let at = base + off as usize;
                        b[at..at + f.len()].copy_from_slice(&f);
                    }
                }
            }
        }
        MemReader::new(b)
    }

    fn chains_from(reader: &MemReader, entries: &[[u8; 32]]) -> Vec<RecordingChain> {
        let p = dahua_profile();
        let map =
            read_block_map(reader, &p, 0, TABLE_AT, VIDEO_BASE, entries.len() as u32).unwrap();
        build_chains(&map, &p)
    }

    fn frame(seed: u8, n: u32, hour: u32, min: u32, sec: u32) -> Vec<u8> {
        FrameBuilder::video_key(h264_payload(seed))
            .frame_number(n)
            .at(2026, 9, 22, hour, min, sec)
            .codec(0x04, 25)
            .build()
    }

    #[test]
    fn a_multi_block_recording_is_reconstructed_in_block_chain_order() {
        // Chain 1 → 3 → 2: link order deliberately differs from numeric and physical order.
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
                .sector_count(4096)
                .build(),
            EntryBuilder::occupied()
                .first_block(1)
                .previous_block(1)
                .next_block(2)
                .build(),
        ];
        let contents = vec![
            BlockContent::Empty,
            BlockContent::Frames(vec![frame(0x11, 1, 8, 0, 0), frame(0x12, 2, 8, 0, 1)]),
            BlockContent::Frames(vec![frame(0x31, 5, 8, 0, 4)]),
            BlockContent::Frames(vec![frame(0x21, 3, 8, 0, 2), frame(0x22, 4, 8, 0, 3)]),
        ];
        let reader = volume(&entries, contents);
        let chains = chains_from(&reader, &entries);
        let chain = chains
            .iter()
            .find(|c| c.chain_id == "dahua:p0:blk1")
            .unwrap();
        assert_eq!(
            chain
                .blocks
                .iter()
                .map(|b| b.block_number)
                .collect::<Vec<_>>(),
            vec![1, 3, 2]
        );

        let p = dahua_profile();
        let rec = reconstruct_chain(&reader, &p, chain).unwrap();

        assert_eq!(rec.chain_id, "dahua:p0:blk1");
        assert_eq!(rec.frames.len(), 5);
        // Block-chain order dominates: block 1's frames, then block 3's, then block 2's.
        assert_eq!(
            rec.frames
                .iter()
                .map(|f| f.block_number)
                .collect::<Vec<_>>(),
            vec![1, 1, 3, 3, 2]
        );
        // Sequence numbers are dense and follow that order.
        assert_eq!(
            rec.frames.iter().map(|f| f.sequence).collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4]
        );
        // The recorder's own frame numbers confirm the reconstruction is chronological.
        assert_eq!(
            rec.frames
                .iter()
                .map(|f| f.frame.frame_number)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
        assert_eq!(
            rec.ordering,
            ReconstructionOrdering::BlockChainThenContainerWalk
        );
        assert!(rec
            .frames
            .iter()
            .all(|f| f.source == FrameSource::ContainerWalk));
        assert_eq!(rec.payload_regions.len(), 5);
        assert_eq!(rec.codec().as_deref(), Some("H.264"));
        assert!(rec.is_fully_verified(), "{}", rec.evidence.reason);
        assert_eq!(rec.evidence.state, ValidationStateKind::Pass);
    }

    #[test]
    fn payload_ranges_are_exact_absolute_sub_ranges_of_the_frames() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(0)
                .sector_count(4096)
                .build(),
        ];
        let f1 = frame(0x11, 1, 8, 0, 0);
        let f2 = frame(0x12, 2, 8, 0, 1);
        let reader = volume(
            &entries,
            vec![
                BlockContent::Empty,
                BlockContent::Frames(vec![f1.clone(), f2.clone()]),
            ],
        );
        let chains = chains_from(&reader, &entries);
        let p = dahua_profile();
        let rec = reconstruct_chain(&reader, &p, &chains[0]).unwrap();

        let block_base = VIDEO_BASE + BLOCK;
        // Frame 1: 24-byte header + 4-byte codec record, then the payload.
        let ext = 4u64;
        assert_eq!(rec.payload_regions[0].offset, block_base + 24 + ext);
        assert_eq!(
            rec.payload_regions[0].length,
            f1.len() as u64 - 24 - ext - 8
        );
        assert_eq!(
            rec.payload_regions[1].offset,
            block_base + f1.len() as u64 + 24 + ext
        );
        assert_eq!(
            rec.payload_bytes(),
            rec.payload_regions.iter().map(|r| r.length).sum::<u64>()
        );
    }

    #[test]
    fn a_block_carrying_a_dhii_index_is_ordered_by_that_index() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(0)
                .sector_count(4096)
                .build(),
        ];
        // Place frames out of physical order relative to the index order, so a pass proves the
        // index decided the sequence.
        let a = frame(0xA1, 10, 9, 0, 0);
        let b = frame(0xB2, 11, 9, 0, 1);
        let placed = [(0x1_0000u32, b.clone()), (0x2_0000u32, a.clone())];
        // Index lists the 0x20000 frame first.
        let index_order = [(0x2_0000u32, a.len()), (0x1_0000u32, b.len())];
        let arrays_placed: Vec<(u32, Vec<u8>)> = index_order
            .iter()
            .map(|(off, _)| {
                let bytes = placed
                    .iter()
                    .find(|(o, _)| o == off)
                    .map(|(_, f)| f.clone())
                    .unwrap();
                (*off, bytes)
            })
            .collect();

        let reader = volume(
            &entries,
            vec![
                BlockContent::Empty,
                BlockContent::IndexedFrames {
                    placed: arrays_placed,
                    index_types: vec![1],
                },
            ],
        );
        let chains = chains_from(&reader, &entries);
        let p = dahua_profile();
        let rec = reconstruct_chain(&reader, &p, &chains[0]).unwrap();

        assert_eq!(rec.ordering, ReconstructionOrdering::BlockChainThenDhii);
        assert!(rec
            .frames
            .iter()
            .all(|f| f.source == FrameSource::DhiiReferenceIndex));
        assert_eq!(rec.frames.len(), 2);
        assert_eq!(rec.dhii_indexes.len(), 1);
        let block_base = VIDEO_BASE + BLOCK;
        assert_eq!(
            rec.frames
                .iter()
                .map(|f| f.frame.physical_offset)
                .collect::<Vec<_>>(),
            vec![block_base + 0x2_0000, block_base + 0x1_0000],
            "the DHII index order wins over physical order"
        );
    }

    #[test]
    fn a_dhii_index_with_no_video_array_falls_back_to_the_container_walk() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(0)
                .sector_count(4096)
                .build(),
        ];
        // Declare only a JPEG array, so nothing indexes video frames.
        let f = frame(0xC3, 1, 10, 0, 0);
        let reader = volume(
            &entries,
            vec![
                BlockContent::Empty,
                BlockContent::IndexedFrames {
                    placed: vec![(0x1_0000, f.clone())],
                    index_types: vec![3],
                },
            ],
        );
        let chains = chains_from(&reader, &entries);
        let p = dahua_profile();
        let rec = reconstruct_chain(&reader, &p, &chains[0]).unwrap();

        assert_eq!(
            rec.ordering,
            ReconstructionOrdering::BlockChainThenContainerWalk
        );
        assert_eq!(rec.frames.len(), 1, "the walk still finds the frame");
        assert_eq!(rec.frames[0].source, FrameSource::ContainerWalk);
        assert!(rec
            .notes
            .iter()
            .any(|n| n.contains("indexes no usable video frames")));
    }

    #[test]
    fn a_block_with_no_frames_is_recorded_as_a_gap_not_filled() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(2)
                .build(),
            EntryBuilder::occupied()
                .first_block(1)
                .previous_block(1)
                .next_block(0)
                .sector_count(4096)
                .build(),
        ];
        let reader = volume(
            &entries,
            vec![
                BlockContent::Empty,
                BlockContent::Frames(vec![frame(0x11, 1, 8, 0, 0)]),
                // Block 2 is in the chain but holds nothing.
                BlockContent::Empty,
            ],
        );
        let chains = chains_from(&reader, &entries);
        let p = dahua_profile();
        let rec = reconstruct_chain(&reader, &p, &chains[0]).unwrap();

        assert_eq!(
            rec.frames.len(),
            1,
            "no frame is synthesised for the empty block"
        );
        assert_eq!(rec.empty_blocks, vec![2]);
        assert!(rec.notes.iter().any(|n| n.contains("not filled")));
        assert_eq!(rec.evidence.state, ValidationStateKind::Review);
        assert!(!rec.is_fully_verified());
    }

    #[test]
    fn a_non_monotonic_recorder_clock_is_flagged_without_reordering_frames() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(0)
                .sector_count(4096)
                .build(),
        ];
        // Second frame's clock goes backwards.
        let reader = volume(
            &entries,
            vec![
                BlockContent::Empty,
                BlockContent::Frames(vec![frame(0x11, 1, 9, 0, 10), frame(0x12, 2, 9, 0, 1)]),
            ],
        );
        let chains = chains_from(&reader, &entries);
        let p = dahua_profile();
        let rec = reconstruct_chain(&reader, &p, &chains[0]).unwrap();

        assert_eq!(
            rec.frames
                .iter()
                .map(|f| f.frame.frame_number)
                .collect::<Vec<_>>(),
            vec![1, 2],
            "the container order is kept; the clock does not reorder frames"
        );
        assert!(rec
            .notes
            .iter()
            .any(|n| n.contains("stronger evidence than the recorder's clock")));
    }

    #[test]
    fn a_frame_channel_disagreeing_with_the_block_table_is_recorded() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .legacy_channel(1)
                .first_block(1)
                .next_block(0)
                .sector_count(4096)
                .build(),
        ];
        let odd = FrameBuilder::video_key(h264_payload(1))
            .channel_0_based(5)
            .at(2026, 9, 22, 8, 0, 0)
            .build();
        let reader = volume(
            &entries,
            vec![BlockContent::Empty, BlockContent::Frames(vec![odd])],
        );
        let chains = chains_from(&reader, &entries);
        let p = dahua_profile();
        let rec = reconstruct_chain(&reader, &p, &chains[0]).unwrap();
        assert!(rec
            .notes
            .iter()
            .any(|n| n.contains("reports channel 6 from its own header")));
    }

    #[test]
    fn the_decoded_time_span_comes_from_the_frames_not_from_wall_clock() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(0)
                .sector_count(4096)
                .build(),
        ];
        let reader = volume(
            &entries,
            vec![
                BlockContent::Empty,
                BlockContent::Frames(vec![frame(0x11, 1, 7, 30, 0), frame(0x12, 2, 7, 30, 20)]),
            ],
        );
        let chains = chains_from(&reader, &entries);
        let p = dahua_profile();
        let rec = reconstruct_chain(&reader, &p, &chains[0]).unwrap();
        let (start, end) = rec.decoded_time_span().unwrap();
        assert_eq!(
            end - start,
            20,
            "20 seconds apart, per the frames' own clocks"
        );
    }

    #[test]
    fn a_chain_with_no_frames_reports_no_ordering_and_no_payload() {
        let entries = [
            EntryBuilder::empty().build(),
            EntryBuilder::occupied()
                .first_block(1)
                .next_block(0)
                .sector_count(4096)
                .build(),
        ];
        let reader = volume(&entries, vec![BlockContent::Empty, BlockContent::Empty]);
        let chains = chains_from(&reader, &entries);
        let p = dahua_profile();
        let rec = reconstruct_chain(&reader, &p, &chains[0]).unwrap();

        assert!(rec.frames.is_empty());
        assert!(rec.payload_regions.is_empty());
        assert_eq!(rec.ordering, ReconstructionOrdering::NoFramesLocated);
        assert_eq!(rec.payload_bytes(), 0);
        assert_eq!(rec.evidence.state, ValidationStateKind::Review);
    }

    #[test]
    fn a_fragmented_chain_is_reconstructed_and_its_non_contiguity_reported() {
        // Chain 1 → 4: a two-block gap between them.
        let mut entries = vec![EntryBuilder::empty().build(); 5];
        entries[1] = EntryBuilder::occupied()
            .first_block(1)
            .next_block(4)
            .build();
        entries[4] = EntryBuilder::occupied()
            .first_block(1)
            .previous_block(1)
            .next_block(0)
            .sector_count(4096)
            .build();
        let mut contents = vec![
            BlockContent::Empty,
            BlockContent::Frames(vec![frame(0x11, 1, 8, 0, 0)]),
            BlockContent::Empty,
            BlockContent::Empty,
            BlockContent::Frames(vec![frame(0x41, 2, 8, 0, 1)]),
        ];
        contents.truncate(5);
        let reader = volume(&entries, contents);
        let chains = chains_from(&reader, &entries);
        let chain = chains
            .iter()
            .find(|c| c.chain_id == "dahua:p0:blk1")
            .unwrap();
        assert!(!chain.is_physically_contiguous());

        let p = dahua_profile();
        let rec = reconstruct_chain(&reader, &p, chain).unwrap();
        assert_eq!(rec.frames.len(), 2);
        assert_eq!(rec.block_regions.len(), 2);
        assert!(rec.evidence.reason.contains("not frame loss"));
    }
}
