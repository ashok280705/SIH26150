//! # Recording reconstruction
//!
//! Turns filesystem facts into an ordered, exportable stream:
//!
//! ```text
//!   B-tree entry → video block → block footer → clip → MPEG-PS/PES parts
//!                → video payload ranges → Recording
//! ```
//!
//! ## Ordering priority
//!
//! Clips and their payload are ordered by the strongest available evidence, and the basis
//! actually used is recorded on the result so an examiner can see which one applied:
//!
//! 1. **Filesystem / B-tree relationship** — the authoritative entry that references a clip
//!    fixes its place in the recording.
//! 2. **Clip metadata** — the footer index's own slot order within a block, and block number
//!    across blocks.
//! 3. **Frame serial** — the pack-header serials inside a clip's container.
//! 4. **Timestamps** — used only to *join* clips into one recording and to report a span;
//!    never to reorder bytes, because a recorder with a mis-set clock would then scramble
//!    the stream.
//! 5. **Physical continuity** — adjacency in the video-data region.
//! 6. Weaker heuristics are not applied at all. Where nothing above resolves an order, the
//!    ambiguity is recorded rather than broken arbitrarily.
//!
//! ## Multi-block recordings
//!
//! A recording that outgrew one 1 GiB block continues in the next. Clips are therefore
//! joined across blocks when the same channel continues within the profile's join gap, and
//! the resulting [`RecordingReconstruction::blocks`] lists every block involved.
//!
//! ## Gaps are marked, never filled
//!
//! A missing clip, a clip whose container walk failed, or a channel disagreement is recorded
//! in [`RecordingReconstruction::notes`]. No byte is ever synthesised to bridge a gap.

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, OemProfile, Region, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::block::ClipRecord;
use crate::layout::{i64_from, key, u64_from, vs};
use crate::ps::{self, ClipStream, CodecEvidence, HikCodec};
use crate::volume::{ClassifiedBlock, HikvisionVolume};

/// What fixed the order of the clips in a reconstruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordingOrdering {
    /// A single clip: nothing to order.
    SingleClip,
    /// Authoritative B-tree entries ordered the clips.
    BTreeEntryOrder,
    /// The footer clip index's slot order, within and across blocks.
    ClipIndexOrder,
    /// Physical adjacency in the video-data region, where the index gave no order.
    PhysicalContinuity,
    /// No clip could be located.
    NoClipsLocated,
}

impl RecordingOrdering {
    pub fn label(&self) -> &'static str {
        match self {
            Self::SingleClip => "single-clip",
            Self::BTreeEntryOrder => "btree-entry-order",
            Self::ClipIndexOrder => "clip-index-order",
            Self::PhysicalContinuity => "physical-continuity",
            Self::NoClipsLocated => "no-clips-located",
        }
    }
}

/// One clip in its reconstructed position.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReconstructedClip {
    /// Position in the recording, from 0.
    pub sequence: usize,
    pub block_number: u32,
    pub clip: ClipRecord,
    /// The container walk over this clip.
    pub stream: ClipStream,
    /// What placed this clip at this position.
    pub order_basis: String,
}

impl ReconstructedClip {
    /// Video payload ranges from this clip, in stream order.
    pub fn payload_regions(&self) -> &[Region] {
        &self.stream.payload_regions
    }
}

/// An ordered, exportable Hikvision recording.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordingReconstruction {
    /// Stable id: the id of the seed clip the reconstruction was built around.
    pub recording_id: String,
    /// Channel, when every clip agrees on one.
    pub channel: Option<u32>,
    /// Clips in recording order.
    pub clips: Vec<ReconstructedClip>,
    /// Physical extents of the clips, in order.
    pub clip_regions: Vec<Region>,
    /// Ordered video payload ranges. Concatenating these yields the elementary stream.
    pub payload_regions: Vec<Region>,
    /// Block numbers involved, ascending.
    pub blocks: Vec<u32>,
    pub ordering: RecordingOrdering,
    /// Codec, decided from the reconstructed payload.
    pub codec: CodecEvidence,
    /// Recorder clock span, when both ends decoded. Reported, never used to reorder.
    pub decoded_time_span: Option<(i64, i64)>,
    /// Whether every clip's block is referenced by the authoritative index.
    pub fully_accessible: bool,
    /// Gaps, disagreements and failures. Marked, never filled.
    pub notes: Vec<String>,
    pub evidence: ValidationState,
}

impl RecordingReconstruction {
    /// Total elementary-stream bytes located.
    pub fn payload_bytes(&self) -> u64 {
        self.payload_regions
            .iter()
            .fold(0u64, |a, r| a.saturating_add(r.length))
    }

    /// Total clip bytes, container framing included.
    pub fn clip_bytes(&self) -> u64 {
        self.clip_regions
            .iter()
            .fold(0u64, |a, r| a.saturating_add(r.length))
    }

    /// Whether the reconstruction produced exportable payload.
    pub fn is_exportable(&self) -> bool {
        !self.payload_regions.is_empty()
    }

    /// Whether the codec's parameter sets were located, so a remux can decode.
    pub fn has_parameter_sets(&self) -> bool {
        self.codec.has_parameter_sets()
    }

    /// Whether every clip's container walked cleanly with no gaps recorded.
    pub fn is_fully_verified(&self) -> bool {
        self.notes.is_empty()
            && self.evidence.state == ValidationStateKind::Pass
            && !self.clips.is_empty()
    }

    /// A human-readable description for an export record.
    pub fn description(&self) -> String {
        format!(
            "Hikvision recording {} on channel {}: {} clip(s) across block(s) {}, {} payload \
             range(s) totalling {} byte(s), codec {} (confidence {:.2}), ordering {}",
            self.recording_id,
            self.channel
                .map(|c| c.to_string())
                .unwrap_or_else(|| "unknown".into()),
            self.clips.len(),
            self.blocks
                .iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join(","),
            self.payload_regions.len(),
            self.payload_bytes(),
            self.codec.codec.label(),
            self.codec.confidence,
            self.ordering.label(),
        )
    }

    /// Metadata for an export record's provenance.
    pub fn oem_metadata(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("hikvision_recording_id".into(), self.recording_id.clone());
        m.insert("hikvision_clip_count".into(), self.clips.len().to_string());
        m.insert(
            "hikvision_block_numbers".into(),
            self.blocks
                .iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join(","),
        );
        m.insert(
            "hikvision_clip_ids".into(),
            self.clips
                .iter()
                .map(|c| c.clip.clip_id())
                .collect::<Vec<_>>()
                .join(","),
        );
        m.insert(
            "hikvision_clip_physical_regions".into(),
            self.clip_regions
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<_>>()
                .join(" "),
        );
        m.insert("hikvision_ordering".into(), self.ordering.label().into());
        m.insert("hikvision_codec".into(), self.codec.codec.label().into());
        m.insert(
            "hikvision_codec_confidence".into(),
            format!("{:.2}", self.codec.confidence),
        );
        m.insert("hikvision_codec_evidence".into(), self.codec.reason.clone());
        m.insert(
            "hikvision_parameter_sets_present".into(),
            self.has_parameter_sets().to_string(),
        );
        m.insert(
            "hikvision_payload_bytes".into(),
            self.payload_bytes().to_string(),
        );
        m.insert(
            "hikvision_fully_accessible".into(),
            self.fully_accessible.to_string(),
        );
        if let Some((s, e)) = self.decoded_time_span {
            m.insert("hikvision_span_start_unix".into(), s.to_string());
            m.insert("hikvision_span_end_unix".into(), e.to_string());
        }
        if let Some(c) = self.channel {
            m.insert("hikvision_channel".into(), c.to_string());
        }
        if !self.notes.is_empty() {
            m.insert(
                "hikvision_reconstruction_notes".into(),
                self.notes.join("; "),
            );
        }
        m
    }
}

/// Reconstruct the recording containing the clip identified by `clip_id`.
///
/// The seed clip is extended into a full recording by joining clips on the same channel
/// whose intervals are continuous within the profile's join gap, across block boundaries.
///
/// Returns `Ok(None)` when the volume no longer yields that clip — a real answer rather than
/// an error, because a clip id from an earlier run may not survive a re-read.
pub fn reconstruct_recording(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    volume: &HikvisionVolume,
    clip_id: &str,
) -> Result<Option<RecordingReconstruction>, ForensicError> {
    let Some((seed_block, seed_clip)) = volume.find_clip(clip_id) else {
        return Ok(None);
    };
    let group = group_clips(profile, volume, seed_block, seed_clip);
    Ok(Some(build(reader, profile, volume, clip_id, group)?))
}

/// Reconstruct exactly one clip, without joining neighbours.
///
/// Used where a caller wants the bytes of a single filesystem clip rather than the whole
/// continuous recording it belongs to.
pub fn reconstruct_clip(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    volume: &HikvisionVolume,
    clip_id: &str,
) -> Result<Option<RecordingReconstruction>, ForensicError> {
    let Some((block, clip)) = volume.find_clip(clip_id) else {
        return Ok(None);
    };
    Ok(Some(build(
        reader,
        profile,
        volume,
        clip_id,
        vec![(block, clip)],
    )?))
}

/// Join clips into one continuous recording around a seed.
///
/// Ordering here is by block number then footer slot index — filesystem order. Timestamps
/// decide only *whether* two clips belong together, never the order they are concatenated
/// in.
fn group_clips<'a>(
    profile: &OemProfile,
    volume: &'a HikvisionVolume,
    seed_block: &'a ClassifiedBlock,
    seed_clip: &'a ClipRecord,
) -> Vec<(&'a ClassifiedBlock, &'a ClipRecord)> {
    let join_gap = i64_from(profile, key::RECORDING_JOIN_GAP_SECONDS, 5);

    // Candidates: same channel, in filesystem order. An unknown channel cannot be joined to
    // anything, because joining on "unknown == unknown" would merge unrelated cameras.
    let Some(channel) = seed_clip.channel.normalized else {
        return vec![(seed_block, seed_clip)];
    };

    let mut ordered: Vec<(&ClassifiedBlock, &ClipRecord)> = volume
        .clips()
        .filter(|(_, c)| c.channel.normalized == Some(channel))
        .collect();
    ordered.sort_by_key(|(b, c)| (b.block_number(), c.slot_index, c.clip_region.offset));

    let Some(seed_pos) = ordered
        .iter()
        .position(|(_, c)| c.clip_id() == seed_clip.clip_id())
    else {
        return vec![(seed_block, seed_clip)];
    };

    // Two clips are continuous when the later one starts no more than `join_gap` after the
    // earlier one ends. Where either end is undecoded, physical adjacency is used instead:
    // the next clip beginning exactly where the previous one ended is strong filesystem
    // evidence of continuation, and it does not depend on the recorder's clock.
    let continuous = |prev: &ClipRecord, next: &ClipRecord| -> bool {
        match (prev.end_time.unix_seconds, next.start_time.unix_seconds) {
            (Some(pe), Some(ns)) => ns >= pe.saturating_sub(join_gap) && ns <= pe + join_gap,
            _ => {
                let prev_end = prev
                    .clip_region
                    .offset
                    .saturating_add(prev.clip_region.length);
                next.clip_region.offset == prev_end
            }
        }
    };

    let mut start = seed_pos;
    while start > 0 && continuous(ordered[start - 1].1, ordered[start].1) {
        start -= 1;
    }
    let mut end = seed_pos;
    while end + 1 < ordered.len() && continuous(ordered[end].1, ordered[end + 1].1) {
        end += 1;
    }

    ordered[start..=end].to_vec()
}

/// Walk each clip's container and assemble the ordered result.
fn build(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    volume: &HikvisionVolume,
    recording_id: &str,
    group: Vec<(&ClassifiedBlock, &ClipRecord)>,
) -> Result<RecordingReconstruction, ForensicError> {
    let mut clips: Vec<ReconstructedClip> = Vec::new();
    let mut clip_regions: Vec<Region> = Vec::new();
    let mut payload_regions: Vec<Region> = Vec::new();
    let mut blocks: Vec<u32> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut channels: Vec<u32> = Vec::new();
    let mut fully_accessible = true;
    let mut used_btree_order = false;

    for (sequence, (block, clip)) in group.iter().enumerate() {
        let stream = ps::walk_clip(reader, profile, clip.clip_region)?;

        // The order basis, recorded per clip so a mixed-evidence recording is transparent.
        let entries = volume.entries_for_block(block.block_number());
        let referencing = entries.iter().find(|e| {
            e.data_offset_physical()
                .is_some_and(|o| clip.clip_region.contains(o))
        });
        let order_basis = match referencing {
            Some(e) => {
                used_btree_order = true;
                format!(
                    "authoritative B-tree entry {} points into this clip's range",
                    e.entry_id()
                )
            }
            None => format!(
                "block {} footer clip index, slot {}",
                block.block_number(),
                clip.slot_index
            ),
        };

        if !block.classification.is_accessible() {
            fully_accessible = false;
            notes.push(format!(
                "clip {} lives in block {}, which is classified {}; its bytes are recovered from \
                 surviving footer metadata rather than from the recorder's live index",
                clip.clip_id(),
                block.block_number(),
                block.classification.label()
            ));
        }

        if !stream.has_framing() {
            notes.push(format!(
                "clip {} at {} carries no MPEG-PS framing this platform interprets, so no payload \
                 was extracted from it; the gap is marked and was not filled",
                clip.clip_id(),
                clip.clip_region
            ));
        } else if stream.payload_regions.is_empty() {
            notes.push(format!(
                "clip {} has container framing but no video PES payload was located in it",
                clip.clip_id()
            ));
        }
        for r in &stream.rejections {
            notes.push(format!("clip {}: {r}", clip.clip_id()));
        }
        if !stream.reached_end {
            notes.push(format!(
                "the container walk over clip {} stopped before the clip's declared end",
                clip.clip_id()
            ));
        }

        // Within a clip, the payload ranges are already in container order — which is frame
        // order. Pack serials corroborate that; a non-monotonic run is reported, not resorted,
        // because reordering bytes on a serial this platform has not fully characterised
        // would risk corrupting a stream that was actually fine.
        if stream.pack_serials.len() > 1 {
            let monotonic = stream.pack_serials.windows(2).all(|w| w[1] >= w[0]);
            if !monotonic {
                notes.push(format!(
                    "clip {} carries non-monotonic pack serials ({:?}...); the container order was \
                     preserved and the anomaly recorded rather than resorting the stream",
                    clip.clip_id(),
                    &stream.pack_serials[..stream.pack_serials.len().min(6)]
                ));
            }
        }

        if let Some(c) = clip.channel.normalized {
            channels.push(c);
        }
        if !blocks.contains(&block.block_number()) {
            blocks.push(block.block_number());
        }
        clip_regions.push(clip.clip_region);
        payload_regions.extend(stream.payload_regions.iter().copied());

        clips.push(ReconstructedClip {
            sequence,
            block_number: block.block_number(),
            clip: (*clip).clone(),
            stream,
            order_basis,
        });
    }

    blocks.sort_unstable();

    // ── Channel agreement ────────────────────────────────────────────────────────
    channels.sort_unstable();
    channels.dedup();
    let channel = match channels.len() {
        1 => Some(channels[0]),
        0 => {
            notes.push(
                "no clip in this recording established a channel number, so none is reported"
                    .into(),
            );
            None
        }
        _ => {
            notes.push(format!(
                "the clips in this recording disagree about the channel ({channels:?}); no single \
                 channel is reported"
            ));
            None
        }
    };

    // ── Ordering basis ───────────────────────────────────────────────────────────
    let ordering = if clips.is_empty() {
        RecordingOrdering::NoClipsLocated
    } else if clips.len() == 1 {
        RecordingOrdering::SingleClip
    } else if used_btree_order {
        RecordingOrdering::BTreeEntryOrder
    } else {
        // Every clip on this path came from a block footer index, so the footer's own slot
        // order — taken across blocks in block-number order — is what fixed the sequence.
        // `PhysicalContinuity` is reserved for the carving path, where no index exists.
        RecordingOrdering::ClipIndexOrder
    };

    // ── Codec, from the reconstructed payload ────────────────────────────────────
    let sample_budget = u64_from(profile, key::CARVE_WINDOW_BYTES, 4 << 20).min(1 << 20);
    let mut sample: Vec<u8> = Vec::new();
    for r in ps::sample_regions(&payload_regions, sample_budget) {
        if let Ok(mut b) = reader.read_exact_at(r.offset, r.length as usize) {
            sample.append(&mut b);
        }
    }
    let codec = if payload_regions.is_empty() {
        CodecEvidence::unknown(
            format!(
                "no video payload was located across the {} clip(s) of recording {recording_id}, so \
                 no codec was established",
                clips.len()
            ),
            0,
        )
    } else {
        ps::classify_codec(profile, &sample)
    };

    if codec.codec != HikCodec::Unknown && !codec.has_parameter_sets() {
        notes.push(format!(
            "the reconstructed stream was identified as {} but no parameter set (SPS/PPS/VPS) was \
             located in the sampled payload; a decoder may need parameter sets supplied separately",
            codec.codec.label()
        ));
    }

    // ── Reported span ────────────────────────────────────────────────────────────
    //
    // Derived from the clips' own timestamps. Reported only; it never influenced the order.
    let starts: Vec<i64> = clips
        .iter()
        .filter_map(|c| c.clip.start_time.unix_seconds)
        .collect();
    let ends: Vec<i64> = clips
        .iter()
        .filter_map(|c| c.clip.end_time.unix_seconds)
        .collect();
    let decoded_time_span = match (starts.iter().min(), ends.iter().max()) {
        (Some(s), Some(e)) => Some((*s, *e)),
        _ => None,
    };
    if let Some((s, e)) = decoded_time_span {
        if e < s {
            notes.push(format!(
                "the recording's decoded span runs backwards ({s} -> {e}); it is reported as stored"
            ));
        }
    }

    // ── Physical continuity note ─────────────────────────────────────────────────
    for w in clip_regions.windows(2) {
        let prev_end = w[0].offset.saturating_add(w[0].length);
        if w[1].offset != prev_end {
            notes.push(format!(
                "clip ranges {} and {} are not physically adjacent; the recording spans a \
                 discontinuity, which was recorded rather than bridged",
                w[0], w[1]
            ));
        }
    }

    let evidence = reconstruction_evidence(
        recording_id,
        &clips,
        &payload_regions,
        &blocks,
        ordering,
        &codec,
        fully_accessible,
        &notes,
    );

    Ok(RecordingReconstruction {
        recording_id: recording_id.to_string(),
        channel,
        clips,
        clip_regions,
        payload_regions,
        blocks,
        ordering,
        codec,
        decoded_time_span,
        fully_accessible,
        notes,
        evidence,
    })
}

#[allow(clippy::too_many_arguments)]
fn reconstruction_evidence(
    recording_id: &str,
    clips: &[ReconstructedClip],
    payload_regions: &[Region],
    blocks: &[u32],
    ordering: RecordingOrdering,
    codec: &CodecEvidence,
    fully_accessible: bool,
    notes: &[String],
) -> ValidationState {
    if clips.is_empty() {
        return vs(
            ValidationStateKind::Unknown,
            format!("no clip could be located for recording {recording_id}"),
            "hikvision_reconstruct",
            "recording",
        );
    }

    let payload_bytes: u64 = payload_regions.iter().map(|r| r.length).sum();
    let base = format!(
        "reconstructed recording {recording_id} from {} clip(s) across {} block(s) in {} order: \
         {} payload range(s) totalling {payload_bytes} byte(s), codec {} ({})",
        clips.len(),
        blocks.len(),
        ordering.label(),
        payload_regions.len(),
        codec.codec.label(),
        codec.reason,
    );

    let mut all = notes.to_vec();
    if !fully_accessible {
        all.push(
            "at least one clip came from a block the authoritative index does not reference, so \
             this recording is an availability finding rather than a live recording"
                .into(),
        );
    }
    if payload_regions.is_empty() {
        all.push("no exportable payload was located".into());
    }

    if all.is_empty() && codec.codec != HikCodec::Unknown {
        vs(
            ValidationStateKind::Pass,
            base,
            "hikvision_reconstruct",
            "recording",
        )
    } else {
        vs(
            ValidationStateKind::Review,
            format!("{base}. Qualifications: {}", all.join("; ")),
            "hikvision_reconstruct",
            "recording",
        )
    }
}

#[cfg(test)]
mod tests {
    // Reconstruction is exercised end-to-end against the synthetic volume builder in this
    // crate's integration tests, where a real boot structure, HIKBTREE and block footer are
    // present. Unit-testing it here would require duplicating that builder.
}
