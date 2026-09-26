//! # OEM storage interpretation contracts
//!
//! These types are the boundary between **OEM-specific interpretation** and the
//! **generic, physical-range reasoning** performed by the recovery engine.
//!
//! The split this module exists to enforce:
//!
//! ```text
//!   OEM DETECTION            "this is a Dahua disk"
//!       ≠
//!   STORAGE INTERPRETATION   "the video data region is [dhav_start, index_offset)"
//!       ≠
//!   INDEX DISCOVERY          "the index claims 6 recordings at these exact offsets"
//!       ≠
//!   RAW VIDEO DISCOVERY      "there is decodable H.264 at 0x2A000"
//!       ≠
//!   STATE CLASSIFICATION     "therefore that H.264 is Orphaned"
//! ```
//!
//! A parser recognising an OEM says nothing about whether any particular physical
//! region is an active recording. Only [`RecordingIndex`] evidence can support that.
//!
//! ## Rules these types encode
//!
//! * Every field a parser cannot establish from evidence is `Option`/`Unknown`. A
//!   guessed value is strictly worse than an absent one.
//! * The generic engine never parses an OEM index format. It consumes
//!   [`IndexedRecording::physical_regions`] — plain byte ranges.
//! * [`IndexAuthority`] gates how strong a conclusion downstream classification may
//!   draw. Only an `Authoritative` index can support an orphan finding; anything
//!   weaker degrades to the conservative "unindexed" outcome.

use std::collections::BTreeMap;

use forensic_core::{Region, ValidationState};
use serde::{Deserialize, Serialize};

/// What is known about a recorder's circular/ring buffer behaviour.
///
/// Most OEM structures this platform has evidence for carry no wrap pointer, so
/// [`CircularBufferEvidence::Unknown`] is the honest and expected value. It must never
/// be replaced with an assumed "not circular".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircularBufferEvidence {
    /// No evidence either way was recovered from the storage structures.
    Unknown,
    /// The storage structures positively record a write cursor / wrap point.
    WrapPointKnown {
        /// Physical byte offset the recorder's write cursor had reached.
        write_cursor: u64,
        /// Whether the structures indicate the buffer has wrapped at least once.
        has_wrapped: Option<bool>,
    },
}

/// Physical storage geometry as declared by the OEM's own structures.
///
/// Only fields the parser actually read from evidence are populated. `None` means
/// "this OEM's structures, as understood today, do not record this" — it does not mean
/// zero, and it does not mean the whole disk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StorageGeometry {
    /// Byte length of the evidence source the geometry was read from.
    pub physical_size: u64,
    /// The region the recorder uses for video payload, if the structures declare it.
    pub video_region: Option<Region>,
    /// The region holding the recording index, if located.
    pub index_region: Option<Region>,
    /// The region holding the filesystem/volume metadata (e.g. a superblock).
    pub metadata_region: Option<Region>,
    /// Allocation block size in bytes, if declared.
    pub block_size: Option<u64>,
    /// Logical sector size in bytes, if declared.
    pub sector_size: Option<u64>,
    /// Circular-buffer evidence, if any.
    pub circular_buffer: CircularBufferEvidence,
    /// OEM-specific descriptive values read verbatim from the structures (model,
    /// volume label, declared block counts, ...). Strings so the generic layer never
    /// needs to interpret them.
    pub oem_fields: BTreeMap<String, String>,
    /// Why this geometry is or is not trustworthy. A geometry that could not be
    /// verified against a magic/checksum must not be `Pass`.
    pub evidence: ValidationState,
}

impl StorageGeometry {
    /// Whether a physical offset falls inside the OEM-declared video payload region.
    ///
    /// Returns `None` when the video region is unknown — the caller must not collapse
    /// that into `false`, because "unknown" and "outside" license different conclusions.
    pub fn offset_in_video_region(&self, offset: u64) -> Option<bool> {
        self.video_region.map(|r| r.contains(offset))
    }
}

/// Whether an index entry's slot is recorded as in-use or free by the OEM structures.
///
/// This exists so an OEM that *does* have an allocation mechanism can support a
/// stronger conclusion than "present but unreferenced". OEMs without one report
/// [`AllocationEvidence::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AllocationEvidence {
    /// The structures record this entry as live/allocated.
    Allocated,
    /// The structures record this entry as freed/deleted (e.g. a tombstone byte or a
    /// cleared allocation bit).
    FreeMarked,
    /// The OEM structures understood today carry no allocation state for this entry.
    Unknown,
}

/// How much weight downstream classification may place on an index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndexAuthority {
    /// The index structure was located, its integrity markers verified, and every
    /// declared entry parsed in-bounds. It may be treated as a complete statement of
    /// what the recorder currently claims within the region it governs.
    Authoritative {
        /// The physical region this index makes a complete statement about. Bytes
        /// outside it are not governed by this index.
        governs: Region,
    },
    /// The index was located but is incomplete: part of it was unreadable, an integrity
    /// marker failed, or a declared entry could not be decoded. Absence from a partial index
    /// proves nothing.
    ///
    /// A declared entry count *larger* than the number of recordings produced is not by
    /// itself grounds for this: see [`RecordingIndex::declared_entry_count`].
    Partial { reason: String },
    /// No index structure was located, or this OEM path cannot read one.
    NotFound { reason: String },
}

impl IndexAuthority {
    /// Whether absence from this index is itself evidence.
    pub fn is_authoritative(&self) -> bool {
        matches!(self, IndexAuthority::Authoritative { .. })
    }
}

/// One recording as described by the OEM's index/metadata — normalized, but never
/// embellished.
///
/// Every optional field is `None` unless it was read from evidence. In particular a
/// missing `channel` must stay `None` rather than becoming channel 0, and a missing
/// timestamp must stay `None` rather than becoming the epoch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IndexedRecording {
    /// Stable identifier derived from the index itself (e.g. "didx#3"), for provenance.
    pub recording_id: String,
    /// The OEM partition/volume this recording lives in, when the storage structures are
    /// partitioned and the parser established which partition described it.
    ///
    /// `None` for OEMs whose structures describe a single flat region — that is an
    /// accurate statement about the format, not a missing value.
    #[serde(default)]
    pub partition: Option<u32>,
    /// Camera/channel, if the index records one.
    pub channel: Option<u32>,
    /// Recording start, as unix seconds, if the index records one.
    pub start_time_unix: Option<i64>,
    /// Recording end, as unix seconds, if the index records one.
    pub end_time_unix: Option<i64>,
    /// Exact physical byte ranges the index claims, including any container framing.
    /// These are the ranges the generic engine treats as "claimed".
    pub physical_regions: Vec<Region>,
    /// The elementary-stream payload sub-ranges, when the container framing is
    /// understood well enough to separate them. Empty when it is not.
    pub payload_regions: Vec<Region>,
    /// Codec as labelled by the OEM structures. Never inferred from stream bytes here —
    /// codec identity from bytes is a separate, downstream signal.
    pub codec_hint: Option<String>,
    /// Allocation state of this entry per the OEM structures.
    pub allocation: AllocationEvidence,
    /// Verbatim OEM-specific fields (frame type byte, CRC, sequence, ...).
    pub oem_metadata: BTreeMap<String, String>,
    /// Why this entry is or is not trustworthy.
    pub evidence: ValidationState,
}

impl IndexedRecording {
    /// Total claimed bytes across this entry's physical regions (saturating).
    pub fn claimed_bytes(&self) -> u64 {
        self.physical_regions
            .iter()
            .fold(0u64, |acc, r| acc.saturating_add(r.length))
    }
}

/// The normalized result of reading an OEM recording index.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordingIndex {
    /// How much weight may be placed on this index.
    pub authority: IndexAuthority,
    /// Entries successfully parsed. May be shorter than the declared count, in which
    /// case `authority` is `Partial`.
    ///
    /// These are the recordings the recorder's metadata **currently references** — the
    /// accessible set. Only these can support an `Active` conclusion.
    pub recordings: Vec<IndexedRecording>,
    /// Recordings whose OEM metadata survives and describes real physical bytes, but
    /// which are **not** part of the accessible recording set.
    ///
    /// This is the "available" / orphaned case: the filesystem still carries enough
    /// structure to say where the recording was, what channel it belonged to and when it
    /// ran, yet the recorder no longer reaches it through its active metadata. Examples
    /// this platform has evidence for: a Dahua block chain whose blocks are valid but
    /// unreachable from any first block, and every chain on a volume where a secondary
    /// partition table downgrades the whole accessible set.
    ///
    /// It is deliberately a separate list rather than a flag on `recordings`, so a
    /// consumer that only knows about `recordings` cannot accidentally report an
    /// available recording as active. It is **not** evidence of deletion: entries here
    /// classify as orphaned, never as `Deleted`, unless the OEM structures separately
    /// record a free/deallocated marker in [`IndexedRecording::allocation`].
    #[serde(default)]
    pub unreferenced_recordings: Vec<IndexedRecording>,
    /// Entry count the index header itself declared, if it declares one.
    ///
    /// This is the count the *structure* declares, which for a slot-table format is the
    /// number of slots rather than the number of recordings. A free or unused slot correctly
    /// yields no [`IndexedRecording`], so `recordings.len() + unreferenced_recordings.len()`
    /// is normally **less** than this and that is not evidence of a partial read. The
    /// universal contract therefore requires only that a parser never produce *more*
    /// recordings than the structure declares.
    ///
    /// [`IndexAuthority::Partial`] is for an index the parser could not finish reading — an
    /// unreadable region, a failed integrity marker, a slot it could not decode — which the
    /// parser knows and this count alone cannot express.
    pub declared_entry_count: Option<usize>,
    /// Physical extent of the index structure.
    pub index_region: Option<Region>,
    /// Why the index is or is not trustworthy.
    pub evidence: ValidationState,
}

impl RecordingIndex {
    /// Every physical region claimed by every accessible entry, in index order.
    pub fn claimed_regions(&self) -> Vec<Region> {
        self.recordings
            .iter()
            .flat_map(|r| r.physical_regions.iter().copied())
            .collect()
    }

    /// Every physical region described by metadata that survives but is not accessible.
    pub fn unreferenced_regions(&self) -> Vec<Region> {
        self.unreferenced_recordings
            .iter()
            .flat_map(|r| r.physical_regions.iter().copied())
            .collect()
    }
}

/// One self-describing container record located by structural scanning of a physical
/// range, rather than by reading an index.
///
/// This is how an OEM parser reports "there are three DHAV frames in the range you
/// handed me, at these exact absolute offsets" without the generic engine learning
/// anything about DHAV. It exists so raw carving is not forced to assume one candidate
/// per scan chunk.
///
/// # This is not an index claim
///
/// A `ContainerRecord` says a structure is physically present and internally
/// consistent. It says nothing about whether the recorder references it, so it can
/// never produce `Active`. Index/claim reasoning stays with
/// [`RecordingIndex`]/[`IndexAuthority`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContainerRecord {
    /// Exact absolute physical range of the whole record, framing included. Never
    /// rebased to the start of the scanned region.
    pub physical_region: Region,
    /// The elementary-stream payload sub-range, when the framing was understood well
    /// enough to separate it. `None` when it was not.
    pub payload_region: Option<Region>,
    /// Channel as decoded from the record's own header, 1-based, when it carries one.
    pub channel: Option<u32>,
    /// Record timestamp as unix seconds, when the header carries a decodable one. Never
    /// substituted with the epoch or with wall-clock time.
    pub start_time_unix: Option<i64>,
    /// Frame/record type label from the container header, when it carries one.
    pub frame_type: Option<String>,
    /// Codec as labelled by the container header. Never inferred from payload bytes
    /// here — that is a separate downstream signal.
    pub codec_hint: Option<String>,
    /// Verbatim OEM-specific fields (declared length, extra-header length, raw channel
    /// value, trailer verification, resolution, ...).
    pub oem_metadata: BTreeMap<String, String>,
    /// Why this record is or is not structurally trustworthy. A record whose declared
    /// length or trailer failed verification must not be `Pass`.
    pub evidence: ValidationState,
}
