//! # parser-dahua
//!
//! Dahua parser. Implements the common `Parser` interface (Req 6.3) over evidence the
//! confidence engine attributed to the Dahua storage family.
//!
//! All Dahua factual knowledge — signatures, offsets, structure layouts, validation rules,
//! applicability, and weights — is supplied by versioned profile data under
//! `profiles/dahua/`, each rule carrying an `Evidence_Status`. Nothing OEM-specific is
//! declared as a source constant (Req 6.1, 11.5).
//!
//! ## The DHFS 4.1 structure model
//!
//! A Dahua volume is not a flat video region behind a superblock. The real structure set,
//! and the order this crate reads it in, is:
//!
//! ```text
//!   DHFS4.1 volume signature          superblock::recognize
//!        │
//!        ▼
//!   partition table  (0x3C00, …)      partition::read_partition_tables
//!        │  entry: start sector, info sector
//!        ▼
//!   partition information             partition::resolve_partition
//!        │  IndexStartSector, VideoStartSector, BlockCount
//!        ▼
//!   block table  (32 bytes/block)     block_table::read_block_map
//!        │  type, channel, times, FirstBlock/PreviousBlock/NextBlock, sectorCount
//!        ▼
//!   recording chains                  chain::build_chains
//!        │  ordered 2 MiB video blocks
//!        ▼
//!   DHII per-clip frame index         dhii::read_index
//!        │  frame offsets, lengths, timestamps
//!        ▼
//!   DHAV frames                       dhav::parse_frame_at / carve_region
//!        │  header, extra header, payload, trailer
//!        ▼
//!   StorageGeometry + RecordingIndex  volume::read_volume
//! ```
//!
//! The generic recovery engine consumes only the last line: plain physical byte ranges plus
//! explicitly-optional metadata. It never learns what DHFS, DHII or DHAV mean.
//!
//! ## Accessible versus available
//!
//! [`volume`] splits what it finds into two sets. Chains reached by traversing from a
//! declared first block, on a volume with a single partition table, are the **accessible**
//! recording set and become `RecordingIndex::recordings`. Chains whose metadata survives but
//! which the recorder no longer reaches — unreachable block groups, and every chain on a
//! volume carrying a secondary partition table — become
//! `RecordingIndex::unreferenced_recordings`, the **available** set.
//!
//! Available is not deleted. DHFS 4.1 as read here carries no tombstone distinguishing
//! "never written" from "freed", so no deletion conclusion is drawn from absence.
//!
//! ## Modules
//!
//! * [`layout`] — profile `[layout]` accessors and total little-endian field readers.
//! * [`timestamp`] — packed base-2000 timestamp decoding, per structure, no timezone applied.
//! * [`channel`] — legacy and extended channel decoding, normalized without losing the raw value.
//! * [`superblock`] — version-aware DHFS volume recognition.
//! * [`partition`] — partition table and partition information.
//! * [`block_table`] — the 32-byte block-table entry and a partition's block map.
//! * [`chain`] — recording chain traversal and validation.
//! * [`dhii`] — the per-clip frame index.
//! * [`dhav`] — the single authoritative DHAV frame parser and carver.
//! * [`volume`] — composes all of the above into `StorageGeometry`/`RecordingIndex`.
//! * [`dhfs`] — the provisional flat-superblock + `DIDX` fallback, retained for volumes
//!   that present it.
//! * [`parser`] — the `Parser` trait implementation.

#![forbid(unsafe_code)]

pub mod block_table;
pub mod chain;
pub mod channel;
pub mod dhav;
pub mod dhfs;
pub mod dhii;
pub mod layout;
pub mod parser;
pub mod partition;
pub mod reconstruct;
pub mod superblock;
pub mod testing;
pub mod timestamp;
pub mod volume;

pub use block_table::{BlockMap, BlockState, BlockTableEntry};
pub use chain::{ChainOrdering, ChainOrigin, ChainValidity, RecordingChain, VideoBlock};
pub use channel::{ChannelEncoding, DahuaChannel};
pub use dhav::{DhavFrame, DhavFrameKind};
pub use dhii::{DhiiEntryType, DhiiIndex};
pub use parser::{find_chain, reconstruct_recording, volume_summary, DahuaParser};
pub use partition::{DahuaPartition, PartitionTable, PartitionTableSet};
pub use reconstruct::{
    ChainReconstruction, FrameSource, ReconstructedFrame, ReconstructionOrdering,
};
pub use superblock::DhfsRecognition;
pub use timestamp::{DahuaTimestamp, TimestampConfidence, TimestampStructure};
pub use volume::{DahuaVolume, VolumeModel};
