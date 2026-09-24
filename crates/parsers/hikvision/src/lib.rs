//! # parser-hikvision
//!
//! Hikvision parser. Implements the common `Parser` interface (Req 6.3) over evidence the
//! confidence engine attributed to the Hikvision storage family.
//!
//! All Hikvision factual knowledge — signatures, offsets, index and frame layouts,
//! validation rules, applicability, and weights — is supplied by versioned profile data
//! under `profiles/hikvision/`, each rule carrying an `Evidence_Status`. Nothing
//! OEM-specific is declared as a source constant (Req 6.1, 11.5).
//!
//! ## The structure set this crate reads
//!
//! ```text
//!   boot structure (identifier, geometry, tree pointers)   boot::read_boot
//!     ├─ HIKBTREE header + page traversal                  hikbtree::read_tree
//!     │    └─ 48-byte leaf entries                         hikbtree::BTreeEntry
//!     ├─ backup HIKBTREE (corroboration / substitution)    hikbtree::select_authority
//!     └─ video blocks                                      block::BlockGeometry
//!          ├─ trailing footer clip index                   block::read_block_index
//!          │    └─ 512-byte clip slots                     block::ClipRecord
//!          └─ MPEG-PS-like clip stream                     ps::walk_clip
//!               ├─ pack / PES parts, OFNI parts            ps::StreamPart
//!               └─ H.264 / H.265 NAL structure             ps::classify_codec
//!
//!   volume::read_volume        composes the above into StorageGeometry + RecordingIndex
//!   reconstruct::*             orders clips into an exportable payload
//!   carve::carve_region        raw MPEG-PS fallback for unindexed space
//! ```
//!
//! ## The recovery hierarchy this supports
//!
//! 1. a block the authoritative HIKBTREE references;
//! 2. that block's own footer clip metadata;
//! 3. valid clip / MPEG-PS frame structure inside it;
//! 4. raw MPEG-PS carving where none of the above is available.
//!
//! ## What this crate deliberately does not do
//!
//! The parser supplies recovery *knowledge*: geometry, an index with an honest
//! [`parsers_core::storage::IndexAuthority`], and structural carving. It does not
//! orchestrate recovery, does not build the unified timeline, does not classify
//! `DataState`, and never makes the final OEM attribution (Req 3, 12, 15.1).
//!
//! In particular, a block the B-tree does not reference is reported as **unreferenced**,
//! never as deleted. Deletion needs an allocation or free marker, and the Hikvision
//! structures this crate reads carry none — so
//! [`parsers_core::storage::AllocationEvidence::Unknown`] is the honest answer and
//! `DataState::Deleted` is unreachable from this parser by construction.

#![forbid(unsafe_code)]

pub mod block;
pub mod boot;
pub mod carve;
pub mod channel;
pub mod hikbtree;
pub mod layout;
pub mod parser;
pub mod ps;
pub mod reconstruct;
pub mod testing;
pub mod timestamp;
pub mod volume;

pub use block::{BlockGeometry, BlockIndex, BlockIndexRecognition, ClipRecord};
pub use boot::{BootRecognition, HikBoot};
pub use carve::{CarveResult, CarvedCandidate};
pub use channel::ChannelEvidence;
pub use hikbtree::{
    AuthoritySelection, BTreeEntry, EntryState, HikBTree, PageType, TreeAgreement, TreeIntegrity,
    TreeRole,
};
pub use parser::{find_recording, reconstruct_recording, volume_summary, HikvisionParser};
pub use ps::{ClipStream, CodecEvidence, HikCodec, StreamPart};
pub use reconstruct::{RecordingOrdering, RecordingReconstruction};
pub use timestamp::{HikTimestamp, TimeConfidence};
pub use volume::{BlockClassification, ClassifiedBlock, HikvisionVolume};
