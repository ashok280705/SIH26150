//! # parser-uniview
//!
//! Uniview parser. Implements the common `Parser` interface (Req 6.3) over evidence the
//! confidence engine attributed to the Uniview storage family.
//!
//! All Uniview factual knowledge — magic values, offsets, sizes, strides and bounds — is
//! supplied by versioned profile data under `profiles/uniview/` and resolved through
//! [`layout::UniviewLayout`]. Nothing OEM-specific is declared as a source constant
//! (Req 6.1, 11.5, 25.3).
//!
//! ## The structure set this crate reads
//!
//! ```text
//!   SUPER (0x0, 0x4000)            magic 0x1367 OLD / 0x1587 NEW     superblock::read_super
//!     ├─ UI      (OLD, 0x4000)     current unit, rewrited flag        ui::read_ui
//!     ├─ UI-CTL  (NEW, 0x4000)     current unit, count, rewrited      ui::read_ui
//!     ├─ UI-DATA (NEW, 0x14000+n*0x10000)  time-index entries + lock  ui::read_ui_data
//!     └─ units (256 MiB, stride 0x10000000; OLD base 0x14000, NEW base 0x10014000)
//!          ├─ DI (256 KiB)         write bytes, count, 16-byte entries  di::read_unit_di
//!          │    └─ SPtoI (14-bit block index)
//!          └─ DATA (16 KiB blocks)  unit_base + SPtoI * 0x4000          data::resolve
//!
//!   volume::read_volume      composes the above into StorageGeometry + RecordingIndex
//!   data::extract_regions    raw, hashed, read-only DATA extraction
//!   recovery::*              INDEXED / STRUCTURAL / HEURISTIC recovery items
//!   report::*                field-level forensic report with known limitations
//!
//!   disktool .h3crd export   recognised by its header tag (only when no SUPER magic
//!                            matches) and read as an OLD-shaped single-unit artifact
//! ```
//!
//! ## Confidence vocabulary
//!
//! Every reported field carries a [`layout::Confidence`]: `CONFIRMED`, `STRONG INFERENCE`,
//! `TENTATIVE` or `UNKNOWN`. Only confirmed structure and well-supported inference drive
//! authoritative output; unknown fields are preserved raw and never given invented meaning.
//!
//! ## What this crate deliberately does not do
//!
//! * It does not claim a codec, container or framing for DATA blocks.
//! * It does not derive a channel from DI field A or from the UI-DATA lock value.
//! * It does not link UI / UI-DATA entries to DI entries.
//! * It does not report anything as deleted: no Uniview deletion structure is known.
//! * It never writes to evidence.
//!
//! It does not orchestrate recovery, build the unified timeline, classify `DataState`, or
//! make the final OEM attribution (Req 3, 12, 15.1).

#![forbid(unsafe_code)]

pub mod data;
pub mod di;
pub mod field;
pub mod layout;
pub mod parser;
pub mod recovery;
pub mod report;
pub mod superblock;
pub mod testing;
pub mod timestamp;
pub mod ui;
pub mod volume;

pub use data::{AddressError, DataBlockAddress, ExtractedData};
pub use di::{
    CountSemantics, DataSpan, DiEntry, DiHeader, DiHeaderState, SpanBasis, SptoiState, UnitDi,
    DI_HEAD_ABNORMAL,
};
pub use field::FieldEvidence;
pub use layout::{Confidence, Generation, UniviewLayout};
pub use parser::{
    extract_di_entry, extract_recording, find_recording, forensic_report, UniviewParser,
};
pub use recovery::{RecoveryBasis, RecoveryItem, RecoveryOptions, UniviewRecoveryReport};
pub use report::{known_limitations, UniviewForensicReport};
pub use superblock::{SuperRecognition, UniviewSuper};
pub use timestamp::{TimestampStatus, UnvTimestamp};
pub use ui::{unit_time_entry, TimeIndexEntry, TimeIndexSummary, UiDataArea, UiHeader, UniviewUi};
pub use volume::{UnitDetail, UnitRecord, UniviewVolume, VendorFlow};
