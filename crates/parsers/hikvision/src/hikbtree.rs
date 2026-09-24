//! # HIKBTREE — the Hikvision recording index
//!
//! The boot structure points at a page-based index tree whose header page carries the
//! `HIKBTREE` magic:
//!
//! ```text
//!   header + 0     "HIKBTREE"
//!   header + 60    i32   tree timestamp (unix seconds)
//!   header + 64    i64   FirstPointerPageOffset
//!   header + 72    i64   LastPointerPageOffset
//!   header + 80    i64   FirstListPageOffset
//!   header + 88    i64   FirstLeafPageOffset
//!   header + 96    i32   PageCount
//! ```
//!
//! Pages are 4096 bytes and carry a type discriminator at `+0` — `2` for a leaf, `3` for
//! an internal page:
//!
//! ```text
//!   leaf     + 16   i32   entryCount        internal + 16   i64  otherPageOffset
//!   leaf     + 24   i64   otherPageOffset   internal + 24   i64  nextPageOffset
//!   leaf     + 32   i64   nextPageOffset
//!   leaf     + 96         entry array, 48 bytes per entry
//! ```
//!
//! ## Traversal, not a single page
//!
//! The index is a tree. Reading only the page the header points at would silently drop
//! every recording past the first ~83 entries, so [`read_tree`] walks the page graph from
//! both the pointer-page and leaf-page roots, following `nextPageOffset` and
//! `otherPageOffset`.
//!
//! A damaged or hostile tree can point anywhere, so traversal is guarded against:
//!
//! * **cycles** — a page whose pointer chain returns to a visited page;
//! * **duplicate processing** — the same page reached by two paths is parsed once;
//! * **out-of-range pointers** — outside the declared tree region or the evidence;
//! * **misalignment** — a pointer that is not on a page boundary;
//! * **unknown page types** — anything that is neither leaf nor internal;
//! * **runaway traversal** — bounded by a profile page guard.
//!
//! Every one of those is *recorded* in the [`TraversalReport`] rather than silently
//! skipped, because a tree that could not be fully walked cannot be authoritative, and the
//! reason an examiner needs is exactly the one traversal discovered.
//!
//! ## The `+8` field is a state sentinel
//!
//! Each 48-byte entry carries at `+8` either the blank value `0xFFFFFFFFFFFFFFFF` (the
//! slot was never written) or the populated value `0` (the slot is in use). Any other
//! value is evidence that the entry is malformed or partially overwritten. This module
//! keeps all three apart and never coerces a third value into one of the two known
//! states: a slot whose sentinel is damaged is not the same finding as an empty slot.
//!
//! ## Sentinel state is not allocation state
//!
//! A blank slot means "never written", which is different from "written and then freed".
//! Nothing in these structures records a free/deallocation marker, so this module makes no
//! deletion claim whatsoever — see [`crate::volume`], which reports
//! [`parsers_core::storage::AllocationEvidence::Unknown`] for every entry.

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, OemProfile, Region, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::channel::{self, ChannelEvidence};
use crate::layout::{
    hex_ascii, i32_at, i64_at, key, magic, sig, u64_bits_from, u64_from, u8_at, usize_from, vs,
};
use crate::timestamp::{HikTimestamp, TimestampStructure};

/// Which of the two trees a parse came from.
///
/// Carried on every page and entry so primary and backup findings can never be confused
/// after the fact, and so a disagreement between them can be attributed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TreeRole {
    /// The tree at the boot structure's `BTreeOffset`.
    Primary,
    /// The tree at the boot structure's `BackupBTreeOffset`.
    Backup,
}

impl TreeRole {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Backup => "backup",
        }
    }

    /// The boot field name this role reads its offset from, for evidence strings.
    pub fn boot_field(&self) -> &'static str {
        match self {
            Self::Primary => "BTreeOffset",
            Self::Backup => "BackupBTreeOffset",
        }
    }
}

/// The kind of a HIKBTREE page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PageType {
    /// A leaf page, carrying the 48-byte entry array.
    Leaf,
    /// An internal page, carrying only pointers.
    Internal,
    /// A discriminator this platform has no structural evidence for. The page's pointers
    /// are **not** followed, because walking a page whose layout is unknown is how a
    /// traversal invents structure.
    Unknown { discriminator: i32 },
    /// The discriminator field could not be read.
    Unreadable { reason: String },
}

impl PageType {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Leaf => "leaf",
            Self::Internal => "internal",
            Self::Unknown { .. } => "unknown",
            Self::Unreadable { .. } => "unreadable",
        }
    }

    pub fn is_known(&self) -> bool {
        matches!(self, Self::Leaf | Self::Internal)
    }
}

/// The state a 48-byte entry's `+8` sentinel declares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryState {
    /// The blank sentinel: this slot has never been written.
    ///
    /// **Not** a deletion marker. An unwritten slot carries no information about any
    /// recording that may once have occupied the bytes it points at.
    Blank,
    /// The populated sentinel: this slot describes a recording.
    Populated,
    /// Neither sentinel value. Preserved verbatim: a damaged sentinel is a finding, and
    /// guessing which of the two states was intended would erase it.
    Malformed { sentinel: u64, reason: String },
}

impl EntryState {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Blank => "blank",
            Self::Populated => "populated",
            Self::Malformed { .. } => "malformed",
        }
    }

    pub fn is_populated(&self) -> bool {
        matches!(self, Self::Populated)
    }
}

/// One 48-byte HIKBTREE entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BTreeEntry {
    /// Which tree this entry came from.
    pub role: TreeRole,
    /// Absolute physical offset of the entry itself.
    pub entry_offset: u64,
    /// Absolute physical offset of the page the entry lives on.
    pub page_offset: u64,
    /// Index of the entry within its page's array.
    pub index_in_page: usize,
    /// The `+0` page back-reference, exactly as stored.
    pub page_offset_field: i64,
    /// The `+8` sentinel, exactly as stored.
    pub sentinel: u64,
    /// What the sentinel declares.
    pub state: EntryState,
    /// Channel, raw and normalized.
    pub channel: ChannelEvidence,
    /// The `+24` start time.
    pub start_time: HikTimestamp,
    /// The `+28` end time.
    pub end_time: HikTimestamp,
    /// The `+32` data offset: where the recording's bytes begin.
    pub data_offset: i64,
    /// The `+40` status field, preserved raw. This platform has not established the
    /// meaning of its bits, so it is never interpreted — only carried.
    pub status_raw: i32,
    /// The `+44` field, preserved raw for the same reason.
    pub unknown_raw: i32,
    /// Why this entry is or is not trustworthy.
    pub evidence: ValidationState,
}

impl BTreeEntry {
    /// A stable identifier derived from the entry's own physical position.
    ///
    /// Derived rather than generated so the same entry always yields the same id across
    /// runs, and so the id points an examiner at real bytes.
    pub fn entry_id(&self) -> String {
        format!(
            "hikbtree:{}:page{:#x}:e{}",
            self.role.label(),
            self.page_offset,
            self.index_in_page
        )
    }

    /// The data offset as an unsigned physical offset, when it is usable.
    ///
    /// A negative or zero data offset does not address bytes in the evidence and yields
    /// `None` rather than a coerced value.
    pub fn data_offset_physical(&self) -> Option<u64> {
        if self.data_offset > 0 {
            Some(self.data_offset as u64)
        } else {
            None
        }
    }

    /// Whether this entry describes a recording whose bytes can be located.
    pub fn references_data(&self) -> bool {
        self.state.is_populated() && self.data_offset_physical().is_some()
    }

    /// Whether the recorder had not finished writing this recording.
    pub fn is_incomplete(&self) -> bool {
        self.start_time.incomplete || self.end_time.incomplete
    }
}

/// One parsed HIKBTREE page.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TreePage {
    pub role: TreeRole,
    /// Absolute physical offset of the page.
    pub page_offset: u64,
    pub page_type: PageType,
    /// The entry count a leaf page declares, exactly as stored.
    pub declared_entry_count: Option<i32>,
    /// The `otherPageOffset` pointer, exactly as stored.
    pub other_page_offset: Option<i64>,
    /// The `nextPageOffset` pointer, exactly as stored.
    pub next_page_offset: Option<i64>,
    /// Entries parsed from a leaf page. Always empty for an internal page.
    pub entries: Vec<BTreeEntry>,
    /// Why this page is or is not trustworthy.
    pub evidence: ValidationState,
}

impl TreePage {
    /// Physical extent of the page.
    pub fn region(&self, page_size: u64) -> Option<Region> {
        Region::new(self.page_offset, page_size).ok()
    }

    pub fn populated_entries(&self) -> impl Iterator<Item = &BTreeEntry> {
        self.entries.iter().filter(|e| e.state.is_populated())
    }
}

/// What traversal established about the page graph.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct TraversalReport {
    /// Pages successfully parsed.
    pub pages_visited: usize,
    /// Page count the header declared, when readable.
    pub declared_page_count: Option<i32>,
    /// Pointers that led back to an already-visited page.
    pub cycles_detected: Vec<String>,
    /// Pointers that resolved to a page already parsed by another path.
    pub duplicates_skipped: Vec<u64>,
    /// Pointers outside the tree region or the evidence.
    pub out_of_range_pointers: Vec<String>,
    /// Pointers that were not on a page boundary.
    pub misaligned_pointers: Vec<String>,
    /// Pages whose type discriminator this platform does not recognise.
    pub invalid_page_types: Vec<String>,
    /// Pages whose bytes could not be read.
    pub unreadable_pages: Vec<String>,
    /// Whether the page guard stopped traversal before it ran out of pointers.
    pub guard_reached: bool,
}

impl TraversalReport {
    /// Whether traversal walked the graph to completion with nothing rejected.
    ///
    /// This is the precondition for treating the tree as a complete statement. A single
    /// rejected pointer means some part of the index was not read, and absence from a
    /// partially read index is not evidence of absence.
    pub fn is_clean(&self) -> bool {
        self.cycles_detected.is_empty()
            && self.out_of_range_pointers.is_empty()
            && self.misaligned_pointers.is_empty()
            && self.invalid_page_types.is_empty()
            && self.unreadable_pages.is_empty()
            && !self.guard_reached
    }

    /// Whether the number of pages parsed matches what the header declared.
    ///
    /// `None` when the header declared no count, which is different from a mismatch.
    pub fn page_count_agrees(&self) -> Option<bool> {
        self.declared_page_count
            .map(|declared| declared >= 0 && declared as usize == self.pages_visited)
    }

    /// Every problem traversal found, as sentences for an evidence string.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        for c in &self.cycles_detected {
            out.push(format!("cycle: {c}"));
        }
        for d in &self.out_of_range_pointers {
            out.push(format!("out-of-range pointer: {d}"));
        }
        for m in &self.misaligned_pointers {
            out.push(format!("misaligned pointer: {m}"));
        }
        for t in &self.invalid_page_types {
            out.push(format!("unrecognised page type: {t}"));
        }
        for u in &self.unreadable_pages {
            out.push(format!("unreadable page: {u}"));
        }
        if self.guard_reached {
            out.push(
                "traversal stopped at the profile page guard, so the tree was not fully walked"
                    .to_string(),
            );
        }
        if self.page_count_agrees() == Some(false) {
            out.push(format!(
                "the header declares {} page(s) but {} were parsed",
                self.declared_page_count.unwrap_or_default(),
                self.pages_visited
            ));
        }
        out
    }
}

/// The parsed HIKBTREE header page.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TreeHeader {
    /// Absolute offset of the header page.
    pub page_offset: u64,
    /// The magic bytes exactly as read.
    pub magic: Vec<u8>,
    /// The `+60` tree timestamp.
    pub tree_timestamp: HikTimestamp,
    pub first_pointer_page_offset: Option<i64>,
    pub last_pointer_page_offset: Option<i64>,
    pub first_list_page_offset: Option<i64>,
    pub first_leaf_page_offset: Option<i64>,
    pub declared_page_count: Option<i32>,
    pub evidence: ValidationState,
}

/// Whether a tree was found at all, and in what condition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TreeRecognition {
    /// The `HIKBTREE` magic was verified at the declared offset.
    HeaderVerified,
    /// Bytes were readable at the declared offset but carry no `HIKBTREE` magic.
    MagicMismatch { observed: String },
    /// The boot structure declares no offset for this tree.
    NoOffsetDeclared { reason: String },
    /// The declared offset could not be read.
    Unreadable { reason: String },
}

impl TreeRecognition {
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::HeaderVerified)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::HeaderVerified => "header-verified",
            Self::MagicMismatch { .. } => "magic-mismatch",
            Self::NoOffsetDeclared { .. } => "no-offset-declared",
            Self::Unreadable { .. } => "unreadable",
        }
    }
}

/// How much of this tree was established, as a graded scale.
///
/// Hikvision index authority is hierarchical: the magic existing says nothing about
/// whether the pages behind it were walked. These levels exist so
/// [`crate::volume`] can map an honest [`parsers_core::storage::IndexAuthority`] instead
/// of declaring a tree authoritative because eight magic bytes matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TreeIntegrity {
    /// No tree: no offset declared, unreadable, or the magic did not match.
    NotEstablished,
    /// The header page verified, but no page was successfully traversed.
    HeaderOnly,
    /// Pages were traversed, but traversal rejected something or the page count
    /// disagreed. Absence from this tree proves nothing.
    PartialTraversal,
    /// Every declared page was walked, nothing was rejected, and the page count agreed.
    /// Only at this level may absence from the tree be treated as evidence.
    CompleteTraversal,
}

impl TreeIntegrity {
    pub fn label(&self) -> &'static str {
        match self {
            Self::NotEstablished => "not-established",
            Self::HeaderOnly => "header-only",
            Self::PartialTraversal => "partial-traversal",
            Self::CompleteTraversal => "complete-traversal",
        }
    }

    /// Whether absence from this tree is itself evidence.
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::CompleteTraversal)
    }
}

/// A parsed HIKBTREE.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HikBTree {
    pub role: TreeRole,
    /// The offset the boot structure declared for this tree.
    pub declared_offset: Option<u64>,
    /// The region traversal was confined to.
    pub tree_region: Option<Region>,
    pub recognition: TreeRecognition,
    pub header: Option<TreeHeader>,
    /// Pages in traversal order.
    pub pages: Vec<TreePage>,
    pub traversal: TraversalReport,
    pub integrity: TreeIntegrity,
    /// Why this tree is or is not trustworthy.
    pub evidence: ValidationState,
}

impl HikBTree {
    /// Every entry from every leaf page, in traversal order.
    pub fn entries(&self) -> impl Iterator<Item = &BTreeEntry> {
        self.pages.iter().flat_map(|p| p.entries.iter())
    }

    /// Entries whose sentinel declares them in use.
    pub fn populated_entries(&self) -> impl Iterator<Item = &BTreeEntry> {
        self.entries().filter(|e| e.state.is_populated())
    }

    /// Entries whose sentinel declares them never written.
    pub fn blank_entries(&self) -> impl Iterator<Item = &BTreeEntry> {
        self.entries()
            .filter(|e| matches!(e.state, EntryState::Blank))
    }

    /// Entries whose sentinel is neither known value.
    pub fn malformed_entries(&self) -> impl Iterator<Item = &BTreeEntry> {
        self.entries()
            .filter(|e| matches!(e.state, EntryState::Malformed { .. }))
    }

    pub fn leaf_pages(&self) -> impl Iterator<Item = &TreePage> {
        self.pages.iter().filter(|p| p.page_type == PageType::Leaf)
    }

    pub fn internal_pages(&self) -> impl Iterator<Item = &TreePage> {
        self.pages
            .iter()
            .filter(|p| p.page_type == PageType::Internal)
    }

    /// Physical data offsets this tree references, deduplicated and sorted.
    ///
    /// This is the authoritative "what the index points at" set. Everything the
    /// unreferenced-block analysis does is defined against it.
    pub fn referenced_data_offsets(&self) -> BTreeSet<u64> {
        self.populated_entries()
            .filter_map(|e| e.data_offset_physical())
            .collect()
    }

    /// Whether this tree can be used as the authority for accessibility.
    pub fn is_usable(&self) -> bool {
        self.recognition.is_verified() && self.integrity >= TreeIntegrity::PartialTraversal
    }
}

/// Read and traverse one HIKBTREE.
///
/// `declared_offset` and `declared_size` come from the boot structure. `declared_size`
/// bounds traversal when present; when it is absent, traversal is bounded by the evidence
/// and the page guard, and that weaker bound is recorded.
///
/// Never fails on damaged input: a tree that cannot be read comes back as a
/// [`TreeRecognition`] variant with [`TreeIntegrity::NotEstablished`], because "there is no
/// usable index here" is a result the recovery engine needs, not an error.
pub fn read_tree(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    role: TreeRole,
    declared_offset: Option<u64>,
    declared_size: Option<u64>,
) -> Result<HikBTree, ForensicError> {
    let physical_size = reader.len();
    let page_size = u64_from(profile, key::BTREE_PAGE_SIZE, 4096).max(1);

    let Some(offset) = declared_offset else {
        return Ok(not_established(
            role,
            None,
            None,
            TreeRecognition::NoOffsetDeclared {
                reason: format!(
                    "the boot structure declares no usable {} for the {} tree",
                    role.boot_field(),
                    role.label()
                ),
            },
        ));
    };

    // Confine traversal to the declared tree extent when there is one. A pointer outside
    // it is out of range even if it happens to address readable bytes.
    let tree_region = {
        let available = physical_size.saturating_sub(offset.min(physical_size));
        let length = declared_size.map(|s| s.min(available)).unwrap_or(available);
        Region::new(offset, length).ok()
    };

    // ── Header page ──────────────────────────────────────────────────────────────
    let Some(expected_magic) = magic(profile, sig::HIKBTREE_MAGIC) else {
        return Ok(not_established(
            role,
            Some(offset),
            tree_region,
            TreeRecognition::Unreadable {
                reason: format!(
                    "the profile declares no '{}' signature, so no tree header could be verified",
                    sig::HIKBTREE_MAGIC
                ),
            },
        ));
    };

    let header_bytes = match read_page_bytes(reader, offset, page_size as usize) {
        Ok(b) => b,
        Err(_) => {
            return Ok(not_established(
                role,
                Some(offset),
                tree_region,
                TreeRecognition::Unreadable {
                    reason: format!(
                    "the {} tree's declared offset {offset} (0x{offset:X}) is not readable in a \
                         {physical_size}-byte image",
                    role.label()
                ),
                },
            ))
        }
    };

    let magic_offset = usize_from(profile, key::BTREE_MAGIC_OFFSET, 0);
    let magic_len = usize_from(profile, key::BTREE_MAGIC_LENGTH, expected_magic.len());
    let observed_magic = header_bytes
        .get(magic_offset..magic_offset.saturating_add(magic_len))
        .unwrap_or_default()
        .to_vec();

    if !observed_magic.starts_with(&expected_magic) {
        return Ok(not_established(
            role,
            Some(offset),
            tree_region,
            TreeRecognition::MagicMismatch {
                observed: hex_ascii(&observed_magic),
            },
        ));
    }

    let header = parse_header(profile, offset, &header_bytes, observed_magic.clone());

    // ── Traversal ────────────────────────────────────────────────────────────────
    let (pages, traversal) = traverse(
        reader,
        profile,
        role,
        &header,
        tree_region,
        page_size,
        physical_size,
    )?;

    let integrity = if pages.is_empty() {
        TreeIntegrity::HeaderOnly
    } else if traversal.is_clean() && traversal.page_count_agrees() != Some(false) {
        TreeIntegrity::CompleteTraversal
    } else {
        TreeIntegrity::PartialTraversal
    };

    let evidence = tree_evidence(role, offset, &header, &traversal, integrity, &pages);

    Ok(HikBTree {
        role,
        declared_offset: Some(offset),
        tree_region,
        recognition: TreeRecognition::HeaderVerified,
        header: Some(header),
        pages,
        traversal,
        integrity,
        evidence,
    })
}

fn not_established(
    role: TreeRole,
    declared_offset: Option<u64>,
    tree_region: Option<Region>,
    recognition: TreeRecognition,
) -> HikBTree {
    let reason = match &recognition {
        TreeRecognition::MagicMismatch { observed } => format!(
            "the {} tree's declared offset holds {observed} where the HIKBTREE magic was expected; \
             no index was read there",
            role.label()
        ),
        TreeRecognition::NoOffsetDeclared { reason } | TreeRecognition::Unreadable { reason } => {
            reason.clone()
        }
        TreeRecognition::HeaderVerified => "header verified".to_string(),
    };
    let evidence = vs(
        ValidationStateKind::Unknown,
        reason,
        "hikvision_hikbtree",
        role.label(),
    );
    HikBTree {
        role,
        declared_offset,
        tree_region,
        recognition,
        header: None,
        pages: Vec::new(),
        traversal: TraversalReport::default(),
        integrity: TreeIntegrity::NotEstablished,
        evidence,
    }
}

fn parse_header(
    profile: &OemProfile,
    page_offset: u64,
    buf: &[u8],
    magic_bytes: Vec<u8>,
) -> TreeHeader {
    let ts_rel = usize_from(profile, key::BTREE_TREE_TIMESTAMP_OFFSET, 60);
    let tree_timestamp = HikTimestamp::decode(
        i32_at(buf, ts_rel).map(|v| v as i64).unwrap_or(0),
        TimestampStructure::BTreeHeader,
        page_offset.saturating_add(ts_rel as u64),
        profile,
    );

    let first_pointer_page_offset = i64_at(
        buf,
        usize_from(profile, key::BTREE_FIRST_POINTER_PAGE_OFFSET, 64),
    );
    let last_pointer_page_offset = i64_at(
        buf,
        usize_from(profile, key::BTREE_LAST_POINTER_PAGE_OFFSET, 72),
    );
    let first_list_page_offset = i64_at(
        buf,
        usize_from(profile, key::BTREE_FIRST_LIST_PAGE_OFFSET, 80),
    );
    let first_leaf_page_offset = i64_at(
        buf,
        usize_from(profile, key::BTREE_FIRST_LEAF_PAGE_OFFSET, 88),
    );
    let declared_page_count = i32_at(buf, usize_from(profile, key::BTREE_PAGE_COUNT_OFFSET, 96));

    let page_count_max = u64_from(profile, key::BTREE_PAGE_COUNT_MAX, 1 << 20);
    let mut notes: Vec<String> = Vec::new();
    match declared_page_count {
        None => notes.push("the page count field is not readable".into()),
        Some(c) if c < 0 => notes.push(format!("the page count field declares {c}")),
        Some(c) if c as u64 > page_count_max => notes.push(format!(
            "the page count field declares {c}, above the structural bound {page_count_max}"
        )),
        Some(_) => {}
    }
    if first_leaf_page_offset.unwrap_or(0) == 0 && first_pointer_page_offset.unwrap_or(0) == 0 {
        notes.push(
            "neither FirstLeafPageOffset nor FirstPointerPageOffset points anywhere, so the tree \
             declares no reachable pages"
                .into(),
        );
    }

    let evidence = if notes.is_empty() {
        vs(
            ValidationStateKind::Pass,
            format!(
                "HIKBTREE header verified at {page_offset} (0x{page_offset:X}): {} declaring {} \
                 page(s)",
                hex_ascii(&magic_bytes),
                declared_page_count.unwrap_or_default()
            ),
            "hikvision_hikbtree_header",
            "tree_header",
        )
    } else {
        vs(
            ValidationStateKind::Review,
            format!(
                "HIKBTREE header at {page_offset} (0x{page_offset:X}) verified its magic but is \
                 qualified: {}",
                notes.join("; ")
            ),
            "hikvision_hikbtree_header",
            "tree_header",
        )
    };

    TreeHeader {
        page_offset,
        magic: magic_bytes,
        tree_timestamp,
        first_pointer_page_offset,
        last_pointer_page_offset,
        first_list_page_offset,
        first_leaf_page_offset,
        declared_page_count,
        evidence,
    }
}

/// A pointer awaiting traversal, with the pointer field that produced it.
struct Pending {
    offset: u64,
    from: String,
}

#[allow(clippy::too_many_arguments)]
fn traverse(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    role: TreeRole,
    header: &TreeHeader,
    tree_region: Option<Region>,
    page_size: u64,
    physical_size: u64,
) -> Result<(Vec<TreePage>, TraversalReport), ForensicError> {
    let guard = u64_from(profile, key::BTREE_TRAVERSAL_MAX_PAGES, 1 << 20) as usize;
    let mut report = TraversalReport {
        declared_page_count: header.declared_page_count,
        ..Default::default()
    };
    let mut pages: Vec<TreePage> = Vec::new();
    let mut visited: BTreeSet<u64> = BTreeSet::new();

    // Seed from every root pointer the header declares. Walking only the leaf root would
    // miss internal pages; walking only the pointer root would miss a tree whose leaves
    // chain directly.
    let mut queue: Vec<Pending> = Vec::new();
    for (name, value) in [
        ("FirstPointerPageOffset", header.first_pointer_page_offset),
        ("FirstLeafPageOffset", header.first_leaf_page_offset),
        ("FirstListPageOffset", header.first_list_page_offset),
        ("LastPointerPageOffset", header.last_pointer_page_offset),
    ] {
        if let Some(v) = value {
            // Zero is "no such page", a legitimate structural statement, not a bad pointer.
            if v != 0 {
                queue.push(Pending {
                    offset: v as u64,
                    from: format!("header {name}"),
                });
            }
        }
    }

    while let Some(pending) = queue.pop() {
        if pages.len() >= guard {
            report.guard_reached = true;
            break;
        }

        let raw = pending.offset;

        // ── Bounds ───────────────────────────────────────────────────────────────
        let in_region = match tree_region {
            Some(r) => raw >= r.offset && raw < r.offset.saturating_add(r.length),
            None => raw < physical_size,
        };
        if !in_region || raw.saturating_add(page_size) > physical_size {
            report.out_of_range_pointers.push(format!(
                "{} -> {raw} (0x{raw:X}) lies outside {}",
                pending.from,
                tree_region
                    .map(|r| format!("the declared tree region {r}"))
                    .unwrap_or_else(|| format!("the {physical_size}-byte evidence"))
            ));
            continue;
        }

        // ── Alignment ────────────────────────────────────────────────────────────
        //
        // Pages are page_size-aligned relative to the start of the tree. The tree itself
        // need not be page-aligned in the image, so alignment is checked against the tree
        // base rather than against absolute zero.
        let base = tree_region.map(|r| r.offset).unwrap_or(0);
        if raw >= base && (raw - base) % page_size != 0 {
            report.misaligned_pointers.push(format!(
                "{} -> {raw} (0x{raw:X}) is not on a {page_size}-byte page boundary relative to the \
                 tree base {base}",
                pending.from
            ));
            continue;
        }

        // ── Cycles and duplicates ────────────────────────────────────────────────
        if !visited.insert(raw) {
            // Reaching a visited page is a cycle when it came from a page pointer, and a
            // benign duplicate when two roots converge. Both are recorded; only the first
            // invalidates completeness, so they are counted separately.
            if pending.from.starts_with("header ") {
                report.duplicates_skipped.push(raw);
            } else {
                report.cycles_detected.push(format!(
                    "{} -> {raw} (0x{raw:X}), which has already been traversed",
                    pending.from
                ));
            }
            continue;
        }

        // ── Read and parse ───────────────────────────────────────────────────────
        let buf = match read_page_bytes(reader, raw, page_size as usize) {
            Ok(b) => b,
            Err(e) => {
                report
                    .unreadable_pages
                    .push(format!("{raw} (0x{raw:X}) via {}: {e}", pending.from));
                continue;
            }
        };

        let page = parse_page(profile, role, raw, &buf);

        match &page.page_type {
            PageType::Unknown { discriminator } => {
                report.invalid_page_types.push(format!(
                    "{raw} (0x{raw:X}) declares type {discriminator}, which is neither leaf nor \
                     internal; its pointers were not followed"
                ));
            }
            PageType::Unreadable { reason } => {
                report
                    .invalid_page_types
                    .push(format!("{raw} (0x{raw:X}): {reason}"));
            }
            PageType::Leaf | PageType::Internal => {
                // Only a page whose layout is known has followable pointers.
                for (name, value) in [
                    ("nextPageOffset", page.next_page_offset),
                    ("otherPageOffset", page.other_page_offset),
                ] {
                    if let Some(v) = value {
                        if v == 0 {
                            continue;
                        }
                        if v < 0 {
                            report.out_of_range_pointers.push(format!(
                                "page {raw} (0x{raw:X}) {name} declares the negative value {v}"
                            ));
                            continue;
                        }
                        queue.push(Pending {
                            offset: v as u64,
                            from: format!("page {raw:#x} {name}"),
                        });
                    }
                }
            }
        }

        pages.push(page);
    }

    report.pages_visited = pages.len();
    // Traversal order is a graph walk; sorting by offset gives a stable, physically
    // meaningful order for reports without losing any page.
    pages.sort_by_key(|p| p.page_offset);
    Ok((pages, report))
}

fn read_page_bytes(
    reader: &dyn EvidenceReader,
    offset: u64,
    size: usize,
) -> Result<Vec<u8>, ForensicError> {
    // A page is a fixed-size structure: a short read means the page is not there, which is
    // different from a page full of zeros.
    reader.read_exact_at(offset, size)
}

fn parse_page(profile: &OemProfile, role: TreeRole, page_offset: u64, buf: &[u8]) -> TreePage {
    let type_rel = usize_from(profile, key::BTREE_PAGE_TYPE_OFFSET, 0);
    let leaf_disc = crate::layout::i32_from(profile, key::BTREE_PAGE_TYPE_LEAF, 2);
    let internal_disc = crate::layout::i32_from(profile, key::BTREE_PAGE_TYPE_INTERNAL, 3);

    let page_type = match i32_at(buf, type_rel) {
        None => PageType::Unreadable {
            reason: format!("the page type field at +{type_rel} is not readable"),
        },
        Some(v) if v == leaf_disc => PageType::Leaf,
        Some(v) if v == internal_disc => PageType::Internal,
        Some(v) => PageType::Unknown { discriminator: v },
    };

    let (declared_entry_count, other_page_offset, next_page_offset, entries, notes) =
        match &page_type {
            PageType::Leaf => {
                let count_rel = usize_from(profile, key::BTREE_LEAF_ENTRY_COUNT_OFFSET, 16);
                let other_rel = usize_from(profile, key::BTREE_LEAF_OTHER_PAGE_OFFSET, 24);
                let next_rel = usize_from(profile, key::BTREE_LEAF_NEXT_PAGE_OFFSET, 32);
                let declared = i32_at(buf, count_rel);
                let (entries, notes) =
                    parse_leaf_entries(profile, role, page_offset, buf, declared);
                (
                    declared,
                    i64_at(buf, other_rel),
                    i64_at(buf, next_rel),
                    entries,
                    notes,
                )
            }
            PageType::Internal => {
                let other_rel = usize_from(profile, key::BTREE_INTERNAL_OTHER_PAGE_OFFSET, 16);
                let next_rel = usize_from(profile, key::BTREE_INTERNAL_NEXT_PAGE_OFFSET, 24);
                (
                    None,
                    i64_at(buf, other_rel),
                    i64_at(buf, next_rel),
                    Vec::new(),
                    Vec::new(),
                )
            }
            // A page whose layout is unknown yields no pointers and no entries. Reading
            // the leaf offsets out of it would be inventing structure.
            PageType::Unknown { .. } | PageType::Unreadable { .. } => {
                (None, None, None, Vec::new(), Vec::new())
            }
        };

    let evidence = match &page_type {
        PageType::Leaf if notes.is_empty() => vs(
            ValidationStateKind::Pass,
            format!(
                "HIKBTREE leaf page at {page_offset} (0x{page_offset:X}) declared {} entry/entries \
                 and {} were parsed",
                declared_entry_count.unwrap_or_default(),
                entries.len()
            ),
            "hikvision_hikbtree_page",
            "leaf_page",
        ),
        PageType::Leaf => vs(
            ValidationStateKind::Review,
            format!(
                "HIKBTREE leaf page at {page_offset} (0x{page_offset:X}) is qualified: {}",
                notes.join("; ")
            ),
            "hikvision_hikbtree_page",
            "leaf_page",
        ),
        PageType::Internal => vs(
            ValidationStateKind::Pass,
            format!("HIKBTREE internal page at {page_offset} (0x{page_offset:X}) parsed"),
            "hikvision_hikbtree_page",
            "internal_page",
        ),
        PageType::Unknown { discriminator } => vs(
            ValidationStateKind::Review,
            format!(
                "the page at {page_offset} (0x{page_offset:X}) declares type {discriminator}, which \
                 is neither leaf ({leaf_disc}) nor internal ({internal_disc}); nothing behind it \
                 was interpreted"
            ),
            "hikvision_hikbtree_page",
            "unknown_page",
        ),
        PageType::Unreadable { reason } => vs(
            ValidationStateKind::Review,
            format!("the page at {page_offset} (0x{page_offset:X}) is unreadable: {reason}"),
            "hikvision_hikbtree_page",
            "unreadable_page",
        ),
    };

    TreePage {
        role,
        page_offset,
        page_type,
        declared_entry_count,
        other_page_offset,
        next_page_offset,
        entries,
        evidence,
    }
}

/// Parse a leaf page's entry array.
///
/// The declared count is honoured but bounded by what physically fits in the page: a
/// declared count larger than the page can hold is a damaged field, and reading past the
/// page would pull unrelated bytes into the index.
fn parse_leaf_entries(
    profile: &OemProfile,
    role: TreeRole,
    page_offset: u64,
    buf: &[u8],
    declared: Option<i32>,
) -> (Vec<BTreeEntry>, Vec<String>) {
    let base = usize_from(profile, key::BTREE_LEAF_ENTRIES_OFFSET, 96);
    let size = usize_from(profile, key::BTREE_ENTRY_SIZE, 48).max(1);
    let cap = usize_from(profile, key::BTREE_LEAF_ENTRY_COUNT_MAX, 83);
    let physical_cap = buf.len().saturating_sub(base) / size;
    let mut notes: Vec<String> = Vec::new();

    let count = match declared {
        None => {
            notes.push("the entry count field is not readable, so no entry was parsed".into());
            0
        }
        Some(c) if c < 0 => {
            notes.push(format!(
                "the entry count field declares {c}; no entry was parsed"
            ));
            0
        }
        Some(c) => {
            let c = c as usize;
            let limit = cap.min(physical_cap);
            if c > limit {
                notes.push(format!(
                    "the entry count field declares {c} but only {limit} entries fit in the page; \
                     the declared count was not trusted past that bound"
                ));
                limit
            } else {
                c
            }
        }
    };

    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let rel = base + i * size;
        let Some(slice) = buf.get(rel..rel + size) else {
            notes.push(format!("entry {i} at +{rel} lies past the end of the page"));
            break;
        };
        entries.push(parse_entry(
            profile,
            role,
            page_offset,
            page_offset.saturating_add(rel as u64),
            i,
            slice,
        ));
    }
    (entries, notes)
}

/// Parse one 48-byte entry.
pub fn parse_entry(
    profile: &OemProfile,
    role: TreeRole,
    page_offset: u64,
    entry_offset: u64,
    index_in_page: usize,
    buf: &[u8],
) -> BTreeEntry {
    let page_ref_rel = usize_from(profile, key::BTREE_ENTRY_PAGE_OFFSET_OFFSET, 0);
    let sentinel_rel = usize_from(profile, key::BTREE_ENTRY_SENTINEL_OFFSET, 8);
    let channel_rel = usize_from(profile, key::BTREE_ENTRY_CHANNEL_OFFSET, 17);
    let start_rel = usize_from(profile, key::BTREE_ENTRY_START_TIME_OFFSET, 24);
    let end_rel = usize_from(profile, key::BTREE_ENTRY_END_TIME_OFFSET, 28);
    let data_rel = usize_from(profile, key::BTREE_ENTRY_DATA_OFFSET_OFFSET, 32);
    let status_rel = usize_from(profile, key::BTREE_ENTRY_STATUS_OFFSET, 40);
    let unknown_rel = usize_from(profile, key::BTREE_ENTRY_UNKNOWN_OFFSET, 44);

    let blank = u64_bits_from(profile, key::BTREE_ENTRY_SENTINEL_BLANK, u64::MAX);
    let populated = u64_bits_from(profile, key::BTREE_ENTRY_SENTINEL_POPULATED, 0);

    let page_offset_field = i64_at(buf, page_ref_rel).unwrap_or(0);
    let sentinel = crate::layout::u64_at(buf, sentinel_rel).unwrap_or(blank);

    let state = if sentinel == blank {
        EntryState::Blank
    } else if sentinel == populated {
        EntryState::Populated
    } else {
        EntryState::Malformed {
            sentinel,
            reason: format!(
                "the state field at +{sentinel_rel} holds 0x{sentinel:016X}, which is neither the \
                 blank sentinel 0x{blank:016X} nor the populated value 0x{populated:016X}; the \
                 entry is malformed or partially overwritten and was not coerced into either state"
            ),
        }
    };

    // ── Channel ──────────────────────────────────────────────────────────────────
    let channel = channel::normalize(
        profile,
        u8_at(buf, channel_rel).unwrap_or(0),
        entry_offset.saturating_add(channel_rel as u64),
        "HIKBTREE entry +17",
        key::BTREE_ENTRY_CHANNEL_MAX,
    );

    // ── Timestamps ───────────────────────────────────────────────────────────────
    let start_time = HikTimestamp::decode(
        i32_at(buf, start_rel).map(|v| v as i64).unwrap_or(0),
        TimestampStructure::EntryStart,
        entry_offset.saturating_add(start_rel as u64),
        profile,
    );
    let end_time = HikTimestamp::decode(
        i32_at(buf, end_rel).map(|v| v as i64).unwrap_or(0),
        TimestampStructure::EntryEnd,
        entry_offset.saturating_add(end_rel as u64),
        profile,
    );

    let data_offset = i64_at(buf, data_rel).unwrap_or(0);
    let status_raw = i32_at(buf, status_rel).unwrap_or(0);
    let unknown_raw = i32_at(buf, unknown_rel).unwrap_or(0);

    // ── Verdict ──────────────────────────────────────────────────────────────────
    let mut notes: Vec<String> = Vec::new();
    if let EntryState::Malformed { reason, .. } = &state {
        notes.push(reason.clone());
    }
    if channel.normalized.is_none() {
        notes.push(channel.note.clone());
    }
    // The +0 back-reference should name the page the entry lives on. A mismatch does not
    // invalidate the entry, but it is exactly the kind of inconsistency an examiner wants.
    if state.is_populated() && page_offset_field != 0 && page_offset_field as u64 != page_offset {
        notes.push(format!(
            "the entry's page back-reference at +{page_ref_rel} declares {page_offset_field} \
             (0x{page_offset_field:X}) but the entry was read from page {page_offset} \
             (0x{page_offset:X})"
        ));
    }
    if state.is_populated() && data_offset <= 0 {
        notes.push(format!(
            "a populated entry declares data offset {data_offset}, which does not address bytes in \
             the evidence"
        ));
    }
    if start_time.incomplete {
        notes.push(
            "the start time holds the incomplete-recording sentinel; the recorder had not finished \
             writing this recording"
                .into(),
        );
    }
    if let (Some(s), Some(e)) = (start_time.unix_seconds, end_time.unix_seconds) {
        if e < s {
            notes.push(format!(
                "the end time {e} precedes the start time {s}; the interval is reported as stored \
                 and was not reordered"
            ));
        }
    }

    let kind = match (&state, notes.is_empty()) {
        (EntryState::Malformed { .. }, _) => ValidationStateKind::Review,
        // A blank slot is a fact about the index, not a problem with it.
        (EntryState::Blank, _) => ValidationStateKind::Unknown,
        (EntryState::Populated, true) => ValidationStateKind::Pass,
        (EntryState::Populated, false) => ValidationStateKind::Review,
    };

    let reason = match (&state, notes.is_empty()) {
        (EntryState::Blank, _) => format!(
            "HIKBTREE entry {index_in_page} at {entry_offset} (0x{entry_offset:X}) is blank: the \
             slot has never been written. This is not a deletion marker and says nothing about the \
             bytes its fields would otherwise point at"
        ),
        (EntryState::Populated, true) => format!(
            "HIKBTREE entry {index_in_page} at {entry_offset} (0x{entry_offset:X}) is populated: \
             channel {}, data offset {data_offset} (0x{data_offset:X}), interval {} -> {}",
            channel
                .normalized
                .map(|c| c.to_string())
                .unwrap_or_else(|| "unknown".into()),
            start_time
                .iso_8601_utc
                .clone()
                .unwrap_or_else(|| "unknown".into()),
            end_time
                .iso_8601_utc
                .clone()
                .unwrap_or_else(|| "unknown".into()),
        ),
        (_, _) => format!(
            "HIKBTREE entry {index_in_page} at {entry_offset} (0x{entry_offset:X}) is qualified: {}",
            notes.join("; ")
        ),
    };

    BTreeEntry {
        role,
        entry_offset,
        page_offset,
        index_in_page,
        page_offset_field,
        sentinel,
        state,
        channel,
        start_time,
        end_time,
        data_offset,
        status_raw,
        unknown_raw,
        evidence: vs(kind, reason, "hikvision_hikbtree_entry", "btree_entry"),
    }
}

fn tree_evidence(
    role: TreeRole,
    offset: u64,
    header: &TreeHeader,
    traversal: &TraversalReport,
    integrity: TreeIntegrity,
    pages: &[TreePage],
) -> ValidationState {
    let populated: usize = pages.iter().map(|p| p.populated_entries().count()).sum();
    let blank: usize = pages
        .iter()
        .flat_map(|p| p.entries.iter())
        .filter(|e| matches!(e.state, EntryState::Blank))
        .count();
    let malformed: usize = pages
        .iter()
        .flat_map(|p| p.entries.iter())
        .filter(|e| matches!(e.state, EntryState::Malformed { .. }))
        .count();

    let base =
        format!(
        "{} HIKBTREE at {offset} (0x{offset:X}): header declares {} page(s); {} page(s) traversed \
         ({} leaf, {} internal); {populated} populated, {blank} blank, {malformed} malformed \
         entry/entries; integrity {}",
        role.label(),
        header.declared_page_count.unwrap_or_default(),
        traversal.pages_visited,
        pages.iter().filter(|p| p.page_type == PageType::Leaf).count(),
        pages
            .iter()
            .filter(|p| p.page_type == PageType::Internal)
            .count(),
        integrity.label(),
    );

    let problems = traversal.problems();
    let kind = match integrity {
        TreeIntegrity::CompleteTraversal if malformed == 0 => ValidationStateKind::Pass,
        TreeIntegrity::NotEstablished => ValidationStateKind::Unknown,
        _ => ValidationStateKind::Review,
    };

    let reason = if problems.is_empty() && malformed == 0 {
        base
    } else {
        let mut all = problems;
        if malformed > 0 {
            all.push(format!(
                "{malformed} entry/entries carry a sentinel that is neither blank nor populated"
            ));
        }
        format!("{base}. Qualifications: {}", all.join("; "))
    };

    vs(kind, reason, "hikvision_hikbtree", role.label())
}

/// How the primary and backup trees relate.
///
/// Produced by [`compare_trees`] and preserved rather than resolved: two indexes that
/// disagree are a finding in their own right, and silently merging them would destroy it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TreeAgreement {
    /// Only one tree was established, so there is nothing to compare.
    SingleTree { role: TreeRole },
    /// Both trees parsed and reference exactly the same data offsets.
    Agree { referenced_offsets: usize },
    /// Both trees parsed but reference different sets.
    Disagree {
        /// Offsets only the primary references.
        primary_only: Vec<u64>,
        /// Offsets only the backup references.
        backup_only: Vec<u64>,
        reason: String,
    },
    /// Neither tree was established.
    NeitherEstablished { reason: String },
}

impl TreeAgreement {
    pub fn label(&self) -> &'static str {
        match self {
            Self::SingleTree { .. } => "single-tree",
            Self::Agree { .. } => "agree",
            Self::Disagree { .. } => "disagree",
            Self::NeitherEstablished { .. } => "neither-established",
        }
    }
}

/// Compare the primary and backup trees without merging them.
pub fn compare_trees(primary: &HikBTree, backup: &HikBTree) -> TreeAgreement {
    match (primary.is_usable(), backup.is_usable()) {
        (false, false) => TreeAgreement::NeitherEstablished {
            reason: format!(
                "neither tree is usable: primary {} ({}), backup {} ({})",
                primary.recognition.label(),
                primary.integrity.label(),
                backup.recognition.label(),
                backup.integrity.label()
            ),
        },
        (true, false) => TreeAgreement::SingleTree {
            role: TreeRole::Primary,
        },
        (false, true) => TreeAgreement::SingleTree {
            role: TreeRole::Backup,
        },
        (true, true) => {
            let p = primary.referenced_data_offsets();
            let b = backup.referenced_data_offsets();
            if p == b {
                TreeAgreement::Agree {
                    referenced_offsets: p.len(),
                }
            } else {
                let primary_only: Vec<u64> = p.difference(&b).copied().collect();
                let backup_only: Vec<u64> = b.difference(&p).copied().collect();
                TreeAgreement::Disagree {
                    reason: format!(
                        "the primary tree references {} data offset(s) and the backup references \
                         {}; {} are unique to the primary and {} to the backup. The two statements \
                         are preserved separately: merging contradictory indexes would destroy the \
                         disagreement, which is itself evidence",
                        p.len(),
                        b.len(),
                        primary_only.len(),
                        backup_only.len()
                    ),
                    primary_only,
                    backup_only,
                }
            }
        }
    }
}

/// Which tree should be treated as the authority, and why.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthoritySelection {
    /// The tree whose statement governs accessibility, when one qualifies.
    pub authority: Option<TreeRole>,
    /// Whether the backup stood in for a missing or weaker primary.
    pub substituted: bool,
    /// How the two trees relate.
    pub agreement: TreeAgreement,
    /// Why this selection was made.
    pub reason: String,
}

/// Choose which tree governs, preferring the primary and falling back to the backup.
///
/// The backup is used when the primary is missing, unverified, or strictly weaker. It is
/// **not** used to patch a primary that parsed: a tree that disagrees with the primary is
/// recorded as a disagreement, and the primary keeps its authority so the reported index is
/// one coherent statement rather than a blend of two.
pub fn select_authority(primary: &HikBTree, backup: &HikBTree) -> AuthoritySelection {
    let agreement = compare_trees(primary, backup);

    let (authority, substituted, reason) = match (primary.is_usable(), backup.is_usable()) {
        (true, true) => {
            if backup.integrity > primary.integrity {
                (
                    Some(TreeRole::Backup),
                    true,
                    format!(
                        "the backup tree traversed further than the primary ({} vs {}), so it was \
                         used as the authority; the primary's own findings are preserved separately",
                        backup.integrity.label(),
                        primary.integrity.label()
                    ),
                )
            } else {
                (
                    Some(TreeRole::Primary),
                    false,
                    format!(
                        "the primary tree is the authority ({}); the backup ({}) was read as \
                         corroborating evidence and not merged into it",
                        primary.integrity.label(),
                        backup.integrity.label()
                    ),
                )
            }
        }
        (true, false) => (
            Some(TreeRole::Primary),
            false,
            format!(
                "the primary tree is the authority ({}); the backup tree is not usable ({}, {})",
                primary.integrity.label(),
                backup.recognition.label(),
                backup.integrity.label()
            ),
        ),
        (false, true) => (
            Some(TreeRole::Backup),
            true,
            format!(
                "the primary tree is not usable ({}, {}), so the backup tree ({}) was used in its \
                 place. The substitution is recorded on every entry it produced",
                primary.recognition.label(),
                primary.integrity.label(),
                backup.integrity.label()
            ),
        ),
        (false, false) => (
            None,
            false,
            format!(
                "neither tree is usable: primary {} ({}), backup {} ({}). No index authority was \
                 established, so absence from the index proves nothing",
                primary.recognition.label(),
                primary.integrity.label(),
                backup.recognition.label(),
                backup.integrity.label()
            ),
        ),
    };

    AuthoritySelection {
        authority,
        substituted,
        agreement,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::tests_support::hikvision_profile;
    use crate::testing::MemReader;

    const PAGE: usize = 4096;
    const ENTRY: usize = 48;
    const ENTRIES_BASE: usize = 96;
    const T_2026: i32 = 1_774_224_000;

    fn put_i32(b: &mut [u8], at: usize, v: i32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put_i64(b: &mut [u8], at: usize, v: i64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// A populated 48-byte entry.
    fn populated_entry(page_offset: u64, channel: u8, start: i32, end: i32, data: i64) -> Vec<u8> {
        let mut e = vec![0u8; ENTRY];
        put_i64(&mut e, 0, page_offset as i64);
        put_u64(&mut e, 8, 0); // populated sentinel
        e[17] = channel;
        put_i32(&mut e, 24, start);
        put_i32(&mut e, 28, end);
        put_i64(&mut e, 32, data);
        put_i32(&mut e, 40, 1);
        put_i32(&mut e, 44, 0x1234);
        e
    }

    /// A never-written 48-byte entry.
    fn blank_entry() -> Vec<u8> {
        let mut e = vec![0u8; ENTRY];
        put_u64(&mut e, 8, u64::MAX);
        e
    }

    /// An entry whose sentinel is neither known value.
    fn malformed_entry() -> Vec<u8> {
        let mut e = vec![0u8; ENTRY];
        put_u64(&mut e, 8, 0xDEAD_BEEF_DEAD_BEEF);
        e
    }

    struct TreeBuilder {
        data: Vec<u8>,
        tree_offset: u64,
    }

    impl TreeBuilder {
        /// `pages` counts pages *including* the header page.
        fn new(tree_offset: u64, pages: usize) -> Self {
            let end = tree_offset as usize + pages * PAGE;
            Self {
                data: vec![0u8; end],
                tree_offset,
            }
        }

        fn page_at(&mut self, index: usize) -> &mut [u8] {
            let start = self.tree_offset as usize + index * PAGE;
            &mut self.data[start..start + PAGE]
        }

        fn page_offset(&self, index: usize) -> u64 {
            self.tree_offset + (index * PAGE) as u64
        }

        fn header(&mut self, first_pointer: u64, first_leaf: u64, page_count: i32) -> &mut Self {
            let p = self.page_at(0);
            p[..8].copy_from_slice(b"HIKBTREE");
            put_i32(p, 60, T_2026);
            put_i64(p, 64, first_pointer as i64);
            put_i64(p, 72, 0);
            put_i64(p, 80, 0);
            put_i64(p, 88, first_leaf as i64);
            put_i32(p, 96, page_count);
            self
        }

        fn leaf(&mut self, index: usize, next: u64, entries: &[Vec<u8>]) -> &mut Self {
            let count = entries.len() as i32;
            let p = self.page_at(index);
            put_i32(p, 0, 2); // leaf
            put_i32(p, 16, count);
            put_i64(p, 24, 0);
            put_i64(p, 32, next as i64);
            for (i, e) in entries.iter().enumerate() {
                let at = ENTRIES_BASE + i * ENTRY;
                p[at..at + ENTRY].copy_from_slice(e);
            }
            self
        }

        fn internal(&mut self, index: usize, other: u64, next: u64) -> &mut Self {
            let p = self.page_at(index);
            put_i32(p, 0, 3); // internal
            put_i64(p, 16, other as i64);
            put_i64(p, 24, next as i64);
            self
        }

        fn reader(&self) -> MemReader {
            MemReader::new(self.data.clone())
        }
    }

    /// A tree with a header and one leaf holding two populated entries.
    fn simple_tree(tree_offset: u64) -> TreeBuilder {
        let mut b = TreeBuilder::new(tree_offset, 2);
        let leaf_off = b.page_offset(1);
        b.header(0, leaf_off, 1);
        b.leaf(
            1,
            0,
            &[
                populated_entry(leaf_off, 0, T_2026, T_2026 + 600, 0x8000_0000),
                populated_entry(leaf_off, 1, T_2026 + 600, T_2026 + 1200, 0xC000_0000),
            ],
        );
        b
    }

    #[test]
    fn a_header_and_one_leaf_page_parse_completely() {
        let p = hikvision_profile();
        let b = simple_tree(0x10000);
        let t = read_tree(
            &b.reader(),
            &p,
            TreeRole::Primary,
            Some(0x10000),
            Some(2 * PAGE as u64),
        )
        .unwrap();

        assert!(t.recognition.is_verified());
        assert_eq!(t.integrity, TreeIntegrity::CompleteTraversal);
        assert_eq!(
            t.traversal.pages_visited, 1,
            "the header page is not a tree page"
        );
        assert_eq!(t.leaf_pages().count(), 1);
        assert_eq!(t.populated_entries().count(), 2);
        assert_eq!(t.evidence.state, ValidationStateKind::Pass);
        let header = t.header.as_ref().unwrap();
        assert_eq!(header.magic, b"HIKBTREE".to_vec());
        assert_eq!(header.declared_page_count, Some(1));
        assert!(header.tree_timestamp.is_decoded());
    }

    #[test]
    fn wrong_magic_at_the_declared_offset_yields_no_index() {
        let p = hikvision_profile();
        let mut data = vec![0u8; 0x20000];
        data[0x10000..0x10008].copy_from_slice(b"NOTATREE");
        let r = MemReader::new(data);
        let t = read_tree(&r, &p, TreeRole::Primary, Some(0x10000), Some(PAGE as u64)).unwrap();
        assert!(!t.recognition.is_verified());
        assert!(matches!(
            t.recognition,
            TreeRecognition::MagicMismatch { .. }
        ));
        assert_eq!(t.integrity, TreeIntegrity::NotEstablished);
        assert!(!t.is_usable());
        assert_eq!(t.entries().count(), 0);
    }

    #[test]
    fn the_magic_existing_does_not_by_itself_make_the_tree_complete() {
        let p = hikvision_profile();
        // Header with the magic, but both root pointers are zero: nothing to traverse.
        let mut b = TreeBuilder::new(0x10000, 1);
        b.header(0, 0, 0);
        let t = read_tree(
            &b.reader(),
            &p,
            TreeRole::Primary,
            Some(0x10000),
            Some(PAGE as u64),
        )
        .unwrap();
        assert!(t.recognition.is_verified());
        assert_eq!(
            t.integrity,
            TreeIntegrity::HeaderOnly,
            "a verified magic with no traversed page is header-only, not authoritative"
        );
        assert!(!t.integrity.is_complete());
        assert_eq!(t.evidence.state, ValidationStateKind::Review);
    }

    #[test]
    fn an_internal_page_is_traversed_and_its_leaf_children_are_reached() {
        let p = hikvision_profile();
        // header -> internal(1) -> other=leaf(2), next=leaf(3)
        let mut b = TreeBuilder::new(0x10000, 4);
        let internal = b.page_offset(1);
        let leaf_a = b.page_offset(2);
        let leaf_b = b.page_offset(3);
        b.header(internal, 0, 3);
        b.internal(1, leaf_a, leaf_b);
        b.leaf(
            2,
            0,
            &[populated_entry(leaf_a, 0, T_2026, T_2026 + 60, 0x4000_0000)],
        );
        b.leaf(
            3,
            0,
            &[populated_entry(leaf_b, 3, T_2026, T_2026 + 60, 0x5000_0000)],
        );

        let t = read_tree(
            &b.reader(),
            &p,
            TreeRole::Primary,
            Some(0x10000),
            Some(4 * PAGE as u64),
        )
        .unwrap();

        assert_eq!(t.internal_pages().count(), 1);
        assert_eq!(t.leaf_pages().count(), 2, "both children must be reached");
        assert_eq!(t.populated_entries().count(), 2);
        assert_eq!(t.integrity, TreeIntegrity::CompleteTraversal);
        assert_eq!(t.referenced_data_offsets().len(), 2);
    }

    #[test]
    fn multiple_leaf_pages_chained_by_next_pointer_are_all_read() {
        let p = hikvision_profile();
        let mut b = TreeBuilder::new(0x10000, 4);
        let l1 = b.page_offset(1);
        let l2 = b.page_offset(2);
        let l3 = b.page_offset(3);
        b.header(0, l1, 3);
        b.leaf(
            1,
            l2,
            &[populated_entry(l1, 0, T_2026, T_2026 + 60, 0x1000_0000)],
        );
        b.leaf(
            2,
            l3,
            &[populated_entry(l2, 1, T_2026, T_2026 + 60, 0x2000_0000)],
        );
        b.leaf(
            3,
            0,
            &[populated_entry(l3, 2, T_2026, T_2026 + 60, 0x3000_0000)],
        );

        let t = read_tree(
            &b.reader(),
            &p,
            TreeRole::Primary,
            Some(0x10000),
            Some(4 * PAGE as u64),
        )
        .unwrap();
        assert_eq!(
            t.leaf_pages().count(),
            3,
            "traversal must not stop at one page"
        );
        assert_eq!(t.populated_entries().count(), 3);
        assert_eq!(t.integrity, TreeIntegrity::CompleteTraversal);
    }

    #[test]
    fn a_page_cycle_is_detected_and_does_not_hang() {
        let p = hikvision_profile();
        let mut b = TreeBuilder::new(0x10000, 3);
        let l1 = b.page_offset(1);
        let l2 = b.page_offset(2);
        b.header(0, l1, 2);
        b.leaf(
            1,
            l2,
            &[populated_entry(l1, 0, T_2026, T_2026 + 60, 0x1000_0000)],
        );
        b.leaf(
            2,
            l1,
            &[populated_entry(l2, 1, T_2026, T_2026 + 60, 0x2000_0000)],
        ); // back to l1

        let t = read_tree(
            &b.reader(),
            &p,
            TreeRole::Primary,
            Some(0x10000),
            Some(3 * PAGE as u64),
        )
        .unwrap();

        assert_eq!(
            t.leaf_pages().count(),
            2,
            "each page is parsed exactly once"
        );
        assert!(
            !t.traversal.cycles_detected.is_empty(),
            "the cycle must be recorded"
        );
        assert_eq!(
            t.integrity,
            TreeIntegrity::PartialTraversal,
            "a tree containing a cycle cannot be a complete statement"
        );
        assert!(!t.integrity.is_complete());
        assert!(t.evidence.reason.contains("cycle"));
    }

    #[test]
    fn a_self_referencing_page_is_a_cycle_not_an_infinite_loop() {
        let p = hikvision_profile();
        let mut b = TreeBuilder::new(0x10000, 2);
        let l1 = b.page_offset(1);
        b.header(0, l1, 1);
        b.leaf(
            1,
            l1,
            &[populated_entry(l1, 0, T_2026, T_2026 + 60, 0x1000_0000)],
        );
        let t = read_tree(
            &b.reader(),
            &p,
            TreeRole::Primary,
            Some(0x10000),
            Some(2 * PAGE as u64),
        )
        .unwrap();
        assert_eq!(t.leaf_pages().count(), 1);
        assert!(!t.traversal.cycles_detected.is_empty());
    }

    #[test]
    fn an_out_of_range_page_pointer_is_rejected_and_recorded() {
        let p = hikvision_profile();
        let mut b = TreeBuilder::new(0x10000, 2);
        let l1 = b.page_offset(1);
        b.header(0, l1, 2);
        // next points far outside the tree region.
        b.leaf(
            1,
            0x7FFF_0000,
            &[populated_entry(l1, 0, T_2026, T_2026 + 60, 0x1000)],
        );

        let t = read_tree(
            &b.reader(),
            &p,
            TreeRole::Primary,
            Some(0x10000),
            Some(2 * PAGE as u64),
        )
        .unwrap();
        assert!(!t.traversal.out_of_range_pointers.is_empty());
        assert_eq!(t.integrity, TreeIntegrity::PartialTraversal);
    }

    #[test]
    fn a_misaligned_page_pointer_is_rejected() {
        let p = hikvision_profile();
        let mut b = TreeBuilder::new(0x10000, 3);
        let l1 = b.page_offset(1);
        b.header(0, l1, 2);
        b.leaf(
            1,
            l1 + 17,
            &[populated_entry(l1, 0, T_2026, T_2026 + 60, 0x1000)],
        );
        let t = read_tree(
            &b.reader(),
            &p,
            TreeRole::Primary,
            Some(0x10000),
            Some(3 * PAGE as u64),
        )
        .unwrap();
        assert!(
            !t.traversal.misaligned_pointers.is_empty(),
            "a pointer off a page boundary must be rejected, not read"
        );
    }

    #[test]
    fn an_unknown_page_type_is_not_walked() {
        let p = hikvision_profile();
        let mut b = TreeBuilder::new(0x10000, 3);
        let bad = b.page_offset(1);
        b.header(0, bad, 2);
        let sibling = b.page_offset(2) as i64;
        {
            let page = b.page_at(1);
            put_i32(page, 0, 99); // neither 2 nor 3
                                  // Plant plausible-looking leaf pointers that must NOT be followed.
            put_i32(page, 16, 1);
            put_i64(page, 32, sibling);
        }
        let t = read_tree(
            &b.reader(),
            &p,
            TreeRole::Primary,
            Some(0x10000),
            Some(3 * PAGE as u64),
        )
        .unwrap();
        assert!(!t.traversal.invalid_page_types.is_empty());
        assert_eq!(
            t.entries().count(),
            0,
            "no entry may be read from an unknown page"
        );
        assert_eq!(t.integrity, TreeIntegrity::PartialTraversal);
    }

    #[test]
    fn a_blank_entry_is_recognized_and_is_not_a_deletion_marker() {
        let p = hikvision_profile();
        let mut b = TreeBuilder::new(0x10000, 2);
        let l1 = b.page_offset(1);
        b.header(0, l1, 1);
        b.leaf(1, 0, &[blank_entry()]);
        let t = read_tree(
            &b.reader(),
            &p,
            TreeRole::Primary,
            Some(0x10000),
            Some(2 * PAGE as u64),
        )
        .unwrap();

        assert_eq!(t.blank_entries().count(), 1);
        assert_eq!(t.populated_entries().count(), 0);
        let e = t.entries().next().unwrap();
        assert_eq!(e.state, EntryState::Blank);
        assert_eq!(e.sentinel, u64::MAX);
        assert!(
            e.evidence.reason.contains("not a deletion marker"),
            "the evidence must say so explicitly: {}",
            e.evidence.reason
        );
        assert_eq!(e.evidence.state, ValidationStateKind::Unknown);
    }

    #[test]
    fn a_populated_entry_decodes_its_channel_timestamps_and_data_offset() {
        let p = hikvision_profile();
        let b = simple_tree(0x10000);
        let t = read_tree(
            &b.reader(),
            &p,
            TreeRole::Primary,
            Some(0x10000),
            Some(2 * PAGE as u64),
        )
        .unwrap();
        let e = t.populated_entries().next().unwrap();
        assert_eq!(e.state, EntryState::Populated);
        assert_eq!(e.channel.raw, 0);
        assert_eq!(
            e.channel.normalized,
            Some(1),
            "0-based byte -> 1-based channel"
        );
        assert_eq!(e.start_time.unix_seconds, Some(T_2026 as i64));
        assert_eq!(e.end_time.unix_seconds, Some(T_2026 as i64 + 600));
        assert_eq!(e.data_offset, 0x8000_0000);
        assert_eq!(e.data_offset_physical(), Some(0x8000_0000));
        assert!(e.references_data());
        assert_eq!(e.status_raw, 1, "EntryStatus is preserved raw");
        assert_eq!(
            e.unknown_raw, 0x1234,
            "the unknown field is preserved, not discarded"
        );
        assert_eq!(e.evidence.state, ValidationStateKind::Pass);
        assert!(e.entry_id().contains("primary"));
    }

    #[test]
    fn a_malformed_sentinel_is_neither_blank_nor_populated() {
        let p = hikvision_profile();
        let mut b = TreeBuilder::new(0x10000, 2);
        let l1 = b.page_offset(1);
        b.header(0, l1, 1);
        b.leaf(1, 0, &[malformed_entry()]);
        let t = read_tree(
            &b.reader(),
            &p,
            TreeRole::Primary,
            Some(0x10000),
            Some(2 * PAGE as u64),
        )
        .unwrap();

        assert_eq!(t.malformed_entries().count(), 1);
        assert_eq!(t.populated_entries().count(), 0);
        assert_eq!(t.blank_entries().count(), 0);
        let e = t.entries().next().unwrap();
        match &e.state {
            EntryState::Malformed { sentinel, reason } => {
                assert_eq!(*sentinel, 0xDEAD_BEEF_DEAD_BEEF);
                assert!(reason.contains("not coerced"));
            }
            other => panic!("expected malformed, got {other:?}"),
        }
        assert_eq!(e.evidence.state, ValidationStateKind::Review);
        // A tree containing a malformed entry is not a clean Pass.
        assert_eq!(t.evidence.state, ValidationStateKind::Review);
    }

    #[test]
    fn an_incomplete_start_time_is_reported_without_inventing_an_instant() {
        let p = hikvision_profile();
        let mut b = TreeBuilder::new(0x10000, 2);
        let l1 = b.page_offset(1);
        b.header(0, l1, 1);
        b.leaf(
            1,
            0,
            &[populated_entry(l1, 0, i32::MAX, T_2026 + 600, 0x8000_0000)],
        );
        let t = read_tree(
            &b.reader(),
            &p,
            TreeRole::Primary,
            Some(0x10000),
            Some(2 * PAGE as u64),
        )
        .unwrap();
        let e = t.populated_entries().next().unwrap();
        assert!(e.is_incomplete());
        assert_eq!(e.start_time.unix_seconds, None);
        assert_eq!(e.evidence.state, ValidationStateKind::Review);
        assert!(e.evidence.reason.contains("incomplete"));
    }

    #[test]
    fn an_implausible_channel_byte_yields_no_channel_number() {
        let p = hikvision_profile();
        let mut b = TreeBuilder::new(0x10000, 2);
        let l1 = b.page_offset(1);
        b.header(0, l1, 1);
        b.leaf(
            1,
            0,
            &[populated_entry(l1, 200, T_2026, T_2026 + 60, 0x8000)],
        );
        let t = read_tree(
            &b.reader(),
            &p,
            TreeRole::Primary,
            Some(0x10000),
            Some(2 * PAGE as u64),
        )
        .unwrap();
        let e = t.populated_entries().next().unwrap();
        assert_eq!(e.channel.raw, 200, "the raw byte survives");
        assert_eq!(e.channel.normalized, None);
        assert_eq!(e.evidence.state, ValidationStateKind::Review);
    }

    #[test]
    fn a_declared_entry_count_above_the_page_capacity_is_not_trusted() {
        let p = hikvision_profile();
        let mut b = TreeBuilder::new(0x10000, 2);
        let l1 = b.page_offset(1);
        b.header(0, l1, 1);
        b.leaf(1, 0, &[populated_entry(l1, 0, T_2026, T_2026 + 60, 0x8000)]);
        // Overwrite the count with an absurd value.
        put_i32(b.page_at(1), 16, 100_000);
        let t = read_tree(
            &b.reader(),
            &p,
            TreeRole::Primary,
            Some(0x10000),
            Some(2 * PAGE as u64),
        )
        .unwrap();
        let page = t.leaf_pages().next().unwrap();
        assert_eq!(
            page.declared_entry_count,
            Some(100_000),
            "the raw count survives"
        );
        assert!(
            page.entries.len() <= 83,
            "no more entries than physically fit may be read: {}",
            page.entries.len()
        );
        assert_eq!(page.evidence.state, ValidationStateKind::Review);
    }

    #[test]
    fn a_negative_entry_count_reads_no_entries() {
        let p = hikvision_profile();
        let mut b = TreeBuilder::new(0x10000, 2);
        let l1 = b.page_offset(1);
        b.header(0, l1, 1);
        b.leaf(1, 0, &[populated_entry(l1, 0, T_2026, T_2026 + 60, 0x8000)]);
        put_i32(b.page_at(1), 16, -5);
        let t = read_tree(
            &b.reader(),
            &p,
            TreeRole::Primary,
            Some(0x10000),
            Some(2 * PAGE as u64),
        )
        .unwrap();
        assert_eq!(t.entries().count(), 0);
    }

    #[test]
    fn no_declared_tree_offset_means_no_tree_and_no_error() {
        let p = hikvision_profile();
        let r = MemReader::new(vec![0u8; 0x2000]);
        let t = read_tree(&r, &p, TreeRole::Backup, None, None).unwrap();
        assert!(matches!(
            t.recognition,
            TreeRecognition::NoOffsetDeclared { .. }
        ));
        assert_eq!(t.integrity, TreeIntegrity::NotEstablished);
        assert!(!t.is_usable());
    }

    #[test]
    fn the_role_is_carried_on_every_page_and_entry() {
        let p = hikvision_profile();
        let b = simple_tree(0x10000);
        let t = read_tree(
            &b.reader(),
            &p,
            TreeRole::Backup,
            Some(0x10000),
            Some(2 * PAGE as u64),
        )
        .unwrap();
        assert_eq!(t.role, TreeRole::Backup);
        for page in &t.pages {
            assert_eq!(page.role, TreeRole::Backup);
            for e in &page.entries {
                assert_eq!(e.role, TreeRole::Backup);
                assert!(e.entry_id().contains("backup"));
            }
        }
    }

    #[test]
    fn two_identical_trees_agree_and_the_primary_keeps_authority() {
        let p = hikvision_profile();
        let b = simple_tree(0x10000);
        let primary = read_tree(
            &b.reader(),
            &p,
            TreeRole::Primary,
            Some(0x10000),
            Some(2 * PAGE as u64),
        )
        .unwrap();
        let backup = read_tree(
            &b.reader(),
            &p,
            TreeRole::Backup,
            Some(0x10000),
            Some(2 * PAGE as u64),
        )
        .unwrap();

        assert!(matches!(
            compare_trees(&primary, &backup),
            TreeAgreement::Agree {
                referenced_offsets: 2
            }
        ));
        let sel = select_authority(&primary, &backup);
        assert_eq!(sel.authority, Some(TreeRole::Primary));
        assert!(!sel.substituted);
        assert!(sel.reason.contains("not merged"));
    }

    #[test]
    fn disagreeing_trees_are_reported_not_merged() {
        let p = hikvision_profile();
        let a = simple_tree(0x10000);
        let mut c = TreeBuilder::new(0x10000, 2);
        let l1 = c.page_offset(1);
        c.header(0, l1, 1);
        // A different data offset: the two trees make different statements.
        c.leaf(
            1,
            0,
            &[populated_entry(l1, 0, T_2026, T_2026 + 600, 0x9999_0000)],
        );

        let primary = read_tree(
            &a.reader(),
            &p,
            TreeRole::Primary,
            Some(0x10000),
            Some(2 * PAGE as u64),
        )
        .unwrap();
        let backup = read_tree(
            &c.reader(),
            &p,
            TreeRole::Backup,
            Some(0x10000),
            Some(2 * PAGE as u64),
        )
        .unwrap();

        match compare_trees(&primary, &backup) {
            TreeAgreement::Disagree {
                primary_only,
                backup_only,
                reason,
            } => {
                assert_eq!(primary_only.len(), 2);
                assert_eq!(backup_only, vec![0x9999_0000]);
                assert!(reason.contains("preserved separately"));
            }
            other => panic!("expected a disagreement, got {other:?}"),
        }

        // Authority stays with the primary; the backup does not patch it.
        let sel = select_authority(&primary, &backup);
        assert_eq!(sel.authority, Some(TreeRole::Primary));
        assert!(!sel.substituted);
    }

    #[test]
    fn the_backup_substitutes_for_an_unusable_primary() {
        let p = hikvision_profile();
        let r_empty = MemReader::new(vec![0u8; 0x2000]);
        let primary = read_tree(
            &r_empty,
            &p,
            TreeRole::Primary,
            Some(0x100),
            Some(PAGE as u64),
        )
        .unwrap();
        let b = simple_tree(0x10000);
        let backup = read_tree(
            &b.reader(),
            &p,
            TreeRole::Backup,
            Some(0x10000),
            Some(2 * PAGE as u64),
        )
        .unwrap();

        assert!(!primary.is_usable());
        let sel = select_authority(&primary, &backup);
        assert_eq!(sel.authority, Some(TreeRole::Backup));
        assert!(sel.substituted, "the substitution must be recorded");
        assert!(sel.reason.contains("in its place"));
        assert!(matches!(sel.agreement, TreeAgreement::SingleTree { .. }));
    }

    #[test]
    fn a_stronger_backup_takes_authority_from_a_weaker_primary() {
        let p = hikvision_profile();
        // Primary: header only.
        let mut weak = TreeBuilder::new(0x10000, 1);
        weak.header(0, 0, 0);
        let primary = read_tree(
            &weak.reader(),
            &p,
            TreeRole::Primary,
            Some(0x10000),
            Some(PAGE as u64),
        )
        .unwrap();
        assert_eq!(primary.integrity, TreeIntegrity::HeaderOnly);

        let b = simple_tree(0x10000);
        let backup = read_tree(
            &b.reader(),
            &p,
            TreeRole::Backup,
            Some(0x10000),
            Some(2 * PAGE as u64),
        )
        .unwrap();
        assert_eq!(backup.integrity, TreeIntegrity::CompleteTraversal);

        let sel = select_authority(&primary, &backup);
        assert_eq!(sel.authority, Some(TreeRole::Backup));
        assert!(sel.substituted);
    }

    #[test]
    fn neither_tree_usable_establishes_no_authority() {
        let p = hikvision_profile();
        let r = MemReader::new(vec![0u8; 0x2000]);
        let primary = read_tree(&r, &p, TreeRole::Primary, Some(0x100), Some(PAGE as u64)).unwrap();
        let backup = read_tree(&r, &p, TreeRole::Backup, None, None).unwrap();
        let sel = select_authority(&primary, &backup);
        assert_eq!(sel.authority, None);
        assert!(sel.reason.contains("absence from the index proves nothing"));
    }

    #[test]
    fn a_page_count_mismatch_prevents_a_complete_verdict() {
        let p = hikvision_profile();
        let mut b = TreeBuilder::new(0x10000, 2);
        let l1 = b.page_offset(1);
        b.header(0, l1, 7); // declares 7 pages, only 1 is reachable
        b.leaf(1, 0, &[populated_entry(l1, 0, T_2026, T_2026 + 60, 0x8000)]);
        let t = read_tree(
            &b.reader(),
            &p,
            TreeRole::Primary,
            Some(0x10000),
            Some(2 * PAGE as u64),
        )
        .unwrap();
        assert_eq!(t.traversal.page_count_agrees(), Some(false));
        assert_eq!(t.integrity, TreeIntegrity::PartialTraversal);
        assert!(t.evidence.reason.contains("declares 7"));
    }

    #[test]
    fn traversal_never_errors_on_hostile_bytes() {
        let p = hikvision_profile();
        // All-0xFF: every pointer is a huge negative i64, every count is -1.
        let mut data = vec![0xFFu8; 0x20000];
        data[0x10000..0x10008].copy_from_slice(b"HIKBTREE");
        let r = MemReader::new(data);
        let t = read_tree(&r, &p, TreeRole::Primary, Some(0x10000), Some(0x1000)).unwrap();
        assert!(t.recognition.is_verified());
        assert!(!t.integrity.is_complete());
        assert_eq!(t.entries().count(), 0);
    }

    #[test]
    fn referenced_data_offsets_are_deduplicated_and_exclude_blank_entries() {
        let p = hikvision_profile();
        let mut b = TreeBuilder::new(0x10000, 2);
        let l1 = b.page_offset(1);
        b.header(0, l1, 1);
        b.leaf(
            1,
            0,
            &[
                populated_entry(l1, 0, T_2026, T_2026 + 60, 0x4000_0000),
                populated_entry(l1, 1, T_2026, T_2026 + 60, 0x4000_0000), // duplicate offset
                blank_entry(),
                malformed_entry(),
            ],
        );
        let t = read_tree(
            &b.reader(),
            &p,
            TreeRole::Primary,
            Some(0x10000),
            Some(2 * PAGE as u64),
        )
        .unwrap();
        let refs = t.referenced_data_offsets();
        assert_eq!(refs.len(), 1, "duplicates collapse");
        assert!(refs.contains(&0x4000_0000));
        assert_eq!(t.blank_entries().count(), 1);
        assert_eq!(t.malformed_entries().count(), 1);
    }
}
