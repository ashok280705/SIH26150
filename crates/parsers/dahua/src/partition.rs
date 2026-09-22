//! # DHFS 4.1 partition table and partition information
//!
//! A DHFS 4.1 volume is **partitioned**. The authoritative geometry does not live at fixed
//! superblock offsets; it is reached through a two-step indirection:
//!
//! ```text
//!   partition table  @ 0x3C00 (primary), 0x3E00 / 0x7C00 (secondary candidates)
//!     identifier     @ +304   ........ AA 55 AA 55
//!     entry[i]       @ +64*i  (4 entries max)
//!        +20  i32    SectorOfPartitionInfoInPartition
//!        +48  i64    SectorOfPartitionStart
//!            │
//!            ▼
//!   partition information @ fs_offset + (start + info) * sector_size
//!        +68  i32    IndexStartSector    → block table base
//!        +72  i32    VideoStartSector    → video block base
//!        +76  i32    BlockCount
//! ```
//!
//! ## Why every value is validated before use
//!
//! `SectorOfPartitionStart` is an `i64` of sectors and `IndexStartSector`/`VideoStartSector`
//! are `i32`s. Multiplied by the sector size they can address far beyond any real image, and
//! a damaged or hostile table will. Each field is therefore range-checked against the
//! evidence length **before** it is used in address arithmetic, and a failure is recorded as
//! a reason on the partition rather than clamped into something plausible. A clamped offset
//! would produce a confident-looking read of the wrong bytes.
//!
//! ## Primary vs secondary tables
//!
//! When a secondary partition table is present as well as the primary, the volume has been
//! re-partitioned or repaired: the block metadata the primary table leads to can no longer
//! be assumed to describe the recorder's current accessible recording set. That is recorded
//! as [`PartitionTableSet::downgrade_accessible_to_available`] and carried through to
//! classification, where it turns otherwise-accessible chains into *available* ones. The
//! secondary table is retained and reported, never silently discarded.

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, OemProfile, Region, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};

use crate::layout::{i32_at, i64_at, key, magic, u64_from, usize_from, vs};

/// Which table an entry set was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartitionTableRole {
    /// The table at the primary offset.
    Primary,
    /// A table at one of the secondary candidate offsets.
    Secondary,
}

impl PartitionTableRole {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Secondary => "secondary",
        }
    }
}

/// The partition-table identifier read at `+304`.
///
/// Both known identifiers end in the `AA55AA55` marker pair; the leading dword
/// distinguishes the table generation. An identifier that matches neither declared pattern
/// means the bytes at the table offset are not a partition table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartitionTableIdentifier {
    /// Matched a profile-declared identifier pattern.
    Recognised {
        /// The rule name that matched, e.g. `partition_table_id_gen1`.
        rule: String,
        bytes: Vec<u8>,
    },
    /// Read cleanly but matched no declared identifier.
    Unrecognised { bytes: Vec<u8> },
}

impl PartitionTableIdentifier {
    pub fn is_recognised(&self) -> bool {
        matches!(self, Self::Recognised { .. })
    }

    fn bytes(&self) -> &[u8] {
        match self {
            Self::Recognised { bytes, .. } | Self::Unrecognised { bytes } => bytes,
        }
    }
}

/// One raw partition-table entry, before the partition information is resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionTableEntry {
    /// Slot index within the table, 0-based.
    pub slot: u32,
    /// Physical offset of the 64-byte entry itself, for provenance.
    pub entry_offset: u64,
    /// `SectorOfPartitionInfoInPartition` — sectors from the partition start.
    pub info_sector: i32,
    /// `SectorOfPartitionStart` — sectors from the filesystem disk offset.
    pub start_sector: i64,
}

impl PartitionTableEntry {
    /// Whether the entry describes a partition at all.
    ///
    /// An unused slot reads as all-zero. A zero start sector would place the partition on
    /// top of the volume header, which no populated entry does, so it is the unused marker
    /// rather than a valid partition at sector 0.
    pub fn is_unused(&self) -> bool {
        self.start_sector == 0 && self.info_sector == 0
    }
}

/// The geometry fields read from a partition's own information structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionInfo {
    /// `IndexStartSector` — sectors from the partition start to the block table.
    pub index_start_sector: i32,
    /// `VideoStartSector` — sectors from the partition start to block 0.
    pub video_start_sector: i32,
    /// `BlockCount` — number of 2 MiB video blocks the partition manages.
    pub block_count: i32,
}

/// One partition, with its resolved physical geometry or the reason it has none.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DahuaPartition {
    /// Slot index within the partition table, 0-based. Used as the partition number
    /// everywhere downstream so a fragment can be traced back to its partition.
    pub number: u32,
    /// The table entry this partition came from.
    pub entry: PartitionTableEntry,
    /// Byte offset of the partition's information structure.
    pub info_offset: u64,
    /// The information structure's fields, when they were read and validated.
    pub info: Option<PartitionInfo>,
    /// Physical byte offset of the block table base, when derivable and in bounds.
    pub block_table_offset: Option<u64>,
    /// Physical byte offset of video block 0, when derivable and in bounds.
    pub video_base_offset: Option<u64>,
    /// Declared block count, when it is a plausible non-negative value.
    pub block_count: Option<u32>,
    /// The region the block table occupies, when both its base and extent are known.
    pub block_table_region: Option<Region>,
    /// The region the partition's video blocks occupy, when derivable.
    pub video_region: Option<Region>,
    /// Why this partition's geometry is or is not trustworthy.
    pub evidence: ValidationState,
}

impl DahuaPartition {
    /// Whether this partition has enough validated geometry to read a block table from.
    pub fn is_usable(&self) -> bool {
        self.block_table_offset.is_some()
            && self.video_base_offset.is_some()
            && self.block_count.map(|c| c > 0).unwrap_or(false)
    }
}

/// One partition table, located and validated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PartitionTable {
    pub role: PartitionTableRole,
    /// Physical offset the table was read from.
    pub offset: u64,
    /// Physical extent of the table structure.
    pub region: Option<Region>,
    pub identifier: PartitionTableIdentifier,
    /// Entries that describe a partition. Unused slots are counted, not stored.
    pub partitions: Vec<DahuaPartition>,
    /// How many of the table's slots were unused.
    pub unused_slots: usize,
    pub evidence: ValidationState,
}

impl PartitionTable {
    /// Partitions with validated geometry.
    pub fn usable_partitions(&self) -> impl Iterator<Item = &DahuaPartition> {
        self.partitions.iter().filter(|p| p.is_usable())
    }
}

/// Every partition table found on the volume, and what their combination implies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PartitionTableSet {
    /// The table whose partitions downstream parsing uses. `None` when none verified.
    pub used: Option<PartitionTable>,
    /// Tables that verified but were not used, retained so the structure is not discarded.
    pub additional: Vec<PartitionTable>,
    /// Candidate offsets that were probed and what was found there, including misses, so
    /// the search itself is auditable.
    pub probe_log: Vec<String>,
    /// Whether the combination of tables means chains reached through the used table must
    /// be reported as *available* rather than *accessible*.
    ///
    /// Set when a secondary partition table verified alongside the primary: the volume's
    /// partitioning has changed, so the primary table's block metadata can no longer be
    /// treated as a statement about the recorder's current accessible set. This is
    /// evidence about accessibility, **not** evidence of deletion.
    pub downgrade_accessible_to_available: bool,
    /// Why the downgrade applies, empty when it does not.
    pub downgrade_reason: String,
    pub evidence: ValidationState,
}

impl PartitionTableSet {
    /// An empty set with a stated reason, for volumes with no readable partition table.
    fn none(reason: String, probe_log: Vec<String>) -> Self {
        Self {
            used: None,
            additional: Vec::new(),
            probe_log,
            downgrade_accessible_to_available: false,
            downgrade_reason: String::new(),
            evidence: vs(
                ValidationStateKind::Review,
                reason,
                "dhfs41_partition_table",
                "partition_table",
            ),
        }
    }

    /// Partitions from the used table, or an empty slice.
    pub fn partitions(&self) -> &[DahuaPartition] {
        self.used
            .as_ref()
            .map(|t| t.partitions.as_slice())
            .unwrap_or(&[])
    }

    /// Every table found, used first.
    pub fn all_tables(&self) -> Vec<&PartitionTable> {
        let mut out: Vec<&PartitionTable> = self.used.iter().collect();
        out.extend(self.additional.iter());
        out
    }
}

/// Read and validate every partition table candidate on the volume.
///
/// `fs_disk_offset` is the byte offset of the DHFS filesystem inside the evidence — zero
/// for a whole-volume image. It is applied to every derived address so a volume embedded in
/// a larger image still yields absolute offsets.
pub fn read_partition_tables(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
) -> Result<PartitionTableSet, ForensicError> {
    let disk_len = reader.len();
    let fs_offset = u64_from(profile, key::FILESYSTEM_DISK_OFFSET, 0);
    let sector_size = u64_from(profile, key::SECTOR_SIZE, 512);

    // A zero or non-power-of-two sector size makes every derived address meaningless.
    // Refuse rather than compute with it.
    if sector_size == 0 || !sector_size.is_power_of_two() {
        return Ok(PartitionTableSet::none(
            format!(
                "the profile declares sector_size {sector_size}, which cannot be used for sector \
                 addressing; no partition geometry was derived"
            ),
            Vec::new(),
        ));
    }

    let primary = u64_from(profile, key::PT_PRIMARY_OFFSET, 15_360);
    let secondaries = [
        u64_from(profile, key::PT_SECONDARY_OFFSET_A, 15_872),
        u64_from(profile, key::PT_SECONDARY_OFFSET_B, 31_744),
    ];

    let mut probe_log = Vec::new();
    let mut found: Vec<PartitionTable> = Vec::new();

    for (offset, role) in std::iter::once((primary, PartitionTableRole::Primary)).chain(
        secondaries
            .iter()
            .map(|o| (*o, PartitionTableRole::Secondary)),
    ) {
        match read_table_at(
            reader,
            profile,
            offset,
            role,
            fs_offset,
            sector_size,
            disk_len,
        )? {
            Ok(table) => {
                probe_log.push(format!(
                    "{} candidate at 0x{offset:X}: identifier verified, {} partition(s), {} unused \
                     slot(s)",
                    role.label(),
                    table.partitions.len(),
                    table.unused_slots
                ));
                found.push(table);
            }
            Err(reason) => probe_log.push(format!(
                "{} candidate at 0x{offset:X}: {reason}",
                role.label()
            )),
        }
    }

    if found.is_empty() {
        return Ok(PartitionTableSet::none(
            format!(
                "no DHFS 4.1 partition table verified at any declared candidate offset (primary \
                 0x{primary:X}, secondary 0x{:X}, 0x{:X}); the partition model does not apply to \
                 this volume",
                secondaries[0], secondaries[1]
            ),
            probe_log,
        ));
    }

    // Prefer the primary table when it verified: it is the recorder's own first statement
    // about the layout. Otherwise fall back to the first verified secondary and say so.
    let used_index = found
        .iter()
        .position(|t| t.role == PartitionTableRole::Primary)
        .unwrap_or(0);
    let used = found.remove(used_index);
    let additional = found;

    let secondary_present = additional
        .iter()
        .any(|t| t.role == PartitionTableRole::Secondary)
        || used.role == PartitionTableRole::Secondary;

    let (downgrade, downgrade_reason) = if secondary_present {
        let offsets: Vec<String> = additional
            .iter()
            .filter(|t| t.role == PartitionTableRole::Secondary)
            .map(|t| format!("0x{:X}", t.offset))
            .collect();
        let where_ = if used.role == PartitionTableRole::Secondary {
            format!(
                "the only verified table is the secondary one at 0x{:X}",
                used.offset
            )
        } else {
            format!("a secondary table also verified at {}", offsets.join(", "))
        };
        (
            true,
            format!(
                "The {} partition table at 0x{:X} was used for geometry, but {where_}. A volume \
                 carrying more than one partition table has been re-partitioned or repaired, so the \
                 block metadata reached through the used table cannot be treated as the recorder's \
                 current accessible recording set. Recordings derived from it are reported as \
                 available rather than accessible. This is a statement about accessibility, not \
                 evidence of deletion.",
                used.role.label(),
                used.offset
            ),
        )
    } else {
        (false, String::new())
    };

    let mut reason = format!(
        "DHFS 4.1 partition table read from the {} offset 0x{:X}: {} partition(s), of which {} have \
         validated geometry",
        used.role.label(),
        used.offset,
        used.partitions.len(),
        used.usable_partitions().count(),
    );
    if downgrade {
        reason.push_str("; ");
        reason.push_str(&downgrade_reason);
    }
    if !additional.is_empty() {
        reason.push_str(&format!(
            "; {} additional table(s) retained at {}",
            additional.len(),
            additional
                .iter()
                .map(|t| format!("0x{:X}", t.offset))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let kind = if downgrade || used.usable_partitions().count() == 0 {
        ValidationStateKind::Review
    } else {
        ValidationStateKind::Pass
    };

    Ok(PartitionTableSet {
        used: Some(used),
        additional,
        probe_log,
        downgrade_accessible_to_available: downgrade,
        downgrade_reason,
        evidence: vs(kind, reason, "dhfs41_partition_table", "partition_table"),
    })
}

/// Read one partition-table candidate.
///
/// The outer `Result` is I/O; the inner `Result` is "is there a partition table here?",
/// where `Err(reason)` is a normal, expected negative answer that belongs in the probe log.
#[allow(clippy::type_complexity)]
fn read_table_at(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    offset: u64,
    role: PartitionTableRole,
    fs_offset: u64,
    sector_size: u64,
    disk_len: u64,
) -> Result<Result<PartitionTable, String>, ForensicError> {
    let table_size = u64_from(profile, key::PT_SIZE, 512);
    let id_offset = usize_from(profile, key::PT_IDENTIFIER_OFFSET, 304);
    let id_size = usize_from(profile, key::PT_IDENTIFIER_SIZE, 8);
    let stride = u64_from(profile, key::PT_ENTRY_STRIDE, 64);
    let max_partitions = u64_from(profile, key::PT_MAX_PARTITIONS, 4) as usize;
    let entry_base = u64_from(profile, key::PT_ENTRY_BASE_OFFSET, 0);
    let f_info = usize_from(profile, key::PT_ENTRY_INFO_SECTOR_OFFSET, 20);
    let f_start = usize_from(profile, key::PT_ENTRY_START_SECTOR_OFFSET, 48);

    let table_at = match fs_offset.checked_add(offset) {
        Some(v) => v,
        None => return Ok(Err("table offset overflows u64".to_string())),
    };

    // The table must be wholly inside the evidence: reading a partially present table and
    // treating missing bytes as zeros would invent unused slots.
    let need = table_size.max((id_offset + id_size) as u64);
    if table_at >= disk_len || table_at.saturating_add(need) > disk_len {
        return Ok(Err(format!(
            "lies outside the {disk_len}-byte evidence (needs {need} byte(s) from 0x{table_at:X})"
        )));
    }

    let buf = match reader.read_exact_at(table_at, need as usize) {
        Ok(b) => b,
        Err(e) => return Ok(Err(format!("unreadable: {e}"))),
    };

    let id_bytes = match buf.get(id_offset..id_offset + id_size) {
        Some(s) => s.to_vec(),
        None => return Ok(Err("identifier field lies outside the table".to_string())),
    };
    let identifier = match declared_identifier_rules(profile)
        .into_iter()
        .find(|(_, pattern)| pattern.as_slice() == id_bytes.as_slice())
    {
        Some((rule, _)) => PartitionTableIdentifier::Recognised {
            rule,
            bytes: id_bytes.clone(),
        },
        None => PartitionTableIdentifier::Unrecognised {
            bytes: id_bytes.clone(),
        },
    };

    // An unrecognised identifier means these bytes are not a partition table. Parsing
    // entries out of them would manufacture partitions from unrelated data.
    if !identifier.is_recognised() {
        return Ok(Err(format!(
            "identifier at +{id_offset} is {} which matches no declared partition table identifier",
            identifier
                .bytes()
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" ")
        )));
    }

    let mut partitions = Vec::new();
    let mut unused_slots = 0usize;
    let mut notes: Vec<String> = Vec::new();

    for slot in 0..max_partitions {
        let rel = match entry_base.checked_add((slot as u64).saturating_mul(stride)) {
            Some(v) => v,
            None => break,
        };
        let rel_usize = rel as usize;
        // The entry's two fields must both be inside the table we read.
        let (info_sector, start_sector) = match (
            i32_at(&buf, rel_usize.saturating_add(f_info)),
            i64_at(&buf, rel_usize.saturating_add(f_start)),
        ) {
            (Some(i), Some(s)) => (i, s),
            _ => {
                notes.push(format!(
                    "slot {slot}: entry fields at +{rel} lie outside the {} byte(s) read",
                    buf.len()
                ));
                break;
            }
        };

        let entry = PartitionTableEntry {
            slot: slot as u32,
            entry_offset: table_at.saturating_add(rel),
            info_sector,
            start_sector,
        };

        if entry.is_unused() {
            unused_slots += 1;
            continue;
        }

        partitions.push(resolve_partition(
            reader,
            profile,
            entry,
            fs_offset,
            sector_size,
            disk_len,
        ));
    }

    let mut reason = format!(
        "{} partition table at 0x{table_at:X}: identifier verified, {} populated slot(s), {} unused",
        role.label(),
        partitions.len(),
        unused_slots
    );
    if !notes.is_empty() {
        reason.push_str("; ");
        reason.push_str(&notes.join("; "));
    }

    Ok(Ok(PartitionTable {
        role,
        offset: table_at,
        region: Region::new(table_at, table_size).ok(),
        identifier,
        partitions,
        unused_slots,
        evidence: vs(
            if notes.is_empty() {
                ValidationStateKind::Pass
            } else {
                ValidationStateKind::Review
            },
            reason,
            "dhfs41_partition_table",
            "partition_table",
        ),
    }))
}

/// The declared partition-table identifier patterns, by rule name.
fn declared_identifier_rules(profile: &OemProfile) -> Vec<(String, Vec<u8>)> {
    ["partition_table_id_gen0", "partition_table_id_gen1"]
        .iter()
        .filter_map(|name| magic(profile, name).map(|p| ((*name).to_string(), p)))
        .collect()
}

/// Resolve one partition entry into validated physical geometry.
fn resolve_partition(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    entry: PartitionTableEntry,
    fs_offset: u64,
    sector_size: u64,
    disk_len: u64,
) -> DahuaPartition {
    const OP: &str = "dhfs41_partition_info";
    let subject = format!("partition{}", entry.slot);
    let mut notes: Vec<String> = Vec::new();

    let none = |info_offset: u64, notes: Vec<String>| DahuaPartition {
        number: entry.slot,
        entry,
        info_offset,
        info: None,
        block_table_offset: None,
        video_base_offset: None,
        block_count: None,
        block_table_region: None,
        video_region: None,
        evidence: vs(
            ValidationStateKind::Review,
            notes.join("; "),
            OP,
            &format!("partition{}", entry.slot),
        ),
    };

    // A negative sector value cannot address storage. Reject before any multiplication.
    if entry.start_sector < 0 {
        notes.push(format!(
            "SectorOfPartitionStart is {} (negative) and cannot address storage",
            entry.start_sector
        ));
        return none(0, notes);
    }
    if entry.info_sector < 0 {
        notes.push(format!(
            "SectorOfPartitionInfoInPartition is {} (negative) and cannot address storage",
            entry.info_sector
        ));
        return none(0, notes);
    }

    let partition_base = match sector_byte_offset(fs_offset, entry.start_sector as u64, sector_size)
    {
        Some(v) => v,
        None => {
            notes.push(format!(
                "SectorOfPartitionStart {} * {sector_size} overflows the address space",
                entry.start_sector
            ));
            return none(0, notes);
        }
    };

    let info_offset = match (entry.info_sector as u64)
        .checked_mul(sector_size)
        .and_then(|d| partition_base.checked_add(d))
    {
        Some(v) => v,
        None => {
            notes.push("the partition information offset overflows the address space".to_string());
            return none(0, notes);
        }
    };

    let info_size = u64_from(profile, key::PI_SIZE, 512);
    let f_index = usize_from(profile, key::PI_INDEX_START_SECTOR_OFFSET, 68);
    let f_video = usize_from(profile, key::PI_VIDEO_START_SECTOR_OFFSET, 72);
    let f_count = usize_from(profile, key::PI_BLOCK_COUNT_OFFSET, 76);
    let need = info_size.max((f_count + 4) as u64);

    if info_offset >= disk_len || info_offset.saturating_add(need) > disk_len {
        notes.push(format!(
            "partition information at 0x{info_offset:X} (partition start sector {}, info sector {}) \
             lies outside the {disk_len}-byte evidence",
            entry.start_sector, entry.info_sector
        ));
        return none(info_offset, notes);
    }

    let buf = match reader.read_exact_at(info_offset, need as usize) {
        Ok(b) => b,
        Err(e) => {
            notes.push(format!(
                "partition information at 0x{info_offset:X} could not be read: {e}"
            ));
            return none(info_offset, notes);
        }
    };

    let (index_start_sector, video_start_sector, block_count_raw) = match (
        i32_at(&buf, f_index),
        i32_at(&buf, f_video),
        i32_at(&buf, f_count),
    ) {
        (Some(i), Some(v), Some(c)) => (i, v, c),
        _ => {
            notes.push(format!(
                "partition information fields at +{f_index}/+{f_video}/+{f_count} lie outside the \
                 {} byte(s) read",
                buf.len()
            ));
            return none(info_offset, notes);
        }
    };
    let info = PartitionInfo {
        index_start_sector,
        video_start_sector,
        block_count: block_count_raw,
    };

    // ── Field-by-field validation ───────────────────────────────────────────
    let mut block_table_offset = None;
    let mut video_base_offset = None;
    let mut block_count = None;

    if index_start_sector < 0 {
        notes.push(format!(
            "IndexStartSector is {index_start_sector} (negative); the block table cannot be located"
        ));
    } else {
        match sector_byte_offset(partition_base, index_start_sector as u64, sector_size) {
            Some(v) if v < disk_len => block_table_offset = Some(v),
            Some(v) => notes.push(format!(
                "block table base 0x{v:X} (IndexStartSector {index_start_sector}) lies outside the \
                 {disk_len}-byte evidence"
            )),
            None => notes.push(format!(
                "IndexStartSector {index_start_sector} * {sector_size} overflows the address space"
            )),
        }
    }

    if video_start_sector < 0 {
        notes.push(format!(
            "VideoStartSector is {video_start_sector} (negative); the video region cannot be located"
        ));
    } else {
        match sector_byte_offset(partition_base, video_start_sector as u64, sector_size) {
            Some(v) if v < disk_len => video_base_offset = Some(v),
            Some(v) => notes.push(format!(
                "video base 0x{v:X} (VideoStartSector {video_start_sector}) lies outside the \
                 {disk_len}-byte evidence"
            )),
            None => notes.push(format!(
                "VideoStartSector {video_start_sector} * {sector_size} overflows the address space"
            )),
        }
    }

    // Region ordering: the block table must precede the video blocks it indexes. An
    // inverted layout means the two fields were misread or the structure is damaged, and
    // reading a block table out of video payload would manufacture chains.
    if let (Some(bt), Some(vb)) = (block_table_offset, video_base_offset) {
        if bt >= vb {
            notes.push(format!(
                "block table base 0x{bt:X} is not before the video base 0x{vb:X}; the index and \
                 video regions are inconsistent, so neither is used"
            ));
            block_table_offset = None;
            video_base_offset = None;
        }
    }

    if block_count_raw <= 0 {
        notes.push(format!(
            "BlockCount is {block_count_raw}; the partition declares no video blocks"
        ));
    } else {
        block_count = Some(block_count_raw as u32);
    }

    // Cross-check the declared block count against what the evidence can physically hold.
    // A count that would run past the end of the image is reported and reduced to what is
    // present, because the blocks that ARE present are still recoverable evidence.
    let block_size = u64_from(profile, key::VIDEO_BLOCK_SIZE, 2 * 1024 * 1024);
    if let (Some(vb), Some(count)) = (video_base_offset, block_count) {
        if block_size == 0 {
            notes.push("the profile declares a zero video block size".to_string());
            block_count = None;
        } else {
            let declared_end = (count as u64)
                .checked_mul(block_size)
                .and_then(|b| vb.checked_add(b));
            match declared_end {
                Some(end) if end <= disk_len => {}
                _ => {
                    let available = disk_len.saturating_sub(vb) / block_size;
                    notes.push(format!(
                        "BlockCount {count} would place the video region past the end of the \
                         {disk_len}-byte evidence; only {available} whole block(s) are physically \
                         present and the count is reduced to that"
                    ));
                    block_count = if available > 0 {
                        Some(available.min(u32::MAX as u64) as u32)
                    } else {
                        None
                    };
                }
            }
        }
    }

    let block_table_region = match (block_table_offset, block_count) {
        (Some(base), Some(count)) => {
            let entry_size = u64_from(profile, key::BT_ENTRY_SIZE, 32);
            (count as u64)
                .checked_mul(entry_size)
                .map(|len| len.min(disk_len.saturating_sub(base)))
                .and_then(|len| Region::new(base, len).ok())
        }
        _ => None,
    };
    let video_region = match (video_base_offset, block_count) {
        (Some(base), Some(count)) => (count as u64)
            .checked_mul(block_size)
            .map(|len| len.min(disk_len.saturating_sub(base)))
            .and_then(|len| Region::new(base, len).ok()),
        _ => None,
    };

    let usable =
        block_table_offset.is_some() && video_base_offset.is_some() && block_count.is_some();
    let mut reason = format!(
        "partition {} at sector {} (byte 0x{partition_base:X}): info at 0x{info_offset:X} declares \
         IndexStartSector={index_start_sector}, VideoStartSector={video_start_sector}, \
         BlockCount={block_count_raw}; block table {}, video base {}",
        entry.slot,
        entry.start_sector,
        block_table_offset
            .map(|v| format!("0x{v:X}"))
            .unwrap_or_else(|| "unresolved".into()),
        video_base_offset
            .map(|v| format!("0x{v:X}"))
            .unwrap_or_else(|| "unresolved".into()),
    );
    if !notes.is_empty() {
        reason.push_str("; ");
        reason.push_str(&notes.join("; "));
    }

    DahuaPartition {
        number: entry.slot,
        entry,
        info_offset,
        info: Some(info),
        block_table_offset,
        video_base_offset,
        block_count,
        block_table_region,
        video_region,
        evidence: vs(
            if usable && notes.is_empty() {
                ValidationStateKind::Pass
            } else {
                ValidationStateKind::Review
            },
            reason,
            OP,
            &subject,
        ),
    }
}

/// `base + sectors * sector_size`, or `None` on overflow.
fn sector_byte_offset(base: u64, sectors: u64, sector_size: u64) -> Option<u64> {
    sectors.checked_mul(sector_size)?.checked_add(base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::tests_support::dahua_profile;
    use crate::testing::MemReader;

    const SECTOR: u64 = 512;
    const PRIMARY: u64 = 0x3C00;
    const SECONDARY_A: u64 = 0x3E00;
    const BLOCK: u64 = 2 * 1024 * 1024;

    struct Builder {
        bytes: Vec<u8>,
    }

    impl Builder {
        fn new(len: usize) -> Self {
            let mut bytes = vec![0u8; len];
            bytes[..8].copy_from_slice(b"DHFS4.1\0");
            Self { bytes }
        }

        fn table(mut self, at: u64, id: &[u8]) -> Self {
            let a = at as usize;
            self.bytes[a + 304..a + 312].copy_from_slice(id);
            self
        }

        fn entry(mut self, table: u64, slot: u64, info_sector: i32, start_sector: i64) -> Self {
            let e = (table + slot * 64) as usize;
            self.bytes[e + 20..e + 24].copy_from_slice(&info_sector.to_le_bytes());
            self.bytes[e + 48..e + 56].copy_from_slice(&start_sector.to_le_bytes());
            self
        }

        fn info(mut self, at: u64, index_start: i32, video_start: i32, block_count: i32) -> Self {
            let a = at as usize;
            self.bytes[a + 68..a + 72].copy_from_slice(&index_start.to_le_bytes());
            self.bytes[a + 72..a + 76].copy_from_slice(&video_start.to_le_bytes());
            self.bytes[a + 76..a + 80].copy_from_slice(&block_count.to_le_bytes());
            self
        }

        fn build(self) -> MemReader {
            MemReader::new(self.bytes)
        }
    }

    /// One partition starting at sector 128 (byte 0x10000), info one sector in,
    /// block table 2 sectors in, video blocks 64 sectors in, 3 blocks.
    fn single_partition_volume() -> MemReader {
        let start_sector: i64 = 128;
        let base = start_sector as u64 * SECTOR;
        let info_at = base + SECTOR;
        let total = (base + 64 * SECTOR + 3 * BLOCK + SECTOR) as usize;
        Builder::new(total)
            .table(PRIMARY, &[0x01, 0, 0, 0, 0xAA, 0x55, 0xAA, 0x55])
            .entry(PRIMARY, 0, 1, start_sector)
            .info(info_at, 2, 64, 3)
            .build()
    }

    #[test]
    fn the_primary_table_is_located_by_its_identifier() {
        let p = dahua_profile();
        let set = read_partition_tables(&single_partition_volume(), &p).unwrap();
        let used = set.used.as_ref().expect("primary table verified");
        assert_eq!(used.role, PartitionTableRole::Primary);
        assert_eq!(used.offset, PRIMARY);
        assert!(used.identifier.is_recognised());
        match &used.identifier {
            PartitionTableIdentifier::Recognised { rule, .. } => {
                assert_eq!(rule, "partition_table_id_gen1")
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(used.partitions.len(), 1);
        assert_eq!(used.unused_slots, 3, "the other three slots are unused");
    }

    #[test]
    fn partition_information_is_read_through_the_documented_indirection() {
        let p = dahua_profile();
        let set = read_partition_tables(&single_partition_volume(), &p).unwrap();
        let part = &set.partitions()[0];
        let base = 128 * SECTOR;

        assert_eq!(part.info_offset, base + SECTOR, "start + info sector");
        assert_eq!(
            part.info,
            Some(PartitionInfo {
                index_start_sector: 2,
                video_start_sector: 64,
                block_count: 3
            })
        );
        assert_eq!(part.block_table_offset, Some(base + 2 * SECTOR));
        assert_eq!(part.video_base_offset, Some(base + 64 * SECTOR));
        assert_eq!(part.block_count, Some(3));
        assert!(part.is_usable());
        assert_eq!(part.evidence.state, ValidationStateKind::Pass);
        // The derived regions describe exactly the declared extents.
        assert_eq!(
            part.video_region,
            Some(Region::new(base + 64 * SECTOR, 3 * BLOCK).unwrap())
        );
        assert_eq!(
            part.block_table_region,
            Some(Region::new(base + 2 * SECTOR, 3 * 32).unwrap())
        );
    }

    #[test]
    fn the_gen0_identifier_is_also_recognised() {
        let p = dahua_profile();
        let start_sector: i64 = 128;
        let base = start_sector as u64 * SECTOR;
        let r = Builder::new((base + 64 * SECTOR + BLOCK + SECTOR) as usize)
            .table(PRIMARY, &[0x00, 0, 0, 0, 0xAA, 0x55, 0xAA, 0x55])
            .entry(PRIMARY, 0, 1, start_sector)
            .info(base + SECTOR, 2, 64, 1)
            .build();
        let set = read_partition_tables(&r, &p).unwrap();
        match &set.used.as_ref().unwrap().identifier {
            PartitionTableIdentifier::Recognised { rule, .. } => {
                assert_eq!(rule, "partition_table_id_gen0")
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_wrong_identifier_is_not_parsed_as_a_partition_table() {
        let p = dahua_profile();
        let start_sector: i64 = 128;
        let base = start_sector as u64 * SECTOR;
        let r = Builder::new((base + 64 * SECTOR + BLOCK + SECTOR) as usize)
            // AA55AA55 absent: these bytes are not a partition table.
            .table(PRIMARY, &[0x01, 0, 0, 0, 0xDE, 0xAD, 0xBE, 0xEF])
            .entry(PRIMARY, 0, 1, start_sector)
            .info(base + SECTOR, 2, 64, 1)
            .build();
        let set = read_partition_tables(&r, &p).unwrap();
        assert!(set.used.is_none(), "no table may be claimed");
        assert!(set.partitions().is_empty());
        assert_eq!(set.evidence.state, ValidationStateKind::Review);
        assert!(
            set.probe_log
                .iter()
                .any(|l| l.contains("matches no declared")),
            "the miss must be logged: {:?}",
            set.probe_log
        );
    }

    #[test]
    fn multiple_partitions_are_read_with_independent_geometry() {
        let p = dahua_profile();
        let s0: i64 = 128;
        let s1: i64 = 4096;
        let b0 = s0 as u64 * SECTOR;
        let b1 = s1 as u64 * SECTOR;
        let total = (b1 + 64 * SECTOR + 2 * BLOCK + SECTOR) as usize;
        let r = Builder::new(total)
            .table(PRIMARY, &[0x01, 0, 0, 0, 0xAA, 0x55, 0xAA, 0x55])
            .entry(PRIMARY, 0, 1, s0)
            .entry(PRIMARY, 1, 3, s1)
            .info(b0 + SECTOR, 2, 32, 1)
            .info(b1 + 3 * SECTOR, 8, 64, 2)
            .build();

        let set = read_partition_tables(&r, &p).unwrap();
        let parts = set.partitions();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].number, 0);
        assert_eq!(parts[1].number, 1);
        // Each partition's video base is derived from its OWN start sector, not a shared one.
        assert_eq!(parts[0].video_base_offset, Some(b0 + 32 * SECTOR));
        assert_eq!(parts[1].video_base_offset, Some(b1 + 64 * SECTOR));
        assert_eq!(parts[0].block_table_offset, Some(b0 + 2 * SECTOR));
        assert_eq!(parts[1].block_table_offset, Some(b1 + 8 * SECTOR));
        assert!(parts.iter().all(|x| x.is_usable()));
    }

    #[test]
    fn a_secondary_table_downgrades_accessible_to_available_and_is_retained() {
        let p = dahua_profile();
        let start_sector: i64 = 128;
        let base = start_sector as u64 * SECTOR;
        let total = (base + 64 * SECTOR + BLOCK + SECTOR) as usize;
        let r = Builder::new(total)
            .table(PRIMARY, &[0x01, 0, 0, 0, 0xAA, 0x55, 0xAA, 0x55])
            .entry(PRIMARY, 0, 1, start_sector)
            .table(SECONDARY_A, &[0x00, 0, 0, 0, 0xAA, 0x55, 0xAA, 0x55])
            .entry(SECONDARY_A, 0, 1, start_sector)
            .info(base + SECTOR, 2, 64, 1)
            .build();

        let set = read_partition_tables(&r, &p).unwrap();
        // The primary is still used for geometry.
        assert_eq!(set.used.as_ref().unwrap().role, PartitionTableRole::Primary);
        // The secondary is kept, not discarded.
        assert_eq!(set.additional.len(), 1);
        assert_eq!(set.additional[0].offset, SECONDARY_A);
        // And the distinction is surfaced as status, not hidden.
        assert!(set.downgrade_accessible_to_available);
        assert!(set
            .downgrade_reason
            .contains("available rather than accessible"));
        assert!(
            set.downgrade_reason.contains("not evidence of deletion"),
            "the downgrade must not be mistaken for a deletion finding"
        );
        assert_eq!(set.evidence.state, ValidationStateKind::Review);
    }

    #[test]
    fn an_out_of_bounds_partition_start_is_rejected_not_clamped() {
        let p = dahua_profile();
        let r = Builder::new(1 << 20)
            .table(PRIMARY, &[0x01, 0, 0, 0, 0xAA, 0x55, 0xAA, 0x55])
            // 1 << 40 sectors is far beyond a 1 MiB image.
            .entry(PRIMARY, 0, 1, 1 << 40)
            .build();
        let set = read_partition_tables(&r, &p).unwrap();
        let part = &set.partitions()[0];
        assert!(part.info.is_none());
        assert!(part.block_table_offset.is_none());
        assert!(part.video_base_offset.is_none());
        assert!(!part.is_usable());
        assert_eq!(part.evidence.state, ValidationStateKind::Review);
        assert!(part.evidence.reason.contains("outside"));
    }

    #[test]
    fn a_negative_start_sector_is_rejected_before_any_multiplication() {
        let p = dahua_profile();
        let r = Builder::new(1 << 20)
            .table(PRIMARY, &[0x01, 0, 0, 0, 0xAA, 0x55, 0xAA, 0x55])
            .entry(PRIMARY, 0, 1, -64)
            .build();
        let set = read_partition_tables(&r, &p).unwrap();
        let part = &set.partitions()[0];
        assert!(!part.is_usable());
        assert!(part.evidence.reason.contains("negative"));
    }

    #[test]
    fn an_inverted_index_video_ordering_invalidates_both_regions() {
        let p = dahua_profile();
        let start_sector: i64 = 128;
        let base = start_sector as u64 * SECTOR;
        let r = Builder::new((base + 128 * SECTOR + BLOCK) as usize)
            .table(PRIMARY, &[0x01, 0, 0, 0, 0xAA, 0x55, 0xAA, 0x55])
            .entry(PRIMARY, 0, 1, start_sector)
            // Video region declared BEFORE the block table that indexes it.
            .info(base + SECTOR, 64, 2, 1)
            .build();
        let set = read_partition_tables(&r, &p).unwrap();
        let part = &set.partitions()[0];
        assert!(part.block_table_offset.is_none());
        assert!(part.video_base_offset.is_none());
        assert!(part.evidence.reason.contains("not before the video base"));
    }

    #[test]
    fn a_zero_or_negative_block_count_yields_no_blocks() {
        let p = dahua_profile();
        let start_sector: i64 = 128;
        let base = start_sector as u64 * SECTOR;
        for count in [0i32, -5] {
            let r = Builder::new((base + 64 * SECTOR + BLOCK) as usize)
                .table(PRIMARY, &[0x01, 0, 0, 0, 0xAA, 0x55, 0xAA, 0x55])
                .entry(PRIMARY, 0, 1, start_sector)
                .info(base + SECTOR, 2, 64, count)
                .build();
            let set = read_partition_tables(&r, &p).unwrap();
            let part = &set.partitions()[0];
            assert!(part.block_count.is_none(), "count {count}");
            assert!(!part.is_usable());
            assert!(part.evidence.reason.contains("declares no video blocks"));
        }
    }

    #[test]
    fn an_overlarge_block_count_is_reduced_to_what_is_physically_present() {
        let p = dahua_profile();
        let start_sector: i64 = 128;
        let base = start_sector as u64 * SECTOR;
        // Room for exactly 2 whole blocks after the video base.
        let total = (base + 64 * SECTOR + 2 * BLOCK) as usize;
        let r = Builder::new(total)
            .table(PRIMARY, &[0x01, 0, 0, 0, 0xAA, 0x55, 0xAA, 0x55])
            .entry(PRIMARY, 0, 1, start_sector)
            .info(base + SECTOR, 2, 64, 4096)
            .build();
        let set = read_partition_tables(&r, &p).unwrap();
        let part = &set.partitions()[0];
        assert_eq!(part.block_count, Some(2));
        assert!(part.evidence.reason.contains("only 2 whole block(s)"));
        assert_eq!(part.evidence.state, ValidationStateKind::Review);
        assert_eq!(
            part.info.unwrap().block_count,
            4096,
            "the declared value is retained"
        );
    }

    #[test]
    fn a_volume_with_no_partition_table_reports_it_rather_than_inventing_one() {
        let p = dahua_profile();
        let r = MemReader::new(vec![0u8; 1 << 20]);
        let set = read_partition_tables(&r, &p).unwrap();
        assert!(set.used.is_none());
        assert!(!set.downgrade_accessible_to_available);
        assert_eq!(set.evidence.state, ValidationStateKind::Review);
        assert!(set.evidence.reason.contains("does not apply"));
        assert_eq!(set.probe_log.len(), 3, "all three candidates were probed");
    }

    #[test]
    fn a_volume_too_small_for_the_table_offset_is_probed_and_missed_cleanly() {
        let p = dahua_profile();
        let set = read_partition_tables(&MemReader::new(vec![0u8; 1024]), &p).unwrap();
        assert!(set.used.is_none());
        assert!(set
            .probe_log
            .iter()
            .all(|l| l.contains("outside the 1024-byte evidence")));
    }

    #[test]
    fn a_secondary_only_volume_uses_the_secondary_and_says_so() {
        let p = dahua_profile();
        let start_sector: i64 = 128;
        let base = start_sector as u64 * SECTOR;
        let r = Builder::new((base + 64 * SECTOR + BLOCK) as usize)
            .table(SECONDARY_A, &[0x01, 0, 0, 0, 0xAA, 0x55, 0xAA, 0x55])
            .entry(SECONDARY_A, 0, 1, start_sector)
            .info(base + SECTOR, 2, 64, 1)
            .build();
        let set = read_partition_tables(&r, &p).unwrap();
        let used = set.used.as_ref().unwrap();
        assert_eq!(used.role, PartitionTableRole::Secondary);
        assert!(set.downgrade_accessible_to_available);
        assert!(set
            .downgrade_reason
            .contains("only verified table is the secondary"));
    }
}
