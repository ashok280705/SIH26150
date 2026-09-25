//! # Profile layout, generation geometry and field readers
//!
//! Every Uniview offset, size, stride and magic value used by this crate is read from the
//! versioned profile's `[layout]` table (and its `[[signatures]]`) through this module. The
//! fallbacks below exist only so an older profile revision degrades to the documented value
//! instead of failing the run; each one is also recorded in
//! `profiles/uniview/uniview-ubifs-v1.0.toml`.
//!
//! ## Two generations, one geometry model
//!
//! ```text
//!                 OLD (magic 0x1367)              NEW (magic 0x1587)
//!   0x00000000    SUPER   0x4000                   SUPER   0x4000
//!   0x00004000    UI      0x10000                  UI-CTL  0x10000
//!   0x00014000    unit 1                           UI-DATA n * 0x10000
//!   0x10014000    unit 2                           unit 1
//!                 ...  stride 0x10000000           ...  stride 0x10000000
//! ```
//!
//! Inside every 256 MiB unit the DI region is at +0 (256 KiB) and DATA is addressed in
//! 16 KiB blocks by the DI entry's 14-bit SPtoI block index:
//!
//! ```text
//!   data_offset = unit_base(gen, unit) + SPtoI * data_block_size
//!   unit_base   = gen_unit_base + (unit - 1) * unit_stride        (unit is 1-based)
//! ```
//!
//! All of it is unsigned 64-bit checked arithmetic: an overflowing offset is `None`, never a
//! wrapped value that would silently point at unrelated evidence.

use forensic_core::{OemProfile, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};

/// Named `[layout]` keys, so a typo is a compile error rather than a silent fallback.
pub mod key {
    // ── SUPER ────────────────────────────────────────────────────────────────────
    pub const SUPER_OFFSET: &str = "uniview_super_offset";
    pub const SUPER_SIZE: &str = "uniview_super_size";
    pub const SUPER_MAGIC_OFFSET: &str = "uniview_super_magic_offset";
    pub const SUPER_LAST_WRITE_TIME_OFFSET: &str = "uniview_super_last_write_time_offset";
    pub const SUPER_START_STORAGE_TIME_OFFSET: &str = "uniview_super_start_storage_time_offset";
    pub const SUPER_EC_PORT_ID_OFFSET: &str = "uniview_super_ec_port_id_offset";
    pub const SUPER_EC_PORT_ID_SIZE: &str = "uniview_super_ec_port_id_size";

    // ── Packed timestamp ─────────────────────────────────────────────────────────
    pub const TIMESTAMP_SIZE: &str = "uniview_timestamp_size";
    pub const TIMESTAMP_PLAUSIBLE_MIN_YEAR: &str = "uniview_timestamp_plausible_min_year";
    pub const TIMESTAMP_PLAUSIBLE_MAX_YEAR: &str = "uniview_timestamp_plausible_max_year";

    // ── UI / UI-CTL ──────────────────────────────────────────────────────────────
    pub const UI_OFFSET: &str = "uniview_ui_offset";
    pub const UI_SIZE: &str = "uniview_ui_size";
    pub const UI_ENTRY_SIZE: &str = "uniview_ui_entry_size";
    pub const OLD_UI_CURRENT_UNIT_OFFSET: &str = "uniview_old_ui_current_unit_offset";
    pub const OLD_UI_FIELD_04_OFFSET: &str = "uniview_old_ui_field_04_offset";
    pub const OLD_UI_REWRITED_OFFSET: &str = "uniview_old_ui_rewrited_offset";
    pub const OLD_UI_UNIT_ENTRY_SLOT_ADDEND: &str = "uniview_old_ui_unit_entry_slot_addend";
    pub const OLD_UI_UNIT_COUNT_ADJUST: &str = "uniview_old_ui_unit_count_adjust";
    pub const NEW_UICTL_CURRENT_UNIT_OFFSET: &str = "uniview_new_uictl_current_unit_offset";
    pub const NEW_UICTL_COUNT_OFFSET: &str = "uniview_new_uictl_count_offset";
    pub const NEW_UICTL_REWRITED_OFFSET: &str = "uniview_new_uictl_rewrited_offset";
    pub const NEW_UICTL_ENTRIES_OFFSET: &str = "uniview_new_uictl_entries_offset";
    pub const NEW_UICTL_COUNT_SHIFT: &str = "uniview_new_uictl_count_shift";
    pub const NEW_UICTL_UNIT_COUNT_ADJUST: &str = "uniview_new_uictl_unit_count_adjust";

    // ── UI-DATA (NEW) ────────────────────────────────────────────────────────────
    pub const UI_DATA_BASE: &str = "uniview_ui_data_base";
    pub const UI_DATA_UNIT_SIZE: &str = "uniview_ui_data_unit_size";
    pub const UI_DATA_ENTRIES_PER_UNIT: &str = "uniview_ui_data_entries_per_unit";
    pub const UI_DATA_SCAN_MAX_UNITS: &str = "uniview_ui_data_scan_max_units";

    // ── Units ────────────────────────────────────────────────────────────────────
    pub const OLD_UNIT_BASE: &str = "uniview_old_unit_base";
    pub const NEW_UNIT_BASE: &str = "uniview_new_unit_base";
    pub const UNIT_STRIDE: &str = "uniview_unit_stride";
    pub const UNIT_SIZE: &str = "uniview_unit_size";
    pub const MAX_UNITS: &str = "uniview_max_units";

    // ── DI ───────────────────────────────────────────────────────────────────────
    pub const DI_OFFSET_IN_UNIT: &str = "uniview_di_offset_in_unit";
    pub const DI_SIZE: &str = "uniview_di_size";
    pub const DI_WRITE_BYTES_OFFSET: &str = "uniview_di_write_bytes_offset";
    pub const DI_ENTRY_COUNT_OFFSET: &str = "uniview_di_entry_count_offset";
    pub const DI_HEADER_UNKNOWN_OFFSET: &str = "uniview_di_header_unknown_offset";
    pub const DI_HEADER_UNKNOWN_SIZE: &str = "uniview_di_header_unknown_size";
    pub const DI_ENTRIES_OFFSET: &str = "uniview_di_entries_offset";
    pub const DI_ENTRY_SIZE: &str = "uniview_di_entry_size";
    pub const DI_COUNT_MAX: &str = "uniview_di_count_max";

    // ── disktool .h3crd export ───────────────────────────────────────────────────
    pub const H3CRD_HEADER_SIZE: &str = "uniview_h3crd_header_size";
    pub const H3CRD_CONSTANT_OFFSET: &str = "uniview_h3crd_constant_offset";
    pub const H3CRD_CONSTANT: &str = "uniview_h3crd_constant";

    // ── DATA ─────────────────────────────────────────────────────────────────────
    pub const DATA_BLOCK_SIZE: &str = "uniview_data_block_size";
    pub const SPTOI_BITS: &str = "uniview_sptoi_bits";

    // ── Bounds / performance knobs ───────────────────────────────────────────────
    pub const MAX_EXTRACT_BYTES: &str = "uniview_max_extract_bytes";
    pub const MAX_ANOMALIES_PER_UNIT: &str = "uniview_max_anomalies_per_unit";
    pub const RECOVERY_MAX_ITEMS: &str = "uniview_recovery_max_items";
}

/// Profile-declared signature rule names this crate resolves by name.
pub mod sig {
    pub const SUPER_MAGIC_OLD: &str = "uniview_super_magic_old";
    pub const SUPER_MAGIC_NEW: &str = "uniview_super_magic_new";
    pub const H3CRD_EXPORT_TAG: &str = "uniview_h3crd_export_tag";
}

/// How well a piece of Uniview interpretation is established.
///
/// Every field this crate reports carries one of these, so an examiner can tell a
/// reverse-engineered fact from an inference and from a value the platform merely preserves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Established by the reverse-engineered vendor tooling: location, width and meaning.
    Confirmed,
    /// Location and width are established; the meaning is a well-supported inference.
    StrongInference,
    /// A plausible reading that has not been corroborated. Never drives authoritative output.
    Tentative,
    /// Location known, meaning unknown. Preserved raw, never interpreted.
    Unknown,
}

impl Confidence {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Confirmed => "CONFIRMED",
            Self::StrongInference => "STRONG INFERENCE",
            Self::Tentative => "TENTATIVE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Uniview on-disk generation, identified solely by the SUPER magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Generation {
    /// SUPER magic 0x1367: a single UI region, units start right after it.
    Old,
    /// SUPER magic 0x1587: UI-CTL, a UI-DATA area, and units starting at 0x10014000.
    New,
}

impl Generation {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Old => "OLD",
            Self::New => "NEW",
        }
    }
}

/// Every Uniview layout value, resolved from the profile once per read.
///
/// Resolving up front means the rest of the crate works with plain integers and cannot
/// accidentally consult a different profile key for the same fact in two places.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniviewLayout {
    pub super_offset: u64,
    pub super_size: u64,
    pub magic_offset: usize,
    /// 4-byte SUPER magic patterns, as declared by the profile signatures.
    pub magic_old: Option<Vec<u8>>,
    pub magic_new: Option<Vec<u8>>,
    pub super_last_write_time_offset: usize,
    pub super_start_storage_time_offset: usize,
    pub ec_port_id_offset: usize,
    pub ec_port_id_size: usize,

    pub timestamp_size: usize,
    pub timestamp_plausible_min_year: u16,
    pub timestamp_plausible_max_year: u16,

    pub ui_offset: u64,
    pub ui_size: u64,
    pub ui_entry_size: usize,
    pub old_ui_current_unit_offset: usize,
    pub old_ui_field_04_offset: usize,
    pub old_ui_rewrited_offset: usize,
    /// OLD: the 8-byte time-index entry of unit `u` is UI slot `u + addend`, i.e. at
    /// `UI + (u + 1) * 8`. CONFIRMED from the disktool display and export paths.
    pub old_ui_unit_entry_slot_addend: u64,
    /// OLD: written unit count = `UI[+0x00] + adjust` (adjust = -1). CONFIRMED (FLOW).
    pub old_ui_unit_count_adjust: i64,
    pub new_uictl_current_unit_offset: usize,
    pub new_uictl_count_offset: usize,
    pub new_uictl_rewrited_offset: usize,
    pub new_uictl_entries_offset: usize,
    /// NEW: UI-CTL entry count = `(UI-CTL[+0x04] >> shift) + 1`. CONFIRMED arithmetic.
    pub new_uictl_count_shift: u32,
    /// NEW: written unit count = `UI-CTL[+0x00] + adjust` (adjust = +1). CONFIRMED (FLOW).
    pub new_uictl_unit_count_adjust: i64,

    pub ui_data_base: u64,
    pub ui_data_unit_size: u64,
    pub ui_data_entries_per_unit: usize,
    pub ui_data_scan_max_units: u64,

    pub old_unit_base: u64,
    pub new_unit_base: u64,
    pub unit_stride: u64,
    pub unit_size: u64,
    pub max_units: u64,

    pub di_offset_in_unit: u64,
    pub di_size: u64,
    pub di_write_bytes_offset: usize,
    pub di_entry_count_offset: usize,
    pub di_header_unknown_offset: usize,
    pub di_header_unknown_size: usize,
    pub di_entries_offset: usize,
    pub di_entry_size: usize,
    /// Vendor bound on DI `+0x04`. The count includes record 0 (the header), so `0x4000`
    /// records fill the 256 KiB DI exactly. Above it disktool prints "data index head
    /// abnormal" and continues.
    pub di_count_max: u64,

    pub h3crd_header_size: u64,
    /// Tag at `.h3crd` offset 0 ("iVS8000@huawei-3com"), from the profile signature.
    pub h3crd_tag: Option<Vec<u8>>,
    /// Offset of the u32 constant inside the `.h3crd` header. STRONG INFERENCE from the
    /// export routine's stack-frame layout; checked only as corroboration.
    pub h3crd_constant_offset: usize,
    pub h3crd_constant: u32,

    pub data_block_size: u64,
    pub sptoi_bits: u32,

    pub max_extract_bytes: u64,
    pub max_anomalies_per_unit: usize,
    pub recovery_max_items: usize,
}

impl UniviewLayout {
    /// Resolve every layout value from the profile.
    pub fn from_profile(profile: &OemProfile) -> Self {
        Self {
            super_offset: u64_from(profile, key::SUPER_OFFSET, 0),
            super_size: u64_from(profile, key::SUPER_SIZE, 0x4000),
            magic_offset: usize_from(profile, key::SUPER_MAGIC_OFFSET, 0),
            magic_old: magic(profile, sig::SUPER_MAGIC_OLD),
            magic_new: magic(profile, sig::SUPER_MAGIC_NEW),
            super_last_write_time_offset: usize_from(profile, key::SUPER_LAST_WRITE_TIME_OFFSET, 0x14),
            super_start_storage_time_offset: usize_from(
                profile,
                key::SUPER_START_STORAGE_TIME_OFFSET,
                0x1C,
            ),
            ec_port_id_offset: usize_from(profile, key::SUPER_EC_PORT_ID_OFFSET, 0x2C),
            ec_port_id_size: usize_from(profile, key::SUPER_EC_PORT_ID_SIZE, 0x40),

            timestamp_size: usize_from(profile, key::TIMESTAMP_SIZE, 5),
            timestamp_plausible_min_year: u64_from(profile, key::TIMESTAMP_PLAUSIBLE_MIN_YEAR, 2000)
                .min(u16::MAX as u64) as u16,
            timestamp_plausible_max_year: u64_from(profile, key::TIMESTAMP_PLAUSIBLE_MAX_YEAR, 2100)
                .min(u16::MAX as u64) as u16,

            ui_offset: u64_from(profile, key::UI_OFFSET, 0x4000),
            ui_size: u64_from(profile, key::UI_SIZE, 0x10000),
            ui_entry_size: usize_from(profile, key::UI_ENTRY_SIZE, 8),
            old_ui_current_unit_offset: usize_from(profile, key::OLD_UI_CURRENT_UNIT_OFFSET, 0),
            old_ui_field_04_offset: usize_from(profile, key::OLD_UI_FIELD_04_OFFSET, 4),
            old_ui_rewrited_offset: usize_from(profile, key::OLD_UI_REWRITED_OFFSET, 6),
            old_ui_unit_entry_slot_addend: u64_from(profile, key::OLD_UI_UNIT_ENTRY_SLOT_ADDEND, 1),
            old_ui_unit_count_adjust: i64_from(profile, key::OLD_UI_UNIT_COUNT_ADJUST, -1),
            new_uictl_current_unit_offset: usize_from(profile, key::NEW_UICTL_CURRENT_UNIT_OFFSET, 0),
            new_uictl_count_offset: usize_from(profile, key::NEW_UICTL_COUNT_OFFSET, 4),
            new_uictl_rewrited_offset: usize_from(profile, key::NEW_UICTL_REWRITED_OFFSET, 0x0C),
            new_uictl_entries_offset: usize_from(profile, key::NEW_UICTL_ENTRIES_OFFSET, 0x10),
            new_uictl_count_shift: u64_from(profile, key::NEW_UICTL_COUNT_SHIFT, 13).min(63) as u32,
            new_uictl_unit_count_adjust: i64_from(profile, key::NEW_UICTL_UNIT_COUNT_ADJUST, 1),

            ui_data_base: u64_from(profile, key::UI_DATA_BASE, 0x14000),
            ui_data_unit_size: u64_from(profile, key::UI_DATA_UNIT_SIZE, 0x10000),
            ui_data_entries_per_unit: usize_from(profile, key::UI_DATA_ENTRIES_PER_UNIT, 0x2000),
            ui_data_scan_max_units: u64_from(profile, key::UI_DATA_SCAN_MAX_UNITS, 4096),

            old_unit_base: u64_from(profile, key::OLD_UNIT_BASE, 0x0001_4000),
            new_unit_base: u64_from(profile, key::NEW_UNIT_BASE, 0x1001_4000),
            unit_stride: u64_from(profile, key::UNIT_STRIDE, 0x1000_0000),
            unit_size: u64_from(profile, key::UNIT_SIZE, 0x1000_0000),
            max_units: u64_from(profile, key::MAX_UNITS, 65_536),

            di_offset_in_unit: u64_from(profile, key::DI_OFFSET_IN_UNIT, 0),
            di_size: u64_from(profile, key::DI_SIZE, 0x40000),
            di_write_bytes_offset: usize_from(profile, key::DI_WRITE_BYTES_OFFSET, 0),
            di_entry_count_offset: usize_from(profile, key::DI_ENTRY_COUNT_OFFSET, 4),
            di_header_unknown_offset: usize_from(profile, key::DI_HEADER_UNKNOWN_OFFSET, 8),
            di_header_unknown_size: usize_from(profile, key::DI_HEADER_UNKNOWN_SIZE, 8),
            di_entries_offset: usize_from(profile, key::DI_ENTRIES_OFFSET, 0x10),
            di_entry_size: usize_from(profile, key::DI_ENTRY_SIZE, 0x10),
            di_count_max: u64_from(profile, key::DI_COUNT_MAX, 0x4000),

            h3crd_header_size: u64_from(profile, key::H3CRD_HEADER_SIZE, 0x68),
            h3crd_tag: magic(profile, sig::H3CRD_EXPORT_TAG),
            h3crd_constant_offset: usize_from(profile, key::H3CRD_CONSTANT_OFFSET, 0x64),
            h3crd_constant: u64_from(profile, key::H3CRD_CONSTANT, 0x56B4_C275)
                .min(u32::MAX as u64) as u32,

            data_block_size: u64_from(profile, key::DATA_BLOCK_SIZE, 0x4000),
            sptoi_bits: u64_from(profile, key::SPTOI_BITS, 14).min(32) as u32,

            max_extract_bytes: u64_from(profile, key::MAX_EXTRACT_BYTES, 1 << 30),
            max_anomalies_per_unit: usize_from(profile, key::MAX_ANOMALIES_PER_UNIT, 64),
            recovery_max_items: usize_from(profile, key::RECOVERY_MAX_ITEMS, 1_000_000),
        }
    }

    /// Identify the generation from the 4 SUPER magic bytes.
    ///
    /// Returns `None` when neither profile-declared magic matches — which means "not a
    /// Uniview SUPER", never "assume OLD".
    pub fn generation_for_magic(&self, observed: &[u8]) -> Option<Generation> {
        if self.magic_old.as_deref().is_some_and(|m| observed.starts_with(m)) {
            Some(Generation::Old)
        } else if self.magic_new.as_deref().is_some_and(|m| observed.starts_with(m)) {
            Some(Generation::New)
        } else {
            None
        }
    }

    /// The first unit's physical base for a generation.
    pub fn generation_unit_base(&self, generation: Generation) -> u64 {
        match generation {
            Generation::Old => self.old_unit_base,
            Generation::New => self.new_unit_base,
        }
    }

    /// Physical base of a 1-based unit: `gen_base + (unit - 1) * stride`.
    ///
    /// `None` for unit 0 (units are 1-based) or on overflow.
    pub fn unit_base(&self, generation: Generation, unit: u32) -> Option<u64> {
        let index = u64::from(unit.checked_sub(1)?);
        self.generation_unit_base(generation)
            .checked_add(index.checked_mul(self.unit_stride)?)
    }

    /// Physical offset of a unit's DI region.
    pub fn di_offset(&self, generation: Generation, unit: u32) -> Option<u64> {
        self.unit_base(generation, unit)?
            .checked_add(self.di_offset_in_unit)
    }

    /// Number of DATA-block slots a 14-bit SPtoI can address (`1 << sptoi_bits`).
    pub fn sptoi_limit(&self) -> u64 {
        1u64.checked_shl(self.sptoi_bits).unwrap_or(u64::MAX)
    }

    /// Number of block indices occupied by the DI region at the start of a unit.
    ///
    /// `data_offset = unit_base + SPtoI * block` addresses the whole unit, so indices below
    /// this value land inside DI rather than DATA. Derived from `di_size / data_block_size`.
    pub fn di_blocks(&self) -> u64 {
        if self.data_block_size == 0 {
            return 0;
        }
        self.di_offset_in_unit
            .saturating_add(self.di_size)
            .div_ceil(self.data_block_size)
    }

    /// Number of DATA-block slots a unit physically holds.
    pub fn blocks_per_unit(&self) -> u64 {
        if self.data_block_size == 0 {
            0
        } else {
            self.unit_size / self.data_block_size
        }
    }

    /// Physical offset of the DATA block an SPtoI selects: `unit_base + SPtoI * block`.
    ///
    /// SPtoI is a **block index**, never a byte offset.
    pub fn data_offset(&self, generation: Generation, unit: u32, sptoi: u32) -> Option<u64> {
        if u64::from(sptoi) >= self.sptoi_limit() {
            return None;
        }
        self.unit_base(generation, unit)?
            .checked_add(u64::from(sptoi).checked_mul(self.data_block_size)?)
    }

    /// DI entry capacity: `(di_size - di_entries_offset) / di_entry_size`.
    pub fn di_max_entries(&self) -> u64 {
        if self.di_entry_size == 0 {
            return 0;
        }
        self.di_size.saturating_sub(self.di_entries_offset as u64) / self.di_entry_size as u64
    }

    /// Physical offset of UI-DATA unit `n` (0-based): `ui_data_base + n * ui_data_unit_size`.
    pub fn ui_data_offset(&self, n: u64) -> Option<u64> {
        self.ui_data_base
            .checked_add(n.checked_mul(self.ui_data_unit_size)?)
    }

    /// How many UI-DATA units fit between the UI-DATA base and the NEW unit base.
    pub fn ui_data_capacity(&self) -> u64 {
        if self.ui_data_unit_size == 0 {
            return 0;
        }
        self.new_unit_base.saturating_sub(self.ui_data_base) / self.ui_data_unit_size
    }

    /// Written unit count from the raw UI / UI-CTL `+0x00` value, with the vendor's
    /// generation-specific adjustment: OLD `raw - 1`, NEW `raw + 1` (disktool FLOW).
    ///
    /// Signed, because a raw OLD value of 0 yields -1: that is reported, not clamped.
    pub fn unit_count_from_raw(&self, generation: Generation, raw: u32) -> i64 {
        let adjust = match generation {
            Generation::Old => self.old_ui_unit_count_adjust,
            Generation::New => self.new_uictl_unit_count_adjust,
        };
        i64::from(raw).saturating_add(adjust)
    }

    /// NEW UI-CTL time-index entry count: `(raw >> shift) + 1`.
    pub fn uictl_entry_count(&self, raw_04: u32) -> u64 {
        u64::from(raw_04)
            .checked_shr(self.new_uictl_count_shift)
            .unwrap_or(0)
            .saturating_add(1)
    }

    /// OLD: physical offset of unit `u`'s 8-byte time-index entry, `UI + (u + 1) * 8`.
    ///
    /// `None` for unit 0, on overflow, or when the entry would not lie inside the UI region.
    pub fn old_ui_unit_entry_offset(&self, unit: u32) -> Option<u64> {
        if unit == 0 {
            return None;
        }
        let slot = u64::from(unit).checked_add(self.old_ui_unit_entry_slot_addend)?;
        let rel = slot.checked_mul(self.ui_entry_size as u64)?;
        if rel.checked_add(self.ui_entry_size as u64)? > self.ui_size {
            return None;
        }
        self.ui_offset.checked_add(rel)
    }

    /// NEW: `(UI-DATA unit n, slot, physical offset)` of unit `u`'s time-index entry.
    ///
    /// The global UI-DATA entry index is `u - 1`, so `n = (u - 1) >> 13` and
    /// `slot = (u - 1) & 0x1FFF` (0x2000 entries per UI-DATA unit). CONFIRMED from the
    /// export path.
    pub fn new_ui_data_unit_entry(&self, unit: u32) -> Option<(u64, u64, u64)> {
        let index = u64::from(unit.checked_sub(1)?);
        let per = self.ui_data_entries_per_unit as u64;
        if per == 0 {
            return None;
        }
        let n = index / per;
        let slot = index % per;
        if n >= self.ui_data_capacity() {
            return None;
        }
        let off = self
            .ui_data_offset(n)?
            .checked_add(slot.checked_mul(self.ui_entry_size as u64)?)?;
        Some((n, slot, off))
    }
}

/// Read a non-negative `[layout]` value, falling back to the documented default.
pub fn u64_from(profile: &OemProfile, key: &str, fallback: u64) -> u64 {
    match profile.layout.get(key) {
        Some(v) if *v >= 0 => *v as u64,
        _ => fallback,
    }
}

/// Read a signed `[layout]` value, for generation adjustments that are legitimately negative.
pub fn i64_from(profile: &OemProfile, key: &str, fallback: i64) -> i64 {
    profile.layout.get(key).copied().unwrap_or(fallback)
}

/// [`u64_from`] narrowed to `usize` for slice indexing, saturating.
pub fn usize_from(profile: &OemProfile, key: &str, fallback: usize) -> usize {
    usize::try_from(u64_from(profile, key, fallback as u64)).unwrap_or(usize::MAX)
}

/// Resolve a profile-declared signature pattern by rule name.
///
/// `None` when the profile declares no such rule: the structure is then unverifiable, which
/// callers must never turn into "assume it matched".
pub fn magic(profile: &OemProfile, name: &str) -> Option<Vec<u8>> {
    profile
        .signatures
        .iter()
        .find(|s| s.name == name)
        .and_then(|s| s.pattern_bytes().ok())
        .filter(|p| !p.is_empty())
}

// ── Little-endian readers ───────────────────────────────────────────────────────

/// Little-endian `u16` at `off`, or `None` when out of range.
pub fn u16_at(buf: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    buf.get(off..end).map(|s| u16::from_le_bytes([s[0], s[1]]))
}

/// Little-endian `u32` at `off`, or `None` when out of range.
pub fn u32_at(buf: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    buf.get(off..end)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Single byte at `off`, or `None` when out of range.
pub fn u8_at(buf: &[u8], off: usize) -> Option<u8> {
    buf.get(off).copied()
}

/// `len` bytes at `off`, or `None` when out of range.
pub fn bytes_at(buf: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    let end = off.checked_add(len)?;
    buf.get(off..end)
}

/// Build a `ValidationState`, substituting a fixed reason if the caller's is empty.
///
/// `ValidationState::new` rejects an empty reason; every reason in this crate is non-empty
/// by construction, and this keeps an impossible `Err` from becoming a panic.
pub fn vs(
    state: ValidationStateKind,
    reason: impl Into<String>,
    operation: &str,
    subject: &str,
) -> ValidationState {
    let reason = reason.into();
    ValidationState::new(state, reason, operation, subject).unwrap_or_else(|_| {
        ValidationState::new(state, "no reason recorded", operation, subject)
            .expect("static reason is non-empty")
    })
}

#[cfg(test)]
pub(crate) mod tests_support {
    use forensic_core::OemProfile;

    /// The real, versioned Uniview profile, loaded from the repository.
    pub fn uniview_profile() -> OemProfile {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../profiles/uniview/uniview-ubifs-v1.0.toml"
        );
        OemProfile::from_file(std::path::Path::new(path)).expect("uniview profile loads")
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::uniview_profile;
    use super::*;

    #[test]
    fn the_profile_declares_every_value_the_fallbacks_document() {
        let p = uniview_profile();
        let resolved = UniviewLayout::from_profile(&p);
        let mut empty = p.clone();
        empty.layout.clear();
        let fallback = UniviewLayout::from_profile(&empty);
        // Magic comes from signatures, not layout, so both carry it.
        assert_eq!(resolved, fallback, "profile values and documented fallbacks diverged");
        for k in [
            key::SUPER_SIZE,
            key::UI_OFFSET,
            key::OLD_UNIT_BASE,
            key::NEW_UNIT_BASE,
            key::UNIT_STRIDE,
            key::DI_SIZE,
            key::DATA_BLOCK_SIZE,
            key::SPTOI_BITS,
        ] {
            assert!(p.layout.contains_key(k), "profile is missing {k}");
        }
    }

    #[test]
    fn magic_values_identify_the_generation() {
        let l = UniviewLayout::from_profile(&uniview_profile());
        assert_eq!(l.generation_for_magic(&0x1367u32.to_le_bytes()), Some(Generation::Old));
        assert_eq!(l.generation_for_magic(&0x1587u32.to_le_bytes()), Some(Generation::New));
        assert_eq!(l.generation_for_magic(&0x1368u32.to_le_bytes()), None);
        assert_eq!(l.generation_for_magic(&0x6713u32.to_le_bytes()), None, "byte order matters");
        assert_eq!(l.generation_for_magic(&[0x67, 0x13]), None, "a truncated magic never matches");
    }

    #[test]
    fn unit_bases_follow_the_generation_geometry() {
        let l = UniviewLayout::from_profile(&uniview_profile());
        assert_eq!(l.unit_base(Generation::Old, 1), Some(0x0001_4000));
        assert_eq!(l.unit_base(Generation::New, 1), Some(0x1001_4000));
        assert_eq!(l.unit_base(Generation::Old, 2), Some(0x1001_4000));
        assert_eq!(l.unit_base(Generation::New, 2), Some(0x2001_4000));
        assert_eq!(
            l.unit_base(Generation::New, 3).unwrap() - l.unit_base(Generation::New, 2).unwrap(),
            0x1000_0000,
            "unit stride"
        );
        assert_eq!(l.unit_base(Generation::Old, 0), None, "units are 1-based");
        // Large unit numbers use 64-bit arithmetic without wrapping.
        assert_eq!(
            l.unit_base(Generation::New, 70_000),
            Some(0x1001_4000u64 + 69_999u64 * 0x1000_0000)
        );
        assert_eq!(l.unit_base(Generation::New, u32::MAX).map(|v| v > u32::MAX as u64), Some(true));
    }

    #[test]
    fn sptoi_resolves_to_a_block_not_a_byte_offset() {
        let l = UniviewLayout::from_profile(&uniview_profile());
        assert_eq!(l.sptoi_limit(), 0x4000);
        assert_eq!(l.di_blocks(), 16, "256 KiB DI / 16 KiB blocks");
        assert_eq!(l.blocks_per_unit(), 0x4000);
        assert_eq!(l.data_offset(Generation::Old, 1, 16), Some(0x0001_4000 + 16 * 0x4000));
        assert_eq!(l.data_offset(Generation::New, 1, 16), Some(0x1001_4000 + 16 * 0x4000));
        assert_eq!(
            l.data_offset(Generation::New, 3, 0x3FFF),
            Some(0x1001_4000 + 2 * 0x1000_0000 + 0x3FFF * 0x4000)
        );
        assert_eq!(l.data_offset(Generation::New, 1, 0x4000), None, "SPtoI is 14-bit");
        assert_eq!(l.di_max_entries(), 16_383);
        assert_eq!(l.di_count_max, 0x4000);
        assert_eq!(l.di_count_max * l.di_entry_size as u64, l.di_size, "0x4000 records fill DI");
        assert_eq!(l.ui_data_capacity(), 4096);
        assert_eq!(l.ui_data_offset(2), Some(0x14000 + 2 * 0x10000));
    }

    #[test]
    fn unit_numbering_is_generation_specific() {
        let l = UniviewLayout::from_profile(&uniview_profile());
        assert_eq!(l.unit_count_from_raw(Generation::Old, 5), 4, "OLD: raw - 1");
        assert_eq!(l.unit_count_from_raw(Generation::New, 5), 6, "NEW: raw + 1");
        assert_eq!(l.unit_count_from_raw(Generation::Old, 0), -1, "reported, not clamped");
        assert_eq!(l.unit_count_from_raw(Generation::New, u32::MAX), u32::MAX as i64 + 1);
        assert_eq!(l.uictl_entry_count(0), 1);
        assert_eq!(l.uictl_entry_count(0x1FFF), 1);
        assert_eq!(l.uictl_entry_count(0x2000), 2);
        assert_eq!(l.uictl_entry_count(u32::MAX), (u32::MAX as u64 >> 13) + 1);
    }

    #[test]
    fn old_ui_unit_time_index_addressing() {
        let l = UniviewLayout::from_profile(&uniview_profile());
        assert_eq!(l.old_ui_unit_entry_offset(1), Some(0x4000 + 2 * 8));
        assert_eq!(l.old_ui_unit_entry_offset(7), Some(0x4000 + 8 * 8));
        assert_eq!(l.old_ui_unit_entry_offset(0), None);
        // The last slot that fits in the 64 KiB UI region is 0x1FFF, i.e. unit 0x1FFE.
        assert_eq!(l.old_ui_unit_entry_offset(0x1FFE), Some(0x4000 + 0x1FFF * 8));
        assert_eq!(l.old_ui_unit_entry_offset(0x1FFF), None);
    }

    #[test]
    fn new_ui_data_unit_slot_addressing() {
        let l = UniviewLayout::from_profile(&uniview_profile());
        assert_eq!(l.new_ui_data_unit_entry(1), Some((0, 0, 0x14000)));
        assert_eq!(l.new_ui_data_unit_entry(2), Some((0, 1, 0x14008)));
        assert_eq!(l.new_ui_data_unit_entry(0x2000), Some((0, 0x1FFF, 0x14000 + 0x1FFF * 8)));
        assert_eq!(l.new_ui_data_unit_entry(0x2001), Some((1, 0, 0x24000)));
        for u in [1u32, 77, 0x2001, 0x9ABC] {
            let (n, slot, off) = l.new_ui_data_unit_entry(u).unwrap();
            assert_eq!(n, u64::from(u - 1) >> 13);
            assert_eq!(slot, u64::from(u - 1) & 0x1FFF);
            assert_eq!(off, 0x14000 + u64::from(u - 1) * 8, "units are contiguous across UI-DATA");
        }
        assert_eq!(l.new_ui_data_unit_entry(0), None);
        assert_eq!(l.new_ui_data_unit_entry(4096 * 0x2000 + 1), None, "beyond UI-DATA capacity");
    }

    #[test]
    fn readers_are_total() {
        let b = [1u8, 2, 3];
        assert_eq!(u16_at(&b, 1), Some(0x0302));
        assert_eq!(u16_at(&b, 2), None);
        assert_eq!(u32_at(&b, 0), None);
        assert_eq!(u8_at(&b, 3), None);
        assert_eq!(bytes_at(&b, usize::MAX, 2), None);
    }
}
