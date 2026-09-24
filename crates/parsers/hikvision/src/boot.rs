//! # Hikvision boot structure
//!
//! The boot structure is the root of every Hikvision filesystem fact this crate
//! establishes. It carries the filesystem identifier, the start of the video region, the
//! block geometry, and the offsets of the primary and backup index trees:
//!
//! ```text
//!   boot + 16    32-byte identifier field, beginning "HIKVISION@HANGZHOU"
//!   boot + 120   i64   VideoStartOffset
//!   boot + 136   i64   BlockSize
//!   boot + 144   i32   NumberOfBlocks
//!   boot + 152   i64   BTreeOffset
//!   boot + 160   i64   BTreeSize
//!   boot + 168   i64   BackupBTreeOffset
//!   boot + 176   i64   BackupBTreeSize
//! ```
//!
//! Every offset above is **relative to the detected boot position**, not to the start of
//! the image. Two boot positions have been observed (`0x200` and `0x4C56000`); this module
//! tries each declared candidate and records which one produced the identifier, so the
//! physical provenance of every derived offset stays traceable.
//!
//! ## Recognition is evidence-based
//!
//! [`recognize`] returns one of four distinguishable answers. Keeping them apart matters:
//!
//! | Outcome                                | Meaning                                              |
//! |----------------------------------------|------------------------------------------------------|
//! | [`BootRecognition::Recognized`]        | the identifier was read at a declared boot position  |
//! | [`BootRecognition::IdentifierMismatch`]| a readable field, but not the Hikvision identifier   |
//! | [`BootRecognition::Malformed`]         | the identifier matched, the rest of the boot did not |
//! | [`BootRecognition::NotFound`]          | no declared boot position was readable               |
//!
//! `IdentifierMismatch` is the answer for a random disk image, and it is what stops the
//! Hikvision path from claiming evidence it has no basis for.
//!
//! ## Fallbacks are narrow by design
//!
//! A field that declares **zero** is treated as "the recorder did not write this", and the
//! profile's documented fallback applies — that is the only case the brief permits. A field
//! that declares an *impossible* value (out of bounds, absurd block size) is reported
//! [`ValueOrigin::Malformed`] and left unusable. Replacing an impossible value with a
//! plausible one would manufacture a filesystem.

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, OemProfile, Region, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::layout::{hex_ascii, i32_at, i64_at, key, magic, sig, u64_from, usize_from, vs};

/// Where a boot field's effective value came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueOrigin {
    /// Read from the structure and used exactly as declared.
    Declared,
    /// The structure declared zero, so the profile's documented fallback was applied.
    /// The substitution is recorded rather than silent.
    DeclaredZeroFallback {
        /// The fallback that was applied, and the profile key it came from.
        reason: String,
    },
    /// The structure declared a value that cannot be true of this evidence. No
    /// substitution is made: an impossible value is evidence of damage, and replacing it
    /// would hide that.
    Malformed { reason: String },
    /// The field could not be read at all (short read / truncated boot structure).
    Absent { reason: String },
}

impl ValueOrigin {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::DeclaredZeroFallback { .. } => "declared-zero-fallback-applied",
            Self::Malformed { .. } => "malformed",
            Self::Absent { .. } => "absent",
        }
    }

    /// Why this field is or is not usable, for an evidence string.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Declared => None,
            Self::DeclaredZeroFallback { reason }
            | Self::Malformed { reason }
            | Self::Absent { reason } => Some(reason),
        }
    }

    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Declared | Self::DeclaredZeroFallback { .. })
    }
}

/// One boot-structure field: the raw value, the usable value, and where it came from.
///
/// `raw` and `value` are kept apart so a report can quote what was on disk even when a
/// fallback was applied or the value was rejected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BootField<T> {
    /// The value exactly as stored, when the field was readable.
    pub raw: Option<T>,
    /// The value this crate will act on. `None` whenever nothing usable was established.
    pub value: Option<T>,
    /// Absolute physical offset of the field in the evidence.
    pub field_offset: u64,
    /// Where `value` came from.
    pub origin: ValueOrigin,
}

impl<T: Copy> BootField<T> {
    fn declared(raw: T, field_offset: u64) -> Self {
        Self {
            raw: Some(raw),
            value: Some(raw),
            field_offset,
            origin: ValueOrigin::Declared,
        }
    }

    fn fallback(raw: T, applied: T, field_offset: u64, reason: String) -> Self {
        Self {
            raw: Some(raw),
            value: Some(applied),
            field_offset,
            origin: ValueOrigin::DeclaredZeroFallback { reason },
        }
    }

    fn malformed(raw: T, field_offset: u64, reason: String) -> Self {
        Self {
            raw: Some(raw),
            value: None,
            field_offset,
            origin: ValueOrigin::Malformed { reason },
        }
    }

    fn absent(field_offset: u64, reason: String) -> Self {
        Self {
            raw: None,
            value: None,
            field_offset,
            origin: ValueOrigin::Absent { reason },
        }
    }

    /// Whether an actionable value was established.
    pub fn is_known(&self) -> bool {
        self.value.is_some()
    }
}

/// The identity of a candidate Hikvision volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootRecognition {
    /// The Hikvision filesystem identifier was read at a declared boot position.
    Recognized {
        /// The boot position the identifier was found at.
        boot_offset: u64,
        /// The identifier field exactly as read, so provenance can quote it.
        identifier: Vec<u8>,
    },
    /// Every declared boot position was readable, but none carried the identifier. This is
    /// the answer for evidence that is not a Hikvision volume.
    IdentifierMismatch {
        /// What was observed at each candidate position, for the examiner.
        observations: Vec<String>,
        reason: String,
    },
    /// The identifier matched, but the boot structure behind it cannot be interpreted.
    ///
    /// Deliberately **not** treated as a usable volume: reading geometry out of a
    /// malformed boot structure is how a parser invents a filesystem.
    Malformed {
        boot_offset: u64,
        identifier: Vec<u8>,
        reason: String,
    },
    /// No declared boot position could be read (image too small or unreadable).
    NotFound { reason: String },
}

impl BootRecognition {
    /// Whether the Hikvision structure set may be parsed.
    pub fn is_recognized(&self) -> bool {
        matches!(self, Self::Recognized { .. })
    }

    /// Whether the filesystem identifier was found, regardless of what followed it.
    pub fn identifier_found(&self) -> bool {
        matches!(self, Self::Recognized { .. } | Self::Malformed { .. })
    }

    /// The boot position in use, when one was established.
    pub fn boot_offset(&self) -> Option<u64> {
        match self {
            Self::Recognized { boot_offset, .. } | Self::Malformed { boot_offset, .. } => {
                Some(*boot_offset)
            }
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Recognized { .. } => "hikvision-recognized",
            Self::IdentifierMismatch { .. } => "not-hikvision",
            Self::Malformed { .. } => "hikvision-malformed-boot",
            Self::NotFound { .. } => "boot-not-readable",
        }
    }

    /// The validation outcome this recognition implies.
    ///
    /// Only a recognized volume is `Pass`. A malformed boot is `Review` — a real
    /// observation needing a human. A mismatch is `Unknown`, because the Hikvision parser
    /// simply does not apply, which is different from the evidence being damaged.
    pub fn validation(&self) -> ValidationState {
        const OP: &str = "hikvision_boot_recognition";
        const SUBJECT: &str = "boot_identifier";
        match self {
            Self::Recognized {
                boot_offset,
                identifier,
            } => vs(
                ValidationStateKind::Pass,
                format!(
                    "Hikvision filesystem identifier verified at boot position {boot_offset} \
                     (0x{boot_offset:X}): {}",
                    hex_ascii(identifier)
                ),
                OP,
                SUBJECT,
            ),
            Self::Malformed {
                boot_offset,
                identifier,
                reason,
            } => vs(
                ValidationStateKind::Review,
                format!(
                    "Hikvision filesystem identifier present at boot position {boot_offset} \
                     (0x{boot_offset:X}) ({}) but the boot structure is malformed: {reason}. No \
                     geometry was interpreted behind it",
                    hex_ascii(identifier)
                ),
                OP,
                SUBJECT,
            ),
            Self::IdentifierMismatch {
                observations,
                reason,
            } => vs(
                ValidationStateKind::Unknown,
                format!(
                    "no Hikvision filesystem identifier at any declared boot position: {reason} \
                     [{}]",
                    observations.join("; ")
                ),
                OP,
                SUBJECT,
            ),
            Self::NotFound { reason } => vs(
                ValidationStateKind::Unknown,
                format!("the Hikvision boot structure could not be read: {reason}"),
                OP,
                SUBJECT,
            ),
        }
    }
}

/// A parsed Hikvision boot structure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HikBoot {
    /// Byte length of the evidence the boot structure was read from.
    pub physical_size: u64,
    /// How the volume was recognized.
    pub recognition: BootRecognition,
    /// Physical extent of the boot structure, when a boot position was established.
    pub boot_region: Option<Region>,
    /// Physical extent of the 32-byte identifier field.
    pub identifier_region: Option<Region>,
    /// The identifier field exactly as read.
    pub identifier: Option<Vec<u8>>,
    /// First byte of the video block region.
    pub video_start_offset: BootField<u64>,
    /// Size of one video block, footer included.
    pub block_size: BootField<u64>,
    /// Number of video blocks the boot structure declares.
    pub number_of_blocks: BootField<u32>,
    /// Offset of the primary HIKBTREE.
    pub btree_offset: BootField<u64>,
    /// Declared size of the primary HIKBTREE.
    pub btree_size: BootField<u64>,
    /// Offset of the backup HIKBTREE.
    pub backup_btree_offset: BootField<u64>,
    /// Declared size of the backup HIKBTREE.
    pub backup_btree_size: BootField<u64>,
    /// Boot positions that were tried, in order, so a negative result is auditable.
    pub candidates_tried: Vec<u64>,
    /// Why this boot structure is or is not trustworthy.
    pub evidence: ValidationState,
}

impl HikBoot {
    /// The video block region, when both its start and its extent were established.
    ///
    /// Computed from the declared block geometry and clipped to the evidence, so a
    /// recorder that declares more blocks than the acquired image holds yields the region
    /// actually present rather than a region past the end.
    pub fn video_region(&self) -> Option<Region> {
        let start = self.video_start_offset.value?;
        if start >= self.physical_size {
            return None;
        }
        let declared = self
            .block_size
            .value
            .zip(self.number_of_blocks.value)
            .and_then(|(size, count)| size.checked_mul(count as u64));
        let available = self.physical_size.saturating_sub(start);
        let length = match declared {
            Some(d) => d.min(available),
            // Without a declared extent the video region still begins where the boot
            // structure says; its end is simply the end of the evidence.
            None => available,
        };
        Region::new(start, length).ok()
    }

    /// Physical region of the primary tree, when its offset and size are usable.
    pub fn btree_region(&self) -> Option<Region> {
        region_from(
            self.btree_offset.value?,
            self.btree_size.value,
            self.physical_size,
        )
    }

    /// Physical region of the backup tree, when its offset and size are usable.
    pub fn backup_btree_region(&self) -> Option<Region> {
        region_from(
            self.backup_btree_offset.value?,
            self.backup_btree_size.value,
            self.physical_size,
        )
    }

    /// Physical offset of block `n`, when the geometry is known and the block is declared.
    pub fn block_offset(&self, block_number: u32) -> Option<u64> {
        let start = self.video_start_offset.value?;
        let size = self.block_size.value?;
        if let Some(count) = self.number_of_blocks.value {
            if block_number >= count {
                return None;
            }
        }
        start.checked_add(size.checked_mul(block_number as u64)?)
    }

    /// Which block number a physical offset falls in, if any.
    ///
    /// Used to attribute a B-tree data offset or a carved candidate back to its block
    /// without assuming the caller already knows the geometry.
    pub fn block_number_at(&self, offset: u64) -> Option<u32> {
        let start = self.video_start_offset.value?;
        let size = self.block_size.value?;
        if size == 0 || offset < start {
            return None;
        }
        let n = (offset - start) / size;
        if let Some(count) = self.number_of_blocks.value {
            if n >= count as u64 {
                return None;
            }
        }
        u32::try_from(n).ok()
    }

    /// Whether the declared geometry is complete enough to enumerate blocks.
    pub fn geometry_is_complete(&self) -> bool {
        self.video_start_offset.is_known()
            && self.block_size.is_known()
            && self.number_of_blocks.is_known()
    }

    /// OEM-specific descriptive fields, as plain strings for the generic geometry type.
    ///
    /// Every entry is something that was actually read or actually decided; nothing here
    /// is invented to fill the map out.
    pub fn oem_fields(&self) -> BTreeMap<String, String> {
        let mut f = BTreeMap::new();
        f.insert(
            "hikvision_recognition".into(),
            self.recognition.label().into(),
        );
        if let Some(boot) = self.recognition.boot_offset() {
            f.insert("hikvision_boot_offset".into(), boot.to_string());
        }
        f.insert(
            "hikvision_boot_candidates_tried".into(),
            self.candidates_tried
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(","),
        );
        if let Some(id) = &self.identifier {
            f.insert("hikvision_identifier".into(), hex_ascii(id));
        }
        field_fields(&mut f, "video_start_offset", &self.video_start_offset);
        field_fields(&mut f, "block_size", &self.block_size);
        field_fields(&mut f, "number_of_blocks", &self.number_of_blocks);
        field_fields(&mut f, "btree_offset", &self.btree_offset);
        field_fields(&mut f, "btree_size", &self.btree_size);
        field_fields(&mut f, "backup_btree_offset", &self.backup_btree_offset);
        field_fields(&mut f, "backup_btree_size", &self.backup_btree_size);
        if let Some(r) = self.video_region() {
            f.insert("hikvision_video_region".into(), r.to_string());
        }
        f.insert(
            "hikvision_geometry_complete".into(),
            self.geometry_is_complete().to_string(),
        );
        f
    }
}

/// Record one field's raw value, effective value and origin into the OEM field map.
fn field_fields<T: std::fmt::Display + Copy>(
    out: &mut BTreeMap<String, String>,
    name: &str,
    field: &BootField<T>,
) {
    if let Some(raw) = field.raw {
        out.insert(format!("hikvision_{name}_declared"), raw.to_string());
    }
    if let Some(v) = field.value {
        out.insert(format!("hikvision_{name}"), v.to_string());
    }
    out.insert(
        format!("hikvision_{name}_origin"),
        field.origin.label().to_string(),
    );
    if let Some(reason) = field.origin.reason() {
        out.insert(format!("hikvision_{name}_note"), reason.to_string());
    }
    out.insert(
        format!("hikvision_{name}_field_offset"),
        field.field_offset.to_string(),
    );
}

/// Build a region from an offset plus an optional size, clipped to the evidence.
fn region_from(offset: u64, size: Option<u64>, physical_size: u64) -> Option<Region> {
    if offset >= physical_size {
        return None;
    }
    let available = physical_size.saturating_sub(offset);
    let length = size.map(|s| s.min(available)).unwrap_or(available);
    if length == 0 {
        return None;
    }
    Region::new(offset, length).ok()
}

/// Boot positions the profile declares, in the order they should be tried.
pub fn boot_candidates(profile: &OemProfile) -> Vec<u64> {
    let mut out = vec![
        u64_from(profile, key::BOOT_CANDIDATE_PRIMARY, 512),
        u64_from(profile, key::BOOT_CANDIDATE_SECONDARY, 80_044_032),
    ];
    out.dedup();
    out
}

/// Read and validate the Hikvision boot structure.
///
/// Never fails on non-Hikvision or damaged input: an unreadable or non-matching volume
/// comes back as a [`BootRecognition`] variant, because "this is not Hikvision" is a
/// result, not an error. A genuine I/O failure still propagates.
pub fn read_boot(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
) -> Result<HikBoot, ForensicError> {
    let physical_size = reader.len();
    let candidates = boot_candidates(profile);
    let boot_size = usize_from(profile, key::BOOT_STRUCTURE_SIZE, 512);
    let id_offset = usize_from(profile, key::BOOT_IDENTIFIER_OFFSET, 16);
    let id_field_size = usize_from(profile, key::BOOT_IDENTIFIER_FIELD_SIZE, 32);

    let Some(pattern) = magic(profile, sig::BOOT_IDENTIFIER) else {
        // Without the declared identifier there is nothing to verify against, and
        // substituting a hard-coded string here would defeat the profile system.
        return Ok(empty_boot(
            physical_size,
            candidates,
            BootRecognition::NotFound {
                reason: format!(
                    "the profile declares no '{}' signature, so no identifier could be verified",
                    sig::BOOT_IDENTIFIER
                ),
            },
        ));
    };

    let mut observations: Vec<String> = Vec::new();
    let mut unreadable = 0usize;

    for boot_offset in &candidates {
        let boot_offset = *boot_offset;
        // A candidate past the end of the evidence is simply not present here. That is not
        // a mismatch, so it is counted separately.
        let Ok(buf) = read_boot_bytes(reader, boot_offset, boot_size) else {
            unreadable += 1;
            observations.push(format!(
                "boot position {boot_offset} (0x{boot_offset:X}): not readable in a {physical_size}-byte image"
            ));
            continue;
        };

        let Some(field) = buf.get(id_offset..id_offset.saturating_add(id_field_size)) else {
            unreadable += 1;
            observations.push(format!(
                "boot position {boot_offset} (0x{boot_offset:X}): identifier field at +{id_offset} \
                 lies past the end of the readable boot structure"
            ));
            continue;
        };

        if !field.starts_with(&pattern) {
            // Quote only the pattern-length prefix: that is what was compared, and dumping
            // the whole 32-byte field would bury the finding.
            let shown = &field[..pattern.len().min(field.len())];
            observations.push(format!(
                "boot position {boot_offset} (0x{boot_offset:X}): identifier field holds {} where \
                 the Hikvision identifier was expected",
                hex_ascii(shown)
            ));
            continue;
        }

        // The identifier matched. Everything from here is geometry, and a failure to read
        // it is a malformed-boot finding rather than a non-Hikvision one.
        return Ok(parse_fields(
            profile,
            physical_size,
            boot_offset,
            boot_size,
            field.to_vec(),
            id_offset as u64,
            id_field_size as u64,
            &buf,
            candidates,
        ));
    }

    let recognition = if unreadable == candidates.len() {
        BootRecognition::NotFound {
            reason: format!(
                "none of the {} declared boot positions is readable in a {physical_size}-byte image",
                candidates.len()
            ),
        }
    } else {
        BootRecognition::IdentifierMismatch {
            observations,
            reason: format!(
                "{} declared boot position(s) were examined and none carried the Hikvision \
                 filesystem identifier",
                candidates.len()
            ),
        }
    };
    Ok(empty_boot(physical_size, candidates, recognition))
}

/// Read the boot structure bytes, tolerating a boot structure truncated by the image end.
fn read_boot_bytes(
    reader: &dyn EvidenceReader,
    offset: u64,
    size: usize,
) -> Result<Vec<u8>, ForensicError> {
    let len = reader.len();
    if offset >= len {
        return Err(ForensicError::out_of_bounds(
            "hikvision_boot",
            offset,
            size as u64,
            len,
        ));
    }
    let available = (len - offset).min(size as u64) as usize;
    let mut buf = vec![0u8; available];
    let n = reader.read_at(offset, &mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

/// A boot result carrying no geometry, for every non-recognized outcome.
fn empty_boot(physical_size: u64, candidates: Vec<u64>, recognition: BootRecognition) -> HikBoot {
    let evidence = recognition.validation();
    let absent = |reason: &str| BootField::<u64>::absent(0, reason.to_string());
    HikBoot {
        physical_size,
        boot_region: None,
        identifier_region: None,
        identifier: None,
        video_start_offset: absent("no recognized boot structure"),
        block_size: absent("no recognized boot structure"),
        number_of_blocks: BootField::<u32>::absent(0, "no recognized boot structure".into()),
        btree_offset: absent("no recognized boot structure"),
        btree_size: absent("no recognized boot structure"),
        backup_btree_offset: absent("no recognized boot structure"),
        backup_btree_size: absent("no recognized boot structure"),
        candidates_tried: candidates,
        recognition,
        evidence,
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_fields(
    profile: &OemProfile,
    physical_size: u64,
    boot_offset: u64,
    boot_size: usize,
    identifier: Vec<u8>,
    id_offset: u64,
    id_field_size: u64,
    buf: &[u8],
    candidates: Vec<u64>,
) -> HikBoot {
    let abs = |rel: usize| boot_offset.saturating_add(rel as u64);

    // ── VideoStartOffset ─────────────────────────────────────────────────────────
    let vso_rel = usize_from(profile, key::BOOT_VIDEO_START_OFFSET, 120);
    let vso_fallback = u64_from(profile, key::BOOT_VIDEO_START_FALLBACK, 0x4C64000);
    let video_start_offset = match i64_at(buf, vso_rel) {
        None => BootField::absent(
            abs(vso_rel),
            format!("VideoStartOffset at boot +{vso_rel} lies past the readable boot structure"),
        ),
        Some(0) => {
            // The one case the brief permits a fallback: the field is present and declares
            // zero, meaning the recorder did not record a video start here.
            if vso_fallback < physical_size {
                BootField::fallback(
                    0i64,
                    vso_fallback as i64,
                    abs(vso_rel),
                    format!(
                        "the boot structure declares VideoStartOffset 0; the profile's documented \
                         fallback {vso_fallback} (0x{vso_fallback:X}) was applied"
                    ),
                )
                .map_u64()
            } else {
                BootField::malformed(
                    0i64,
                    abs(vso_rel),
                    format!(
                        "the boot structure declares VideoStartOffset 0 and the profile's fallback \
                         {vso_fallback} lies past the end of this {physical_size}-byte image, so no \
                         video start could be established"
                    ),
                )
                .map_u64()
            }
        }
        Some(v) if v < 0 => BootField::malformed(
            v,
            abs(vso_rel),
            format!("VideoStartOffset declares the negative value {v}"),
        )
        .map_u64(),
        Some(v) if (v as u64) >= physical_size => BootField::malformed(
            v,
            abs(vso_rel),
            format!(
                "VideoStartOffset declares {v} (0x{v:X}), past the end of this \
                 {physical_size}-byte image"
            ),
        )
        .map_u64(),
        Some(v) => BootField::declared(v as u64, abs(vso_rel)),
    };

    // ── BlockSize ────────────────────────────────────────────────────────────────
    let bs_rel = usize_from(profile, key::BOOT_BLOCK_SIZE_OFFSET, 136);
    let bs_default = u64_from(profile, key::BOOT_BLOCK_SIZE_DEFAULT, 1 << 30);
    let bs_min = u64_from(profile, key::BOOT_BLOCK_SIZE_MIN, 1 << 20);
    let bs_max = u64_from(profile, key::BOOT_BLOCK_SIZE_MAX, 64u64 << 30);
    let footer = u64_from(profile, key::BLOCK_FOOTER_SIZE, 1 << 20);
    let block_size = match i64_at(buf, bs_rel) {
        None => BootField::absent(
            abs(bs_rel),
            format!("BlockSize at boot +{bs_rel} lies past the readable boot structure"),
        ),
        Some(0) => BootField::fallback(
            0i64,
            bs_default as i64,
            abs(bs_rel),
            format!(
                "the boot structure declares BlockSize 0; the profile's documented default \
                 {bs_default} was applied"
            ),
        )
        .map_u64(),
        Some(v) if v < 0 => BootField::malformed(
            v,
            abs(bs_rel),
            format!("BlockSize declares the negative value {v}"),
        )
        .map_u64(),
        Some(v) if (v as u64) < bs_min || (v as u64) > bs_max => BootField::malformed(
            v,
            abs(bs_rel),
            format!(
                "BlockSize declares {v}, outside the structurally possible range \
                 [{bs_min}, {bs_max}]"
            ),
        )
        .map_u64(),
        Some(v) if (v as u64) <= footer => BootField::malformed(
            v,
            abs(bs_rel),
            format!(
                "BlockSize declares {v}, which does not exceed the {footer}-byte block footer, so \
                 the block would contain no video data"
            ),
        )
        .map_u64(),
        Some(v) => BootField::declared(v as u64, abs(bs_rel)),
    };

    // ── NumberOfBlocks ───────────────────────────────────────────────────────────
    let nb_rel = usize_from(profile, key::BOOT_NUMBER_OF_BLOCKS_OFFSET, 144);
    let nb_max = u64_from(profile, key::BOOT_NUMBER_OF_BLOCKS_MAX, 1 << 20);
    let number_of_blocks = match i32_at(buf, nb_rel) {
        None => BootField::<u32>::absent(
            abs(nb_rel),
            format!("NumberOfBlocks at boot +{nb_rel} lies past the readable boot structure"),
        ),
        Some(v) if v <= 0 => BootField::<u32>::malformed(
            v.max(0) as u32,
            abs(nb_rel),
            format!(
                "NumberOfBlocks declares {v}; a volume with no video blocks has no recordings to \
                 index, so the value is not usable as geometry"
            ),
        ),
        Some(v) if (v as u64) > nb_max => BootField::<u32>::malformed(
            v as u32,
            abs(nb_rel),
            format!("NumberOfBlocks declares {v}, above the structural bound {nb_max}"),
        ),
        Some(v) => BootField::declared(v as u32, abs(nb_rel)),
    };

    // ── Tree offsets and sizes ───────────────────────────────────────────────────
    let bto_rel = usize_from(profile, key::BOOT_BTREE_OFFSET_OFFSET, 152);
    let bts_rel = usize_from(profile, key::BOOT_BTREE_SIZE_OFFSET, 160);
    let bbo_rel = usize_from(profile, key::BOOT_BACKUP_BTREE_OFFSET_OFFSET, 168);
    let bbs_rel = usize_from(profile, key::BOOT_BACKUP_BTREE_SIZE_OFFSET, 176);

    let btree_offset = offset_field(buf, bto_rel, abs(bto_rel), physical_size, "BTreeOffset");
    let btree_size = size_field(buf, bts_rel, abs(bts_rel), "BTreeSize");
    let backup_btree_offset = offset_field(
        buf,
        bbo_rel,
        abs(bbo_rel),
        physical_size,
        "BackupBTreeOffset",
    );
    let backup_btree_size = size_field(buf, bbs_rel, abs(bbs_rel), "BackupBTreeSize");

    // ── Overall boot-structure verdict ───────────────────────────────────────────
    //
    // The identifier matched, so this volume is Hikvision. Whether its geometry is usable
    // is a separate question, and the two are reported separately.
    let mut problems: Vec<String> = Vec::new();
    // Which fields a volume may legitimately leave absent. A recorder need not have a backup
    // tree, so a zero BackupBTreeOffset/Size is a normal structural statement, not a
    // qualification on the boot structure. The other fields being absent is a real problem.
    for (name, origin, optional) in [
        ("VideoStartOffset", &video_start_offset.origin, false),
        ("BlockSize", &block_size.origin, false),
        ("NumberOfBlocks", &number_of_blocks.origin, false),
        ("BTreeOffset", &btree_offset.origin, false),
        ("BTreeSize", &btree_size.origin, false),
        ("BackupBTreeOffset", &backup_btree_offset.origin, true),
        ("BackupBTreeSize", &backup_btree_size.origin, true),
    ] {
        match origin {
            // An absent optional structure (a missing backup tree) is expected and not flagged.
            ValueOrigin::Absent { .. } if optional => {}
            ValueOrigin::Malformed { reason } | ValueOrigin::Absent { reason } => {
                problems.push(format!("{name}: {reason}"))
            }
            ValueOrigin::DeclaredZeroFallback { reason } => {
                problems.push(format!("{name}: {reason}"))
            }
            ValueOrigin::Declared => {}
        }
    }

    // A boot structure that establishes neither a video start nor any tree offset is not
    // usable, however good the identifier looked.
    let unusable = !video_start_offset.is_known()
        && !btree_offset.is_known()
        && !backup_btree_offset.is_known();

    let recognition = if unusable {
        BootRecognition::Malformed {
            boot_offset,
            identifier: identifier.clone(),
            reason: format!(
                "neither a video start offset nor any index tree offset could be established: {}",
                problems.join("; ")
            ),
        }
    } else {
        BootRecognition::Recognized {
            boot_offset,
            identifier: identifier.clone(),
        }
    };

    let evidence = if unusable {
        recognition.validation()
    } else if problems.is_empty() {
        vs(
            ValidationStateKind::Pass,
            format!(
                "Hikvision boot structure at {boot_offset} (0x{boot_offset:X}) parsed completely: \
                 every declared field was usable as stored"
            ),
            "hikvision_boot",
            "boot_structure",
        )
    } else {
        vs(
            ValidationStateKind::Review,
            format!(
                "Hikvision boot structure at {boot_offset} (0x{boot_offset:X}) parsed with \
                 qualifications: {}",
                problems.join("; ")
            ),
            "hikvision_boot",
            "boot_structure",
        )
    };

    HikBoot {
        physical_size,
        boot_region: Region::new(boot_offset, boot_size as u64).ok(),
        identifier_region: Region::new(boot_offset.saturating_add(id_offset), id_field_size).ok(),
        identifier: Some(identifier),
        video_start_offset,
        block_size,
        number_of_blocks,
        btree_offset,
        btree_size,
        backup_btree_offset,
        backup_btree_size,
        candidates_tried: candidates,
        recognition,
        evidence,
    }
}

/// Read a tree offset field, validating it against the image bounds.
///
/// Zero means "this tree does not exist", which is a legitimate structural statement (a
/// volume may have no backup tree) and is therefore reported as absent rather than
/// malformed.
fn offset_field(
    buf: &[u8],
    rel: usize,
    absolute: u64,
    physical_size: u64,
    name: &str,
) -> BootField<u64> {
    match i64_at(buf, rel) {
        None => BootField::absent(
            absolute,
            format!("{name} at boot +{rel} lies past the readable boot structure"),
        ),
        Some(0) => BootField {
            raw: Some(0),
            value: None,
            field_offset: absolute,
            origin: ValueOrigin::Absent {
                reason: format!("{name} declares 0, i.e. this structure is not present"),
            },
        },
        Some(v) if v < 0 => BootField::malformed(
            v,
            absolute,
            format!("{name} declares the negative value {v}"),
        )
        .map_u64(),
        Some(v) if (v as u64) >= physical_size => BootField::malformed(
            v,
            absolute,
            format!(
                "{name} declares {v} (0x{v:X}), past the end of this {physical_size}-byte image"
            ),
        )
        .map_u64(),
        Some(v) => BootField::declared(v as u64, absolute),
    }
}

/// Read a declared structure size. Zero means "unknown extent", not "empty".
fn size_field(buf: &[u8], rel: usize, absolute: u64, name: &str) -> BootField<u64> {
    match i64_at(buf, rel) {
        None => BootField::absent(
            absolute,
            format!("{name} at boot +{rel} lies past the readable boot structure"),
        ),
        Some(0) => BootField {
            raw: Some(0),
            value: None,
            field_offset: absolute,
            origin: ValueOrigin::Absent {
                reason: format!(
                    "{name} declares 0; the structure's extent is unknown and was not guessed"
                ),
            },
        },
        Some(v) if v < 0 => BootField::malformed(
            v,
            absolute,
            format!("{name} declares the negative value {v}"),
        )
        .map_u64(),
        Some(v) => BootField::declared(v as u64, absolute),
    }
}

/// Reinterpret an `i64`-raw field as a `u64`-raw field, preserving the declared value's
/// printable form. Used where the on-disk field is signed but the usable value is not.
impl BootField<i64> {
    fn map_u64(self) -> BootField<u64> {
        BootField {
            raw: self.raw.map(|v| v as u64),
            value: self.value.map(|v| v as u64),
            field_offset: self.field_offset,
            origin: self.origin,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::tests_support::hikvision_profile;
    use crate::testing::MemReader;

    const IDENT: &[u8] = b"HIKVISION@HANGZHOU";
    const GIB: u64 = 1 << 30;

    /// Build an image with a boot structure at `boot_offset`.
    fn image(boot_offset: u64, f: impl FnOnce(&mut [u8])) -> Vec<u8> {
        // Large enough to hold the boot structure and a little beyond, without allocating
        // a real multi-gigabyte volume.
        let mut data = vec![0u8; (boot_offset + 4096) as usize];
        let start = boot_offset as usize;
        f(&mut data[start..start + 512]);
        data
    }

    fn put_id(boot: &mut [u8]) {
        boot[16..16 + IDENT.len()].copy_from_slice(IDENT);
    }

    fn put_i64(boot: &mut [u8], at: usize, v: i64) {
        boot[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn put_i32(boot: &mut [u8], at: usize, v: i32) {
        boot[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// A boot structure whose every field is declared and valid, inside a small image.
    fn valid_boot(boot_offset: u64, image_len: u64) -> Vec<u8> {
        let mut data = vec![0u8; image_len as usize];
        let b = &mut data[boot_offset as usize..boot_offset as usize + 512];
        put_id(b);
        put_i64(b, 120, 0x10000); // VideoStartOffset
        put_i64(b, 136, 0x8000); // BlockSize — small so the fixture stays small
        put_i32(b, 144, 2); // NumberOfBlocks
        put_i64(b, 152, 0x2000); // BTreeOffset
        put_i64(b, 160, 0x1000); // BTreeSize
        put_i64(b, 168, 0x3000); // BackupBTreeOffset
        put_i64(b, 176, 0x1000); // BackupBTreeSize
        data
    }

    #[test]
    fn a_valid_boot_structure_is_recognized_at_the_primary_position() {
        let p = hikvision_profile();
        // BlockSize must exceed the footer, so use a realistic 1 GiB block and a declared
        // count the image cannot hold — the region clips, which is the documented behaviour.
        let mut data = vec![0u8; 0x20000];
        {
            let b = &mut data[512..1024];
            put_id(b);
            put_i64(b, 120, 0x10000);
            put_i64(b, 136, GIB as i64);
            put_i32(b, 144, 4);
            put_i64(b, 152, 0x2000);
            put_i64(b, 160, 0x1000);
            put_i64(b, 168, 0x3000);
            put_i64(b, 176, 0x1000);
        }
        let r = MemReader::new(data);
        let boot = read_boot(&r, &p).unwrap();

        assert!(boot.recognition.is_recognized(), "{:?}", boot.recognition);
        assert_eq!(boot.recognition.boot_offset(), Some(512));
        assert_eq!(boot.video_start_offset.value, Some(0x10000));
        assert_eq!(boot.block_size.value, Some(GIB));
        assert_eq!(boot.number_of_blocks.value, Some(4));
        assert_eq!(boot.btree_offset.value, Some(0x2000));
        assert_eq!(boot.backup_btree_offset.value, Some(0x3000));
        assert!(boot.geometry_is_complete());
        // Field offsets must be absolute, not relative to the boot position.
        assert_eq!(boot.video_start_offset.field_offset, 512 + 120);
        assert_eq!(boot.backup_btree_size.field_offset, 512 + 176);
    }

    #[test]
    fn the_identifier_is_located_relative_to_the_detected_boot_position() {
        let p = hikvision_profile();
        let secondary = u64_from(&p, key::BOOT_CANDIDATE_SECONDARY, 80_044_032);
        let mut data = vec![0u8; (secondary + 4096) as usize];
        {
            let b = &mut data[secondary as usize..secondary as usize + 512];
            put_id(b);
            put_i64(b, 120, 0x10000);
            put_i64(b, 136, GIB as i64);
            put_i32(b, 144, 1);
            put_i64(b, 152, 0x2000);
        }
        let r = MemReader::new(data);
        let boot = read_boot(&r, &p).unwrap();
        assert!(boot.recognition.is_recognized());
        assert_eq!(
            boot.recognition.boot_offset(),
            Some(secondary),
            "the secondary boot position must be tried too"
        );
        assert_eq!(
            boot.identifier_region.map(|r| r.offset),
            Some(secondary + 16),
            "the identifier region is boot + 16, not a fixed absolute offset"
        );
    }

    #[test]
    fn a_wrong_identifier_is_a_mismatch_not_a_recognition() {
        let p = hikvision_profile();
        let data = image(512, |b| {
            b[16..16 + 8].copy_from_slice(b"NOTHIKVI");
        });
        let r = MemReader::new(data);
        let boot = read_boot(&r, &p).unwrap();
        assert!(!boot.recognition.is_recognized());
        assert!(!boot.recognition.identifier_found());
        assert!(matches!(
            boot.recognition,
            BootRecognition::IdentifierMismatch { .. }
        ));
        assert_eq!(boot.evidence.state, ValidationStateKind::Unknown);
        assert!(boot.video_start_offset.value.is_none());
    }

    #[test]
    fn an_all_zero_image_is_not_recognized_as_hikvision() {
        let p = hikvision_profile();
        let r = MemReader::new(vec![0u8; 1 << 16]);
        let boot = read_boot(&r, &p).unwrap();
        assert!(!boot.recognition.is_recognized());
        assert!(!boot.geometry_is_complete());
    }

    #[test]
    fn a_random_image_is_not_recognized_as_hikvision() {
        let p = hikvision_profile();
        // Deterministic pseudo-random bytes; no seed dependency on the test runner.
        let data: Vec<u8> = (0..(1u32 << 16))
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let r = MemReader::new(data);
        let boot = read_boot(&r, &p).unwrap();
        assert!(
            !boot.recognition.is_recognized(),
            "pseudo-random bytes must not be recognized as a Hikvision volume"
        );
    }

    #[test]
    fn an_image_smaller_than_every_boot_candidate_reports_not_found() {
        let p = hikvision_profile();
        let r = MemReader::new(vec![0u8; 64]);
        let boot = read_boot(&r, &p).unwrap();
        assert!(matches!(boot.recognition, BootRecognition::NotFound { .. }));
        assert_eq!(boot.candidates_tried.len(), 2);
    }

    #[test]
    fn a_declared_zero_video_start_takes_the_profile_fallback_and_records_it() {
        let p = hikvision_profile();
        let fallback = u64_from(&p, key::BOOT_VIDEO_START_FALLBACK, 0x4C64000);
        let mut data = vec![0u8; (fallback + 0x1000) as usize];
        {
            let b = &mut data[512..1024];
            put_id(b);
            put_i64(b, 120, 0); // declared zero -> fallback permitted
            put_i64(b, 136, GIB as i64);
            put_i32(b, 144, 1);
            put_i64(b, 152, 0x2000);
        }
        let r = MemReader::new(data);
        let boot = read_boot(&r, &p).unwrap();
        assert_eq!(
            boot.video_start_offset.raw,
            Some(0),
            "the raw zero survives"
        );
        assert_eq!(boot.video_start_offset.value, Some(fallback));
        assert!(matches!(
            boot.video_start_offset.origin,
            ValueOrigin::DeclaredZeroFallback { .. }
        ));
        // A substitution must be visible, never silent.
        assert_eq!(boot.evidence.state, ValidationStateKind::Review);
        assert!(boot.evidence.reason.contains("fallback"));
    }

    #[test]
    fn a_declared_zero_block_size_takes_the_documented_one_gib_default() {
        let p = hikvision_profile();
        let mut data = vec![0u8; 0x20000];
        {
            let b = &mut data[512..1024];
            put_id(b);
            put_i64(b, 120, 0x10000);
            put_i64(b, 136, 0); // declared zero
            put_i32(b, 144, 1);
            put_i64(b, 152, 0x2000);
        }
        let r = MemReader::new(data);
        let boot = read_boot(&r, &p).unwrap();
        assert_eq!(boot.block_size.value, Some(GIB));
        assert!(matches!(
            boot.block_size.origin,
            ValueOrigin::DeclaredZeroFallback { .. }
        ));
    }

    #[test]
    fn an_out_of_bounds_video_start_is_malformed_and_not_replaced() {
        let p = hikvision_profile();
        let mut data = vec![0u8; 0x20000];
        {
            let b = &mut data[512..1024];
            put_id(b);
            put_i64(b, 120, 0x7FFF_FFFF_0000); // far past the image
            put_i64(b, 136, GIB as i64);
            put_i32(b, 144, 1);
            put_i64(b, 152, 0x2000);
        }
        let r = MemReader::new(data);
        let boot = read_boot(&r, &p).unwrap();
        assert!(matches!(
            boot.video_start_offset.origin,
            ValueOrigin::Malformed { .. }
        ));
        assert_eq!(
            boot.video_start_offset.value, None,
            "an impossible value must not be replaced with a plausible one"
        );
        assert_eq!(boot.video_start_offset.raw, Some(0x7FFF_FFFF_0000));
        // A tree offset is still usable, so the volume is recognized but qualified.
        assert!(boot.recognition.is_recognized());
        assert_eq!(boot.evidence.state, ValidationStateKind::Review);
        assert!(!boot.geometry_is_complete());
    }

    #[test]
    fn a_block_size_below_the_footer_size_is_rejected() {
        let p = hikvision_profile();
        let mut data = vec![0u8; 0x20000];
        {
            let b = &mut data[512..1024];
            put_id(b);
            put_i64(b, 120, 0x10000);
            put_i64(b, 136, 4096); // smaller than the 1 MiB footer
            put_i32(b, 144, 1);
            put_i64(b, 152, 0x2000);
        }
        let r = MemReader::new(data);
        let boot = read_boot(&r, &p).unwrap();
        assert!(matches!(
            boot.block_size.origin,
            ValueOrigin::Malformed { .. }
        ));
        assert_eq!(boot.block_size.value, None);
    }

    #[test]
    fn an_invalid_block_count_is_rejected_rather_than_defaulted() {
        let p = hikvision_profile();
        for declared in [0i32, -1, i32::MIN] {
            let mut data = vec![0u8; 0x20000];
            {
                let b = &mut data[512..1024];
                put_id(b);
                put_i64(b, 120, 0x10000);
                put_i64(b, 136, GIB as i64);
                put_i32(b, 144, declared);
                put_i64(b, 152, 0x2000);
            }
            let r = MemReader::new(data);
            let boot = read_boot(&r, &p).unwrap();
            assert!(
                matches!(boot.number_of_blocks.origin, ValueOrigin::Malformed { .. }),
                "NumberOfBlocks {declared} must be rejected"
            );
            assert_eq!(boot.number_of_blocks.value, None);
            assert!(!boot.geometry_is_complete());
        }
    }

    #[test]
    fn a_block_count_above_the_structural_bound_is_rejected() {
        let p = hikvision_profile();
        let mut data = vec![0u8; 0x20000];
        {
            let b = &mut data[512..1024];
            put_id(b);
            put_i64(b, 120, 0x10000);
            put_i64(b, 136, GIB as i64);
            put_i32(b, 144, i32::MAX);
            put_i64(b, 152, 0x2000);
        }
        let r = MemReader::new(data);
        let boot = read_boot(&r, &p).unwrap();
        assert!(matches!(
            boot.number_of_blocks.origin,
            ValueOrigin::Malformed { .. }
        ));
    }

    #[test]
    fn a_zero_backup_tree_offset_means_absent_not_malformed() {
        let p = hikvision_profile();
        let mut data = vec![0u8; 0x20000];
        {
            let b = &mut data[512..1024];
            put_id(b);
            put_i64(b, 120, 0x10000);
            put_i64(b, 136, GIB as i64);
            put_i32(b, 144, 1);
            put_i64(b, 152, 0x2000);
            put_i64(b, 168, 0); // no backup tree on this volume
        }
        let r = MemReader::new(data);
        let boot = read_boot(&r, &p).unwrap();
        assert!(matches!(
            boot.backup_btree_offset.origin,
            ValueOrigin::Absent { .. }
        ));
        assert!(boot.backup_btree_region().is_none());
        // A volume with no backup tree is still a recognized volume.
        assert!(boot.recognition.is_recognized());
    }

    #[test]
    fn a_boot_with_the_identifier_but_no_usable_pointers_is_malformed() {
        let p = hikvision_profile();
        let data = image(512, |b| {
            put_id(b);
            // Every geometry field left zero, and the profile fallback for the video start
            // lies past this small image.
        });
        let r = MemReader::new(data);
        let boot = read_boot(&r, &p).unwrap();
        assert!(matches!(
            boot.recognition,
            BootRecognition::Malformed { .. }
        ));
        assert!(
            boot.recognition.identifier_found(),
            "the identifier was still found, and that fact must survive"
        );
        assert_eq!(boot.evidence.state, ValidationStateKind::Review);
    }

    #[test]
    fn tree_regions_are_clipped_to_the_evidence_rather_than_running_past_it() {
        let p = hikvision_profile();
        let mut data = vec![0u8; 0x20000];
        {
            let b = &mut data[512..1024];
            put_id(b);
            put_i64(b, 120, 0x10000);
            put_i64(b, 136, GIB as i64);
            put_i32(b, 144, 1);
            put_i64(b, 152, 0x1F000);
            put_i64(b, 160, 0x100000); // declares 1 MiB, but only 0x1000 remains
        }
        let r = MemReader::new(data);
        let boot = read_boot(&r, &p).unwrap();
        let region = boot.btree_region().expect("a region inside the image");
        assert_eq!(region.offset, 0x1F000);
        assert_eq!(
            region.offset + region.length,
            0x20000,
            "clipped to the image end"
        );
    }

    #[test]
    fn block_offsets_are_computed_from_the_declared_geometry_and_bounded_by_the_count() {
        let p = hikvision_profile();
        let data = valid_boot(512, 0x20000);
        let r = MemReader::new(data);
        let boot = read_boot(&r, &p).unwrap();
        // BlockSize 0x8000 is below the 1 MiB footer, so it is rejected — which means no
        // block offsets can be computed. That is the honest outcome.
        assert!(boot.block_size.value.is_none());
        assert!(boot.block_offset(0).is_none());
    }

    #[test]
    fn block_offset_and_block_number_are_inverses_within_the_declared_count() {
        let p = hikvision_profile();
        let mut data = vec![0u8; 0x20000];
        {
            let b = &mut data[512..1024];
            put_id(b);
            put_i64(b, 120, 0x10000);
            put_i64(b, 136, GIB as i64);
            put_i32(b, 144, 3);
            put_i64(b, 152, 0x2000);
        }
        let r = MemReader::new(data);
        let boot = read_boot(&r, &p).unwrap();
        for n in 0..3u32 {
            let off = boot.block_offset(n).expect("declared block");
            assert_eq!(off, 0x10000 + n as u64 * GIB);
            assert_eq!(boot.block_number_at(off), Some(n));
            assert_eq!(boot.block_number_at(off + 1234), Some(n));
        }
        assert_eq!(boot.block_offset(3), None, "past the declared count");
        assert_eq!(boot.block_number_at(0x10000 + 3 * GIB), None);
        assert_eq!(boot.block_number_at(0), None, "before the video region");
    }

    #[test]
    fn oem_fields_record_both_the_declared_value_and_the_substitution() {
        let p = hikvision_profile();
        let mut data = vec![0u8; 0x20000];
        {
            let b = &mut data[512..1024];
            put_id(b);
            put_i64(b, 120, 0x10000);
            put_i64(b, 136, 0); // fallback applied
            put_i32(b, 144, 1);
            put_i64(b, 152, 0x2000);
        }
        let r = MemReader::new(data);
        let boot = read_boot(&r, &p).unwrap();
        let f = boot.oem_fields();
        assert_eq!(
            f.get("hikvision_block_size_declared").map(String::as_str),
            Some("0")
        );
        assert_eq!(
            f.get("hikvision_block_size").map(String::as_str),
            Some(GIB.to_string().as_str())
        );
        assert_eq!(
            f.get("hikvision_block_size_origin").map(String::as_str),
            Some("declared-zero-fallback-applied")
        );
        assert!(f.contains_key("hikvision_block_size_note"));
        assert_eq!(
            f.get("hikvision_boot_offset").map(String::as_str),
            Some("512")
        );
        assert!(f
            .get("hikvision_identifier")
            .unwrap()
            .contains("HIKVISION@HANGZHOU"));
    }

    #[test]
    fn a_truncated_boot_structure_reports_absent_fields_not_zeros() {
        let p = hikvision_profile();
        // Identifier present, but the image ends before the geometry fields.
        let mut data = vec![0u8; 512 + 100];
        data[528..528 + IDENT.len()].copy_from_slice(IDENT);
        let r = MemReader::new(data);
        let boot = read_boot(&r, &p).unwrap();
        assert!(boot.recognition.identifier_found());
        assert!(matches!(
            boot.video_start_offset.origin,
            ValueOrigin::Absent { .. }
        ));
        assert_eq!(boot.video_start_offset.raw, None, "absent is not zero");
        assert!(matches!(
            boot.recognition,
            BootRecognition::Malformed { .. }
        ));
    }

    #[test]
    fn reading_the_boot_structure_never_errors_on_hostile_input() {
        let p = hikvision_profile();
        for len in [0usize, 1, 15, 511, 512, 513, 4095] {
            let r = MemReader::new(vec![0xFFu8; len]);
            assert!(
                read_boot(&r, &p).is_ok(),
                "a {len}-byte image must produce a result, not an error"
            );
        }
    }
}
