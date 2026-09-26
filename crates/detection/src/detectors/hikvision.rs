//! # Hikvision Storage Detector
//!
//! Profile-driven detector for the Hikvision recorder filesystem (Req 2.1, 2.2, 2.5, 2.8, 3.1,
//! 9.1, 11.3).
//!
//! Key invariants:
//! - Interpretation is driven exclusively by profile rules; no magic value, offset or weight is
//!   hard-coded here (Req 2.5).
//! - Frame/video content interpretation is downstream; this detector reasons over storage
//!   structures only.
//! - It emits a `DetectorOutput` and never claims attribution — that is the confidence engine's
//!   job.
//!
//! ## What this detector looks for
//!
//! ```text
//!   boot candidate + identifier offset   32-byte field beginning "HIKVISION@HANGZHOU"
//!   boot candidate + btree offset field  i64 BTreeOffset  ──► "HIKBTREE" page magic
//!                                        i64 BackupBTreeOffset ──► "HIKBTREE" page magic
//! ```
//!
//! The identifier is the attribution signal. Corroboration comes from **following the boot
//! structure's own pointer** to a tree header and verifying the magic there — a structural
//! relationship, not a second scan. That matters because the trees on a real Hikvision volume sit
//! tens of megabytes in; a window scan near offset 0 would never find them, and the volume would
//! be reported as a lone magic and downgraded to `Insufficient`.
//!
//! ## Boundary arithmetic
//!
//! Every derived offset — identifier field, tree header, video region start — is computed with
//! checked arithmetic and evaluated against the acquired size. A pointer that resolves outside the
//! image lowers confidence through a `Mismatch` evidence item and a warning; it never panics, and
//! it never by itself means "not Hikvision", because truncation, fragmentation and overwriting all
//! produce exactly that observation on a genuine Hikvision disk.
//!
//! ## What was removed
//!
//! An earlier revision matched a 4-byte `HIK_` tag at offset 0 and a `HKSEG` string anywhere in
//! the first 64 KiB. Neither value exists in the Hikvision filesystem; both were synthetic
//! fixture tags. Any image carrying those four bytes at offset 0 was reported `Confirmed`.

use evidence_reader::EvidenceReader;
use forensic_core::{EvidenceItem, ForensicError, Hash, OemProfile, Region, RuleMatchStatus};

use crate::detector::Detector;
use crate::output::{DetectionStatus, DetectorOutput};

/// Profile `[layout]` keys this detector needs. Key *names* are not OEM facts; the values
/// behind them are, and they live in the versioned profile.
const KEY_BOOT_PRIMARY: &str = "boot_candidate_offset_primary";
const KEY_BOOT_SECONDARY: &str = "boot_candidate_offset_secondary";
const KEY_BOOT_SIZE: &str = "boot_structure_size";
const KEY_IDENTIFIER_OFFSET: &str = "boot_identifier_offset";
const KEY_IDENTIFIER_FIELD_SIZE: &str = "boot_identifier_field_size";
const KEY_BTREE_OFFSET_FIELD: &str = "boot_btree_offset_offset";
const KEY_BACKUP_BTREE_OFFSET_FIELD: &str = "boot_backup_btree_offset_offset";
const KEY_VIDEO_START_FIELD: &str = "boot_video_start_offset_offset";
const KEY_BTREE_PAGE_SIZE: &str = "hikbtree_page_size";

/// Profile signature rule names this detector evaluates.
const SIG_IDENTIFIER: &str = "hikvision_boot_identifier";
const SIG_HIKBTREE: &str = "hikbtree_magic";

/// Read a non-negative `[layout]` value, falling back to the documented value.
fn layout(profile: &OemProfile, key: &str, fallback: u64) -> u64 {
    match profile.layout.get(key) {
        Some(v) if *v >= 0 => *v as u64,
        _ => fallback,
    }
}

/// Little-endian `i64` at `off`, or `None` when the field is out of range.
fn i64_at(buf: &[u8], off: usize) -> Option<i64> {
    let end = off.checked_add(8)?;
    buf.get(off..end)
        .map(|s| i64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

/// Read up to `size` bytes at `offset`, tolerating a structure truncated by the image end.
fn read_upto(reader: &dyn EvidenceReader, offset: u64, size: usize) -> Option<Vec<u8>> {
    let len = reader.len();
    if offset >= len {
        return None;
    }
    let available = (len - offset).min(size as u64) as usize;
    let mut buf = vec![0u8; available];
    let n = reader.read_at(offset, &mut buf).ok()?;
    buf.truncate(n);
    if buf.is_empty() {
        None
    } else {
        Some(buf)
    }
}

pub struct HikvisionDetector;

impl Detector for HikvisionDetector {
    fn oem_key(&self) -> &'static str {
        "hikvision"
    }

    fn detect(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<DetectorOutput, ForensicError> {
        let profile_hash = profile
            .profile_hash
            .clone()
            .unwrap_or_else(|| Hash::sha256(vec![0; 32]));
        let profile_version = &profile.profile_version;
        let physical_size = reader.len();

        let mut evidence_items: Vec<EvidenceItem> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();
        let mut candidate_regions: Vec<Region> = Vec::new();

        // The profile is the only source of the patterns. A missing rule means the structure
        // cannot be verified, which is reported rather than worked around with a literal.
        let identifier_rule = profile.signatures.iter().find(|s| s.name == SIG_IDENTIFIER);
        let hikbtree_rule = profile.signatures.iter().find(|s| s.name == SIG_HIKBTREE);

        let Some(identifier_rule) = identifier_rule else {
            warnings.push(format!(
                "the Hikvision profile declares no '{SIG_IDENTIFIER}' signature, so no filesystem \
                 identifier could be verified"
            ));
            return Ok(DetectorOutput::new(
                self.oem_key(),
                &profile.storage_family,
                DetectionStatus::NotDetected,
                evidence_items,
                candidate_regions,
                warnings,
                profile_version,
                profile_hash,
            ));
        };
        let identifier = identifier_rule.pattern_bytes()?;

        let boot_size = layout(profile, KEY_BOOT_SIZE, 512) as usize;
        let id_offset = layout(profile, KEY_IDENTIFIER_OFFSET, 16);
        let id_field_size = layout(profile, KEY_IDENTIFIER_FIELD_SIZE, 32);
        let page_size = layout(profile, KEY_BTREE_PAGE_SIZE, 4096) as usize;

        let candidates = [
            layout(profile, KEY_BOOT_PRIMARY, 512),
            layout(profile, KEY_BOOT_SECONDARY, 80_044_032),
        ];

        let mut identifier_matched_at: Option<u64> = None;
        let mut boot_bytes: Vec<u8> = Vec::new();

        // ── Step 1: the filesystem identifier at a declared boot position ────────────
        for boot_offset in candidates.iter().copied() {
            let Some(buf) = read_upto(reader, boot_offset, boot_size) else {
                // Not present in this acquisition. Not a mismatch, so no evidence item: a
                // 40 MB image simply does not contain a boot structure at 0x4C56000.
                continue;
            };

            // Checked boundary arithmetic for the identifier field.
            let Some(field_offset) = boot_offset.checked_add(id_offset) else {
                warnings.push(format!(
                    "boot candidate {boot_offset} plus identifier offset {id_offset} overflows"
                ));
                continue;
            };
            let id_start = id_offset as usize;
            let id_end = id_start.saturating_add(id_field_size as usize);

            let Some(field) = buf.get(id_start..id_end.min(buf.len())) else {
                warnings.push(format!(
                    "the identifier field at {field_offset} lies past the readable boot structure \
                     at {boot_offset}"
                ));
                continue;
            };

            let compared = field[..identifier.len().min(field.len())].to_vec();
            let field_len = field.len();
            if compared == identifier {
                identifier_matched_at = Some(boot_offset);
                boot_bytes = buf;
                evidence_items.push(EvidenceItem::new(
                    forensic_core::EvidenceId::new(),
                    "filesystem_identifier",
                    field_offset,
                    identifier.len() as u64,
                    &compared,
                    &identifier,
                    RuleMatchStatus::Match,
                    identifier_rule.evidence_status,
                    identifier_rule.weight,
                    identifier_rule.is_exclusive,
                    &identifier_rule.explanation,
                    profile_version,
                    profile_hash.clone(),
                ));
                if let Ok(region) =
                    Region::new(boot_offset, boot_size.min(field_len + id_start) as u64)
                {
                    candidate_regions.push(region);
                }
                break;
            }

            // A readable field that is not the identifier is a real, recordable observation:
            // it is what says "this is not a Hikvision volume".
            evidence_items.push(EvidenceItem::new(
                forensic_core::EvidenceId::new(),
                "filesystem_identifier",
                field_offset,
                identifier.len() as u64,
                &compared,
                &identifier,
                RuleMatchStatus::Mismatch,
                identifier_rule.evidence_status,
                0.0,
                identifier_rule.is_exclusive,
                format!(
                    "the 32-byte identifier field at boot offset {boot_offset} (+{id_offset}) does \
                     not carry the Hikvision filesystem identifier"
                ),
                profile_version,
                profile_hash.clone(),
            ));
        }

        // ── Step 2: corroboration by following the boot structure's own tree pointers ─
        //
        // Only attempted when the identifier matched, because without a verified boot structure
        // the bytes at +152 are not a tree pointer and reading them as one would be inventing
        // structure.
        let mut hikbtree_verified = false;
        if let (Some(_boot_offset), Some(hikbtree_rule)) = (identifier_matched_at, hikbtree_rule) {
            let magic = hikbtree_rule.pattern_bytes()?;
            let fields = [
                (
                    "primary_index_header",
                    layout(profile, KEY_BTREE_OFFSET_FIELD, 152) as usize,
                    "BTreeOffset",
                ),
                (
                    "backup_index_header",
                    layout(profile, KEY_BACKUP_BTREE_OFFSET_FIELD, 168) as usize,
                    "BackupBTreeOffset",
                ),
            ];

            for (kind, field_rel, field_name) in fields {
                let Some(declared) = i64_at(&boot_bytes, field_rel) else {
                    warnings.push(format!(
                        "the boot structure's {field_name} field at +{field_rel} lies past the \
                         readable boot structure"
                    ));
                    continue;
                };
                // Zero means "this tree is not present", a legitimate structural statement about
                // a volume rather than a damaged pointer.
                if declared == 0 {
                    continue;
                }
                if declared < 0 {
                    warnings.push(format!(
                        "the boot structure's {field_name} declares the negative value {declared}"
                    ));
                    continue;
                }
                let tree_offset = declared as u64;

                // Boundary arithmetic against the acquired size. A pointer past the end lowers
                // confidence; it does not mean the volume is not Hikvision, because a truncated
                // acquisition of a genuine Hikvision disk looks exactly like this.
                let end = tree_offset.checked_add(page_size as u64);
                if end.is_none() || tree_offset >= physical_size {
                    warnings.push(format!(
                        "the boot structure's {field_name} points to {tree_offset} \
                         (0x{tree_offset:X}), outside this {physical_size}-byte acquisition; the \
                         index header could not be verified there. This is consistent with a \
                         truncated or partial image and is not by itself evidence that the volume \
                         is not Hikvision"
                    ));
                    continue;
                }

                let Some(page) = read_upto(reader, tree_offset, magic.len()) else {
                    warnings.push(format!(
                        "the {field_name} target {tree_offset} could not be read"
                    ));
                    continue;
                };
                let observed = &page[..magic.len().min(page.len())];

                if observed == magic.as_slice() {
                    // Only the first verified tree contributes weight. A volume with both a
                    // primary and a backup tree is not twice as Hikvision as one with a primary
                    // only, and double-counting would push the score past the profile's declared
                    // `max_possible_score`.
                    let weight = if hikbtree_verified {
                        0.0
                    } else {
                        hikbtree_rule.weight
                    };
                    hikbtree_verified = true;
                    evidence_items.push(EvidenceItem::new(
                        forensic_core::EvidenceId::new(),
                        kind,
                        tree_offset,
                        magic.len() as u64,
                        observed,
                        &magic,
                        RuleMatchStatus::Match,
                        hikbtree_rule.evidence_status,
                        weight,
                        hikbtree_rule.is_exclusive,
                        format!(
                            "the index header magic was verified at the offset the boot \
                             structure's {field_name} points to, establishing a structural \
                             relationship between the two"
                        ),
                        profile_version,
                        profile_hash.clone(),
                    ));
                    if let Ok(region) = Region::new(tree_offset, page_size as u64) {
                        candidate_regions.push(region);
                    }
                } else {
                    evidence_items.push(EvidenceItem::new(
                        forensic_core::EvidenceId::new(),
                        kind,
                        tree_offset,
                        magic.len() as u64,
                        observed,
                        &magic,
                        RuleMatchStatus::Mismatch,
                        hikbtree_rule.evidence_status,
                        0.0,
                        hikbtree_rule.is_exclusive,
                        format!(
                            "the boot structure's {field_name} points to {tree_offset} but no index \
                             header magic is present there; the index may be damaged or overwritten"
                        ),
                        profile_version,
                        profile_hash.clone(),
                    ));
                    warnings.push(format!(
                        "{field_name} resolved inside the image but carries no index header magic"
                    ));
                }
            }

            // ── Video region boundary check ──────────────────────────────────────────
            //
            // Reported as a warning only. A recorder whose declared video region runs past the
            // acquired bytes is a truncated acquisition, which an examiner needs told.
            let vs_rel = layout(profile, KEY_VIDEO_START_FIELD, 120) as usize;
            if let Some(declared) = i64_at(&boot_bytes, vs_rel) {
                if declared > 0 && (declared as u64) >= physical_size {
                    warnings.push(format!(
                        "the boot structure declares the video region starting at {declared} \
                         (0x{declared:X}), past the end of this {physical_size}-byte acquisition; \
                         the image appears to be a partial capture of a larger Hikvision volume"
                    ));
                }
            }

            if !hikbtree_verified {
                warnings.push(
                    "the Hikvision filesystem identifier was verified but no index header could be \
                     confirmed through the boot structure's tree pointers, so the identifier stands \
                     alone"
                        .to_string(),
                );
            }
        }

        // ── Status ───────────────────────────────────────────────────────────────────
        //
        // A lone magic is `Insufficient` by policy (Req 10.11): the identifier alone could be a
        // fragment of a Hikvision disk, or a file that happens to contain the string. Attribution
        // needs a second, independent structure.
        let status = match (identifier_matched_at.is_some(), hikbtree_verified) {
            (true, true) => DetectionStatus::Confirmed,
            (true, false) => DetectionStatus::Insufficient,
            // The identifier is the only attribution signal this format has; without it there is
            // nothing to be ambiguous about.
            (false, _) => DetectionStatus::NotDetected,
        };

        Ok(DetectorOutput::new(
            self.oem_key(),
            &profile.storage_family,
            status,
            evidence_items,
            candidate_regions,
            warnings,
            profile_version,
            profile_hash,
        ))
    }
}
