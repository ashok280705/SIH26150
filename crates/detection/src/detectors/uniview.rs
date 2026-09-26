//! # Uniview Storage Detector
//!
//! Profile-driven detector for the Uniview recorder filesystem (Req 2.1, 2.2, 2.5, 2.8, 3.1,
//! 9.1, 11.3, 25.1–25.4).
//!
//! ## What this detector looks for
//!
//! ```text
//!   SUPER + magic offset   u32 LE   0x1367 → OLD generation
//!                                   0x1587 → NEW generation
//! ```
//!
//! The SUPER magic is the primary vendor and generation signature — it is the only acceptance
//! test the vendor's own disktool applies.
//!
//! * A magic match with the whole SUPER block in the image → `Confirmed`.
//! * A magic match in an image that ends inside the SUPER block → `Insufficient`, with a
//!   warning: the signature is present but the structure it heads is not.
//! * Neither magic → `NotDetected`, unless the evidence is a disktool `.h3crd` export (below).
//!
//! ## Structural corroboration (never mandatory)
//!
//! With a confirmed magic, three checks mirror disktool's own logic and reduce false positives
//! from an unrelated structure that happens to start with the magic bytes:
//!
//! * UI / UI-CTL: the u16 rewrited flag is 0 or 1, and the raw current-unit value gives a
//!   written-unit count (OLD `raw - 1`, NEW `raw + 1`) within the profile's unit bound;
//! * unit 1's DI record count is `<= 0x4000` (disktool's "data index head abnormal" bound);
//! * unit 1's first DI entry decodes: a calendar-valid timestamp and an SPtoI beyond the DI.
//!
//! A passing check adds a corroborating (non-exclusive) evidence item weighted by the profile's
//! validation rule. A failing or unevaluable check adds only a warning: the evidence is then a
//! Uniview candidate / degraded filesystem, never "not Uniview".
//!
//! ## disktool `.h3crd` exports
//!
//! Only when neither magic matches, the detector checks for the disktool export header tag
//! (`"iVS8000@huawei-3com"`). A match is reported with a warning that the evidence is a
//! normalized export artifact, not a physical disk. Raw-disk detection is unaffected.
//!
//! Key invariants:
//! - Magic values, offsets, sizes and weights come from the profile only (Req 2.5).
//! - All offset arithmetic is checked; malformed or short evidence never panics.
//! - Emits `DetectorOutput` without claiming attribution.

use evidence_reader::EvidenceReader;
use forensic_core::{EvidenceItem, ForensicError, Hash, OemProfile, Region, RuleMatchStatus};

use crate::detector::Detector;
use crate::output::{DetectionStatus, DetectorOutput};

/// Profile `[layout]` keys this detector needs. Key *names* are not OEM facts; the values
/// behind them are, and they live in the versioned profile.
const KEY_SUPER_OFFSET: &str = "uniview_super_offset";
const KEY_SUPER_SIZE: &str = "uniview_super_size";
const KEY_MAGIC_OFFSET: &str = "uniview_super_magic_offset";
const KEY_UI_OFFSET: &str = "uniview_ui_offset";
const KEY_OLD_CUR: &str = "uniview_old_ui_current_unit_offset";
const KEY_OLD_REWRITED: &str = "uniview_old_ui_rewrited_offset";
const KEY_OLD_ADJUST: &str = "uniview_old_ui_unit_count_adjust";
const KEY_NEW_CUR: &str = "uniview_new_uictl_current_unit_offset";
const KEY_NEW_REWRITED: &str = "uniview_new_uictl_rewrited_offset";
const KEY_NEW_ADJUST: &str = "uniview_new_uictl_unit_count_adjust";
const KEY_MAX_UNITS: &str = "uniview_max_units";
const KEY_OLD_UNIT_BASE: &str = "uniview_old_unit_base";
const KEY_NEW_UNIT_BASE: &str = "uniview_new_unit_base";
const KEY_DI_COUNT_OFFSET: &str = "uniview_di_entry_count_offset";
const KEY_DI_COUNT_MAX: &str = "uniview_di_count_max";
const KEY_DI_ENTRIES_OFFSET: &str = "uniview_di_entries_offset";
const KEY_DI_SIZE: &str = "uniview_di_size";
const KEY_DATA_BLOCK_SIZE: &str = "uniview_data_block_size";
const KEY_TS_MIN_YEAR: &str = "uniview_timestamp_plausible_min_year";
const KEY_TS_MAX_YEAR: &str = "uniview_timestamp_plausible_max_year";
const KEY_H3CRD_HEADER_SIZE: &str = "uniview_h3crd_header_size";

/// Profile signature rule names this detector evaluates, with the generation each denotes.
const SIG_MAGICS: &[(&str, Gen)] = &[
    ("uniview_super_magic_old", Gen::Old),
    ("uniview_super_magic_new", Gen::New),
];
const SIG_H3CRD_TAG: &str = "uniview_h3crd_export_tag";

/// Profile validation rules used for corroboration weights.
const RULE_UI: &str = "ui_header_plausible";
const RULE_DI_COUNT: &str = "di_head_count_within_vendor_bound";
const RULE_DI_ENTRY: &str = "di_first_entry_decodes";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gen {
    Old,
    New,
}

impl Gen {
    fn label(self) -> &'static str {
        match self {
            Gen::Old => "OLD",
            Gen::New => "NEW",
        }
    }
}

pub struct UniviewDetector;

fn layout_u64(profile: &OemProfile, key: &str) -> Option<u64> {
    profile.layout.get(key).and_then(|v| u64::try_from(*v).ok())
}

fn layout_u64_or(profile: &OemProfile, key: &str, fallback: u64) -> u64 {
    layout_u64(profile, key).unwrap_or(fallback)
}

fn layout_i64_or(profile: &OemProfile, key: &str, fallback: i64) -> i64 {
    profile.layout.get(key).copied().unwrap_or(fallback)
}

/// Read up to `len` bytes at `offset`; `None` when fewer than `len` are in the image.
fn read_exact(
    reader: &dyn EvidenceReader,
    offset: u64,
    len: usize,
) -> Result<Option<Vec<u8>>, ForensicError> {
    let Some(end) = offset.checked_add(len as u64) else {
        return Ok(None);
    };
    if end > reader.len() {
        return Ok(None);
    }
    Ok(Some(reader.read_exact_at(offset, len)?))
}

fn u16_le(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes([
        *b.get(off)?,
        *b.get(off.checked_add(1)?)?,
    ]))
}

fn u32_le(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// The packed 5-byte timestamp's fields form a plausible calendar date and time.
fn packed_timestamp_plausible(b: &[u8], min_year: u64, max_year: u64) -> bool {
    if b.len() < 5 || b[..5].iter().all(|&x| x == 0) {
        return false;
    }
    let year = u64::from(b[0]) | (u64::from(b[1] & 0x0F) << 8);
    let month = b[1] >> 4;
    let day = b[2] & 0x1F;
    let hour = ((b[3] & 0x03) << 3) | (b[2] >> 5);
    let minute = b[3] >> 2;
    let second = b[4] & 0x3F;
    (min_year..=max_year).contains(&year)
        && (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && hour < 24
        && minute < 60
        && second < 60
}

struct Corroboration<'a> {
    profile: &'a OemProfile,
    profile_hash: Hash,
    items: Vec<EvidenceItem>,
    warnings: Vec<String>,
}

impl Corroboration<'_> {
    fn pass(&mut self, rule: &str, offset: u64, observed: &[u8], explanation: String) {
        let profile: &OemProfile = self.profile;
        match profile.validation_rules.iter().find(|r| r.name == rule) {
            Some(r) => self.items.push(EvidenceItem::new(
                forensic_core::EvidenceId::new(),
                format!("uniview_{rule}"),
                offset,
                observed.len() as u64,
                observed,
                &[],
                RuleMatchStatus::Match,
                r.evidence_status,
                r.weight,
                false, // corroboration only
                explanation,
                &profile.profile_version,
                self.profile_hash.clone(),
            )),
            None => self.warnings.push(format!(
                "structural check '{rule}' passed but the profile declares no validation rule for it"
            )),
        }
    }

    fn degraded(&mut self, what: String) {
        self.warnings.push(format!(
            "structural corroboration failed: {what}; reported as a degraded Uniview filesystem \
             (the SUPER magic still identifies it)"
        ));
    }
}

fn corroborate(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    profile_hash: Hash,
    gen: Gen,
) -> Result<(Vec<EvidenceItem>, Vec<String>), ForensicError> {
    let mut c = Corroboration {
        profile,
        profile_hash,
        items: Vec::new(),
        warnings: Vec::new(),
    };

    // ── UI / UI-CTL header ───────────────────────────────────────────────────
    let ui_offset = layout_u64_or(profile, KEY_UI_OFFSET, 0x4000);
    let (cur_off, rw_off, adjust) = match gen {
        Gen::Old => (
            layout_u64_or(profile, KEY_OLD_CUR, 0),
            layout_u64_or(profile, KEY_OLD_REWRITED, 6),
            layout_i64_or(profile, KEY_OLD_ADJUST, -1),
        ),
        Gen::New => (
            layout_u64_or(profile, KEY_NEW_CUR, 0),
            layout_u64_or(profile, KEY_NEW_REWRITED, 12),
            layout_i64_or(profile, KEY_NEW_ADJUST, 1),
        ),
    };
    let max_units =
        i64::try_from(layout_u64_or(profile, KEY_MAX_UNITS, 65_536)).unwrap_or(i64::MAX);
    match read_exact(reader, ui_offset, 16)? {
        Some(ui) => {
            let cur = usize::try_from(cur_off).ok().and_then(|o| u32_le(&ui, o));
            let flag = usize::try_from(rw_off).ok().and_then(|o| u16_le(&ui, o));
            match (cur, flag) {
                (Some(cur), Some(flag)) => {
                    let count = i64::from(cur).saturating_add(adjust);
                    if flag <= 1 && (0..=max_units).contains(&count) {
                        c.pass(
                            RULE_UI,
                            ui_offset,
                            &ui,
                            format!(
                                "{} header plausible: rewrited flag {flag}, raw current unit {cur} \
                                 -> {count} written unit(s)",
                                if gen == Gen::Old { "UI" } else { "UI-CTL" }
                            ),
                        );
                    } else {
                        c.degraded(format!(
                            "UI header implausible (rewrited flag {flag}, raw current unit {cur} -> \
                             {count} written unit(s))"
                        ));
                    }
                }
                _ => c.degraded("UI header fields not addressable".into()),
            }
        }
        None => c.degraded("the UI / UI-CTL header is not in the image".into()),
    }

    // ── Unit 1 DI head and first entry ───────────────────────────────────────
    let base = match gen {
        Gen::Old => layout_u64_or(profile, KEY_OLD_UNIT_BASE, 0x1_4000),
        Gen::New => layout_u64_or(profile, KEY_NEW_UNIT_BASE, 0x1001_4000),
    };
    let count_off = layout_u64_or(profile, KEY_DI_COUNT_OFFSET, 4);
    let count_max = layout_u64_or(profile, KEY_DI_COUNT_MAX, 0x4000);
    let entries_off = layout_u64_or(profile, KEY_DI_ENTRIES_OFFSET, 0x10);
    let block = layout_u64_or(profile, KEY_DATA_BLOCK_SIZE, 0x4000).max(1);
    let di_blocks = layout_u64_or(profile, KEY_DI_SIZE, 0x40000).div_ceil(block);
    let min_year = layout_u64_or(profile, KEY_TS_MIN_YEAR, 2000);
    let max_year = layout_u64_or(profile, KEY_TS_MAX_YEAR, 2100);
    let head_len = usize::try_from(entries_off.saturating_add(16)).unwrap_or(32);
    match read_exact(reader, base, head_len)? {
        Some(di) => {
            let count = usize::try_from(count_off).ok().and_then(|o| u32_le(&di, o));
            match count {
                Some(count) if u64::from(count) <= count_max => {
                    c.pass(
                        RULE_DI_COUNT,
                        base.saturating_add(count_off),
                        &count.to_le_bytes(),
                        format!("unit 1 DI record count {count} is within the vendor bound {count_max}"),
                    );
                    if count >= 2 {
                        let e = usize::try_from(entries_off).ok().and_then(|o| di.get(o..o + 16));
                        match e {
                            Some(e) => {
                                let sptoi = (u64::from(e[7]) << 6) | (u64::from(e[6]) >> 2);
                                if packed_timestamp_plausible(e, min_year, max_year) && sptoi >= di_blocks {
                                    c.pass(
                                        RULE_DI_ENTRY,
                                        base.saturating_add(entries_off),
                                        e,
                                        format!("unit 1 DI record 1 decodes: plausible timestamp, SPtoI {sptoi}"),
                                    );
                                } else {
                                    c.degraded(format!(
                                        "unit 1 DI record 1 does not decode (timestamp implausible or SPtoI \
                                         {sptoi} < {di_blocks})"
                                    ));
                                }
                            }
                            None => c.degraded("unit 1 DI record 1 not addressable".into()),
                        }
                    }
                }
                Some(count) => c.degraded(format!(
                    "unit 1 DI record count {count} exceeds the vendor bound {count_max} (\"data index \
                     head abnormal\")"
                )),
                None => c.degraded("unit 1 DI header not addressable".into()),
            }
        }
        None => c.degraded("unit 1's DI header is not in the image".into()),
    }

    Ok((c.items, c.warnings))
}

impl Detector for UniviewDetector {
    fn oem_key(&self) -> &'static str {
        "uniview"
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
        let mut evidence_items = Vec::new();
        let mut warnings = Vec::new();
        let mut candidate_regions = Vec::new();

        let image_len = reader.len();
        let super_offset = layout_u64(profile, KEY_SUPER_OFFSET).unwrap_or(0);
        let super_size = layout_u64(profile, KEY_SUPER_SIZE);
        let magic_offset =
            super_offset.checked_add(layout_u64(profile, KEY_MAGIC_OFFSET).unwrap_or(0));

        // Resolve the declared magic rules. A profile that declares none cannot detect
        // Uniview, which is reported rather than substituted with a built-in value.
        let mut rules = Vec::new();
        for (name, gen) in SIG_MAGICS {
            if let Some(sig) = profile.signatures.iter().find(|s| s.name == *name) {
                rules.push((sig, sig.pattern_bytes()?, *gen));
            }
        }
        let max_len = rules.iter().map(|(_, p, _)| p.len()).max().unwrap_or(0);

        let mut status = DetectionStatus::NotDetected;
        let mut magic_matched = false;
        if rules.is_empty() {
            warnings.push("the Uniview profile declares no SUPER magic signature".to_string());
        } else if let Some(magic_offset) = magic_offset.filter(|o| *o < image_len && max_len > 0) {
            let mut buf = vec![0u8; max_len];
            let n = reader.read_at(magic_offset, &mut buf)?;
            let observed = &buf[..n];

            let matched = rules
                .iter()
                .find(|(_, pattern, _)| !pattern.is_empty() && observed.starts_with(pattern));

            match matched {
                Some((sig, pattern, gen)) => {
                    magic_matched = true;
                    let sig_len = pattern.len() as u64;
                    evidence_items.push(EvidenceItem::new(
                        forensic_core::EvidenceId::new(),
                        "uniview_super_magic",
                        magic_offset,
                        sig_len,
                        &observed[..pattern.len()],
                        pattern,
                        RuleMatchStatus::Match,
                        sig.evidence_status,
                        sig.weight,
                        sig.is_exclusive,
                        format!("{} ({} generation)", sig.explanation, gen.label()),
                        profile_version,
                        profile_hash.clone(),
                    ));

                    let super_end = super_size.and_then(|s| super_offset.checked_add(s));
                    match super_end {
                        Some(end) if end <= image_len => {
                            status = DetectionStatus::Confirmed;
                            if let Ok(r) = Region::new(super_offset, end - super_offset) {
                                candidate_regions.push(r);
                            }
                            let (items, notes) =
                                corroborate(reader, profile, profile_hash.clone(), *gen)?;
                            evidence_items.extend(items);
                            warnings.extend(notes);
                        }
                        Some(end) => {
                            status = DetectionStatus::Insufficient;
                            warnings.push(format!(
                                "Uniview {} SUPER magic found, but the image ends at {image_len} \
                                 byte(s), inside the SUPER block (0x{super_offset:X}..0x{end:X})",
                                gen.label()
                            ));
                            if let Ok(r) = Region::new(super_offset, image_len - super_offset) {
                                candidate_regions.push(r);
                            }
                        }
                        None => {
                            status = DetectionStatus::Insufficient;
                            warnings.push(
                                "the Uniview profile declares no SUPER size, so the structure the \
                                 magic heads cannot be bounded"
                                    .to_string(),
                            );
                        }
                    }
                }
                None => {
                    let (sig, pattern, _) = &rules[0];
                    let shown = &observed[..observed.len().min(pattern.len())];
                    evidence_items.push(EvidenceItem::new(
                        forensic_core::EvidenceId::new(),
                        "uniview_super_magic",
                        magic_offset,
                        shown.len() as u64,
                        shown,
                        pattern,
                        RuleMatchStatus::Mismatch,
                        sig.evidence_status,
                        0.0,
                        sig.is_exclusive,
                        "neither Uniview SUPER magic (0x1367 OLD, 0x1587 NEW) is present",
                        profile_version,
                        profile_hash.clone(),
                    ));
                }
            }
        }

        // ── disktool .h3crd export: only when no raw-disk magic matched ──────────
        if !magic_matched {
            if let Some(sig) = profile.signatures.iter().find(|s| s.name == SIG_H3CRD_TAG) {
                let tag = sig.pattern_bytes()?;
                if !tag.is_empty() {
                    if let Some(observed) = read_exact(reader, 0, tag.len())? {
                        if observed == tag {
                            // The magic mismatch item is not evidence against an export, whose
                            // header replaces the SUPER; keep only the export's own evidence.
                            evidence_items.clear();
                            evidence_items.push(EvidenceItem::new(
                                forensic_core::EvidenceId::new(),
                                "uniview_h3crd_export_tag",
                                0,
                                tag.len() as u64,
                                &observed,
                                &tag,
                                RuleMatchStatus::Match,
                                sig.evidence_status,
                                sig.weight,
                                sig.is_exclusive,
                                sig.explanation.clone(),
                                profile_version,
                                profile_hash.clone(),
                            ));
                            status = DetectionStatus::Confirmed;
                            let header =
                                layout_u64_or(profile, KEY_H3CRD_HEADER_SIZE, 0x68).min(image_len);
                            if let Ok(r) = Region::new(0, header) {
                                candidate_regions.push(r);
                            }
                            warnings.push(
                                "Uniview disktool .h3crd export: an OLD-shaped single-unit \
                                 normalized artifact produced by disktool, not an original physical \
                                 disk layout"
                                    .to_string(),
                            );
                        }
                    }
                }
            }
        }

        Ok(DetectorOutput::new(
            "uniview",
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

#[cfg(test)]
mod tests {
    use super::*;

    struct Mem(Vec<u8>);

    impl EvidenceReader for Mem {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
            if offset >= self.len() {
                return Err(ForensicError::out_of_bounds(
                    "mem",
                    offset,
                    buf.len() as u64,
                    self.len(),
                ));
            }
            let s = offset as usize;
            let n = (self.0.len() - s).min(buf.len());
            buf[..n].copy_from_slice(&self.0[s..s + n]);
            Ok(n)
        }
        fn source_kind(&self) -> evidence_reader::SourceKind {
            evidence_reader::SourceKind::Raw
        }
        fn source_path(&self) -> &str {
            "mem://uniview-detector"
        }
    }

    fn profile() -> OemProfile {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../profiles/uniview/uniview-ubifs-v1.0.toml"
        );
        OemProfile::from_file(std::path::Path::new(path)).unwrap()
    }

    fn image(magic: u32, len: usize) -> Mem {
        let mut d = vec![0u8; len];
        d[..4.min(len)].copy_from_slice(&magic.to_le_bytes()[..4.min(len)]);
        Mem(d)
    }

    /// A small OLD image with a plausible UI and a decodable first DI entry.
    fn structured_old() -> Mem {
        let mut d = vec![0u8; 0x14000 + 0x40000];
        d[..4].copy_from_slice(&0x1367u32.to_le_bytes());
        d[0x4000..0x4004].copy_from_slice(&2u32.to_le_bytes()); // raw 2 -> 1 written unit
        d[0x4006..0x4008].copy_from_slice(&1u16.to_le_bytes()); // rewrited
        d[0x14004..0x14008].copy_from_slice(&2u32.to_le_bytes()); // header + 1 entry
                                                                  // 2024-03-15 13:45:30, SPtoI 16.
        d[0x14010..0x14015].copy_from_slice(&[0xE8, 0x37, 0xAF, 0xB5, 0x1E]);
        d[0x14016] = (16 & 0x3F) << 2;
        d[0x14017] = 0;
        Mem(d)
    }

    #[test]
    fn old_and_new_magic_are_confirmed_even_without_structure() {
        for (magic, gen) in [(0x1367u32, "OLD"), (0x1587u32, "NEW")] {
            let out = UniviewDetector
                .detect(&image(magic, 0x4000), &profile())
                .unwrap();
            assert_eq!(out.status, DetectionStatus::Confirmed);
            assert_eq!(
                out.evidence.len(),
                1,
                "failed corroboration adds no evidence item"
            );
            assert_eq!(out.evidence[0].rule_match_status, RuleMatchStatus::Match);
            assert!(out.evidence[0].is_exclusive);
            assert!(out.evidence[0].explanation.contains(gen));
            assert_eq!(out.candidate_regions, vec![Region::new(0, 0x4000).unwrap()]);
            assert!(
                out.warnings.iter().any(|w| w.contains("degraded")),
                "{:?}",
                out.warnings
            );
        }
    }

    #[test]
    fn structural_corroboration_adds_non_exclusive_evidence() {
        let out = UniviewDetector
            .detect(&structured_old(), &profile())
            .unwrap();
        assert_eq!(out.status, DetectionStatus::Confirmed);
        let kinds: Vec<_> = out.evidence.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec![
                "uniview_super_magic",
                "uniview_ui_header_plausible",
                "uniview_di_head_count_within_vendor_bound",
                "uniview_di_first_entry_decodes",
            ]
        );
        assert!(out.evidence[1..].iter().all(|e| !e.is_exclusive));
        assert!(out.warnings.is_empty(), "{:?}", out.warnings);
    }

    #[test]
    fn a_degraded_filesystem_is_still_uniview() {
        let mut m = structured_old();
        m.0[0x4006..0x4008].copy_from_slice(&7u16.to_le_bytes()); // implausible flag
        m.0[0x14004..0x14008].copy_from_slice(&0x4001u32.to_le_bytes()); // abnormal count
        let out = UniviewDetector.detect(&m, &profile()).unwrap();
        assert_eq!(out.status, DetectionStatus::Confirmed);
        assert_eq!(out.evidence.len(), 1);
        assert_eq!(out.warnings.len(), 2);
        assert!(out
            .warnings
            .iter()
            .any(|w| w.contains("data index head abnormal")));
    }

    #[test]
    fn unknown_magic_is_not_detected() {
        for magic in [0u32, 0x1368, 0x6713, 0x8715, 0x5649_4E55 /* "UNIV" */] {
            let out = UniviewDetector
                .detect(&image(magic, 0x4000), &profile())
                .unwrap();
            assert_eq!(out.status, DetectionStatus::NotDetected, "magic {magic:#x}");
        }
    }

    #[test]
    fn a_disktool_h3crd_export_is_detected_and_labelled() {
        let mut d = vec![0u8; 0x54000];
        d[..19].copy_from_slice(b"iVS8000@huawei-3com");
        let out = UniviewDetector.detect(&Mem(d), &profile()).unwrap();
        assert_eq!(out.status, DetectionStatus::Confirmed);
        assert_eq!(out.evidence.len(), 1);
        assert_eq!(out.evidence[0].kind, "uniview_h3crd_export_tag");
        assert!(out
            .warnings
            .iter()
            .any(|w| w.contains("not an original physical disk")));
        // A lookalike prefix is not an export.
        let mut d = vec![0u8; 0x100];
        d[..8].copy_from_slice(b"iVS8000@");
        assert_eq!(
            UniviewDetector.detect(&Mem(d), &profile()).unwrap().status,
            DetectionStatus::NotDetected
        );
    }

    #[test]
    fn a_truncated_super_is_insufficient_and_short_images_do_not_panic() {
        let out = UniviewDetector
            .detect(&image(0x1587, 0x100), &profile())
            .unwrap();
        assert_eq!(out.status, DetectionStatus::Insufficient);
        assert!(!out.warnings.is_empty());
        for len in [0usize, 1, 3] {
            let out = UniviewDetector
                .detect(&image(0x1367, len), &profile())
                .unwrap();
            assert_eq!(out.status, DetectionStatus::NotDetected, "len {len}");
        }
    }
}
