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
//! The SUPER magic is the primary vendor and generation signature. Nothing else — EcPortId,
//! timestamps, UI, DI or DATA — is required to identify the filesystem, and nothing else is
//! consulted here: content interpretation is the parser's job.
//!
//! * A magic match with the whole SUPER block in the image → `Confirmed`.
//! * A magic match in an image that ends inside the SUPER block → `Insufficient`, with a
//!   warning: the signature is present but the structure it heads is not.
//! * Neither magic → `NotDetected`.
//!
//! Key invariants:
//! - Magic values, offsets and sizes come from the profile only; none is hard-coded (Req 2.5).
//! - All offset arithmetic is checked; malformed or short evidence never panics.
//! - Emits `DetectorOutput` without claiming attribution.
//!
//! ## What was removed
//!
//! An earlier revision matched an ASCII `UNIV` tag at offset 0 and an `EC1001` string in the
//! first 64 KiB. Neither is the Uniview on-disk signature; both were synthetic fixture tags.

use evidence_reader::EvidenceReader;
use forensic_core::{EvidenceItem, ForensicError, Hash, OemProfile, Region, RuleMatchStatus};

use crate::detector::Detector;
use crate::output::{DetectionStatus, DetectorOutput};

/// Profile `[layout]` keys this detector needs. Key *names* are not OEM facts; the values
/// behind them are, and they live in the versioned profile.
const KEY_SUPER_OFFSET: &str = "uniview_super_offset";
const KEY_SUPER_SIZE: &str = "uniview_super_size";
const KEY_MAGIC_OFFSET: &str = "uniview_super_magic_offset";

/// Profile signature rule names this detector evaluates, with the generation each denotes.
const SIG_MAGICS: &[(&str, &str)] = &[
    ("uniview_super_magic_old", "OLD"),
    ("uniview_super_magic_new", "NEW"),
];

pub struct UniviewDetector;

fn layout_u64(profile: &OemProfile, key: &str) -> Option<u64> {
    profile.layout.get(key).and_then(|v| u64::try_from(*v).ok())
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
        let magic_offset = super_offset.checked_add(layout_u64(profile, KEY_MAGIC_OFFSET).unwrap_or(0));

        // Resolve the declared magic rules. A profile that declares none cannot detect
        // Uniview, which is reported rather than substituted with a built-in value.
        let mut rules = Vec::new();
        for (name, generation) in SIG_MAGICS {
            if let Some(sig) = profile.signatures.iter().find(|s| s.name == *name) {
                rules.push((sig, sig.pattern_bytes()?, *generation));
            }
        }
        let max_len = rules.iter().map(|(_, p, _)| p.len()).max().unwrap_or(0);

        let mut status = DetectionStatus::NotDetected;
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
                Some((sig, pattern, generation)) => {
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
                        &format!("{} ({generation} generation)", sig.explanation),
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
                        }
                        Some(end) => {
                            status = DetectionStatus::Insufficient;
                            warnings.push(format!(
                                "Uniview {generation} SUPER magic found, but the image ends at \
                                 {image_len} byte(s), inside the SUPER block (0x{super_offset:X}..0x{end:X})"
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
                return Err(ForensicError::out_of_bounds("mem", offset, buf.len() as u64, self.len()));
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
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../profiles/uniview/uniview-ubifs-v1.0.toml");
        OemProfile::from_file(std::path::Path::new(path)).unwrap()
    }

    fn image(magic: u32, len: usize) -> Mem {
        let mut d = vec![0u8; len];
        d[..4.min(len)].copy_from_slice(&magic.to_le_bytes()[..4.min(len)]);
        Mem(d)
    }

    #[test]
    fn old_and_new_magic_are_confirmed() {
        for (magic, gen) in [(0x1367u32, "OLD"), (0x1587u32, "NEW")] {
            let out = UniviewDetector.detect(&image(magic, 0x4000), &profile()).unwrap();
            assert_eq!(out.status, DetectionStatus::Confirmed);
            assert_eq!(out.evidence.len(), 1);
            assert_eq!(out.evidence[0].rule_match_status, RuleMatchStatus::Match);
            assert!(out.evidence[0].is_exclusive);
            assert!(out.evidence[0].explanation.contains(gen));
            assert_eq!(out.candidate_regions, vec![Region::new(0, 0x4000).unwrap()]);
        }
    }

    #[test]
    fn unknown_magic_is_not_detected() {
        for magic in [0u32, 0x1368, 0x6713, 0x8715, 0x5649_4E55 /* "UNIV" */] {
            let out = UniviewDetector.detect(&image(magic, 0x4000), &profile()).unwrap();
            assert_eq!(out.status, DetectionStatus::NotDetected, "magic {magic:#x}");
        }
    }

    #[test]
    fn a_truncated_super_is_insufficient_and_short_images_do_not_panic() {
        let out = UniviewDetector.detect(&image(0x1587, 0x100), &profile()).unwrap();
        assert_eq!(out.status, DetectionStatus::Insufficient);
        assert!(!out.warnings.is_empty());
        for len in [0usize, 1, 3] {
            let out = UniviewDetector.detect(&image(0x1367, len), &profile()).unwrap();
            assert_eq!(out.status, DetectionStatus::NotDetected, "len {len}");
        }
    }
}
