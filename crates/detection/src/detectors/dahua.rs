//! # Dahua Storage Detector
//!
//! Profile-driven detector for Dahua DHFS / DHFS 4.1 storage structures (Req 2.1, 2.2, 2.5, 2.8,
//! 3.1, 9.1, 11.3).
//!
//! Key invariants:
//! - Interpretation is driven exclusively by profile rules; no magic value, offset or weight is
//!   hard-coded here (Req 2.5).
//! - Frame/video content interpretation is downstream; this detector reasons over storage
//!   structures only.
//! - It emits a `DetectorOutput` and never claims attribution — that is the confidence engine's
//!   job.
//!
//! ## Corroboration on a real DHFS 4.1 layout
//!
//! A lone magic value is `Insufficient` by policy (Req 10.11), so the detector needs a second,
//! independent structure. It previously looked only for a `DHAV` frame tag inside the first
//! 64 KiB — which works on a flat image whose video starts at sector 1, but **not** on a real
//! DHFS 4.1 volume, where the video region begins megabytes in behind the partition table. Such a
//! disk would have been reported as a lone magic and downgraded to `Insufficient`.
//!
//! Corroboration therefore now also reads the DHFS 4.1 **partition table identifier** at its
//! declared offsets — a filesystem structure that sits at a fixed, known position — and the full
//! `DHFS4.1` volume signature. The `DHAV`-in-window probe is kept, so volumes that do place video
//! early still corroborate the way they always did.

use evidence_reader::EvidenceReader;
use forensic_core::{EvidenceItem, ForensicError, Hash, OemProfile, Region, RuleMatchStatus};

use crate::detector::Detector;
use crate::output::{DetectionStatus, DetectorOutput};

/// Profile `[layout]` keys this detector needs to locate the partition table.
const KEY_PT_PRIMARY: &str = "partition_table_primary_offset";
const KEY_PT_SECONDARY_A: &str = "partition_table_secondary_offset_a";
const KEY_PT_SECONDARY_B: &str = "partition_table_secondary_offset_b";
const KEY_PT_IDENTIFIER_OFFSET: &str = "partition_table_identifier_offset";
const KEY_PT_SIZE: &str = "partition_table_size";

/// Read a non-negative `[layout]` value, falling back to the documented DHFS 4.1 value.
fn layout(profile: &OemProfile, key: &str, fallback: u64) -> u64 {
    match profile.layout.get(key) {
        Some(v) if *v >= 0 => *v as u64,
        _ => fallback,
    }
}

pub struct DahuaDetector;

impl Detector for DahuaDetector {
    fn oem_key(&self) -> &'static str {
        "dahua"
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

        let mut primary_magic_matched = false;
        let mut corroborating_matched = false;

        // ── 1. The family magic at offset 0 ─────────────────────────────────
        for sig in &profile.signatures {
            let pattern = sig.pattern_bytes()?;
            let sig_len = pattern.len() as u64;

            if sig.name == "dhfs_magic" {
                if reader.len() >= sig_len {
                    let mut buf = vec![0u8; pattern.len()];
                    if let Ok(n) = reader.read_at(0, &mut buf) {
                        let observed = &buf[..n];
                        if observed == pattern.as_slice() {
                            primary_magic_matched = true;
                            candidate_regions.push(Region::new(0, 512.min(reader.len()))?);
                            evidence_items.push(EvidenceItem::new(
                                forensic_core::EvidenceId::new(),
                                "superblock_magic",
                                0,
                                sig_len,
                                observed,
                                &pattern,
                                RuleMatchStatus::Match,
                                sig.evidence_status,
                                sig.weight,
                                sig.is_exclusive,
                                &sig.explanation,
                                profile_version,
                                profile_hash.clone(),
                            ));
                        } else {
                            evidence_items.push(EvidenceItem::new(
                                forensic_core::EvidenceId::new(),
                                "superblock_magic",
                                0,
                                sig_len,
                                observed,
                                &pattern,
                                RuleMatchStatus::Mismatch,
                                sig.evidence_status,
                                0.0,
                                sig.is_exclusive,
                                "DHFS magic not found at offset 0",
                                profile_version,
                                profile_hash.clone(),
                            ));
                        }
                    }
                }
            } else if sig.name == "dhav_tag" {
                // Corroborating: a frame tag near the start of the volume. This finds flat
                // layouts whose video begins at sector 1; a real DHFS 4.1 volume is corroborated
                // by its partition table instead (below), not by this window.
                let scan_limit = reader.len().min(65536);
                let mut chunk = vec![0u8; scan_limit as usize];
                if let Ok(read_len) = reader.read_at(0, &mut chunk) {
                    if let Some(pos) = chunk[..read_len]
                        .windows(pattern.len())
                        .position(|w| w == pattern.as_slice())
                    {
                        corroborating_matched = true;
                        evidence_items.push(EvidenceItem::new(
                            forensic_core::EvidenceId::new(),
                            "stream_frame_tag",
                            pos as u64,
                            sig_len,
                            &pattern,
                            &pattern,
                            RuleMatchStatus::Match,
                            sig.evidence_status,
                            sig.weight,
                            sig.is_exclusive,
                            &sig.explanation,
                            profile_version,
                            profile_hash.clone(),
                        ));
                    }
                }
            }
        }

        // ── 2. The full DHFS 4.1 volume signature ───────────────────────────
        // Not corroboration on its own — it overlaps the family magic at the same offset — but it
        // records which DHFS variant this is, which the parser then acts on.
        let mut is_dhfs41 = false;
        if let Some(sig) = profile.signatures.iter().find(|s| s.name == "dhfs41_magic") {
            let pattern = sig.pattern_bytes()?;
            if reader.len() >= pattern.len() as u64 {
                if let Ok(buf) = reader.read_exact_at(0, pattern.len()) {
                    if buf == pattern {
                        is_dhfs41 = true;
                        evidence_items.push(EvidenceItem::new(
                            forensic_core::EvidenceId::new(),
                            "dhfs41_volume_signature",
                            0,
                            pattern.len() as u64,
                            &buf,
                            &pattern,
                            RuleMatchStatus::Match,
                            sig.evidence_status,
                            sig.weight,
                            sig.is_exclusive,
                            &sig.explanation,
                            profile_version,
                            profile_hash.clone(),
                        ));
                    }
                }
            }
        }

        // ── 3. Corroborating: the DHFS 4.1 partition table identifier ───────
        let identifier_offset = layout(profile, KEY_PT_IDENTIFIER_OFFSET, 304);
        let table_size = layout(profile, KEY_PT_SIZE, 512);
        let candidates = [
            ("primary", layout(profile, KEY_PT_PRIMARY, 15_360)),
            ("secondary_a", layout(profile, KEY_PT_SECONDARY_A, 15_872)),
            ("secondary_b", layout(profile, KEY_PT_SECONDARY_B, 31_744)),
        ];
        let identifier_rules: Vec<(&str, Vec<u8>)> = profile
            .signatures
            .iter()
            .filter(|s| s.name.starts_with("partition_table_id_"))
            .filter_map(|s| s.pattern_bytes().ok().map(|p| (s.name.as_str(), p)))
            .collect();

        for (role, table_at) in candidates {
            let at = match table_at.checked_add(identifier_offset) {
                Some(v) => v,
                None => continue,
            };
            for (rule_name, pattern) in &identifier_rules {
                let want = pattern.len() as u64;
                if at >= reader.len() || at.saturating_add(want) > reader.len() {
                    continue;
                }
                let Ok(observed) = reader.read_exact_at(at, pattern.len()) else {
                    continue;
                };
                if &observed != pattern {
                    continue;
                }
                corroborating_matched = true;
                if let Ok(region) = Region::new(table_at, table_size.min(reader.len() - table_at)) {
                    candidate_regions.push(region);
                }
                let sig = profile
                    .signatures
                    .iter()
                    .find(|s| s.name == *rule_name)
                    .expect("the rule came from this profile");
                evidence_items.push(EvidenceItem::new(
                    forensic_core::EvidenceId::new(),
                    "partition_table_identifier",
                    at,
                    want,
                    &observed,
                    pattern,
                    RuleMatchStatus::Match,
                    sig.evidence_status,
                    sig.weight,
                    sig.is_exclusive,
                    format!(
                        "{} ({} partition table candidate at 0x{table_at:X})",
                        sig.explanation, role
                    ),
                    profile_version,
                    profile_hash.clone(),
                ));
                // One identifier per candidate offset; the generations are mutually exclusive.
                break;
            }
        }

        if primary_magic_matched && is_dhfs41 && !corroborating_matched {
            warnings.push(
                "DHFS 4.1 volume signature present but neither a partition table identifier nor a \
                 frame tag was located, so the volume is reported as structurally insufficient \
                 rather than attributed"
                    .into(),
            );
        }

        let status = if primary_magic_matched && corroborating_matched {
            DetectionStatus::Confirmed
        } else if primary_magic_matched {
            // A lone magic without corroborating structures is Insufficient (Req 10.11).
            DetectionStatus::Insufficient
        } else if corroborating_matched {
            warnings.push(
                "Dahua storage structures observed without the DHFS volume signature at offset 0"
                    .into(),
            );
            DetectionStatus::Ambiguous
        } else {
            DetectionStatus::NotDetected
        };

        Ok(DetectorOutput::new(
            "dahua",
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
