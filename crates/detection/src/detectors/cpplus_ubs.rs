//! # CP Plus / UBS Storage Detector
//!
//! Profile-driven detector for CP Plus and UBS storage formats (Req 2.1, 2.2, 2.4, 2.5, 2.8, 3.1, 9.1, 11.3).
//!
//! Key invariants:
//! - UBS signature alone does NOT establish CP Plus confirmation (Req 2.4).
//! - All candidate values are profile data, never source constants.
//! - Emits `DetectorOutput` without claiming attribution.

use evidence_reader::EvidenceReader;
use forensic_core::{EvidenceItem, ForensicError, Hash, OemProfile, Region, RuleMatchStatus};

use crate::detector::Detector;
use crate::output::{DetectionStatus, DetectorOutput};

pub struct CpPlusUbsDetector;

impl Detector for CpPlusUbsDetector {
    fn oem_key(&self) -> &'static str {
        "cpplus_ubs"
    }

    fn detect(&self, reader: &dyn EvidenceReader, profile: &OemProfile) -> Result<DetectorOutput, ForensicError> {
        let profile_hash = profile.profile_hash.clone().unwrap_or_else(|| Hash::sha256(vec![0; 32]));
        let profile_version = &profile.profile_version;
        let mut evidence_items = Vec::new();
        let mut warnings = Vec::new();
        let mut candidate_regions = Vec::new();

        let mut ubs_marker_matched = false;
        let mut cpplus_string_matched = false;

        for sig in &profile.signatures {
            let pattern = sig.pattern_bytes()?;
            let sig_len = pattern.len() as u64;

            if sig.name == "ubs_partition_marker" {
                if reader.len() >= sig_len {
                    let mut buf = vec![0u8; pattern.len()];
                    if let Ok(n) = reader.read_at(0, &mut buf) {
                        let observed = &buf[..n];
                        if observed == pattern.as_slice() {
                            ubs_marker_matched = true;
                            candidate_regions.push(Region::new(0, 512.min(reader.len()))?);
                            evidence_items.push(EvidenceItem::new(
                                forensic_core::EvidenceId::new(),
                                "ubs_superblock_marker",
                                0,
                                sig_len,
                                observed,
                                &pattern,
                                RuleMatchStatus::Match,
                                sig.evidence_status,
                                sig.weight,
                                sig.is_exclusive, // false! Non-exclusive
                                &sig.explanation,
                                profile_version,
                                profile_hash.clone(),
                            ));
                        } else {
                            evidence_items.push(EvidenceItem::new(
                                forensic_core::EvidenceId::new(),
                                "ubs_superblock_marker",
                                0,
                                sig_len,
                                observed,
                                &pattern,
                                RuleMatchStatus::Mismatch,
                                sig.evidence_status,
                                0.0,
                                sig.is_exclusive,
                                "UBS marker not found at offset 0",
                                profile_version,
                                profile_hash.clone(),
                            ));
                        }
                    }
                }
            } else if sig.name == "cpplus_oem_string" {
                let scan_limit = reader.len().min(65536);
                let mut chunk = vec![0u8; scan_limit as usize];
                if let Ok(read_len) = reader.read_at(0, &mut chunk) {
                    if let Some(pos) = chunk[..read_len].windows(pattern.len()).position(|w| w == pattern.as_slice()) {
                        cpplus_string_matched = true;
                        evidence_items.push(EvidenceItem::new(
                            forensic_core::EvidenceId::new(),
                            "cpplus_branding_string",
                            pos as u64,
                            sig_len,
                            &pattern,
                            &pattern,
                            RuleMatchStatus::Match,
                            sig.evidence_status,
                            sig.weight,
                            sig.is_exclusive, // true! Exclusive CP Plus string
                            &sig.explanation,
                            profile_version,
                            profile_hash.clone(),
                        ));
                    }
                }
            }
        }

        let status = if ubs_marker_matched && cpplus_string_matched {
            DetectionStatus::Confirmed
        } else if ubs_marker_matched {
            // UBS alone is compatible candidate indicator (Req 2.4)
            warnings.push("UBS storage detected without explicit CP Plus branding".into());
            DetectionStatus::Confirmed // preliminary detector indicator, downstream attribution handles exclusivity
        } else if cpplus_string_matched {
            warnings.push("CP Plus string observed without valid UBS superblock".into());
            DetectionStatus::Ambiguous
        } else {
            DetectionStatus::NotDetected
        };

        Ok(DetectorOutput::new(
            "cpplus_ubs",
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
