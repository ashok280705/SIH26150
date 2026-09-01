//! # Dahua Storage Detector
//!
//! Profile-driven detector for Dahua DHFS/DHFS4.1 storage structures (Req 2.1, 2.2, 2.5, 2.8, 3.1, 9.1, 11.3).
//!
//! Key invariants:
//! - Generic interpretation logic driven exclusively by profile rules; no magic values are hard-coded (Req 2.5).
//! - DHAV/frame/video content interpretation is downstream; detector reasons over storage structures only.
//! - Emits `DetectorOutput` without claiming attribution.

use evidence_reader::EvidenceReader;
use forensic_core::{EvidenceItem, ForensicError, Hash, OemProfile, Region, RuleMatchStatus};


use crate::detector::Detector;
use crate::output::{DetectionStatus, DetectorOutput};

pub struct DahuaDetector;

impl Detector for DahuaDetector {
    fn oem_key(&self) -> &'static str {
        "dahua"
    }

    fn detect(&self, reader: &dyn EvidenceReader, profile: &OemProfile) -> Result<DetectorOutput, ForensicError> {
        let profile_hash = profile.profile_hash.clone().unwrap_or_else(|| Hash::sha256(vec![0; 32]));
        let profile_version = &profile.profile_version;
        let mut evidence_items = Vec::new();
        let mut warnings = Vec::new();
        let mut candidate_regions = Vec::new();

        let mut primary_magic_matched = false;
        let mut corroborating_matched = false;

        // 1. Evaluate Profile Signatures
        for sig in &profile.signatures {
            let pattern = sig.pattern_bytes()?;
            let sig_len = pattern.len() as u64;

            if sig.name == "dhfs_magic" {
                // Check exact offset 0
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
                // Scan initial window (e.g. 64KB) for corroborating DHAV packets
                let scan_limit = reader.len().min(65536);
                let mut chunk = vec![0u8; scan_limit as usize];
                if let Ok(read_len) = reader.read_at(0, &mut chunk) {
                    if let Some(pos) = chunk[..read_len].windows(pattern.len()).position(|w| w == pattern.as_slice()) {
                        corroborating_matched = true;
                        evidence_items.push(EvidenceItem::new(
                            forensic_core::EvidenceId::new(),
                            "stream_packet_tag",
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

        let status = if primary_magic_matched && corroborating_matched {
            DetectionStatus::Confirmed
        } else if primary_magic_matched {
            // Lone magic without corroborating structures is Insufficient (Req 10.11)
            DetectionStatus::Insufficient
        } else if corroborating_matched {
            warnings.push("DHAV stream tag observed without DHFS superblock".into());
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
