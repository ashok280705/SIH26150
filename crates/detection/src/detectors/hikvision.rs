//! # Hikvision Storage Detector
//!
//! Profile-driven detector for Hikvision proprietary storage structures and boundaries (Req 2.1, 2.2, 2.5, 2.8, 3.1, 9.1, 11.3).
//!
//! Key invariants:
//! - Driven exclusively by profile rules; boundary arithmetic uses checked helpers (Req 24.4).
//! - Boundary mismatches lower confidence via evidence items rather than hard panics.
//! - Emits `DetectorOutput` without claiming attribution.

use evidence_reader::EvidenceReader;
use forensic_core::{EvidenceItem, ForensicError, Hash, OemProfile, Region, RuleMatchStatus};

use crate::detector::Detector;
use crate::output::{DetectionStatus, DetectorOutput};

pub struct HikvisionDetector;

impl Detector for HikvisionDetector {
    fn oem_key(&self) -> &'static str {
        "hikvision"
    }

    fn detect(&self, reader: &dyn EvidenceReader, profile: &OemProfile) -> Result<DetectorOutput, ForensicError> {
        let profile_hash = profile.profile_hash.clone().unwrap_or_else(|| Hash::sha256(vec![0; 32]));
        let profile_version = &profile.profile_version;
        let mut evidence_items = Vec::new();
        let mut warnings = Vec::new();
        let mut candidate_regions = Vec::new();

        let mut primary_magic_matched = false;
        let mut segment_tag_matched = false;

        for sig in &profile.signatures {
            let pattern = sig.pattern_bytes()?;
            let sig_len = pattern.len() as u64;

            if sig.name == "hik_magic" {
                if reader.len() >= sig_len {
                    let mut buf = vec![0u8; pattern.len()];
                    if let Ok(n) = reader.read_at(0, &mut buf) {
                        let observed = &buf[..n];
                        if observed == pattern.as_slice() {
                            primary_magic_matched = true;
                            candidate_regions.push(Region::new(0, 512.min(reader.len()))?);
                            evidence_items.push(EvidenceItem::new(
                                forensic_core::EvidenceId::new(),
                                "volume_header_magic",
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
                                "volume_header_magic",
                                0,
                                sig_len,
                                observed,
                                &pattern,
                                RuleMatchStatus::Mismatch,
                                sig.evidence_status,
                                0.0,
                                sig.is_exclusive,
                                "HIK header signature not found at offset 0",
                                profile_version,
                                profile_hash.clone(),
                            ));
                        }
                    }
                }
            } else if sig.name == "hik_segment_tag" {
                let scan_limit = reader.len().min(65536);
                let mut chunk = vec![0u8; scan_limit as usize];
                if let Ok(read_len) = reader.read_at(0, &mut chunk) {
                    if let Some(pos) = chunk[..read_len].windows(pattern.len()).position(|w| w == pattern.as_slice()) {
                        segment_tag_matched = true;
                        evidence_items.push(EvidenceItem::new(
                            forensic_core::EvidenceId::new(),
                            "segment_descriptor",
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

        let status = if primary_magic_matched && segment_tag_matched {
            DetectionStatus::Confirmed
        } else if primary_magic_matched {
            DetectionStatus::Insufficient
        } else if segment_tag_matched {
            warnings.push("Segment descriptor found without volume header".into());
            DetectionStatus::Ambiguous
        } else {
            DetectionStatus::NotDetected
        };

        Ok(DetectorOutput::new(
            "hikvision",
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
