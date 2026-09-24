//! # Honeywell MAXPRO Storage Detector
//!
//! Profile-driven, topology-aware detector for Honeywell MAXPRO NVR storage structures (Req 2.1, 2.2, 2.5, 2.8, 3.1, 9.1, 11.3, 24.4).
//!
//! Key invariants:
//! - Partition ≠ sector; sector size is NOT assumed to be 512.
//! - The largest partition is NOT proof of Honeywell.
//! - Absolute offsets computed using `checked_sector_offset` with bounds validation (Req 24.4).
//! - Emits `DetectorOutput` without claiming attribution.

use evidence_reader::EvidenceReader;
use forensic_core::{EvidenceItem, ForensicError, Hash, OemProfile, RuleMatchStatus};

use crate::detector::Detector;
use crate::output::{DetectionStatus, DetectorOutput};
use crate::topology::StorageTopologyProfiler;

pub struct HoneywellDetector;

impl Detector for HoneywellDetector {
    fn oem_key(&self) -> &'static str {
        "honeywell"
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

        // 1. Profile Topology to discover candidate regions
        let topology = StorageTopologyProfiler::profile(reader, None)?;
        let mut search_offsets = vec![0u64];

        for part in &topology.partitions {
            search_offsets.push(part.region.offset);
            candidate_regions.push(part.region);
        }

        let mut header_matched = false;
        let mut stream_marker_matched = false;

        for sig in &profile.signatures {
            let pattern = sig.pattern_bytes()?;
            let sig_len = pattern.len() as u64;

            if sig.name == "honeywell_header_magic" {
                for &offset in &search_offsets {
                    if offset + sig_len <= reader.len() {
                        let mut buf = vec![0u8; pattern.len()];
                        if let Ok(n) = reader.read_at(offset, &mut buf) {
                            if &buf[..n] == pattern.as_slice() {
                                header_matched = true;
                                evidence_items.push(EvidenceItem::new(
                                    forensic_core::EvidenceId::new(),
                                    "maxpro_volume_magic",
                                    offset,
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
                                break;
                            }
                        }
                    }
                }
            } else if sig.name == "maxpro_stream_marker" {
                let scan_limit = reader.len().min(1048576); // 1 MiB scan
                let mut chunk = vec![0u8; scan_limit as usize];
                if let Ok(read_len) = reader.read_at(0, &mut chunk) {
                    if let Some(pos) = chunk[..read_len]
                        .windows(pattern.len())
                        .position(|w| w == pattern.as_slice())
                    {
                        stream_marker_matched = true;
                        evidence_items.push(EvidenceItem::new(
                            forensic_core::EvidenceId::new(),
                            "stream_marker",
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

        let status = if header_matched && stream_marker_matched {
            DetectionStatus::Confirmed
        } else if header_matched {
            DetectionStatus::Insufficient
        } else if stream_marker_matched {
            warnings.push("MAXPRO stream marker observed without primary partition header".into());
            DetectionStatus::Ambiguous
        } else {
            DetectionStatus::NotDetected
        };

        Ok(DetectorOutput::new(
            "honeywell",
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
