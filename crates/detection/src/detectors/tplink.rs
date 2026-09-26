//! # TP-Link VIGI NVR Storage Detector
//!
//! Profile-driven detector for TP-Link VIGI NVR storage structures (Req 2.1, 2.2, 2.5, 2.8, 3.1, 9.1, 11.3).
//!
//! Key invariants:
//! - Generic interpretation logic driven exclusively by profile rules.
//! - Uses multiple independent indicators (partitioning, EXT4, TP-Link metadata, SQLite).
//! - Emits `DetectorOutput` without claiming attribution.

use evidence_reader::EvidenceReader;
use forensic_core::{EvidenceItem, ForensicError, Hash, OemProfile, RuleMatchStatus};

use crate::detector::Detector;
use crate::output::{DetectionStatus, DetectorOutput};
use crate::topology::{StorageTopologyProfiler, TopologyType};

pub struct TplinkDetector;

impl Detector for TplinkDetector {
    fn oem_key(&self) -> &'static str {
        "tplink"
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

        // Indicator flags
        let mut ext4_matched = false;
        let mut swap_matched = false;
        let mut tp_magic_matched = false;
        let mut tp_metadata_matched = false;
        let mut sqlite_matched = false;

        // 1. Storage Topology Profiling
        // TP-Link VIGI NVR uses MBR partitioning with SWAP (partition 1) and EXT4 (partition 2)
        if let Ok(topology) = StorageTopologyProfiler::profile(reader, None) {
            if topology.topology_type == TopologyType::Mbr {
                for part in topology.partitions {
                    candidate_regions.push(part.region);
                }
            }
        }

        // 2. Evaluate Profile Signatures
        for sig in &profile.signatures {
            let pattern = sig.pattern_bytes()?;
            let sig_len = pattern.len() as u64;

            // Define a search window based on constraints, or default to first 10MB
            let search_limit =
                if let Some(forensic_core::OffsetConstraint::HeaderWindow { max_offset }) =
                    sig.offset_constraints.first()
                {
                    reader.len().min(*max_offset)
                } else {
                    reader.len().min(10 * 1024 * 1024)
                };

            // In a real implementation, we'd use RegionScanner for efficiency,
            // but for detection within a reasonable window, reading a chunk is acceptable.
            let chunk_size = search_limit as usize;
            let mut chunk = vec![0u8; chunk_size];
            if let Ok(read_len) = reader.read_at(0, &mut chunk) {
                let actual_chunk = &chunk[..read_len];

                if let Some(pos) = actual_chunk
                    .windows(pattern.len())
                    .position(|w| w == pattern.as_slice())
                {
                    let observed = &actual_chunk[pos..pos + pattern.len()];

                    match sig.name.as_str() {
                        "ext4_superblock" => ext4_matched = true,
                        "swap_signature" => swap_matched = true,
                        "tp_layout_magic" => tp_magic_matched = true,
                        "tp_metadata_string" => tp_metadata_matched = true,
                        "sys_bin_sqlite" => sqlite_matched = true,
                        _ => {}
                    }

                    evidence_items.push(EvidenceItem::new(
                        forensic_core::EvidenceId::new(),
                        &sig.name,
                        pos as u64,
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
                }
            }
        }

        // 3. Determine Detection Status based on independent indicators
        // Confirmed = requires exclusive TP-Link indicators + supporting structures
        // Ambiguous = missing strong metadata but has layout or SQLite
        // Insufficient = only EXT4/SWAP (which are generic)

        let status = if tp_metadata_matched && tp_magic_matched && sqlite_matched && ext4_matched {
            DetectionStatus::Confirmed
        } else if tp_metadata_matched || tp_magic_matched || sqlite_matched {
            if !tp_metadata_matched {
                warnings
                    .push("TP-Link metadata string missing, but other indicators present".into());
            }
            DetectionStatus::Ambiguous
        } else if ext4_matched || swap_matched {
            // Found EXT4 or SWAP but no TP-Link specific signatures.
            DetectionStatus::Insufficient
        } else {
            DetectionStatus::NotDetected
        };

        Ok(DetectorOutput::new(
            "tplink",
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
    use forensic_core::OemProfile;

    // Helper for testing
    struct MockReader {
        data: Vec<u8>,
    }

    impl EvidenceReader for MockReader {
        fn len(&self) -> u64 {
            self.data.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
            if offset >= self.len() {
                return Err(ForensicError::out_of_bounds(
                    "test",
                    offset,
                    buf.len() as u64,
                    self.len(),
                ));
            }
            let start = offset as usize;
            let n = (self.data.len() - start).min(buf.len());
            buf[..n].copy_from_slice(&self.data[start..start + n]);
            Ok(n)
        }
        fn source_kind(&self) -> evidence_reader::SourceKind {
            evidence_reader::SourceKind::Raw
        }
        fn source_path(&self) -> &str {
            "mock://tplink"
        }
    }

    #[test]
    fn tplink_detector_not_detected_on_empty() {
        let profile = OemProfile::from_toml_str(
            r#"
profile_id = "tplink-1"
profile_version = "1.0"
schema_version = "1.0"
oem = "tplink"
storage_family = "TPLINK_VIGI"
[applicability]
[[signatures]]
name = "tp_layout_magic"
pattern_hex = "54 50"
evidence_status = "provisional"
weight = 0.8
is_exclusive = true
[confidence_weights]
max_possible_score = 1.0
"#,
        )
        .unwrap();

        let detector = TplinkDetector;
        let reader = MockReader {
            data: vec![0; 1024],
        };
        let output = detector.detect(&reader, &profile).unwrap();
        assert_eq!(output.status, DetectionStatus::NotDetected);
    }
}
