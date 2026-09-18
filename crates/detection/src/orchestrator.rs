//! # Detection Orchestrator
//!
//! Executes multi-vendor detectors in parallel over read-only evidence, producing sorted, deterministic outputs (Req 6.2, 9.1, 9.2, 9.5, 20.4, 25.1).
//!
//! Key invariants:
//! - All five OEMs (Dahua, Hikvision, Honeywell, CP Plus/UBS, Uniview) run over the same read-only reader.
//! - Results are sorted deterministically by `oem_key` independent of thread execution order (Req 20.4).
//! - The Orchestrator emits `Vec<DetectorOutput>` with NO attribution (Attribution belongs exclusively to Confidence_Engine).

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, ProfileRegistry};

use crate::detector::Detector;
use crate::detectors::{CpPlusUbsDetector, DahuaDetector, HikvisionDetector, HoneywellDetector, UniviewDetector, TplinkDetector};
use crate::output::DetectorOutput;

pub struct DetectionOrchestrator {
    detectors: Vec<Box<dyn Detector>>,
}

impl Default for DetectionOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectionOrchestrator {
    /// Create an orchestrator with all five standard OEM detectors.
    pub fn new() -> Self {
        let detectors: Vec<Box<dyn Detector>> = vec![
            Box::new(DahuaDetector),
            Box::new(HikvisionDetector),
            Box::new(HoneywellDetector),
            Box::new(CpPlusUbsDetector),
            Box::new(UniviewDetector),
            Box::new(TplinkDetector),
        ];
        Self { detectors }
    }

    /// Run detection across all registered detectors in deterministic order.
    pub fn run(
        &self,
        reader: &dyn EvidenceReader,
        registry: &ProfileRegistry,
    ) -> Result<Vec<DetectorOutput>, ForensicError> {
        let mut outputs = Vec::new();

        for detector in &self.detectors {
            let oem = detector.oem_key();
            if let Some(profile) = registry.find_applicable(oem, None, None, None) {
                let output = detector.detect(reader, profile)?;
                outputs.push(output);
            }
        }

        // Deterministic sorting by oem_key (Req 20.4)
        outputs.sort_by(|a, b| a.oem_key.cmp(&b.oem_key));

        Ok(outputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_core::OemProfile;

    struct MockReader {
        data: Vec<u8>,
    }

    impl EvidenceReader for MockReader {
        fn len(&self) -> u64 { self.data.len() as u64 }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
            if offset >= self.len() {
                return Err(ForensicError::out_of_bounds("test", offset, buf.len() as u64, self.len()));
            }
            let start = offset as usize;
            let n = (self.data.len() - start).min(buf.len());
            buf[..n].copy_from_slice(&self.data[start..start + n]);
            Ok(n)
        }
        fn source_kind(&self) -> evidence_reader::SourceKind { evidence_reader::SourceKind::Raw }
        fn source_path(&self) -> &str { "mock://orchestrator" }
    }

    #[test]
    fn orchestrator_runs_and_sorts_outputs() {
        let dahua_profile = OemProfile::from_toml_str(r#"
profile_id = "dahua-1"
profile_version = "1.0"
schema_version = "1.0"
oem = "dahua"
storage_family = "DHFS"
[applicability]
[[signatures]]
name = "dhfs_magic"
pattern_hex = "44 48 46 53"
evidence_status = "validated"
weight = 0.8
[confidence_weights]
max_possible_score = 1.0
"#).unwrap();

        let hik_profile = OemProfile::from_toml_str(r#"
profile_id = "hik-1"
profile_version = "1.0"
schema_version = "1.0"
oem = "hikvision"
storage_family = "HIKVISION_FS"
[applicability]
[[signatures]]
name = "hik_magic"
pattern_hex = "48 49 4B 5F"
evidence_status = "validated"
weight = 0.8
[confidence_weights]
max_possible_score = 1.0
"#).unwrap();

        let registry = ProfileRegistry::from_profiles(vec![dahua_profile, hik_profile]);
        let reader = MockReader { data: b"DHFS\x00\x00\x00\x00".to_vec() };

        let orchestrator = DetectionOrchestrator::new();
        let outputs = orchestrator.run(&reader, &registry).unwrap();

        assert!(!outputs.is_empty());
        // Verify deterministic sorting: oem_key ascending
        for i in 1..outputs.len() {
            assert!(outputs[i-1].oem_key <= outputs[i].oem_key);
        }
    }
}

