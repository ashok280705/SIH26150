//! # Phase 2 Detection Test Suite
//!
//! Enforces Release Gates and Correctness Properties 5, 6, 7 for storage detection (Req 2.1–2.8, 9.1–9.6, 10.1–10.11, 20.4, 25.1–25.4):
//! - Property 5: Evidence independence across detectors
//! - Property 6: Margin-respecting classification (ambiguity preserved, no forced winner)
//! - Property 7: Attribution honesty (confirmed requires exclusive evidence; UBS yields compatible_candidate)
//! - Lone magic is `Insufficient`, never `Unknown` or `Confirmed`
//! - Non-512 sector size topology handling without panic

use std::fs;
use std::path::Path;

use confidence::{AttributionStatus, Classification, ConfidenceConfig, ConfidenceEngine};
use detection::output::DetectionStatus;
use detection::topology::StorageTopologyProfiler;
use detection::DetectionOrchestrator;
use evidence_reader::{EvidenceReader, RawReader};
use forensic_core::{
    EvidenceId, EvidenceItem, EvidenceStatus, Hash, ProfileRegistry, RuleMatchStatus,
};
use forensic_tests::fixtures::{generate_fixture, FixtureShape, OemShape};

/// Property 5: Evidence independence across all 5 parallel detectors.
#[test]
fn property_5_evidence_independence_across_detectors() {
    let registry = ProfileRegistry::load_from_dir(Path::new("profiles")).unwrap();
    let orchestrator = DetectionOrchestrator::new();

    let fixture = generate_fixture(OemShape::Dahua, FixtureShape::Normal, 100);
    let temp_dir = std::env::temp_dir().join(format!("p2_prop5_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();
    let path = temp_dir.join("dahua.raw");
    fs::write(&path, &fixture.bytes).unwrap();

    let reader = RawReader::open(&path).unwrap();

    // Run orchestrator
    let outputs = orchestrator.run(&reader, &registry).unwrap();
    assert_eq!(outputs.len(), 6); // Dahua, Hikvision, Honeywell, CP Plus, Uniview, TP-Link

    // Dahua detector should see confirmed indicators; others should not falsely trigger
    let dahua_out = outputs.iter().find(|o| o.oem_key == "dahua").unwrap();
    assert_eq!(dahua_out.status, DetectionStatus::Confirmed);

    let hik_out = outputs.iter().find(|o| o.oem_key == "hikvision").unwrap();
    assert_ne!(hik_out.status, DetectionStatus::Confirmed);

    let _ = fs::remove_dir_all(&temp_dir);
}

/// Property 6: Margin-respecting classification (ambiguity never collapsed to winner).
#[test]
fn property_6_margin_respecting_ambiguity_preserved() {
    let registry = ProfileRegistry::load_from_dir(Path::new("profiles")).unwrap();
    let config = ConfidenceConfig::provisional_default();

    // Create 2 outputs with close scores (< min_margin 0.20)
    let out1 = detection::DetectorOutput::new(
        "dahua",
        "DHFS",
        DetectionStatus::Confirmed,
        vec![EvidenceItem::new(
            EvidenceId::new(),
            "sig",
            0,
            4,
            b"DHFS",
            b"DHFS",
            RuleMatchStatus::Match,
            EvidenceStatus::Validated,
            0.85,
            true,
            "match",
            "1.0",
            Hash::sha256(vec![0; 32]),
        )],
        vec![],
        vec![],
        "1.0",
        Hash::sha256(vec![0; 32]),
    );

    let out2 = detection::DetectorOutput::new(
        "hikvision",
        "HIKVISION_FS",
        DetectionStatus::Confirmed,
        vec![EvidenceItem::new(
            EvidenceId::new(),
            "hikvision_boot_identifier",
            528,
            18,
            b"HIKVISION@HANGZHOU",
            b"HIKVISION@HANGZHOU",
            RuleMatchStatus::Match,
            EvidenceStatus::Validated,
            0.80, // Very close score! (diff = 0.05 < 0.20 margin)
            true,
            "match",
            "1.0",
            Hash::sha256(vec![0; 32]),
        )],
        vec![],
        vec![],
        "1.0",
        Hash::sha256(vec![0; 32]),
    );

    let classified = ConfidenceEngine::classify(&[out1, out2], &registry, &config).unwrap();
    assert_eq!(classified.classification, Classification::Ambiguous);
    assert_eq!(classified.attribution_status, AttributionStatus::Unknown);
}

/// Property 7: Attribution honesty (UBS storage alone yields CompatibleCandidate, never Confirmed).
#[test]
fn property_7_ubs_storage_without_branding_yields_compatible_candidate() {
    let registry = ProfileRegistry::load_from_dir(Path::new("profiles")).unwrap();
    let config = ConfidenceConfig::provisional_default();

    let ubs_output = detection::DetectorOutput::new(
        "cpplus_ubs",
        "CPPLUS_UBS",
        DetectionStatus::Confirmed,
        vec![
            EvidenceItem::new(
                EvidenceId::new(),
                "ubs_partition_marker",
                0,
                4,
                b"UBS_",
                b"UBS_",
                RuleMatchStatus::Match,
                EvidenceStatus::Validated,
                0.70,
                false, // Non-exclusive! (Req 2.4)
                "UBS marker found",
                "1.0",
                Hash::sha256(vec![0; 32]),
            ),
            EvidenceItem::new(
                EvidenceId::new(),
                "ubs_descriptor_table",
                512,
                4,
                b"DESC",
                b"DESC",
                RuleMatchStatus::Match,
                EvidenceStatus::Validated,
                0.40,
                false, // Non-exclusive
                "Descriptor table matched",
                "1.0",
                Hash::sha256(vec![0; 32]),
            ),
        ],
        vec![],
        vec![],
        "1.0",
        Hash::sha256(vec![0; 32]),
    );

    let classified = ConfidenceEngine::classify(&[ubs_output], &registry, &config).unwrap();
    assert_eq!(
        classified.classification,
        Classification::CompatibleCandidate
    );
    assert_eq!(
        classified.attribution_status,
        AttributionStatus::CompatibleCandidate
    );
    assert_ne!(classified.attribution_status, AttributionStatus::Confirmed);
}

/// Adversarial: Lone magic without corroboration yields Insufficient (preempting threshold).
#[test]
fn adversarial_lone_magic_yields_insufficient() {
    let registry = ProfileRegistry::load_from_dir(Path::new("profiles")).unwrap();
    let config = ConfidenceConfig::provisional_default();

    let lone_magic_output = detection::DetectorOutput::new(
        "dahua",
        "DHFS",
        DetectionStatus::Insufficient, // Lone magic detected
        vec![EvidenceItem::new(
            EvidenceId::new(),
            "dhfs_magic",
            0,
            4,
            b"DHFS",
            b"DHFS",
            RuleMatchStatus::Match,
            EvidenceStatus::Validated,
            0.85,
            true,
            "lone magic",
            "1.0",
            Hash::sha256(vec![0; 32]),
        )],
        vec![],
        vec!["lone magic without corroboration".into()],
        "1.0",
        Hash::sha256(vec![0; 32]),
    );

    let classified = ConfidenceEngine::classify(&[lone_magic_output], &registry, &config).unwrap();
    assert_eq!(classified.classification, Classification::Insufficient);
    assert_eq!(classified.attribution_status, AttributionStatus::Unknown);
}

/// Adversarial: Non-512 sector size topology handling without panic.
#[test]
fn adversarial_non_512_sector_size_topology() {
    struct Non512Reader {
        data: Vec<u8>,
    }
    impl EvidenceReader for Non512Reader {
        fn len(&self) -> u64 {
            self.data.len() as u64
        }
        fn read_at(
            &self,
            offset: u64,
            buf: &mut [u8],
        ) -> Result<usize, forensic_core::ForensicError> {
            if offset >= self.len() {
                return Err(forensic_core::ForensicError::out_of_bounds(
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
            "mock://4k_sector"
        }
    }

    let reader = Non512Reader {
        data: vec![0x00; 16384],
    };
    // Sector size 4096 (Advanced Format 4Kn)
    let topo = StorageTopologyProfiler::profile(&reader, Some(4096)).unwrap();
    assert_eq!(topo.sector_size, 4096);
}
