//! # TP-Link Synthetic 2TB Dry-Run Test
//!
//! Simulates a 2TB TP-Link NVR HDD and verifies the detector architecture.

use forensic_core::{ProfileRegistry, OemProfile, ForensicError};
use evidence_reader::EvidenceReader;
use detection::orchestrator::DetectionOrchestrator;
use detection::output::DetectionStatus;

struct SyntheticTpLinkDisk {
    size: u64,
}

impl SyntheticTpLinkDisk {
    pub fn new_2tb() -> Self {
        Self {
            size: 2 * 1024 * 1024 * 1024 * 1024, // 2 TB
        }
    }
}

impl EvidenceReader for SyntheticTpLinkDisk {
    fn len(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
        if offset >= self.size {
            return Err(ForensicError::out_of_bounds("test", offset, buf.len() as u64, self.size));
        }
        
        let start = offset as usize;
        let mut bytes_written = 0;

        // Mock MBR (sector 0)
        if offset == 0 && buf.len() >= 512 {
            buf[510] = 0x55;
            buf[511] = 0xAA;
            
            // Partition 1: Linux Swap (0x82)
            buf[446 + 4] = 0x82;
            buf[446 + 8] = 1; // start sector
            buf[446 + 12] = 100; // num sectors
            
            // Partition 2: EXT4 Linux (0x83)
            buf[462 + 4] = 0x83;
            buf[462 + 8] = 101; // start sector
            buf[462 + 12] = 0xFF; // mock size
            
            bytes_written = 512.min(buf.len());
        }

        // Mock EXT4 Superblock
        if offset <= 51712 && offset + buf.len() as u64 > 51712 {
            let relative = (51712 - offset) as usize;
            if relative + 2 <= buf.len() {
                buf[relative] = 0x53;
                buf[relative + 1] = 0xEF;
                bytes_written = bytes_written.max(relative + 2);
            }
        }

        // Mock TP-Link Magic "TP" (0x5450)
        if offset <= 1048576 && offset + buf.len() as u64 > 1048576 {
            let relative = (1048576 - offset) as usize;
            if relative + 2 <= buf.len() {
                buf[relative] = 0x54;
                buf[relative + 1] = 0x50;
                bytes_written = bytes_written.max(relative + 2);
            }
        }

        // Mock TP-Link Metadata String
        let metadata = b"TP-Link Corporation Limited, NVR FOR VERSION";
        let meta_offset = 2000000;
        if offset <= meta_offset && offset + buf.len() as u64 > meta_offset {
            let relative = (meta_offset - offset) as usize;
            if relative + metadata.len() <= buf.len() {
                buf[relative..relative + metadata.len()].copy_from_slice(metadata);
                bytes_written = bytes_written.max(relative + metadata.len());
            }
        }

        // Mock SQLite header
        let sqlite = b"SQLite format 3\0";
        let sqlite_offset = 3000000;
        if offset <= sqlite_offset && offset + buf.len() as u64 > sqlite_offset {
            let relative = (sqlite_offset - offset) as usize;
            if relative + sqlite.len() <= buf.len() {
                buf[relative..relative + sqlite.len()].copy_from_slice(sqlite);
                bytes_written = bytes_written.max(relative + sqlite.len());
            }
        }

        // For this synthetic test, we pretend we read the whole buffer
        Ok(buf.len())
    }

    fn source_kind(&self) -> evidence_reader::SourceKind {
        evidence_reader::SourceKind::Raw
    }

    fn source_path(&self) -> &str {
        "mock://tplink_2tb"
    }
}

#[test]
fn test_synthetic_tplink_2tb_detection() {
    // 1. Create the mock profile
    let profile = OemProfile::from_toml_str(r#"
profile_id = "tplink-vigi-nvr-v1.0"
profile_version = "1.0.0"
schema_version = "1.0"
oem = "tplink"
storage_family = "TPLINK_VIGI_NVR"
[applicability]
[[signatures]]
name = "tp_layout_magic"
pattern_hex = "54 50"
evidence_status = "provisional"
weight = 0.70
is_exclusive = true
[[signatures.offset_constraints]]
type = "header_window"
max_offset = 10485760

[[signatures]]
name = "tp_metadata_string"
pattern_hex = "54502D4C696E6B20436F72706F726174696F6E204C696D69746564"
evidence_status = "provisional"
weight = 0.80
is_exclusive = true

[[signatures]]
name = "sys_bin_sqlite"
pattern_hex = "53514C69746520666F726D6174203300"
evidence_status = "provisional"
weight = 0.50
is_exclusive = false

[[signatures]]
name = "ext4_superblock"
pattern_hex = "53 EF"
evidence_status = "provisional"
weight = 0.15
is_exclusive = false

[confidence_weights]
max_possible_score = 2.25
min_threshold = 0.60
"#).unwrap();

    let registry = ProfileRegistry::from_profiles(vec![profile]);
    let disk = SyntheticTpLinkDisk::new_2tb();
    
    // 2. Run the detection orchestrator
    let orchestrator = DetectionOrchestrator::new();
    let outputs = orchestrator.run(&disk, &registry).unwrap();
    
    // 3. Verify TP-Link was detected
    let tplink_output = outputs.iter().find(|o| o.oem_key == "tplink").unwrap();
    
    // We expect Confirmed status because all indicators (TP magic, metadata, SQLite, EXT4) were mocked
    assert_eq!(tplink_output.status, DetectionStatus::Confirmed);
    assert!(tplink_output.evidence.len() >= 4, "Expected at least 4 evidence items");
    
    let has_tp_magic = tplink_output.evidence.iter().any(|e| e.kind == "tp_layout_magic");
    let has_tp_metadata = tplink_output.evidence.iter().any(|e| e.kind == "tp_metadata_string");
    
    assert!(has_tp_magic);
    assert!(has_tp_metadata);
}
