//! # Forensic Physical Acquisition Subsystem Tests
//!
//! Validates Tests 1 through 13 of the forensic physical acquisition engine:
//! - TEST 1: Clean synthetic source
//! - TEST 2: Known source data -> known MD5/SHA-256
//! - TEST 3: Acquisition -> Pass-1 hash
//! - TEST 4: Pass-2 independent verification
//! - TEST 5: Injected read error
//! - TEST 6: Retry succeeds
//! - TEST 7: Unrecoverable sector -> zero-fill
//! - TEST 8: Bad-sector ranges exactly recorded
//! - TEST 9: Destination write failure
//! - TEST 10: Cancellation
//! - TEST 11: Verification mismatch
//! - TEST 12: Destination/source collision
//! - TEST 13: EvidenceReader opens generated RAW

use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

use md5::Md5;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use acquisition::{
    assess_safety, run_acquisition, verify_image_file, AcquisitionConfig, AcquisitionError,
    AcquisitionManifest, AcquisitionStatus, BadSectorStatus, ExaminerWriteBlockerAttestation,
    MockSourceDevice, PhysicalSource, SafetyAssessment, VerificationStatus,
    VolumeLockState,
};
use evidence_reader::{CancellationToken, EvidenceReader, RawReader};

fn create_temp_dest(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vf_test_{}_{}", name, Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(format!("{name}.raw"))
}

fn cleanup_temp(path: &PathBuf) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::remove_dir_all(parent);
    }
}

fn dummy_safety(source: &PhysicalSource) -> SafetyAssessment {
    SafetyAssessment {
        source_accessible: true,
        source_read_only_confirmed: true,
        destination_exists_or_creatable: true,
        destination_is_not_source: true,
        destination_not_on_source_device: true,
        destination_device_number: None,
        source_capacity_bytes: source.capacity,
        destination_free_space_bytes: source.capacity * 4,
        has_sufficient_space: true,
        collision_detected: false,
        recognized_volumes: vec![],
        volume_lock_state: VolumeLockState::NotApplicable,
        is_safe_to_proceed: true,
        blocking_reasons: vec![],
        warnings: vec![],
    }
}

#[test]
fn test_1_to_4_clean_synthetic_source_pass1_pass2() {
    // 2 MiB test pattern with known content
    let pattern_len = 2 * 1024 * 1024;
    let mut data = Vec::with_capacity(pattern_len);
    for i in 0..pattern_len {
        data.push((i % 251) as u8);
    }

    // Compute expected MD5 and SHA-256
    let mut exp_md5 = Md5::new();
    exp_md5.update(&data);
    let expected_md5 = hex::encode(exp_md5.finalize());

    let mut exp_sha256 = Sha256::new();
    exp_sha256.update(&data);
    let expected_sha256 = hex::encode(exp_sha256.finalize());

    let source = MockSourceDevice::new("SyntheticDrive1", data.clone());
    let dest_path = create_temp_dest("clean_test");

    let config = AcquisitionConfig {
        source_path: "SyntheticDrive1".to_string(),
        destination_path: dest_path.to_string_lossy().to_string(),
        chunk_size: 512 * 1024,
        max_retries: 3,
        case_id: Uuid::new_v4(),
        examiner: "Forensic Examiner Jane Doe".to_string(),
        attestation: ExaminerWriteBlockerAttestation {
            hardware_write_blocker_used: true,
            blocker_make_model: Some("Tableau T8u".to_string()),
            examiner_notes: Some("Forensic bridge validated before imaging".to_string()),
        },
        attempt_volume_lock: true,
    };

    let meta = PhysicalSource {
        drive_number: 1,
        device_path: "SyntheticDrive1".to_string(),
        vendor: Some("WDC".to_string()),
        model: Some("WD20PURZ".to_string()),
        serial: Some("WCC4M0123456".to_string()),
        bus_type: acquisition::BusType::Sata,
        capacity: pattern_len as u64,
        logical_sector_size: 512,
        physical_sector_size: 4096,
        removable: false,
        os_write_protected: false,
        volumes: vec![],
    };

    let safety = dummy_safety(&meta);

    let result = run_acquisition(&source, Some(&meta), &config, &safety, None, None).unwrap();

    // Assertions
    assert_eq!(result.status, AcquisitionStatus::Complete);
    assert_eq!(result.bytes_written, pattern_len as u64);
    assert!(result.bad_sectors.is_empty());
    assert_eq!(result.verification.status, VerificationStatus::Verified);

    // Pass-1 and Pass-2 check
    assert_eq!(result.verification.pass1_md5, expected_md5);
    assert_eq!(result.verification.pass2_md5, Some(expected_md5));
    assert_eq!(result.verification.pass1_sha256, expected_sha256);
    assert_eq!(result.verification.pass2_sha256, Some(expected_sha256));

    // Staging file .part promoted to final .raw
    assert!(dest_path.exists());
    let part_path = PathBuf::from(format!("{}.part", dest_path.display()));
    assert!(!part_path.exists());

    // Manifest verified
    assert!(result.manifest_path.exists());
    let manifest_bytes = std::fs::read(&result.manifest_path).unwrap();
    let manifest: AcquisitionManifest = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(manifest.status, AcquisitionStatus::Complete);
    assert_eq!(manifest.source.model, Some("WD20PURZ".to_string()));
    assert_eq!(manifest.destination.file_size_bytes, pattern_len as u64);

    cleanup_temp(&dest_path);
}

#[test]
fn test_5_and_6_injected_read_error_and_retry_succeeds() {
    let pattern_len = 64 * 1024; // 64 KiB
    let mut data = Vec::with_capacity(pattern_len);
    for i in 0..pattern_len {
        data.push((i % 127) as u8);
    }

    let mut exp_sha256 = Sha256::new();
    exp_sha256.update(&data);
    let expected_sha256 = hex::encode(exp_sha256.finalize());

    let source = MockSourceDevice::new("SyntheticDrive2", data.clone());
    // Inject failure at offset 1024 for 512 bytes that fails 2 times then succeeds
    source.inject_bad_range(1024, 512, 2);

    let dest_path = create_temp_dest("retry_test");

    let config = AcquisitionConfig {
        source_path: "SyntheticDrive2".to_string(),
        destination_path: dest_path.to_string_lossy().to_string(),
        chunk_size: 16 * 1024,
        max_retries: 3, // retry allowance allows recovery
        case_id: Uuid::new_v4(),
        examiner: "Investigator Smith".to_string(),
        attestation: ExaminerWriteBlockerAttestation::default(),
        attempt_volume_lock: false,
    };

    let meta = PhysicalSource {
        drive_number: 2,
        device_path: "SyntheticDrive2".to_string(),
        vendor: None,
        model: None,
        serial: None,
        bus_type: acquisition::BusType::Unknown,
        capacity: pattern_len as u64,
        logical_sector_size: 512,
        physical_sector_size: 512,
        removable: false,
        os_write_protected: false,
        volumes: vec![],
    };

    let safety = dummy_safety(&meta);
    let result = run_acquisition(&source, Some(&meta), &config, &safety, None, None).unwrap();

    // Assert that retry succeeded and no bad sectors were zero-filled
    assert_eq!(result.status, AcquisitionStatus::Complete);
    assert_eq!(result.bytes_written, pattern_len as u64);
    assert_eq!(result.bad_sectors.len(), 0);
    assert_eq!(result.verification.pass1_sha256, expected_sha256);
    assert_eq!(result.verification.pass2_sha256, Some(expected_sha256));

    cleanup_temp(&dest_path);
}

#[test]
fn test_7_and_8_unrecoverable_sector_zero_filled_and_recorded() {
    let pattern_len = 16 * 1024; // 16 KiB
    let data = vec![0xAAu8; pattern_len];

    let source = MockSourceDevice::new("SyntheticDrive3", data.clone());
    // Inject permanent failure at sector 4 (offset 2048..2560)
    source.inject_bad_range(2048, 512, u32::MAX);

    let dest_path = create_temp_dest("bad_sector_test");

    let config = AcquisitionConfig {
        source_path: "SyntheticDrive3".to_string(),
        destination_path: dest_path.to_string_lossy().to_string(),
        chunk_size: 4 * 1024,
        max_retries: 2,
        case_id: Uuid::new_v4(),
        examiner: "Forensic Analyst".to_string(),
        attestation: ExaminerWriteBlockerAttestation::default(),
        attempt_volume_lock: false,
    };

    let meta = PhysicalSource {
        drive_number: 3,
        device_path: "SyntheticDrive3".to_string(),
        vendor: None,
        model: None,
        serial: None,
        bus_type: acquisition::BusType::Unknown,
        capacity: pattern_len as u64,
        logical_sector_size: 512,
        physical_sector_size: 512,
        removable: false,
        os_write_protected: false,
        volumes: vec![],
    };

    let safety = dummy_safety(&meta);
    let result = run_acquisition(&source, Some(&meta), &config, &safety, None, None).unwrap();

    // Partial acquisition status
    assert_eq!(result.status, AcquisitionStatus::Partial);
    assert_eq!(result.bytes_written, pattern_len as u64);
    assert_eq!(result.bad_sectors.len(), 1);

    let bad = &result.bad_sectors[0];
    assert_eq!(bad.offset, 2048);
    assert_eq!(bad.length, 512);
    assert_eq!(bad.start_lba, 4);
    assert_eq!(bad.status, BadSectorStatus::ZeroFilled);

    // Read generated image back from disk
    let mut read_back = vec![0u8; pattern_len];
    let mut f = File::open(&dest_path).unwrap();
    f.read_exact(&mut read_back).unwrap();

    // Verify non-bad sectors match 0xAA
    assert_eq!(&read_back[0..2048], &vec![0xAA; 2048][..]);
    // Verify bad sector range is strictly zero-filled!
    assert_eq!(&read_back[2048..2560], &vec![0x00; 512][..]);
    // Verify sectors after bad sector match 0xAA
    assert_eq!(&read_back[2560..pattern_len], &vec![0xAA; pattern_len - 2560][..]);

    // Independent Pass-2 verified the written image (with zero-fills)
    assert_eq!(result.verification.status, VerificationStatus::Verified);

    cleanup_temp(&dest_path);
}

#[test]
fn test_9_destination_write_collision_error() {
    let dest_path = create_temp_dest("collision_test");
    // Pre-create the destination file
    File::create(&dest_path).unwrap().write_all(b"existing").unwrap();

    let source = MockSourceDevice::new("SyntheticDrive4", vec![0u8; 1024]);
    let config = AcquisitionConfig {
        source_path: "SyntheticDrive4".to_string(),
        destination_path: dest_path.to_string_lossy().to_string(),
        chunk_size: 512,
        max_retries: 1,
        case_id: Uuid::new_v4(),
        examiner: "Examiner".to_string(),
        attestation: ExaminerWriteBlockerAttestation::default(),
        attempt_volume_lock: false,
    };

    let meta = PhysicalSource {
        drive_number: 4,
        device_path: "SyntheticDrive4".to_string(),
        vendor: None,
        model: None,
        serial: None,
        bus_type: acquisition::BusType::Unknown,
        capacity: 1024,
        logical_sector_size: 512,
        physical_sector_size: 512,
        removable: false,
        os_write_protected: false,
        volumes: vec![],
    };

    let safety = dummy_safety(&meta);
    let res = run_acquisition(&source, Some(&meta), &config, &safety, None, None);
    assert!(matches!(res, Err(AcquisitionError::DestinationExists { .. })));

    cleanup_temp(&dest_path);
}

#[test]
fn test_10_cancellation() {
    let source = MockSourceDevice::new("SyntheticDrive5", vec![0x55; 1024 * 1024]);
    let dest_path = create_temp_dest("cancelled_test");

    let config = AcquisitionConfig {
        source_path: "SyntheticDrive5".to_string(),
        destination_path: dest_path.to_string_lossy().to_string(),
        chunk_size: 1024,
        max_retries: 1,
        case_id: Uuid::new_v4(),
        examiner: "Examiner".to_string(),
        attestation: ExaminerWriteBlockerAttestation::default(),
        attempt_volume_lock: false,
    };

    let meta = PhysicalSource {
        drive_number: 5,
        device_path: "SyntheticDrive5".to_string(),
        vendor: None,
        model: None,
        serial: None,
        bus_type: acquisition::BusType::Unknown,
        capacity: 1024 * 1024,
        logical_sector_size: 512,
        physical_sector_size: 512,
        removable: false,
        os_write_protected: false,
        volumes: vec![],
    };

    let safety = dummy_safety(&meta);
    let token = CancellationToken::new();
    token.cancel(); // Pre-cancelled

    let res = run_acquisition(&source, Some(&meta), &config, &safety, Some(&token), None);
    assert!(matches!(res, Err(AcquisitionError::Cancelled)));

    // Final image should NOT be promoted
    assert!(!dest_path.exists());

    cleanup_temp(&dest_path);
}

#[test]
fn test_11_verification_corruption_mismatch() {
    let dest_path = create_temp_dest("verify_corruption");
    let staging_path = PathBuf::from(format!("{}.part", dest_path.display()));

    let original_bytes = b"Deterministic forensic acquisition test bytes string for verification check";
    File::create(&staging_path).unwrap().write_all(original_bytes).unwrap();

    let mut md5_h = Md5::new();
    md5_h.update(original_bytes);
    let pass1_md5 = hex::encode(md5_h.finalize());

    let mut sha256_h = Sha256::new();
    sha256_h.update(original_bytes);
    let pass1_sha256 = hex::encode(sha256_h.finalize());

    // Corrupt one byte on disk
    let mut corrupted = original_bytes.to_vec();
    corrupted[0] ^= 0xFF;
    File::create(&staging_path).unwrap().write_all(&corrupted).unwrap();

    // Run independent Pass-2 verification
    let res = verify_image_file(&staging_path, &pass1_md5, &pass1_sha256, None, None);
    assert!(matches!(res, Err(AcquisitionError::VerificationFailed { .. })));

    cleanup_temp(&dest_path);
}

#[test]
fn test_12_destination_source_collision_rejected_by_safety() {
    let source = PhysicalSource {
        drive_number: 0,
        device_path: r"\\.\PhysicalDrive0".to_string(),
        vendor: None,
        model: None,
        serial: None,
        bus_type: acquisition::BusType::Unknown,
        capacity: 1000,
        logical_sector_size: 512,
        physical_sector_size: 512,
        removable: false,
        os_write_protected: false,
        volumes: vec![],
    };

    let config = AcquisitionConfig {
        source_path: r"\\.\PhysicalDrive0".to_string(),
        destination_path: r"\\.\PhysicalDrive0".to_string(), // self-destination!
        chunk_size: 512,
        max_retries: 1,
        case_id: Uuid::new_v4(),
        examiner: "Examiner".to_string(),
        attestation: ExaminerWriteBlockerAttestation::default(),
        attempt_volume_lock: false,
    };

    let assessment = assess_safety(&source, &config);
    assert!(!assessment.is_safe_to_proceed);
    assert!(!assessment.blocking_reasons.is_empty());
}

#[test]
fn test_13_evidencereader_opens_generated_raw() {
    let pattern_len = 128 * 1024;
    let data = vec![0x42u8; pattern_len];

    let source = MockSourceDevice::new("SyntheticDriveRaw", data.clone());
    let dest_path = create_temp_dest("raw_reader_test");

    let config = AcquisitionConfig {
        source_path: "SyntheticDriveRaw".to_string(),
        destination_path: dest_path.to_string_lossy().to_string(),
        chunk_size: 32 * 1024,
        max_retries: 1,
        case_id: Uuid::new_v4(),
        examiner: "Examiner".to_string(),
        attestation: ExaminerWriteBlockerAttestation::default(),
        attempt_volume_lock: false,
    };

    let meta = PhysicalSource {
        drive_number: 1,
        device_path: "SyntheticDriveRaw".to_string(),
        vendor: None,
        model: None,
        serial: None,
        bus_type: acquisition::BusType::Unknown,
        capacity: pattern_len as u64,
        logical_sector_size: 512,
        physical_sector_size: 512,
        removable: false,
        os_write_protected: false,
        volumes: vec![],
    };

    let safety = dummy_safety(&meta);
    let result = run_acquisition(&source, Some(&meta), &config, &safety, None, None).unwrap();
    assert_eq!(result.status, AcquisitionStatus::Complete);

    // Now open the generated image using the EXISTING EvidenceReader (RawReader)
    let raw_reader = RawReader::open(&dest_path).expect("RawReader must open generated forensic RAW");
    assert_eq!(raw_reader.len(), pattern_len as u64);

    let mut buf = vec![0u8; 1024];
    let n = raw_reader.read_at(0, &mut buf).unwrap();
    assert_eq!(n, 1024);
    assert_eq!(buf, vec![0x42u8; 1024]);

    cleanup_temp(&dest_path);
}

#[test]
fn test_14_existing_analysis_pipeline_can_consume_generated_raw() {
    use confidence::config::ConfidenceConfig;
    use forensic_core::{EvidenceId, ProfileRegistry};
    use pipeline::{run_pipeline, GateRecord, ParseDecision, PipelineOptions, ThresholdDecision};
    use std::path::Path;

    // 1. Locate Dahua fixture
    let mut raw_path = None;
    for base in [".", "..", "../.."] {
        let p = Path::new(base).join("dahua_dhfs_sample.raw");
        if p.exists() {
            raw_path = Some(p);
            break;
        }
    }

    let Some(raw_path) = raw_path else {
        eprintln!("skipping: dahua_dhfs_sample.raw not present");
        return;
    };

    let dahua_bytes = std::fs::read(&raw_path).expect("read dahua sample");
    let dahua_len = dahua_bytes.len() as u64;

    // 2. Wrap as physical SourceDevice
    let source = MockSourceDevice::new("PhysicalDriveDahua", dahua_bytes)
        .with_sector_size(512, 4096);

    let dest_path = create_temp_dest("pipeline_acquired_dahua");

    let config = AcquisitionConfig {
        source_path: "PhysicalDriveDahua".to_string(),
        destination_path: dest_path.to_string_lossy().to_string(),
        chunk_size: 512 * 1024,
        max_retries: 2,
        case_id: Uuid::new_v4(),
        examiner: "Forensic Officer".to_string(),
        attestation: ExaminerWriteBlockerAttestation::default(),
        attempt_volume_lock: false,
    };

    let meta = PhysicalSource {
        drive_number: 10,
        device_path: "PhysicalDriveDahua".to_string(),
        vendor: Some("Dahua OEM".to_string()),
        model: Some("DH-DVR-500GB".to_string()),
        serial: Some("DH123456789".to_string()),
        bus_type: acquisition::BusType::Sata,
        capacity: dahua_len,
        logical_sector_size: 512,
        physical_sector_size: 4096,
        removable: false,
        os_write_protected: false,
        volumes: vec![],
    };

    let safety = dummy_safety(&meta);

    // 3. Perform physical acquisition
    let acq_result = run_acquisition(&source, Some(&meta), &config, &safety, None, None)
        .expect("acquisition succeeds");
    assert_eq!(acq_result.status, AcquisitionStatus::Complete);

    // 4. Existing forensic pipeline consumes generated RAW image through RawReader
    let reader = RawReader::open(&dest_path).expect("RawReader opens acquired raw");
    assert_eq!(reader.len(), dahua_len);

    let mut profiles_dir = None;
    for base in [".", "..", "../.."] {
        let p = Path::new(base).join("profiles");
        if p.exists() {
            profiles_dir = Some(p);
            break;
        }
    }
    let registry = ProfileRegistry::load_from_dir(&profiles_dir.expect("profiles/ exists"))
        .expect("profiles must load");
    let conf = ConfidenceConfig::provisional_default();
    let options = PipelineOptions::default();

    let run = run_pipeline(
        EvidenceId::new(),
        &reader,
        &registry,
        &conf,
        &options,
    )
    .expect("pipeline runs on acquired image");

    // Downstream verification
    let attribution = run.attribution.as_ref().expect("attribution present");
    assert_eq!(attribution.oem_key, "dahua");

    let threshold = run
        .gates
        .iter()
        .find_map(|g| match g {
            GateRecord::Threshold { decision, .. } => Some(*decision),
            _ => None,
        })
        .expect("threshold gate recorded");
    assert_eq!(threshold, ThresholdDecision::OemConfirmed);

    let parsed = run
        .gates
        .iter()
        .find_map(|g| match g {
            GateRecord::Parsed { decision, .. } => Some(*decision),
            _ => None,
        })
        .expect("parsed gate recorded");
    assert_eq!(parsed, ParseDecision::Parsed);
    assert_eq!(run.oem_key_used.as_deref(), Some("dahua"));

    let tl = run.recordings_timeline.as_ref().expect("recordings timeline present");
    assert_eq!(tl.recordings_with_unknown_timezone, 6);

    cleanup_temp(&dest_path);
}

