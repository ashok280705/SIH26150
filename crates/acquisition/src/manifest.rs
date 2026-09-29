//! # Forensic Acquisition Manifest
//!
//! Generates a standardized, deterministic JSON acquisition manifest accompanying
//! the finalized forensic image artifact (e.g. `<image>.raw.json`).

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AcquisitionError;
use crate::types::{
    AcquisitionConfig, AcquisitionStatus, BadSectorRange, ExaminerWriteBlockerAttestation,
    PhysicalSource, SafetyAssessment, VerificationRecord,
};

/// Comprehensive forensic acquisition manifest written adjacent to the RAW image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquisitionManifest {
    pub manifest_version: String,
    pub acquisition_id: Uuid,
    pub case_id: Uuid,
    pub examiner: String,
    pub vidforge_version: String,
    pub os_platform: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub elapsed_seconds: f64,
    pub status: AcquisitionStatus,
    pub source: SourceDeviceIdentity,
    pub destination: DestinationInfo,
    pub verification: VerificationRecord,
    pub safety_assessment: SafetyAssessmentSummary,
    pub attestation: ExaminerWriteBlockerAttestation,
    pub bad_sector_ranges: Vec<BadSectorRange>,
    pub total_bad_sectors: u64,
    pub total_zero_filled_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceDeviceIdentity {
    pub device_path: String,
    pub drive_number: u32,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub bus_type: String,
    pub capacity_bytes: u64,
    pub logical_sector_size: u32,
    pub physical_sector_size: u32,
    pub removable: bool,
    pub os_write_protected: bool,
    pub recognized_volume_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestinationInfo {
    pub raw_image_path: String,
    pub file_size_bytes: u64,
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyAssessmentSummary {
    pub destination_not_on_source_device: bool,
    pub volume_lock_state: String,
    pub source_read_only_confirmed: bool,
    pub sufficient_space_confirmed: bool,
}

impl AcquisitionManifest {
    /// Constructs a manifest from acquisition results.
    pub fn build(
        acquisition_id: Uuid,
        config: &AcquisitionConfig,
        source: &PhysicalSource,
        safety: &SafetyAssessment,
        verification: VerificationRecord,
        status: AcquisitionStatus,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        final_image_path: &Path,
        bytes_written: u64,
        bad_sectors: Vec<BadSectorRange>,
    ) -> Self {
        let elapsed_seconds = (end_time - start_time).num_milliseconds() as f64 / 1000.0;
        let total_bad_sectors = bad_sectors.iter().map(|b| b.sector_count).sum();
        let total_zero_filled_bytes = bad_sectors.iter().map(|b| b.length).sum();

        Self {
            manifest_version: "1.0.0".to_string(),
            acquisition_id,
            case_id: config.case_id,
            examiner: config.examiner.clone(),
            vidforge_version: env!("CARGO_PKG_VERSION").to_string(),
            os_platform: std::env::consts::OS.to_string(),
            start_time,
            end_time,
            elapsed_seconds,
            status,
            source: SourceDeviceIdentity {
                device_path: source.device_path.clone(),
                drive_number: source.drive_number,
                vendor: source.vendor.clone(),
                model: source.model.clone(),
                serial: source.serial.clone(),
                bus_type: source.bus_type.to_string(),
                capacity_bytes: source.capacity,
                logical_sector_size: source.logical_sector_size,
                physical_sector_size: source.physical_sector_size,
                removable: source.removable,
                os_write_protected: source.os_write_protected,
                recognized_volume_count: source.volumes.len(),
            },
            destination: DestinationInfo {
                raw_image_path: final_image_path.to_string_lossy().to_string(),
                file_size_bytes: bytes_written,
                format: "RAW (dd bitstream)".to_string(),
            },
            verification,
            safety_assessment: SafetyAssessmentSummary {
                destination_not_on_source_device: safety.destination_not_on_source_device,
                volume_lock_state: safety.volume_lock_state.to_string(),
                source_read_only_confirmed: safety.source_read_only_confirmed,
                sufficient_space_confirmed: safety.has_sufficient_space,
            },
            attestation: config.attestation.clone(),
            bad_sector_ranges: bad_sectors,
            total_bad_sectors,
            total_zero_filled_bytes,
        }
    }

    /// Write manifest to disk adjacent to the RAW image (`<image_path>.json`).
    pub fn write_to_file(&self, final_image_path: &Path) -> Result<PathBuf, AcquisitionError> {
        let manifest_path = PathBuf::from(format!("{}.json", final_image_path.display()));
        let json = serde_json::to_string_pretty(self).map_err(|e| AcquisitionError::ManifestError {
            message: format!("Failed to serialize manifest to JSON: {e}"),
        })?;

        let mut file = File::create(&manifest_path).map_err(|e| AcquisitionError::ManifestError {
            message: format!("Failed to create manifest file '{}': {e}", manifest_path.display()),
        })?;

        file.write_all(json.as_bytes()).map_err(|e| AcquisitionError::ManifestError {
            message: format!("Failed to write manifest data to '{}': {e}", manifest_path.display()),
        })?;

        Ok(manifest_path)
    }
}
