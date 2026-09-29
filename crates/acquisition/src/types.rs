//! # Physical Acquisition Domain Types
//!
//! Core data contracts for Windows forensic physical acquisition, safety inspection,
//! bad-sector recording, independent verification, and acquisition manifests.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Bus/interface type for a physical disk device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BusType {
    Sata,
    Nvme,
    Usb,
    Scsi,
    Atapi,
    Raid,
    Virtual,
    Unknown,
}

impl std::fmt::Display for BusType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sata => write!(f, "SATA"),
            Self::Nvme => write!(f, "NVMe"),
            Self::Usb => write!(f, "USB"),
            Self::Scsi => write!(f, "SCSI"),
            Self::Atapi => write!(f, "ATAPI"),
            Self::Raid => write!(f, "RAID"),
            Self::Virtual => write!(f, "Virtual"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Information about a Windows-recognized filesystem volume residing on a physical drive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeInfo {
    pub volume_path: String,
    pub drive_letter: Option<String>,
    pub label: Option<String>,
    pub filesystem: Option<String>,
    pub capacity: u64,
}

/// Metadata and geometry of an enumerated physical source block device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalSource {
    /// PhysicalDrive number (e.g. 0 for `\\.\PhysicalDrive0`)
    pub drive_number: u32,
    /// Full Win32 device path (e.g. `\\.\PhysicalDrive0`)
    pub device_path: String,
    /// Storage vendor string, if reported by device descriptor
    pub vendor: Option<String>,
    /// Storage product/model string
    pub model: Option<String>,
    /// Serial number string
    pub serial: Option<String>,
    /// Bus interface
    pub bus_type: BusType,
    /// Total capacity in bytes (from `IOCTL_DISK_GET_LENGTH_INFO`)
    pub capacity: u64,
    /// Logical sector size in bytes (typically 512 or 4096)
    pub logical_sector_size: u32,
    /// Physical sector size in bytes (e.g. 512 for 512n, 4096 for 512e/4Kn)
    pub physical_sector_size: u32,
    /// Whether the device is removable media (e.g. USB flash, memory card)
    pub removable: bool,
    /// Operating system write-protection flag (from `IOCTL_DISK_IS_WRITABLE`)
    pub os_write_protected: bool,
    /// Recognized Windows volumes on this device, if any
    pub volumes: Vec<VolumeInfo>,
}

/// State of volume locking for a physical source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeLockState {
    /// No Windows filesystem volumes were detected on the physical disk (e.g. raw DVR/NVR media).
    NotApplicable,
    /// All recognized volumes on the physical disk were successfully locked.
    Locked,
    /// Volumes were locked and dismounted.
    Dismounted,
    /// Locking failed for one or more recognized volumes.
    LockFailed(String),
    /// Locking was skipped by user configuration.
    Skipped,
}

impl std::fmt::Display for VolumeLockState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotApplicable => write!(f, "Not Applicable (No Windows Volumes)"),
            Self::Locked => write!(f, "Locked"),
            Self::Dismounted => write!(f, "Dismounted"),
            Self::LockFailed(msg) => write!(f, "Lock Failed: {msg}"),
            Self::Skipped => write!(f, "Skipped"),
        }
    }
}

/// Examiner hardware write blocker attestation.
///
/// NOTE: Software cannot prove that a physical hardware write blocker exists.
/// This structure records examiner attestation and notes, never "verified by software".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExaminerWriteBlockerAttestation {
    /// True if the forensic examiner attests that a hardware write blocker was physically connected.
    pub hardware_write_blocker_used: bool,
    /// Make and model of the hardware write blocker, if specified.
    pub blocker_make_model: Option<String>,
    /// Additional forensic notes entered by the examiner.
    pub examiner_notes: Option<String>,
}

impl Default for ExaminerWriteBlockerAttestation {
    fn default() -> Self {
        Self {
            hardware_write_blocker_used: false,
            blocker_make_model: None,
            examiner_notes: None,
        }
    }
}

/// Pre-acquisition safety assessment report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyAssessment {
    pub source_accessible: bool,
    pub source_read_only_confirmed: bool,
    pub destination_exists_or_creatable: bool,
    pub destination_is_not_source: bool,
    pub destination_not_on_source_device: bool,
    pub destination_device_number: Option<u32>,
    pub source_capacity_bytes: u64,
    pub destination_free_space_bytes: u64,
    pub has_sufficient_space: bool,
    pub collision_detected: bool,
    pub recognized_volumes: Vec<VolumeInfo>,
    pub volume_lock_state: VolumeLockState,
    pub is_safe_to_proceed: bool,
    pub blocking_reasons: Vec<String>,
    pub warnings: Vec<String>,
}

/// Status of a bad sector or range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BadSectorStatus {
    Readable,
    RetriedSuccessfully,
    Unreadable,
    ZeroFilled,
}

/// Detailed accounting of an unreadable or retried sector/range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BadSectorRange {
    /// Byte offset within the source device
    pub offset: u64,
    /// Length of the range in bytes
    pub length: u64,
    /// Starting Logical Block Address (LBA)
    pub start_lba: u64,
    /// Number of logical sectors in this range
    pub sector_count: u64,
    /// Resolution status
    pub status: BadSectorStatus,
    /// Win32 OS error code, if applicable
    pub win32_error: Option<u32>,
    /// Number of retries attempted before fallback/zero-filling
    pub retry_count: u32,
}

/// Status of independent cryptographic image verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Pending,
    Verified,
    FailedMismatch,
    Skipped,
}

/// Two-pass cryptographic verification record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationRecord {
    /// Pass-1 MD5 computed over bytes successfully written to disk.
    pub pass1_md5: String,
    /// Pass-1 SHA-256 computed over bytes successfully written to disk.
    pub pass1_sha256: String,
    /// Pass-2 MD5 computed by independent re-read of output image file from disk.
    pub pass2_md5: Option<String>,
    /// Pass-2 SHA-256 computed by independent re-read of output image file from disk.
    pub pass2_sha256: Option<String>,
    /// Verification outcome.
    pub status: VerificationStatus,
    /// Explanation of outcome.
    pub details: Option<String>,
    /// Timestamp when verification pass completed.
    pub verified_at: Option<DateTime<Utc>>,
}

/// High-level lifecycle state of an acquisition job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionStatus {
    NotStarted,
    SafetyCheck,
    Acquiring,
    Verifying,
    Finalizing,
    Complete,
    Partial,
    Failed,
    Cancelled,
}

/// Real-time progress metric reported during acquisition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquisitionProgress {
    pub bytes_processed: u64,
    pub total_bytes: u64,
    pub percentage: f64,
    pub throughput_bytes_per_sec: u64,
    pub elapsed_seconds: f64,
    pub eta_seconds: Option<u64>,
    pub bad_sector_count: u64,
    pub unreadable_bytes: u64,
    pub current_phase: String,
}

/// Configuration parameters for an acquisition run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquisitionConfig {
    pub source_path: String,
    pub destination_path: String,
    /// Bounded read chunk size (default: 1 MiB = 1,048,576 bytes)
    pub chunk_size: usize,
    /// Max retries per failing sector before deterministic zero-fill
    pub max_retries: u32,
    pub case_id: Uuid,
    pub examiner: String,
    pub attestation: ExaminerWriteBlockerAttestation,
    /// Whether to attempt locking Windows-recognized volumes if any exist
    pub attempt_volume_lock: bool,
}

impl Default for AcquisitionConfig {
    fn default() -> Self {
        Self {
            source_path: String::new(),
            destination_path: String::new(),
            chunk_size: 1024 * 1024, // 1 MiB bounded default
            max_retries: 3,
            case_id: Uuid::nil(),
            examiner: String::new(),
            attestation: ExaminerWriteBlockerAttestation::default(),
            attempt_volume_lock: true,
        }
    }
}

/// Final outcome of an acquisition job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquisitionResult {
    pub acquisition_id: Uuid,
    pub case_id: Uuid,
    pub status: AcquisitionStatus,
    pub image_path: std::path::PathBuf,
    pub manifest_path: std::path::PathBuf,
    pub bytes_written: u64,
    pub bad_sectors: Vec<BadSectorRange>,
    pub verification: VerificationRecord,
    pub elapsed_seconds: f64,
}
