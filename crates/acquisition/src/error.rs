//! # Physical Acquisition Error Definitions

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AcquisitionError {
    #[error("Failed to open source device '{path}': {message} (OS code: {os_error:?})")]
    SourceOpenFailed {
        path: String,
        os_error: Option<i32>,
        message: String,
    },

    #[error("Source access denied for '{path}': elevation (Administrator) is required to acquire physical drives")]
    SourceAccessDenied {
        path: String,
        message: String,
    },

    #[error("Failed to read from source at offset {offset} (length {len}): {message} (OS code: {os_error:?})")]
    SourceReadFailed {
        offset: u64,
        len: usize,
        os_error: Option<i32>,
        message: String,
    },

    #[error("Physical source device disconnected or disappeared during acquisition at offset {offset}: {message}")]
    SourceDisconnected {
        offset: u64,
        message: String,
    },

    #[error("Destination file already exists: '{path}'")]
    DestinationExists {
        path: String,
    },

    #[error("FATAL SAFETY VIOLATION: Destination path resides on the source physical disk (Drive #{destination_drive})! Acquisition aborted to protect source evidence.")]
    DestinationCollisionWithSource {
        source_drive: u32,
        destination_drive: u32,
    },

    #[error("Insufficient destination disk space: required {required} bytes, available {available} bytes")]
    InsufficientDiskSpace {
        required: u64,
        available: u64,
    },

    #[error("Destination write failed for '{path}': {message}")]
    DestinationWriteFailed {
        path: String,
        message: String,
    },

    #[error("Cryptographic verification failed for {algorithm}: Pass-1 write hash ({pass1_hash}) does not match Pass-2 disk hash ({pass2_hash})! Forensic image integrity compromised.")]
    VerificationFailed {
        algorithm: String,
        pass1_hash: String,
        pass2_hash: String,
    },

    #[error("Physical acquisition was cancelled by examiner")]
    Cancelled,

    #[error("Safety assessment rejected acquisition: {reasons:?}")]
    SafetyCheckFailed {
        reasons: Vec<String>,
    },

    #[error("Invalid drive geometry: {message}")]
    InvalidGeometry {
        message: String,
    },

    #[error("Acquisition manifest error: {message}")]
    ManifestError {
        message: String,
    },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
