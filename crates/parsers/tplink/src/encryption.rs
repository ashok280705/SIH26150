//! # Encryption Reporting
//!
//! Reports encryption status for TP-Link evidence.

use crate::types::EncryptionStatus;

pub struct EncryptionReporter;

impl EncryptionReporter {
    pub fn check_status() -> EncryptionStatus {
        // Until evidence proves otherwise, encryption status is unknown.
        EncryptionStatus::Unknown
    }
}
