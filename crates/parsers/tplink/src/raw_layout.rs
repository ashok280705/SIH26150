//! # TP-Link Raw Layout Parser
//!
//! Validates `rawDiskLayout` metadata.

use evidence_reader::EvidenceReader;
use forensic_core::ForensicError;

pub struct RawLayout;

impl RawLayout {
    pub fn validate(reader: &dyn EvidenceReader, offset: u64) -> Result<bool, ForensicError> {
        let mut buf = [0u8; 2];
        if reader.read_at(offset, &mut buf)? == 2 {
            // Check for "TP" magic
            Ok(&buf == b"TP")
        } else {
            Ok(false)
        }
    }
}
