//! # Recovery Analysis
//!
//! Multi-level recovery of recordings.

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, Recording};

pub struct RecoveryAnalyzer;

impl RecoveryAnalyzer {
    pub fn recover(_reader: &dyn EvidenceReader) -> Result<Vec<Recording>, ForensicError> {
        // TODO: Implement index-guided recovery, then physical zone, unallocated EXT4, carving.
        Ok(Vec::new())
    }
}
