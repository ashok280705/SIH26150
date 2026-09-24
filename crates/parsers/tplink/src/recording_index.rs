//! # Recording Index Analysis
//!
//! Parses event and GOP metadata from the SQLite sys.bin DB.

use crate::types::RecordingEvent;
use forensic_core::ForensicError;

pub struct RecordingIndexParser;

impl RecordingIndexParser {
    pub fn parse_events() -> Result<Vec<RecordingEvent>, ForensicError> {
        // TODO: Implement parsing from SQLite Reader
        Ok(Vec::new())
    }
}
