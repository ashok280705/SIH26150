//! # Recording Index Analysis
//!
//! Parses event and GOP metadata from the SQLite sys.bin DB.

use forensic_core::ForensicError;
use crate::types::RecordingEvent;

pub struct RecordingIndexParser;

impl RecordingIndexParser {
    pub fn parse_events() -> Result<Vec<RecordingEvent>, ForensicError> {
        // TODO: Implement parsing from SQLite Reader
        Ok(Vec::new())
    }
}
