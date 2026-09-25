//! # Recording Model
//!
//! Represents a unified forensic recording extracted by an OEM parser (Req 12.2, 12.4).
//!
//! A recording ties together a channel, time evidence, the structural byte offsets where
//! the video/audio data is located, and integrity flags indicating whether the parser
//! encountered profile-inconsistent structures.

use serde::{Deserialize, Serialize};

use crate::hash::Hash;
use crate::identifiers::ProfileId;
use crate::region::Region;
use crate::time_evidence::TimeEvidence;

/// Known integrity flags indicating inconsistent or anomalous structure data (Req 12.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityFlag {
    /// Timestamp falls outside expected system uptime bounds.
    TimestampBoundsAnomaly,
    /// The recorded length differs significantly from calculated block lengths.
    LengthMismatch,
    /// Link pointers in a chain point backward or to invalid locations.
    InvalidPointer,
    /// Overwritten or partially overwritten metadata block.
    PartialOverwrite,
    /// A custom parser-specific integrity anomaly.
    Custom(String),
}

/// A parsed recording containing time evidence and associated data regions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Recording {
    pub channel: u32,
    pub time: TimeEvidence,
    pub source_image: String,
    pub source_offsets: Vec<Region>,

    // Provenance (Req 5.8)
    pub parser_id: String,
    pub parser_version: String,
    pub profile_id: ProfileId,
    pub profile_hash: Hash,

    /// Set of integrity flags populated if the parser encountered inconsistencies (Req 12.4).
    pub integrity: Vec<IntegrityFlag>,

    /// Path to the extracted video file, populated later during the recovery phase (Req 12.2).
    /// Parsers must NOT require this field during initial structure parsing.
    pub exported_video_path: Option<String>,
}

impl Recording {
    /// Create a new parsed recording.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        channel: u32,
        time: TimeEvidence,
        source_image: String,
        source_offsets: Vec<Region>,
        parser_id: String,
        parser_version: String,
        profile_id: ProfileId,
        profile_hash: Hash,
    ) -> Self {
        Self {
            channel,
            time,
            source_image,
            source_offsets,
            parser_id,
            parser_version,
            profile_id,
            profile_hash,
            integrity: Vec::new(),
            exported_video_path: None,
        }
    }

    /// Flag an integrity anomaly on this recording.
    pub fn add_anomaly(&mut self, flag: IntegrityFlag) {
        if !self.integrity.contains(&flag) {
            self.integrity.push(flag);
        }
    }
}
