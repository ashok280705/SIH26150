//! # Timeline Event Models
//!
//! Models representing timeline candidate events extracted during the parsing phase (Req 15.2, 15.5).
//!
//! The parser strictly emits `TimelineEvent` candidates and NEVER constructs the final unified
//! timeline. Candidates carry the full `TimeEvidence` block, preserving raw and recorder-native values.

use serde::{Deserialize, Serialize};

use crate::hash::Hash;
use crate::identifiers::ProfileId;
use crate::region::Region;
use crate::time_evidence::TimeEvidence;

/// A candidate timeline event extracted from metadata or indexing structures.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub channel: u32,
    pub time: TimeEvidence,
    pub description: String,

    /// Offsets associated with the physical structure representing this event.
    pub source_offsets: Vec<Region>,

    // Provenance (Req 5.8)
    pub parser_id: String,
    pub parser_version: String,
    pub profile_id: ProfileId,
    pub profile_hash: Hash,
}

impl TimelineEvent {
    /// Extract a new candidate timeline event.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        channel: u32,
        time: TimeEvidence,
        description: String,
        source_offsets: Vec<Region>,
        parser_id: String,
        parser_version: String,
        profile_id: ProfileId,
        profile_hash: Hash,
    ) -> Self {
        Self {
            channel,
            time,
            description,
            source_offsets,
            parser_id,
            parser_version,
            profile_id,
            profile_hash,
        }
    }
}
