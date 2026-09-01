//! # Parser Run Models
//!
//! Tracks provenance, validation states, and unrun stage tracking (Req 5.4, 5.8, 22.1–22.3).
//!
//! A parser stage that did not run is `UNKNOWN`, never `PASS`. A partially interpreted 
//! structure is `REVIEW` with a reason.

use serde::{Deserialize, Serialize};

use crate::identifiers::ProfileId;
use crate::hash::Hash;
use crate::validation::ValidationState;

/// Tracks a discrete parser operation's validation state and provenance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParserRun {
    pub parser_id: String,
    pub parser_version: String,
    pub profile_id: ProfileId,
    pub profile_hash: Hash,
    pub operation_name: String,
    pub validation_state: ValidationState,
}

impl ParserRun {
    /// Create a new parser run tracking object.
    pub fn new(
        parser_id: String,
        parser_version: String,
        profile_id: ProfileId,
        profile_hash: Hash,
        operation_name: String,
        validation_state: ValidationState,
    ) -> Self {
        Self {
            parser_id,
            parser_version,
            profile_id,
            profile_hash,
            operation_name,
            validation_state,
        }
    }
}
