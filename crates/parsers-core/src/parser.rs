//! # Parser Trait
//!
//! Core interface for all OEM-specific storage and recording parsers (Req 3.2, 3.3, 3.4, 3.5, 6.3, 12.1, 12.5).
//!
//! The `Parser` NEVER makes or overrides final OEM attribution (Req 3.5, 12.5).
//! It does NOT build the unified timeline (Req 15.5) or own the recovery-level 
//! state machine. It interprets structures for the storage family and profile version
//! passed in from detection.

use forensic_core::ForensicError;
use forensic_core::Recording;
use forensic_core::TimelineEvent;
use forensic_core::ParserRun;
use forensic_core::OemProfile;

use evidence_reader::EvidenceReader;

/// Common interface for all OEM storage parsers.
pub trait Parser: Send + Sync {
    /// The unique identifier of this parser implementation (e.g. `dahua_dhfs_parser`).
    fn id(&self) -> &str;

    /// The semantic version of this parser implementation.
    fn version(&self) -> &str;

    /// Parse the high-level filesystem structures, if applicable.
    fn parse_filesystem(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Vec<ParserRun>, ForensicError>;

    /// Parse internal metadata indexing tables.
    fn parse_metadata(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Vec<ParserRun>, ForensicError>;

    /// Recover recordings from the evidence structure.
    fn parse_recordings(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<(Vec<Recording>, Vec<ParserRun>), ForensicError>;

    /// Extract timeline candidates (does NOT build the unified timeline).
    fn extract_timeline_events(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<(Vec<TimelineEvent>, Vec<ParserRun>), ForensicError>;

    /// Validates the structural integrity of a provided region.
    fn validate_structure(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Vec<ParserRun>, ForensicError>;
    
    /// Recognize if the candidate structure looks structurally sound for recovery.
    fn recognize_candidate(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<bool, ForensicError>;
}
