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

use crate::storage::{RecordingIndex, StorageGeometry};

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
    
    /// Whether the bytes in the window handed to this method look like a structurally
    /// sound instance of *this OEM's* container/stream framing.
    ///
    /// # This is NOT an index lookup
    ///
    /// A `true` here means only "these bytes are shaped like our format". It is
    /// **never** evidence that the region is an active, indexed recording, and callers
    /// must not derive [`forensic_core::DataState`] from it. Claim/state reasoning is
    /// driven exclusively by [`Parser::recording_index`].
    ///
    /// Returning `Ok(true)` unconditionally makes this signal useless and silently
    /// suppresses orphan/unindexed discovery; implementations must inspect the bytes.
    fn recognize_candidate(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<bool, ForensicError>;

    /// Read the recorder's declared physical storage geometry from its own structures.
    ///
    /// `Ok(None)` means this OEM path cannot establish geometry from evidence. That is
    /// a supported, honest answer: the recovery engine degrades to a whole-image scan
    /// whose candidates can only reach the conservative "unindexed" state, never
    /// `Active` or `Orphaned`.
    ///
    /// Implementations must not invent fields. Anything not read from evidence stays
    /// `None`/`Unknown`.
    fn storage_geometry(
        &self,
        _reader: &dyn EvidenceReader,
        _profile: &OemProfile,
    ) -> Result<Option<StorageGeometry>, ForensicError> {
        Ok(None)
    }

    /// Read the recorder's recording/index metadata and normalize it into physical
    /// byte ranges.
    ///
    /// `Ok(None)` means this OEM path has no index reader. The engine then treats every
    /// region as `NoIndexEvidence`, so no `Active` or `Orphaned` conclusion can be drawn.
    ///
    /// Implementations must set [`crate::storage::IndexAuthority`] honestly: an index
    /// that was only partially parsed cannot support an orphan finding, because absence
    /// from a partial index is not evidence of absence.
    fn recording_index(
        &self,
        _reader: &dyn EvidenceReader,
        _profile: &OemProfile,
    ) -> Result<Option<RecordingIndex>, ForensicError> {
        Ok(None)
    }
}
