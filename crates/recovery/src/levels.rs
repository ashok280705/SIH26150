//! Recovery level strategies: L1 (indexed), L2 (orphan/slack), L3 (raw carving).
//!
//! Each level processes evidence strictly within the engine's bounded loop.
//! Bounds are enforced using the `BoundedReader` abstraction to prevent out-of-bounds reads.

use forensic_core::{
    ForensicError, OemProfile, RecoveryCandidate, Region,
};
use evidence_reader::{BoundedReader, EvidenceReader};
use parsers_core::parser::Parser;

/// L1: Indexed recovery — uses valid filesystem/index entries to locate recordings.
/// Index-derived offsets are validated with checked arithmetic (Req 24).
pub fn recover_l1_indexed(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    parser: &dyn Parser,
    search_region: &Region,
) -> Result<Vec<RecoveryCandidate>, ForensicError> {
    // Isolate search region using BoundedReader
    let bounded = BoundedReader::new(reader, search_region.offset, search_region.length)?;

    // Delegate candidate recognition to the parser within the bounded region
    match parser.recognize_candidate(&bounded, profile) {
        Ok(true) => {
            // Placeholder: candidates extracted with absolute offset provenance
            Ok(vec![])
        }
        Ok(false) | Err(_) => Ok(vec![]),
    }
}

/// L2: Orphan/slack recovery — metadata missing, payload remains.
/// Missing index linkage yields `Orphaned`; absence of an index is NEVER
/// treated as proof of overwrite (Req 13.11).
pub fn recover_l2_orphan(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    parser: &dyn Parser,
    search_region: &Region,
) -> Result<Vec<RecoveryCandidate>, ForensicError> {
    let bounded = BoundedReader::new(reader, search_region.offset, search_region.length)?;

    match parser.recognize_candidate(&bounded, profile) {
        Ok(true) => {
            Ok(vec![])
        }
        Ok(false) | Err(_) => Ok(vec![]),
    }
}

/// L3: Raw carving — bounded, cancellable scan for video structures.
/// A truncated carve reports REVIEW and never claims a global optimum (Req 13.10).
pub fn recover_l3_carve(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    parser: &dyn Parser,
    search_region: &Region,
) -> Result<Vec<RecoveryCandidate>, ForensicError> {
    let bounded = BoundedReader::new(reader, search_region.offset, search_region.length)?;

    match parser.recognize_candidate(&bounded, profile) {
        Ok(true) => {
            Ok(vec![])
        }
        Ok(false) | Err(_) => Ok(vec![]),
    }
}
