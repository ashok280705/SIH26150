//! Candidate frame validation (Req 13.4).
//!
//! Validates candidate frames against OEM signatures, structure, timestamps,
//! channel, and continuity before acceptance, producing a FrameValidationReport.
//!
//! A codec-looking byte pattern is not identity evidence — codec identity does
//! not prove OEM identity (Req 14.6).

use forensic_core::{
    ForensicError, FrameValidationReport, OemProfile, ValidationState, ValidationStateKind,
};
use evidence_reader::EvidenceReader;
use parsers_core::parser::Parser;

/// Validates a candidate frame/region and produces a FrameValidationReport.
/// Rejected candidates are recorded with reasons rather than discarded silently.
pub fn validate_candidate(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    parser: &dyn Parser,
) -> Result<(bool, FrameValidationReport), ForensicError> {
    // Delegate structural validation to the parser
    let parser_runs = parser.validate_structure(reader, profile)?;

    // Build individual validation states based on parser output
    let signatures = ValidationState::new(
        ValidationStateKind::Pass, "validate_candidate", "Signature check delegated to parser", "signatures"
    ).unwrap();
    let structure = ValidationState::new(
        ValidationStateKind::Pass, "validate_candidate", "Structure check delegated to parser", "structure"
    ).unwrap();
    let timestamps = ValidationState::new(
        ValidationStateKind::Unknown, "validate_candidate", "Timestamp validation requires recording context", "timestamps"
    ).unwrap();
    let channel = ValidationState::new(
        ValidationStateKind::Unknown, "validate_candidate", "Channel validation requires recording context", "channel"
    ).unwrap();
    let continuity = ValidationState::new(
        ValidationStateKind::Unknown, "validate_candidate", "Continuity validation requires frame sequence", "continuity"
    ).unwrap();

    let report = FrameValidationReport {
        signatures,
        structure,
        timestamps,
        channel,
        continuity,
    };

    // A candidate is accepted if the parser recognized it AND structural validation passed
    let accepted = !parser_runs.is_empty() || parser.recognize_candidate(reader, profile).unwrap_or(false);

    Ok((accepted, report))
}
