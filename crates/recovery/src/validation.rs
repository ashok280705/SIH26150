//! Candidate frame validation (Req 13.4).
//!
//! # Status: not wired into the production recovery path
//!
//! The index-aware engine builds its `FrameValidationReport` in
//! [`crate::levels::scan_target`], which has the codec evidence and the index claim in
//! hand. This helper remains for callers that only have a parser and a bounded window.
//!
//! It previously stamped `signatures` and `structure` as `Pass` unconditionally, with the
//! reason "delegated to parser" — an unearned PASS on checks it never performed. That is
//! now fixed: the states are derived from the parser's actual `ParserRun` outcomes, and a
//! check with no result is `Unknown`, never `Pass`.
//!
//! A codec-looking byte pattern is not identity evidence — codec identity does not prove
//! OEM identity (Req 14.6), and recognising a format does not establish that a region is
//! an indexed recording.

use evidence_reader::EvidenceReader;
use forensic_core::{
    ForensicError, FrameValidationReport, OemProfile, ValidationState, ValidationStateKind,
};
use parsers_core::parser::Parser;

/// Total `ValidationState` constructor; the static fallback reason is non-empty, so this
/// introduces no panic path into evidence handling.
fn vs(kind: ValidationStateKind, reason: impl Into<String>, subject: &str) -> ValidationState {
    let reason = reason.into();
    ValidationState::new(kind, reason, "validate_candidate", subject).unwrap_or_else(|_| {
        ValidationState::new(kind, "reason unavailable", "validate_candidate", subject)
            .expect("static fallback reason is non-empty")
    })
}

/// Validate a candidate region and produce a `FrameValidationReport`.
///
/// Returns `(accepted, report)`. `accepted` is true only when the parser's structural
/// validation actually passed — not merely when the parser recognised the byte format.
/// Rejected candidates are reported with reasons rather than discarded silently.
pub fn validate_candidate(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    parser: &dyn Parser,
) -> Result<(bool, FrameValidationReport), ForensicError> {
    let parser_runs = parser.validate_structure(reader, profile)?;

    // Structure reflects what the parser actually concluded. No runs means the check did
    // not execute, which is Unknown.
    let structure = match parser_runs
        .iter()
        .map(|r| r.validation_state.state)
        .reduce(|a, b| {
            // The weakest outcome wins: one failing check cannot be averaged away.
            use ValidationStateKind::*;
            match (a, b) {
                (Fail, _) | (_, Fail) => Fail,
                (Review, _) | (_, Review) => Review,
                (Unknown, _) | (_, Unknown) => Unknown,
                _ => Pass,
            }
        }) {
        Some(state) => {
            let reasons = parser_runs
                .iter()
                .map(|r| format!("{}: {}", r.operation_name, r.validation_state.reason))
                .collect::<Vec<_>>()
                .join("; ");
            vs(state, reasons, "structure")
        }
        None => vs(
            ValidationStateKind::Unknown,
            format!(
                "parser '{}' ran no structural validation for this region",
                parser.id()
            ),
            "structure",
        ),
    };

    // Format recognition is a signature-level observation, and it is explicitly not a
    // structural verdict. Recognising the format yields REVIEW, not PASS: a signature
    // match alone is never "valid video".
    let recognised = parser.recognize_candidate(reader, profile)?;
    let signatures = if recognised {
        vs(
            ValidationStateKind::Review,
            format!(
                "parser '{}' recognises its own container framing in this region; a format \
                 match alone does not establish valid video",
                parser.id()
            ),
            "signatures",
        )
    } else {
        vs(
            ValidationStateKind::Review,
            format!(
                "parser '{}' does not recognise its container framing in this region",
                parser.id()
            ),
            "signatures",
        )
    };

    let report = FrameValidationReport {
        signatures,
        structure: structure.clone(),
        // These need recorder metadata or a frame sequence, neither of which a
        // single-region validation has. An unrun check is Unknown.
        timestamps: vs(
            ValidationStateKind::Unknown,
            "timestamp validation requires recording/index context not available here",
            "timestamps",
        ),
        channel: vs(
            ValidationStateKind::Unknown,
            "channel validation requires recording/index context not available here",
            "channel",
        ),
        continuity: vs(
            ValidationStateKind::Unknown,
            "continuity validation requires a frame sequence, not a single region",
            "continuity",
        ),
    };

    // Acceptance requires the structural check to have actually passed. Format recognition
    // alone is not sufficient.
    let accepted = matches!(structure.state, ValidationStateKind::Pass);

    Ok((accepted, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_core::identifiers::ProfileId;
    use forensic_core::{Hash, ParserRun, Recording, TimelineEvent};

    struct EmptyReader;
    impl EvidenceReader for EmptyReader {
        fn len(&self) -> u64 {
            0
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
            Err(ForensicError::out_of_bounds(
                "empty",
                offset,
                buf.len() as u64,
                0,
            ))
        }
        fn source_kind(&self) -> evidence_reader::SourceKind {
            evidence_reader::SourceKind::Raw
        }
        fn source_path(&self) -> &str {
            "mem://empty"
        }
    }

    /// A parser that recognises everything but reports a given structural outcome.
    struct StubParser {
        structural: Option<ValidationStateKind>,
    }

    impl Parser for StubParser {
        fn id(&self) -> &str {
            "stub"
        }
        fn version(&self) -> &str {
            "1.0"
        }
        fn parse_filesystem(
            &self,
            _: &dyn EvidenceReader,
            _: &OemProfile,
        ) -> Result<Vec<ParserRun>, ForensicError> {
            Ok(vec![])
        }
        fn parse_metadata(
            &self,
            _: &dyn EvidenceReader,
            _: &OemProfile,
        ) -> Result<Vec<ParserRun>, ForensicError> {
            Ok(vec![])
        }
        fn parse_recordings(
            &self,
            _: &dyn EvidenceReader,
            _: &OemProfile,
        ) -> Result<(Vec<Recording>, Vec<ParserRun>), ForensicError> {
            Ok((vec![], vec![]))
        }
        fn extract_timeline_events(
            &self,
            _: &dyn EvidenceReader,
            _: &OemProfile,
        ) -> Result<(Vec<TimelineEvent>, Vec<ParserRun>), ForensicError> {
            Ok((vec![], vec![]))
        }
        fn validate_structure(
            &self,
            _: &dyn EvidenceReader,
            profile: &OemProfile,
        ) -> Result<Vec<ParserRun>, ForensicError> {
            match self.structural {
                Some(state) => Ok(vec![ParserRun::new(
                    "stub".to_string(),
                    "1.0".to_string(),
                    ProfileId(profile.profile_id.clone()),
                    Hash::sha256(vec![0; 32]),
                    "validate_structure".to_string(),
                    vs(state, "stub structural outcome", "test"),
                )]),
                None => Ok(vec![]),
            }
        }
        fn recognize_candidate(
            &self,
            _: &dyn EvidenceReader,
            _: &OemProfile,
        ) -> Result<bool, ForensicError> {
            Ok(true)
        }
    }

    fn profile() -> OemProfile {
        OemProfile::from_toml_str(
            r#"
profile_id = "t-v1.0"
profile_version = "1.0.0"
schema_version = "1.0"
oem = "t"
storage_family = "T"
[applicability]
[[signatures]]
name = "s"
pattern_hex = "00"
evidence_status = "provisional"
weight = 0.5
[confidence_weights]
max_possible_score = 0.5
"#,
        )
        .unwrap()
    }

    #[test]
    fn format_recognition_alone_is_never_a_pass() {
        // The parser recognises the format and reports no structural result.
        let (accepted, report) =
            validate_candidate(&EmptyReader, &profile(), &StubParser { structural: None }).unwrap();

        assert!(
            !accepted,
            "recognising a format must not accept a candidate"
        );
        assert_ne!(
            report.signatures.state,
            ValidationStateKind::Pass,
            "a signature match is not a PASS"
        );
        assert_eq!(
            report.structure.state,
            ValidationStateKind::Unknown,
            "a structural check that never ran is Unknown, never Pass"
        );
    }

    #[test]
    fn structural_pass_is_required_for_acceptance() {
        let (accepted, report) = validate_candidate(
            &EmptyReader,
            &profile(),
            &StubParser {
                structural: Some(ValidationStateKind::Pass),
            },
        )
        .unwrap();
        assert!(accepted);
        assert_eq!(report.structure.state, ValidationStateKind::Pass);

        let (accepted, report) = validate_candidate(
            &EmptyReader,
            &profile(),
            &StubParser {
                structural: Some(ValidationStateKind::Review),
            },
        )
        .unwrap();
        assert!(!accepted);
        assert_eq!(report.structure.state, ValidationStateKind::Review);
    }

    #[test]
    fn unrun_checks_stay_unknown() {
        let (_, report) = validate_candidate(
            &EmptyReader,
            &profile(),
            &StubParser {
                structural: Some(ValidationStateKind::Pass),
            },
        )
        .unwrap();
        assert_eq!(report.timestamps.state, ValidationStateKind::Unknown);
        assert_eq!(report.channel.state, ValidationStateKind::Unknown);
        assert_eq!(report.continuity.state, ValidationStateKind::Unknown);
    }
}
