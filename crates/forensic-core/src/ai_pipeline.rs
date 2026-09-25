//! AI Analytics Pipeline Boundary & Graceful Degradation (Req 16.1–16.6, 22.3).
//!
//! Enforces:
//! - Validated-evidence boundary: AI is strictly downstream of validated parsing (Req 16.1).
//! - Rejection of UNKNOWN or FAIL inputs (Req 16.1).
//! - Storing findings as DerivedArtifacts with provenance (Req 5.9, 16.6).
//! - Graceful degradation when AI is disabled/unreachable without crashing the core pipeline (Req 16.5).
//! - Unrun AI operations report UNKNOWN, never PASS (Req 22.3).

use crate::ai::AiFinding;
use crate::artifact::{DerivedArtifact, DerivedKind};
use crate::error::ForensicError;
use crate::identifiers::{ArtifactId, EvidenceId};
use crate::provenance::Provenance;
use crate::validation::{ValidationState, ValidationStateKind};
use chrono::Utc;

pub struct AiPipeline;

impl AiPipeline {
    /// Evaluates whether an input recording is eligible for AI analysis.
    /// Rejects inputs with ValidationState == FAIL or UNKNOWN (Req 16.1).
    pub fn validate_ai_input(input_validation: &ValidationState) -> Result<(), ForensicError> {
        match input_validation.state {
            ValidationStateKind::Pass => Ok(()),
            ValidationStateKind::Review => Ok(()), // Eligible for AI assistance during review
            ValidationStateKind::Fail => Err(ForensicError::corrupt(
                "validate_ai_input",
                "Input recording failed structural validation; AI analysis prohibited (Req 16.1)",
            )),
            ValidationStateKind::Unknown => Err(ForensicError::corrupt(
                "validate_ai_input",
                "Input recording validation has not executed (UNKNOWN); AI analysis prohibited (Req 16.1)",
            )),
        }
    }

    /// Processes an AI detection result, wrapping it into a DerivedArtifact and an AiFinding.
    pub fn create_ai_derived_artifact(
        evidence_id: EvidenceId,
        _recording_id: &str,
        finding: &AiFinding,
    ) -> DerivedArtifact {
        let val_state = ValidationState::new(
            ValidationStateKind::Pass,
            "AI finding registered as probabilistic derived artifact",
            "ai_analytics",
            "AiAnalyticsPipeline",
        )
        .unwrap();

        let prov = Provenance::new(
            evidence_id,
            finding.provenance.source_hash.clone(),
            vec![],
            "AiAnalyticsService",
            "1.0.0",
            finding.provenance.output_hash.clone(),
            val_state,
        );

        DerivedArtifact {
            id: ArtifactId::new(),
            kind: DerivedKind::AiOutput,
            provenance: prov,
            output_path: format!("artifacts/ai/{}_{}.json", evidence_id, finding.id),
            description: format!(
                "AI Finding: {} (confidence: {:.2})",
                finding.finding_type, finding.confidence
            ),
            produced_at: Utc::now(),
        }
    }

    /// Handles graceful degradation when AI service is disabled or unreachable (Req 16.5).
    /// Returns ValidationState = UNKNOWN (never PASS) to document that AI did not execute.
    pub fn handle_ai_degradation(ai_enabled: bool, service_reachable: bool) -> ValidationState {
        if !ai_enabled {
            ValidationState::new(
                ValidationStateKind::Unknown,
                "AI analytics service is disabled by examiner configuration (Req 16.5)",
                "ai_analytics",
                "AiAnalytics",
            )
            .unwrap()
        } else if !service_reachable {
            ValidationState::new(
                ValidationStateKind::Unknown,
                "AI analytics service is currently unreachable; pipeline degraded gracefully (Req 16.5)",
                "ai_analytics",
                "AiAnalytics",
            ).unwrap()
        } else {
            ValidationState::new(
                ValidationStateKind::Pass,
                "AI analytics executed successfully",
                "ai_analytics",
                "AiAnalytics",
            )
            .unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fail_and_unknown_inputs_rejected_from_ai() {
        let pass_state = ValidationState::pass("valid", "test", "test").unwrap();
        assert!(AiPipeline::validate_ai_input(&pass_state).is_ok());

        let fail_state =
            ValidationState::new(ValidationStateKind::Fail, "corrupt", "test", "test").unwrap();
        assert!(AiPipeline::validate_ai_input(&fail_state).is_err());

        let unknown_state =
            ValidationState::new(ValidationStateKind::Unknown, "unrun", "test", "test").unwrap();
        assert!(AiPipeline::validate_ai_input(&unknown_state).is_err());
    }

    #[test]
    fn test_graceful_degradation_yields_unknown_never_pass() {
        // Disabled AI yields UNKNOWN
        let disabled = AiPipeline::handle_ai_degradation(false, false);
        assert_eq!(disabled.state, ValidationStateKind::Unknown);
        assert!(disabled.reason.contains("disabled"));

        // Unreachable AI yields UNKNOWN
        let unreachable = AiPipeline::handle_ai_degradation(true, false);
        assert_eq!(unreachable.state, ValidationStateKind::Unknown);
        assert!(unreachable.reason.contains("unreachable"));

        // Normal online AI yields PASS
        let online = AiPipeline::handle_ai_degradation(true, true);
        assert_eq!(online.state, ValidationStateKind::Pass);
    }
}
