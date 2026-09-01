//! AI Integration & Boundary Test Suite (Task 123 / Req 16.1–16.6).
//!
//! Asserts:
//! - Validated-evidence boundary: AI is strictly downstream of validated parsing.
//! - Non-validated / FAIL inputs are rejected.
//! - Findings are stored strictly as `DerivedArtifact` with `AI-assisted` labeling.
//! - AI findings never alter or replace original native evidence.
//! - Graceful degradation when AI is disabled or unreachable (reports UNKNOWN, never PASS).

use forensic_core::{
    ai::{AiFinding, BoundingBox},
    ai_pipeline::AiPipeline,
    artifact::DerivedKind,
    EvidenceId, Hash, Provenance, Region, ValidationState, ValidationStateKind,
};

#[test]
fn test_ai_validated_evidence_boundary() {
    // 1. Validated (Pass) input is accepted
    let pass_state = ValidationState::pass("structural check pass", "parse_recording", "Recording 1").unwrap();
    assert!(AiPipeline::validate_ai_input(&pass_state).is_ok());

    // 2. Review input is accepted (eligible for AI assisted review)
    let review_state = ValidationState::new(ValidationStateKind::Review, "truncated clip", "parse_recording", "Recording 2").unwrap();
    assert!(AiPipeline::validate_ai_input(&review_state).is_ok());

    // 3. Corrupt/Fail input is rejected (Req 16.1)
    let fail_state = ValidationState::new(ValidationStateKind::Fail, "corrupted GOP headers", "parse_recording", "Recording 3").unwrap();
    let err = AiPipeline::validate_ai_input(&fail_state);
    assert!(err.is_err(), "Failed validation inputs must be rejected by AI boundary");

    // 4. Unvalidated (Unknown) input is rejected (Req 16.1)
    let unknown_state = ValidationState::new(ValidationStateKind::Unknown, "unrun parser validation", "parse_recording", "Recording 4").unwrap();
    let err2 = AiPipeline::validate_ai_input(&unknown_state);
    assert!(err2.is_err(), "Unvalidated inputs must be rejected by AI boundary");
}

#[test]
fn test_ai_finding_provenance_and_derived_artifact() {
    let evidence_id = EvidenceId::new();
    let prov = Provenance::new(
        evidence_id,
        Hash::sha256(vec![0x11; 32]),
        vec![],
        "AiAnalyticsService",
        "1.0.0",
        Hash::sha256(vec![0x22; 32]),
        ValidationState::pass("motion detected", "ai_analytics", "CH 1").unwrap(),
    );

    let finding = AiFinding::new(
        evidence_id,
        "rec-001".into(),
        1,
        "2026-09-01T12:00:00Z".into(),
        "PersonDetected".into(),
        0.92,
        Some(BoundingBox { x: 0.2, y: 0.3, width: 0.1, height: 0.4 }),
        Region { offset: 0x1000, length: 1024 },
        prov,
    );

    // AI findings must always be labeled AI-assisted (Req 16.3)
    assert!(finding.is_ai_assisted);
    assert!(finding.disclaimer.contains("AI-assisted"));
    assert!(finding.disclaimer.contains("not absolute truth"));

    // Register as DerivedArtifact (Req 5.9, 16.6)
    let artifact = AiPipeline::create_ai_derived_artifact(evidence_id, "rec-001", &finding);
    assert_eq!(artifact.kind, DerivedKind::AiOutput);
    assert!(artifact.output_path.contains("artifacts/ai/"));
}

#[test]
fn test_ai_graceful_degradation_and_unrun_honesty() {
    // Disabled AI must return UNKNOWN, never PASS (Req 22.3, 16.5)
    let disabled_state = AiPipeline::handle_ai_degradation(false, false);
    assert_eq!(disabled_state.state, ValidationStateKind::Unknown);
    assert!(disabled_state.reason.contains("disabled"));

    // Unreachable AI must return UNKNOWN, never PASS
    let unreachable_state = AiPipeline::handle_ai_degradation(true, false);
    assert_eq!(unreachable_state.state, ValidationStateKind::Unknown);
    assert!(unreachable_state.reason.contains("unreachable"));
}
