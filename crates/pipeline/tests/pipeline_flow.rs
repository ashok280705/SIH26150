//! End-to-end pipeline flow tests against the generated Dahua fixture.
//!
//! These assert the flow *routes correctly through its gates*, not just that a
//! function returns Ok.

use confidence::config::ConfidenceConfig;
use evidence_reader::RawReader;
use forensic_core::ProfileRegistry;
use pipeline::{
    run_pipeline, GapDecision, GateRecord, ParseDecision, PipelineOptions, PipelineOutcome,
    ThresholdDecision,
};
use std::path::{Path, PathBuf};

fn find(rel: &str) -> Option<PathBuf> {
    for base in [".", "..", "../.."] {
        let p = Path::new(base).join(rel);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn load_registry() -> ProfileRegistry {
    let dir = find("profiles").expect("profiles/ directory must exist");
    ProfileRegistry::load_from_dir(&dir).expect("profiles must load")
}

#[test]
fn dahua_fixture_runs_full_flow_to_final_timeline() {
    let Some(raw) = find("dahua_dhfs_sample.raw") else {
        eprintln!("skipping: dahua_dhfs_sample.raw not present (run generate_dahua_raw.py)");
        return;
    };
    let reader = RawReader::open(raw.to_str().unwrap()).expect("open fixture");
    let registry = load_registry();
    let config = ConfidenceConfig::provisional_default();
    let options = PipelineOptions::default();

    let run = run_pipeline(forensic_core::EvidenceId::new(), &reader, &registry, &config, &options).expect("pipeline runs");

    // Attribution should confirm Dahua and take the OEM-confirmed branch.
    let attribution = run.attribution.as_ref().expect("attribution present");
    assert_eq!(attribution.oem_key, "dahua");

    let threshold = run
        .gates
        .iter()
        .find_map(|g| match g {
            GateRecord::Threshold { decision, .. } => Some(*decision),
            _ => None,
        })
        .expect("threshold gate recorded");
    assert_eq!(threshold, ThresholdDecision::OemConfirmed);

    // Evidence must be parsed (the Dahua parser extracts two recordings).
    let parsed = run
        .gates
        .iter()
        .find_map(|g| match g {
            GateRecord::Parsed { decision, .. } => Some(*decision),
            _ => None,
        })
        .expect("parsed gate recorded");
    assert_eq!(parsed, ParseDecision::Parsed);
    assert_eq!(run.oem_key_used.as_deref(), Some("dahua"));
    assert!(!run.used_unified_fallback);

    // A gaps gate decision must have been recorded either way.
    assert!(run
        .gates
        .iter()
        .any(|g| matches!(g, GateRecord::Gaps { .. })));

    // The preliminary timeline and gap analysis must exist.
    assert!(run.preliminary_timeline.is_some());
    assert!(run.gap_analysis.is_some());

    // A final timeline must always be produced when not halted for an analyst.
    if !run.requires_analyst {
        assert!(run.final_timeline.is_some());
        assert!(matches!(
            run.outcome,
            PipelineOutcome::CompletedNoGaps
                | PipelineOutcome::CompletedAfterRecovery
                | PipelineOutcome::CompletedPartialRecovery
        ));
    }

    // The gap gate decision and outcome must be internally consistent.
    let gaps = run.gates.iter().find_map(|g| match g {
        GateRecord::Gaps { decision, .. } => Some(*decision),
        _ => None,
    });
    if gaps == Some(GapDecision::GapsPresent) && !run.requires_analyst {
        assert!(run.recovery.is_some(), "gaps present must trigger recovery");
    }
}

#[test]
fn every_stage_and_gate_has_a_reason() {
    let Some(raw) = find("dahua_dhfs_sample.raw") else {
        eprintln!("skipping: dahua_dhfs_sample.raw not present");
        return;
    };
    let reader = RawReader::open(raw.to_str().unwrap()).unwrap();
    let registry = load_registry();
    let config = ConfidenceConfig::provisional_default();
    let run = run_pipeline(forensic_core::EvidenceId::new(), &reader, &registry, &config, &PipelineOptions::default()).unwrap();

    // Auditability: no stage detail or gate reason may be empty.
    for stage in &run.stages {
        assert!(!stage.detail.trim().is_empty(), "stage {:?} has empty detail", stage.stage);
    }
    for gate in &run.gates {
        let reason = match gate {
            GateRecord::Threshold { reason, .. } => reason,
            GateRecord::Parsed { reason, .. } => reason,
            GateRecord::Gaps { reason, .. } => reason,
            GateRecord::Recovery { reason, .. } => reason,
        };
        assert!(!reason.trim().is_empty(), "a gate has an empty reason");
    }
}
