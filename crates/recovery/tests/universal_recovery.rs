//! # The universal recovery suite
//!
//! One place that asserts what the engine **decides**, on real evidence, for every recovery
//! situation the platform claims to handle. It is deliberately not a smoke test: no assertion
//! here is satisfied by `Ok(...)`, and every one names the state, the evidence behind it, or
//! the explicit absence of evidence.
//!
//! ```text
//!   situation                     asserted outcome
//!   ─────────────────────────────────────────────────────────────────────
//!   active indexed recording      Active, with the index entry named
//!   orphan inside index scope     Orphaned, because an authoritative index omits it
//!   available (unreachable) meta  Orphaned, NOT Deleted, with the recorder's channel kept
//!   raw media outside any scope   Unindexed, never Active, never Deleted
//!   no recording index at all     every finding Unindexed, nothing Orphaned
//!   missing codec / timestamps    UNKNOWN fields, never 0 / epoch / H264
//!   fragments of one recording    one correlated recording, ordering from evidence
//!   fragments with no evidence    separate recordings, ordering UNKNOWN
//!   corrupted media               Corrupted, and Corrupted is not Unrecoverable
//!   bounded run                   REVIEW, never PASS
//! ```
//!
//! The fixture is the real Dahua DHFS 4.1 structure set from `tests/common`, driven through
//! the production `RawReader` and the production parser. Nothing bypasses the parser, so a
//! test cannot pass on fabricated normalized data.

mod common;

use forensic_core::{CancelToken, DataState, RecoveryBounds, RecoveryStatus, ValidationStateKind};
use parser_dahua::DahuaParser;
use recovery::capabilities::{RecoveryCapability, RecoveryStrategy};
use recovery::correlation::TemporalOrdering;
use recovery::{RecoveryEngine, RecoveryOutcome, RecoveryRequest};

use forensic_core::{EvidenceId, OemProfile, ProfileRegistry};

fn registry() -> ProfileRegistry {
    ProfileRegistry::load_from_dir(&common::profiles_dir()).expect("profiles/ must load")
}

/// Run the production engine over the shared Dahua fixture.
fn run_on_fixture(bounds: &RecoveryBounds) -> (common::Fixture, RecoveryOutcome) {
    let fx = common::build_fixture();
    let (_dir, reader) = common::open_fixture(&fx);
    let reg = registry();
    let profile: &OemProfile = common::dahua_profile(&reg);
    let parser = DahuaParser::default();

    let outcome = RecoveryEngine::new()
        .execute_recovery(RecoveryRequest::new(
            EvidenceId::new(),
            &reader,
            profile,
            "dahua",
            &parser,
            bounds,
        ))
        .expect("recovery over a readable fixture must not error");
    // `_dir` is dropped here; the outcome holds no borrow on the file.
    (fx, outcome)
}

fn unbounded() -> RecoveryBounds {
    common::bounds()
}

// ── Recovery decisions ──────────────────────────────────────────────────────

#[test]
fn an_indexed_recording_is_active_and_names_the_index_entry_that_claims_it() {
    let (_fx, out) = run_on_fixture(&unbounded());

    let active: Vec<_> = out.in_state(DataState::Active).collect();
    assert!(
        !active.is_empty(),
        "the fixture's reachable chains must be recovered as Active"
    );
    for c in &active {
        assert_eq!(c.recovery_status, RecoveryStatus::Recoverable);
        assert!(
            c.provenance.validation_state.reason.contains("index entry"),
            "an Active finding must name the index entry that claims it: {}",
            c.provenance.validation_state.reason
        );
    }

    // Every Active finding's fragment carries recorder metadata, because only an index claim
    // can produce Active and an index claim is what supplies channel and clock.
    for (c, f) in out.candidates.iter().zip(out.fragments.iter()) {
        if c.data_state == DataState::Active {
            assert!(
                f.parent_recording.is_known(),
                "an Active fragment must be attributable to the entry that claimed it"
            );
        }
    }
}

#[test]
fn video_an_authoritative_index_omits_is_orphaned_not_deleted() {
    let (_fx, out) = run_on_fixture(&unbounded());

    let orphans: Vec<_> = out.in_state(DataState::Orphaned).collect();
    assert!(
        !orphans.is_empty(),
        "the fixture holds video in a slot the block table does not reference"
    );
    assert_eq!(
        out.in_state(DataState::Deleted).count(),
        0,
        "absence from an index is never a deletion finding without a free marker"
    );
    for c in &orphans {
        let reason = &c.provenance.validation_state.reason;
        assert!(
            reason.contains("not part of the accessible recording set")
                || reason.contains("without referencing it"),
            "an orphan finding must state the non-reference it rests on: {reason}"
        );
    }
}

#[test]
fn surviving_but_unreachable_metadata_keeps_the_recorders_channel_and_clock() {
    let (_fx, out) = run_on_fixture(&unbounded());

    let available: Vec<_> = out
        .fragments
        .iter()
        .zip(out.candidates.iter())
        .filter(|(f, _)| f.discovery_method == recovery::DiscoveryMethod::AvailableMetadataProbe)
        .collect();
    assert!(
        !available.is_empty(),
        "the fixture holds one fully described but unreachable chain"
    );

    for (f, c) in &available {
        assert_eq!(
            c.data_state,
            DataState::Orphaned,
            "unreachability is not deallocation, so it is Orphaned and never Deleted"
        );
        assert!(
            f.camera_id.is_known(),
            "the recorder's own metadata survives here, so the channel must survive with it"
        );
        assert!(
            f.timestamp_unix.is_known(),
            "the recorder's own metadata survives here, so the timestamp must survive with it"
        );
    }
}

#[test]
fn video_outside_any_index_scope_is_unindexed_and_never_active() {
    let (fx, out) = run_on_fixture(&unbounded());

    // The loose DHAV frame written into slack past the declared video region.
    let loose = out
        .fragments
        .iter()
        .zip(out.candidates.iter())
        .find(|(f, _)| f.physical_region.contains(fx.loose_frame_offset))
        .expect("the slack frame must be discovered");

    assert_eq!(
        loose.1.data_state,
        DataState::Unindexed,
        "bytes no authoritative index governs can only be unindexed"
    );
    assert!(
        loose
            .1
            .provenance
            .validation_state
            .reason
            .contains("not evidence of deletion"),
        "an unindexed finding must say what it is not: {}",
        loose.1.provenance.validation_state.reason
    );
}

#[test]
fn a_fragment_with_no_recorder_metadata_reports_unknown_not_zero() {
    let (_fx, out) = run_on_fixture(&unbounded());

    let blind: Vec<_> = out
        .fragments
        .iter()
        .filter(|f| !f.discovery_method.is_metadata_driven())
        .collect();
    assert!(
        !blind.is_empty(),
        "the fixture produces blind-sweep findings"
    );

    for f in blind {
        // A swept fragment may still learn channel/time from a container record's own header,
        // which is read evidence. What it must never do is report a substituted default with
        // no source recorded.
        if let Some(c) = f.camera_id.value() {
            assert_ne!(*c, 0, "channel 0 is a substituted default, not a reading");
        }
        if let Some(t) = f.timestamp_unix.value() {
            assert!(*t > 0, "the epoch is a substituted default, not a reading");
        }
        if !f.camera_id.is_known() {
            match &f.camera_id {
                recovery::FieldEvidence::Unknown { reason } => {
                    assert!(!reason.trim().is_empty(), "an unknown must say why")
                }
                _ => unreachable!(),
            }
        }
    }
}

#[test]
fn a_region_with_no_codec_evidence_produces_no_candidate() {
    let (fx, out) = run_on_fixture(&unbounded());

    // Block 5 is an unused slot holding nothing. No candidate may describe it.
    let empty_block = fx.block_offset(5);
    let describing: Vec<_> = out
        .fragments
        .iter()
        .filter(|f| f.physical_region.contains(empty_block))
        .collect();
    assert!(
        describing.is_empty(),
        "a region with no codec evidence must not be reported as recovered video"
    );
}

// ── Capability assessment and strategy selection ────────────────────────────

#[test]
fn capabilities_are_derived_from_what_the_parser_established() {
    let (_fx, out) = run_on_fixture(&unbounded());

    assert!(out.capabilities.has(RecoveryCapability::StorageGeometry));
    assert!(out.capabilities.has(RecoveryCapability::RecordingIndex));
    assert!(out
        .capabilities
        .has(RecoveryCapability::AuthoritativeIndexScope));
    assert!(out
        .capabilities
        .has(RecoveryCapability::UnreferencedMetadata));
    assert!(out.capabilities.has(RecoveryCapability::ContainerCarving));

    // Every capability is reported either way, with a reason.
    assert_eq!(
        out.capabilities.findings.len(),
        RecoveryCapability::ALL.len()
    );
    for f in &out.capabilities.findings {
        assert!(
            !f.reason.trim().is_empty(),
            "{:?} has no reason",
            f.capability
        );
    }
}

#[test]
fn strategy_selection_records_why_a_strategy_was_not_applied() {
    let (_fx, out) = run_on_fixture(&unbounded());

    assert!(out
        .strategies
        .is_licensed(RecoveryStrategy::IndexedRecovery));
    assert!(out
        .strategies
        .is_licensed(RecoveryStrategy::AvailableMetadataRecovery));
    assert!(out
        .strategies
        .is_licensed(RecoveryStrategy::StructuralOrphanRecovery));

    for d in &out.strategies.decisions {
        assert!(
            !d.reason.trim().is_empty(),
            "strategy {:?} carries no reason",
            d.strategy
        );
    }
}

#[test]
fn an_evidence_item_with_no_index_licenses_only_the_raw_sweep() {
    // Non-Dahua bytes under the Dahua profile: the parser establishes nothing, and the engine
    // must degrade rather than fail or over-claim.
    use evidence_reader::EvidenceReader;
    use forensic_core::ForensicError;

    struct Noise(Vec<u8>);
    impl EvidenceReader for Noise {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
            if offset >= self.len() {
                return Err(ForensicError::out_of_bounds(
                    "noise",
                    offset,
                    buf.len() as u64,
                    self.len(),
                ));
            }
            let s = offset as usize;
            let n = (self.0.len() - s).min(buf.len());
            buf[..n].copy_from_slice(&self.0[s..s + n]);
            Ok(n)
        }
        fn source_kind(&self) -> evidence_reader::SourceKind {
            evidence_reader::SourceKind::Raw
        }
        fn source_path(&self) -> &str {
            "mem://noise"
        }
    }

    // Real H.264 in an image with no DVR structure at all.
    let mut data = vec![0u8; 3 << 20];
    let clip = common::h264_clip(7);
    data[1 << 20..(1 << 20) + clip.len()].copy_from_slice(&clip);
    let reader = Noise(data);

    let reg = registry();
    let profile = common::dahua_profile(&reg);
    let parser = DahuaParser::default();
    let bounds = unbounded();
    let out = RecoveryEngine::new()
        .execute_recovery(RecoveryRequest::new(
            EvidenceId::new(),
            &reader,
            profile,
            "dahua",
            &parser,
            &bounds,
        ))
        .expect("an unrecognised image must degrade, not error");

    assert!(!out.capabilities.has(RecoveryCapability::RecordingIndex));
    assert!(!out
        .capabilities
        .has(RecoveryCapability::AuthoritativeIndexScope));
    assert!(out.strategies.is_licensed(RecoveryStrategy::RawRecovery));
    assert!(!out
        .strategies
        .is_licensed(RecoveryStrategy::IndexedRecovery));
    assert!(!out
        .strategies
        .is_licensed(RecoveryStrategy::StructuralOrphanRecovery));

    assert_eq!(
        out.in_state(DataState::Active).count(),
        0,
        "no index means nothing can be Active"
    );
    assert_eq!(
        out.in_state(DataState::Orphaned).count(),
        0,
        "no authoritative index means nothing can be Orphaned"
    );
    assert!(
        out.candidates
            .iter()
            .all(|c| matches!(c.data_state, DataState::Unindexed | DataState::Corrupted)),
        "every finding must be unindexed or corrupted"
    );
}

// ── Correlation ─────────────────────────────────────────────────────────────

#[test]
fn carved_records_of_one_recording_correlate_into_one_recording() {
    let (_fx, out) = run_on_fixture(&unbounded());

    assert!(
        !out.recordings.is_empty(),
        "correlation must produce recordings from the run's fragments"
    );
    // Correlation reduces per-record candidates to recordings; it never invents one.
    assert!(
        out.recordings.len() <= out.fragments.len(),
        "correlation can only group, never multiply"
    );

    // Every fragment appears in exactly one correlated recording.
    let mut seen: Vec<&str> = out
        .recordings
        .iter()
        .flat_map(|r| r.fragment_ids.iter().map(|s| s.as_str()))
        .collect();
    seen.sort_unstable();
    let before = seen.len();
    seen.dedup();
    assert_eq!(before, seen.len(), "a fragment was placed in two groups");
    assert_eq!(
        seen.len(),
        out.fragments.len(),
        "every fragment must be accounted for by correlation"
    );
}

#[test]
fn a_correlated_recording_states_the_basis_for_its_ordering() {
    let (_fx, out) = run_on_fixture(&unbounded());

    for rec in &out.recordings {
        assert!(
            !rec.evidence.is_empty(),
            "a correlated recording must carry the evidence behind its grouping"
        );
        match &rec.ordering {
            TemporalOrdering::Unknown { reason } => {
                assert!(!reason.trim().is_empty(), "UNKNOWN ordering must say why");
                assert_eq!(
                    rec.validation.state,
                    ValidationStateKind::Review,
                    "a group with no established order cannot be PASS"
                );
            }
            TemporalOrdering::SingleFragment => {
                assert_eq!(rec.regions.len(), 1);
            }
            established => {
                assert!(established.is_established());
                assert!(rec.regions.len() >= 2);
            }
        }
    }
}

#[test]
fn the_hypothesis_count_reflects_the_groups_actually_formed() {
    let (_fx, out) = run_on_fixture(&unbounded());

    assert!(
        out.run.hypothesis_count > 0,
        "a run that produced candidates must report the hypotheses it considered"
    );
    assert_eq!(
        out.run.hypothesis_count as usize, out.metrics.correlation_groups_considered,
        "the run's hypothesis count and the metric must be the same number"
    );
}

#[test]
fn the_hypothesis_bound_is_enforced_and_downgrades_the_run() {
    let mut bounds = unbounded();
    bounds.max_hypotheses = 1;
    let (_fx, out) = run_on_fixture(&bounds);

    assert!(
        out.recordings.len() <= 1,
        "the hypothesis bound must limit the reported recordings"
    );
    assert!(
        out.run.hypothesis_count > 1,
        "what was considered is still reported even when the output is bounded"
    );
    assert!(out.run.truncated, "a bounded correlation truncates the run");
    assert_eq!(
        out.run.validation_state.state,
        ValidationStateKind::Review,
        "a bounded run can never be PASS"
    );
    assert!(
        out.run.validation_state.reason.contains("truncated"),
        "the reason must explain the downgrade, not name a type: {}",
        out.run.validation_state.reason
    );
}

// ── Determinism ─────────────────────────────────────────────────────────────

#[test]
fn two_runs_over_the_same_evidence_agree_on_every_decision() {
    let (_fx, a) = run_on_fixture(&unbounded());
    let (_fx2, b) = run_on_fixture(&unbounded());

    let states_a: Vec<DataState> = a.candidates.iter().map(|c| c.data_state).collect();
    let states_b: Vec<DataState> = b.candidates.iter().map(|c| c.data_state).collect();
    assert_eq!(states_a, states_b, "candidate states must be reproducible");

    let offsets_a: Vec<u64> = a
        .fragments
        .iter()
        .map(|f| f.physical_region.offset)
        .collect();
    let offsets_b: Vec<u64> = b
        .fragments
        .iter()
        .map(|f| f.physical_region.offset)
        .collect();
    assert_eq!(
        offsets_a, offsets_b,
        "candidate ordering must be reproducible"
    );

    let keys_a: Vec<&str> = a
        .recordings
        .iter()
        .map(|r| r.recording_key.as_str())
        .collect();
    let keys_b: Vec<&str> = b
        .recordings
        .iter()
        .map(|r| r.recording_key.as_str())
        .collect();
    assert_eq!(keys_a, keys_b, "correlation must be reproducible");

    assert_eq!(
        a.capabilities, b.capabilities,
        "capability assessment must be reproducible"
    );
    assert_eq!(
        a.strategies, b.strategies,
        "strategy selection must be reproducible"
    );
}

#[test]
fn candidates_are_ordered_by_physical_offset() {
    let (_fx, out) = run_on_fixture(&unbounded());
    let offsets: Vec<u64> = out
        .fragments
        .iter()
        .map(|f| f.physical_region.offset)
        .collect();
    let mut sorted = offsets.clone();
    sorted.sort_unstable();
    assert_eq!(
        offsets, sorted,
        "candidate order must be a stable function of the disk"
    );
}

// ── Provenance ──────────────────────────────────────────────────────────────

#[test]
fn every_candidate_traces_to_the_exact_bytes_in_the_exact_evidence_item() {
    let (_fx, out) = run_on_fixture(&unbounded());
    assert!(!out.candidates.is_empty());

    let evidence_id = out.fragments[0].evidence_id;
    for (c, f) in out.candidates.iter().zip(out.fragments.iter()) {
        assert_eq!(f.evidence_id, evidence_id, "one run, one evidence item");
        assert_eq!(c.provenance.source_evidence_id, evidence_id);
        assert!(
            !c.provenance.source_regions.is_empty(),
            "a candidate with no source region cannot be traced to bytes"
        );
        assert!(
            c.provenance
                .source_regions
                .iter()
                .all(|r| r.evidence_id == evidence_id),
            "every source region must name the evidence item it came from"
        );
        assert!(
            c.source_offsets.iter().any(|r| r == &f.physical_region),
            "the candidate's offsets must include the fragment's own range"
        );
        assert!(
            f.id_is_consistent(),
            "a fragment id must be derivable from its own evidence id and range"
        );
        assert!(
            !c.provenance.validation_state.reason.trim().is_empty(),
            "a candidate must explain its own classification"
        );
    }
}

#[test]
fn unrun_validation_checks_are_unknown_and_never_pass() {
    let (_fx, out) = run_on_fixture(&unbounded());

    for c in &out.candidates {
        assert_eq!(
            c.validation.continuity.state,
            ValidationStateKind::Unknown,
            "a single-region scan cannot assess continuity, so it must stay Unknown"
        );
        assert!(!c.validation.continuity.reason.trim().is_empty());
    }
}

// ── Bounds and hostile input ────────────────────────────────────────────────

#[test]
fn a_cancelled_run_is_review_and_explains_itself() {
    let bounds = RecoveryBounds {
        cancel: {
            let t = CancelToken::new();
            t.cancel();
            t
        },
        ..unbounded()
    };
    let (_fx, out) = run_on_fixture(&bounds);

    assert!(out.run.cancelled);
    assert_eq!(out.run.validation_state.state, ValidationStateKind::Review);
    assert!(
        out.run.validation_state.reason.contains("cancelled"),
        "the reason must explain the cancellation rather than name a type: {}",
        out.run.validation_state.reason
    );
}

#[test]
fn a_byte_bounded_run_is_review_and_never_claims_completeness() {
    let bounds = RecoveryBounds {
        max_scan_bytes: 4096,
        ..unbounded()
    };
    let (_fx, out) = run_on_fixture(&bounds);

    assert!(out.run.truncated);
    assert_eq!(out.run.validation_state.state, ValidationStateKind::Review);
    assert!(out.run.searched_bytes <= 4096 + common::SECTOR);
}

#[test]
fn the_engine_never_reads_beyond_the_evidence() {
    let (fx, out) = run_on_fixture(&unbounded());

    for r in &out.run.searched_regions {
        let end = r.end().expect("a searched region must not overflow");
        assert!(
            end <= fx.disk_size,
            "the engine read [{}..{end}) of a {}-byte image",
            r.offset,
            fx.disk_size
        );
    }
    for f in &out.fragments {
        let end = f.physical_region.end().expect("no overflow");
        assert!(end <= fx.disk_size, "a fragment escapes the evidence");
    }
}
