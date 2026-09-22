//! Overwritten/unrecoverable classification rules (Req 13.3, 13.7, 13.8, 13.11).
//!
//! Constraints:
//! - Corrupted != Unrecoverable (Req 13.7)
//! - DataState and RecoveryStatus are independent (Req 13.8)
//! - Missing index != overwritten (Req 13.11)
//! - Only confirmed physical overwrite evidence → Overwritten state (Req 13.3)

use forensic_core::{DataState, RecoveryAssessment, RecoveryLevel, RecoveryStatus};
use parsers_core::storage::AllocationEvidence;
use serde::{Deserialize, Serialize};

use crate::claims::{ClaimAccessibility, ClaimMap, ClaimedRegion, UnclaimedKind};

/// What the OEM's index evidence says about one specific physical region.
///
/// This type is the whole point of the phase: it is produced *only* from index/geometry
/// evidence, and it is the sole input to state classification. Recognising the OEM,
/// finding a container signature, or successfully classifying a codec can never
/// construct an [`RegionClaim::Indexed`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RegionClaim {
    /// An authoritative index entry claims these bytes.
    Indexed {
        /// Identifier of the claiming index entry, for provenance.
        recording_id: String,
        /// The OEM partition the entry came from, when the storage is partitioned.
        partition: Option<u32>,
        /// Channel, only if the index recorded one.
        channel: Option<u32>,
        /// Start time as unix seconds, only if the index recorded one.
        start_time_unix: Option<i64>,
        /// End time as unix seconds, only if the index recorded one.
        end_time_unix: Option<i64>,
        /// Allocation state the OEM structures record for that entry.
        allocation: AllocationEvidence,
    },
    /// OEM metadata describing these bytes **survives**, but the recorder does not reach the
    /// recording through its current structures — the *available* case.
    ///
    /// This is stronger evidence than an unreferenced gap: the recorder's own structures still
    /// say what channel this was and when it ran, they just no longer reach it. It is
    /// nonetheless **not** a deletion finding; that needs
    /// [`AllocationEvidence::FreeMarked`].
    AvailableUnreferenced {
        /// Identifier of the metadata entry that describes these bytes.
        recording_id: String,
        partition: Option<u32>,
        channel: Option<u32>,
        start_time_unix: Option<i64>,
        end_time_unix: Option<i64>,
        allocation: AllocationEvidence,
        /// The OEM's own account of why the recording is no longer reachable.
        reason: String,
    },
    /// An authoritative index governs these bytes and does **not** claim them. This is
    /// positive evidence of non-reference, and the only basis for an orphan finding.
    UnclaimedWithinIndexScope {
        /// How many entries the authoritative index contained, for the explanation.
        index_entry_count: usize,
    },
    /// These bytes lie outside the scope of any authoritative index (or the index was
    /// only partially readable). The index makes no statement here.
    OutsideIndexScope {
        /// Why no authoritative statement covers this region.
        reason: String,
    },
    /// No index evidence exists for this evidence item at all — e.g. an OEM path with
    /// no index reader, or a volume whose index structures were not located.
    NoIndexEvidence {
        /// Why no index evidence is available.
        reason: String,
    },
}

impl RegionClaim {
    /// Resolve the claim for a physical offset from a [`ClaimMap`].
    ///
    /// The lookup is the *only* way production code obtains a claim, which keeps
    /// "is this indexed?" answerable exclusively from index evidence.
    pub fn resolve(map: &ClaimMap, offset: u64) -> RegionClaim {
        if let Some(claim) = map.any_claim_at(offset) {
            return RegionClaim::from_claim(claim);
        }
        match map.kind_at(offset) {
            Some(UnclaimedKind::WithinAuthoritativeIndexScope) => {
                RegionClaim::UnclaimedWithinIndexScope {
                    index_entry_count: map.claims.len(),
                }
            }
            Some(UnclaimedKind::OutsideIndexScope) => {
                if map.has_authoritative_index() {
                    RegionClaim::OutsideIndexScope {
                        reason: format!(
                            "offset 0x{offset:X} lies outside the region the authoritative index governs ({})",
                            map.authoritative_scope
                                .map(|r| r.to_string())
                                .unwrap_or_else(|| "none".into())
                        ),
                    }
                } else {
                    RegionClaim::NoIndexEvidence {
                        reason: "no authoritative recording index was established for this evidence"
                            .to_string(),
                    }
                }
            }
            // Outside the map's universe entirely: we have no statement either way.
            None => RegionClaim::NoIndexEvidence {
                reason: format!(
                    "offset 0x{offset:X} lies outside the analysed address space {}",
                    map.universe
                ),
            },
        }
    }

    /// Build a claim from a resolved [`ClaimedRegion`], preserving whether the recorder still
    /// reaches it.
    pub fn from_claim(claim: &ClaimedRegion) -> RegionClaim {
        match &claim.accessibility {
            ClaimAccessibility::Accessible => RegionClaim::Indexed {
                recording_id: claim.recording_id.clone(),
                partition: claim.partition,
                channel: claim.channel,
                start_time_unix: claim.start_time_unix,
                end_time_unix: claim.end_time_unix,
                allocation: claim.allocation,
            },
            ClaimAccessibility::Available { reason } => RegionClaim::AvailableUnreferenced {
                recording_id: claim.recording_id.clone(),
                partition: claim.partition,
                channel: claim.channel,
                start_time_unix: claim.start_time_unix,
                end_time_unix: claim.end_time_unix,
                allocation: claim.allocation,
                reason: reason.clone(),
            },
        }
    }

    /// Short label for logs and provenance.
    pub fn label(&self) -> &'static str {
        match self {
            RegionClaim::Indexed { .. } => "indexed",
            RegionClaim::AvailableUnreferenced { .. } => "available-unreferenced",
            RegionClaim::UnclaimedWithinIndexScope { .. } => "unclaimed-in-index-scope",
            RegionClaim::OutsideIndexScope { .. } => "outside-index-scope",
            RegionClaim::NoIndexEvidence { .. } => "no-index-evidence",
        }
    }

    /// Recorder metadata this claim supplies, when it supplies any.
    ///
    /// Returned as a tuple so the scanner populates a fragment's channel/time from exactly one
    /// place, and so an unclaimed region's `None`s cannot be confused with zero.
    #[allow(clippy::type_complexity)]
    pub fn recorder_metadata(
        &self,
    ) -> Option<(&str, Option<u32>, Option<u32>, Option<i64>, Option<i64>)> {
        match self {
            RegionClaim::Indexed {
                recording_id,
                partition,
                channel,
                start_time_unix,
                end_time_unix,
                ..
            }
            | RegionClaim::AvailableUnreferenced {
                recording_id,
                partition,
                channel,
                start_time_unix,
                end_time_unix,
                ..
            } => Some((
                recording_id.as_str(),
                *partition,
                *channel,
                *start_time_unix,
                *end_time_unix,
            )),
            _ => None,
        }
    }
}

/// What was established about video data actually present in a region.
///
/// `signature_found` alone is never enough: [`VideoEvidence::structurally_valid`] must
/// come from a validation result, and if validation did not run it is `false` here while
/// the candidate's own validation report records `Unknown` — never `Pass`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoEvidence {
    /// A codec signature / NAL evidence was observed in the region's bytes.
    pub signature_found: bool,
    /// Bytes were actually read from the region.
    pub physically_present: bool,
    /// A validation check ran **and passed**. Not "a signature matched".
    pub structurally_valid: bool,
}

/// The classification outcome for one region, with the reasoning that produced it.
#[derive(Debug, Clone, PartialEq)]
pub struct StateAssessment {
    pub data_state: DataState,
    pub recovery_status: RecoveryStatus,
    /// The recovery level this discovery path corresponds to.
    pub recovery_level: RecoveryLevel,
    /// Why this state was assigned, phrased so it can be shown to an examiner verbatim.
    pub reason: String,
}

/// Classify a region from index evidence plus video evidence.
///
/// Returns `None` when the region holds no video at all — a region with no codec
/// evidence is not a recovered video candidate and must not be reported as one.
///
/// # Rules
///
/// | index evidence                    | video          | state       |
/// |-----------------------------------|----------------|-------------|
/// | indexed, allocated/unknown        | valid          | `Active`    |
/// | indexed, free-marked              | valid          | `Deleted`   |
/// | available (metadata, unreachable) | valid          | `Orphaned`  |
/// | available **and** free-marked     | valid          | `Deleted`   |
/// | unclaimed within index scope      | valid          | `Orphaned`  |
/// | outside index scope               | valid          | `Unindexed` |
/// | no index evidence                 | valid          | `Unindexed` |
/// | any                               | signature only | `Corrupted` |
///
/// Two rules are load-bearing and deliberately absent:
///
/// * There is no "not in index ⇒ deleted" path. Unreferenced data reaches `Orphaned`
///   only with an authoritative index behind it, and otherwise stays `Unindexed`.
/// * Recognising the OEM cannot produce `Active`. `Active` requires an `Indexed` claim,
///   which only [`RecordingIndex`](parsers_core::storage::RecordingIndex) evidence builds.
pub fn classify_region_state(
    claim: &RegionClaim,
    video: VideoEvidence,
) -> Option<StateAssessment> {
    if !video.physically_present || !video.signature_found {
        return None;
    }

    // Structurally invalid data is reported as Corrupted regardless of index evidence.
    // Promoting it to Active or Orphaned would assert a conclusion about a recording we
    // have not established is a recording. Corrupted is not Unrecoverable.
    if !video.structurally_valid {
        return Some(StateAssessment {
            data_state: DataState::Corrupted,
            recovery_status: RecoveryStatus::PartiallyRecoverable,
            recovery_level: match claim {
                RegionClaim::Indexed { .. } => RecoveryLevel::L1,
                RegionClaim::AvailableUnreferenced { .. }
                | RegionClaim::UnclaimedWithinIndexScope { .. } => RecoveryLevel::L2,
                _ => RecoveryLevel::L3,
            },
            reason: format!(
                "Codec signature present but structural validation did not pass, so no recording-level conclusion is drawn ({} region)",
                claim.label()
            ),
        });
    }

    let assessment = match claim {
        RegionClaim::Indexed {
            recording_id,
            allocation: AllocationEvidence::FreeMarked,
            ..
        } => StateAssessment {
            data_state: DataState::Deleted,
            recovery_status: RecoveryStatus::Recoverable,
            recovery_level: RecoveryLevel::L1,
            reason: format!(
                "Index entry {recording_id} claims this region but the OEM structures mark the entry free; valid video is still physically present"
            ),
        },
        RegionClaim::Indexed {
            recording_id,
            allocation,
            ..
        } => StateAssessment {
            data_state: DataState::Active,
            recovery_status: RecoveryStatus::Recoverable,
            recovery_level: RecoveryLevel::L1,
            reason: format!(
                "Region is claimed by authoritative index entry {recording_id} (allocation: {allocation:?}) and valid video was validated there"
            ),
        },
        // Available metadata that the OEM *also* marks free is the one case where a deletion
        // finding is supported, and it is supported by the allocation field, not by
        // unreachability.
        RegionClaim::AvailableUnreferenced {
            recording_id,
            allocation: AllocationEvidence::FreeMarked,
            reason,
            ..
        } => StateAssessment {
            data_state: DataState::Deleted,
            recovery_status: RecoveryStatus::Recoverable,
            recovery_level: RecoveryLevel::L2,
            reason: format!(
                "OEM metadata entry {recording_id} still describes this region and the OEM \
                 structures mark it free, which is explicit deallocation evidence; valid video is \
                 still physically present. Reachability: {reason}"
            ),
        },
        RegionClaim::AvailableUnreferenced {
            recording_id,
            partition,
            reason,
            ..
        } => StateAssessment {
            data_state: DataState::Orphaned,
            recovery_status: RecoveryStatus::Recoverable,
            recovery_level: RecoveryLevel::L2,
            reason: format!(
                "Valid video is physically present here and the recorder's own metadata entry \
                 {recording_id}{partition_note} still describes it, but the recording is not part \
                 of the accessible recording set: {reason}. Reported as orphaned; this is not \
                 evidence of deletion, and no deallocation marker was found",
                partition_note = partition
                    .map(|p| format!(" in partition {p}"))
                    .unwrap_or_default()
            ),
        },
        RegionClaim::UnclaimedWithinIndexScope { index_entry_count } => StateAssessment {
            data_state: DataState::Orphaned,
            recovery_status: RecoveryStatus::Recoverable,
            recovery_level: RecoveryLevel::L2,
            reason: format!(
                "Valid video is physically present here, and the authoritative recording index ({index_entry_count} entr{plural}) governs this region without referencing it - the recording is no longer indexed",
                plural = if *index_entry_count == 1 { "y" } else { "ies" }
            ),
        },
        RegionClaim::OutsideIndexScope { reason } => StateAssessment {
            data_state: DataState::Unindexed,
            recovery_status: RecoveryStatus::Recoverable,
            recovery_level: RecoveryLevel::L3,
            reason: format!(
                "Valid video discovered, but no authoritative index statement covers these bytes ({reason}); recorded as unindexed, which is not evidence of deletion"
            ),
        },
        RegionClaim::NoIndexEvidence { reason } => StateAssessment {
            data_state: DataState::Unindexed,
            recovery_status: RecoveryStatus::Recoverable,
            recovery_level: RecoveryLevel::L3,
            reason: format!(
                "Valid video discovered without index linkage ({reason}); recorded as unindexed, which is not evidence of deletion"
            ),
        },
    };
    Some(assessment)
}

/// Classifies a candidate's data state and recovery status based on evidence.
/// This function enforces all the independence constraints from the requirements.
///
/// Retained for callers that only have the four coarse booleans (the API's
/// parser-recording path). Index-aware recovery uses [`classify_region_state`], which
/// takes actual index evidence instead of a `has_index_entry` flag.
pub fn classify_recovery(
    has_index_entry: bool,
    is_physically_present: bool,
    is_structurally_valid: bool,
    has_overwrite_evidence: bool,
) -> RecoveryAssessment {
    let data_state = if has_overwrite_evidence {
        // Only confirmed physical overwrite evidence → Overwritten (Req 13.3)
        DataState::Overwritten
    } else if !has_index_entry && is_physically_present {
        // Missing index but payload exists → Orphaned, NOT Overwritten (Req 13.11)
        DataState::Orphaned
    } else if !is_structurally_valid {
        DataState::Corrupted
    } else if has_index_entry && !is_physically_present {
        DataState::Deleted
    } else {
        DataState::Active
    };

    let recovery_status = if has_overwrite_evidence && !is_physically_present {
        RecoveryStatus::Unrecoverable
    } else if !is_structurally_valid && is_physically_present {
        // Corrupted != Unrecoverable (Req 13.7) — corrupted data may still be partially recoverable
        RecoveryStatus::PartiallyRecoverable
    } else if is_physically_present {
        RecoveryStatus::Recoverable
    } else {
        RecoveryStatus::Unrecoverable
    };

    RecoveryAssessment {
        data_state,
        recovery_status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: VideoEvidence = VideoEvidence {
        signature_found: true,
        physically_present: true,
        structurally_valid: true,
    };
    const SIGNATURE_ONLY: VideoEvidence = VideoEvidence {
        signature_found: true,
        physically_present: true,
        structurally_valid: false,
    };
    const NO_VIDEO: VideoEvidence = VideoEvidence {
        signature_found: false,
        physically_present: true,
        structurally_valid: false,
    };

    fn indexed(allocation: AllocationEvidence) -> RegionClaim {
        RegionClaim::Indexed {
            recording_id: "didx#2".into(),
            partition: Some(0),
            channel: Some(1),
            start_time_unix: Some(1_700_000_000),
            end_time_unix: None,
            allocation,
        }
    }

    fn available(allocation: AllocationEvidence) -> RegionClaim {
        RegionClaim::AvailableUnreferenced {
            recording_id: "dahua:p0:blk7".into(),
            partition: Some(0),
            channel: Some(3),
            start_time_unix: Some(1_700_000_000),
            end_time_unix: Some(1_700_000_600),
            allocation,
            reason: "no traversal from a declared first block reached these blocks".into(),
        }
    }

    // ── Candidate classification ────────────────────────────────────────────

    #[test]
    fn indexed_plus_valid_video_is_active() {
        let a = classify_region_state(&indexed(AllocationEvidence::Allocated), VALID).unwrap();
        assert_eq!(a.data_state, DataState::Active);
        assert_eq!(a.recovery_status, RecoveryStatus::Recoverable);
        assert_eq!(a.recovery_level, RecoveryLevel::L1);
        assert!(a.reason.contains("didx#2"), "reason must cite the index entry");
    }

    #[test]
    fn unclaimed_within_authoritative_index_scope_plus_valid_video_is_orphaned() {
        let claim = RegionClaim::UnclaimedWithinIndexScope {
            index_entry_count: 6,
        };
        let a = classify_region_state(&claim, VALID).unwrap();
        assert_eq!(a.data_state, DataState::Orphaned);
        assert_eq!(a.recovery_level, RecoveryLevel::L2);
        assert!(
            a.reason.contains("no longer indexed"),
            "the orphan finding must be explained: {}",
            a.reason
        );
    }

    #[test]
    fn valid_video_without_index_evidence_is_unindexed_not_deleted() {
        let claim = RegionClaim::NoIndexEvidence {
            reason: "OEM path has no index reader".into(),
        };
        let a = classify_region_state(&claim, VALID).unwrap();
        assert_eq!(a.data_state, DataState::Unindexed);
        assert_ne!(a.data_state, DataState::Deleted, "unindexed != deleted");
        assert_ne!(a.data_state, DataState::Orphaned, "unindexed != orphaned");
        assert_ne!(a.data_state, DataState::Active);
        assert_eq!(a.recovery_level, RecoveryLevel::L3);
    }

    #[test]
    fn valid_video_outside_the_index_scope_is_unindexed_not_orphaned() {
        // An authoritative index exists, but it does not govern these bytes, so its
        // silence here is not evidence of anything.
        let claim = RegionClaim::OutsideIndexScope {
            reason: "past the end of the declared video region".into(),
        };
        let a = classify_region_state(&claim, VALID).unwrap();
        assert_eq!(a.data_state, DataState::Unindexed);
        assert_ne!(a.data_state, DataState::Orphaned);
        assert!(a.reason.contains("not evidence of deletion"));
    }

    #[test]
    fn available_metadata_plus_valid_video_is_orphaned_never_deleted() {
        for allocation in [AllocationEvidence::Unknown, AllocationEvidence::Allocated] {
            let a = classify_region_state(&available(allocation), VALID).unwrap();
            assert_eq!(a.data_state, DataState::Orphaned, "allocation {allocation:?}");
            assert_ne!(a.data_state, DataState::Deleted);
            assert_ne!(a.data_state, DataState::Active, "available is not active");
            assert_eq!(a.recovery_level, RecoveryLevel::L2);
            assert_eq!(a.recovery_status, RecoveryStatus::Recoverable);
            assert!(
                a.reason.contains("not evidence of deletion"),
                "the finding must say so: {}",
                a.reason
            );
            assert!(a.reason.contains("dahua:p0:blk7"), "cite the metadata entry");
            assert!(a.reason.contains("partition 0"));
        }
    }

    #[test]
    fn available_metadata_that_is_also_free_marked_is_deleted_on_the_allocation_evidence() {
        // The deletion conclusion comes from the free marker, not from unreachability.
        let a = classify_region_state(&available(AllocationEvidence::FreeMarked), VALID).unwrap();
        assert_eq!(a.data_state, DataState::Deleted);
        assert!(a.reason.contains("explicit deallocation evidence"));
        // Still recoverable: the two dimensions stay independent.
        assert_eq!(a.recovery_status, RecoveryStatus::Recoverable);
    }

    #[test]
    fn available_metadata_with_only_a_signature_is_corrupted_at_l2() {
        let a = classify_region_state(&available(AllocationEvidence::Unknown), SIGNATURE_ONLY)
            .unwrap();
        assert_eq!(a.data_state, DataState::Corrupted);
        assert_eq!(a.recovery_level, RecoveryLevel::L2);
        assert_eq!(a.recovery_status, RecoveryStatus::PartiallyRecoverable);
    }

    #[test]
    fn claims_expose_their_recorder_metadata_and_unclaimed_regions_expose_none() {
        let claim = available(AllocationEvidence::Unknown);
        let (id, partition, channel, start, end) = claim.recorder_metadata().unwrap();
        assert_eq!(id, "dahua:p0:blk7");
        assert_eq!(partition, Some(0));
        assert_eq!(channel, Some(3));
        assert_eq!(start, Some(1_700_000_000));
        assert_eq!(end, Some(1_700_000_600));

        assert!(RegionClaim::UnclaimedWithinIndexScope {
            index_entry_count: 1
        }
        .recorder_metadata()
        .is_none());
        assert!(RegionClaim::NoIndexEvidence {
            reason: "x".into()
        }
        .recorder_metadata()
        .is_none());
    }

    #[test]
    fn index_entry_marked_free_is_deleted_not_orphaned() {
        let a = classify_region_state(&indexed(AllocationEvidence::FreeMarked), VALID).unwrap();
        assert_eq!(a.data_state, DataState::Deleted);
        // Deleted-but-present data is still recoverable; the two dimensions stay independent.
        assert_eq!(a.recovery_status, RecoveryStatus::Recoverable);
    }

    #[test]
    fn signature_without_passing_validation_is_corrupted_never_active() {
        for claim in [
            indexed(AllocationEvidence::Allocated),
            RegionClaim::UnclaimedWithinIndexScope { index_entry_count: 3 },
            RegionClaim::NoIndexEvidence { reason: "none".into() },
        ] {
            let a = classify_region_state(&claim, SIGNATURE_ONLY).unwrap();
            assert_eq!(
                a.data_state,
                DataState::Corrupted,
                "a signature match is not a valid video for claim {}",
                claim.label()
            );
            assert_eq!(a.recovery_status, RecoveryStatus::PartiallyRecoverable);
        }
    }

    #[test]
    fn no_codec_evidence_is_not_a_recovered_candidate() {
        assert!(classify_region_state(&indexed(AllocationEvidence::Allocated), NO_VIDEO).is_none());
        assert!(classify_region_state(
            &RegionClaim::UnclaimedWithinIndexScope { index_entry_count: 1 },
            NO_VIDEO
        )
        .is_none());
    }

    #[test]
    fn absent_bytes_are_not_a_recovered_candidate() {
        let absent = VideoEvidence {
            signature_found: true,
            physically_present: false,
            structurally_valid: true,
        };
        assert!(classify_region_state(&indexed(AllocationEvidence::Unknown), absent).is_none());
    }

    #[test]
    fn overwritten_is_never_inferred_from_missing_index_linkage() {
        for claim in [
            available(AllocationEvidence::Unknown),
            available(AllocationEvidence::FreeMarked),
            RegionClaim::UnclaimedWithinIndexScope { index_entry_count: 2 },
            RegionClaim::OutsideIndexScope { reason: "x".into() },
            RegionClaim::NoIndexEvidence { reason: "x".into() },
        ] {
            for video in [VALID, SIGNATURE_ONLY] {
                if let Some(a) = classify_region_state(&claim, video) {
                    assert_ne!(
                        a.data_state,
                        DataState::Overwritten,
                        "Overwritten requires positive overwrite evidence"
                    );
                }
            }
        }
    }

    #[test]
    fn claim_resolution_comes_only_from_index_evidence() {
        use crate::claims::empty_claim_map;
        use forensic_core::Region;

        // A claim map with no index evidence can never resolve to Indexed, no matter the
        // offset — so nothing downstream of it can reach Active.
        let map = empty_claim_map(Region::new(0, 4096).unwrap()).unwrap();
        for offset in [0u64, 1, 2048, 4095] {
            let claim = RegionClaim::resolve(&map, offset);
            assert!(
                matches!(claim, RegionClaim::NoIndexEvidence { .. }),
                "unexpected claim at {offset}: {claim:?}"
            );
            let a = classify_region_state(&claim, VALID).unwrap();
            assert_eq!(a.data_state, DataState::Unindexed);
        }
    }

    // ── Legacy coarse classifier ────────────────────────────────────────────

    #[test]
    fn test_corrupted_is_not_automatically_unrecoverable() {
        // Req 13.7: Corrupted != Unrecoverable
        let assessment = classify_recovery(true, true, false, false);
        assert_eq!(assessment.data_state, DataState::Corrupted);
        assert_eq!(assessment.recovery_status, RecoveryStatus::PartiallyRecoverable);
    }

    #[test]
    fn test_missing_index_is_orphaned_not_overwritten() {
        // Req 13.11: Missing index != overwritten
        let assessment = classify_recovery(false, true, true, false);
        assert_eq!(assessment.data_state, DataState::Orphaned);
        assert_eq!(assessment.recovery_status, RecoveryStatus::Recoverable);
    }

    #[test]
    fn test_confirmed_overwrite_is_overwritten() {
        let assessment = classify_recovery(true, false, false, true);
        assert_eq!(assessment.data_state, DataState::Overwritten);
        assert_eq!(assessment.recovery_status, RecoveryStatus::Unrecoverable);
    }

    #[test]
    fn test_active_data() {
        let assessment = classify_recovery(true, true, true, false);
        assert_eq!(assessment.data_state, DataState::Active);
        assert_eq!(assessment.recovery_status, RecoveryStatus::Recoverable);
    }

    #[test]
    fn test_deleted_data() {
        let assessment = classify_recovery(true, false, true, false);
        assert_eq!(assessment.data_state, DataState::Deleted);
        assert_eq!(assessment.recovery_status, RecoveryStatus::Unrecoverable);
    }
}
