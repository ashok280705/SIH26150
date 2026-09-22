//! # Region scanning and candidate construction
//!
//! One bounded read of one [`ScanTarget`], turned into at most one
//! [`RecoveryCandidate`] plus its [`DiscoveredFragment`].
//!
//! ## What changed and why
//!
//! This module previously exposed `recover_l1_indexed` / `recover_l2_orphan` /
//! `recover_l3_carve`, dispatched as a cascade: L1 gated on
//! `Parser::recognize_candidate()`, and if L1 produced anything, L2 and L3 never ran.
//! Because every OEM parser returned `Ok(true)` unconditionally, L1 claimed every
//! codec-bearing chunk and passed `has_index_entry = true` — a literal, not evidence —
//! into classification. The result was that recognising the OEM made every region
//! `Active` and made the orphan/unindexed paths unreachable in production.
//!
//! The cascade is gone. There is now a single path: the planner decides *what* to read
//! and attaches the index-derived [`RegionClaim`] to it, this module reads the bytes and
//! establishes what video is there, and [`classify_region_state`] combines the two. The
//! recovery level is a *consequence* of the claim, not a dispatch decision.
//!
//! Format recognition (`recognize_candidate`) is still consulted, but only as a
//! corroborating observation recorded on the candidate. It cannot change the data state.

use evidence_reader::{BoundedReader, EvidenceReader};
use forensic_core::{
    EvidenceId, ForensicError, FrameValidationReport, Hash, OemProfile, Provenance,
    RecoveryCandidate, RecoveryLevel, Region, SourceRegion, TransformationStep, ValidationState,
    ValidationStateKind,
};
use parsers_core::parser::Parser;
use sha2::{Digest, Sha256};

use crate::classification::{classify_region_state, RegionClaim, StateAssessment, VideoEvidence};
use crate::fragment::{DiscoveredFragment, DiscoveryMethod, FieldEvidence};
use crate::plan::ScanTarget;
use crate::reconstructor::{CodecEvidence, VideoCodec, VideoReconstructor};

/// Largest window a single scan will pull into memory in one pass. Regions larger than
/// this are examined only up to this bound and the candidate is marked as a partial read.
const MAX_WINDOW_BYTES: u64 = 8 * 1024 * 1024;

/// Immutable context shared by every scan in one recovery run.
///
/// Carrying the [`EvidenceId`] here is what keeps provenance intact: it is supplied once
/// by the caller that owns the evidence item and propagated to every candidate and
/// fragment. Nothing downstream mints a new one.
#[derive(Debug, Clone)]
pub struct ScanContext {
    /// The evidence item being recovered from.
    pub evidence_id: EvidenceId,
    /// OEM key the run is executing under.
    pub oem_key: String,
    /// Profile id applied.
    pub profile_id: String,
    /// Profile version applied.
    pub profile_version: String,
    /// Hash of the profile applied.
    pub profile_hash: Option<Hash>,
    /// Parser id and version, for provenance.
    pub parser_id: String,
    pub parser_version: String,
}

/// The result of scanning one target that held video.
#[derive(Debug, Clone)]
pub struct ScanFinding {
    pub candidate: RecoveryCandidate,
    pub fragment: DiscoveredFragment,
    /// Whether the OEM parser recognised its own container framing in these bytes.
    /// Recorded for the examiner; never an input to the data state.
    pub oem_format_recognised: bool,
}

/// Read up to [`MAX_WINDOW_BYTES`] of a region through a [`BoundedReader`].
///
/// Returns the bytes read and whether the region was longer than the window. Overflowing
/// or out-of-bounds regions propagate the `BoundedReader` error unchanged — hostile
/// offsets never panic.
fn read_bounded_window(
    reader: &dyn EvidenceReader,
    region: &Region,
) -> Result<(Vec<u8>, bool), ForensicError> {
    // Constructing the bounded reader is what enforces checked arithmetic and bounds.
    let bounded = BoundedReader::new(reader, region.offset, region.length)?;
    let want = region.length.min(MAX_WINDOW_BYTES) as usize;
    let truncated_view = region.length > MAX_WINDOW_BYTES;

    let mut buf = vec![0u8; want];
    let n = bounded.read_at(0, &mut buf)?;
    buf.truncate(n);
    Ok((buf, truncated_view))
}

/// SHA-256 digest of a byte slice, wrapped as a `Hash`.
fn digest(bytes: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Hash::sha256(hasher.finalize().to_vec())
}

/// Total `ValidationState` constructor: `ValidationState::new` only rejects an empty
/// reason, and the static fallback is non-empty, so no panic path is introduced.
fn vs(
    kind: ValidationStateKind,
    reason: impl Into<String>,
    op: &str,
    subject: &str,
) -> ValidationState {
    let reason = reason.into();
    ValidationState::new(kind, reason, op, subject).unwrap_or_else(|_| {
        ValidationState::new(kind, "reason unavailable", op, subject)
            .expect("static fallback reason is non-empty")
    })
}

/// Build a `FrameValidationReport` from codec evidence and index evidence.
///
/// Checks that did not run are `Unknown`, never `Pass`. In particular `timestamps` and
/// `channel` are only `Pass` when the *index* supplied those values; a raw stream scan
/// has no recorder clock and no channel, so claiming otherwise would be fabrication.
fn validation_report(
    codec: &CodecEvidence,
    structurally_valid: bool,
    claim: &RegionClaim,
) -> FrameValidationReport {
    let signatures = if codec.codec != VideoCodec::Unknown || !codec.nal_evidence.is_empty() {
        vs(
            ValidationStateKind::Pass,
            format!(
                "{:?} NAL/marker signature(s) observed ({} unit(s))",
                codec.codec,
                codec.nal_evidence.len()
            ),
            "region_scan",
            "signatures",
        )
    } else {
        vs(
            ValidationStateKind::Review,
            "No decodable codec signature in window",
            "region_scan",
            "signatures",
        )
    };

    let structure = if structurally_valid {
        vs(
            ValidationStateKind::Pass,
            codec.validation.reason.clone(),
            "region_scan",
            "structure",
        )
    } else {
        vs(
            ValidationStateKind::Review,
            codec.validation.reason.clone(),
            "region_scan",
            "structure",
        )
    };

    let (timestamps, channel) = match claim {
        RegionClaim::Indexed {
            recording_id,
            channel: ch,
            start_time_unix,
            ..
        } => {
            let ts = match start_time_unix {
                Some(t) => vs(
                    ValidationStateKind::Pass,
                    format!("Recorder timestamp {t} read from index entry {recording_id}"),
                    "region_scan",
                    "timestamps",
                ),
                None => vs(
                    ValidationStateKind::Unknown,
                    format!("Index entry {recording_id} records no timestamp for this region"),
                    "region_scan",
                    "timestamps",
                ),
            };
            let chan = match ch {
                Some(c) => vs(
                    ValidationStateKind::Pass,
                    format!("Channel {c} read from index entry {recording_id}"),
                    "region_scan",
                    "channel",
                ),
                None => vs(
                    ValidationStateKind::Unknown,
                    format!("Index entry {recording_id} records no channel for this region"),
                    "region_scan",
                    "channel",
                ),
            };
            (ts, chan)
        }
        _ => (
            vs(
                ValidationStateKind::Unknown,
                "No index entry covers this region, so no recorder timestamp is available",
                "region_scan",
                "timestamps",
            ),
            vs(
                ValidationStateKind::Unknown,
                "No index entry covers this region, so no channel is available",
                "region_scan",
                "channel",
            ),
        ),
    };

    FrameValidationReport {
        signatures,
        structure,
        timestamps,
        channel,
        // Continuity is a multi-fragment property. A single-region scan cannot assess it,
        // and an unrun check is Unknown.
        continuity: vs(
            ValidationStateKind::Unknown,
            "Frame continuity is not assessed by a single-region scan",
            "region_scan",
            "continuity",
        ),
    }
}

/// Assemble the provenance chain for a finding.
///
/// The chain recorded here is:
/// `evidence item → planner region → scanned region → candidate`.
/// `source_evidence_id` and every `SourceRegion::evidence_id` are the caller's real
/// evidence id, so a candidate is always traceable to the exact bytes it came from in
/// the exact evidence item it came from.
fn build_provenance(
    ctx: &ScanContext,
    target: &ScanTarget,
    window: &[u8],
    assessment: &StateAssessment,
    truncated_view: bool,
) -> Provenance {
    let level_str = level_label(assessment.recovery_level);
    let mut reason = format!("{level_str}: {}", assessment.reason);
    if truncated_view {
        reason.push_str(
            "; window truncated to the scan cap, bytes beyond the cap were not examined",
        );
    }

    let prov_state = vs(
        if truncated_view {
            ValidationStateKind::Review
        } else {
            ValidationStateKind::Pass
        },
        reason,
        "recovery_scan",
        "RecoveryCandidate",
    );

    let mut source_regions = vec![SourceRegion::new(ctx.evidence_id, target.region)
        .with_description(format!(
            "scanned region, discovery method {}",
            target.discovery_method.label()
        ))];
    // Record the planner region separately when the scan only covered part of it, so the
    // provenance shows both what was targeted and what was actually read.
    if target.originating_region != target.region {
        source_regions.push(
            SourceRegion::new(ctx.evidence_id, target.originating_region).with_description(
                format!(
                    "originating {} region",
                    match target.discovery_method {
                        DiscoveryMethod::IndexClaimedProbe => "index-claimed",
                        _ => "unclaimed",
                    }
                ),
            ),
        );
    }

    let mut provenance = Provenance::new(
        ctx.evidence_id,
        digest(window),
        source_regions,
        "recovery-engine",
        env!("CARGO_PKG_VERSION"),
        digest(window),
        prov_state,
    );
    provenance.profile_version = Some(ctx.profile_version.clone());
    provenance.profile_hash = ctx.profile_hash.clone();
    provenance.parser_version = Some(format!("{}@{}", ctx.parser_id, ctx.parser_version));
    provenance.recovery_level = Some(level_str.to_string());
    provenance.add_transformation(TransformationStep {
        operation: format!("region_scan[{}]", target.discovery_method.label()),
        component: "recovery-engine".to_string(),
        component_version: env!("CARGO_PKG_VERSION").to_string(),
        performed_at: chrono::Utc::now(),
        notes: Some(format!(
            "claim={}, region={}, profile={}",
            target.claim.label(),
            target.region,
            ctx.profile_id
        )),
    });
    provenance
}

/// Stable string label for a recovery level.
pub fn level_label(level: RecoveryLevel) -> &'static str {
    match level {
        RecoveryLevel::L1 => "L1",
        RecoveryLevel::L2 => "L2",
        RecoveryLevel::L3 => "L3",
    }
}

/// Build the fragment record for a finding.
///
/// Recorder metadata is populated **only** from the index claim. A fragment found in
/// unclaimed space carries explicit `Unknown` values with the reason attached, rather
/// than channel 0 at the epoch.
fn build_fragment(
    ctx: &ScanContext,
    target: &ScanTarget,
    codec: &CodecEvidence,
    payload_region: Option<Region>,
    validation: ValidationState,
    provenance: Provenance,
) -> DiscoveredFragment {
    let (camera_id, timestamp_unix, frame_type) = match &target.claim {
        RegionClaim::Indexed {
            recording_id,
            channel,
            start_time_unix,
            ..
        } => {
            let cam = match channel {
                Some(c) => FieldEvidence::known(*c, format!("index entry {recording_id}")),
                None => FieldEvidence::unknown(format!(
                    "index entry {recording_id} records no channel"
                )),
            };
            let ts = match start_time_unix {
                Some(t) => FieldEvidence::known(*t, format!("index entry {recording_id}")),
                None => FieldEvidence::unknown(format!(
                    "index entry {recording_id} records no timestamp"
                )),
            };
            (
                cam,
                ts,
                FieldEvidence::unknown(
                    "frame type is not established by a region scan in this phase".to_string(),
                ),
            )
        }
        other => {
            let reason = format!(
                "no index entry covers this region ({})",
                other.label()
            );
            (
                FieldEvidence::unknown(reason.clone()),
                FieldEvidence::unknown(reason.clone()),
                FieldEvidence::unknown(reason),
            )
        }
    };

    DiscoveredFragment {
        evidence_id: ctx.evidence_id,
        physical_region: target.region,
        payload_region,
        originating_region: target.originating_region,
        oem_key: ctx.oem_key.clone(),
        profile_id: ctx.profile_id.clone(),
        discovery_method: target.discovery_method,
        codec: format!("{:?}", codec.codec),
        camera_id,
        timestamp_unix,
        // Sequence association is the next phase's job. Deriving a sequence number from
        // a single isolated fragment would be an invention.
        sequence_number: FieldEvidence::unknown(
            "fragment sequence association is not performed in this phase".to_string(),
        ),
        frame_type,
        validation,
        provenance,
    }
}

/// Scan one planned target and, if it holds video, produce a candidate and fragment.
///
/// Returns `Ok(None)` when the region holds no codec evidence: an empty or non-video
/// region is not a recovered candidate, and reporting one would be a fabricated finding.
///
/// The `claim` on the target is index evidence supplied by the planner. This function
/// never upgrades it — in particular, a `true` from `recognize_candidate` cannot turn an
/// unclaimed region into an indexed one.
pub fn scan_target(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    parser: &dyn Parser,
    ctx: &ScanContext,
    target: &ScanTarget,
) -> Result<Option<ScanFinding>, ForensicError> {
    let (window, truncated_view) = read_bounded_window(reader, &target.region)?;

    let codec = VideoReconstructor::classify_codec(&window);
    let signature_found = codec.codec != VideoCodec::Unknown || !codec.nal_evidence.is_empty();
    if !signature_found {
        return Ok(None);
    }

    // Structural validity comes from the codec classifier's own verdict — a signature
    // match alone is explicitly not enough.
    let structurally_valid = matches!(codec.validation.state, ValidationStateKind::Pass);

    let video = VideoEvidence {
        signature_found,
        physically_present: !window.is_empty(),
        structurally_valid,
    };

    let Some(assessment) = classify_region_state(&target.claim, video) else {
        return Ok(None);
    };

    // Corroborating observation only. Recorded on the finding, never fed into the state.
    // Errors are surfaced as "not recognised" rather than failing the whole region, since
    // a format probe is not load-bearing here.
    let oem_format_recognised = BoundedReader::new(reader, target.region.offset, target.region.length)
        .ok()
        .and_then(|bounded| parser.recognize_candidate(&bounded, profile).ok())
        .unwrap_or(false);

    let report = validation_report(&codec, structurally_valid, &target.claim);
    let provenance = build_provenance(ctx, target, &window, &assessment, truncated_view);

    // The payload sub-range comes from the OEM parser via the planner. It is never
    // inferred here — an unclaimed region has no established framing.
    let payload_region = target.payload_region;

    let fragment_validation = vs(
        if truncated_view {
            ValidationStateKind::Review
        } else {
            codec.validation.state
        },
        format!(
            "{} | {}",
            codec.validation.reason,
            if oem_format_recognised {
                format!("{} container framing also recognised here", ctx.oem_key)
            } else {
                format!("no {} container framing recognised here", ctx.oem_key)
            }
        ),
        "region_scan",
        "DiscoveredFragment",
    );

    let fragment = build_fragment(
        ctx,
        target,
        &codec,
        payload_region,
        fragment_validation,
        provenance.clone(),
    );

    let candidate = RecoveryCandidate {
        recovery_level: assessment.recovery_level,
        data_state: assessment.data_state,
        recovery_status: assessment.recovery_status,
        // Exact physical offsets, absolute in the evidence.
        source_offsets: vec![target.region],
        validation: report,
        provenance,
    };

    Ok(Some(ScanFinding {
        candidate,
        fragment,
        oem_format_recognised,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_core::{
        Applicability, ConfidenceWeights, DataState, EvidenceStatus, SignatureRule,
    };
    use parsers_core::storage::AllocationEvidence;
    use std::collections::HashMap;

    struct MemReader {
        data: Vec<u8>,
    }
    impl EvidenceReader for MemReader {
        fn len(&self) -> u64 {
            self.data.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
            if offset >= self.len() {
                return Err(ForensicError::out_of_bounds(
                    "test",
                    offset,
                    buf.len() as u64,
                    self.len(),
                ));
            }
            let start = offset as usize;
            let n = (self.data.len() - start).min(buf.len());
            buf[..n].copy_from_slice(&self.data[start..start + n]);
            Ok(n)
        }
        fn source_kind(&self) -> evidence_reader::SourceKind {
            evidence_reader::SourceKind::Raw
        }
        fn source_path(&self) -> &str {
            "mem://test"
        }
    }

    /// A parser that recognises everything — the old always-true behaviour, kept here
    /// precisely to prove it can no longer influence the data state.
    struct YesParser;
    impl Parser for YesParser {
        fn id(&self) -> &str {
            "yes"
        }
        fn version(&self) -> &str {
            "1.0"
        }
        fn parse_filesystem(
            &self,
            _: &dyn EvidenceReader,
            _: &OemProfile,
        ) -> Result<Vec<forensic_core::ParserRun>, ForensicError> {
            Ok(vec![])
        }
        fn parse_metadata(
            &self,
            _: &dyn EvidenceReader,
            _: &OemProfile,
        ) -> Result<Vec<forensic_core::ParserRun>, ForensicError> {
            Ok(vec![])
        }
        fn parse_recordings(
            &self,
            _: &dyn EvidenceReader,
            _: &OemProfile,
        ) -> Result<(Vec<forensic_core::Recording>, Vec<forensic_core::ParserRun>), ForensicError>
        {
            Ok((vec![], vec![]))
        }
        fn extract_timeline_events(
            &self,
            _: &dyn EvidenceReader,
            _: &OemProfile,
        ) -> Result<
            (
                Vec<forensic_core::TimelineEvent>,
                Vec<forensic_core::ParserRun>,
            ),
            ForensicError,
        > {
            Ok((vec![], vec![]))
        }
        fn validate_structure(
            &self,
            _: &dyn EvidenceReader,
            _: &OemProfile,
        ) -> Result<Vec<forensic_core::ParserRun>, ForensicError> {
            Ok(vec![])
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
        OemProfile {
            profile_id: "t".into(),
            profile_version: "1.0".into(),
            schema_version: "1.0".into(),
            oem: "t".into(),
            storage_family: "T".into(),
            applicability: Applicability {
                models: vec![],
                firmwares: vec![],
                storage_variants: vec![],
                reference: None,
            },
            signatures: vec![SignatureRule {
                name: "m".into(),
                pattern_hex: "00".into(),
                evidence_status: EvidenceStatus::Provisional,
                weight: 1.0,
                is_exclusive: false,
                explanation: "t".into(),
                offset_constraints: vec![],
            }],
            validation_rules: vec![],
            layout: HashMap::new(),
            confidence_weights: ConfidenceWeights {
                max_possible_score: 1.0,
                min_threshold: 0.5,
            },
            profile_hash: Some(Hash::sha256(vec![0; 32])),
        }
    }

    fn ctx() -> ScanContext {
        ScanContext {
            evidence_id: EvidenceId::new(),
            oem_key: "t".into(),
            profile_id: "t".into(),
            profile_version: "1.0".into(),
            profile_hash: Some(Hash::sha256(vec![0; 32])),
            parser_id: "yes".into(),
            parser_version: "1.0".into(),
        }
    }

    /// A tiny but real H.264 Annex-B fragment: SPS (0x67) + PPS (0x68) + IDR (0x65).
    fn h264_bytes() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1F]);
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x3C, 0x80]);
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x65, 0xB8, 0x00, 0x04]);
        v
    }

    fn target(region: Region, claim: RegionClaim, method: DiscoveryMethod) -> ScanTarget {
        ScanTarget {
            region,
            originating_region: region,
            payload_region: None,
            claim,
            discovery_method: method,
        }
    }

    #[test]
    fn indexed_target_with_valid_video_is_active_at_l1() {
        let reader = MemReader { data: h264_bytes() };
        let t = target(
            Region::new(0, reader.len()).unwrap(),
            RegionClaim::Indexed {
                recording_id: "didx#0".into(),
                channel: Some(1),
                start_time_unix: Some(1_700_000_000),
                allocation: AllocationEvidence::Unknown,
            },
            DiscoveryMethod::IndexClaimedProbe,
        );
        let f = scan_target(&reader, &profile(), &YesParser, &ctx(), &t)
            .unwrap()
            .expect("valid video in an indexed region is a candidate");

        assert_eq!(f.candidate.data_state, DataState::Active);
        assert_eq!(f.candidate.recovery_level, RecoveryLevel::L1);
        assert_eq!(f.candidate.provenance.recovery_level.as_deref(), Some("L1"));
        // Index-supplied metadata reaches the fragment.
        assert_eq!(f.fragment.camera_id.value(), Some(&1));
        assert_eq!(f.fragment.timestamp_unix.value(), Some(&1_700_000_000));
    }

    #[test]
    fn unclaimed_target_in_index_scope_is_orphaned_even_though_the_parser_recognises_everything() {
        // This is the regression guard for the original defect: YesParser returns
        // Ok(true) for any bytes, exactly as every OEM parser used to. That must not
        // produce Active.
        let reader = MemReader { data: h264_bytes() };
        let t = target(
            Region::new(0, reader.len()).unwrap(),
            RegionClaim::UnclaimedWithinIndexScope {
                index_entry_count: 4,
            },
            DiscoveryMethod::UnclaimedScanInIndexScope,
        );
        let f = scan_target(&reader, &profile(), &YesParser, &ctx(), &t)
            .unwrap()
            .unwrap();

        assert!(
            f.oem_format_recognised,
            "the parser did recognise the format, and that is recorded"
        );
        assert_eq!(
            f.candidate.data_state,
            DataState::Orphaned,
            "format recognition must not override index evidence"
        );
        assert_eq!(f.candidate.recovery_level, RecoveryLevel::L2);
    }

    #[test]
    fn target_without_index_evidence_is_unindexed_never_active_or_deleted() {
        let reader = MemReader { data: h264_bytes() };
        let t = target(
            Region::new(0, reader.len()).unwrap(),
            RegionClaim::NoIndexEvidence {
                reason: "no index reader for this OEM".into(),
            },
            DiscoveryMethod::WholeImageScanWithoutIndex,
        );
        let f = scan_target(&reader, &profile(), &YesParser, &ctx(), &t)
            .unwrap()
            .unwrap();

        assert_eq!(f.candidate.data_state, DataState::Unindexed);
        assert_eq!(f.candidate.recovery_level, RecoveryLevel::L3);
        // No recorder metadata may be invented for carved space.
        assert!(!f.fragment.camera_id.is_known());
        assert!(!f.fragment.timestamp_unix.is_known());
        assert!(!f.fragment.has_recorder_metadata());
    }

    #[test]
    fn unrun_checks_are_unknown_not_pass() {
        let reader = MemReader { data: h264_bytes() };
        let t = target(
            Region::new(0, reader.len()).unwrap(),
            RegionClaim::NoIndexEvidence {
                reason: "none".into(),
            },
            DiscoveryMethod::WholeImageScanWithoutIndex,
        );
        let f = scan_target(&reader, &profile(), &YesParser, &ctx(), &t)
            .unwrap()
            .unwrap();

        assert_eq!(f.candidate.validation.continuity.state, ValidationStateKind::Unknown);
        assert_eq!(f.candidate.validation.timestamps.state, ValidationStateKind::Unknown);
        assert_eq!(f.candidate.validation.channel.state, ValidationStateKind::Unknown);
    }

    #[test]
    fn provenance_carries_the_callers_evidence_id_and_exact_offsets() {
        let reader = MemReader {
            data: {
                let mut v = vec![0u8; 4096];
                let h = h264_bytes();
                v[2048..2048 + h.len()].copy_from_slice(&h);
                v
            },
        };
        let c = ctx();
        let scanned = Region::new(2048, 1024).unwrap();
        let originating = Region::new(2048, 2048).unwrap();
        let t = ScanTarget {
            region: scanned,
            originating_region: originating,
            payload_region: None,
            claim: RegionClaim::UnclaimedWithinIndexScope {
                index_entry_count: 1,
            },
            discovery_method: DiscoveryMethod::UnclaimedScanInIndexScope,
        };
        let f = scan_target(&reader, &profile(), &YesParser, &c, &t)
            .unwrap()
            .unwrap();

        assert_eq!(f.candidate.provenance.source_evidence_id, c.evidence_id);
        assert!(f
            .candidate
            .provenance
            .source_regions
            .iter()
            .all(|sr| sr.evidence_id == c.evidence_id));
        assert_eq!(f.candidate.source_offsets, vec![scanned]);
        assert_eq!(f.fragment.evidence_id, c.evidence_id);
        assert_eq!(f.fragment.physical_region, scanned);
        assert_eq!(f.fragment.originating_region, originating);
        // Both the scanned window and the region it came from are recorded.
        assert_eq!(f.candidate.provenance.source_regions.len(), 2);
    }

    #[test]
    fn non_video_bytes_produce_no_candidate() {
        let reader = MemReader { data: vec![0u8; 4096] };
        let t = target(
            Region::new(0, 4096).unwrap(),
            RegionClaim::Indexed {
                recording_id: "didx#0".into(),
                channel: Some(1),
                start_time_unix: None,
                allocation: AllocationEvidence::Allocated,
            },
            DiscoveryMethod::IndexClaimedProbe,
        );
        assert!(scan_target(&reader, &profile(), &YesParser, &ctx(), &t)
            .unwrap()
            .is_none());
    }

    #[test]
    fn overflow_region_rejected() {
        let reader = MemReader { data: vec![0u8; 1024] };
        let t = target(
            Region {
                offset: u64::MAX - 10,
                length: 20,
            },
            RegionClaim::NoIndexEvidence {
                reason: "n".into(),
            },
            DiscoveryMethod::WholeImageScanWithoutIndex,
        );
        let err = scan_target(&reader, &profile(), &YesParser, &ctx(), &t).unwrap_err();
        assert!(matches!(err, ForensicError::ArithmeticOverflow { .. }));
    }

    #[test]
    fn out_of_bounds_region_rejected() {
        let reader = MemReader { data: vec![0u8; 1024] };
        let t = target(
            Region {
                offset: 2000,
                length: 500,
            },
            RegionClaim::NoIndexEvidence {
                reason: "n".into(),
            },
            DiscoveryMethod::WholeImageScanWithoutIndex,
        );
        let err = scan_target(&reader, &profile(), &YesParser, &ctx(), &t).unwrap_err();
        assert!(matches!(err, ForensicError::OutOfBounds { .. }));
    }
}
