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
use parsers_core::storage::ContainerRecord;
use std::collections::BTreeMap;

/// Default window a single codec-classification read pulls into memory.
///
/// This is a **memory** bound, not a semantic one. It bounds how much of a region is read in
/// one pass to classify its codec; it never bounds what can be recovered, because the OEM
/// structural carver ([`Parser::scan_region_for_candidates`]) describes records from their own
/// declared lengths and reads in its own streaming windows. Callers override it through
/// [`ScanContext::max_window_bytes`].
pub const DEFAULT_SCAN_WINDOW_BYTES: u64 = 8 * 1024 * 1024;

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
    /// Largest window one codec-classification read pulls into memory.
    ///
    /// Configurable so a run can trade memory for fewer reads. It does not limit what is
    /// recoverable: an OEM container record longer than the window is still described in full
    /// from its own declared length.
    pub max_window_bytes: u64,
}

impl ScanContext {
    /// A context with the default read window.
    pub fn new(
        evidence_id: EvidenceId,
        oem_key: impl Into<String>,
        profile_id: impl Into<String>,
        profile_version: impl Into<String>,
        profile_hash: Option<Hash>,
        parser_id: impl Into<String>,
        parser_version: impl Into<String>,
    ) -> Self {
        Self {
            evidence_id,
            oem_key: oem_key.into(),
            profile_id: profile_id.into(),
            profile_version: profile_version.into(),
            profile_hash,
            parser_id: parser_id.into(),
            parser_version: parser_version.into(),
            max_window_bytes: DEFAULT_SCAN_WINDOW_BYTES,
        }
    }

    /// Override the read window. A zero or absurd value falls back to the default rather than
    /// producing zero-length reads.
    pub fn with_window(mut self, bytes: u64) -> Self {
        self.max_window_bytes = if bytes == 0 {
            DEFAULT_SCAN_WINDOW_BYTES
        } else {
            bytes
        };
        self
    }
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

/// Read up to `window` bytes of a region through a [`BoundedReader`].
///
/// Returns the bytes read and whether the region was longer than the window. Overflowing
/// or out-of-bounds regions propagate the `BoundedReader` error unchanged — hostile
/// offsets never panic.
fn read_bounded_window(
    reader: &dyn EvidenceReader,
    region: &Region,
    window: u64,
) -> Result<(Vec<u8>, bool), ForensicError> {
    // Constructing the bounded reader is what enforces checked arithmetic and bounds.
    let bounded = BoundedReader::new(reader, region.offset, region.length)?;
    let window = window.max(1);
    let want = region.length.min(window) as usize;
    let truncated_view = region.length > window;

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
    record: Option<&ContainerRecord>,
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

    // Structural validity combines the codec classifier's verdict with the OEM container
    // record's own, when one was established. A record whose declared length or trailer failed
    // verification must not read as structurally sound just because its payload decodes.
    let record_state = record.map(|r| r.evidence.state);
    let structure_pass = structurally_valid
        && record_state
            .map(|s| s == ValidationStateKind::Pass)
            .unwrap_or(true);
    let structure_reason = match record {
        Some(r) => format!(
            "{} | OEM container record at 0x{:X}: {}",
            codec.validation.reason, r.physical_region.offset, r.evidence.reason
        ),
        None => codec.validation.reason.clone(),
    };
    let structure = vs(
        if structure_pass {
            ValidationStateKind::Pass
        } else {
            ValidationStateKind::Review
        },
        structure_reason,
        "region_scan",
        "structure",
    );

    // Timestamp and channel are only `Pass` when OEM metadata supplied them. A record's own
    // container header can supply them too, which is why `record` is consulted: a carved DHAV
    // frame genuinely carries a channel and a clock, and reporting those as Unknown would
    // discard read evidence.
    let (timestamps, channel) = match claim.recorder_metadata() {
        Some((recording_id, _partition, ch, start_time_unix, _end)) => {
            let ts = match start_time_unix {
                Some(t) => vs(
                    ValidationStateKind::Pass,
                    format!("Recorder timestamp {t} read from OEM metadata entry {recording_id}"),
                    "region_scan",
                    "timestamps",
                ),
                None => vs(
                    ValidationStateKind::Unknown,
                    format!(
                        "OEM metadata entry {recording_id} records no timestamp for this region"
                    ),
                    "region_scan",
                    "timestamps",
                ),
            };
            let chan = match ch {
                Some(c) => vs(
                    ValidationStateKind::Pass,
                    format!("Channel {c} read from OEM metadata entry {recording_id}"),
                    "region_scan",
                    "channel",
                ),
                None => vs(
                    ValidationStateKind::Unknown,
                    format!("OEM metadata entry {recording_id} records no channel for this region"),
                    "region_scan",
                    "channel",
                ),
            };
            (ts, chan)
        }
        None if record.is_some() => {
            let rec = record.expect("checked");
            let ts = match rec.start_time_unix {
                Some(t) => vs(
                    ValidationStateKind::Pass,
                    format!(
                        "Recorder timestamp {t} decoded from the container record's own header at \
                         0x{:X}",
                        rec.physical_region.offset
                    ),
                    "region_scan",
                    "timestamps",
                ),
                None => vs(
                    ValidationStateKind::Unknown,
                    format!(
                        "the container record at 0x{:X} carries no decodable timestamp",
                        rec.physical_region.offset
                    ),
                    "region_scan",
                    "timestamps",
                ),
            };
            let chan = match rec.channel {
                Some(c) => vs(
                    ValidationStateKind::Pass,
                    format!(
                        "Channel {c} decoded from the container record's own header at 0x{:X}",
                        rec.physical_region.offset
                    ),
                    "region_scan",
                    "channel",
                ),
                None => vs(
                    ValidationStateKind::Unknown,
                    format!(
                        "the container record at 0x{:X} carries no channel",
                        rec.physical_region.offset
                    ),
                    "region_scan",
                    "channel",
                ),
            };
            (ts, chan)
        }
        None => (
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
    fragment_region: Region,
    window: &[u8],
    assessment: &StateAssessment,
    truncated_view: bool,
) -> Provenance {
    let level_str = level_label(assessment.recovery_level);
    let mut reason = format!("{level_str}: {}", assessment.reason);
    if truncated_view {
        reason
            .push_str("; window truncated to the scan cap, bytes beyond the cap were not examined");
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

    // The chain recorded is: evidence item → planner region → scanned region → fragment region.
    // Each distinct step is recorded once, so a fragment carved out of a chunk of a claimed
    // range is traceable through every level of the range algebra that reached it.
    let mut source_regions = vec![SourceRegion::new(ctx.evidence_id, fragment_region)
        .with_description(format!(
            "recovered fragment region, discovery method {}",
            target.discovery_method.label()
        ))];
    if target.region != fragment_region {
        source_regions.push(
            SourceRegion::new(ctx.evidence_id, target.region)
                .with_description("scanned region the fragment was carved from".to_string()),
        );
    }
    // Record the planner region separately when the scan only covered part of it, so the
    // provenance shows both what was targeted and what was actually read.
    if target.originating_region != target.region && target.originating_region != fragment_region {
        source_regions.push(
            SourceRegion::new(ctx.evidence_id, target.originating_region).with_description(
                format!(
                    "originating {} region",
                    match target.discovery_method {
                        DiscoveryMethod::IndexClaimedProbe => "index-claimed",
                        DiscoveryMethod::AvailableMetadataProbe => "available-metadata",
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
            "claim={}, scanned={}, fragment={}, profile={}",
            target.claim.label(),
            target.region,
            fragment_region,
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
#[allow(clippy::too_many_arguments)]
fn build_fragment(
    ctx: &ScanContext,
    target: &ScanTarget,
    physical_region: Region,
    codec: &CodecEvidence,
    payload_region: Option<Region>,
    record: Option<&ContainerRecord>,
    validation: ValidationState,
    confidence: FieldEvidence<f64>,
    provenance: Provenance,
) -> DiscoveredFragment {
    // Recorder metadata comes from the OEM claim first — it is the recorder's own index — and
    // from the container record's own header second. Both are read evidence; neither is
    // invented. A region with neither keeps explicit `Unknown`s with the reason attached,
    // rather than channel 0 at the epoch.
    let mut partition = FieldEvidence::unknown(format!(
        "no OEM metadata covers this region ({})",
        target.claim.label()
    ));
    let mut camera_id = FieldEvidence::unknown(format!(
        "no OEM metadata covers this region ({})",
        target.claim.label()
    ));
    let mut timestamp_unix = FieldEvidence::unknown(format!(
        "no OEM metadata covers this region ({})",
        target.claim.label()
    ));
    let mut end_timestamp_unix = FieldEvidence::unknown(format!(
        "no OEM metadata covers this region ({})",
        target.claim.label()
    ));
    let mut parent_recording = FieldEvidence::unknown(format!(
        "no OEM metadata associates this region with a recording ({})",
        target.claim.label()
    ));
    let mut frame_type = FieldEvidence::unknown(
        "no container record established a frame type for these bytes".to_string(),
    );
    let mut sequence_number = FieldEvidence::unknown(
        "no on-disk sequence number was established for these bytes".to_string(),
    );

    if let Some((recording_id, part, channel, start, end)) = target.claim.recorder_metadata() {
        let source = format!("OEM metadata entry {recording_id}");
        parent_recording = FieldEvidence::known(recording_id.to_string(), source.clone());
        if let Some(p) = part {
            partition = FieldEvidence::known(p, source.clone());
        } else {
            partition = FieldEvidence::unknown(format!("{source} records no partition"));
        }
        if let Some(c) = channel {
            camera_id = FieldEvidence::known(c, source.clone());
        } else {
            camera_id = FieldEvidence::unknown(format!("{source} records no channel"));
        }
        if let Some(t) = start {
            timestamp_unix = FieldEvidence::known(t, source.clone());
        } else {
            timestamp_unix = FieldEvidence::unknown(format!("{source} records no start timestamp"));
        }
        if let Some(t) = end {
            end_timestamp_unix = FieldEvidence::known(t, source.clone());
        } else {
            end_timestamp_unix =
                FieldEvidence::unknown(format!("{source} records no end timestamp"));
        }
    }

    let mut oem_metadata: BTreeMap<String, String> = BTreeMap::new();
    if let Some(rec) = record {
        let source = format!(
            "OEM container record header at 0x{:X}",
            rec.physical_region.offset
        );
        // A record's own header is read evidence and fills in what the index did not supply.
        if !camera_id.is_known() {
            if let Some(c) = rec.channel {
                camera_id = FieldEvidence::known(c, source.clone());
            }
        }
        if !timestamp_unix.is_known() {
            if let Some(t) = rec.start_time_unix {
                timestamp_unix = FieldEvidence::known(t, source.clone());
            }
        }
        if let Some(ft) = &rec.frame_type {
            frame_type = FieldEvidence::known(ft.clone(), source.clone());
        }
        if let Some(seq) = rec
            .oem_metadata
            .get("dhav_frame_number")
            .and_then(|v| v.parse::<u64>().ok())
        {
            sequence_number = FieldEvidence::known(seq, source.clone());
        }
        oem_metadata.extend(rec.oem_metadata.clone());
        if let Some(codec_hint) = &rec.codec_hint {
            oem_metadata.insert("oem_declared_codec".into(), codec_hint.clone());
        }
    }

    DiscoveredFragment {
        evidence_id: ctx.evidence_id,
        // Derived from the evidence id and the exact range, so it is stable across runs and
        // across every later representation of these same bytes.
        fragment_id: DiscoveredFragment::derive_id(ctx.evidence_id, physical_region),
        physical_region,
        payload_region,
        framing: if record.is_some() {
            crate::fragment::FragmentFraming::OemContainerRecord
        } else {
            crate::fragment::FragmentFraming::ScanWindow
        },
        originating_region: target.originating_region,
        oem_key: ctx.oem_key.clone(),
        profile_id: ctx.profile_id.clone(),
        discovery_method: target.discovery_method,
        codec: format!("{:?}", codec.codec),
        partition,
        camera_id,
        timestamp_unix,
        end_timestamp_unix,
        sequence_number,
        frame_type,
        parent_recording,
        oem_metadata,
        validation,
        confidence,
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
    Ok(scan_target_all(reader, profile, parser, ctx, target)?
        .into_iter()
        .next())
}

/// Scan one planned target and produce a finding for **every** piece of video in it.
///
/// This is the production entry point. It replaces the one-candidate-per-target rule that made
/// a 1 MiB sweep chunk equal exactly one "recovered recording" regardless of how many records it
/// actually held.
///
/// ```text
///   target region
///      │
///      ├─ parser.scan_region_for_candidates()   ── OEM structural carve
///      │     └─ N container records, absolute offsets, own declared lengths
///      │           └─ one finding per record, classified against the target's claim
///      │
///      └─ (no carver, or no records)            ── fall back to one window classification
/// ```
///
/// The target's [`RegionClaim`] is index evidence supplied by the planner, and this function
/// never upgrades it: a `true` from `recognize_candidate`, or a successfully carved record,
/// cannot turn an unclaimed region into an indexed one.
pub fn scan_target_all(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    parser: &dyn Parser,
    ctx: &ScanContext,
    target: &ScanTarget,
) -> Result<Vec<ScanFinding>, ForensicError> {
    // Bounds and overflow are enforced here, before any OEM code sees the region.
    let (window, truncated_view) =
        read_bounded_window(reader, &target.region, ctx.max_window_bytes)?;

    // Corroborating observation only. Recorded on each finding, never fed into the state.
    // Errors are surfaced as "not recognised" rather than failing the whole region, since a
    // format probe is not load-bearing here.
    let oem_format_recognised =
        BoundedReader::new(reader, target.region.offset, target.region.length)
            .ok()
            .and_then(|bounded| parser.recognize_candidate(&bounded, profile).ok())
            .unwrap_or(false);

    // ── OEM structural carve ────────────────────────────────────────────────
    // A parser with no carver returns an empty vector, which is an honest "this OEM path
    // supplies no structural carver" rather than a failure.
    let records = match parser.scan_region_for_candidates(reader, profile, target.region) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(
                target: "recovery::scan",
                offset = target.region.offset,
                length = target.region.length,
                error = %e,
                "the OEM structural carver failed; falling back to whole-window classification"
            );
            Vec::new()
        }
    };

    if !records.is_empty() {
        let mut findings = Vec::with_capacity(records.len());
        for record in &records {
            // A record the parser placed outside the region it was asked about would break the
            // provenance chain, so it is dropped and recorded rather than trusted.
            if !record.physical_region.overlaps(&target.region) {
                tracing::warn!(
                    target: "recovery::scan",
                    record_offset = record.physical_region.offset,
                    region_offset = target.region.offset,
                    region_length = target.region.length,
                    "the OEM carver reported a record outside the scanned region; discarded"
                );
                continue;
            }
            if let Some(finding) =
                finding_from_record(reader, ctx, target, record, oem_format_recognised)?
            {
                findings.push(finding);
            }
        }
        if !findings.is_empty() {
            // Deterministic order: ascending physical offset.
            findings.sort_by_key(|f| f.fragment.physical_region.offset);
            return Ok(findings);
        }
    }

    // ── Fallback: classify the window as a whole ─────────────────────────────
    let codec = VideoReconstructor::classify_codec(&window);
    let signature_found = codec.codec != VideoCodec::Unknown || !codec.nal_evidence.is_empty();
    if !signature_found {
        return Ok(Vec::new());
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
        return Ok(Vec::new());
    };

    let report = validation_report(&codec, structurally_valid, &target.claim, None);
    let provenance = build_provenance(
        ctx,
        target,
        target.region,
        &window,
        &assessment,
        truncated_view,
    );

    // The payload sub-range comes from the OEM parser via the planner. It is never inferred
    // here — a region with no established framing has no payload boundary.
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

    let confidence = window_confidence(&codec, &target.claim, truncated_view);
    let fragment = build_fragment(
        ctx,
        target,
        target.region,
        &codec,
        payload_region,
        None,
        fragment_validation,
        confidence,
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

    Ok(vec![ScanFinding {
        candidate,
        fragment,
        oem_format_recognised,
    }])
}

/// Build a finding from one OEM container record.
///
/// The record's own declared bounds become the fragment's physical region, so the fragment
/// describes a record rather than an arbitrary slice of a scan chunk. Its payload is classified
/// from the payload bytes the record identified, which is a stricter test than classifying a
/// window that happens to contain framing.
fn finding_from_record(
    reader: &dyn EvidenceReader,
    ctx: &ScanContext,
    target: &ScanTarget,
    record: &ContainerRecord,
    oem_format_recognised: bool,
) -> Result<Option<ScanFinding>, ForensicError> {
    let classify_region = record.payload_region.unwrap_or(record.physical_region);
    let (bytes, truncated_view) =
        match read_bounded_window(reader, &classify_region, ctx.max_window_bytes) {
            Ok(v) => v,
            // A record pointing at unreadable bytes is not a recovered candidate. Recorded at
            // debug level and skipped, rather than failing the whole region.
            Err(e) => {
                tracing::debug!(
                    target: "recovery::scan",
                    offset = classify_region.offset,
                    length = classify_region.length,
                    error = %e,
                    "an OEM container record's bytes could not be read; skipped"
                );
                return Ok(None);
            }
        };

    let codec = VideoReconstructor::classify_codec(&bytes);
    let signature_found = codec.codec != VideoCodec::Unknown || !codec.nal_evidence.is_empty();
    if !signature_found {
        // The record exists structurally but carries no decodable video. Reporting it as a
        // recovered video candidate would be a finding the bytes do not support.
        return Ok(None);
    }
    let structurally_valid = matches!(codec.validation.state, ValidationStateKind::Pass)
        && record.evidence.state == ValidationStateKind::Pass;

    let video = VideoEvidence {
        signature_found,
        physically_present: !bytes.is_empty(),
        structurally_valid,
    };
    let Some(assessment) = classify_region_state(&target.claim, video) else {
        return Ok(None);
    };

    let report = validation_report(&codec, structurally_valid, &target.claim, Some(record));
    let provenance = build_provenance(
        ctx,
        target,
        record.physical_region,
        &bytes,
        &assessment,
        truncated_view,
    );

    let fragment_validation = vs(
        if truncated_view {
            ValidationStateKind::Review
        } else if structurally_valid {
            ValidationStateKind::Pass
        } else {
            ValidationStateKind::Review
        },
        format!(
            "{} | OEM container record: {} | {}",
            codec.validation.reason,
            record.evidence.reason,
            if oem_format_recognised {
                format!(
                    "{} container framing recognised in this region",
                    ctx.oem_key
                )
            } else {
                format!(
                    "{} container framing was not recognised across the whole region",
                    ctx.oem_key
                )
            }
        ),
        "region_scan",
        "DiscoveredFragment",
    );

    let confidence = record_confidence(&codec, record, &target.claim, truncated_view);
    let fragment = build_fragment(
        ctx,
        target,
        record.physical_region,
        &codec,
        record.payload_region,
        Some(record),
        fragment_validation,
        confidence,
        provenance.clone(),
    );

    let candidate = RecoveryCandidate {
        recovery_level: assessment.recovery_level,
        data_state: assessment.data_state,
        recovery_status: assessment.recovery_status,
        source_offsets: vec![record.physical_region],
        validation: report,
        provenance,
    };

    Ok(Some(ScanFinding {
        candidate,
        fragment,
        oem_format_recognised,
    }))
}

/// Confidence for a fragment established from an OEM container record.
///
/// Composed from named, additive observations so the number is explainable rather than a magic
/// weight. It is capped below 1.0: a bounded search can never be certain.
fn record_confidence(
    codec: &CodecEvidence,
    record: &ContainerRecord,
    claim: &RegionClaim,
    truncated_view: bool,
) -> FieldEvidence<f64> {
    let mut score = 0.0f64;
    let mut basis: Vec<&str> = Vec::new();

    if record.evidence.state == ValidationStateKind::Pass {
        score += 0.45;
        basis.push("OEM container record fully verified (+0.45)");
    } else {
        score += 0.20;
        basis.push("OEM container record structurally located but not fully verified (+0.20)");
    }
    if codec.validation.state == ValidationStateKind::Pass {
        score += 0.30;
        basis.push("codec validated from parameter sets (+0.30)");
    } else if !codec.nal_evidence.is_empty() {
        score += 0.10;
        basis.push("codec signature observed but not validated (+0.10)");
    }
    if claim.recorder_metadata().is_some() {
        score += 0.15;
        basis.push("OEM metadata supplies channel/time for this region (+0.15)");
    }
    if record.payload_region.is_some() {
        score += 0.05;
        basis.push("payload boundary separated from framing (+0.05)");
    }
    if truncated_view {
        score -= 0.10;
        basis.push("only part of the record was read in one pass (-0.10)");
    }

    FieldEvidence::known(score.clamp(0.0, 0.95), basis.join("; "))
}

/// Confidence for a fragment established only from a window classification.
fn window_confidence(
    codec: &CodecEvidence,
    claim: &RegionClaim,
    truncated_view: bool,
) -> FieldEvidence<f64> {
    let mut score = 0.0f64;
    let mut basis: Vec<&str> = Vec::new();

    if codec.validation.state == ValidationStateKind::Pass {
        score += 0.35;
        basis.push("codec validated from parameter sets (+0.35)");
    } else if !codec.nal_evidence.is_empty() {
        score += 0.10;
        basis.push("codec signature observed but not validated (+0.10)");
    }
    if claim.recorder_metadata().is_some() {
        score += 0.20;
        basis.push("OEM metadata supplies channel/time for this region (+0.20)");
    }
    basis.push(
        "no OEM container record bounds these bytes, so the fragment covers a scan window rather \
         than a record (no credit)",
    );
    if truncated_view {
        score -= 0.10;
        basis.push("only part of the window was read in one pass (-0.10)");
    }

    FieldEvidence::known(score.clamp(0.0, 0.95), basis.join("; "))
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
            max_window_bytes: DEFAULT_SCAN_WINDOW_BYTES,
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
                partition: Some(0),
                channel: Some(1),
                start_time_unix: Some(1_700_000_000),
                end_time_unix: None,
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

        assert_eq!(
            f.candidate.validation.continuity.state,
            ValidationStateKind::Unknown
        );
        assert_eq!(
            f.candidate.validation.timestamps.state,
            ValidationStateKind::Unknown
        );
        assert_eq!(
            f.candidate.validation.channel.state,
            ValidationStateKind::Unknown
        );
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
        let reader = MemReader {
            data: vec![0u8; 4096],
        };
        let t = target(
            Region::new(0, 4096).unwrap(),
            RegionClaim::Indexed {
                recording_id: "didx#0".into(),
                partition: None,
                channel: Some(1),
                start_time_unix: None,
                end_time_unix: None,
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
        let reader = MemReader {
            data: vec![0u8; 1024],
        };
        let t = target(
            Region {
                offset: u64::MAX - 10,
                length: 20,
            },
            RegionClaim::NoIndexEvidence { reason: "n".into() },
            DiscoveryMethod::WholeImageScanWithoutIndex,
        );
        let err = scan_target(&reader, &profile(), &YesParser, &ctx(), &t).unwrap_err();
        assert!(matches!(err, ForensicError::ArithmeticOverflow { .. }));
    }

    #[test]
    fn out_of_bounds_region_rejected() {
        let reader = MemReader {
            data: vec![0u8; 1024],
        };
        let t = target(
            Region {
                offset: 2000,
                length: 500,
            },
            RegionClaim::NoIndexEvidence { reason: "n".into() },
            DiscoveryMethod::WholeImageScanWithoutIndex,
        );
        let err = scan_target(&reader, &profile(), &YesParser, &ctx(), &t).unwrap_err();
        assert!(matches!(err, ForensicError::OutOfBounds { .. }));
    }
}
