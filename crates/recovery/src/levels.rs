//! Recovery level strategies: L1 (indexed), L2 (orphan/slack), L3 (raw carving).
//!
//! Each level processes evidence strictly within a bounded sub-window using
//! `BoundedReader`, which maps window offsets back to absolute evidence offsets and
//! rejects any out-of-bounds read. The three levels differ in *what they trust* and
//! therefore in the `DataState` they assign:
//!
//! * **L1 indexed** — the region was handed to us because a parser/index referenced
//!   it. A valid codec stream here is `Active` data.
//! * **L2 orphan/slack** — a codec stream exists in a region the index does *not*
//!   reference. Missing index linkage yields `Orphaned`; the absence of an index is
//!   never treated as proof of overwrite (Req 13.11).
//! * **L3 raw carving** — a bounded, signature-driven scan with no index and no OEM
//!   framing to lean on. Findings are the weakest form of evidence; structurally
//!   invalid carves are `Corrupted`, and a scan stopped by its cap reports the
//!   truncation rather than claiming completeness (Req 13.10).
//!
//! Common invariants: gaps are never filled, no bytes are synthesized, and
//! `DataState`/`RecoveryStatus` are assigned by `classify_recovery`, never guessed.

use forensic_core::{
    ForensicError, FrameValidationReport, Hash, OemProfile, Provenance,
    RecoveryCandidate, RecoveryLevel, Region, ValidationState, ValidationStateKind,
};
use evidence_reader::{BoundedReader, EvidenceReader};
use parsers_core::parser::Parser;
use sha2::{Digest, Sha256};

use crate::reconstructor::{CodecEvidence, VideoCodec, VideoReconstructor};

/// Largest window a single level will pull into memory in one pass. Regions larger
/// than this are scanned only up to this bound, and the candidate is marked as a
/// partial read via its validation reason.
const MAX_WINDOW_BYTES: u64 = 8 * 1024 * 1024;

/// Read up to `MAX_WINDOW_BYTES` of a region through a `BoundedReader`.
///
/// Returns the bytes read and whether the region was longer than the window (so the
/// caller can flag a truncated view). Overflowing or out-of-bounds regions propagate
/// the `BoundedReader` error unchanged — hostile offsets never panic (Req 24).
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

/// Build a `FrameValidationReport` from codec evidence.
///
/// Signature/structure reflect the codec classifier's own verdict. Timestamp,
/// channel, and continuity are `Unknown` here: a level scan sees raw stream bytes and
/// has no recorder metadata to assess them, and an unrun check is never a `PASS`.
fn validation_report(codec: &CodecEvidence, structurally_valid: bool) -> FrameValidationReport {
    let sig_state = if codec.codec != VideoCodec::Unknown {
        ValidationState::new(
            ValidationStateKind::Pass,
            format!("{:?} NAL/marker signatures observed", codec.codec),
            "level_scan",
            "signatures",
        )
        .unwrap()
    } else {
        ValidationState::new(
            ValidationStateKind::Review,
            "No decodable codec signature in window",
            "level_scan",
            "signatures",
        )
        .unwrap()
    };

    let struct_state = if structurally_valid {
        ValidationState::new(
            ValidationStateKind::Pass,
            codec.validation.reason.clone(),
            "level_scan",
            "structure",
        )
        .unwrap()
    } else {
        ValidationState::new(
            ValidationStateKind::Review,
            codec.validation.reason.clone(),
            "level_scan",
            "structure",
        )
        .unwrap()
    };

    FrameValidationReport {
        signatures: sig_state,
        structure: struct_state,
        timestamps: ValidationState::new(
            ValidationStateKind::Unknown,
            "Timestamps require recorder metadata not available to a byte-level scan",
            "level_scan",
            "timestamps",
        )
        .unwrap(),
        channel: ValidationState::new(
            ValidationStateKind::Unknown,
            "Channel attribution requires index metadata not available to a byte-level scan",
            "level_scan",
            "channel",
        )
        .unwrap(),
        continuity: ValidationState::new(
            ValidationStateKind::Unknown,
            "Frame continuity is assessed by the reconstructor, not at scan time",
            "level_scan",
            "continuity",
        )
        .unwrap(),
    }
}

/// Assemble a candidate from a scanned region and its codec evidence.
#[allow(clippy::too_many_arguments)]
fn build_candidate(
    reader: &dyn EvidenceReader,
    region: &Region,
    window: &[u8],
    codec: CodecEvidence,
    level: RecoveryLevel,
    has_index_entry: bool,
    truncated_view: bool,
) -> RecoveryCandidate {
    let structurally_valid =
        matches!(codec.validation.state, ValidationStateKind::Pass);
    let is_physically_present = !window.is_empty();

    // Overwrite is a positive finding established elsewhere; a level scan never infers
    // it, so `has_overwrite_evidence` is always false here (Req 13.3, 13.11).
    let assessment = crate::classification::classify_recovery(
        has_index_entry,
        is_physically_present,
        structurally_valid,
        false,
    );

    let report = validation_report(&codec, structurally_valid);

    let level_str = match level {
        RecoveryLevel::L1 => "L1",
        RecoveryLevel::L2 => "L2",
        RecoveryLevel::L3 => "L3",
    };
    let mut reason = format!(
        "{level_str} scan: codec={:?}, {} NAL/marker(s), {}",
        codec.codec,
        codec.nal_evidence.len(),
        codec.validation.reason
    );
    if truncated_view {
        reason.push_str("; window truncated to scan cap, bytes beyond the cap were not examined");
    }
    let prov_state = ValidationState::new(
        if truncated_view {
            ValidationStateKind::Review
        } else {
            codec.validation.state
        },
        reason,
        "recover_level",
        "RecoveryCandidate",
    )
    .unwrap();

    let mut provenance = Provenance::new(
        forensic_core::EvidenceId::new(),
        digest(window),
        vec![forensic_core::SourceRegion::new(
            forensic_core::EvidenceId::new(),
            region.clone(),
        )],
        "recovery-engine",
        env!("CARGO_PKG_VERSION"),
        digest(window),
        prov_state,
    );
    provenance.recovery_level = Some(level_str.to_string());

    let _ = reader; // reader is used for bounds/reads upstream; retained for signature symmetry.

    RecoveryCandidate {
        recovery_level: level,
        data_state: assessment.data_state,
        recovery_status: assessment.recovery_status,
        source_offsets: vec![region.clone()],
        validation: report,
        provenance,
    }
}

/// L1: Indexed recovery — the region is index/parser referenced.
///
/// A valid codec stream in an indexed region is `Active` data. The parser is asked to
/// confirm the region is structurally sound before a candidate is emitted.
pub fn recover_l1_indexed(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    parser: &dyn Parser,
    search_region: &Region,
) -> Result<Vec<RecoveryCandidate>, ForensicError> {
    let (window, truncated_view) = read_bounded_window(reader, search_region)?;
    let bounded = BoundedReader::new(reader, search_region.offset, search_region.length)?;

    // The parser vets the region; if it declines, L1 yields nothing (L2/L3 may still
    // find orphaned or carvable data there).
    if !parser.recognize_candidate(&bounded, profile).unwrap_or(false) {
        return Ok(vec![]);
    }

    let codec = VideoReconstructor::classify_codec(&window);
    if codec.codec == VideoCodec::Unknown && codec.nal_evidence.is_empty() {
        return Ok(vec![]);
    }

    Ok(vec![build_candidate(
        reader,
        search_region,
        &window,
        codec,
        RecoveryLevel::L1,
        true, // indexed
        truncated_view,
    )])
}

/// L2: Orphan/slack recovery — codec data with no index linkage.
///
/// Emits a candidate only when a codec signature is present but the parser does *not*
/// recognize the region as an indexed structure. Missing linkage → `Orphaned`.
pub fn recover_l2_orphan(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    parser: &dyn Parser,
    search_region: &Region,
) -> Result<Vec<RecoveryCandidate>, ForensicError> {
    let (window, truncated_view) = read_bounded_window(reader, search_region)?;
    let bounded = BoundedReader::new(reader, search_region.offset, search_region.length)?;

    let indexed = parser.recognize_candidate(&bounded, profile).unwrap_or(false);
    if indexed {
        // Indexed regions belong to L1, not the orphan pass.
        return Ok(vec![]);
    }

    let codec = VideoReconstructor::classify_codec(&window);
    if codec.codec == VideoCodec::Unknown && codec.nal_evidence.is_empty() {
        return Ok(vec![]);
    }

    Ok(vec![build_candidate(
        reader,
        search_region,
        &window,
        codec,
        RecoveryLevel::L2,
        false, // no index entry -> Orphaned
        truncated_view,
    )])
}

/// L3: Raw carving — bounded, signature-driven scan of unstructured space.
///
/// Independent of the parser and the index: any decodable codec signature in the
/// window is carved. Structurally invalid carves are `Corrupted` (still possibly
/// partially recoverable). A window truncated by the scan cap is reported as such and
/// never claims a global optimum (Req 13.10).
pub fn recover_l3_carve(
    reader: &dyn EvidenceReader,
    _profile: &OemProfile,
    _parser: &dyn Parser,
    search_region: &Region,
) -> Result<Vec<RecoveryCandidate>, ForensicError> {
    let (window, truncated_view) = read_bounded_window(reader, search_region)?;

    let codec = VideoReconstructor::classify_codec(&window);
    // Raw carving requires at least one codec signature to justify a candidate;
    // otherwise the region is left unclaimed rather than fabricating a finding.
    if codec.nal_evidence.is_empty() && codec.codec == VideoCodec::Unknown {
        return Ok(vec![]);
    }

    Ok(vec![build_candidate(
        reader,
        search_region,
        &window,
        codec,
        RecoveryLevel::L3,
        false, // carved from unindexed space
        truncated_view,
    )])
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_core::{Applicability, ConfidenceWeights, DataState, EvidenceStatus, SignatureRule};
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

    /// A parser that recognizes everything (stands in for an index hit).
    struct YesParser;
    impl Parser for YesParser {
        fn id(&self) -> &str {
            "yes"
        }
        fn version(&self) -> &str {
            "1.0"
        }
        fn parse_filesystem(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<Vec<forensic_core::ParserRun>, ForensicError> {
            Ok(vec![])
        }
        fn parse_metadata(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<Vec<forensic_core::ParserRun>, ForensicError> {
            Ok(vec![])
        }
        fn parse_recordings(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<(Vec<forensic_core::Recording>, Vec<forensic_core::ParserRun>), ForensicError> {
            Ok((vec![], vec![]))
        }
        fn extract_timeline_events(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<(Vec<forensic_core::TimelineEvent>, Vec<forensic_core::ParserRun>), ForensicError> {
            Ok((vec![], vec![]))
        }
        fn validate_structure(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<Vec<forensic_core::ParserRun>, ForensicError> {
            Ok(vec![])
        }
        fn recognize_candidate(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<bool, ForensicError> {
            Ok(true)
        }
    }

    /// A parser that recognizes nothing (region is not indexed).
    struct NoParser;
    impl Parser for NoParser {
        fn id(&self) -> &str {
            "no"
        }
        fn version(&self) -> &str {
            "1.0"
        }
        fn parse_filesystem(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<Vec<forensic_core::ParserRun>, ForensicError> {
            Ok(vec![])
        }
        fn parse_metadata(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<Vec<forensic_core::ParserRun>, ForensicError> {
            Ok(vec![])
        }
        fn parse_recordings(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<(Vec<forensic_core::Recording>, Vec<forensic_core::ParserRun>), ForensicError> {
            Ok((vec![], vec![]))
        }
        fn extract_timeline_events(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<(Vec<forensic_core::TimelineEvent>, Vec<forensic_core::ParserRun>), ForensicError> {
            Ok((vec![], vec![]))
        }
        fn validate_structure(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<Vec<forensic_core::ParserRun>, ForensicError> {
            Ok(vec![])
        }
        fn recognize_candidate(&self, _: &dyn EvidenceReader, _: &OemProfile) -> Result<bool, ForensicError> {
            Ok(false)
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

    /// A tiny but real H.264 Annex-B fragment: SPS (0x67) + PPS (0x68) + IDR (0x65).
    fn h264_bytes() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1F]);
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x3C, 0x80]);
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x65, 0xB8, 0x00, 0x04]);
        v
    }

    #[test]
    fn l1_emits_active_candidate_for_indexed_codec_region() {
        let reader = MemReader { data: h264_bytes() };
        let region = Region { offset: 0, length: reader.len() };
        let out = recover_l1_indexed(&reader, &profile(), &YesParser, &region).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].recovery_level, RecoveryLevel::L1);
        assert_eq!(out[0].data_state, DataState::Active);
        assert_eq!(out[0].provenance.recovery_level.as_deref(), Some("L1"));
    }

    #[test]
    fn l1_yields_nothing_when_parser_declines() {
        let reader = MemReader { data: h264_bytes() };
        let region = Region { offset: 0, length: reader.len() };
        let out = recover_l1_indexed(&reader, &profile(), &NoParser, &region).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn l2_emits_orphaned_candidate_for_unindexed_codec_region() {
        let reader = MemReader { data: h264_bytes() };
        let region = Region { offset: 0, length: reader.len() };
        let out = recover_l2_orphan(&reader, &profile(), &NoParser, &region).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].recovery_level, RecoveryLevel::L2);
        assert_eq!(out[0].data_state, DataState::Orphaned);
    }

    #[test]
    fn l2_defers_indexed_regions_to_l1() {
        let reader = MemReader { data: h264_bytes() };
        let region = Region { offset: 0, length: reader.len() };
        let out = recover_l2_orphan(&reader, &profile(), &YesParser, &region).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn l3_carves_codec_signature_without_parser_help() {
        let reader = MemReader { data: h264_bytes() };
        let region = Region { offset: 0, length: reader.len() };
        let out = recover_l3_carve(&reader, &profile(), &NoParser, &region).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].recovery_level, RecoveryLevel::L3);
    }

    #[test]
    fn l3_yields_nothing_on_non_codec_bytes() {
        let reader = MemReader { data: vec![0u8; 4096] };
        let region = Region { offset: 0, length: reader.len() };
        let out = recover_l3_carve(&reader, &profile(), &NoParser, &region).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn overflow_region_rejected() {
        let reader = MemReader { data: vec![0u8; 1024] };
        let region = Region { offset: u64::MAX - 10, length: 20 };
        let err = recover_l1_indexed(&reader, &profile(), &YesParser, &region).unwrap_err();
        assert!(matches!(err, ForensicError::ArithmeticOverflow { .. }));
    }

    #[test]
    fn out_of_bounds_region_rejected() {
        let reader = MemReader { data: vec![0u8; 1024] };
        let region = Region { offset: 2000, length: 500 };
        let err = recover_l1_indexed(&reader, &profile(), &YesParser, &region).unwrap_err();
        assert!(matches!(err, ForensicError::OutOfBounds { .. }));
    }
}
