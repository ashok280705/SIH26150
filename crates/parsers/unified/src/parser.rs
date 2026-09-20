//! Unified fallback parser implementation: OEM-agnostic video carving.

use evidence_reader::EvidenceReader;
use forensic_core::identifiers::ProfileId;
use forensic_core::{
    ForensicError, Hash, OemProfile, ParserRun, Provenance, RawTimestamp,
    Recording, Region, TimeEvidence, TimeZoneState, TimelineEvent, ValidationState,
};
use parsers_core::Parser;

/// Largest span the fallback scanner will read into memory in one pass.
const MAX_SCAN_BYTES: u64 = 16 * 1024 * 1024;
/// A gap larger than this between consecutive NAL start codes closes the current
/// carved run and begins a new one.
const RUN_GAP_BYTES: usize = 256 * 1024;
/// Minimum NAL start codes for a run to be reported as a recording. Isolated
/// start-code look-alikes below this are not promoted to carved recordings.
const MIN_NALS_PER_RUN: usize = 2;

/// Codec family inferred for a carved region (a media fact, not an OEM identity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarvedCodec {
    H264,
    H265,
    Mjpeg,
    Unknown,
}

impl CarvedCodec {
    fn label(&self) -> &'static str {
        match self {
            CarvedCodec::H264 => "H.264/AVC",
            CarvedCodec::H265 => "H.265/HEVC",
            CarvedCodec::Mjpeg => "MJPEG",
            CarvedCodec::Unknown => "Unknown",
        }
    }
}

/// A contiguous run of codec activity carved from raw bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct CarvedRegion {
    /// Absolute offset of the region within the evidence.
    pub offset: u64,
    /// Length in bytes (bounded by the scan window).
    pub length: u64,
    pub codec: CarvedCodec,
    pub nal_count: usize,
}

pub struct UnifiedParser {
    pub id: String,
    pub version: String,
}

impl Default for UnifiedParser {
    fn default() -> Self {
        Self {
            id: "unified-fallback-parser".to_string(),
            version: "1.0.0".to_string(),
        }
    }
}

impl UnifiedParser {
    fn profile_hash(&self, profile: &OemProfile) -> Hash {
        profile
            .profile_hash
            .clone()
            .unwrap_or_else(|| Hash::sha256(vec![0; 32]))
    }

    fn run(&self, profile: &OemProfile, op: &str, state: ValidationState) -> ParserRun {
        ParserRun::new(
            self.id.clone(),
            self.version.clone(),
            ProfileId(profile.profile_id.clone()),
            self.profile_hash(profile),
            op.to_string(),
            state,
        )
    }

    /// A `TimeEvidence` with an Unknown timezone and no normalized instant.
    ///
    /// Carved streams have no recorder clock. Reporting `Unknown` (never UTC) is a hard
    /// forensic rule — a fabricated timeline is worse than an honest absence.
    fn unknown_time(&self, profile: &OemProfile) -> TimeEvidence {
        let prov = Provenance::new(
            forensic_core::EvidenceId::new(),
            self.profile_hash(profile),
            vec![],
            &self.id,
            &self.version,
            Hash::sha256(vec![0; 32]),
            ValidationState::new(
                forensic_core::ValidationStateKind::Unknown,
                "Carved stream carries no recorder timestamp",
                "unified_parse",
                "raw_time",
            )
            .unwrap(),
        );
        TimeEvidence {
            raw: RawTimestamp {
                value: 0,
                format: "none".into(),
                source: prov,
            },
            recorder_native: None,
            normalized: None,
            reference: None,
            timezone: TimeZoneState::Unknown,
            correction: None,
        }
    }
}

impl Parser for UnifiedParser {
    fn id(&self) -> &str {
        &self.id
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn parse_filesystem(
        &self,
        _reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Vec<ParserRun>, ForensicError> {
        // The fallback makes no filesystem claim — it does not know the OEM layout.
        Ok(vec![self.run(
            profile,
            "parse_filesystem",
            ValidationState::new(
                forensic_core::ValidationStateKind::Unknown,
                "Unified fallback does not interpret OEM filesystem structures",
                "parse_filesystem",
                "filesystem",
            )
            .unwrap(),
        )])
    }

    fn parse_metadata(
        &self,
        _reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Vec<ParserRun>, ForensicError> {
        Ok(vec![self.run(
            profile,
            "parse_metadata",
            ValidationState::new(
                forensic_core::ValidationStateKind::Unknown,
                "Unified fallback has no OEM index metadata to parse",
                "parse_metadata",
                "metadata",
            )
            .unwrap(),
        )])
    }

    fn parse_recordings(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<(Vec<Recording>, Vec<ParserRun>), ForensicError> {
        let regions = scan_carved_regions(reader)?;

        let state = if regions.is_empty() {
            ValidationState::new(
                forensic_core::ValidationStateKind::Review,
                "Unified fallback scan found no codec-bearing regions",
                "parse_recordings",
                "carve",
            )
            .unwrap()
        } else {
            // Carved output is inherently unverified against an index -> REVIEW, never PASS.
            ValidationState::new(
                forensic_core::ValidationStateKind::Review,
                format!(
                    "Unified fallback carved {} codec-bearing region(s) without OEM index corroboration",
                    regions.len()
                ),
                "parse_recordings",
                "carve",
            )
            .unwrap()
        };

        let mut recordings = Vec::new();
        for region in &regions {
            let reg = Region::new(region.offset, region.length)?;
            recordings.push(Recording::new(
                0, // channel unknown for a carved stream
                self.unknown_time(profile),
                reader.source_path().to_string(),
                vec![reg],
                self.id.clone(),
                self.version.clone(),
                ProfileId(profile.profile_id.clone()),
                self.profile_hash(profile),
            ));
        }

        Ok((recordings, vec![self.run(profile, "parse_recordings", state)]))
    }

    fn extract_timeline_events(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<(Vec<TimelineEvent>, Vec<ParserRun>), ForensicError> {
        let regions = scan_carved_regions(reader)?;

        let state = if regions.is_empty() {
            ValidationState::new(
                forensic_core::ValidationStateKind::Unknown,
                "No carved regions to place on a timeline",
                "extract_timeline_events",
                "carve",
            )
            .unwrap()
        } else {
            ValidationState::new(
                forensic_core::ValidationStateKind::Review,
                format!(
                    "{} carved region(s) placed on the timeline with Unknown timezone",
                    regions.len()
                ),
                "extract_timeline_events",
                "carve",
            )
            .unwrap()
        };

        let mut events = Vec::new();
        for region in &regions {
            let reg = Region::new(region.offset, 64.min(region.length).max(1))?;
            events.push(TimelineEvent::new(
                0,
                self.unknown_time(profile),
                format!(
                    "Carved {} region at 0x{:X} ({} NAL/marker(s)) — no recorder time",
                    region.codec.label(),
                    region.offset,
                    region.nal_count
                ),
                vec![reg],
                self.id.clone(),
                self.version.clone(),
                ProfileId(profile.profile_id.clone()),
                self.profile_hash(profile),
            ));
        }

        Ok((events, vec![self.run(profile, "extract_timeline_events", state)]))
    }

    fn validate_structure(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Vec<ParserRun>, ForensicError> {
        let regions = scan_carved_regions(reader)?;
        let state = if regions.is_empty() {
            ValidationState::new(
                forensic_core::ValidationStateKind::Review,
                "No codec structure recognized by the unified fallback",
                "validate_structure",
                "carve",
            )
            .unwrap()
        } else {
            ValidationState::new(
                forensic_core::ValidationStateKind::Review,
                format!(
                    "{} codec region(s) recognized; structural completeness unverifiable without an OEM index",
                    regions.len()
                ),
                "validate_structure",
                "carve",
            )
            .unwrap()
        };
        Ok(vec![self.run(profile, "validate_structure", state)])
    }

    fn recognize_candidate(
        &self,
        reader: &dyn EvidenceReader,
        _profile: &OemProfile,
    ) -> Result<bool, ForensicError> {
        Ok(!scan_carved_regions(reader)?.is_empty())
    }
}

/// A located NAL start code.
struct StartCode {
    /// Offset of the byte immediately after the start code (the NAL header).
    header_pos: usize,
}

/// Find all Annex-B start codes (`00 00 01` and `00 00 00 01`) in `data`.
fn find_start_codes(data: &[u8]) -> Vec<StartCode> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 3 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            out.push(StartCode { header_pos: i + 3 });
            i += 3;
        } else {
            i += 1;
        }
    }
    out
}

/// Tally codec evidence for a single NAL header, updating running scores.
///
/// Uses the full two-byte HEVC header validation so that the common H.264 P-slice
/// header `0x41` is not misread as an HEVC VPS (the same trap fixed in the
/// reconstructor's classifier).
fn score_nal(data: &[u8], header_pos: usize, h264: &mut u32, h265: &mut u32) -> bool {
    if header_pos >= data.len() {
        return false;
    }
    let b0 = data[header_pos];
    let forbidden = (b0 & 0x80) != 0;
    if forbidden {
        return false;
    }

    // H.264 interpretation.
    let h264_type = b0 & 0x1F;
    // H.265 interpretation (two-byte header).
    let h265_type = (b0 >> 1) & 0x3F;
    let b1 = data.get(header_pos + 1).copied();
    let tid_plus1 = b1.map(|b| b & 0x07).unwrap_or(0);
    let layer_id = b1
        .map(|b| (((b0 & 0x01) as u16) << 5) | ((b >> 3) & 0x1F) as u16)
        .unwrap_or(u16::MAX);
    let h265_base_layer = tid_plus1 != 0 && layer_id == 0;

    let mut scored = false;
    // HEVC parameter sets require TemporalId 0 (second byte 0x01 on base layer).
    if h265_base_layer && tid_plus1 == 1 {
        match h265_type {
            32 => {
                *h265 += 6;
                scored = true;
            } // VPS
            33 => {
                *h265 += 5;
                scored = true;
            } // SPS
            34 => {
                *h265 += 4;
                scored = true;
            } // PPS
            _ => {}
        }
    }
    if h265_base_layer && matches!(h265_type, 19 | 20) {
        *h265 += 3; // IDR
        scored = true;
    }

    match h264_type {
        7 => {
            *h264 += 5;
            scored = true;
        } // SPS
        8 => {
            *h264 += 4;
            scored = true;
        } // PPS
        5 => {
            *h264 += 3;
            scored = true;
        } // IDR
        _ => {}
    }
    scored
}

/// Whether a NAL header is a stream-restart boundary (a new coded video sequence).
fn is_boundary(data: &[u8], header_pos: usize) -> bool {
    if header_pos >= data.len() {
        return false;
    }
    let b0 = data[header_pos];
    if (b0 & 0x80) != 0 {
        return false;
    }
    let h264_sps = (b0 & 0x1F) == 7;
    let h265_type = (b0 >> 1) & 0x3F;
    let b1 = data.get(header_pos + 1).copied();
    let tid_plus1 = b1.map(|b| b & 0x07).unwrap_or(0);
    let h265_vps = h265_type == 32 && tid_plus1 == 1;
    h264_sps || h265_vps
}

/// Scan the evidence (bounded window) and group codec activity into carved regions.
pub fn scan_carved_regions(reader: &dyn EvidenceReader) -> Result<Vec<CarvedRegion>, ForensicError> {
    let scan_len = reader.len().min(MAX_SCAN_BYTES) as usize;
    if scan_len == 0 {
        return Ok(vec![]);
    }
    let mut buf = vec![0u8; scan_len];
    let n = reader.read_at(0, &mut buf)?;
    let data = &buf[..n];

    // MJPEG: a plain SOI at the very start with no NAL start codes.
    let start_codes = find_start_codes(data);
    if start_codes.is_empty() {
        if data.len() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
            return Ok(vec![CarvedRegion {
                offset: 0,
                length: data.len() as u64,
                codec: CarvedCodec::Mjpeg,
                nal_count: 0,
            }]);
        }
        return Ok(vec![]);
    }

    let mut regions = Vec::new();
    let mut run_start = start_codes[0].header_pos.saturating_sub(3);
    let mut run_h264 = 0u32;
    let mut run_h265 = 0u32;
    let mut run_nals = 0usize;
    let mut prev_pos = start_codes[0].header_pos;

    let flush = |regions: &mut Vec<CarvedRegion>,
                 start: usize,
                 end: usize,
                 h264: u32,
                 h265: u32,
                 nals: usize| {
        if nals >= MIN_NALS_PER_RUN {
            let codec = if h264 == 0 && h265 == 0 {
                CarvedCodec::Unknown
            } else if h265 > h264 {
                CarvedCodec::H265
            } else {
                CarvedCodec::H264
            };
            regions.push(CarvedRegion {
                offset: start as u64,
                length: (end.saturating_sub(start)).max(1) as u64,
                codec,
                nal_count: nals,
            });
        }
    };

    for (idx, sc) in start_codes.iter().enumerate() {
        let pos = sc.header_pos;
        let gap = pos.saturating_sub(prev_pos);
        let boundary = is_boundary(data, pos) && run_nals >= MIN_NALS_PER_RUN;

        if idx > 0 && (gap > RUN_GAP_BYTES || boundary) {
            // Close the current run at the previous NAL, start a fresh run here.
            flush(&mut regions, run_start, prev_pos, run_h264, run_h265, run_nals);
            run_start = pos.saturating_sub(3);
            run_h264 = 0;
            run_h265 = 0;
            run_nals = 0;
        }

        if score_nal(data, pos, &mut run_h264, &mut run_h265) {
            run_nals += 1;
        } else {
            // Still counts as a NAL for grouping purposes even if it is a slice.
            run_nals += 1;
        }
        prev_pos = pos;
    }

    // Close the final run, extending to the scan end.
    flush(&mut regions, run_start, data.len(), run_h264, run_h265, run_nals);

    Ok(regions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_core::ValidationStateKind;

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
                    "t",
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
            "mem://unified"
        }
    }

    fn profile() -> OemProfile {
        OemProfile::from_toml_str(
            r#"
profile_id = "unified-fallback"
profile_version = "1.0.0"
schema_version = "1.0"
oem = "unified"
storage_family = "GENERIC"
[applicability]
[[signatures]]
name = "noop"
pattern_hex = "00"
evidence_status = "provisional"
weight = 0.1
is_exclusive = false
explanation = "placeholder signature for the generic fallback profile"
[confidence_weights]
max_possible_score = 1.0
"#,
        )
        .unwrap()
    }

    fn h264() -> Vec<u8> {
        let mut v = vec![0u8; 16]; // leading padding
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1F]);
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x3C, 0x80]);
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x65, 0xB8, 0x00, 0x04]);
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x41, 0x9A, 0x00, 0x01]); // P-slice
        v
    }

    fn h265() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x0C, 0x01]); // VPS
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x42, 0x01, 0x01, 0x01]); // SPS
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x44, 0x01, 0xC0, 0xF3]); // PPS
        v
    }

    #[test]
    fn carves_h264_region() {
        let reader = MemReader { data: h264() };
        let regions = scan_carved_regions(&reader).unwrap();
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].codec, CarvedCodec::H264);
        assert!(regions[0].nal_count >= 3);
    }

    #[test]
    fn h264_pslice_not_misread_as_h265() {
        // The P-slice header 0x41 must not tip the codec vote to H.265.
        let reader = MemReader { data: h264() };
        let regions = scan_carved_regions(&reader).unwrap();
        assert_eq!(regions[0].codec, CarvedCodec::H264);
    }

    #[test]
    fn carves_h265_region() {
        let reader = MemReader { data: h265() };
        let regions = scan_carved_regions(&reader).unwrap();
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].codec, CarvedCodec::H265);
    }

    #[test]
    fn empty_evidence_yields_no_regions() {
        let reader = MemReader { data: vec![0u8; 4096] };
        assert!(scan_carved_regions(&reader).unwrap().is_empty());
    }

    #[test]
    fn recordings_have_unknown_timezone_never_utc() {
        let reader = MemReader { data: h264() };
        let (recs, runs) = UnifiedParser::default()
            .parse_recordings(&reader, &profile())
            .unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].time.timezone, TimeZoneState::Unknown);
        assert!(recs[0].time.normalized.is_none());
        // Carved recordings are never asserted as verified.
        assert_eq!(runs[0].validation_state.state, ValidationStateKind::Review);
    }

    #[test]
    fn recognizes_candidate_when_codec_present() {
        let p = profile();
        let up = UnifiedParser::default();
        assert!(up
            .recognize_candidate(&MemReader { data: h264() }, &p)
            .unwrap());
        assert!(!up
            .recognize_candidate(&MemReader { data: vec![0u8; 512] }, &p)
            .unwrap());
    }

    #[test]
    fn two_sequences_split_into_two_regions() {
        // Two H.264 sequences separated by a large gap carve into two regions.
        let mut data = h264();
        data.extend(vec![0u8; RUN_GAP_BYTES + 16]);
        data.extend(h264());
        let reader = MemReader { data };
        let regions = scan_carved_regions(&reader).unwrap();
        assert_eq!(regions.len(), 2);
    }
}
