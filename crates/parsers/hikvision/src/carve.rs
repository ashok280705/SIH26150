//! # Raw Hikvision carving
//!
//! The last tier of the recovery hierarchy. Where the B-tree references nothing and a block
//! footer describes nothing, the video data itself may still hold recoverable recordings.
//! This module walks those bytes structurally.
//!
//! ## The sentinel is one clue, not the rule
//!
//! `FF FF FF FB` appears adjacent to recoverable Hikvision stream data. Treating its presence
//! as sufficient would report every coincidental four-byte match as a recording; treating its
//! absence as disqualifying would discard real recordings. So it is one of seven independent
//! conditions a candidate is scored against:
//!
//! 1. the candidate lies inside the physical region that was asked to be carved;
//! 2. its container framing walks — at least the profile's minimum number of parts;
//! 3. it carries the expected MPEG-PS tag mix — a pack header *and* a video PES;
//! 4. every declared length inside it validated, with no rejection in its extent;
//! 5. it ends on a part boundary, so its extent is structurally recoverable;
//! 6. its video payload establishes a codec;
//! 7. the sentinel appears within the profile's proximity window of its start.
//!
//! A candidate must satisfy at least `hikvision_carve_min_conditions` of them to be reported
//! as recoverable. Ones that fall short are still described — with the conditions they missed
//! — because "there is structure here that did not verify" is a finding, not nothing.
//!
//! ## Many candidates per region, no arbitrary boundaries
//!
//! A scan region is not one candidate. The scanner finds every pack-header start in the
//! region and walks each one to the end of its own valid framing, so a 1 GiB block can yield
//! hundreds of candidates at their true extents. Nothing is truncated at a window edge: the
//! container walk resumes reading past a window when a candidate is longer than one, and the
//! next search position is the end of the candidate that was just accepted.
//!
//! ## Carving establishes no state
//!
//! A [`CarvedCandidate`] says bytes with valid Hikvision framing are physically present. It
//! says nothing about whether the recorder referenced them, so it can never produce
//! `Active`, and on its own it cannot produce `Deleted` either. State classification stays
//! with the generic engine, driven by [`crate::volume::recording_index`].

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, OemProfile, Region, ValidationState, ValidationStateKind};
use parsers_core::storage::ContainerRecord;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::layout::{key, magic, sig, u64_from, usize_from, vs};
use crate::ps::{self, ClipStream, HikCodec};

/// One corroborating condition, and whether the candidate met it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Condition {
    pub name: String,
    pub satisfied: bool,
    pub detail: String,
}

impl Condition {
    fn new(name: &str, satisfied: bool, detail: String) -> Self {
        Self {
            name: name.to_string(),
            satisfied,
            detail,
        }
    }
}

/// A candidate recording located by structural carving.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CarvedCandidate {
    /// Absolute physical extent of the candidate, ending where its valid framing ended.
    pub region: Region,
    /// The region that was being carved when this candidate was found.
    pub originating_region: Region,
    /// Ordered video payload ranges inside the candidate.
    pub payload_regions: Vec<Region>,
    /// Container parts located.
    pub part_count: usize,
    /// Pack serials, in order.
    pub pack_serials: Vec<u32>,
    /// Absolute offsets where the structural sentinel was seen near this candidate.
    pub sentinel_offsets: Vec<u64>,
    /// The conditions evaluated, satisfied or not.
    pub conditions: Vec<Condition>,
    /// How many conditions were satisfied.
    pub satisfied_count: usize,
    /// Whether the candidate met the profile's minimum corroboration.
    pub recoverable: bool,
    /// Codec, from the candidate's own video payload.
    pub codec: ps::CodecEvidence,
    pub evidence: ValidationState,
}

impl CarvedCandidate {
    /// A stable identifier derived from the candidate's physical position.
    pub fn candidate_id(&self) -> String {
        format!("hikcarve:{:#x}:{}", self.region.offset, self.region.length)
    }

    pub fn payload_bytes(&self) -> u64 {
        self.payload_regions
            .iter()
            .fold(0u64, |a, r| a.saturating_add(r.length))
    }

    /// Convert to the generic structural-carving record the recovery engine consumes.
    ///
    /// Offsets stay absolute. The first payload range is reported as the record's payload;
    /// the full ordered list stays in the metadata so a multi-part candidate is not reduced
    /// to its first fragment.
    pub fn to_container_record(&self) -> ContainerRecord {
        let mut oem_metadata: BTreeMap<String, String> = BTreeMap::new();
        oem_metadata.insert("hikvision_candidate_id".into(), self.candidate_id());
        oem_metadata.insert(
            "hikvision_discovery_method".into(),
            "raw-mpeg-ps-structural-carving".into(),
        );
        oem_metadata.insert(
            "hikvision_carve_part_count".into(),
            self.part_count.to_string(),
        );
        oem_metadata.insert(
            "hikvision_carve_payload_bytes".into(),
            self.payload_bytes().to_string(),
        );
        oem_metadata.insert(
            "hikvision_carve_payload_regions".into(),
            self.payload_regions
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<_>>()
                .join(" "),
        );
        oem_metadata.insert(
            "hikvision_carve_originating_region".into(),
            self.originating_region.to_string(),
        );
        oem_metadata.insert(
            "hikvision_carve_conditions_satisfied".into(),
            format!("{}/{}", self.satisfied_count, self.conditions.len()),
        );
        oem_metadata.insert(
            "hikvision_carve_conditions".into(),
            self.conditions
                .iter()
                .map(|c| format!("{}={}", c.name, c.satisfied))
                .collect::<Vec<_>>()
                .join(","),
        );
        oem_metadata.insert(
            "hikvision_carve_recoverable".into(),
            self.recoverable.to_string(),
        );
        if !self.sentinel_offsets.is_empty() {
            oem_metadata.insert(
                "hikvision_carve_sentinel_offsets".into(),
                self.sentinel_offsets
                    .iter()
                    .map(|o| o.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        if !self.pack_serials.is_empty() {
            oem_metadata.insert(
                "hikvision_carve_pack_serials".into(),
                self.pack_serials
                    .iter()
                    .take(16)
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        oem_metadata.insert("hikvision_codec".into(), self.codec.codec.label().into());
        oem_metadata.insert(
            "hikvision_codec_confidence".into(),
            format!("{:.2}", self.codec.confidence),
        );
        oem_metadata.insert("hikvision_codec_evidence".into(), self.codec.reason.clone());
        // Carving cannot establish accessibility. Stating that here stops a consumer
        // reading a carved record as an index claim.
        oem_metadata.insert(
            "hikvision_carve_index_statement".into(),
            "structural carving establishes only that Hikvision container framing is physically \
             present at this offset; it makes no statement about whether the recorder's index \
             references it, and cannot support an Active or Deleted conclusion"
                .into(),
        );

        ContainerRecord {
            physical_region: self.region,
            payload_region: self.payload_regions.first().copied(),
            // Carved framing carries no channel field: the channel lives in the footer clip
            // index, which by definition is not available on this path.
            channel: None,
            // Nor any timestamp. Substituting one would be fabrication.
            start_time_unix: None,
            frame_type: Some("mpeg-ps-clip".to_string()),
            codec_hint: match self.codec.codec {
                HikCodec::Unknown => None,
                other => Some(other.label().to_string()),
            },
            oem_metadata,
            evidence: self.evidence.clone(),
        }
    }
}

/// The result of carving one physical region.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CarveResult {
    pub region: Region,
    /// Candidates found, in physical order. May be many.
    pub candidates: Vec<CarvedCandidate>,
    /// Bytes read while searching.
    pub bytes_scanned: u64,
    /// Whether the per-region candidate bound stopped the search.
    pub candidate_guard_reached: bool,
    pub evidence: ValidationState,
}

impl CarveResult {
    /// Candidates that met the profile's minimum corroboration.
    pub fn recoverable(&self) -> impl Iterator<Item = &CarvedCandidate> {
        self.candidates.iter().filter(|c| c.recoverable)
    }
}

/// Carve a physical region for Hikvision MPEG-PS candidates.
///
/// Streams the region through a bounded, overlapping window. A candidate longer than the
/// window is still described in full, because the container walk does its own bounded reads
/// from the candidate's start to the end of the region.
pub fn carve_region(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    region: Region,
) -> Result<CarveResult, ForensicError> {
    let window = u64_from(profile, key::CARVE_WINDOW_BYTES, 4 << 20).max(4096);
    let overlap = u64_from(profile, key::CARVE_WINDOW_OVERLAP_BYTES, 512);
    let max_candidates = u64_from(profile, key::CARVE_MAX_CANDIDATES_PER_REGION, 65_536) as usize;
    let min_parts = usize_from(profile, key::CARVE_MIN_PARTS, 3);
    let min_conditions = usize_from(profile, key::CARVE_MIN_CONDITIONS, 4);
    let proximity = u64_from(profile, key::CARVE_SENTINEL_PROXIMITY_BYTES, 65_536);

    let pack_magic = magic(profile, sig::PS_PACK_HEADER).unwrap_or_else(|| vec![0, 0, 1, 0xBA]);
    let sentinel =
        magic(profile, sig::CARVE_SENTINEL).unwrap_or_else(|| vec![0xFF, 0xFF, 0xFF, 0xFB]);

    let region_end = region
        .offset
        .saturating_add(region.length)
        .min(reader.len());
    if region.offset >= region_end {
        return Ok(CarveResult {
            region,
            candidates: Vec::new(),
            bytes_scanned: 0,
            candidate_guard_reached: false,
            evidence: vs(
                ValidationStateKind::Unknown,
                format!(
                    "the carve region {region} lies outside the {}-byte evidence",
                    reader.len()
                ),
                "hikvision_carve",
                "region",
            ),
        });
    }

    let mut candidates: Vec<CarvedCandidate> = Vec::new();
    let mut sentinel_hits: Vec<u64> = Vec::new();
    let mut bytes_scanned = 0u64;
    let mut guard_reached = false;

    // `search` is the next offset to look for a candidate start at. It jumps past an accepted
    // candidate, so overlapping candidates are not reported twice.
    let mut search = region.offset;
    let mut window_start = region.offset;

    while window_start < region_end && candidates.len() < max_candidates {
        let want = (region_end - window_start).min(window) as usize;
        let mut buf = vec![0u8; want];
        let n = match reader.read_at(window_start, &mut buf) {
            Ok(n) => n,
            // A window that cannot be read is not a fatal error: record nothing for it and
            // continue past, so one bad sector does not abandon the region.
            Err(_) => {
                window_start = window_start.saturating_add(window);
                continue;
            }
        };
        buf.truncate(n);
        if buf.is_empty() {
            break;
        }
        bytes_scanned = bytes_scanned.saturating_add(n as u64);

        // Record every sentinel occurrence in this window. They corroborate candidates
        // later; they never by themselves create one.
        for i in find_all(&buf, &sentinel) {
            let abs = window_start.saturating_add(i as u64);
            if !sentinel_hits.contains(&abs) {
                sentinel_hits.push(abs);
            }
        }

        // Every pack-header start in this window, at or after the search cursor.
        for i in find_all(&buf, &pack_magic) {
            if candidates.len() >= max_candidates {
                guard_reached = true;
                break;
            }
            let start = window_start.saturating_add(i as u64);
            if start < search {
                continue;
            }

            // Walk this candidate's own framing to its natural end. The walk reads past the
            // current window as needed, so the candidate is never truncated at a window edge.
            let Ok(search_span) = Region::new(start, region_end.saturating_sub(start)) else {
                continue;
            };
            let stream = ps::walk_contiguous(reader, profile, search_span)?;

            if stream.parts.len() < min_parts {
                // Not enough structure to be a candidate at all. Move past this start code
                // only, not past the whole window, so a real candidate just after it is
                // still found.
                continue;
            }

            let conditions = evaluate(
                &stream,
                &region,
                start,
                &sentinel_hits,
                proximity,
                min_parts,
            );
            let satisfied_count = conditions.iter().filter(|c| c.satisfied).count();
            let recoverable = satisfied_count >= min_conditions;

            let candidate = CarvedCandidate {
                region: stream.region,
                originating_region: region,
                payload_regions: stream.payload_regions.clone(),
                part_count: stream.parts.len(),
                pack_serials: stream.pack_serials.clone(),
                sentinel_offsets: sentinel_hits
                    .iter()
                    .copied()
                    .filter(|s| start.saturating_sub(proximity) <= *s && *s <= start)
                    .collect(),
                evidence: candidate_evidence(
                    &stream,
                    &conditions,
                    satisfied_count,
                    min_conditions,
                    recoverable,
                ),
                conditions,
                satisfied_count,
                recoverable,
                codec: stream.codec.clone(),
            };

            // Continue searching after this candidate's extent, so its interior start codes
            // do not each spawn a duplicate candidate.
            search = candidate
                .region
                .offset
                .saturating_add(candidate.region.length)
                .max(start.saturating_add(1));
            candidates.push(candidate);
        }

        if candidates.len() >= max_candidates {
            guard_reached = true;
            break;
        }

        // Advance with overlap so framing straddling the boundary is still found. `search`
        // already prevents re-reporting anything inside an accepted candidate.
        let next = window_start
            .saturating_add(window.saturating_sub(overlap))
            .max(window_start.saturating_add(1));
        window_start = next.max(search.saturating_sub(overlap));
    }

    let evidence = result_evidence(
        &region,
        &candidates,
        bytes_scanned,
        guard_reached,
        min_conditions,
    );

    Ok(CarveResult {
        region,
        candidates,
        bytes_scanned,
        candidate_guard_reached: guard_reached,
        evidence,
    })
}

/// Evaluate the corroborating conditions for one candidate.
fn evaluate(
    stream: &ClipStream,
    carve_region: &Region,
    start: u64,
    sentinel_hits: &[u64],
    proximity: u64,
    min_parts: usize,
) -> Vec<Condition> {
    let end = stream.region.offset.saturating_add(stream.region.length);
    let region_end = carve_region.offset.saturating_add(carve_region.length);

    let in_region = start >= carve_region.offset && end <= region_end;
    let has_pack = stream
        .parts
        .iter()
        .any(|p| matches!(p.kind, ps::PartKind::PackHeader { .. }));
    let has_video = stream.parts.iter().any(|p| p.kind.is_video());
    let nearby_sentinel = sentinel_hits
        .iter()
        .any(|s| start.saturating_sub(proximity) <= *s && *s <= start);

    vec![
        Condition::new(
            "physical-region",
            in_region,
            format!(
                "the candidate's extent {}..{end} lies {}within the carved region {carve_region}",
                stream.region.offset,
                if in_region { "" } else { "NOT " }
            ),
        ),
        Condition::new(
            "frame-structure",
            stream.parts.len() >= min_parts,
            format!(
                "{} container part(s) walked, against a minimum of {min_parts}",
                stream.parts.len()
            ),
        ),
        Condition::new(
            "mpeg-ps-tags",
            has_pack && has_video,
            format!(
                "pack header present: {has_pack}; video PES present: {has_video}. Both are required \
                 because a pack header alone could be any MPEG stream and a video PES alone could \
                 be a fragment"
            ),
        ),
        Condition::new(
            "declared-lengths",
            stream.rejections.is_empty(),
            if stream.rejections.is_empty() {
                "every declared part length inside the candidate validated".to_string()
            } else {
                format!(
                    "{} declared length(s) or payload offset(s) did not validate: {}",
                    stream.rejections.len(),
                    stream.rejections[..stream.rejections.len().min(2)].join("; ")
                )
            },
        ),
        Condition::new(
            "clip-boundary",
            stream.bytes_walked == stream.region.length && stream.region.length > 0,
            format!(
                "the candidate's {} byte(s) are exactly accounted for by its {} part(s), so its end \
                 is a structural boundary rather than a scan artifact",
                stream.region.length,
                stream.parts.len()
            ),
        ),
        Condition::new(
            "codec-consistency",
            stream.codec.codec != HikCodec::Unknown,
            stream.codec.reason.clone(),
        ),
        Condition::new(
            "sentinel-proximity",
            nearby_sentinel,
            if nearby_sentinel {
                format!(
                    "the structural sentinel appears within {proximity} byte(s) before the \
                     candidate's start"
                )
            } else {
                format!(
                    "no structural sentinel appears within {proximity} byte(s) before the \
                     candidate's start. This is one clue among several and its absence is not \
                     disqualifying"
                )
            },
        ),
    ]
}

fn candidate_evidence(
    stream: &ClipStream,
    conditions: &[Condition],
    satisfied: usize,
    min_conditions: usize,
    recoverable: bool,
) -> ValidationState {
    let missed: Vec<&str> = conditions
        .iter()
        .filter(|c| !c.satisfied)
        .map(|c| c.name.as_str())
        .collect();
    let base = format!(
        "carved candidate at {} (0x{:X}), {} byte(s): {} container part(s), {} video payload \
         range(s), codec {}. {satisfied}/{} corroborating condition(s) satisfied against a minimum \
         of {min_conditions}",
        stream.region.offset,
        stream.region.offset,
        stream.region.length,
        stream.parts.len(),
        stream.payload_regions.len(),
        stream.codec.codec.label(),
        conditions.len(),
    );
    if recoverable {
        // A candidate that met the corroboration minimum is structurally trustworthy, even if
        // a non-decisive condition (typically sentinel-proximity, whose absence the brief says
        // is not disqualifying) was unmet. The unmet conditions are still named in the reason.
        let detail = if missed.is_empty() {
            base
        } else {
            format!("{base}; unmet (non-decisive): {}", missed.join(", "))
        };
        vs(
            ValidationStateKind::Pass,
            detail,
            "hikvision_carve",
            "candidate",
        )
    } else {
        vs(
            // Below the corroboration minimum. Described, but explicitly not reported as a
            // recoverable recording.
            ValidationStateKind::Review,
            format!(
                "{base}; unmet: {}. Below the corroboration minimum, so this is reported as \
                 structure that did not verify rather than as a recoverable recording",
                missed.join(", ")
            ),
            "hikvision_carve",
            "candidate",
        )
    }
}

fn result_evidence(
    region: &Region,
    candidates: &[CarvedCandidate],
    bytes_scanned: u64,
    guard_reached: bool,
    min_conditions: usize,
) -> ValidationState {
    let recoverable = candidates.iter().filter(|c| c.recoverable).count();
    if candidates.is_empty() {
        return vs(
            ValidationStateKind::Unknown,
            format!(
                "carved {bytes_scanned} byte(s) of {region} and found no Hikvision MPEG-PS \
                 candidate; the region carries no framing this platform interprets"
            ),
            "hikvision_carve",
            "region",
        );
    }
    let base = format!(
        "carved {bytes_scanned} byte(s) of {region}: {} candidate(s) located, {recoverable} meeting \
         the {min_conditions}-condition corroboration minimum",
        candidates.len()
    );
    if guard_reached {
        vs(
            ValidationStateKind::Review,
            format!(
                "{base}. The per-region candidate bound was reached, so the region may hold more \
                 than was reported"
            ),
            "hikvision_carve",
            "region",
        )
    } else if recoverable > 0 {
        vs(ValidationStateKind::Pass, base, "hikvision_carve", "region")
    } else {
        vs(
            ValidationStateKind::Review,
            format!("{base}. No candidate reached the corroboration minimum"),
            "hikvision_carve",
            "region",
        )
    }
}

/// Every offset in `haystack` where `needle` occurs.
fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    (0..=haystack.len() - needle.len())
        .filter(|&i| &haystack[i..i + needle.len()] == needle)
        .collect()
}

/// Whether a probe window carries structurally sound Hikvision container framing.
///
/// This is what `recognize_candidate` rests on. It requires a *walkable* container — a pack
/// header followed by parts whose declared lengths validate — not merely a signature match.
/// Returning true for any window carrying four coincidental bytes would make the signal
/// useless and suppress orphan discovery, which is exactly the defect this replaces.
pub fn window_carries_hikvision_framing(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    probe_bytes: u64,
) -> Result<bool, ForensicError> {
    let len = reader.len();
    if len == 0 {
        return Ok(false);
    }
    let span = probe_bytes.min(len).max(1);
    let Ok(region) = Region::new(0, span) else {
        return Ok(false);
    };
    let min_parts = usize_from(profile, key::CARVE_MIN_PARTS, 3);

    let result = carve_region(reader, profile, region)?;
    Ok(result.candidates.iter().any(|c| {
        c.part_count >= min_parts
            && !c.payload_regions.is_empty()
            && c.conditions
                .iter()
                .any(|cond| cond.name == "mpeg-ps-tags" && cond.satisfied)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::tests_support::hikvision_profile;
    use crate::testing::MemReader;

    use crate::testing::build;

    /// A self-consistent MPEG-PS clip: pack header, system header, two video PES parts.
    fn clip(serial: u32, es: &[u8]) -> Vec<u8> {
        build::clip(serial, es, 2)
    }

    fn h264() -> Vec<u8> {
        build::h264_es()
    }

    #[test]
    fn a_single_well_formed_clip_is_carved_with_its_true_extent() {
        let p = hikvision_profile();
        let c = clip(1, &h264());
        let mut data = Vec::new();
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFB]); // sentinel before the clip
        let start = data.len() as u64;
        data.extend_from_slice(&c);
        data.extend_from_slice(&[0x00u8; 4096]); // trailing slack
        let len = data.len() as u64;

        let r = MemReader::new(data);
        let out = carve_region(&r, &p, Region::new(0, len).unwrap()).unwrap();

        assert_eq!(out.candidates.len(), 1, "one clip must yield one candidate");
        let cand = &out.candidates[0];
        assert_eq!(cand.region.offset, start);
        assert_eq!(
            cand.region.length,
            c.len() as u64,
            "the candidate must end where its framing ends, not at a window edge"
        );
        assert_eq!(cand.part_count, 4);
        assert_eq!(cand.payload_regions.len(), 2);
        assert_eq!(cand.codec.codec, HikCodec::H264);
        assert!(cand.recoverable, "{}", cand.evidence.reason);
        assert!(
            !cand.sentinel_offsets.is_empty(),
            "the sentinel must be recorded"
        );
        assert_eq!(out.evidence.state, ValidationStateKind::Pass);
    }

    #[test]
    fn multiple_candidates_in_one_region_are_all_reported() {
        let p = hikvision_profile();
        let es = h264();
        let mut data = Vec::new();
        let mut expected_starts = Vec::new();
        for i in 0..5u32 {
            data.extend_from_slice(&[0x00u8; 1024]); // gap between clips
            expected_starts.push(data.len() as u64);
            data.extend_from_slice(&clip(i, &es));
        }
        let len = data.len() as u64;
        let r = MemReader::new(data);
        let out = carve_region(&r, &p, Region::new(0, len).unwrap()).unwrap();

        assert_eq!(
            out.candidates.len(),
            5,
            "a scan region is not one candidate: {:?}",
            out.candidates.iter().map(|c| c.region).collect::<Vec<_>>()
        );
        for (cand, expected) in out.candidates.iter().zip(expected_starts) {
            assert_eq!(cand.region.offset, expected);
        }
        assert_eq!(out.recoverable().count(), 5);
    }

    #[test]
    fn candidate_ids_are_distinct_and_derived_from_physical_position() {
        let p = hikvision_profile();
        let es = h264();
        let mut data = Vec::new();
        for i in 0..3u32 {
            data.extend_from_slice(&[0x00u8; 512]);
            data.extend_from_slice(&clip(i, &es));
        }
        let len = data.len() as u64;
        let r = MemReader::new(data);
        let out = carve_region(&r, &p, Region::new(0, len).unwrap()).unwrap();
        let ids: std::collections::BTreeSet<_> =
            out.candidates.iter().map(|c| c.candidate_id()).collect();
        assert_eq!(ids.len(), out.candidates.len());
        for c in &out.candidates {
            assert!(c
                .candidate_id()
                .contains(&format!("{:#x}", c.region.offset)));
        }
    }

    #[test]
    fn the_sentinel_alone_does_not_produce_a_candidate() {
        let p = hikvision_profile();
        // A region full of sentinels and nothing else.
        let mut data = Vec::new();
        for _ in 0..2000 {
            data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFB]);
        }
        let len = data.len() as u64;
        let r = MemReader::new(data);
        let out = carve_region(&r, &p, Region::new(0, len).unwrap()).unwrap();
        assert!(
            out.candidates.is_empty(),
            "the sentinel is a clue, not a sufficient condition"
        );
        assert_eq!(out.evidence.state, ValidationStateKind::Unknown);
    }

    #[test]
    fn a_candidate_without_a_nearby_sentinel_is_still_recoverable() {
        let p = hikvision_profile();
        let c = clip(1, &h264());
        let mut data = vec![0x00u8; 512];
        data.extend_from_slice(&c);
        let len = data.len() as u64;
        let r = MemReader::new(data);
        let out = carve_region(&r, &p, Region::new(0, len).unwrap()).unwrap();
        assert_eq!(out.candidates.len(), 1);
        let cand = &out.candidates[0];
        assert!(cand.sentinel_offsets.is_empty());
        let sentinel_condition = cand
            .conditions
            .iter()
            .find(|c| c.name == "sentinel-proximity")
            .unwrap();
        assert!(!sentinel_condition.satisfied);
        assert!(sentinel_condition.detail.contains("not disqualifying"));
        assert!(
            cand.recoverable,
            "absence of the sentinel must not disqualify a structurally sound candidate"
        );
    }

    #[test]
    fn a_lone_pack_header_is_not_reported_as_a_recording() {
        let p = hikvision_profile();
        let mut data = vec![0x00u8; 256];
        data.extend_from_slice(&build::pack(1));
        data.extend_from_slice(&[0xAAu8; 4096]); // nothing follows the pack header
        let len = data.len() as u64;
        let r = MemReader::new(data);
        let out = carve_region(&r, &p, Region::new(0, len).unwrap()).unwrap();
        assert!(
            out.candidates.is_empty(),
            "one part is below the minimum: {:?}",
            out.candidates
                .iter()
                .map(|c| c.part_count)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn every_condition_is_evaluated_and_reported() {
        let p = hikvision_profile();
        let mut data = vec![0xFF, 0xFF, 0xFF, 0xFB];
        data.extend_from_slice(&clip(1, &h264()));
        let len = data.len() as u64;
        let r = MemReader::new(data);
        let out = carve_region(&r, &p, Region::new(0, len).unwrap()).unwrap();
        let cand = &out.candidates[0];
        let names: Vec<&str> = cand.conditions.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "physical-region",
                "frame-structure",
                "mpeg-ps-tags",
                "declared-lengths",
                "clip-boundary",
                "codec-consistency",
                "sentinel-proximity",
            ]
        );
        assert_eq!(cand.satisfied_count, 7, "{:?}", cand.conditions);
        // Every condition carries a reason, so a report can explain the score.
        for c in &cand.conditions {
            assert!(!c.detail.is_empty(), "condition {} has no detail", c.name);
        }
    }

    #[test]
    fn valid_framing_with_an_unrecognised_payload_is_still_a_recoverable_candidate() {
        let p = hikvision_profile();
        // Video PES parts whose payload is not Annex-B at all: framing is fine, codec is not.
        let mut c = Vec::new();
        c.extend_from_slice(&build::pack(1));
        c.extend_from_slice(&build::pes(0xE0, &[0xAAu8; 64], 14));
        c.extend_from_slice(&build::pes(0xE0, &[0xAAu8; 64], 14));
        let mut data = vec![0x00u8; 128];
        data.extend_from_slice(&c);
        let len = data.len() as u64;
        let r = MemReader::new(data);
        let out = carve_region(&r, &p, Region::new(0, len).unwrap()).unwrap();
        assert_eq!(out.candidates.len(), 1);
        let cand = &out.candidates[0];
        // The codec cannot be established from this payload, and that one condition is unmet...
        assert_eq!(cand.codec.codec, HikCodec::Unknown);
        assert!(cand
            .conditions
            .iter()
            .any(|c| c.name == "codec-consistency" && !c.satisfied));
        // ...but the candidate still clears the corroboration minimum on its other conditions,
        // so it is reported as recoverable structure. A recoverable candidate is Pass; the
        // unmet, non-decisive condition is named in the evidence reason rather than downgrading
        // the whole candidate.
        assert!(cand.recoverable, "{}", cand.evidence.reason);
        assert!(
            cand.satisfied_count >= 4,
            "met {} conditions",
            cand.satisfied_count
        );
        assert_eq!(cand.evidence.state, ValidationStateKind::Pass);
        assert!(cand.evidence.reason.contains("non-decisive"));
    }

    #[test]
    fn a_candidate_below_the_corroboration_minimum_is_not_reported_recoverable() {
        // Raise the minimum above what a codec-less, sentinel-less candidate can reach, so the
        // below-minimum branch is exercised honestly.
        let mut p = hikvision_profile();
        p.layout.insert(key::CARVE_MIN_CONDITIONS.to_string(), 7);
        let mut c = Vec::new();
        c.extend_from_slice(&build::pack(1));
        c.extend_from_slice(&build::pes(0xE0, &[0xAAu8; 64], 14));
        c.extend_from_slice(&build::pes(0xE0, &[0xAAu8; 64], 14));
        let mut data = vec![0x00u8; 128];
        data.extend_from_slice(&c);
        let len = data.len() as u64;
        let r = MemReader::new(data);
        let out = carve_region(&r, &p, Region::new(0, len).unwrap()).unwrap();
        assert_eq!(out.candidates.len(), 1);
        let cand = &out.candidates[0];
        assert!(!cand.recoverable, "met {}/7", cand.satisfied_count);
        assert_eq!(cand.evidence.state, ValidationStateKind::Review);
        assert!(cand
            .evidence
            .reason
            .contains("Below the corroboration minimum"));
    }

    #[test]
    fn a_container_record_preserves_absolute_offsets_and_makes_no_index_claim() {
        let p = hikvision_profile();
        let clip_offset = 0x2000u64;
        let mut data = vec![0x00u8; clip_offset as usize];
        data.extend_from_slice(&clip(1, &h264()));
        let len = data.len() as u64;
        let r = MemReader::new(data);
        let out = carve_region(&r, &p, Region::new(0, len).unwrap()).unwrap();
        let rec = out.candidates[0].to_container_record();

        assert_eq!(
            rec.physical_region.offset, clip_offset,
            "absolute, never rebased"
        );
        assert!(rec.payload_region.unwrap().offset > clip_offset);
        assert_eq!(rec.channel, None, "carved framing carries no channel");
        assert_eq!(rec.start_time_unix, None, "no timestamp may be invented");
        assert_eq!(rec.codec_hint.as_deref(), Some("H.264"));
        let claim = rec
            .oem_metadata
            .get("hikvision_carve_index_statement")
            .unwrap();
        assert!(claim.contains("cannot support an Active or Deleted conclusion"));
        assert!(rec
            .oem_metadata
            .contains_key("hikvision_carve_conditions_satisfied"));
    }

    #[test]
    fn a_candidate_longer_than_the_carve_window_is_not_truncated() {
        let mut p = hikvision_profile();
        // Force a window far smaller than the candidate.
        p.layout.insert(key::CARVE_WINDOW_BYTES.to_string(), 8192);
        let es = h264();
        let mut c = Vec::new();
        c.extend_from_slice(&build::pack(1));
        for _ in 0..600 {
            c.extend_from_slice(&build::pes(0xE0, &es, 14));
        }
        assert!(c.len() > 8192 * 2, "the candidate must exceed the window");

        let mut data = vec![0x00u8; 256];
        let start = data.len() as u64;
        data.extend_from_slice(&c);
        let len = data.len() as u64;
        let r = MemReader::new(data);
        let out = carve_region(&r, &p, Region::new(0, len).unwrap()).unwrap();

        let cand = out
            .candidates
            .iter()
            .find(|x| x.region.offset == start)
            .expect("the candidate at the known start");
        assert_eq!(
            cand.region.length,
            c.len() as u64,
            "a candidate longer than the scan window must still be described in full"
        );
        assert_eq!(cand.part_count, 601);
    }

    #[test]
    fn carving_an_empty_or_out_of_bounds_region_is_a_result_not_an_error() {
        let p = hikvision_profile();
        let r = MemReader::new(vec![0u8; 1024]);
        let out = carve_region(&r, &p, Region::new(4096, 1024).unwrap()).unwrap();
        assert!(out.candidates.is_empty());
        assert_eq!(out.bytes_scanned, 0);
    }

    #[test]
    fn carving_never_errors_on_hostile_bytes() {
        let p = hikvision_profile();
        for fill in [0x00u8, 0xFF, 0x01] {
            let r = MemReader::new(vec![fill; 1 << 16]);
            assert!(carve_region(&r, &p, Region::new(0, 1 << 16).unwrap()).is_ok());
        }
    }

    // ── recognize_candidate's backing check ─────────────────────────────────────

    #[test]
    fn framing_recognition_is_true_only_for_a_walkable_container() {
        let p = hikvision_profile();
        let probe = u64_from(&p, key::RECOGNITION_PROBE_BYTES, 65_536);

        let mut good = Vec::new();
        good.extend_from_slice(&clip(1, &h264()));
        good.resize(4096, 0);
        let r = MemReader::new(good);
        assert!(window_carries_hikvision_framing(&r, &p, probe).unwrap());
    }

    #[test]
    fn framing_recognition_is_false_for_zeros_random_and_lone_signatures() {
        let p = hikvision_profile();
        let probe = u64_from(&p, key::RECOGNITION_PROBE_BYTES, 65_536);

        // All zeros.
        let r = MemReader::new(vec![0u8; 1 << 16]);
        assert!(!window_carries_hikvision_framing(&r, &p, probe).unwrap());

        // Deterministic pseudo-random bytes.
        let random: Vec<u8> = (0..(1u32 << 16))
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let r = MemReader::new(random);
        assert!(!window_carries_hikvision_framing(&r, &p, probe).unwrap());

        // A lone pack-header signature with nothing behind it.
        let mut lone = build::pack(1);
        lone.resize(1 << 16, 0xAA);
        let r = MemReader::new(lone);
        assert!(
            !window_carries_hikvision_framing(&r, &p, probe).unwrap(),
            "a lone signature must not be recognised as Hikvision framing"
        );

        // Sentinels only.
        let mut sentinels = Vec::new();
        for _ in 0..4000 {
            sentinels.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFB]);
        }
        let r = MemReader::new(sentinels);
        assert!(!window_carries_hikvision_framing(&r, &p, probe).unwrap());
    }

    #[test]
    fn framing_recognition_handles_an_empty_reader() {
        let p = hikvision_profile();
        let r = MemReader::new(Vec::new());
        assert!(!window_carries_hikvision_framing(&r, &p, 4096).unwrap());
    }

    #[test]
    fn find_all_locates_every_occurrence_including_adjacent_ones() {
        assert_eq!(find_all(b"aXXbXXc", b"XX"), vec![1, 4]);
        assert_eq!(find_all(b"XXXX", b"XX"), vec![0, 1, 2]);
        assert!(find_all(b"abc", b"").is_empty());
        assert!(find_all(b"a", b"abc").is_empty());
    }
}
