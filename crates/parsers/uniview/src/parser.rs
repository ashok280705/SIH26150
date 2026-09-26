//! # UniviewParser
//!
//! The [`Parser`] implementation for the Uniview storage family. Every stage reads the volume
//! through [`crate::volume::read_volume`]:
//!
//! ```text
//!   SUPER magic → UI / UI-CTL → UI-DATA → units → DI → SPtoI → DATA
//! ```
//!
//! | Stage | Reports |
//! |---|---|
//! | `validate_structure`      | SUPER, UI, UI-DATA and per-unit DI findings, by kind |
//! | `parse_filesystem`        | whether the Uniview structure set applies, and its generation |
//! | `parse_metadata`          | UI/UI-DATA and DI index facts, with the index's partial authority |
//! | `parse_recordings`        | one `Recording` per storage-unit index group |
//! | `extract_timeline_events` | one event per index group with a decodable time |
//!
//! ## What is never claimed here
//!
//! * **Channel.** No established Uniview field records a channel (DI field A and the UI-DATA
//!   lock are UNKNOWN). Channel 0 — the platform's "unknown channel" value — is used where a
//!   type requires a number, and an anomaly says so.
//! * **Codec.** DATA framing is unknown; no codec hint is ever set.
//! * **Timezone.** Wall-clock digits are read as UTC and [`TimeZoneState::Unknown`] is kept.
//! * **Deletion.** No deletion structure is known; `AllocationEvidence::Unknown` throughout.
//! * **Structural carving.** No DATA framing is known, so
//!   [`Parser::scan_region_for_candidates`] honestly returns no records.

use evidence_reader::EvidenceReader;
use forensic_core::identifiers::ProfileId;
use forensic_core::{
    ForensicError, Hash, IntegrityFlag, NormalizedTime, OemProfile, ParserRun, Provenance,
    RawTimestamp, RecorderNativeTime, Recording, Region, SourceRegion, TimeEvidence, TimeZoneState,
    TimelineEvent, ValidationState, ValidationStateKind,
};
use parsers_core::storage::{ContainerRecord, RecordingIndex, StorageGeometry};
use parsers_core::Parser;

use crate::data::{self, ExtractedData};
use crate::di::{DiHeaderState, SpanBasis};
use crate::layout::{u32_at, vs, UniviewLayout};
use crate::recovery::{self, RecoveryOptions, UniviewRecoveryReport};
use crate::report::{self, UniviewForensicReport};
use crate::superblock::SuperRecognition;
use crate::timestamp::{UnvTimestamp, NORMALIZATION_METHOD, RAW_FORMAT};
use crate::volume::{self, UnitRecord, UniviewVolume, GROUPING_NOTE};

pub struct UniviewParser {
    pub id: String,
    pub version: String,
}

impl Default for UniviewParser {
    fn default() -> Self {
        Self {
            id: "uniview-super-di-parser".to_string(),
            version: "2.0.0".to_string(),
        }
    }
}

impl UniviewParser {
    fn profile_hash(&self, profile: &OemProfile) -> Hash {
        // A profile with no computed hash is a loader problem, not evidence. Hash the profile
        // id so the value is deterministic and traceable rather than an all-zero placeholder.
        profile.profile_hash.clone().unwrap_or_else(|| {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"uniview-profile-id:");
            h.update(profile.profile_id.as_bytes());
            h.update(b"@");
            h.update(profile.profile_version.as_bytes());
            Hash::sha256(h.finalize().to_vec())
        })
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

    fn provenance(&self, profile: &OemProfile, offset: u64, len: u64, detail: &str) -> Provenance {
        let hash = self.profile_hash(profile);
        let region = Region::new(offset, len).unwrap_or(Region::point(offset));
        // A parser does not own an `EvidenceId`; the nil id records that honestly and the
        // structure's physical offset carries the identification.
        Provenance::new(
            forensic_core::EvidenceId(uuid::Uuid::nil()),
            hash.clone(),
            vec![
                SourceRegion::new(forensic_core::EvidenceId(uuid::Uuid::nil()), region)
                    .with_description(detail.to_string()),
            ],
            &self.id,
            &self.version,
            hash,
            vs(
                ValidationStateKind::Pass,
                detail,
                "uniview_timestamp_provenance",
                "packed_timestamp",
            ),
        )
        .with_profile(profile.profile_version.clone(), self.profile_hash(profile))
    }

    /// `TimeEvidence` from a packed timestamp: native digits, UTC reading, no timezone.
    pub fn time_evidence(&self, profile: &OemProfile, ts: &UnvTimestamp) -> TimeEvidence {
        TimeEvidence {
            raw: RawTimestamp {
                value: ts.raw_value(),
                format: RAW_FORMAT.to_string(),
                source: self.provenance(
                    profile,
                    ts.field_offset,
                    5,
                    &format!("Uniview packed timestamp: {}", ts.label()),
                ),
            },
            recorder_native: ts
                .wall_clock()
                .map(|iso_8601| RecorderNativeTime { iso_8601 }),
            normalized: ts.iso_8601_as_utc().map(|iso_8601| NormalizedTime {
                iso_8601,
                method: NORMALIZATION_METHOD.to_string(),
            }),
            reference: None,
            // Load-bearing: no offset was established, so none is claimed.
            timezone: TimeZoneState::Unknown,
            correction: None,
        }
    }

    fn absent_time_evidence(&self, profile: &OemProfile, offset: u64, why: &str) -> TimeEvidence {
        TimeEvidence {
            raw: RawTimestamp {
                value: 0,
                format: format!("{RAW_FORMAT}_ABSENT"),
                source: self.provenance(profile, offset, 16, why),
            },
            recorder_native: None,
            normalized: None,
            reference: None,
            timezone: TimeZoneState::Unknown,
            correction: None,
        }
    }

    fn unit_to_recording(&self, profile: &OemProfile, source: &str, u: &UnitRecord) -> Recording {
        let time = match &u.earliest {
            Some(t) => self.time_evidence(profile, t),
            None => self.absent_time_evidence(
                profile,
                u.di_offset,
                "no DI entry in this unit carries a decodable timestamp",
            ),
        };
        let mut rec = Recording::new(
            0,
            time,
            source.to_string(),
            u.data_regions.clone(),
            self.id.clone(),
            self.version.clone(),
            ProfileId(profile.profile_id.clone()),
            self.profile_hash(profile),
        );
        rec.add_anomaly(IntegrityFlag::Custom(format!(
            "{} ({})",
            GROUPING_NOTE,
            u.recording_id()
        )));
        rec.add_anomaly(IntegrityFlag::Custom(
            "no channel is recorded in any established Uniview field (DI field A and the UI-DATA \
             lock are UNKNOWN); channel 0 here means unknown"
                .into(),
        ));
        rec.add_anomaly(IntegrityFlag::Custom(
            "DATA codec/container/framing is UNKNOWN; the source ranges are raw DATA blocks".into(),
        ));
        let lower_bound: u64 = u
            .span_basis_counts
            .iter()
            .filter(|(k, _)| {
                k.as_str() != SpanBasis::AdjacentSptoi.label()
                    && k.as_str() != SpanBasis::ExportDataEnd.label()
            })
            .map(|(_, v)| *v)
            .sum();
        if lower_bound > 0 {
            rec.add_anomaly(IntegrityFlag::Custom(format!(
                "{lower_bound} DI entr(y/ies) had no adjacent SPtoI supporting an extent; only the \
                 block each SPtoI selects is claimed for them"
            )));
        }
        if u.spans_truncated_by_image > 0 {
            rec.add_anomaly(IntegrityFlag::LengthMismatch);
        }
        if u.timestamp_regressions > 0 {
            rec.add_anomaly(IntegrityFlag::TimestampBoundsAnomaly);
        }
        if u.sptoi_into_di > 0 || u.sptoi_outside_image > 0 {
            rec.add_anomaly(IntegrityFlag::InvalidPointer);
        }
        for a in &u.anomalies {
            rec.add_anomaly(IntegrityFlag::Custom(a.clone()));
        }
        rec
    }
}

impl Parser for UniviewParser {
    fn id(&self) -> &str {
        &self.id
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn parse_filesystem(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Vec<ParserRun>, ForensicError> {
        let vol = volume::read_volume(reader, profile)?;
        let state = match &vol.super_block.recognition {
            SuperRecognition::Recognized { .. } | SuperRecognition::H3crdExport { .. } => {
                vol.evidence.clone()
            }
            other => other.validation(),
        };
        Ok(vec![self.run(profile, "parse_filesystem", state)])
    }

    fn parse_metadata(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Vec<ParserRun>, ForensicError> {
        let vol = volume::read_volume(reader, profile)?;
        let state = if !vol.is_uniview() {
            vs(
                ValidationStateKind::Unknown,
                format!(
                    "no Uniview metadata to read: {}",
                    vol.super_block.recognition.label()
                ),
                "parse_metadata",
                "uniview_metadata",
            )
        } else {
            let mut parts = Vec::new();
            if let Some(ui) = &vol.ui {
                parts.push(ui.evidence.reason.clone());
            }
            if let Some(d) = &vol.ui_data {
                parts.push(d.evidence.reason.clone());
            }
            if let Some(ix) = volume::recording_index(&vol)? {
                parts.push(ix.evidence.reason.clone());
            }
            parts.push(format!("vendor FLOW: {}", vol.vendor_flow().label()));
            parts.push(format!(
                "filesystem-scan total of DI +0x00 over every unit in the image (not the vendor \
                 FLOW) = {} byte(s)",
                vol.scan_total_write_bytes()
            ));
            if vol.is_h3crd_export() {
                parts.push(vol.source_label().to_string());
            }
            let clean = vol.is_usable()
                && vol
                    .ui
                    .as_ref()
                    .is_some_and(|u| u.evidence.state == ValidationStateKind::Pass)
                && vol
                    .ui_data
                    .as_ref()
                    .is_none_or(|d| d.evidence.state == ValidationStateKind::Pass)
                && vol.indexed_units().next().is_some()
                && !vol.units.iter().any(UnitRecord::has_problems);
            vs(
                if clean {
                    ValidationStateKind::Pass
                } else {
                    ValidationStateKind::Review
                },
                parts.join(". "),
                "parse_metadata",
                "uniview_metadata",
            )
        };
        Ok(vec![self.run(profile, "parse_metadata", state)])
    }

    fn parse_recordings(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<(Vec<Recording>, Vec<ParserRun>), ForensicError> {
        let vol = volume::read_volume(reader, profile)?;
        let source = reader.source_path().to_string();
        let recordings: Vec<Recording> = vol
            .indexed_units()
            .map(|u| self.unit_to_recording(profile, &source, u))
            .collect();

        let state = if !recordings.is_empty() {
            let problems = vol.indexed_units().any(|u| u.has_problems());
            vs(
                if problems {
                    ValidationStateKind::Review
                } else {
                    ValidationStateKind::Pass
                },
                format!(
                    "{} storage-unit index group(s) built from {} usable DI entr(y/ies) across {} \
                     unit(s). {GROUPING_NOTE}",
                    recordings.len(),
                    vol.usable_entries(),
                    vol.units.len()
                ),
                "parse_recordings",
                "uniview_recordings",
            )
        } else if vol.is_uniview() {
            vs(
                ValidationStateKind::Review,
                format!(
                    "the Uniview structure set was read but no unit carries a usable DI entry. {}",
                    vol.evidence.reason
                ),
                "parse_recordings",
                "uniview_recordings",
            )
        } else {
            vs(
                ValidationStateKind::Unknown,
                format!(
                    "no Uniview structures were established ({})",
                    vol.super_block.recognition.label()
                ),
                "parse_recordings",
                "uniview_recordings",
            )
        };
        Ok((
            recordings,
            vec![self.run(profile, "parse_recordings", state)],
        ))
    }

    fn extract_timeline_events(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<(Vec<TimelineEvent>, Vec<ParserRun>), ForensicError> {
        let vol = volume::read_volume(reader, profile)?;
        let mut events = Vec::new();
        let mut withheld = 0usize;
        for u in vol.indexed_units() {
            // `TimelineEvent` has no "time unknown"; placing an undated group on the timeline
            // would put a fabricated instant in front of an examiner.
            let Some(t) = u.earliest.as_ref().filter(|t| t.is_decoded()) else {
                withheld += 1;
                continue;
            };
            events.push(TimelineEvent::new(
                0,
                self.time_evidence(profile, t),
                format!(
                    "Uniview {} unit {} index group ({} usable DI entr(y/ies), {} byte(s) of DATA) \
                     from {} to {} recorder wall clock; channel unknown (0 here means unknown)",
                    vol.generation().map(|g| g.label()).unwrap_or("?"),
                    u.unit,
                    u.usable_entries,
                    u.indexed_bytes(),
                    t.wall_clock().unwrap_or_default(),
                    u.latest.as_ref().and_then(|l| l.wall_clock()).unwrap_or_else(|| "unknown".into()),
                ),
                u.data_regions.clone(),
                self.id.clone(),
                self.version.clone(),
                ProfileId(profile.profile_id.clone()),
                self.profile_hash(profile),
            ));
        }
        let state = if !events.is_empty() {
            vs(
                if withheld > 0 {
                    ValidationStateKind::Review
                } else {
                    ValidationStateKind::Pass
                },
                format!(
                    "{} Uniview unit index-group event(s) extracted{}",
                    events.len(),
                    if withheld > 0 {
                        format!("; {withheld} group(s) withheld for lack of a decodable timestamp")
                    } else {
                        String::new()
                    }
                ),
                "extract_timeline_events",
                "uniview_timeline",
            )
        } else if withheld > 0 {
            vs(
                ValidationStateKind::Review,
                format!("{withheld} index group(s) found but none carries a decodable timestamp"),
                "extract_timeline_events",
                "uniview_timeline",
            )
        } else {
            vs(
                ValidationStateKind::Unknown,
                format!(
                    "no Uniview index groups were established ({})",
                    vol.super_block.recognition.label()
                ),
                "extract_timeline_events",
                "uniview_timeline",
            )
        };
        Ok((
            events,
            vec![self.run(profile, "extract_timeline_events", state)],
        ))
    }

    fn validate_structure(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Vec<ParserRun>, ForensicError> {
        let vol = volume::read_volume(reader, profile)?;
        if !vol.is_uniview() {
            return Ok(vec![self.run(
                profile,
                "validate_structure",
                vs(
                    ValidationStateKind::Unknown,
                    format!(
                        "the Uniview structure set does not apply to this evidence: {}",
                        vol.super_block.recognition.label()
                    ),
                    "validate_structure",
                    "uniview_structures",
                ),
            )]);
        }
        let mut findings = vec![vol.evidence.reason.clone()];
        let count = |f: &dyn Fn(&UnitRecord) -> bool| vol.units.iter().filter(|u| f(u)).count();
        let abnormal = count(&|u| matches!(u.header_state, DiHeaderState::CountAbnormal { .. }));
        let truncated = count(&|u| matches!(u.header_state, DiHeaderState::Truncated { .. }));
        let bad_ts: u64 = vol.units.iter().map(|u| u.invalid_timestamps).sum();
        let bad_sptoi: u64 = vol
            .units
            .iter()
            .map(|u| u.sptoi_into_di + u.sptoi_outside_image)
            .sum();
        if abnormal > 0 {
            findings.push(format!(
                "{abnormal} unit(s): {} (record count above the vendor bound); parsing continued \
                 over every non-blank record the DI region holds",
                crate::di::DI_HEAD_ABNORMAL
            ));
        }
        if truncated > 0 {
            findings.push(format!(
                "{truncated} unit(s) have a DI region truncated by the end of the image"
            ));
        }
        if bad_ts > 0 {
            findings.push(format!(
                "{bad_ts} DI entr(y/ies) carry an undecodable timestamp"
            ));
        }
        if bad_sptoi > 0 {
            findings.push(format!(
                "{bad_sptoi} DI entr(y/ies) carry an SPtoI that selects no readable DATA block"
            ));
        }
        let state = if vol.evidence.state == ValidationStateKind::Pass {
            ValidationStateKind::Pass
        } else {
            ValidationStateKind::Review
        };
        Ok(vec![self.run(
            profile,
            "validate_structure",
            vs(
                state,
                findings.join(". "),
                "validate_structure",
                "uniview_structures",
            ),
        )])
    }

    /// Whether the window begins with a structurally sound Uniview DI region.
    ///
    /// The framing inside DATA blocks is unknown, so no DATA-level recognition is possible.
    /// What *can* be recognised from bytes alone is a DI header whose declared count fits the
    /// DI capacity, followed by a first entry with a real timestamp and an SPtoI beyond the DI
    /// blocks. Anything else — including every raw DATA window — is `false`.
    fn recognize_candidate(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<bool, ForensicError> {
        let l = UniviewLayout::from_profile(profile);
        let need = l.di_entries_offset.saturating_add(l.di_entry_size);
        if reader.len() < need as u64 {
            return Ok(false);
        }
        let buf = reader.read_exact_at(0, need)?;
        let Some(count) = u32_at(&buf, l.di_entry_count_offset) else {
            return Ok(false);
        };
        // The count includes record 0, so at least one entry needs a count of 2; above the
        // vendor bound the header is abnormal and is not recognised as sound.
        if count < 2 || u64::from(count) > l.di_count_max {
            return Ok(false);
        }
        let e = &buf[l.di_entries_offset..];
        if e.len() < 8 {
            return Ok(false);
        }
        let ts = UnvTimestamp::decode(
            &e[..5],
            0,
            l.timestamp_plausible_min_year,
            l.timestamp_plausible_max_year,
        );
        let sptoi = (u64::from(e[7]) << 6) | (u64::from(e[6]) >> 2);
        Ok(ts.status == crate::timestamp::TimestampStatus::Valid && sptoi >= l.di_blocks())
    }

    fn storage_geometry(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Option<StorageGeometry>, ForensicError> {
        volume::storage_geometry(&volume::read_volume(reader, profile)?)
    }

    fn recording_index(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Option<RecordingIndex>, ForensicError> {
        volume::recording_index(&volume::read_volume(reader, profile)?)
    }

    /// No Uniview DATA framing is known, so no self-describing record can be carved. The
    /// empty result is the honest "no structural carver" answer; the engine then classifies
    /// the window with its own, OEM-independent byte classifier.
    fn scan_region_for_candidates(
        &self,
        _reader: &dyn EvidenceReader,
        _profile: &OemProfile,
        _region: Region,
    ) -> Result<Vec<ContainerRecord>, ForensicError> {
        Ok(Vec::new())
    }
}

/// Locate the unit record behind a recording id (`unv:u<unit>`).
pub fn find_recording<'a>(volume: &'a UniviewVolume, recording_id: &str) -> Option<&'a UnitRecord> {
    volume.find_unit(recording_id)
}

/// Extract the raw DATA of one index group (`unv:u<unit>`), exactly as on disk, hashed.
///
/// `Ok(None)` when the id does not resolve against this volume.
pub fn extract_recording(
    reader: &dyn EvidenceReader,
    volume: &UniviewVolume,
    recording_id: &str,
) -> Result<Option<ExtractedData>, ForensicError> {
    let Some(u) = volume.find_unit(recording_id) else {
        return Ok(None);
    };
    if u.data_regions.is_empty() {
        return Ok(None);
    }
    data::extract_regions(reader, &volume.layout, &u.data_regions).map(Some)
}

/// Extract the DATA span of one DI entry, exactly as on disk, hashed.
///
/// `Ok(None)` when the unit or entry does not exist or the entry is unusable.
pub fn extract_di_entry(
    reader: &dyn EvidenceReader,
    volume: &UniviewVolume,
    unit: u32,
    entry_index: u32,
) -> Result<Option<ExtractedData>, ForensicError> {
    let Some(detail) = volume::unit_detail(reader, volume, unit)? else {
        return Ok(None);
    };
    let Some(span) = detail.spans.iter().find(|s| s.entry_index == entry_index) else {
        return Ok(None);
    };
    let Some(region) = span.region else {
        return Ok(None);
    };
    data::extract_regions(reader, &volume.layout, &[region]).map(Some)
}

/// Build the full forensic report, including the recovery report.
pub fn forensic_report(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    options: RecoveryOptions,
) -> Result<UniviewForensicReport, ForensicError> {
    let parser = UniviewParser::default();
    let vol = volume::read_volume(reader, profile)?;
    let rec: Option<UniviewRecoveryReport> = if vol.is_uniview() {
        Some(recovery::build_recovery_report(reader, &vol, options)?)
    } else {
        None
    };
    Ok(report::build_report(
        &vol,
        profile,
        &parser.id,
        &parser.version,
        rec,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::tests_support::uniview_profile;
    use crate::testing::{build, SparseReader};
    use crate::timestamp::encode;

    #[test]
    fn a_non_uniview_image_runs_every_stage_without_asserting_anything() {
        let p = uniview_profile();
        let parser = UniviewParser::default();
        for r in [
            SparseReader::new(1 << 16),
            SparseReader::new(0),
            SparseReader::new(3),
        ] {
            assert_eq!(
                parser.parse_filesystem(&r, &p).unwrap()[0]
                    .validation_state
                    .state,
                ValidationStateKind::Unknown
            );
            assert_eq!(
                parser.parse_metadata(&r, &p).unwrap()[0]
                    .validation_state
                    .state,
                ValidationStateKind::Unknown
            );
            let (recs, runs) = parser.parse_recordings(&r, &p).unwrap();
            assert!(recs.is_empty());
            assert_eq!(runs[0].validation_state.state, ValidationStateKind::Unknown);
            let (ev, _) = parser.extract_timeline_events(&r, &p).unwrap();
            assert!(ev.is_empty());
            assert_eq!(
                parser.validate_structure(&r, &p).unwrap()[0]
                    .validation_state
                    .state,
                ValidationStateKind::Unknown
            );
            assert!(parser.storage_geometry(&r, &p).unwrap().is_none());
            assert!(parser.recording_index(&r, &p).unwrap().is_none());
        }
    }

    #[test]
    fn time_evidence_keeps_native_digits_and_claims_no_timezone() {
        let p = uniview_profile();
        let parser = UniviewParser::default();
        let ts = UnvTimestamp::decode(&encode(2024, 3, 15, 13, 45, 30), 0x1000, 2000, 2100);
        let te = parser.time_evidence(&p, &ts);
        assert_eq!(te.timezone, TimeZoneState::Unknown);
        assert_eq!(te.recorder_native.unwrap().iso_8601, "2024-03-15T13:45:30");
        let n = te.normalized.unwrap();
        assert_eq!(n.iso_8601, "2024-03-15T13:45:30Z");
        assert!(n.method.contains("no timezone offset"));
        assert_eq!(te.raw.format, RAW_FORMAT);
    }

    #[test]
    fn recognition_rests_on_a_di_header_and_never_on_raw_data() {
        let p = uniview_profile();
        let parser = UniviewParser::default();
        let di = build::di_region(
            10,
            2,
            &[build::di_entry(encode(2024, 1, 1, 0, 0, 0), 0, 16, [0; 8])],
        );
        assert!(parser
            .recognize_candidate(&SparseReader::new(0x4000).with(0, &di), &p)
            .unwrap());
        for data in [vec![0u8; 0x4000], vec![0xFF; 0x4000], build::data_block(3)] {
            let r = SparseReader::new(0x4000).with(0, &data);
            assert!(!parser.recognize_candidate(&r, &p).unwrap());
        }
        let bad = build::di_region(
            10,
            2,
            &[build::di_entry(encode(2024, 1, 1, 0, 0, 0), 0, 3, [0; 8])],
        );
        assert!(!parser
            .recognize_candidate(&SparseReader::new(0x4000).with(0, &bad), &p)
            .unwrap());
        // A count of 1 is the header alone: nothing to recognise.
        let bad = build::di_region(
            10,
            1,
            &[build::di_entry(encode(2024, 1, 1, 0, 0, 0), 0, 16, [0; 8])],
        );
        assert!(!parser
            .recognize_candidate(&SparseReader::new(0x4000).with(0, &bad), &p)
            .unwrap());
        assert!(!parser
            .recognize_candidate(&SparseReader::new(4), &p)
            .unwrap());
    }

    #[test]
    fn scanning_never_fabricates_records() {
        let p = uniview_profile();
        let r = SparseReader::new(0x8000).with(0, &build::data_block(1));
        let recs = UniviewParser::default()
            .scan_region_for_candidates(&r, &p, Region::new(0, 0x8000).unwrap())
            .unwrap();
        assert!(recs.is_empty());
    }
}
