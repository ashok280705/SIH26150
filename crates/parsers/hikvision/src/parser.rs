//! # HikvisionParser
//!
//! The [`Parser`] implementation for the Hikvision storage family. Every stage reads the
//! volume through [`crate::volume`], which walks the real structure set:
//!
//! ```text
//!   boot identifier → HIKBTREE pages → 48-byte entries → video blocks
//!                   → footer clip index → MPEG-PS/PES parts → video payload
//! ```
//!
//! ## What each stage reports
//!
//! | Stage | Reads | Reports |
//! |---|---|---|
//! | `validate_structure`   | boot, both trees, every block footer | structural findings, separated by kind |
//! | `parse_filesystem`     | boot + tree recognition              | whether the Hikvision structure set applies |
//! | `parse_metadata`       | the index recovery will act on       | exactly the index's own evidence |
//! | `parse_recordings`     | every validated clip                 | one `Recording` per clip |
//! | `extract_timeline_events` | clips with a decodable clock      | events, withholding the rest |
//!
//! ## Timestamps carry no assumed timezone
//!
//! Hikvision stores unix seconds and records no UTC offset anywhere. Time evidence produced
//! here reports the raw value, the instant read as UTC, and
//! [`TimeZoneState::Unknown`] — because no offset was established. Presenting a recorder's
//! clock in a jurisdiction's timezone needs an offset established separately, and that is an
//! evidence-layer decision, not a parser's.
//!
//! ## No deletion claim is reachable from here
//!
//! The Hikvision structures this parser reads carry no allocation, free or tombstone marker.
//! Every index entry reports [`parsers_core::storage::AllocationEvidence::Unknown`], which is
//! the only input that could produce `DataState::Deleted`. A block the B-tree does not
//! reference is reported *unreferenced*, and the generic classifier turns that into
//! `Orphaned` — never `Deleted`.

use std::collections::BTreeMap;

use evidence_reader::EvidenceReader;
use forensic_core::identifiers::ProfileId;
use forensic_core::{
    ForensicError, Hash, IntegrityFlag, NormalizedTime, OemProfile, ParserRun, Provenance,
    RawTimestamp, Recording, Region, SourceRegion, TimeEvidence, TimeZoneState, TimelineEvent,
    ValidationState, ValidationStateKind,
};
use parsers_core::storage::{ContainerRecord, RecordingIndex, StorageGeometry};
use parsers_core::Parser;

use crate::block::ClipRecord;
use crate::boot::BootRecognition;
use crate::carve;
use crate::layout::{key, u64_from, vs};
use crate::reconstruct::RecordingReconstruction;
use crate::timestamp::{HikTimestamp, NORMALIZATION_METHOD, RAW_FORMAT};
use crate::volume::{self, ClassifiedBlock, HikvisionVolume};

pub struct HikvisionParser {
    pub id: String,
    pub version: String,
}

impl Default for HikvisionParser {
    fn default() -> Self {
        Self {
            id: "hikvision-hikbtree-parser".to_string(),
            version: "2.0.0".to_string(),
        }
    }
}

impl HikvisionParser {
    fn profile_hash(&self, profile: &OemProfile) -> Hash {
        // A profile with no computed hash is a loader problem, not evidence. Hash the profile
        // id so the value is deterministic and traceable instead of an all-zero placeholder
        // that would look like a real digest in a report.
        profile.profile_hash.clone().unwrap_or_else(|| {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"hikvision-profile-id:");
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

    /// Provenance for a timestamp read out of a specific structure at a specific offset.
    ///
    /// A parser does not own an `EvidenceId`, so the nil id records that honestly rather than
    /// fabricating a fresh one that would look like a different evidence item. The structure's
    /// real physical offset carries the identification instead.
    fn timestamp_provenance(
        &self,
        profile: &OemProfile,
        structure_offset: u64,
        detail: &str,
    ) -> Provenance {
        let hash = self.profile_hash(profile);
        let region = Region::new(structure_offset, 4).unwrap_or(Region::point(structure_offset));
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
                "hikvision_timestamp_provenance",
                "unix_timestamp",
            ),
        )
        .with_profile(profile.profile_version.clone(), self.profile_hash(profile))
    }

    /// Build `TimeEvidence` from a decoded Hikvision timestamp, applying no timezone.
    fn time_evidence(&self, profile: &OemProfile, ts: &HikTimestamp) -> TimeEvidence {
        let source = self.timestamp_provenance(profile, ts.field_offset, &ts.evidence);
        TimeEvidence {
            raw: RawTimestamp {
                value: ts.raw.max(0) as u64,
                format: RAW_FORMAT.to_string(),
                source,
            },
            // Hikvision writes unix seconds, not recorder wall-clock digits, so there is no
            // separate native rendering to report. Repeating the UTC reading here would imply
            // the recorder stored a local time it did not.
            recorder_native: None,
            normalized: ts.iso_8601_utc.as_ref().map(|iso| NormalizedTime {
                iso_8601: iso.clone(),
                method: NORMALIZATION_METHOD.to_string(),
            }),
            reference: None,
            // Load-bearing: no offset was established, so none is claimed.
            timezone: TimeZoneState::Unknown,
            correction: None,
        }
    }

    /// Time evidence for a structure that carries no decodable timestamp.
    fn absent_time_evidence(
        &self,
        profile: &OemProfile,
        structure_offset: u64,
        why: &str,
    ) -> TimeEvidence {
        let source = self.timestamp_provenance(profile, structure_offset, why);
        TimeEvidence {
            raw: RawTimestamp {
                value: 0,
                format: format!("{RAW_FORMAT}_ABSENT"),
                source,
            },
            recorder_native: None,
            normalized: None,
            reference: None,
            timezone: TimeZoneState::Unknown,
            correction: None,
        }
    }

    /// Convert one validated clip into a `Recording`, preserving every anomaly found.
    fn clip_to_recording(
        &self,
        profile: &OemProfile,
        volume: &HikvisionVolume,
        source_image: &str,
        block: &ClassifiedBlock,
        clip: &ClipRecord,
    ) -> Recording {
        let time = if clip.start_time.is_decoded() {
            self.time_evidence(profile, &clip.start_time)
        } else {
            self.absent_time_evidence(
                profile,
                clip.start_time.field_offset,
                "neither the clip slot's start-time field nor its fallback field established an \
                 instant",
            )
        };

        // A clip whose channel could not be normalized still has bytes worth reporting. The
        // channel is recorded as an anomaly rather than silently becoming 0, which would
        // attribute the recording to a camera.
        let channel = clip.channel.normalized.unwrap_or(0);

        let mut rec = Recording::new(
            channel,
            time,
            source_image.to_string(),
            vec![clip.clip_region],
            self.id.clone(),
            self.version.clone(),
            ProfileId(profile.profile_id.clone()),
            self.profile_hash(profile),
        );

        if clip.channel.normalized.is_none() {
            rec.add_anomaly(IntegrityFlag::Custom(format!(
                "no channel number could be derived: {}",
                clip.channel.note
            )));
        }
        if !block.classification.is_accessible() {
            rec.add_anomaly(IntegrityFlag::Custom(format!(
                "recovered from block {} classified {}: {}",
                block.block_number(),
                block.classification.label(),
                volume::UNREFERENCED_REASON
            )));
        }
        if clip.start_from_fallback {
            rec.add_anomaly(IntegrityFlag::Custom(
                "the start time was taken from the clip slot's fallback time field because the \
                 dedicated start field established no instant"
                    .to_string(),
            ));
        }
        if !clip.start_time.is_decoded() {
            rec.add_anomaly(IntegrityFlag::Custom(
                "no start time was established for this clip; the interval is open at the start"
                    .to_string(),
            ));
        }
        if let (Some(s), Some(e)) = (clip.start_time.unix_seconds, clip.end_time.unix_seconds) {
            if e < s {
                rec.add_anomaly(IntegrityFlag::TimestampBoundsAnomaly);
            }
        }
        if clip.start_time.confidence == crate::timestamp::TimeConfidence::Low
            || clip.end_time.confidence == crate::timestamp::TimeConfidence::Low
        {
            rec.add_anomaly(IntegrityFlag::Custom(
                "a clip timestamp decoded outside the profile's plausibility window; the recorder's \
                 clock may not have been set correctly"
                    .to_string(),
            ));
        }

        // Corroborating B-tree entry, or the honest absence of one.
        let entries = volume.entries_for_block(block.block_number());
        match entries.iter().find(|e| {
            e.data_offset_physical()
                .is_some_and(|o| clip.clip_region.contains(o))
        }) {
            Some(entry) => {
                if entry.is_incomplete() {
                    rec.add_anomaly(IntegrityFlag::Custom(format!(
                        "the referencing B-tree entry {} carries the incomplete-recording \
                         sentinel; the recorder had not finished writing this recording",
                        entry.entry_id()
                    )));
                }
                if let (Some(ec), Some(cc)) = (entry.channel.normalized, clip.channel.normalized) {
                    if ec != cc {
                        rec.add_anomaly(IntegrityFlag::Custom(format!(
                            "the referencing B-tree entry {} declares channel {ec} but the block \
                             footer clip slot declares channel {cc}; both are reported as stored",
                            entry.entry_id()
                        )));
                    }
                }
            }
            None => {
                rec.add_anomaly(IntegrityFlag::Custom(format!(
                    "no authoritative B-tree entry points into this clip's range; it was located \
                     from block {}'s own footer index",
                    block.block_number()
                )));
            }
        }

        rec
    }
}

impl Parser for HikvisionParser {
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
        let state = match &vol.boot.recognition {
            // A recognised volume's filesystem verdict is the volume's own evidence, which
            // already folds in the boot fields, both trees and the block classification.
            BootRecognition::Recognized { .. } => vol.evidence.clone(),
            BootRecognition::Malformed { .. } => vol.boot.recognition.validation(),
            // Not Hikvision, or not readable: the parser does not apply, which is different
            // from the evidence being damaged.
            BootRecognition::IdentifierMismatch { .. } | BootRecognition::NotFound { .. } => {
                vol.boot.recognition.validation()
            }
        };
        Ok(vec![self.run(profile, "parse_filesystem", state)])
    }

    fn parse_metadata(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Vec<ParserRun>, ForensicError> {
        // Delegate to the same index reader the recovery engine consumes, so this stage
        // reports exactly the facts recovery will act on — including how authoritative the
        // HIKBTREE statement is.
        let state = match self.recording_index(reader, profile)? {
            Some(index) => index.evidence.clone(),
            // `vs(Unknown, ..)` rather than `ValidationState::not_run`, which files its second
            // argument as the subject and would drop this explanation from the reason.
            None => vs(
                ValidationStateKind::Unknown,
                "no Hikvision volume structures; no recording metadata to read",
                "parse_metadata",
                "hikvision_volume",
            ),
        };
        Ok(vec![self.run(profile, "parse_metadata", state)])
    }

    fn parse_recordings(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<(Vec<Recording>, Vec<ParserRun>), ForensicError> {
        let vol = volume::read_volume(reader, profile)?;
        let source_image = reader.source_path().to_string();
        let mut recordings: Vec<Recording> = Vec::new();

        for (block, clip) in vol.clips() {
            recordings.push(self.clip_to_recording(profile, &vol, &source_image, block, clip));
        }

        let state =
            if !recordings.is_empty() {
                let accessible = vol.accessible_clips().count();
                let available = vol.unreferenced_clips().count();
                vs(
                    ValidationStateKind::Pass,
                    format!(
                        "{} recording(s) reconstructed from the Hikvision structure set across {} \
                     block(s) ({accessible} accessible, {available} available). {}",
                        recordings.len(),
                        vol.blocks.len(),
                        vol.evidence.reason
                    ),
                    "parse_recordings",
                    "hikvision_recordings",
                )
            } else if vol.is_usable() {
                // A recognised volume that yielded nothing is a real, reportable finding: the
                // structures were read and they describe no clip.
                vs(
                    ValidationStateKind::Review,
                    format!(
                    "the Hikvision structure set was read but no block footer described a valid \
                     clip, so no recording could be reconstructed from metadata. {} block(s) are \
                     candidates for structural carving. {}",
                    vol.blocks.iter().filter(|b| b.is_carving_candidate()).count(),
                    vol.evidence.reason
                ),
                    "parse_recordings",
                    "hikvision_recordings",
                )
            } else {
                vs(
                    ValidationStateKind::Unknown,
                    format!(
                        "no Hikvision volume structures were established ({})",
                        vol.boot.recognition.label()
                    ),
                    "parse_recordings",
                    "hikvision_recordings",
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
        let mut events: Vec<TimelineEvent> = Vec::new();

        // Only clips whose slot carried a decodable clock become events. `TimelineEvent` has
        // no representation for "time unknown", so placing a clip with no timestamp on the
        // timeline would put a fabricated instant in front of an examiner.
        let mut withheld = 0usize;
        for (block, clip) in vol.clips() {
            let Some(_) = clip.start_time.unix_seconds else {
                withheld += 1;
                continue;
            };
            let time = self.time_evidence(profile, &clip.start_time);
            // `TimelineEvent` requires a channel number. When none was derived, 0 — the
            // platform's "unknown channel" value — is used and the description says so, so the
            // event is never read as camera 0's.
            let channel_note = if clip.channel.normalized.is_none() {
                format!(
                    "; no channel number could be derived ({}), so channel 0 here means unknown",
                    clip.channel.note
                )
            } else {
                String::new()
            };
            events.push(TimelineEvent::new(
                clip.channel.normalized.unwrap_or(0),
                time,
                format!(
                    "Hikvision clip {} on channel {} ({}, block {}, {} byte(s)) from {} to \
                     {}{channel_note}",
                    clip.clip_id(),
                    clip.channel.label(),
                    if block.classification.is_accessible() {
                        "accessible"
                    } else {
                        "available"
                    },
                    block.block_number(),
                    clip.clip_region.length,
                    clip.start_time.iso_8601_utc.as_deref().unwrap_or("unknown"),
                    clip.end_time.iso_8601_utc.as_deref().unwrap_or("unknown"),
                ),
                vec![clip.clip_region],
                self.id.clone(),
                self.version.clone(),
                ProfileId(profile.profile_id.clone()),
                self.profile_hash(profile),
            ));
        }

        let state = if !events.is_empty() {
            let mut reason = format!("{} Hikvision clip event(s) extracted", events.len());
            if withheld > 0 {
                reason.push_str(&format!(
                    "; {withheld} clip(s) withheld because their footer slots carry no decodable \
                     start time, and no instant may be invented for them"
                ));
            }
            vs(
                if withheld > 0 {
                    ValidationStateKind::Review
                } else {
                    ValidationStateKind::Pass
                },
                reason,
                "extract_timeline_events",
                "hikvision_clip_events",
            )
        } else if withheld > 0 {
            vs(
                ValidationStateKind::Review,
                format!(
                    "{withheld} clip(s) were located but none carried a decodable start time, so no \
                     timeline event could be placed without inventing one"
                ),
                "extract_timeline_events",
                "hikvision_clip_events",
            )
        } else {
            vs(
                ValidationStateKind::Unknown,
                format!(
                    "no Hikvision clips were established ({})",
                    vol.boot.recognition.label()
                ),
                "extract_timeline_events",
                "hikvision_timeline",
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

        // Findings are separated by kind, because "the tree has a cycle", "a block footer is
        // damaged" and "a block is simply unreferenced" license different conclusions and must
        // not be collapsed into one count.
        let mut findings: Vec<String> = vec![
            vol.boot.evidence.reason.clone(),
            vol.primary_tree.evidence.reason.clone(),
            vol.backup_tree.evidence.reason.clone(),
            vol.authority.reason.clone(),
        ];

        let malformed_entries: usize = vol.primary_tree.malformed_entries().count()
            + vol.backup_tree.malformed_entries().count();
        let traversal_problems: Vec<String> = vol
            .primary_tree
            .traversal
            .problems()
            .into_iter()
            .chain(vol.backup_tree.traversal.problems())
            .collect();
        let damaged_footers = vol.malformed_blocks().count();
        let unreferenced = vol.unreferenced_blocks().count();
        let rejected_slots: usize = vol
            .blocks
            .iter()
            .map(|b| b.index.rejected_slots.len())
            .sum();

        if malformed_entries > 0 {
            findings.push(format!(
                "{malformed_entries} B-tree entry/entries carry a state sentinel that is neither \
                 blank nor populated; those slots are damaged or partially overwritten"
            ));
        }
        if !traversal_problems.is_empty() {
            findings.push(format!(
                "page traversal rejected {} pointer(s)/page(s): {}",
                traversal_problems.len(),
                traversal_problems.join("; ")
            ));
        }
        if damaged_footers > 0 {
            findings.push(format!(
                "{damaged_footers} block(s) have a footer index that could not be interpreted; \
                 their video data is a structural carving target rather than a metadata-backed \
                 finding"
            ));
        }
        if rejected_slots > 0 {
            findings.push(format!(
                "{rejected_slots} clip slot(s) failed validation and were not accepted; none was \
                 adjusted to fit"
            ));
        }
        if unreferenced > 0 {
            findings.push(format!(
                "{unreferenced} block(s) are unreferenced by the authoritative index. \
                 {}",
                volume::UNREFERENCED_REASON
            ));
        }

        let structural_damage = malformed_entries > 0
            || !traversal_problems.is_empty()
            || damaged_footers > 0
            || rejected_slots > 0;

        let state = if !vol.is_hikvision() {
            vs(
                ValidationStateKind::Unknown,
                format!(
                    "the Hikvision structure set does not apply to this evidence: {}",
                    vol.boot.recognition.validation().reason
                ),
                "validate_structure",
                "hikvision_structures",
            )
        } else if structural_damage || unreferenced > 0 {
            // Two reasons for Review, kept in one arm because the reported findings are the
            // same: structural damage needs a human, and unreferenced blocks — though a normal
            // condition on a running recorder — are the basis of an orphan finding and warrant
            // a look. Which of the two applies is spelled out in `findings`.
            vs(
                ValidationStateKind::Review,
                findings.join(". "),
                "validate_structure",
                "hikvision_structures",
            )
        } else {
            vs(
                ValidationStateKind::Pass,
                findings.join(". "),
                "validate_structure",
                "hikvision_structures",
            )
        };

        Ok(vec![self.run(profile, "validate_structure", state)])
    }

    /// Whether the window's bytes carry structurally sound Hikvision container framing.
    ///
    /// Evidence-based: it requires a walkable MPEG-PS container — a pack header followed by
    /// parts whose declared lengths and payload offsets validate, with a video PES among them.
    /// It is not a signature match, and it never returns an unconditional `true`. Returning
    /// true for every window would make the signal useless and silently suppress
    /// orphan/unindexed discovery, which is exactly the defect this replaces.
    fn recognize_candidate(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<bool, ForensicError> {
        let probe = u64_from(profile, key::RECOGNITION_PROBE_BYTES, 65_536);
        carve::window_carries_hikvision_framing(reader, profile, probe)
    }

    fn storage_geometry(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Option<StorageGeometry>, ForensicError> {
        let vol = volume::read_volume(reader, profile)?;
        volume::storage_geometry(&vol, profile)
    }

    fn recording_index(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Option<RecordingIndex>, ForensicError> {
        let vol = volume::read_volume(reader, profile)?;
        volume::recording_index(&vol, profile)
    }

    /// Carve a physical range and report every Hikvision container candidate in it.
    ///
    /// This is the raw-carving half of recovery: the engine hands over a range it has
    /// established nothing about, and this walks Hikvision's own framing. It reports many
    /// records per range, at absolute offsets, and never substitutes a length to make a
    /// candidate fit a window.
    fn scan_region_for_candidates(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
        region: Region,
    ) -> Result<Vec<ContainerRecord>, ForensicError> {
        let carved = carve::carve_region(reader, profile, region)?;
        Ok(carved
            .candidates
            .iter()
            .map(|c| c.to_container_record())
            .collect())
    }

    fn reconstruction_provider(&self) -> Option<&dyn parsers_core::ReconstructionProvider> {
        Some(self)
    }
}

impl parsers_core::ReconstructionProvider for HikvisionParser {
    fn reconstruct_recording(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
        recording_id: &str,
    ) -> Result<Option<parsers_core::ReconstructedStream>, ForensicError> {
        let volume = volume::read_volume(reader, profile)?;
        let Some(reconstruction) = reconstruct_recording(reader, profile, &volume, recording_id)? else {
            return Ok(None);
        };
        if reconstruction.payload_regions.is_empty() {
            return Err(ForensicError::corrupt(
                "hikvision_reconstruct",
                format!(
                    "Hikvision recording '{recording_id}' was located but no MPEG-PS video payload could be established in its clip(s): {}",
                    reconstruction.evidence.reason
                ),
            ));
        }
        let description = format!(
            "{}; {}; {}",
            reconstruction.description(),
            reconstruction.normalization.summary(),
            reconstruction.evidence.reason
        );
        Ok(Some(parsers_core::ReconstructedStream {
            payload_regions: reconstruction.export_regions().to_vec(),
            channel: reconstruction.channel.unwrap_or(0),
            description,
        }))
    }
}

/// Reconstruct one Hikvision recording into ordered clips and payload ranges.
///
/// Exposed as a free function rather than on the `Parser` trait because it is
/// Hikvision-specific depth the generic interface does not need. The export layer calls it to
/// turn an engine-discovered clip into an exportable stream while keeping the clip id and
/// every physical offset intact.
///
/// `recording_id` is the [`ClipRecord::clip_id`] the engine reported. Returns `Ok(None)` when
/// the volume no longer yields that clip — a real answer, not an error.
pub fn reconstruct_recording(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    volume: &HikvisionVolume,
    recording_id: &str,
) -> Result<Option<RecordingReconstruction>, ForensicError> {
    crate::reconstruct::reconstruct_recording(reader, profile, volume, recording_id)
}

/// Locate the clip behind a recording id assigned by [`crate::volume::recording_index`].
///
/// Returns the clip and the block it lives in. `None` when the volume no longer yields it.
pub fn find_recording<'a>(
    volume: &'a HikvisionVolume,
    recording_id: &str,
) -> Option<(&'a ClassifiedBlock, &'a ClipRecord)> {
    volume.find_clip(recording_id)
}

/// OEM-specific descriptive fields for a report, as plain strings.
pub fn volume_summary(volume: &HikvisionVolume) -> BTreeMap<String, String> {
    volume::volume_summary(volume)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::tests_support::hikvision_profile;
    use crate::testing::MemReader;

    #[test]
    fn the_profile_hash_is_deterministic_and_not_an_all_zero_placeholder() {
        let mut p = hikvision_profile();
        p.profile_hash = None;
        let parser = HikvisionParser::default();
        let a = parser.profile_hash(&p);
        let b = parser.profile_hash(&p);
        assert_eq!(a, b, "the fallback hash must be deterministic");
        assert_ne!(
            a,
            Hash::sha256(vec![0; 32]),
            "an all-zero digest would look like a real hash in a report"
        );
    }

    #[test]
    fn time_evidence_never_claims_a_timezone_it_did_not_establish() {
        let p = hikvision_profile();
        let parser = HikvisionParser::default();
        let ts = HikTimestamp::decode(
            1_774_224_000,
            crate::timestamp::TimestampStructure::ClipStart,
            0x1000,
            &p,
        );
        let te = parser.time_evidence(&p, &ts);

        assert_eq!(te.timezone, TimeZoneState::Unknown);
        assert_eq!(te.raw.value, 1_774_224_000);
        assert_eq!(te.raw.format, RAW_FORMAT);
        let normalized = te.normalized.as_ref().unwrap();
        assert!(
            normalized.method.contains("no timezone offset"),
            "the normalization method must state that no offset was applied: {}",
            normalized.method
        );
        assert!(
            !normalized.iso_8601.contains("+05:30"),
            "no regional offset may be applied during parsing"
        );
        assert!(
            te.recorder_native.is_none(),
            "Hikvision stores unix seconds, not wall-clock digits; repeating the UTC reading as a \
             recorder-native time would claim a local time the recorder never stored"
        );
    }

    #[test]
    fn an_absent_timestamp_produces_no_native_or_normalized_time() {
        let p = hikvision_profile();
        let parser = HikvisionParser::default();
        let te = parser.absent_time_evidence(&p, 0x2000, "no timestamp in this structure");
        assert!(te.recorder_native.is_none());
        assert!(te.normalized.is_none());
        assert_eq!(te.timezone, TimeZoneState::Unknown);
        assert_eq!(te.raw.value, 0);
        assert!(te.raw.format.ends_with("_ABSENT"));
    }

    /// The defect this rewrite exists to remove: recognition must rest on bytes.
    #[test]
    fn recognize_candidate_is_false_for_non_hikvision_bytes() {
        let p = hikvision_profile();
        let parser = HikvisionParser::default();

        for (label, data) in [
            ("all zeros", vec![0u8; 1 << 16]),
            ("all 0xFF", vec![0xFFu8; 1 << 16]),
            (
                "pseudo-random",
                (0..(1u32 << 16))
                    .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
                    .collect(),
            ),
            ("empty", Vec::new()),
        ] {
            let r = MemReader::new(data);
            assert!(
                !parser.recognize_candidate(&r, &p).unwrap(),
                "{label} must not be recognised as Hikvision framing"
            );
        }
    }

    #[test]
    fn recognize_candidate_is_true_only_for_a_walkable_container() {
        let p = hikvision_profile();
        let parser = HikvisionParser::default();
        let mut data = crate::testing::build::clip(1, &crate::testing::build::h264_es(), 3);
        data.resize(1 << 16, 0);
        let r = MemReader::new(data);
        assert!(parser.recognize_candidate(&r, &p).unwrap());
    }

    #[test]
    fn a_non_hikvision_volume_runs_every_stage_without_asserting_anything() {
        let p = hikvision_profile();
        let parser = HikvisionParser::default();
        let r = MemReader::new(vec![0u8; 1 << 16]);

        let fs = parser.parse_filesystem(&r, &p).unwrap();
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].validation_state.state, ValidationStateKind::Unknown);

        let md = parser.parse_metadata(&r, &p).unwrap();
        assert_eq!(md.len(), 1);

        let (recordings, runs) = parser.parse_recordings(&r, &p).unwrap();
        assert!(recordings.is_empty());
        assert_eq!(runs[0].validation_state.state, ValidationStateKind::Unknown);

        let (events, runs) = parser.extract_timeline_events(&r, &p).unwrap();
        assert!(events.is_empty());
        assert_eq!(runs[0].validation_state.state, ValidationStateKind::Unknown);

        let vs_runs = parser.validate_structure(&r, &p).unwrap();
        assert_eq!(
            vs_runs[0].validation_state.state,
            ValidationStateKind::Unknown
        );

        // Geometry and index must be absent, not invented, for non-Hikvision evidence.
        assert!(parser.storage_geometry(&r, &p).unwrap().is_none());
        assert!(parser.recording_index(&r, &p).unwrap().is_none());
    }

    #[test]
    fn every_stage_reports_provenance_on_its_run() {
        let p = hikvision_profile();
        let parser = HikvisionParser::default();
        let r = MemReader::new(vec![0u8; 1 << 16]);
        for run in parser
            .parse_filesystem(&r, &p)
            .unwrap()
            .into_iter()
            .chain(parser.parse_metadata(&r, &p).unwrap())
            .chain(parser.validate_structure(&r, &p).unwrap())
        {
            assert_eq!(run.parser_id, "hikvision-hikbtree-parser");
            assert_eq!(run.parser_version, "2.0.0");
            assert_eq!(run.profile_id.0, p.profile_id);
            assert!(!run.validation_state.reason.is_empty());
        }
    }

    #[test]
    fn scanning_a_region_with_no_framing_returns_no_fabricated_records() {
        let p = hikvision_profile();
        let parser = HikvisionParser::default();
        let r = MemReader::new(vec![0xAAu8; 1 << 16]);
        let records = parser
            .scan_region_for_candidates(&r, &p, Region::new(0, 1 << 16).unwrap())
            .unwrap();
        assert!(
            records.is_empty(),
            "bytes with no framing must produce no record"
        );
    }

    #[test]
    fn scanning_reports_many_records_per_region_at_absolute_offsets() {
        let p = hikvision_profile();
        let parser = HikvisionParser::default();
        let es = crate::testing::build::h264_es();
        let mut data = Vec::new();
        let mut starts = Vec::new();
        for i in 0..4u32 {
            data.extend_from_slice(&[0u8; 512]);
            starts.push(data.len() as u64);
            data.extend_from_slice(&crate::testing::build::clip(i, &es, 2));
        }
        let len = data.len() as u64;
        let r = MemReader::new(data);
        let records = parser
            .scan_region_for_candidates(&r, &p, Region::new(0, len).unwrap())
            .unwrap();
        assert_eq!(records.len(), 4, "a scan region is not one candidate");
        for (rec, expected) in records.iter().zip(starts) {
            assert_eq!(
                rec.physical_region.offset, expected,
                "absolute offsets only"
            );
            // Carving cannot know the channel or the time; it must not invent them.
            assert_eq!(rec.channel, None);
            assert_eq!(rec.start_time_unix, None);
        }
    }
}
