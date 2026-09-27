//! # DahuaParser
//!
//! The `Parser` implementation for the Dahua DHFS storage family. Every stage reads the
//! volume through [`crate::volume`], which walks the real DHFS 4.1 structure set:
//!
//! ```text
//!   signature → partition table → partition info → block table → chains → DHII → DHAV
//! ```
//!
//! ## Timestamps carry no assumed timezone
//!
//! An earlier revision added a fixed `UTC+05:30` during parsing, which silently attributed an
//! offset the evidence never stated. Time evidence produced here reports:
//!
//! * `raw` — the packed field exactly as stored, tagged with its encoding;
//! * `recorder_native` — the recorder's own wall-clock digits, with no zone suffix;
//! * `normalized` — those digits read as UTC, with the method naming that choice explicitly;
//! * `timezone` — [`TimeZoneState::Unknown`], because no offset was established.
//!
//! Presenting the recorder's clock in a jurisdiction's timezone is an evidence-layer decision
//! that needs a separately established offset. It does not belong in a parser.

use std::collections::BTreeMap;

use evidence_reader::EvidenceReader;
use forensic_core::identifiers::ProfileId;
use forensic_core::{
    ForensicError, Hash, IntegrityFlag, NormalizedTime, OemProfile, ParserRun, Provenance,
    RawTimestamp, RecorderNativeTime, Recording, Region, SourceRegion, TimeEvidence, TimeZoneState,
    TimelineEvent, ValidationState, ValidationStateKind,
};
use parsers_core::storage::{ContainerRecord, RecordingIndex, StorageGeometry};
use parsers_core::Parser;

use crate::chain::{ChainOrigin, RecordingChain};
use crate::layout::{key, u64_from, vs};
use crate::timestamp::DahuaTimestamp;
use crate::volume::{self, ChainAccessibility, ClassifiedChain, DahuaVolume, VolumeModel};

/// Encoding label recorded on every packed Dahua timestamp, so the raw value is
/// re-derivable without reading this crate.
const PACKED_FORMAT: &str = "DAHUA_PACKED_BASE2000_LE";

/// How the normalized time was produced. Named so the absence of a timezone is explicit in
/// the output rather than implied.
const NORMALIZATION_METHOD: &str =
    "dahua_packed_base2000_digits_read_as_utc; no recorder timezone offset was established from \
     evidence, so none was applied";

pub struct DahuaParser {
    pub id: String,
    pub version: String,
}

impl Default for DahuaParser {
    fn default() -> Self {
        Self {
            id: "dahua-dhfs-parser".to_string(),
            version: "2.0.0".to_string(),
        }
    }
}

impl DahuaParser {
    fn profile_hash(&self, profile: &OemProfile) -> Hash {
        // A profile with no computed hash is a loader problem, not evidence. Hash the profile
        // id so the value is deterministic and traceable instead of an all-zero placeholder
        // that would look like a real digest in a report.
        profile.profile_hash.clone().unwrap_or_else(|| {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"dahua-profile-id:");
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
    /// `evidence_id` is not available to a parser, so the raw timestamp's provenance points at
    /// the structure it came from through its source region and its validation reason. It does
    /// not mint a random evidence id pretending to identify an evidence item.
    fn timestamp_provenance(
        &self,
        profile: &OemProfile,
        structure_offset: u64,
        detail: &str,
    ) -> Provenance {
        let hash = self.profile_hash(profile);
        let region = Region::new(structure_offset, 4).unwrap_or(Region::point(structure_offset));
        Provenance::new(
            // The parser does not own an evidence id; the nil id records that honestly rather
            // than fabricating a fresh one that would look like a different evidence item.
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
                "dahua_timestamp_provenance",
                "packed_timestamp",
            ),
        )
    }

    /// Build `TimeEvidence` from a decoded Dahua timestamp, applying no timezone.
    fn time_evidence(
        &self,
        profile: &OemProfile,
        ts: &DahuaTimestamp,
        structure_offset: u64,
    ) -> TimeEvidence {
        let source = self.timestamp_provenance(profile, structure_offset, &ts.evidence);
        TimeEvidence {
            raw: RawTimestamp {
                value: ts.raw as u64,
                format: PACKED_FORMAT.to_string(),
                source,
            },
            // The recorder's own digits, with no zone suffix because none is known.
            recorder_native: ts
                .recorder_wall_clock
                .as_ref()
                .map(|iso| RecorderNativeTime {
                    iso_8601: iso.clone(),
                }),
            normalized: ts.unix_seconds.and_then(|secs| {
                chrono::DateTime::from_timestamp(secs, 0).map(|d| NormalizedTime {
                    iso_8601: d.to_rfc3339(),
                    method: NORMALIZATION_METHOD.to_string(),
                })
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
                format: format!("{PACKED_FORMAT}_ABSENT"),
                source,
            },
            recorder_native: None,
            normalized: None,
            reference: None,
            timezone: TimeZoneState::Unknown,
            correction: None,
        }
    }

    /// Turn one classified chain into a `Recording`.
    fn chain_to_recording(
        &self,
        profile: &OemProfile,
        source_image: &str,
        classified: &ClassifiedChain,
    ) -> Recording {
        let chain = &classified.chain;
        let anchor = chain.blocks.first().map(|b| b.entry_offset).unwrap_or(0);
        let time = match &chain.start_time {
            Some(ts) => self.time_evidence(profile, ts, anchor.saturating_add(4)),
            None => self.absent_time_evidence(
                profile,
                anchor.saturating_add(4),
                "the chain's block-table entries carry no decodable start timestamp",
            ),
        };

        let mut recording = Recording::new(
            chain.channel.normalized,
            time,
            source_image.to_string(),
            chain.regions(),
            self.id.clone(),
            self.version.clone(),
            ProfileId(profile.profile_id.clone()),
            self.profile_hash(profile),
        );

        // Integrity flags come from the chain's own validation, so an examiner sees the same
        // anomalies the structure reader recorded.
        if !chain.validity.is_complete() {
            recording.add_anomaly(IntegrityFlag::InvalidPointer);
        }
        if chain.origin == ChainOrigin::UnreachableBlockGroup {
            recording.add_anomaly(IntegrityFlag::Custom(
                "reconstructed from block-table metadata that no first-block traversal reached; \
                 available, not deleted"
                    .to_string(),
            ));
        }
        if let ChainAccessibility::Available { reason } = &classified.accessibility {
            recording.add_anomaly(IntegrityFlag::Custom(format!("available: {reason}")));
        }
        if !chain.channel_disagreements.is_empty() {
            recording.add_anomaly(IntegrityFlag::Custom(format!(
                "channel disagreement inside the chain: {}",
                chain.channel_disagreements.join("; ")
            )));
        }
        if let (Some(s), Some(e)) = (
            chain.start_time.as_ref().and_then(|t| t.unix_seconds),
            chain.end_time.as_ref().and_then(|t| t.unix_seconds),
        ) {
            if e < s {
                recording.add_anomaly(IntegrityFlag::TimestampBoundsAnomaly);
            }
        }
        recording
    }
}

impl Parser for DahuaParser {
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
        // Version-aware: a recognised DHFS 4.1 passes, an unsupported variant or a malformed
        // header is surfaced for review, and a non-Dahua volume is Unknown rather than a
        // failure of this parser.
        let vol = volume::read_volume(reader, profile)?;
        let state = match &vol.model {
            VolumeModel::Dhfs41 => vs(
                if vol.block_maps.is_empty() {
                    ValidationStateKind::Review
                } else {
                    ValidationStateKind::Pass
                },
                format!(
                    "{} {}",
                    vol.recognition.validation().reason,
                    vol.evidence.reason
                ),
                "parse_filesystem",
                "dhfs41_volume",
            ),
            VolumeModel::FlatDidxFallback { reason } => vs(
                ValidationStateKind::Review,
                reason.clone(),
                "parse_filesystem",
                "flat_didx_fallback",
            ),
            VolumeModel::NotApplicable { .. } => vol.recognition.validation(),
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
        // block metadata is.
        let state = match self.recording_index(reader, profile)? {
            Some(index) => index.evidence.clone(),
            None => ValidationState::not_run(
                "parse_metadata",
                "no Dahua volume structures; no recording metadata to read",
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

        match &vol.model {
            VolumeModel::Dhfs41 => {
                for classified in &vol.chains {
                    recordings.push(self.chain_to_recording(profile, &source_image, classified));
                }
            }
            VolumeModel::FlatDidxFallback { .. } | VolumeModel::NotApplicable { .. } => {
                // The flat model's recordings come from its own index entries. Their timestamps
                // are unix seconds, not the packed encoding, so they are reported as such.
                if let Some(index) = crate::dhfs::read_recording_index(reader, profile)? {
                    for entry in &index.recordings {
                        let anchor = entry
                            .physical_regions
                            .first()
                            .map(|r| r.offset)
                            .unwrap_or(0);
                        let time = match entry.start_time_unix {
                            Some(secs) if secs > 0 => {
                                let source = self.timestamp_provenance(
                                    profile,
                                    anchor,
                                    "unix-seconds timestamp from a flat-model DIDX entry",
                                );
                                TimeEvidence {
                                    raw: RawTimestamp {
                                        value: secs as u64,
                                        format: "UNIX_SECONDS_LE".to_string(),
                                        source,
                                    },
                                    recorder_native: None,
                                    normalized: chrono::DateTime::from_timestamp(secs, 0).map(
                                        |d| NormalizedTime {
                                            iso_8601: d.to_rfc3339(),
                                            method:
                                                "unix_seconds_read_as_utc; no recorder timezone \
                                                     offset was established"
                                                    .to_string(),
                                        },
                                    ),
                                    reference: None,
                                    timezone: TimeZoneState::Unknown,
                                    correction: None,
                                }
                            }
                            _ => self.absent_time_evidence(
                                profile,
                                anchor,
                                "the flat-model index entry carries no timestamp",
                            ),
                        };
                        let mut rec = Recording::new(
                            entry.channel.unwrap_or(1),
                            time,
                            source_image.clone(),
                            entry.physical_regions.clone(),
                            self.id.clone(),
                            self.version.clone(),
                            ProfileId(profile.profile_id.clone()),
                            self.profile_hash(profile),
                        );
                        rec.add_anomaly(IntegrityFlag::Custom(
                            "located through the provisional flat superblock + DIDX model, not the \
                             DHFS 4.1 structure set"
                                .to_string(),
                        ));
                        recordings.push(rec);
                    }
                }
            }
        }

        let state = if !recordings.is_empty() {
            let accessible = vol.accessible_chains().count();
            let available = vol.available_chains().count();
            vs(
                ValidationStateKind::Pass,
                format!(
                    "{} recording(s) reconstructed from {} structures ({accessible} accessible, \
                     {available} available)",
                    recordings.len(),
                    vol.model.label()
                ),
                "parse_recordings",
                "dahua_recordings",
            )
        } else {
            ValidationState::not_run(
                "parse_recordings",
                format!(
                    "no Dahua recording structures were established ({})",
                    vol.model.label()
                ),
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

        // Only chains whose block-table entries carried a decodable clock become events.
        // `TimelineEvent` has no representation for "time unknown", so placing a chain with no
        // timestamp on the timeline would put a fabricated instant in front of an examiner.
        let mut withheld = 0usize;
        for classified in &vol.chains {
            let chain = &classified.chain;
            let Some(ts) = chain.start_time.as_ref() else {
                withheld += 1;
                continue;
            };
            let anchor = chain.blocks.first().map(|b| b.entry_offset).unwrap_or(0);
            let time = self.time_evidence(profile, ts, anchor.saturating_add(4));
            let accessibility = match &classified.accessibility {
                ChainAccessibility::Accessible => "accessible",
                ChainAccessibility::Available { .. } => "available",
            };
            events.push(TimelineEvent::new(
                chain.channel.normalized,
                time,
                format!(
                    "Dahua DHFS 4.1 partition {} chain {} on channel {} ({}, {} block(s), {} byte(s), \
                     traversal {}) starting at recorder clock {}",
                    chain.partition,
                    chain.chain_id,
                    chain.channel.normalized,
                    accessibility,
                    chain.blocks.len(),
                    chain.total_bytes(),
                    chain.validity.label(),
                    ts.recorder_wall_clock.as_deref().unwrap_or("unknown"),
                ),
                chain.regions(),
                self.id.clone(),
                self.version.clone(),
                ProfileId(profile.profile_id.clone()),
                self.profile_hash(profile),
            ));
        }

        let state = if !events.is_empty() {
            let mut reason = format!("{} Dahua recording chain event(s) extracted", events.len());
            if withheld > 0 {
                reason.push_str(&format!(
                    "; {withheld} chain(s) withheld because their block-table entries carry no \
                     decodable timestamp, and no instant may be invented for them"
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
                "dahua_chain_events",
            )
        } else if withheld > 0 {
            vs(
                ValidationStateKind::Review,
                format!(
                    "{withheld} chain(s) were reconstructed but none carried a decodable timestamp, \
                     so no timeline event could be placed without inventing one"
                ),
                "extract_timeline_events",
                "dahua_chain_events",
            )
        } else {
            ValidationState::not_run(
                "extract_timeline_events",
                format!(
                    "no Dahua recording chains were established ({})",
                    vol.model.label()
                ),
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
        let mut findings: Vec<String> = Vec::new();

        findings.push(vol.recognition.validation().reason.clone());
        if let Some(tables) = &vol.partition_tables {
            findings.push(tables.evidence.reason.clone());
        }
        for map in &vol.block_maps {
            findings.push(map.evidence.reason.clone());
        }
        let malformed: usize = vol.block_maps.iter().map(|m| m.malformed_count).sum();
        // Two different anomalies, kept apart because they mean different things. A chain whose
        // traversal broke is damaged link structure. A chain recovered from unreachable blocks is
        // intact metadata the recorder no longer reaches — the available case, which is normal on
        // a disk that has been recording for a while and is not damage.
        let broken_chains = vol
            .chains
            .iter()
            .filter(|c| {
                !c.chain.validity.is_complete()
                    && c.chain.origin != ChainOrigin::UnreachableBlockGroup
            })
            .count();
        let recovered_chains = vol
            .chains
            .iter()
            .filter(|c| c.chain.origin == ChainOrigin::UnreachableBlockGroup)
            .count();

        let state = match &vol.model {
            VolumeModel::Dhfs41 if !vol.block_maps.is_empty() => {
                let reason = format!(
                    "DHFS 4.1 structures consistent: {} partition(s), {} block table(s), {} chain(s); \
                     {malformed} malformed block entr{}, {broken_chains} chain(s) with damaged links, \
                     {recovered_chains} chain(s) recovered from blocks no first-block traversal \
                     reached (available, not damage and not deletion). {}",
                    vol.partition_tables
                        .as_ref()
                        .map(|t| t.partitions().len())
                        .unwrap_or(0),
                    vol.block_maps.len(),
                    vol.chains.len(),
                    if malformed == 1 { "y" } else { "ies" },
                    findings.join(" | ")
                );
                vs(
                    if malformed == 0 && broken_chains == 0 {
                        ValidationStateKind::Pass
                    } else {
                        ValidationStateKind::Review
                    },
                    reason,
                    "validate_structure",
                    "dhfs41_structures",
                )
            }
            VolumeModel::Dhfs41 => vs(
                ValidationStateKind::Review,
                format!(
                    "the DHFS 4.1 volume signature verified but no block table could be read. {}",
                    findings.join(" | ")
                ),
                "validate_structure",
                "dhfs41_structures",
            ),
            VolumeModel::FlatDidxFallback { reason } => vs(
                ValidationStateKind::Review,
                reason.clone(),
                "validate_structure",
                "flat_didx_fallback",
            ),
            VolumeModel::NotApplicable { .. } => vol.recognition.validation(),
        };

        Ok(vec![self.run(profile, "validate_structure", state)])
    }

    /// Format recognition only: do the bytes in this window carry Dahua DHAV framing?
    ///
    /// A `true` means "these bytes are shaped like our container" and nothing more. It is never
    /// evidence that the region is an indexed recording — that question is answered by
    /// [`Parser::recording_index`]. It requires a structurally valid frame, not just a tag
    /// match, so four coincidental bytes in random data do not read as a container.
    fn recognize_candidate(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<bool, ForensicError> {
        let probe = u64_from(profile, key::DHAV_CARVE_WINDOW_BYTES, 4 * 1024 * 1024);
        crate::dhav::window_carries_dhav_framing(reader, profile, probe)
    }

    fn storage_geometry(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Option<StorageGeometry>, ForensicError> {
        let vol = volume::read_volume(reader, profile)?;
        volume::storage_geometry(&vol, reader, profile)
    }

    fn recording_index(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Option<RecordingIndex>, ForensicError> {
        let vol = volume::read_volume(reader, profile)?;
        volume::recording_index(&vol, reader, profile)
    }

    /// Carve a physical range and report every DHAV frame in it.
    ///
    /// This is the raw-carving half of recovery: the engine hands over a range it has
    /// established nothing about, and this walks Dahua's own framing. It reports many records
    /// per range, at absolute offsets, and never substitutes a length to make a frame fit.
    fn scan_region_for_candidates(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
        region: Region,
    ) -> Result<Vec<ContainerRecord>, ForensicError> {
        let carved = crate::dhav::carve_region(reader, profile, region)?;
        Ok(carved
            .frames
            .iter()
            .map(|f| f.to_container_record())
            .collect())
    }

    fn reconstruction_provider(&self) -> Option<&dyn parsers_core::ReconstructionProvider> {
        Some(self)
    }
}

impl parsers_core::ReconstructionProvider for DahuaParser {
    fn reconstruct_recording(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
        recording_id: &str,
    ) -> Result<Option<parsers_core::ReconstructedStream>, ForensicError> {
        let volume = volume::read_volume(reader, profile)?;
        let Some(classified) = find_chain(&volume, recording_id) else {
            return Ok(None);
        };
        let reconstruction = reconstruct_recording(reader, profile, &classified.chain)?;
        if reconstruction.payload_regions.is_empty() {
            return Err(ForensicError::corrupt(
                "dahua_reconstruct",
                format!(
                    "Dahua chain '{recording_id}' was located but no frame payload could be established in its blocks: {}",
                    reconstruction.evidence.reason
                ),
            ));
        }
        let description = format!(
            "{recording_id}: {} block(s), {} frame(s), {} payload range(s), ordered by {}; {}",
            reconstruction.block_regions.len(),
            reconstruction.frames.len(),
            reconstruction.payload_regions.len(),
            reconstruction.ordering.label(),
            reconstruction.evidence.reason
        );
        Ok(Some(parsers_core::ReconstructedStream {
            payload_regions: reconstruction.payload_regions,
            channel: reconstruction.channel.normalized,
            description,
        }))
    }
}

/// Reconstruct one Dahua recording chain into ordered frames and payload ranges.
///
/// Exposed as a free function rather than on the `Parser` trait because it is Dahua-specific
/// depth the generic interface does not need. The export layer calls it to turn an
/// engine-discovered chain into an exportable stream while keeping the chain id and every
/// physical offset intact.
pub fn reconstruct_recording(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
    chain: &RecordingChain,
) -> Result<crate::reconstruct::ChainReconstruction, ForensicError> {
    crate::reconstruct::reconstruct_chain(reader, profile, chain)
}

/// Locate a recording chain by the id [`crate::volume`] assigned it.
///
/// Used by the export layer: it receives a `recording_id` from the recovery engine and needs
/// the chain behind it. Returns `None` when the volume no longer yields that chain, which is a
/// real answer rather than an error.
pub fn find_chain(volume: &DahuaVolume, chain_id: &str) -> Option<ClassifiedChain> {
    volume
        .chains
        .iter()
        .find(|c| c.chain.chain_id == chain_id)
        .cloned()
}

/// OEM-specific descriptive fields for a report, as plain strings.
pub fn volume_summary(volume: &DahuaVolume) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    out.insert("structural_model".into(), volume.model.label().into());
    out.insert("dhfs_recognition".into(), volume.recognition.label().into());
    out.insert(
        "accessible_chains".into(),
        volume.accessible_chains().count().to_string(),
    );
    out.insert(
        "available_chains".into(),
        volume.available_chains().count().to_string(),
    );
    out.insert("block_tables".into(), volume.block_maps.len().to_string());
    if let Some(m) = &volume.descriptors.model {
        out.insert("model".into(), m.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::tests_support::dahua_profile;
    use crate::testing::MemReader;

    /// The parser must never bake a timezone into its output.
    #[test]
    fn time_evidence_never_claims_a_timezone_it_did_not_establish() {
        let p = dahua_profile();
        let parser = DahuaParser::default();
        let raw = crate::timestamp::pack(2026, 9, 22, 14, 35, 7, 2000).unwrap();
        let ts = DahuaTimestamp::decode(
            raw,
            crate::timestamp::TimestampStructure::BlockTableStart,
            &p,
        );
        let te = parser.time_evidence(&p, &ts, 0x1000);

        assert_eq!(te.timezone, TimeZoneState::Unknown);
        assert_eq!(te.raw.value, raw as u64);
        assert_eq!(te.raw.format, PACKED_FORMAT);
        assert_eq!(
            te.recorder_native.as_ref().map(|r| r.iso_8601.as_str()),
            Some("2026-09-22T14:35:07"),
            "the recorder's own digits, with no zone suffix"
        );
        let normalized = te.normalized.as_ref().unwrap();
        assert!(normalized.iso_8601.starts_with("2026-09-22T14:35:07"));
        assert!(
            normalized.method.contains("no recorder timezone offset"),
            "the normalization method must state that no offset was applied: {}",
            normalized.method
        );
        assert!(
            !normalized.iso_8601.contains("+05:30"),
            "no regional offset may be applied during parsing"
        );
    }

    #[test]
    fn an_absent_timestamp_produces_no_native_or_normalized_time() {
        let p = dahua_profile();
        let parser = DahuaParser::default();
        let te = parser.absent_time_evidence(&p, 0x2000, "no timestamp in this structure");
        assert!(te.recorder_native.is_none());
        assert!(te.normalized.is_none());
        assert_eq!(te.timezone, TimeZoneState::Unknown);
        assert_eq!(te.raw.value, 0);
        assert!(te.raw.format.ends_with("_ABSENT"));
    }

    #[test]
    fn the_profile_hash_is_deterministic_and_not_an_all_zero_placeholder() {
        let mut p = dahua_profile();
        p.profile_hash = None;
        let parser = DahuaParser::default();
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
    fn a_non_dahua_volume_runs_every_stage_without_asserting_anything() {
        let p = dahua_profile();
        let parser = DahuaParser::default();
        let r = MemReader::new(vec![0u8; 1 << 16]);

        let fs = parser.parse_filesystem(&r, &p).unwrap();
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].validation_state.state, ValidationStateKind::Unknown);

        let (recordings, runs) = parser.parse_recordings(&r, &p).unwrap();
        assert!(recordings.is_empty());
        assert_eq!(runs[0].validation_state.state, ValidationStateKind::Unknown);

        let (events, runs) = parser.extract_timeline_events(&r, &p).unwrap();
        assert!(events.is_empty());
        assert_eq!(runs[0].validation_state.state, ValidationStateKind::Unknown);

        assert!(parser.storage_geometry(&r, &p).unwrap().is_none());
        assert!(!parser.recognize_candidate(&r, &p).unwrap());
        assert!(parser
            .scan_region_for_candidates(&r, &p, Region::new(0, r.len()).unwrap())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn scan_region_for_candidates_reports_every_frame_in_the_range() {
        use crate::dhav::builder::{h264_payload, FrameBuilder};
        let p = dahua_profile();
        let parser = DahuaParser::default();

        let frames: Vec<Vec<u8>> = (0..4)
            .map(|i| {
                FrameBuilder::video_key(h264_payload(i as u8))
                    .frame_number(i + 1)
                    .build()
            })
            .collect();
        let total: usize = frames.iter().map(|f| f.len()).sum();
        let mut bytes = vec![0u8; 4096 + total + 4096];
        let mut cursor = 4096usize;
        let mut offsets = Vec::new();
        for f in &frames {
            offsets.push(cursor as u64);
            bytes[cursor..cursor + f.len()].copy_from_slice(f);
            cursor += f.len();
        }
        let r = MemReader::new(bytes);

        let records = parser
            .scan_region_for_candidates(&r, &p, Region::new(0, r.len()).unwrap())
            .unwrap();
        assert_eq!(
            records.len(),
            4,
            "one scan range must be able to yield many candidates"
        );
        assert_eq!(
            records
                .iter()
                .map(|c| c.physical_region.offset)
                .collect::<Vec<_>>(),
            offsets,
            "absolute offsets, preserved"
        );
        assert!(records.iter().all(|c| c.payload_region.is_some()));
        assert!(records.iter().all(|c| c.channel == Some(1)));
        assert!(records.iter().all(|c| c.start_time_unix.is_some()));
    }
}
