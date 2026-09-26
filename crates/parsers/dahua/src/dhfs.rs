//! # Provisional flat-superblock + `DIDX` fallback
//!
//! This module reads a **flat** Dahua-shaped volume: descriptive geometry fields at fixed
//! superblock offsets, and one global `DIDX` recording-index table located through them.
//!
//! ## This is a fallback, and it says so
//!
//! It is **not** the DHFS 4.1 structure set. A real DHFS 4.1 volume keeps its authoritative
//! geometry in the partition table at `0x3C00` and its recording metadata in per-partition
//! block tables; that is what [`crate::volume`] reads, and it is what runs first.
//!
//! This path is retained because the platform's corpus contains volumes that present the flat
//! structures, and removing a working reader would lose that capability. It is entered only
//! when:
//!
//! 1. the DHFS 4.1 partition table did **not** verify, **and**
//! 2. a `DIDX` header **does** verify at the superblock-declared offset.
//!
//! Every geometry and index value it produces is labelled as coming from the provisional
//! model, so it can never be mistaken for a reading of the real filesystem.
//!
//! ## Forensic rules
//!
//! * Every structure offset comes from the versioned profile `[layout]` table.
//! * Reads are bounds-checked before use; a truncated or hostile image yields a degraded
//!   [`IndexAuthority`], never a panic and never a fabricated entry.
//! * A field that cannot be read is `None`. A field that reads but is implausible (zero sector
//!   size, index before the video region, region past end of evidence) is also `None`, with the
//!   reason recorded.
//! * [`IndexAuthority::Authoritative`] requires the `DIDX` header verified, a non-zero declared
//!   count, and **every** declared entry parsed in bounds. Anything less degrades to
//!   [`IndexAuthority::Partial`], which downstream classification treats as "absence proves
//!   nothing".
//! * Container framing inside a claimed region is separated by the one authoritative DHAV
//!   parser in [`crate::dhav`] — never by a second, divergent notion of where a payload starts.

use std::collections::BTreeMap;

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, OemProfile, Region, ValidationStateKind};
use parsers_core::storage::{
    AllocationEvidence, CircularBufferEvidence, IndexAuthority, IndexedRecording, RecordingIndex,
    StorageGeometry,
};

use crate::layout::{ascii_at, key, magic, u32_at, u64_at, u64_from, usize_from, vs};

/// Tag applied to every value this module produces, so the provisional model is visible.
const MODEL_TAG: &str = "provisional flat superblock + DIDX model (not the DHFS 4.1 structure set)";

/// Parsed flat superblock fields, before plausibility filtering.
struct Superblock {
    sector_size: Option<u64>,
    block_size: Option<u64>,
    total_blocks: Option<u64>,
    video_start: Option<u64>,
    index_offset: Option<u64>,
    ctime_unix: Option<u64>,
    model: Option<String>,
    serial: Option<String>,
    volume_label: Option<String>,
}

/// Read the flat superblock at offset 0.
///
/// Returns `Ok(None)` when the DHFS family magic is absent — this evidence is not a Dahua
/// volume at all, so no geometry can be claimed from it.
fn read_superblock(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
) -> Result<Option<Superblock>, ForensicError> {
    let sb_size = u64_from(profile, key::SUPERBLOCK_SIZE, 512);
    if sb_size == 0 || reader.len() < sb_size {
        return Ok(None);
    }

    let family = match magic(profile, "dhfs_magic") {
        Some(m) => m,
        // Without a profile-declared magic there is no way to verify the structure, and
        // verifying is the whole point. Refuse rather than guess.
        None => return Ok(None),
    };

    let buf = match reader.read_exact_at(0, sb_size as usize) {
        Ok(b) => b,
        // A short read here means the image is truncated inside its own first sector.
        Err(_) => return Ok(None),
    };
    if !buf.starts_with(&family) {
        return Ok(None);
    }

    Ok(Some(Superblock {
        sector_size: u32_at(&buf, usize_from(profile, key::SB_SECTOR_SIZE_OFFSET, 8))
            .map(u64::from),
        block_size: u32_at(&buf, usize_from(profile, key::SB_BLOCK_SIZE_OFFSET, 12)).map(u64::from),
        total_blocks: u64_at(&buf, usize_from(profile, key::SB_TOTAL_BLOCKS_OFFSET, 16)),
        video_start: u64_at(&buf, usize_from(profile, key::SB_DHAV_START_OFFSET, 24)),
        index_offset: u64_at(&buf, usize_from(profile, key::SB_INDEX_OFFSET_OFFSET, 32)),
        ctime_unix: u64_at(&buf, usize_from(profile, key::SB_CTIME_OFFSET, 40)),
        model: ascii_at(
            &buf,
            usize_from(profile, key::SB_MODEL_OFFSET, 48),
            usize_from(profile, key::SB_MODEL_LEN, 16),
        ),
        serial: ascii_at(
            &buf,
            usize_from(profile, key::SB_SERIAL_OFFSET, 64),
            usize_from(profile, key::SB_SERIAL_LEN, 32),
        ),
        volume_label: ascii_at(
            &buf,
            usize_from(profile, key::SB_VOLUME_LABEL_OFFSET, 96),
            usize_from(profile, key::SB_VOLUME_LABEL_LEN, 16),
        ),
    }))
}

/// Whether a `DIDX` header verifies at the superblock-declared index offset.
///
/// This is the gate [`crate::volume`] uses to decide whether the flat fallback applies at
/// all. It deliberately verifies the structure rather than merely finding a plausible offset.
pub fn didx_header_verifies(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
) -> Result<bool, ForensicError> {
    let Some(sb) = read_superblock(reader, profile)? else {
        return Ok(false);
    };
    let Some(tag) = magic(profile, "didx_magic") else {
        return Ok(false);
    };
    let Some(start) = sb.index_offset else {
        return Ok(false);
    };
    let need = tag.len() as u64;
    if start >= reader.len() || start.saturating_add(need) > reader.len() {
        return Ok(false);
    }
    Ok(reader
        .read_exact_at(start, need as usize)
        .map(|b| b.starts_with(&tag))
        .unwrap_or(false))
}

/// Derive [`StorageGeometry`] from the flat superblock.
///
/// Returns `Ok(None)` when the volume carries no DHFS family magic. Individual fields degrade
/// to `None` independently, so a damaged `index_offset` does not cost us the block size.
pub fn read_storage_geometry(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
) -> Result<Option<StorageGeometry>, ForensicError> {
    let Some(sb) = read_superblock(reader, profile)? else {
        return Ok(None);
    };

    let disk_len = reader.len();
    let mut notes: Vec<String> = Vec::new();

    // Plausibility filters. A value that fails one is reported as unknown, with the reason
    // surfaced, rather than silently propagated into range arithmetic.
    let sector_size = sb
        .sector_size
        .filter(|s| *s > 0 && s.is_power_of_two() && *s <= 65536);
    if sector_size.is_none() && sb.sector_size.is_some() {
        notes.push(format!(
            "declared sector_size {} is implausible; reported as unknown",
            sb.sector_size.unwrap_or(0)
        ));
    }
    let block_size = sb.block_size.filter(|b| *b > 0 && *b <= 64 * 1024 * 1024);
    if block_size.is_none() && sb.block_size.is_some() {
        notes.push(format!(
            "declared block_size {} is implausible; reported as unknown",
            sb.block_size.unwrap_or(0)
        ));
    }

    // The index region: [index_offset, index_offset + header + count*entry_size). Its true
    // length needs the entry count, so the header is read here directly.
    let index_tag = magic(profile, "didx_magic");
    let header_size = u64_from(profile, key::INDEX_HEADER_SIZE, 16);
    let entry_size = u64_from(profile, key::INDEX_ENTRY_SIZE, 32);
    let count_off = u64_from(profile, key::INDEX_ENTRY_COUNT_OFFSET, 4);

    let mut index_region: Option<Region> = None;
    let mut index_start_verified: Option<u64> = None;
    if let (Some(start), Some(tag)) = (sb.index_offset, index_tag.as_ref()) {
        let want = header_size.max(count_off.saturating_add(4));
        if start < disk_len && start.saturating_add(want) <= disk_len {
            if let Ok(hdr) = reader.read_exact_at(start, want as usize) {
                if hdr.starts_with(tag) {
                    index_start_verified = Some(start);
                    let count = u32_at(&hdr, count_off as usize).unwrap_or(0) as u64;
                    let declared_len = header_size.saturating_add(count.saturating_mul(entry_size));
                    // A declared length must never describe bytes outside the image.
                    let clamped = declared_len.min(disk_len.saturating_sub(start));
                    index_region = Region::new(start, clamped).ok();
                } else {
                    notes.push(format!(
                        "superblock index_offset 0x{start:X} does not carry the DIDX header magic"
                    ));
                }
            }
        } else {
            notes.push(format!(
                "superblock index_offset 0x{start:X} lies outside the {disk_len}-byte evidence"
            ));
        }
    }

    // The video payload region runs from the declared video start to the start of the index
    // when the index verified, otherwise to end of evidence. It is claimed only when the
    // bounds are internally consistent — this region is what licenses an orphan finding, so a
    // sloppy bound here would be a forensic error.
    let video_region = match sb.video_start {
        Some(start) if start < disk_len => {
            let end = index_start_verified
                .filter(|ix| *ix > start && *ix <= disk_len)
                .unwrap_or(disk_len);
            if end > start {
                Region::new(start, end - start).ok()
            } else {
                notes.push(format!(
                    "declared video start 0x{start:X} is not before the index region; video region \
                     reported as unknown"
                ));
                None
            }
        }
        Some(start) => {
            notes.push(format!(
                "declared video start 0x{start:X} lies outside the {disk_len}-byte evidence"
            ));
            None
        }
        None => None,
    };

    let metadata_region = sector_size
        .or(Some(u64_from(profile, key::SUPERBLOCK_SIZE, 512)))
        .filter(|s| *s <= disk_len)
        .and_then(|s| Region::new(0, s).ok());

    let mut oem_fields: BTreeMap<String, String> = BTreeMap::new();
    oem_fields.insert("structural_model".into(), "flat-didx-fallback".into());
    oem_fields.insert("structural_model_note".into(), MODEL_TAG.into());
    if let Some(v) = sb.model {
        oem_fields.insert("model".into(), v);
    }
    if let Some(v) = sb.serial {
        oem_fields.insert("serial".into(), v);
    }
    if let Some(v) = sb.volume_label {
        oem_fields.insert("volume_label".into(), v);
    }
    if let Some(v) = sb.total_blocks {
        oem_fields.insert("declared_total_blocks".into(), v.to_string());
    }
    if let Some(v) = sb.ctime_unix {
        oem_fields.insert("filesystem_ctime_unix".into(), v.to_string());
    }

    let mut reason = format!(
        "{MODEL_TAG}: superblock verified at offset 0; video_region={}, index_region={}, \
         block_size={}, sector_size={}",
        video_region
            .map(|r| r.to_string())
            .unwrap_or_else(|| "unknown".into()),
        index_region
            .map(|r| r.to_string())
            .unwrap_or_else(|| "unknown".into()),
        block_size
            .map(|b| b.to_string())
            .unwrap_or_else(|| "unknown".into()),
        sector_size
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".into()),
    );
    if !notes.is_empty() {
        reason.push_str("; ");
        reason.push_str(&notes.join("; "));
    }

    // Geometry from a provisional model is never Pass: the model itself is the caveat.
    let evidence = vs(
        ValidationStateKind::Review,
        reason,
        "dhfs_flat_storage_geometry",
        "flat_superblock",
    );

    Ok(Some(StorageGeometry {
        physical_size: disk_len,
        video_region,
        index_region,
        metadata_region,
        block_size,
        sector_size,
        // The flat structures carry no write cursor or wrap flag. Reporting anything other
        // than Unknown here would be fabrication.
        circular_buffer: CircularBufferEvidence::Unknown,
        oem_fields,
        evidence,
    }))
}

/// Read the `DIDX` recording index located via the superblock's `index_offset`.
///
/// Returns `Ok(None)` when the volume carries no DHFS family magic. When it does but the index
/// cannot be located or fully parsed, a [`RecordingIndex`] is still returned with a
/// non-authoritative [`IndexAuthority`], because "we looked and could not establish it" is
/// materially different information from "we never looked".
pub fn read_recording_index(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
) -> Result<Option<RecordingIndex>, ForensicError> {
    let Some(sb) = read_superblock(reader, profile)? else {
        return Ok(None);
    };

    let disk_len = reader.len();
    let header_size = u64_from(profile, key::INDEX_HEADER_SIZE, 16);
    let entry_size = u64_from(profile, key::INDEX_ENTRY_SIZE, 32);
    let count_off = usize_from(profile, key::INDEX_ENTRY_COUNT_OFFSET, 4);

    let not_found = |reason: String| -> Result<Option<RecordingIndex>, ForensicError> {
        Ok(Some(RecordingIndex {
            authority: IndexAuthority::NotFound {
                reason: reason.clone(),
            },
            recordings: Vec::new(),
            unreferenced_recordings: Vec::new(),
            declared_entry_count: None,
            index_region: None,
            evidence: vs(
                ValidationStateKind::Review,
                reason,
                "dhfs_flat_recording_index",
                "didx",
            ),
        }))
    };

    let tag = match magic(profile, "didx_magic") {
        Some(m) => m,
        None => return not_found(
            "the profile declares no DIDX header signature, so index entries cannot be verified"
                .to_string(),
        ),
    };

    let start = match sb.index_offset {
        Some(s) => s,
        None => {
            return not_found(
                "the flat superblock declares no index_offset; no recording index located"
                    .to_string(),
            )
        }
    };

    if start >= disk_len || start.saturating_add(header_size) > disk_len {
        return not_found(format!(
            "the flat superblock declares index_offset 0x{start:X}, outside the {disk_len}-byte \
             evidence"
        ));
    }

    let hdr = match reader.read_exact_at(start, header_size as usize) {
        Ok(h) => h,
        Err(e) => {
            return not_found(format!(
                "index header at 0x{start:X} could not be read: {e}"
            ))
        }
    };
    if !hdr.starts_with(&tag) {
        return not_found(format!(
            "no DIDX header magic at the superblock-declared offset 0x{start:X}"
        ));
    }

    let declared = u32_at(&hdr, count_off).unwrap_or(0) as usize;
    let table_start = start.saturating_add(header_size);

    let f_channel = usize_from(profile, key::INDEX_ENTRY_CHANNEL_OFFSET, 0);
    let f_frame_type = usize_from(profile, key::INDEX_ENTRY_FRAME_TYPE_OFFSET, 1);
    let f_offset = usize_from(profile, key::INDEX_ENTRY_OFFSET_OFFSET, 4);
    let f_length = usize_from(profile, key::INDEX_ENTRY_LENGTH_OFFSET, 12);
    let f_timestamp = usize_from(profile, key::INDEX_ENTRY_TIMESTAMP_OFFSET, 20);
    let f_crc = usize_from(profile, key::INDEX_ENTRY_CRC_OFFSET, 28);

    let mut recordings: Vec<IndexedRecording> = Vec::new();
    let mut rejected: Vec<String> = Vec::new();

    for i in 0..declared {
        let entry_at = match table_start.checked_add((i as u64).saturating_mul(entry_size)) {
            Some(v) => v,
            None => {
                rejected.push(format!("entry {i}: table offset overflows u64"));
                break;
            }
        };
        if entry_at.saturating_add(entry_size) > disk_len {
            rejected.push(format!(
                "entry {i}: entry bytes at 0x{entry_at:X} lie outside the evidence"
            ));
            break;
        }
        let e = match reader.read_exact_at(entry_at, entry_size as usize) {
            Ok(b) => b,
            Err(err) => {
                rejected.push(format!("entry {i}: unreadable at 0x{entry_at:X}: {err}"));
                continue;
            }
        };

        let Some(rec_offset) = u64_at(&e, f_offset) else {
            rejected.push(format!("entry {i}: offset field out of entry bounds"));
            continue;
        };
        let Some(rec_length) = u64_at(&e, f_length) else {
            rejected.push(format!("entry {i}: length field out of entry bounds"));
            continue;
        };

        // An entry describing bytes outside the evidence is rejected and recorded, never
        // clamped into something plausible: a clamped claim would misstate what the recorder
        // actually said.
        if rec_length == 0 {
            rejected.push(format!(
                "entry {i}: declares a zero-length recording at 0x{rec_offset:X}"
            ));
            continue;
        }
        let Some(rec_end) = rec_offset.checked_add(rec_length) else {
            rejected.push(format!(
                "entry {i}: offset 0x{rec_offset:X} + length {rec_length} overflows u64"
            ));
            continue;
        };
        if rec_end > disk_len {
            rejected.push(format!(
                "entry {i}: claims [0x{rec_offset:X}..0x{rec_end:X}) beyond the {disk_len}-byte \
                 evidence"
            ));
            continue;
        }

        let physical = Region::new(rec_offset, rec_length)?;

        // Payload separation goes through the one authoritative DHAV parser, so this path
        // cannot develop its own idea of where a payload begins. When the claimed bytes do
        // not parse as a frame, no payload sub-range is claimed at all.
        let mut oem_metadata: BTreeMap<String, String> = BTreeMap::new();
        oem_metadata.insert("structural_model".into(), "flat-didx-fallback".into());
        oem_metadata.insert("structural_model_note".into(), MODEL_TAG.into());
        oem_metadata.insert("index_entry_number".into(), i.to_string());
        oem_metadata.insert("index_entry_offset".into(), format!("0x{entry_at:X}"));

        let mut payload_regions = Vec::new();
        let mut codec_hint = None;
        match crate::dhav::parse_frame_at(reader, profile, rec_offset, rec_end)? {
            Ok(frame) => {
                if let Some(p) = frame.payload_region {
                    payload_regions.push(p);
                }
                codec_hint = frame.codec.clone();
                oem_metadata.insert("dhav_frame_kind".into(), frame.kind.label());
                oem_metadata.insert(
                    "dhav_extra_header_length".into(),
                    frame.extra_header_length.to_string(),
                );
                oem_metadata.insert(
                    "dhav_trailer_tag_verified".into(),
                    frame.trailer_tag_verified.to_string(),
                );
                oem_metadata.insert("dhav_frame_evidence".into(), frame.evidence.reason.clone());
                if let Some(w) = &frame.timestamp.recorder_wall_clock {
                    oem_metadata.insert("dahua_recorder_wall_clock".into(), w.clone());
                }
            }
            Err(rejection) => {
                oem_metadata.insert(
                    "dhav_frame_evidence".into(),
                    format!(
                        "the claimed region does not parse as a DHAV frame, so no payload sub-range \
                         is claimed: {}",
                        rejection.reason
                    ),
                );
            }
        }

        // Channel is stored 0-based on disk and reported 1-based, matching the recorder's own
        // CH01/CH02 labelling.
        let channel = e.get(f_channel).map(|b| *b as u32 + 1);
        if let Some(ft) = e.get(f_frame_type) {
            oem_metadata.insert("index_entry_frame_type".into(), format!("0x{ft:02X}"));
        }
        if let Some(c) = u32_at(&e, f_crc) {
            oem_metadata.insert("declared_crc32".into(), format!("0x{c:08X}"));
        }
        // A zero timestamp is the absence of a timestamp in this structure, not 1970.
        let start_time_unix = u64_at(&e, f_timestamp)
            .filter(|t| *t > 0)
            .and_then(|t| i64::try_from(t).ok());

        recordings.push(IndexedRecording {
            recording_id: format!("didx#{i}"),
            // The flat model describes a single unpartitioned region, so there is no
            // partition to report. That is a fact about the model, not a missing value.
            partition: None,
            channel,
            start_time_unix,
            // The entry carries no duration or end timestamp, so the end time is genuinely
            // unknown. Deriving it from the next entry would be an inference, not a reading.
            end_time_unix: None,
            physical_regions: vec![physical],
            payload_regions,
            codec_hint,
            // The flat structures carry no allocation/tombstone field.
            allocation: AllocationEvidence::Unknown,
            oem_metadata,
            evidence: vs(
                ValidationStateKind::Pass,
                format!("DIDX entry {i} parsed: claims {physical} ({MODEL_TAG})"),
                "dhfs_flat_recording_index",
                "didx_entry",
            ),
        });
    }

    let index_region = {
        let declared_len = header_size.saturating_add((declared as u64).saturating_mul(entry_size));
        let clamped = declared_len.min(disk_len.saturating_sub(start));
        Region::new(start, clamped).ok()
    };

    // Authority: only a fully parsed, non-empty index is a complete statement about what the
    // recorder currently claims. Anything else and absence proves nothing.
    let (authority, evidence) = if declared == 0 {
        let reason = format!(
            "DIDX header verified at 0x{start:X} but declares zero entries; the index makes no claim \
             about any region ({MODEL_TAG})"
        );
        (
            IndexAuthority::Partial {
                reason: reason.clone(),
            },
            vs(
                ValidationStateKind::Review,
                reason,
                "dhfs_flat_recording_index",
                "didx",
            ),
        )
    } else if !rejected.is_empty() || recordings.len() != declared {
        let reason = format!(
            "DIDX at 0x{start:X} declares {declared} entries but only {parsed} parsed cleanly; \
             absence from a partial index is not evidence of deletion. Rejected: {detail} ({MODEL_TAG})",
            parsed = recordings.len(),
            detail = rejected.join("; ")
        );
        (
            IndexAuthority::Partial {
                reason: reason.clone(),
            },
            vs(
                ValidationStateKind::Review,
                reason,
                "dhfs_flat_recording_index",
                "didx",
            ),
        )
    } else {
        // The index governs the video payload region it indexes. Falling back to the span of
        // its own claims keeps the governed region evidence-bounded when the superblock's
        // video region could not be established.
        let governs = match read_storage_geometry(reader, profile)?.and_then(|g| g.video_region) {
            Some(r) => r,
            None => {
                let min = recordings
                    .iter()
                    .flat_map(|r| r.physical_regions.iter())
                    .map(|r| r.offset)
                    .min()
                    .unwrap_or(0);
                let max = recordings
                    .iter()
                    .flat_map(|r| r.physical_regions.iter())
                    .map(|r| r.end().unwrap_or(u64::MAX))
                    .max()
                    .unwrap_or(0);
                Region::new(min, max.saturating_sub(min))?
            }
        };
        let reason = format!(
            "DIDX at 0x{start:X} fully parsed: {declared} entr{plural} claiming {bytes} bytes; \
             authoritative over {governs} ({MODEL_TAG})",
            plural = if declared == 1 { "y" } else { "ies" },
            bytes = recordings
                .iter()
                .fold(0u64, |a, r| a.saturating_add(r.claimed_bytes())),
        );
        (
            IndexAuthority::Authoritative { governs },
            vs(
                ValidationStateKind::Review,
                reason,
                "dhfs_flat_recording_index",
                "didx",
            ),
        )
    };

    Ok(Some(RecordingIndex {
        authority,
        recordings,
        // The flat model offers no way to distinguish a surviving-but-unreferenced recording
        // from one that was never indexed, so it contributes no available set. Video found in
        // its unclaimed space is reported as orphaned by the engine's own range algebra.
        unreferenced_recordings: Vec::new(),
        declared_entry_count: Some(declared),
        index_region,
        evidence,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhav::builder::{h264_payload, FrameBuilder};
    use crate::layout::tests_support::dahua_profile;
    use crate::testing::MemReader;

    const SECTOR: u64 = 512;
    const VIDEO_START: u64 = 512;
    const SLOT: u64 = 64 * 1024;

    struct Flat {
        bytes: Vec<u8>,
        frame_regions: Vec<Region>,
        index_offset: u64,
    }

    /// Build a flat volume: superblock, real DHAV frames, and a DIDX table referencing
    /// `indexed`-flagged frames.
    fn flat_volume(frames: &[(u8, bool)]) -> Flat {
        let built: Vec<Vec<u8>> = frames
            .iter()
            .enumerate()
            .map(|(i, (ch0, _))| {
                FrameBuilder::video_key(h264_payload(0x40 + i as u8))
                    .channel_0_based(*ch0 as u16)
                    .frame_number(i as u32 + 1)
                    .build()
            })
            .collect();
        let offsets: Vec<u64> = (0..built.len())
            .map(|i| VIDEO_START + i as u64 * SLOT)
            .collect();
        let last_end = offsets[built.len() - 1] + built[built.len() - 1].len() as u64;
        let index_offset = ((last_end + SLOT) / SECTOR) * SECTOR;
        let indexed_count = frames.iter().filter(|f| f.1).count() as u64;
        let total = index_offset + 16 + indexed_count * 32 + SECTOR;

        let mut b = vec![0u8; total as usize];
        b[..4].copy_from_slice(b"DHFS");
        b[4..8].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        b[8..12].copy_from_slice(&(SECTOR as u32).to_le_bytes());
        b[12..16].copy_from_slice(&65536u32.to_le_bytes());
        b[16..24].copy_from_slice(&(total / 65536).to_le_bytes());
        b[24..32].copy_from_slice(&VIDEO_START.to_le_bytes());
        b[32..40].copy_from_slice(&index_offset.to_le_bytes());
        b[48..48 + 13].copy_from_slice(b"DHI-XVR5216AN");
        b[96..96 + 12].copy_from_slice(b"DVR_REC_VOL0");

        for (i, f) in built.iter().enumerate() {
            let at = offsets[i] as usize;
            b[at..at + f.len()].copy_from_slice(f);
        }

        let io = index_offset as usize;
        b[io..io + 4].copy_from_slice(b"DIDX");
        b[io + 4..io + 8].copy_from_slice(&(indexed_count as u32).to_le_bytes());
        let mut e = io + 16;
        let mut frame_regions = Vec::new();
        for (i, (ch0, indexed)) in frames.iter().enumerate() {
            if !*indexed {
                continue;
            }
            let len = built[i].len() as u64;
            b[e] = *ch0;
            b[e + 1] = 0xFD;
            b[e + 4..e + 12].copy_from_slice(&offsets[i].to_le_bytes());
            b[e + 12..e + 20].copy_from_slice(&len.to_le_bytes());
            b[e + 20..e + 28].copy_from_slice(&1_790_500_000u64.to_le_bytes());
            b[e + 28..e + 32].copy_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
            e += 32;
            frame_regions.push(Region::new(offsets[i], len).unwrap());
        }

        Flat {
            bytes: b,
            frame_regions,
            index_offset,
        }
    }

    #[test]
    fn the_flat_gate_requires_a_verified_didx_header() {
        let p = dahua_profile();
        let flat = flat_volume(&[(0, true)]);
        assert!(didx_header_verifies(&MemReader::new(flat.bytes.clone()), &p).unwrap());

        // Break the DIDX magic: the gate must close.
        let mut broken = flat.bytes.clone();
        let at = flat.index_offset as usize;
        broken[at..at + 4].copy_from_slice(b"XXXX");
        assert!(!didx_header_verifies(&MemReader::new(broken), &p).unwrap());

        // A non-Dahua volume never opens it.
        assert!(!didx_header_verifies(&MemReader::new(vec![0u8; 1 << 16]), &p).unwrap());
    }

    #[test]
    fn flat_geometry_is_read_but_never_reported_as_a_clean_parse() {
        let p = dahua_profile();
        let flat = flat_volume(&[(0, true), (1, true)]);
        let r = MemReader::new(flat.bytes);
        let g = read_storage_geometry(&r, &p)
            .unwrap()
            .expect("flat geometry");

        assert_eq!(g.sector_size, Some(SECTOR));
        assert_eq!(g.block_size, Some(65536));
        assert_eq!(g.video_region.map(|x| x.offset), Some(VIDEO_START));
        assert_eq!(g.index_region.map(|x| x.offset), Some(flat.index_offset));
        assert_eq!(
            g.evidence.state,
            ValidationStateKind::Review,
            "a provisional model is never a clean parse"
        );
        assert!(g.evidence.reason.contains("not the DHFS 4.1 structure set"));
        assert_eq!(
            g.oem_fields.get("structural_model").map(|s| s.as_str()),
            Some("flat-didx-fallback")
        );
    }

    #[test]
    fn didx_entries_become_claims_with_payloads_from_the_authoritative_dhav_parser() {
        let p = dahua_profile();
        let flat = flat_volume(&[(0, true), (1, false), (0, true)]);
        let r = MemReader::new(flat.bytes);
        let idx = read_recording_index(&r, &p).unwrap().expect("index");

        assert!(idx.authority.is_authoritative());
        assert_eq!(idx.recordings.len(), 2);
        assert_eq!(idx.claimed_regions(), flat.frame_regions);
        assert!(idx.unreferenced_recordings.is_empty());

        let first = &idx.recordings[0];
        assert_eq!(first.partition, None, "the flat model has no partitions");
        assert_eq!(first.channel, Some(1));
        // The payload sub-range comes from the real DHAV framing: 24-byte header, no extra
        // header, 8-byte trailer.
        assert_eq!(first.payload_regions.len(), 1);
        assert_eq!(
            first.payload_regions[0].offset,
            first.physical_regions[0].offset + 24
        );
        assert_eq!(
            first.payload_regions[0].length,
            first.physical_regions[0].length - 32
        );
        assert_eq!(
            first
                .oem_metadata
                .get("dhav_frame_kind")
                .map(|s| s.as_str()),
            Some("video-key-frame")
        );
    }

    #[test]
    fn a_claim_that_does_not_parse_as_dhav_yields_no_payload_sub_range() {
        let p = dahua_profile();
        let mut flat = flat_volume(&[(0, true)]);
        // Destroy the frame's tag while leaving the DIDX claim intact.
        let at = VIDEO_START as usize;
        flat.bytes[at..at + 4].copy_from_slice(b"ZZZZ");
        let r = MemReader::new(flat.bytes);
        let idx = read_recording_index(&r, &p).unwrap().unwrap();

        let entry = &idx.recordings[0];
        assert!(entry.payload_regions.is_empty());
        assert!(entry
            .oem_metadata
            .get("dhav_frame_evidence")
            .unwrap()
            .contains("does not parse as a DHAV frame"));
    }

    #[test]
    fn an_out_of_bounds_claim_is_rejected_and_degrades_authority() {
        let p = dahua_profile();
        let mut flat = flat_volume(&[(0, true), (0, true)]);
        // Point the second entry past the end of the image.
        let e = flat.index_offset as usize + 16 + 32;
        let bogus = flat.bytes.len() as u64 + 1_000_000;
        flat.bytes[e + 4..e + 12].copy_from_slice(&bogus.to_le_bytes());
        let r = MemReader::new(flat.bytes);
        let idx = read_recording_index(&r, &p).unwrap().unwrap();

        assert_eq!(idx.recordings.len(), 1, "the bad claim is not clamped in");
        assert!(!idx.authority.is_authoritative());
        match &idx.authority {
            IndexAuthority::Partial { reason } => {
                assert!(reason.contains("not evidence of deletion"))
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_zero_entry_index_is_partial_not_authoritative() {
        let p = dahua_profile();
        let mut flat = flat_volume(&[(0, true)]);
        let at = flat.index_offset as usize;
        flat.bytes[at + 4..at + 8].copy_from_slice(&0u32.to_le_bytes());
        let r = MemReader::new(flat.bytes);
        let idx = read_recording_index(&r, &p).unwrap().unwrap();
        assert!(matches!(idx.authority, IndexAuthority::Partial { .. }));
        assert!(idx.recordings.is_empty());
    }

    #[test]
    fn a_volume_with_no_dahua_magic_yields_nothing_rather_than_a_guess() {
        let p = dahua_profile();
        let r = MemReader::new(vec![0u8; 1 << 16]);
        assert!(read_storage_geometry(&r, &p).unwrap().is_none());
        assert!(read_recording_index(&r, &p).unwrap().is_none());
    }

    #[test]
    fn a_missing_didx_header_is_not_found_not_a_fabricated_empty_index() {
        let p = dahua_profile();
        let mut flat = flat_volume(&[(0, true)]);
        let at = flat.index_offset as usize;
        flat.bytes[at..at + 4].copy_from_slice(b"XXXX");
        let r = MemReader::new(flat.bytes);
        let idx = read_recording_index(&r, &p).unwrap().unwrap();
        assert!(matches!(idx.authority, IndexAuthority::NotFound { .. }));
        assert!(idx.recordings.is_empty());
    }
}
