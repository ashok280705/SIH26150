//! # DHFS storage geometry and DIDX recording index readers
//!
//! This module is the Dahua-specific half of the OEM/generic boundary. It turns raw
//! evidence bytes into [`StorageGeometry`] and [`RecordingIndex`] — plain physical byte
//! ranges plus explicitly-optional metadata — so the recovery engine never has to know
//! what "DHFS", "DHAV" or "DIDX" mean.
//!
//! ## Forensic rules this module follows
//!
//! * Every structure offset comes from the versioned profile `[layout]` table. Nothing
//!   OEM-factual is a source constant.
//! * Reads are bounds-checked against the evidence length before use; hostile or
//!   truncated images yield a degraded [`IndexAuthority`], never a panic and never a
//!   fabricated entry.
//! * A field that cannot be read is `None`. A field that can be read but is implausible
//!   (zero sector size, index before the video region, region past end of evidence) is
//!   also `None`, with the reason recorded in the returned [`ValidationState`].
//! * [`IndexAuthority::Authoritative`] is granted only when the `DIDX` header verified,
//!   the declared entry count is non-zero, and **every** declared entry parsed in-bounds.
//!   Any shortfall degrades to [`IndexAuthority::Partial`], which downstream
//!   classification treats as "absence proves nothing".

use std::collections::BTreeMap;

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, OemProfile, Region, ValidationState, ValidationStateKind};
use parsers_core::storage::{
    AllocationEvidence, CircularBufferEvidence, IndexAuthority, IndexedRecording, RecordingIndex,
    StorageGeometry,
};

/// Build a `ValidationState` without a fallible call site.
///
/// `ValidationState::new` only rejects an empty reason. Every reason produced here is
/// non-empty by construction, and the fallback substitutes a static non-empty reason so
/// this helper is total — evidence handling never gains a panic path.
fn vs(kind: ValidationStateKind, reason: impl Into<String>, op: &str, subject: &str) -> ValidationState {
    let reason = reason.into();
    ValidationState::new(kind, reason, op, subject).unwrap_or_else(|_| {
        ValidationState::new(kind, "reason unavailable", op, subject)
            .expect("static fallback reason is non-empty")
    })
}

/// Read an i64 from the profile `[layout]` table, falling back to a documented default.
///
/// A missing key is a profile-completeness problem, not an evidence problem, so the
/// fallback keeps the parser operational on older profile revisions rather than failing
/// the whole run. Negative values are rejected because every layout value is an offset
/// or a size.
fn layout_u64(profile: &OemProfile, key: &str, fallback: u64) -> u64 {
    match profile.layout.get(key) {
        Some(v) if *v >= 0 => *v as u64,
        _ => fallback,
    }
}

fn layout_usize(profile: &OemProfile, key: &str, fallback: usize) -> usize {
    layout_u64(profile, key, fallback as u64) as usize
}

/// Little-endian u32 at `off` inside `buf`, or `None` if out of range.
fn u32_at(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Little-endian u64 at `off` inside `buf`, or `None` if out of range.
fn u64_at(buf: &[u8], off: usize) -> Option<u64> {
    buf.get(off..off + 8).map(|s| {
        u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
    })
}

/// Trim a fixed-width ASCII field; returns `None` when the field is absent or blank.
fn ascii_at(buf: &[u8], off: usize, len: usize) -> Option<String> {
    let s = buf.get(off..off.saturating_add(len))?;
    let text = String::from_utf8_lossy(s)
        .trim_matches('\0')
        .trim()
        .to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// Resolve the profile-declared magic pattern for a signature name.
fn magic_bytes(profile: &OemProfile, name: &str) -> Option<Vec<u8>> {
    profile
        .signatures
        .iter()
        .find(|s| s.name == name)
        .and_then(|s| s.pattern_bytes().ok())
}

/// Parsed DHFS superblock fields, before plausibility filtering.
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

/// Read and verify the DHFS superblock at offset 0.
///
/// Returns `Ok(None)` when the superblock magic is absent — i.e. this evidence is not a
/// DHFS volume, so no geometry can be claimed from it.
fn read_superblock(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
) -> Result<Option<Superblock>, ForensicError> {
    let sb_size = layout_u64(profile, "superblock_size", 512);
    if sb_size == 0 || reader.len() < sb_size {
        return Ok(None);
    }

    let magic = match magic_bytes(profile, "dhfs_magic") {
        Some(m) if !m.is_empty() => m,
        // Without a profile-declared magic the parser has no way to verify the
        // structure, and verifying is the whole point. Refuse rather than guess.
        _ => return Ok(None),
    };

    // A short read here means the image is truncated inside its own superblock.
    let buf = match reader.read_exact_at(0, sb_size as usize) {
        Ok(b) => b,
        Err(_) => return Ok(None),
    };
    if !buf.starts_with(&magic) {
        return Ok(None);
    }

    let sector_size = u32_at(&buf, layout_usize(profile, "superblock_sector_size_offset", 8))
        .map(u64::from);
    let block_size =
        u32_at(&buf, layout_usize(profile, "superblock_block_size_offset", 12)).map(u64::from);
    let total_blocks = u64_at(&buf, layout_usize(profile, "superblock_total_blocks_offset", 16));
    let video_start = u64_at(&buf, layout_usize(profile, "superblock_dhav_start_offset", 24));
    let index_offset = u64_at(&buf, layout_usize(profile, "superblock_index_offset_offset", 32));
    let ctime_unix = u64_at(&buf, layout_usize(profile, "superblock_ctime_offset", 40));

    let model = ascii_at(
        &buf,
        layout_usize(profile, "superblock_model_offset", 48),
        layout_usize(profile, "superblock_model_len", 16),
    );
    let serial = ascii_at(
        &buf,
        layout_usize(profile, "superblock_serial_offset", 64),
        layout_usize(profile, "superblock_serial_len", 32),
    );
    let volume_label = ascii_at(
        &buf,
        layout_usize(profile, "superblock_volume_label_offset", 96),
        layout_usize(profile, "superblock_volume_label_len", 16),
    );

    Ok(Some(Superblock {
        sector_size,
        block_size,
        total_blocks,
        video_start,
        index_offset,
        ctime_unix,
        model,
        serial,
        volume_label,
    }))
}

/// Derive [`StorageGeometry`] from the DHFS superblock.
///
/// Returns `Ok(None)` when the volume is not DHFS. Individual fields degrade to `None`
/// independently, so a damaged `index_offset` does not cost us the block size.
pub fn read_storage_geometry(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
) -> Result<Option<StorageGeometry>, ForensicError> {
    let sb = match read_superblock(reader, profile)? {
        Some(sb) => sb,
        None => return Ok(None),
    };

    let disk_len = reader.len();
    let mut notes: Vec<String> = Vec::new();

    // Plausibility filters. A value that fails one is reported as unknown, with the
    // reason surfaced, rather than silently propagated into range arithmetic.
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

    // The index region: [index_offset, index_offset + header + count*entry_size).
    // Its true length needs the entry count, so it is read here directly from the header.
    let index_magic = magic_bytes(profile, "didx_magic");
    let header_size = layout_u64(profile, "index_header_size", 16);
    let entry_size = layout_u64(profile, "index_entry_size", 32);
    let count_off = layout_u64(profile, "index_entry_count_offset", 4);

    let mut index_region: Option<Region> = None;
    let mut index_start_verified: Option<u64> = None;
    if let (Some(start), Some(magic)) = (sb.index_offset, index_magic.as_ref()) {
        let want = header_size.max(count_off.saturating_add(4));
        if start < disk_len && start.saturating_add(want) <= disk_len {
            if let Ok(hdr) = reader.read_exact_at(start, want as usize) {
                if hdr.starts_with(magic) {
                    index_start_verified = Some(start);
                    let count = u32_at(&hdr, count_off as usize).unwrap_or(0) as u64;
                    let declared_len =
                        header_size.saturating_add(count.saturating_mul(entry_size));
                    // Clamp to the evidence: a declared length must never describe bytes
                    // outside the image.
                    let clamped = declared_len.min(disk_len.saturating_sub(start));
                    index_region = Region::new(start, clamped).ok();
                } else {
                    notes.push(format!(
                        "superblock index_offset 0x{start:X} does not carry the index header magic"
                    ));
                }
            }
        } else {
            notes.push(format!(
                "superblock index_offset 0x{start:X} lies outside the {disk_len}-byte evidence"
            ));
        }
    }

    // The video payload region runs from the declared video start to the start of the
    // index when the index was verified, otherwise to end of evidence. It is only
    // claimed when the bounds are internally consistent — this region is what licenses
    // an orphan finding, so a sloppy bound here would be a forensic error.
    let video_region = match sb.video_start {
        Some(start) if start < disk_len => {
            let end = index_start_verified
                .filter(|ix| *ix > start && *ix <= disk_len)
                .unwrap_or(disk_len);
            if end > start {
                Region::new(start, end - start).ok()
            } else {
                notes.push(format!(
                    "declared video start 0x{start:X} is not before the index region; video region reported as unknown"
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
        .or(Some(layout_u64(profile, "superblock_size", 512)))
        .filter(|s| *s <= disk_len)
        .and_then(|s| Region::new(0, s).ok());

    let mut oem_fields: BTreeMap<String, String> = BTreeMap::new();
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
        "DHFS superblock verified at offset 0; video_region={}, index_region={}, block_size={}, sector_size={}",
        video_region.map(|r| r.to_string()).unwrap_or_else(|| "unknown".into()),
        index_region.map(|r| r.to_string()).unwrap_or_else(|| "unknown".into()),
        block_size.map(|b| b.to_string()).unwrap_or_else(|| "unknown".into()),
        sector_size.map(|s| s.to_string()).unwrap_or_else(|| "unknown".into()),
    );
    if !notes.is_empty() {
        reason.push_str("; ");
        reason.push_str(&notes.join("; "));
    }

    // Geometry with an unreadable video region cannot support claim reasoning, so it is
    // surfaced for review rather than passed off as a clean read.
    let evidence = if video_region.is_some() && notes.is_empty() {
        vs(ValidationStateKind::Pass, reason, "dhfs_storage_geometry", "superblock")
    } else {
        vs(ValidationStateKind::Review, reason, "dhfs_storage_geometry", "superblock")
    };

    Ok(Some(StorageGeometry {
        physical_size: disk_len,
        video_region,
        index_region,
        metadata_region,
        block_size,
        sector_size,
        // The DHFS structures this platform has evidence for carry no write cursor or
        // wrap flag. Reporting anything other than Unknown here would be fabrication.
        circular_buffer: CircularBufferEvidence::Unknown,
        oem_fields,
        evidence,
    }))
}

/// Read the DIDX recording index located via the superblock's `index_offset`.
///
/// Returns `Ok(None)` when the volume is not DHFS at all. When the volume is DHFS but
/// the index cannot be located or fully parsed, a `RecordingIndex` is still returned
/// with a non-authoritative [`IndexAuthority`], because "we looked and could not
/// establish it" is materially different information from "we never looked".
pub fn read_recording_index(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
) -> Result<Option<RecordingIndex>, ForensicError> {
    let sb = match read_superblock(reader, profile)? {
        Some(sb) => sb,
        None => return Ok(None),
    };

    let disk_len = reader.len();
    let header_size = layout_u64(profile, "index_header_size", 16);
    let entry_size = layout_u64(profile, "index_entry_size", 32);
    let count_off = layout_usize(profile, "index_entry_count_offset", 4);

    let not_found = |reason: String| -> Result<Option<RecordingIndex>, ForensicError> {
        Ok(Some(RecordingIndex {
            authority: IndexAuthority::NotFound {
                reason: reason.clone(),
            },
            recordings: Vec::new(),
            declared_entry_count: None,
            index_region: None,
            evidence: vs(ValidationStateKind::Review, reason, "dhfs_recording_index", "didx"),
        }))
    };

    let magic = match magic_bytes(profile, "didx_magic") {
        Some(m) if !m.is_empty() => m,
        _ => {
            return not_found(
                "profile declares no index header signature; DIDX entries cannot be verified"
                    .to_string(),
            )
        }
    };

    let start = match sb.index_offset {
        Some(s) => s,
        None => {
            return not_found(
                "DHFS superblock does not declare an index_offset; no recording index located"
                    .to_string(),
            )
        }
    };

    if start >= disk_len || start.saturating_add(header_size) > disk_len {
        return not_found(format!(
            "DHFS superblock declares index_offset 0x{start:X}, outside the {disk_len}-byte evidence"
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
    if !hdr.starts_with(&magic) {
        return not_found(format!(
            "no DIDX index header magic at the superblock-declared offset 0x{start:X}"
        ));
    }

    let declared = u32_at(&hdr, count_off).unwrap_or(0) as usize;
    let table_start = start.saturating_add(header_size);

    // Field offsets inside one 32-byte entry.
    let f_channel = layout_usize(profile, "index_entry_channel_offset", 0);
    let f_frame_type = layout_usize(profile, "index_entry_frame_type_offset", 1);
    let f_offset = layout_usize(profile, "index_entry_offset_offset", 4);
    let f_length = layout_usize(profile, "index_entry_length_offset", 12);
    let f_timestamp = layout_usize(profile, "index_entry_timestamp_offset", 20);
    let f_crc = layout_usize(profile, "index_entry_crc_offset", 28);

    let dhav_header = layout_u64(profile, "dhav_header_size", 64);
    let dhav_footer = layout_u64(profile, "dhav_footer_size", 4);

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

        let rec_offset = match u64_at(&e, f_offset) {
            Some(v) => v,
            None => {
                rejected.push(format!("entry {i}: offset field out of entry bounds"));
                continue;
            }
        };
        let rec_length = match u64_at(&e, f_length) {
            Some(v) => v,
            None => {
                rejected.push(format!("entry {i}: length field out of entry bounds"));
                continue;
            }
        };

        // An entry that describes bytes outside the evidence is not silently clamped
        // into something plausible — it is rejected and recorded, because a clamped
        // claim would misstate what the recorder actually said.
        if rec_length == 0 {
            rejected.push(format!(
                "entry {i}: declares a zero-length recording at 0x{rec_offset:X}"
            ));
            continue;
        }
        let rec_end = match rec_offset.checked_add(rec_length) {
            Some(v) => v,
            None => {
                rejected.push(format!(
                    "entry {i}: offset 0x{rec_offset:X} + length {rec_length} overflows u64"
                ));
                continue;
            }
        };
        if rec_end > disk_len {
            rejected.push(format!(
                "entry {i}: claims [0x{rec_offset:X}..0x{rec_end:X}) beyond the {disk_len}-byte evidence"
            ));
            continue;
        }

        let physical = Region::new(rec_offset, rec_length)?;

        // The elementary-stream payload sits between the DHAV header and footer. When
        // the packet is too small to hold both, no payload sub-range is claimed.
        let framing = dhav_header.saturating_add(dhav_footer);
        let payload_regions = if rec_length > framing {
            match Region::new(
                rec_offset.saturating_add(dhav_header),
                rec_length - framing,
            ) {
                Ok(r) => vec![r],
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };

        // Channel is stored 0-based on disk and reported 1-based, matching the
        // recorder's own CH01/CH02 labelling used elsewhere in the Dahua parser.
        let channel = e.get(f_channel).map(|b| *b as u32 + 1);
        let frame_type = e.get(f_frame_type).copied();
        // A zero timestamp is the absence of a timestamp in this structure, not 1970.
        let start_time_unix = u64_at(&e, f_timestamp)
            .filter(|t| *t > 0)
            .and_then(|t| i64::try_from(t).ok());
        let crc = u32_at(&e, f_crc);

        let mut oem_metadata: BTreeMap<String, String> = BTreeMap::new();
        oem_metadata.insert("index_entry_number".into(), i.to_string());
        oem_metadata.insert("index_entry_offset".into(), format!("0x{entry_at:X}"));
        if let Some(ft) = frame_type {
            oem_metadata.insert("dhav_frame_type".into(), format!("0x{ft:02X}"));
        }
        if let Some(c) = crc {
            oem_metadata.insert("declared_crc32".into(), format!("0x{c:08X}"));
        }

        recordings.push(IndexedRecording {
            recording_id: format!("didx#{i}"),
            channel,
            start_time_unix,
            // The DIDX entry carries no duration or end timestamp, so the end time is
            // genuinely unknown. Deriving it from the next entry would be an inference,
            // not a reading.
            end_time_unix: None,
            physical_regions: vec![physical],
            payload_regions,
            // The index entry carries no codec label; the DHAV packet header does, and
            // reading that is the container walker's job, not the index reader's.
            codec_hint: None,
            // DHFS as understood today has no per-entry allocation/tombstone field.
            allocation: AllocationEvidence::Unknown,
            oem_metadata,
            evidence: vs(ValidationStateKind::Pass, format!("DIDX entry {i} parsed: claims {physical}"), "dhfs_recording_index", "didx_entry"),
        });
    }

    let index_region = {
        let declared_len = header_size.saturating_add((declared as u64).saturating_mul(entry_size));
        let clamped = declared_len.min(disk_len.saturating_sub(start));
        Region::new(start, clamped).ok()
    };

    // Authority: only a fully parsed, non-empty index is a complete statement about
    // what the recorder currently claims. Anything else and absence proves nothing.
    let (authority, evidence) = if declared == 0 {
        let reason = format!(
            "DIDX header verified at 0x{start:X} but declares zero entries; the index makes no claim about any region"
        );
        (
            IndexAuthority::Partial {
                reason: reason.clone(),
            },
            vs(ValidationStateKind::Review, reason, "dhfs_recording_index", "didx"),
        )
    } else if !rejected.is_empty() || recordings.len() != declared {
        let reason = format!(
            "DIDX at 0x{start:X} declares {declared} entries but only {parsed} parsed cleanly; absence from a partial index is not evidence of deletion. Rejected: {detail}",
            parsed = recordings.len(),
            detail = rejected.join("; ")
        );
        (
            IndexAuthority::Partial {
                reason: reason.clone(),
            },
            vs(ValidationStateKind::Review, reason, "dhfs_recording_index", "didx"),
        )
    } else {
        // The index governs the video payload region it indexes. Falling back to the
        // span of its own claims keeps the governed region evidence-bounded when the
        // superblock's video region could not be established.
        let governs = match read_storage_geometry(reader, profile)?
            .and_then(|g| g.video_region)
        {
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
            "DIDX at 0x{start:X} fully parsed: {declared} entr{plural} claiming {bytes} bytes; authoritative over {governs}",
            plural = if declared == 1 { "y" } else { "ies" },
            bytes = recordings
                .iter()
                .fold(0u64, |a, r| a.saturating_add(r.claimed_bytes())),
        );
        (
            IndexAuthority::Authoritative { governs },
            vs(ValidationStateKind::Pass, reason, "dhfs_recording_index", "didx"),
        )
    };

    Ok(Some(RecordingIndex {
        authority,
        recordings,
        declared_entry_count: Some(declared),
        index_region,
        evidence,
    }))
}

/// Whether the bytes visible through `reader` are shaped like Dahua DHAV container
/// framing.
///
/// This is a **format** test, not an index lookup: it answers "do these bytes look like
/// our container?" and nothing more. It deliberately does not consult the index, does
/// not look at offset 0 of the volume, and must never be used to infer that a region is
/// an active recording.
///
/// The window handed in by the recovery engine is relative to the region being
/// examined, so only self-describing framing can be checked: the `DHAV` tag followed by
/// a declared packet length that is internally consistent.
pub fn window_looks_like_dhav(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
) -> Result<bool, ForensicError> {
    let tag = match magic_bytes(profile, "dhav_tag") {
        Some(t) if !t.is_empty() => t,
        _ => return Ok(false),
    };
    let header_size = layout_u64(profile, "dhav_header_size", 64);
    let footer_size = layout_u64(profile, "dhav_footer_size", 4);
    let min_len = header_size.saturating_add(footer_size);

    // Bounded probe: enough to find framing near the start of the window without
    // pulling a large region into memory.
    const PROBE_BYTES: u64 = 64 * 1024;
    let want = reader.len().min(PROBE_BYTES);
    if want < tag.len() as u64 {
        return Ok(false);
    }
    let mut buf = vec![0u8; want as usize];
    let n = match reader.read_at(0, &mut buf) {
        Ok(n) => n,
        Err(_) => return Ok(false),
    };
    let slice = &buf[..n];

    let length_field = layout_usize(profile, "dhav_packet_len_offset", 12);
    let mut i = 0usize;
    while i + tag.len() <= slice.len() {
        if &slice[i..i + tag.len()] == tag.as_slice() {
            // Verify the packet's own declared length is structurally plausible. A bare
            // 4-byte tag match in random data is not container framing.
            if let Some(declared) = u32_at(slice, i + length_field) {
                let declared = declared as u64;
                if declared >= min_len && declared <= 64 * 1024 * 1024 {
                    return Ok(true);
                }
            }
        }
        i += 1;
    }
    Ok(false)
}
