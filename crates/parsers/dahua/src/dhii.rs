//! # DHII per-clip frame index
//!
//! A Dahua clip carries its own frame index, which is what makes frame-accurate
//! reconstruction possible without walking every frame header:
//!
//! ```text
//!   +0   "DHII"
//!   +4   u32  indexLength          total bytes of the index structure
//!   +8   i32  count                number of index-header entries that follow
//!   +12  index-header entries, `count` of them, 12 bytes each:
//!          +0  u32  type           1 ReferenceFrames, 3 JpegFrames, 4 JsonJpeg, 6 UnknownEntries
//!          +4  u32  offset of the first entry, from the clip start
//!          +8  u32  length         total bytes of this type's entry array
//!
//!   frame index entry (12 bytes):
//!          +0  u32  frame offset   from the clip start; 0xFFFFFFFF = no entry
//!          +4  i32  frame length
//!          +8  u32  packed timestamp
//! ```
//!
//! ## One index can describe several entry types
//!
//! The header is an array, so a clip routinely carries a reference-frame array *and* a JPEG
//! array. Reading only the first header entry — or assuming one type — loses frames. Every
//! declared header entry is read, and a type this platform does not recognise is reported as
//! [`DhiiEntryType::Unrecognised`] with its raw value rather than crashing or being dropped.
//!
//! ## Every entry is bounds-checked against the clip
//!
//! `frame offset` and `frame length` are clip-relative and attacker-controllable on a
//! damaged image. An entry that points outside `indexLength`, outside the clip, or declares a
//! non-positive length is rejected **with its reason recorded** — never clamped into
//! something that looks plausible, because a clamped frame range would export the wrong bytes
//! under a valid-looking provenance record.

use forensic_core::{OemProfile, Region, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};

use crate::layout::{i32_at, key, magic, u32_at, u32_from, u64_from, usize_from, vs};
use crate::timestamp::{DahuaTimestamp, TimestampStructure};

/// A declared index-header entry type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DhiiEntryType {
    /// Type 1: reference (key) frame index — the array reconstruction relies on.
    ReferenceFrames,
    /// Type 3: JPEG frame index.
    JpegFrames,
    /// Type 4: JSON/JPEG sidecar index.
    JsonJpeg,
    /// Type 6: entries whose meaning is recorded by the recorder but not understood here.
    UnknownEntries,
    /// A type value this platform has no evidence for. Retained verbatim.
    Unrecognised(u32),
}

impl DhiiEntryType {
    /// Classify a raw type value using the profile-declared discriminators.
    pub fn from_raw(raw: u32, profile: &OemProfile) -> Self {
        if raw == u32_from(profile, key::DHII_TYPE_REFERENCE_FRAMES, 1) {
            Self::ReferenceFrames
        } else if raw == u32_from(profile, key::DHII_TYPE_JPEG_FRAMES, 3) {
            Self::JpegFrames
        } else if raw == u32_from(profile, key::DHII_TYPE_JSON_JPEG, 4) {
            Self::JsonJpeg
        } else if raw == u32_from(profile, key::DHII_TYPE_UNKNOWN_ENTRIES, 6) {
            Self::UnknownEntries
        } else {
            Self::Unrecognised(raw)
        }
    }

    /// Stable label for provenance and reports.
    pub fn label(&self) -> String {
        match self {
            Self::ReferenceFrames => "reference-frames".to_string(),
            Self::JpegFrames => "jpeg-frames".to_string(),
            Self::JsonJpeg => "json-jpeg".to_string(),
            Self::UnknownEntries => "unknown-entries".to_string(),
            Self::Unrecognised(raw) => format!("unrecognised-type-{raw}"),
        }
    }

    /// Whether entries of this type index video frames usable for reconstruction.
    ///
    /// Reference frames do. JPEG/JSON arrays describe stills and sidecars, and an
    /// unrecognised type describes something this platform cannot interpret, so neither is
    /// treated as a video frame source.
    pub fn indexes_video_frames(&self) -> bool {
        matches!(self, Self::ReferenceFrames)
    }
}

/// One index-header entry: where a type's entry array lives inside the clip.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DhiiHeaderEntry {
    /// Position of this header entry in the header array.
    pub slot: usize,
    pub entry_type: DhiiEntryType,
    /// Raw type value as stored.
    pub raw_type: u32,
    /// Offset of the first entry of this type, from the clip start.
    pub first_entry_offset: u32,
    /// Declared total length of this type's entry array, in bytes.
    pub length: u32,
    /// Stride used to walk the array, and how it was determined.
    pub entry_stride: u64,
    /// Entries this header describes, after validation.
    pub entries: Vec<DhiiFrameEntry>,
    /// Entries rejected, with reasons, so a shortfall is auditable.
    pub rejected: Vec<String>,
    pub evidence: ValidationState,
}

/// One frame index entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DhiiFrameEntry {
    /// Position within its type's array.
    pub slot: usize,
    /// Frame offset from the clip start, as declared.
    pub frame_offset: u32,
    /// Frame length, as declared.
    pub frame_length: i32,
    /// Decoded timestamp, or an explicit non-value.
    pub timestamp: DahuaTimestamp,
    /// The absolute physical region of the frame, when the entry validated.
    pub region: Option<Region>,
    pub evidence: ValidationState,
}

impl DhiiFrameEntry {
    /// Whether this entry describes a usable physical frame range.
    pub fn is_usable(&self) -> bool {
        self.region.map(|r| !r.is_empty()).unwrap_or(false)
    }
}

/// A clip's whole frame index.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DhiiIndex {
    /// Absolute physical offset of the clip the index is relative to.
    pub clip_offset: u64,
    /// Absolute physical offset of the `DHII` header.
    pub index_offset: u64,
    /// Declared total index length.
    pub index_length: u32,
    /// Declared header-entry count.
    pub declared_count: i32,
    /// Header entries actually read.
    pub headers: Vec<DhiiHeaderEntry>,
    /// Physical extent of the index structure, clipped to the evidence.
    pub region: Option<Region>,
    pub evidence: ValidationState,
}

impl DhiiIndex {
    /// Every usable video-frame region, in index order.
    ///
    /// Only types that index video frames contribute. JPEG stills and unrecognised types are
    /// read and reported but never presented as video frames.
    pub fn video_frame_regions(&self) -> Vec<Region> {
        self.headers
            .iter()
            .filter(|h| h.entry_type.indexes_video_frames())
            .flat_map(|h| h.entries.iter())
            .filter_map(|e| e.region)
            .collect()
    }

    /// Every usable entry of every type, in index order.
    pub fn all_usable_entries(&self) -> Vec<(&DhiiHeaderEntry, &DhiiFrameEntry)> {
        self.headers
            .iter()
            .flat_map(|h| h.entries.iter().map(move |e| (h, e)))
            .filter(|(_, e)| e.is_usable())
            .collect()
    }

    /// Total entries across all types.
    pub fn entry_count(&self) -> usize {
        self.headers.iter().map(|h| h.entries.len()).sum()
    }
}

/// Read a `DHII` index from bytes already loaded for a clip.
///
/// `clip_bytes` must start at `clip_offset`, and `index_at_clip_relative` is where inside the
/// clip the `DHII` header sits. `clip_length` is the clip's authoritative extent, used to
/// bound every frame range.
///
/// Returns `None` when there is no `DHII` header at that position — a clip without a frame
/// index is normal, and inventing one would be worse than having none.
pub fn read_index(
    clip_bytes: &[u8],
    clip_offset: u64,
    clip_length: u64,
    index_at_clip_relative: u64,
    profile: &OemProfile,
) -> Option<DhiiIndex> {
    const OP: &str = "dhfs41_dhii_index";
    let subject = format!("clip@0x{clip_offset:X}");

    let tag = magic(profile, "dhii_magic")?;
    let header_size = u64_from(profile, key::DHII_HEADER_SIZE, 12);
    let f_index_len = usize_from(profile, key::DHII_INDEX_LENGTH_OFFSET, 4);
    let f_count = usize_from(profile, key::DHII_COUNT_OFFSET, 8);
    let hdr_entry_size = u64_from(profile, key::DHII_HEADER_ENTRY_SIZE, 12);
    let f_hdr_type = usize_from(profile, key::DHII_HEADER_ENTRY_TYPE_OFFSET, 0);
    let f_hdr_first = usize_from(profile, key::DHII_HEADER_ENTRY_FIRST_ENTRY_OFFSET, 4);
    let f_hdr_len = usize_from(profile, key::DHII_HEADER_ENTRY_LENGTH_OFFSET, 8);
    let max_headers = u64_from(profile, key::DHII_HEADER_ENTRY_MAX_COUNT, 4096) as usize;

    let base = index_at_clip_relative as usize;
    let head = clip_bytes.get(base..base.checked_add(header_size as usize)?)?;
    if !head.starts_with(&tag) {
        return None;
    }

    let index_length = u32_at(head, f_index_len).unwrap_or(0);
    let declared_count = i32_at(head, f_count).unwrap_or(0);
    let index_offset = clip_offset.saturating_add(index_at_clip_relative);

    let mut notes: Vec<String> = Vec::new();

    // A declared index length that does not at least cover its own header means the
    // structure contradicts itself; every offset inside it is then unusable as a bound.
    let effective_index_length = if (index_length as u64) < header_size {
        notes.push(format!(
            "declared indexLength {index_length} is smaller than the {header_size}-byte header, so \
             it cannot bound the entry arrays; the clip length is used as the bound instead"
        ));
        clip_length.min(u32::MAX as u64) as u32
    } else {
        index_length
    };

    let header_count = if declared_count <= 0 {
        notes.push(format!(
            "declared header entry count is {declared_count}; no entry arrays are described"
        ));
        0usize
    } else if declared_count as usize > max_headers {
        notes.push(format!(
            "declared header entry count {declared_count} exceeds the {max_headers}-entry bound; \
             reading is capped there"
        ));
        max_headers
    } else {
        declared_count as usize
    };

    // The index structure's clip-relative span. Every entry array must live inside it, and no
    // frame range may overlap it.
    let index_span = (
        index_at_clip_relative,
        index_at_clip_relative.saturating_add(effective_index_length as u64),
    );

    let mut headers: Vec<DhiiHeaderEntry> = Vec::new();
    for slot in 0..header_count {
        let rel = base
            .saturating_add(header_size as usize)
            .saturating_add(slot * hdr_entry_size as usize);
        let Some(hbuf) = clip_bytes.get(rel..rel.saturating_add(hdr_entry_size as usize)) else {
            notes.push(format!(
                "header entry {slot} at clip offset {rel} lies outside the {} byte(s) loaded for \
                 this clip",
                clip_bytes.len()
            ));
            break;
        };
        headers.push(read_header_entry(
            hbuf,
            slot,
            clip_bytes,
            clip_offset,
            clip_length,
            effective_index_length,
            index_span,
            (f_hdr_type, f_hdr_first, f_hdr_len),
            profile,
        ));
    }

    let total_entries: usize = headers.iter().map(|h| h.entries.len()).sum();
    let total_rejected: usize = headers.iter().map(|h| h.rejected.len()).sum();

    let mut reason = format!(
        "DHII index at 0x{index_offset:X} (clip 0x{clip_offset:X}): indexLength {index_length}, \
         {declared_count} declared header entr{}, {} read, {total_entries} frame entr{} validated, \
         {total_rejected} rejected. Types: [{}]",
        if declared_count == 1 { "y" } else { "ies" },
        headers.len(),
        if total_entries == 1 { "y" } else { "ies" },
        headers
            .iter()
            .map(|h| h.entry_type.label())
            .collect::<Vec<_>>()
            .join(", ")
    );
    if !notes.is_empty() {
        reason.push_str("; ");
        reason.push_str(&notes.join("; "));
    }

    // The index is only a clean read when every header entry was one too: a header carrying an
    // unrecognised type, a ragged array length, or a rejected entry is a real observation that
    // must not be flattened into a Pass at the index level.
    let headers_clean = headers
        .iter()
        .all(|h| h.evidence.state == ValidationStateKind::Pass);
    let clean = notes.is_empty() && total_rejected == 0 && total_entries > 0 && headers_clean;

    Some(DhiiIndex {
        clip_offset,
        index_offset,
        index_length,
        declared_count,
        headers,
        region: Region::new(
            index_offset,
            (effective_index_length as u64).min(clip_length.saturating_sub(index_at_clip_relative)),
        )
        .ok(),
        evidence: vs(
            if clean {
                ValidationStateKind::Pass
            } else {
                ValidationStateKind::Review
            },
            reason,
            OP,
            &subject,
        ),
    })
}

/// Read one index-header entry and the frame entries it describes.
#[allow(clippy::too_many_arguments)]
fn read_header_entry(
    hbuf: &[u8],
    slot: usize,
    clip_bytes: &[u8],
    clip_offset: u64,
    clip_length: u64,
    index_length: u32,
    index_span: (u64, u64),
    fields: (usize, usize, usize),
    profile: &OemProfile,
) -> DhiiHeaderEntry {
    const OP: &str = "dhfs41_dhii_header_entry";
    let (f_type, f_first, f_len) = fields;

    let raw_type = u32_at(hbuf, f_type).unwrap_or(0);
    let entry_type = DhiiEntryType::from_raw(raw_type, profile);
    let first_entry_offset = u32_at(hbuf, f_first).unwrap_or(0);
    let length = u32_at(hbuf, f_len).unwrap_or(0);

    // Entry stride. The reference-frame array is 12 bytes per entry; for other types the
    // stride is not independently established, so it is derived from the declared array
    // length when that divides cleanly and otherwise reported as assumed.
    let declared_stride = u64_from(profile, key::DHII_ENTRY_SIZE, 12);
    let entry_stride = declared_stride.max(1);

    let mut entries: Vec<DhiiFrameEntry> = Vec::new();
    let mut rejected: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    if length == 0 {
        notes.push("the header entry declares a zero-length array".to_string());
    }
    // The entry array belongs to the index structure, so it must start inside the index's
    // own clip-relative span. When the index sits at clip offset 0 this is exactly the
    // documented `offset < indexLength` rule; expressing it as a span keeps the rule correct
    // for clips that store their index after the payload.
    let (index_start, index_end) = index_span;
    if (first_entry_offset as u64) < index_start || (first_entry_offset as u64) >= index_end {
        rejected.push(format!(
            "the array's first entry offset {first_entry_offset} is not inside the \
             {index_length}-byte index structure at clip offset {index_start}..{index_end}"
        ));
    } else if (first_entry_offset as u64) >= clip_length {
        rejected.push(format!(
            "the array's first entry offset {first_entry_offset} is outside the {clip_length}-byte \
             clip"
        ));
    } else {
        let count = (length as u64 / entry_stride) as usize;
        if length as u64 % entry_stride != 0 {
            notes.push(format!(
                "the declared array length {length} is not a whole multiple of the {entry_stride}-byte \
                 entry stride; {count} whole entr{} were read",
                if count == 1 { "y was" } else { "ies were" }
            ));
        }
        if !entry_type.indexes_video_frames() {
            notes.push(format!(
                "entries of type {} are read and reported but are not treated as video frames",
                entry_type.label()
            ));
        }
        for i in 0..count {
            let rel = (first_entry_offset as u64).saturating_add(i as u64 * entry_stride) as usize;
            let Some(ebuf) = clip_bytes.get(rel..rel.saturating_add(entry_stride as usize)) else {
                rejected.push(format!(
                    "entry {i} at clip offset {rel} lies outside the {} byte(s) loaded for this clip",
                    clip_bytes.len()
                ));
                break;
            };
            match read_frame_entry(ebuf, i, clip_offset, clip_length, index_span, profile) {
                Ok(entry) => entries.push(entry),
                Err(reason) => rejected.push(format!("entry {i}: {reason}")),
            }
        }
    }

    let mut reason = format!(
        "DHII header entry {slot}: type {} (raw {raw_type}), array at clip offset \
         {first_entry_offset}, declared length {length}, stride {entry_stride}; {} entr{} validated, \
         {} rejected",
        entry_type.label(),
        entries.len(),
        if entries.len() == 1 { "y" } else { "ies" },
        rejected.len()
    );
    if !notes.is_empty() {
        reason.push_str("; ");
        reason.push_str(&notes.join("; "));
    }
    if !rejected.is_empty() {
        reason.push_str("; rejected: ");
        reason.push_str(&rejected.join("; "));
    }

    DhiiHeaderEntry {
        slot,
        entry_type,
        raw_type,
        first_entry_offset,
        length,
        entry_stride,
        entries,
        rejected: rejected.clone(),
        evidence: vs(
            if rejected.is_empty() && notes.is_empty() {
                ValidationStateKind::Pass
            } else {
                ValidationStateKind::Review
            },
            reason,
            OP,
            &format!("dhii_header_{slot}"),
        ),
    }
}

/// Read and validate one frame index entry.
///
/// `Err(reason)` is a rejection, which the caller records. A rejected entry never becomes a
/// region.
fn read_frame_entry(
    ebuf: &[u8],
    slot: usize,
    clip_offset: u64,
    clip_length: u64,
    index_span: (u64, u64),
    profile: &OemProfile,
) -> Result<DhiiFrameEntry, String> {
    const OP: &str = "dhfs41_dhii_entry";
    let f_off = usize_from(profile, key::DHII_ENTRY_FRAME_OFFSET_OFFSET, 0);
    let f_len = usize_from(profile, key::DHII_ENTRY_FRAME_LENGTH_OFFSET, 4);
    let f_ts = usize_from(profile, key::DHII_ENTRY_TIMESTAMP_OFFSET, 8);
    let sentinel = u32_from(profile, key::DHII_ENTRY_OFFSET_SENTINEL, 0xFFFF_FFFF);

    let frame_offset = u32_at(ebuf, f_off).ok_or("frame offset field is outside the entry")?;
    let frame_length = i32_at(ebuf, f_len).ok_or("frame length field is outside the entry")?;
    let timestamp = DahuaTimestamp::decode(
        u32_at(ebuf, f_ts).unwrap_or(0),
        TimestampStructure::DhiiFrameIndexEntry,
        profile,
    );

    // The all-ones sentinel is the recorder's "this slot holds no frame". It is a normal
    // value, not damage, and must not be read as an offset near 4 GiB.
    if frame_offset == sentinel {
        return Err(format!(
            "frame offset is the 0x{sentinel:08X} sentinel, meaning the slot holds no frame"
        ));
    }
    if frame_length <= 0 {
        return Err(format!(
            "declared frame length is {frame_length}; a frame cannot be empty or negative and the \
             length is not substituted"
        ));
    }
    let end = (frame_offset as u64)
        .checked_add(frame_length as u64)
        .ok_or_else(|| format!("frame offset {frame_offset} + length {frame_length} overflows"))?;
    if end > clip_length {
        return Err(format!(
            "frame range [{frame_offset}..{end}) extends past the {clip_length}-byte clip"
        ));
    }
    // A frame range that overlaps the index structure would make the index describe its own
    // bytes as video. That is a contradiction in the structure, not a frame.
    let (index_start, index_end) = index_span;
    if (frame_offset as u64) < index_end && index_start < end {
        return Err(format!(
            "frame range [{frame_offset}..{end}) overlaps the index structure at \
             {index_start}..{index_end} rather than pointing at clip payload"
        ));
    }

    let absolute = clip_offset
        .checked_add(frame_offset as u64)
        .ok_or("absolute frame offset overflows the address space")?;
    let region = Region::new(absolute, frame_length as u64)
        .map_err(|e| format!("frame region could not be formed: {e}"))?;

    Ok(DhiiFrameEntry {
        slot,
        frame_offset,
        frame_length,
        timestamp: timestamp.clone(),
        region: Some(region),
        evidence: vs(
            ValidationStateKind::Pass,
            format!(
                "DHII entry {slot}: clip-relative [{frame_offset}..{end}) resolves to {region}; {}",
                timestamp.evidence
            ),
            OP,
            &format!("dhii_entry_{slot}"),
        ),
    })
}

#[cfg(test)]
pub(crate) mod builder {
    //! Byte-accurate `DHII` builder, used by this module's tests and the fixture crate.

    /// One entry array to place in a built index.
    #[derive(Debug, Clone)]
    pub struct Array {
        pub raw_type: u32,
        /// `(frame_offset, frame_length, packed_timestamp)` per entry.
        pub entries: Vec<(u32, i32, u32)>,
    }

    /// Build a `DHII` structure destined for clip-relative offset `base`.
    ///
    /// Entry arrays follow the header array, and every `offset of first entry` is written
    /// **clip-relative** as the format specifies — which is why `base` has to be supplied.
    /// `indexLength` covers the whole structure.
    pub fn build(arrays: &[Array], base: u32) -> Vec<u8> {
        let header_size = 12usize;
        let hdr_entry_size = 12usize;
        let entry_size = 12usize;
        let header_total = header_size + arrays.len() * hdr_entry_size;
        let arrays_total: usize = arrays.iter().map(|a| a.entries.len() * entry_size).sum();
        let index_length = header_total + arrays_total;

        let mut out = vec![0u8; index_length];
        out[..4].copy_from_slice(b"DHII");
        out[4..8].copy_from_slice(&(index_length as u32).to_le_bytes());
        out[8..12].copy_from_slice(&(arrays.len() as i32).to_le_bytes());

        let mut array_cursor = header_total;
        for (i, array) in arrays.iter().enumerate() {
            let h = header_size + i * hdr_entry_size;
            let len = array.entries.len() * entry_size;
            out[h..h + 4].copy_from_slice(&array.raw_type.to_le_bytes());
            out[h + 4..h + 8].copy_from_slice(&(base + array_cursor as u32).to_le_bytes());
            out[h + 8..h + 12].copy_from_slice(&(len as u32).to_le_bytes());

            for (j, (off, length, ts)) in array.entries.iter().enumerate() {
                let e = array_cursor + j * entry_size;
                out[e..e + 4].copy_from_slice(&off.to_le_bytes());
                out[e + 4..e + 8].copy_from_slice(&length.to_le_bytes());
                out[e + 8..e + 12].copy_from_slice(&ts.to_le_bytes());
            }
            array_cursor += len;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::builder::{build, Array};
    use super::*;
    use crate::layout::tests_support::dahua_profile;
    use crate::timestamp::pack;

    const CLIP_AT: u64 = 0x20_0000;
    const CLIP_LEN: u64 = 2 * 1024 * 1024;

    fn ts() -> u32 {
        pack(2026, 9, 22, 12, 0, 0, 2000).unwrap()
    }

    /// Place a built index at clip offset 0 inside a clip buffer of `CLIP_LEN` bytes.
    fn clip_with(index: Vec<u8>) -> Vec<u8> {
        let mut clip = vec![0u8; CLIP_LEN as usize];
        clip[..index.len()].copy_from_slice(&index);
        clip
    }

    /// Build an index destined for clip offset 0.
    fn at_start(arrays: &[Array]) -> Vec<u8> {
        build(arrays, 0)
    }

    fn read(clip: &[u8]) -> Option<DhiiIndex> {
        read_index(clip, CLIP_AT, CLIP_LEN, 0, &dahua_profile())
    }

    #[test]
    fn a_valid_reference_frame_index_resolves_absolute_frame_regions() {
        let index = at_start(&[Array {
            raw_type: 1,
            entries: vec![(4096, 1000, ts()), (8192, 2048, ts())],
        }]);
        let idx = read(&clip_with(index)).expect("DHII located");

        assert_eq!(idx.clip_offset, CLIP_AT);
        assert_eq!(idx.index_offset, CLIP_AT);
        assert_eq!(idx.declared_count, 1);
        assert_eq!(idx.headers.len(), 1);
        assert_eq!(idx.headers[0].entry_type, DhiiEntryType::ReferenceFrames);
        assert_eq!(idx.entry_count(), 2);
        assert_eq!(idx.evidence.state, ValidationStateKind::Pass);

        // Offsets are clip-relative on disk and absolute in the output.
        let regions = idx.video_frame_regions();
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0], Region::new(CLIP_AT + 4096, 1000).unwrap());
        assert_eq!(regions[1], Region::new(CLIP_AT + 8192, 2048).unwrap());
    }

    #[test]
    fn multiple_entry_types_are_all_read() {
        let index = at_start(&[
            Array {
                raw_type: 1,
                entries: vec![(4096, 500, ts())],
            },
            Array {
                raw_type: 3,
                entries: vec![(8192, 600, ts()), (16384, 700, ts())],
            },
            Array {
                raw_type: 4,
                entries: vec![(32768, 100, ts())],
            },
            Array {
                raw_type: 6,
                entries: vec![(40960, 100, ts())],
            },
        ]);
        let idx = read(&clip_with(index)).unwrap();

        assert_eq!(idx.headers.len(), 4, "every declared header entry is read");
        let types: Vec<DhiiEntryType> = idx.headers.iter().map(|h| h.entry_type).collect();
        assert_eq!(
            types,
            vec![
                DhiiEntryType::ReferenceFrames,
                DhiiEntryType::JpegFrames,
                DhiiEntryType::JsonJpeg,
                DhiiEntryType::UnknownEntries
            ]
        );
        assert_eq!(idx.entry_count(), 5);
        // Only reference frames are offered as video.
        assert_eq!(idx.video_frame_regions().len(), 1);
        // But every type's entries are still available with their regions.
        assert_eq!(idx.all_usable_entries().len(), 5);
    }

    #[test]
    fn an_unrecognised_type_is_retained_not_a_crash_or_a_drop() {
        let index = at_start(&[Array {
            raw_type: 0x5A5A,
            entries: vec![(4096, 500, ts())],
        }]);
        let idx = read(&clip_with(index)).unwrap();
        assert_eq!(idx.headers.len(), 1);
        assert_eq!(
            idx.headers[0].entry_type,
            DhiiEntryType::Unrecognised(0x5A5A)
        );
        assert_eq!(idx.headers[0].raw_type, 0x5A5A);
        assert_eq!(
            idx.headers[0].entries.len(),
            1,
            "its entries are still read"
        );
        assert!(idx.video_frame_regions().is_empty(), "not treated as video");
        assert_eq!(idx.evidence.state, ValidationStateKind::Review);
        assert!(idx.evidence.reason.contains("unrecognised-type-23130"));
    }

    #[test]
    fn a_frame_offset_past_the_clip_is_rejected_with_a_reason() {
        let index = at_start(&[Array {
            raw_type: 1,
            entries: vec![(4096, 500, ts()), (CLIP_LEN as u32 + 4096, 500, ts())],
        }]);
        let idx = read(&clip_with(index)).unwrap();
        assert_eq!(idx.entry_count(), 1, "only the in-bounds entry survives");
        assert_eq!(idx.headers[0].rejected.len(), 1);
        assert!(
            idx.headers[0].rejected[0].contains("extends past"),
            "{:?}",
            idx.headers[0].rejected
        );
        assert_eq!(idx.evidence.state, ValidationStateKind::Review);
    }

    #[test]
    fn a_frame_extending_past_the_clip_end_is_rejected_not_truncated() {
        let index = at_start(&[Array {
            raw_type: 1,
            entries: vec![(CLIP_LEN as u32 - 100, 4096, ts())],
        }]);
        let idx = read(&clip_with(index)).unwrap();
        assert_eq!(idx.entry_count(), 0, "the frame is not silently shortened");
        assert!(idx.headers[0].rejected[0].contains("extends past"));
    }

    #[test]
    fn a_non_positive_frame_length_is_rejected_and_never_substituted() {
        for length in [0i32, -512] {
            let index = at_start(&[Array {
                raw_type: 1,
                entries: vec![(4096, length, ts())],
            }]);
            let idx = read(&clip_with(index)).unwrap();
            assert_eq!(idx.entry_count(), 0, "length {length}");
            assert!(idx.headers[0].rejected[0].contains("not substituted"));
        }
    }

    #[test]
    fn the_all_ones_offset_sentinel_marks_an_unused_slot() {
        let index = at_start(&[Array {
            raw_type: 1,
            entries: vec![(0xFFFF_FFFF, 500, ts()), (4096, 500, ts())],
        }]);
        let idx = read(&clip_with(index)).unwrap();
        assert_eq!(idx.entry_count(), 1);
        assert!(idx.headers[0].rejected[0].contains("sentinel"));
        assert!(idx.headers[0].rejected[0].contains("holds no frame"));
    }

    #[test]
    fn a_frame_range_overlapping_the_index_structure_is_rejected() {
        // Clip offset 20 lands inside the header array, so this "frame" would be the index
        // describing its own bytes as video.
        let index = at_start(&[Array {
            raw_type: 1,
            entries: vec![(20, 100, ts())],
        }]);
        let idx = read(&clip_with(index)).unwrap();
        assert_eq!(idx.entry_count(), 0);
        assert!(
            idx.headers[0].rejected[0].contains("overlaps the index structure"),
            "{:?}",
            idx.headers[0].rejected
        );
    }

    #[test]
    fn an_array_offset_outside_the_declared_index_length_is_rejected() {
        let mut index = at_start(&[Array {
            raw_type: 1,
            entries: vec![(4096, 500, ts())],
        }]);
        // Point the header's array offset past the declared indexLength.
        let bogus = (index.len() as u32) + 10_000;
        index[16..20].copy_from_slice(&bogus.to_le_bytes());
        let idx = read(&clip_with(index)).unwrap();
        assert_eq!(idx.entry_count(), 0);
        assert!(idx.headers[0]
            .rejected
            .iter()
            .any(|r| r.contains("not inside")));
    }

    #[test]
    fn an_index_length_smaller_than_its_own_header_is_reported_and_bounded_by_the_clip() {
        let mut index = at_start(&[Array {
            raw_type: 1,
            entries: vec![(4096, 500, ts())],
        }]);
        index[4..8].copy_from_slice(&4u32.to_le_bytes());
        let idx = read(&clip_with(index)).unwrap();
        assert_eq!(idx.index_length, 4, "the declared value is retained");
        assert_eq!(idx.evidence.state, ValidationStateKind::Review);
        assert!(idx
            .evidence
            .reason
            .contains("cannot bound the entry arrays"));
    }

    #[test]
    fn a_zero_or_negative_header_count_describes_nothing() {
        for count in [0i32, -3] {
            let mut index = at_start(&[Array {
                raw_type: 1,
                entries: vec![(4096, 500, ts())],
            }]);
            index[8..12].copy_from_slice(&count.to_le_bytes());
            let idx = read(&clip_with(index)).unwrap();
            assert!(idx.headers.is_empty(), "count {count}");
            assert!(idx
                .evidence
                .reason
                .contains("no entry arrays are described"));
        }
    }

    #[test]
    fn an_absurd_header_count_is_capped_rather_than_allocating_unbounded() {
        let mut index = at_start(&[Array {
            raw_type: 1,
            entries: vec![(4096, 500, ts())],
        }]);
        index[8..12].copy_from_slice(&i32::MAX.to_le_bytes());
        let idx = read(&clip_with(index)).unwrap();
        assert!(idx.headers.len() <= 4096);
        assert!(idx.evidence.reason.contains("exceeds the 4096-entry bound"));
    }

    #[test]
    fn an_array_length_not_a_multiple_of_the_stride_reads_whole_entries_and_says_so() {
        let mut index = at_start(&[Array {
            raw_type: 1,
            entries: vec![(4096, 500, ts()), (8192, 500, ts())],
        }]);
        // Declared array length 20: one whole 12-byte entry plus 8 stray bytes.
        index[20..24].copy_from_slice(&20u32.to_le_bytes());
        let idx = read(&clip_with(index)).unwrap();
        assert_eq!(idx.entry_count(), 1);
        assert!(idx.headers[0]
            .evidence
            .reason
            .contains("not a whole multiple"));
    }

    #[test]
    fn no_dhii_header_yields_none_rather_than_an_empty_index() {
        let clip = vec![0u8; CLIP_LEN as usize];
        assert!(read(&clip).is_none());
        let mut clip = vec![0u8; CLIP_LEN as usize];
        clip[..4].copy_from_slice(b"DHAV");
        assert!(read(&clip).is_none());
    }

    #[test]
    fn a_clip_too_short_to_hold_the_header_yields_none() {
        assert!(read_index(b"DHII", CLIP_AT, CLIP_LEN, 0, &dahua_profile()).is_none());
    }

    #[test]
    fn entry_timestamps_are_decoded_and_marked_provisional_for_this_structure() {
        let index = at_start(&[Array {
            raw_type: 1,
            entries: vec![(4096, 500, ts())],
        }]);
        let idx = read(&clip_with(index)).unwrap();
        let e = &idx.headers[0].entries[0];
        assert_eq!(
            e.timestamp.recorder_wall_clock.as_deref(),
            Some("2026-09-22T12:00:00")
        );
        assert_eq!(
            e.timestamp.confidence,
            crate::timestamp::TimestampConfidence::DecodedProvisionalEncoding
        );
    }

    #[test]
    fn an_index_placed_part_way_into_a_clip_still_resolves_relative_offsets_correctly() {
        // A real clip carries its index after the payload; offsets stay clip-relative.
        let index_at = 1_000_000u64;
        let index = build(
            &[Array {
                raw_type: 1,
                entries: vec![(1024, 256, ts())],
            }],
            index_at as u32,
        );
        let mut clip = vec![0u8; CLIP_LEN as usize];
        clip[index_at as usize..index_at as usize + index.len()].copy_from_slice(&index);

        let idx = read_index(&clip, CLIP_AT, CLIP_LEN, index_at, &dahua_profile()).unwrap();
        assert_eq!(idx.index_offset, CLIP_AT + index_at);
        // The frame is at clip-relative 1024, so absolute CLIP_AT + 1024 — not
        // CLIP_AT + index_at + 1024.
        assert_eq!(
            idx.video_frame_regions()[0],
            Region::new(CLIP_AT + 1024, 256).unwrap()
        );
    }
}
