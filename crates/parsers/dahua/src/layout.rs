//! # Profile layout accessors and little-endian field readers
//!
//! Every Dahua structure offset, stride, size, mask and sentinel used by this crate is
//! read from the versioned profile's `[layout]` table through this module. Nothing
//! OEM-factual is a source constant — the fallbacks below exist only so an older profile
//! revision degrades to the documented DHFS 4.1 value instead of failing the whole run,
//! and each one is recorded in the profile as well.
//!
//! The byte readers are total: an out-of-range field yields `None`, never a panic and
//! never a silently zero value. Evidence is adversarial input, so "the field is not
//! there" has to be representable.

use forensic_core::{OemProfile, ValidationState, ValidationStateKind};

/// Named `[layout]` keys, so a typo is a compile error rather than a silent fallback.
///
/// Grouped in the same order as the profile file to keep the two readable side by side.
pub mod key {
    // Volume / sector geometry.
    pub const SUPERBLOCK_SIZE: &str = "superblock_size";
    pub const DHFS41_MAGIC_LENGTH: &str = "dhfs41_magic_length";
    pub const SECTOR_SIZE: &str = "sector_size";
    pub const FILESYSTEM_DISK_OFFSET: &str = "filesystem_disk_offset";

    // Partition table.
    pub const PT_PRIMARY_OFFSET: &str = "partition_table_primary_offset";
    pub const PT_SECONDARY_OFFSET_A: &str = "partition_table_secondary_offset_a";
    pub const PT_SECONDARY_OFFSET_B: &str = "partition_table_secondary_offset_b";
    pub const PT_IDENTIFIER_OFFSET: &str = "partition_table_identifier_offset";
    pub const PT_IDENTIFIER_SIZE: &str = "partition_table_identifier_size";
    pub const PT_SIZE: &str = "partition_table_size";
    pub const PT_MAX_PARTITIONS: &str = "partition_table_max_partitions";
    pub const PT_ENTRY_STRIDE: &str = "partition_entry_stride";
    pub const PT_ENTRY_BASE_OFFSET: &str = "partition_entry_base_offset";
    pub const PT_ENTRY_INFO_SECTOR_OFFSET: &str = "partition_entry_info_sector_offset";
    pub const PT_ENTRY_START_SECTOR_OFFSET: &str = "partition_entry_start_sector_offset";

    // Partition information.
    pub const PI_SIZE: &str = "partition_info_size";
    pub const PI_INDEX_START_SECTOR_OFFSET: &str = "partition_info_index_start_sector_offset";
    pub const PI_VIDEO_START_SECTOR_OFFSET: &str = "partition_info_video_start_sector_offset";
    pub const PI_BLOCK_COUNT_OFFSET: &str = "partition_info_block_count_offset";

    // Block table.
    pub const BT_ENTRY_SIZE: &str = "block_table_entry_size";
    pub const VIDEO_BLOCK_SIZE: &str = "video_block_size";
    pub const BE_TYPE_OFFSET: &str = "block_entry_type_offset";
    pub const BE_LEGACY_CHANNEL_OFFSET: &str = "block_entry_legacy_channel_offset";
    pub const BE_START_TIME_OFFSET: &str = "block_entry_start_time_offset";
    pub const BE_END_TIME_OFFSET: &str = "block_entry_end_time_offset";
    pub const BE_NEXT_BLOCK_OFFSET: &str = "block_entry_next_block_offset";
    pub const BE_SECTOR_COUNT_OFFSET: &str = "block_entry_sector_count_offset";
    pub const BE_PREVIOUS_BLOCK_OFFSET: &str = "block_entry_previous_block_offset";
    pub const BE_FIRST_BLOCK_OFFSET: &str = "block_entry_first_block_offset";
    pub const BE_EXT_CHANNEL_FLAG_OFFSET: &str = "block_entry_extended_channel_flag_offset";
    pub const BE_EXT_CHANNEL_OFFSET: &str = "block_entry_extended_channel_offset";
    pub const BE_TYPE_EMPTY_PRIMARY: &str = "block_entry_type_empty_primary";
    pub const BE_TYPE_EMPTY_SECONDARY: &str = "block_entry_type_empty_secondary";
    pub const BE_LEGACY_CHANNEL_MASK: &str = "block_entry_legacy_channel_mask";
    pub const BE_EXT_CHANNEL_MASK: &str = "block_entry_extended_channel_mask";
    pub const BE_EXT_CHANNEL_FLAG_MASK: &str = "block_entry_extended_channel_flag_mask";
    pub const BLOCK_CHAIN_MAX_LENGTH: &str = "block_chain_max_length";

    // DHII.
    pub const DHII_HEADER_SIZE: &str = "dhii_header_size";
    pub const DHII_INDEX_LENGTH_OFFSET: &str = "dhii_index_length_offset";
    pub const DHII_COUNT_OFFSET: &str = "dhii_count_offset";
    pub const DHII_HEADER_ENTRY_SIZE: &str = "dhii_header_entry_size";
    pub const DHII_HEADER_ENTRY_TYPE_OFFSET: &str = "dhii_header_entry_type_offset";
    pub const DHII_HEADER_ENTRY_FIRST_ENTRY_OFFSET: &str = "dhii_header_entry_first_entry_offset";
    pub const DHII_HEADER_ENTRY_LENGTH_OFFSET: &str = "dhii_header_entry_length_offset";
    pub const DHII_HEADER_ENTRY_MAX_COUNT: &str = "dhii_header_entry_max_count";
    pub const DHII_ENTRY_SIZE: &str = "dhii_entry_size";
    pub const DHII_ENTRY_FRAME_OFFSET_OFFSET: &str = "dhii_entry_frame_offset_offset";
    pub const DHII_ENTRY_FRAME_LENGTH_OFFSET: &str = "dhii_entry_frame_length_offset";
    pub const DHII_ENTRY_TIMESTAMP_OFFSET: &str = "dhii_entry_timestamp_offset";
    pub const DHII_ENTRY_OFFSET_SENTINEL: &str = "dhii_entry_offset_sentinel";
    pub const DHII_TYPE_REFERENCE_FRAMES: &str = "dhii_entry_type_reference_frames";
    pub const DHII_TYPE_JPEG_FRAMES: &str = "dhii_entry_type_jpeg_frames";
    pub const DHII_TYPE_JSON_JPEG: &str = "dhii_entry_type_json_jpeg";
    pub const DHII_TYPE_UNKNOWN_ENTRIES: &str = "dhii_entry_type_unknown_entries";

    // DHAV framing.
    pub const DHAV_FIXED_HEADER_SIZE: &str = "dhav_fixed_header_size";
    pub const DHAV_FRAME_TYPE_OFFSET: &str = "dhav_frame_type_offset";
    pub const DHAV_SUBTYPE_OFFSET: &str = "dhav_subtype_offset";
    pub const DHAV_CHANNEL_OFFSET: &str = "dhav_channel_offset";
    pub const DHAV_CHANNEL_FIELD_SIZE: &str = "dhav_channel_field_size";
    pub const DHAV_FRAME_NUMBER_OFFSET: &str = "dhav_frame_number_offset";
    pub const DHAV_TOTAL_LENGTH_OFFSET: &str = "dhav_total_length_offset";
    pub const DHAV_PACKED_TIMESTAMP_OFFSET: &str = "dhav_packed_timestamp_offset";
    pub const DHAV_SUB_TIMESTAMP_OFFSET: &str = "dhav_sub_timestamp_offset";
    pub const DHAV_EXTRA_HEADER_LENGTH_OFFSET: &str = "dhav_extra_header_length_offset";
    pub const DHAV_CHECKSUM_OFFSET: &str = "dhav_checksum_offset";
    pub const DHAV_TRAILER_SIZE: &str = "dhav_trailer_size";
    pub const DHAV_FOOTER_SIZE: &str = "dhav_footer_size";
    pub const DHAV_MIN_TOTAL_LENGTH: &str = "dhav_min_total_length";
    pub const DHAV_MAX_TOTAL_LENGTH: &str = "dhav_max_total_length";
    pub const DHAV_TYPE_VIDEO_KEY: &str = "dhav_frame_type_video_key";
    pub const DHAV_TYPE_VIDEO_DELTA: &str = "dhav_frame_type_video_delta";
    pub const DHAV_TYPE_AUDIO: &str = "dhav_frame_type_audio";
    pub const DHAV_TYPE_INFO: &str = "dhav_frame_type_info";
    pub const DHAV_EXT_TAG_RESOLUTION_SCALED: &str = "dhav_ext_tag_resolution_scaled";
    pub const DHAV_EXT_TAG_CODEC: &str = "dhav_ext_tag_codec";
    pub const DHAV_EXT_TAG_RESOLUTION_EXACT: &str = "dhav_ext_tag_resolution_exact";
    pub const DHAV_EXT_TAG_AUDIO: &str = "dhav_ext_tag_audio";
    pub const DHAV_EXT_RECORD_SIZE_SHORT: &str = "dhav_ext_record_size_short";
    pub const DHAV_EXT_RECORD_SIZE_LONG: &str = "dhav_ext_record_size_long";
    pub const DHAV_CODEC_MPEG4: &str = "dhav_codec_mpeg4";
    pub const DHAV_CODEC_MJPEG: &str = "dhav_codec_mjpeg";
    pub const DHAV_CODEC_H264_A: &str = "dhav_codec_h264_a";
    pub const DHAV_CODEC_H264_B: &str = "dhav_codec_h264_b";
    pub const DHAV_CODEC_H264_C: &str = "dhav_codec_h264_c";
    pub const DHAV_CODEC_H265: &str = "dhav_codec_h265";

    // Packed timestamp encoding.
    pub const TS_BASE_YEAR: &str = "dahua_timestamp_base_year";
    pub const TS_SECOND_SHIFT: &str = "dahua_timestamp_second_shift";
    pub const TS_SECOND_MASK: &str = "dahua_timestamp_second_mask";
    pub const TS_MINUTE_SHIFT: &str = "dahua_timestamp_minute_shift";
    pub const TS_MINUTE_MASK: &str = "dahua_timestamp_minute_mask";
    pub const TS_HOUR_SHIFT: &str = "dahua_timestamp_hour_shift";
    pub const TS_HOUR_MASK: &str = "dahua_timestamp_hour_mask";
    pub const TS_DAY_SHIFT: &str = "dahua_timestamp_day_shift";
    pub const TS_DAY_MASK: &str = "dahua_timestamp_day_mask";
    pub const TS_MONTH_SHIFT: &str = "dahua_timestamp_month_shift";
    pub const TS_MONTH_MASK: &str = "dahua_timestamp_month_mask";
    pub const TS_YEAR_SHIFT: &str = "dahua_timestamp_year_shift";
    pub const TS_YEAR_MASK: &str = "dahua_timestamp_year_mask";

    // Bounded scanning.
    pub const DHAV_CARVE_WINDOW_BYTES: &str = "dhav_carve_window_bytes";
    pub const DHAV_CARVE_WINDOW_OVERLAP_BYTES: &str = "dhav_carve_window_overlap_bytes";
    pub const DHAV_CARVE_MAX_FRAMES_PER_REGION: &str = "dhav_carve_max_frames_per_region";

    // Flat-model fallback.
    pub const SB_SECTOR_SIZE_OFFSET: &str = "superblock_sector_size_offset";
    pub const SB_BLOCK_SIZE_OFFSET: &str = "superblock_block_size_offset";
    pub const SB_TOTAL_BLOCKS_OFFSET: &str = "superblock_total_blocks_offset";
    pub const SB_DHAV_START_OFFSET: &str = "superblock_dhav_start_offset";
    pub const SB_INDEX_OFFSET_OFFSET: &str = "superblock_index_offset_offset";
    pub const SB_CTIME_OFFSET: &str = "superblock_ctime_offset";
    pub const SB_MODEL_OFFSET: &str = "superblock_model_offset";
    pub const SB_MODEL_LEN: &str = "superblock_model_len";
    pub const SB_SERIAL_OFFSET: &str = "superblock_serial_offset";
    pub const SB_SERIAL_LEN: &str = "superblock_serial_len";
    pub const SB_VOLUME_LABEL_OFFSET: &str = "superblock_volume_label_offset";
    pub const SB_VOLUME_LABEL_LEN: &str = "superblock_volume_label_len";
    pub const INDEX_HEADER_SIZE: &str = "index_header_size";
    pub const INDEX_ENTRY_COUNT_OFFSET: &str = "index_entry_count_offset";
    pub const INDEX_ENTRY_SIZE: &str = "index_entry_size";
    pub const INDEX_ENTRY_CHANNEL_OFFSET: &str = "index_entry_channel_offset";
    pub const INDEX_ENTRY_FRAME_TYPE_OFFSET: &str = "index_entry_frame_type_offset";
    pub const INDEX_ENTRY_OFFSET_OFFSET: &str = "index_entry_offset_offset";
    pub const INDEX_ENTRY_LENGTH_OFFSET: &str = "index_entry_length_offset";
    pub const INDEX_ENTRY_TIMESTAMP_OFFSET: &str = "index_entry_timestamp_offset";
    pub const INDEX_ENTRY_CRC_OFFSET: &str = "index_entry_crc_offset";
}

/// Read a non-negative `[layout]` value, falling back to the documented default.
///
/// A missing key is a profile-completeness problem, not an evidence problem, so the
/// fallback keeps the parser operational on an older profile revision. Negative values
/// are rejected because every layout value here is an offset, size, mask or sentinel.
pub fn u64_from(profile: &OemProfile, key: &str, fallback: u64) -> u64 {
    match profile.layout.get(key) {
        Some(v) if *v >= 0 => *v as u64,
        _ => fallback,
    }
}

/// [`u64_from`] narrowed to `usize` for slice indexing.
pub fn usize_from(profile: &OemProfile, key: &str, fallback: usize) -> usize {
    u64_from(profile, key, fallback as u64) as usize
}

/// [`u64_from`] narrowed to `u32`, saturating rather than wrapping.
pub fn u32_from(profile: &OemProfile, key: &str, fallback: u32) -> u32 {
    u64_from(profile, key, fallback as u64).min(u32::MAX as u64) as u32
}

/// [`u64_from`] narrowed to a single byte, for type discriminators and masks.
pub fn u8_from(profile: &OemProfile, key: &str, fallback: u8) -> u8 {
    u64_from(profile, key, fallback as u64).min(u8::MAX as u64) as u8
}

/// Resolve a profile-declared signature pattern by rule name.
///
/// Returns `None` when the profile declares no such signature, which callers must treat
/// as "this structure cannot be verified" rather than "assume it matched".
pub fn magic(profile: &OemProfile, name: &str) -> Option<Vec<u8>> {
    profile
        .signatures
        .iter()
        .find(|s| s.name == name)
        .and_then(|s| s.pattern_bytes().ok())
        .filter(|p| !p.is_empty())
}

/// Little-endian `u16` at `off`, or `None` when the field is out of range.
pub fn u16_at(buf: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    buf.get(off..end).map(|s| u16::from_le_bytes([s[0], s[1]]))
}

/// Little-endian `u32` at `off`, or `None` when the field is out of range.
pub fn u32_at(buf: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    buf.get(off..end)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Little-endian `i32` at `off`, or `None` when the field is out of range.
pub fn i32_at(buf: &[u8], off: usize) -> Option<i32> {
    u32_at(buf, off).map(|v| v as i32)
}

/// Little-endian `i16` at `off`, or `None` when the field is out of range.
pub fn i16_at(buf: &[u8], off: usize) -> Option<i16> {
    u16_at(buf, off).map(|v| v as i16)
}

/// Little-endian `u64` at `off`, or `None` when the field is out of range.
pub fn u64_at(buf: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    buf.get(off..end)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

/// Little-endian `i64` at `off`, or `None` when the field is out of range.
pub fn i64_at(buf: &[u8], off: usize) -> Option<i64> {
    u64_at(buf, off).map(|v| v as i64)
}

/// Single byte at `off`, or `None` when out of range.
pub fn u8_at(buf: &[u8], off: usize) -> Option<u8> {
    buf.get(off).copied()
}

/// Trim a fixed-width ASCII field; `None` when the field is absent or blank.
pub fn ascii_at(buf: &[u8], off: usize, len: usize) -> Option<String> {
    let end = off.checked_add(len)?;
    let s = buf.get(off..end)?;
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

/// Build a [`ValidationState`] without introducing a fallible call site.
///
/// `ValidationState::new` only rejects an empty reason, and the static fallback reason is
/// non-empty, so this helper is total: Dahua parsing never gains a panic path from
/// recording why something was or was not trusted.
pub fn vs(
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

/// Test-only helpers shared by this crate's unit tests.
///
/// The profile loader here reads the **real** versioned profile from `profiles/dahua/`
/// rather than a hand-written stub. That is deliberate: it means the unit tests exercise
/// the same offsets production does, so a profile that drifts from the parser fails the
/// test suite instead of passing against a private copy of the numbers.
#[cfg(test)]
pub mod tests_support {
    use forensic_core::OemProfile;
    use std::path::{Path, PathBuf};

    /// Locate `profiles/dahua/dahua-dhfs-v1.0.toml` by walking up from the crate dir.
    pub fn profile_path() -> PathBuf {
        let mut dir: PathBuf = env!("CARGO_MANIFEST_DIR").into();
        loop {
            let candidate = dir.join("profiles/dahua/dahua-dhfs-v1.0.toml");
            if candidate.is_file() {
                return candidate;
            }
            if !dir.pop() {
                panic!("could not locate profiles/dahua/dahua-dhfs-v1.0.toml from the crate dir");
            }
        }
    }

    /// The real, versioned Dahua profile.
    pub fn dahua_profile() -> OemProfile {
        let path = profile_path();
        OemProfile::from_file(Path::new(&path)).expect("the shipped Dahua profile must load")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn profile_with(layout: HashMap<String, i64>) -> OemProfile {
        use forensic_core::{Applicability, ConfidenceWeights, EvidenceStatus, SignatureRule};
        OemProfile {
            profile_id: "t".into(),
            profile_version: "1.0".into(),
            schema_version: "1.0".into(),
            oem: "dahua".into(),
            storage_family: "DHFS".into(),
            applicability: Applicability {
                models: vec![],
                firmwares: vec![],
                storage_variants: vec![],
                reference: None,
            },
            signatures: vec![SignatureRule {
                name: "dhfs41_magic".into(),
                pattern_hex: "44 48 46 53 34 2E 31 00".into(),
                evidence_status: EvidenceStatus::Validated,
                weight: 1.0,
                is_exclusive: false,
                explanation: "t".into(),
                offset_constraints: vec![],
            }],
            validation_rules: vec![],
            layout,
            confidence_weights: ConfidenceWeights {
                max_possible_score: 1.0,
                min_threshold: 0.5,
            },
            profile_hash: None,
        }
    }

    #[test]
    fn declared_layout_values_win_over_the_fallback() {
        let mut layout = HashMap::new();
        layout.insert("video_block_size".to_string(), 4_194_304);
        let p = profile_with(layout);
        assert_eq!(u64_from(&p, key::VIDEO_BLOCK_SIZE, 2_097_152), 4_194_304);
    }

    #[test]
    fn a_negative_layout_value_is_rejected_not_wrapped() {
        // A negative offset is never meaningful and must not become a huge u64.
        let mut layout = HashMap::new();
        layout.insert("partition_entry_stride".to_string(), -64);
        let p = profile_with(layout);
        assert_eq!(u64_from(&p, key::PT_ENTRY_STRIDE, 64), 64);
    }

    #[test]
    fn magic_resolves_declared_patterns_and_nothing_else() {
        let p = profile_with(HashMap::new());
        assert_eq!(
            magic(&p, "dhfs41_magic").as_deref(),
            Some(&b"DHFS4.1\0"[..])
        );
        assert!(magic(&p, "not_declared").is_none());
    }

    #[test]
    fn readers_return_none_past_the_end_instead_of_zero() {
        let buf = [1u8, 2, 3];
        assert_eq!(u8_at(&buf, 2), Some(3));
        assert_eq!(u8_at(&buf, 3), None);
        assert_eq!(u16_at(&buf, 2), None);
        assert_eq!(u32_at(&buf, 0), None);
        assert_eq!(u64_at(&buf, 0), None);
    }

    #[test]
    fn readers_do_not_overflow_on_hostile_offsets() {
        let buf = [0u8; 8];
        assert_eq!(u32_at(&buf, usize::MAX), None);
        assert_eq!(u64_at(&buf, usize::MAX - 2), None);
        assert_eq!(ascii_at(&buf, usize::MAX, 4), None);
    }

    #[test]
    fn signed_fields_decode_as_two_complement() {
        let buf = (-1i32).to_le_bytes();
        assert_eq!(i32_at(&buf, 0), Some(-1));
        let buf16 = (-2i16).to_le_bytes();
        assert_eq!(i16_at(&buf16, 0), Some(-2));
    }

    #[test]
    fn ascii_fields_are_trimmed_and_blank_becomes_none() {
        let buf = b"DHI-XVR\0\0\0";
        assert_eq!(ascii_at(buf, 0, 10).as_deref(), Some("DHI-XVR"));
        assert!(ascii_at(&[0u8; 8], 0, 8).is_none());
    }

    #[test]
    fn vs_is_total_even_for_an_empty_reason() {
        let state = vs(ValidationStateKind::Review, "", "op", "subject");
        assert_eq!(state.state, ValidationStateKind::Review);
        assert!(!state.reason.is_empty());
    }
}
