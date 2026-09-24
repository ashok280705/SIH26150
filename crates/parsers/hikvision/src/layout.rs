//! # Profile layout accessors and field readers
//!
//! Every Hikvision structure offset, stride, size, mask, sentinel and bound used by this
//! crate is read from the versioned profile's `[layout]` table through this module.
//! Nothing OEM-factual is a source constant — the fallbacks below exist only so an older
//! profile revision degrades to the documented value instead of failing the whole run,
//! and each one is also recorded in `profiles/hikvision/hikvision-hik-v1.0.toml`.
//!
//! ## Two endiannesses, kept apart
//!
//! Hikvision's filesystem structures (boot, HIKBTREE, block footer, clip slots) are
//! little-endian. The clip payload is an MPEG-PS-like stream whose pack and PES header
//! fields are **big-endian**. Mixing the two silently is an easy way to invent
//! structure, so the readers are named for their endianness (`u16_at` vs `u16_be_at`)
//! and callers must pick deliberately.
//!
//! ## The readers are total
//!
//! An out-of-range field yields `None`, never a panic and never a silently zero value.
//! Evidence is adversarial input, so "the field is not there" has to be representable
//! and distinguishable from "the field is there and holds zero".

use forensic_core::{OemProfile, ValidationState, ValidationStateKind};

/// Named `[layout]` keys, so a typo is a compile error rather than a silent fallback.
///
/// Grouped in the same order as the profile file to keep the two readable side by side.
pub mod key {
    // ── Boot structure ───────────────────────────────────────────────────────────
    pub const BOOT_CANDIDATE_PRIMARY: &str = "boot_candidate_offset_primary";
    pub const BOOT_CANDIDATE_SECONDARY: &str = "boot_candidate_offset_secondary";
    pub const BOOT_STRUCTURE_SIZE: &str = "boot_structure_size";
    pub const BOOT_IDENTIFIER_OFFSET: &str = "boot_identifier_offset";
    pub const BOOT_IDENTIFIER_FIELD_SIZE: &str = "boot_identifier_field_size";
    pub const BOOT_VIDEO_START_OFFSET: &str = "boot_video_start_offset_offset";
    pub const BOOT_BLOCK_SIZE_OFFSET: &str = "boot_block_size_offset";
    pub const BOOT_NUMBER_OF_BLOCKS_OFFSET: &str = "boot_number_of_blocks_offset";
    pub const BOOT_BTREE_OFFSET_OFFSET: &str = "boot_btree_offset_offset";
    pub const BOOT_BTREE_SIZE_OFFSET: &str = "boot_btree_size_offset";
    pub const BOOT_BACKUP_BTREE_OFFSET_OFFSET: &str = "boot_backup_btree_offset_offset";
    pub const BOOT_BACKUP_BTREE_SIZE_OFFSET: &str = "boot_backup_btree_size_offset";
    pub const BOOT_VIDEO_START_FALLBACK: &str = "boot_video_start_offset_fallback";
    pub const BOOT_BLOCK_SIZE_DEFAULT: &str = "boot_block_size_default";
    pub const BOOT_BLOCK_SIZE_MIN: &str = "boot_block_size_min";
    pub const BOOT_BLOCK_SIZE_MAX: &str = "boot_block_size_max";
    pub const BOOT_NUMBER_OF_BLOCKS_MAX: &str = "boot_number_of_blocks_max";

    // ── HIKBTREE header ──────────────────────────────────────────────────────────
    pub const BTREE_PAGE_SIZE: &str = "hikbtree_page_size";
    pub const BTREE_MAGIC_LENGTH: &str = "hikbtree_magic_length";
    pub const BTREE_MAGIC_OFFSET: &str = "hikbtree_magic_offset";
    pub const BTREE_TREE_TIMESTAMP_OFFSET: &str = "hikbtree_tree_timestamp_offset";
    pub const BTREE_FIRST_POINTER_PAGE_OFFSET: &str = "hikbtree_first_pointer_page_offset";
    pub const BTREE_LAST_POINTER_PAGE_OFFSET: &str = "hikbtree_last_pointer_page_offset";
    pub const BTREE_FIRST_LIST_PAGE_OFFSET: &str = "hikbtree_first_list_page_offset";
    pub const BTREE_FIRST_LEAF_PAGE_OFFSET: &str = "hikbtree_first_leaf_page_offset";
    pub const BTREE_PAGE_COUNT_OFFSET: &str = "hikbtree_page_count_offset";
    pub const BTREE_PAGE_COUNT_MAX: &str = "hikbtree_page_count_max";
    pub const BTREE_TRAVERSAL_MAX_PAGES: &str = "hikbtree_traversal_max_pages";

    // ── HIKBTREE page header ─────────────────────────────────────────────────────
    pub const BTREE_PAGE_TYPE_OFFSET: &str = "hikbtree_page_type_offset";
    pub const BTREE_PAGE_TYPE_LEAF: &str = "hikbtree_page_type_leaf";
    pub const BTREE_PAGE_TYPE_INTERNAL: &str = "hikbtree_page_type_internal";
    pub const BTREE_LEAF_ENTRY_COUNT_OFFSET: &str = "hikbtree_leaf_entry_count_offset";
    pub const BTREE_LEAF_OTHER_PAGE_OFFSET: &str = "hikbtree_leaf_other_page_offset";
    pub const BTREE_LEAF_NEXT_PAGE_OFFSET: &str = "hikbtree_leaf_next_page_offset";
    pub const BTREE_LEAF_ENTRIES_OFFSET: &str = "hikbtree_leaf_entries_offset";
    pub const BTREE_INTERNAL_OTHER_PAGE_OFFSET: &str = "hikbtree_internal_other_page_offset";
    pub const BTREE_INTERNAL_NEXT_PAGE_OFFSET: &str = "hikbtree_internal_next_page_offset";
    pub const BTREE_LEAF_ENTRY_COUNT_MAX: &str = "hikbtree_leaf_entry_count_max";

    // ── HIKBTREE entry ───────────────────────────────────────────────────────────
    pub const BTREE_ENTRY_SIZE: &str = "hikbtree_entry_size";
    pub const BTREE_ENTRY_PAGE_OFFSET_OFFSET: &str = "hikbtree_entry_page_offset_offset";
    pub const BTREE_ENTRY_SENTINEL_OFFSET: &str = "hikbtree_entry_sentinel_offset";
    pub const BTREE_ENTRY_CHANNEL_OFFSET: &str = "hikbtree_entry_channel_offset";
    pub const BTREE_ENTRY_START_TIME_OFFSET: &str = "hikbtree_entry_start_time_offset";
    pub const BTREE_ENTRY_END_TIME_OFFSET: &str = "hikbtree_entry_end_time_offset";
    pub const BTREE_ENTRY_DATA_OFFSET_OFFSET: &str = "hikbtree_entry_data_offset_offset";
    pub const BTREE_ENTRY_STATUS_OFFSET: &str = "hikbtree_entry_status_offset";
    pub const BTREE_ENTRY_UNKNOWN_OFFSET: &str = "hikbtree_entry_unknown_offset";
    pub const BTREE_ENTRY_SENTINEL_BLANK: &str = "hikbtree_entry_sentinel_blank";
    pub const BTREE_ENTRY_SENTINEL_POPULATED: &str = "hikbtree_entry_sentinel_populated";
    pub const BTREE_ENTRY_CHANNEL_MAX: &str = "hikbtree_entry_channel_max";
    pub const CHANNEL_NORMALIZATION_ADDEND: &str = "hikvision_channel_normalization_addend";

    // ── Video block geometry ─────────────────────────────────────────────────────
    pub const BLOCK_FOOTER_SIZE: &str = "block_footer_size";

    // ── Block footer clip index ──────────────────────────────────────────────────
    pub const BLOCK_INDEX_HEADER_SIZE: &str = "block_index_header_size";
    pub const BLOCK_INDEX_REJECT_BYTE_OFFSET: &str = "block_index_reject_byte_offset";
    pub const BLOCK_INDEX_REJECT_BYTE_VALUE: &str = "block_index_reject_byte_value";
    pub const BLOCK_INDEX_CLIP_COUNT_OFFSET: &str = "block_index_clip_count_offset";
    pub const BLOCK_INDEX_EPOCH_START_OFFSET: &str = "block_index_epoch_start_offset";
    pub const BLOCK_INDEX_EPOCH_END_OFFSET: &str = "block_index_epoch_end_offset";
    pub const BLOCK_INDEX_CLIP_BASE_OFFSET: &str = "block_index_clip_base_offset";
    pub const BLOCK_INDEX_CLIP_STRIDE: &str = "block_index_clip_stride";
    pub const BLOCK_INDEX_CLIP_COUNT_MAX: &str = "block_index_clip_count_max";

    // ── Clip slot fields ─────────────────────────────────────────────────────────
    pub const CLIP_CHANNEL_OFFSET: &str = "clip_channel_offset";
    pub const CLIP_CHANNEL_MAX: &str = "clip_channel_max";
    pub const CLIP_TIME_A_OFFSET: &str = "clip_time_a_offset";
    pub const CLIP_END_TIME_OFFSET: &str = "clip_end_time_offset";
    pub const CLIP_START_TIME_OFFSET: &str = "clip_start_time_offset";
    pub const CLIP_START_OFFSET_OFFSET: &str = "clip_start_offset_offset";
    pub const CLIP_END_OFFSET_OFFSET: &str = "clip_end_offset_offset";
    pub const CLIP_FRAME_RATE_OFFSET: &str = "clip_frame_rate_offset";
    pub const CLIP_UNKNOWN_A_OFFSET: &str = "clip_unknown_a_offset";
    pub const CLIP_UNKNOWN_B_OFFSET: &str = "clip_unknown_b_offset";
    pub const CLIP_MAX_DURATION_SECONDS: &str = "clip_max_duration_seconds";
    pub const CLIP_MIN_LENGTH_BYTES: &str = "clip_min_length_bytes";

    // ── Timestamps ───────────────────────────────────────────────────────────────
    pub const TS_EPOCH_BASE: &str = "hikvision_timestamp_epoch_base";
    pub const TS_INCOMPLETE_VALUE: &str = "hikvision_timestamp_incomplete_value";
    pub const TS_PLAUSIBLE_MIN: &str = "hikvision_timestamp_plausible_min";
    pub const TS_PLAUSIBLE_MAX: &str = "hikvision_timestamp_plausible_max";

    // ── MPEG-PS / PES ────────────────────────────────────────────────────────────
    pub const PS_START_CODE_PREFIX_LENGTH: &str = "ps_start_code_prefix_length";
    pub const PS_START_CODE_LENGTH: &str = "ps_start_code_length";
    pub const PS_TAG_PACK_HEADER: &str = "ps_tag_pack_header";
    pub const PS_TAG_SYSTEM_HEADER: &str = "ps_tag_system_header";
    pub const PS_TAG_PROGRAM_STREAM_MAP: &str = "ps_tag_program_stream_map";
    pub const PS_TAG_PRIVATE_STREAM_1: &str = "ps_tag_private_stream_1";
    pub const PS_TAG_AUDIO_STREAM_0: &str = "ps_tag_audio_stream_0";
    pub const PS_TAG_VIDEO_STREAM_0: &str = "ps_tag_video_stream_0";
    pub const PS_TAG_VIDEO_STREAM_1: &str = "ps_tag_video_stream_1";
    pub const PS_PACK_HEADER_SIZE: &str = "ps_pack_header_size";
    pub const PS_PACK_SERIAL_OFFSET: &str = "ps_pack_serial_offset";
    pub const PS_PES_LENGTH_OFFSET: &str = "ps_pes_length_offset";
    pub const PS_PES_LENGTH_ADDEND: &str = "ps_pes_length_addend";
    pub const PS_PES_PAYLOAD_OFFSET_FIELD: &str = "ps_pes_payload_offset_field";
    pub const PS_PES_PAYLOAD_OFFSET_MASK: &str = "ps_pes_payload_offset_mask";
    pub const PS_PES_PAYLOAD_OFFSET_ADDEND: &str = "ps_pes_payload_offset_addend";
    pub const PS_PES_MIN_PART_LENGTH: &str = "ps_pes_min_part_length";
    pub const PS_PES_MAX_PART_LENGTH: &str = "ps_pes_max_part_length";
    pub const PS_MAX_PARTS_PER_CLIP: &str = "ps_max_parts_per_clip";

    // ── OFNI ─────────────────────────────────────────────────────────────────────
    pub const OFNI_TAG_LENGTH: &str = "ofni_tag_length";
    pub const OFNI_LENGTH_OFFSET: &str = "ofni_length_offset";
    pub const OFNI_LENGTH_ADDEND: &str = "ofni_length_addend";
    pub const OFNI_MAX_LENGTH: &str = "ofni_max_length";

    // ── Codec detection ──────────────────────────────────────────────────────────
    pub const NAL_H264_TYPE_MASK: &str = "nal_h264_type_mask";
    pub const NAL_H264_TYPE_SPS: &str = "nal_h264_type_sps";
    pub const NAL_H264_TYPE_PPS: &str = "nal_h264_type_pps";
    pub const NAL_H264_TYPE_IDR: &str = "nal_h264_type_idr";
    pub const NAL_H264_TYPE_NON_IDR: &str = "nal_h264_type_non_idr";
    pub const NAL_H264_TYPE_SEI: &str = "nal_h264_type_sei";
    pub const NAL_H264_TYPE_AUD: &str = "nal_h264_type_aud";
    pub const NAL_H265_TYPE_MASK: &str = "nal_h265_type_mask";
    pub const NAL_H265_TYPE_SHIFT: &str = "nal_h265_type_shift";
    pub const NAL_H265_TYPE_VPS: &str = "nal_h265_type_vps";
    pub const NAL_H265_TYPE_SPS: &str = "nal_h265_type_sps";
    pub const NAL_H265_TYPE_PPS: &str = "nal_h265_type_pps";
    pub const NAL_H265_TYPE_IDR_W_RADL: &str = "nal_h265_type_idr_w_radl";
    pub const NAL_H265_TYPE_IDR_N_LP: &str = "nal_h265_type_idr_n_lp";
    pub const NAL_H265_TYPE_TRAIL_R: &str = "nal_h265_type_trail_r";
    pub const NAL_H265_TYPE_AUD: &str = "nal_h265_type_aud";
    pub const CODEC_MIN_AGREEING_NALS: &str = "codec_min_agreeing_nals";

    // ── Bounded scanning ─────────────────────────────────────────────────────────
    pub const READ_WINDOW_BYTES: &str = "hikvision_read_window_bytes";
    pub const CARVE_WINDOW_BYTES: &str = "hikvision_carve_window_bytes";
    pub const CARVE_WINDOW_OVERLAP_BYTES: &str = "hikvision_carve_window_overlap_bytes";
    pub const CARVE_MAX_CANDIDATES_PER_REGION: &str = "hikvision_carve_max_candidates_per_region";
    pub const RECOGNITION_PROBE_BYTES: &str = "hikvision_recognition_probe_bytes";
    pub const MAX_BLOCKS_EXAMINED: &str = "hikvision_max_blocks_examined";
    pub const CARVE_MIN_PARTS: &str = "hikvision_carve_min_parts";
    pub const CARVE_MIN_CONDITIONS: &str = "hikvision_carve_min_conditions";
    pub const CARVE_SENTINEL_PROXIMITY_BYTES: &str = "hikvision_carve_sentinel_proximity_bytes";
    pub const RECORDING_JOIN_GAP_SECONDS: &str = "hikvision_recording_join_gap_seconds";

    // ── Uncertainty flags ────────────────────────────────────────────────────────
    pub const UNCERTAINTY_BOOT_IDENTIFIER: &str = "uncertainty_boot_identifier_established";
    pub const UNCERTAINTY_BTREE_PAGE_LAYOUT: &str = "uncertainty_btree_page_layout_established";
    pub const UNCERTAINTY_ENTRY_LAYOUT: &str = "uncertainty_entry_layout_established";
    pub const UNCERTAINTY_BLOCK_FOOTER_GEOMETRY: &str =
        "uncertainty_block_footer_geometry_established";
    pub const UNCERTAINTY_PS_FRAMING: &str = "uncertainty_ps_framing_established";
    pub const UNCERTAINTY_CHANNEL_ENCODING: &str = "uncertainty_channel_encoding_established";
    pub const UNCERTAINTY_CLIP_SLOT_SEMANTICS: &str =
        "uncertainty_clip_slot_field_semantics_established";
    pub const UNCERTAINTY_ENTRY_STATUS_SEMANTICS: &str =
        "uncertainty_entry_status_semantics_established";
    pub const UNCERTAINTY_CARVE_SENTINEL_SEMANTICS: &str =
        "uncertainty_carve_sentinel_semantics_established";
    pub const UNCERTAINTY_ALLOCATION_STATE: &str = "uncertainty_allocation_state_available";
}

/// Profile-declared signature rule names this crate resolves by name.
///
/// The names live here rather than inline so a profile rename is a single-site change,
/// and so it is visible at a glance which rules the parser depends on existing.
pub mod sig {
    pub const BOOT_IDENTIFIER: &str = "hikvision_boot_identifier";
    pub const HIKBTREE_MAGIC: &str = "hikbtree_magic";
    pub const OFNI_PART: &str = "hikvision_ofni_part";
    pub const CARVE_SENTINEL: &str = "hikvision_carve_sentinel";
    pub const PS_PACK_HEADER: &str = "ps_pack_header";
    pub const PS_VIDEO_STREAM_0: &str = "ps_video_stream_0";
}

/// Read a non-negative `[layout]` value, falling back to the documented default.
///
/// A missing key is a profile-completeness problem, not an evidence problem, so the
/// fallback keeps the parser operational on an older profile revision. Negative values
/// are rejected because every value read through this accessor is an offset, size, mask
/// or bound. Sentinels that are genuinely wider than `i64::MAX` go through
/// [`u64_bits_from`] instead.
pub fn u64_from(profile: &OemProfile, key: &str, fallback: u64) -> u64 {
    match profile.layout.get(key) {
        Some(v) if *v >= 0 => *v as u64,
        _ => fallback,
    }
}

/// Read a `[layout]` value as raw 64-bit **bits**, preserving a negative encoding.
///
/// `OemProfile::layout` is `HashMap<String, i64>` because TOML integers are signed, but
/// some Hikvision sentinels are unsigned values with the high bit set — the blank entry
/// sentinel `0xFFFFFFFFFFFFFFFF` is recorded in the profile as `-1`. Reinterpreting the
/// two's-complement bits here keeps the profile readable while letting the parser compare
/// against the real on-disk value.
pub fn u64_bits_from(profile: &OemProfile, key: &str, fallback: u64) -> u64 {
    match profile.layout.get(key) {
        Some(v) => *v as u64,
        None => fallback,
    }
}

/// Read a signed `[layout]` value, for fields that may legitimately be negative.
pub fn i64_from(profile: &OemProfile, key: &str, fallback: i64) -> i64 {
    profile.layout.get(key).copied().unwrap_or(fallback)
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

/// [`u64_from`] narrowed to `i32`, for on-disk signed discriminators.
pub fn i32_from(profile: &OemProfile, key: &str, fallback: i32) -> i32 {
    match profile.layout.get(key) {
        Some(v) if *v >= i32::MIN as i64 && *v <= i32::MAX as i64 => *v as i32,
        _ => fallback,
    }
}

/// Whether a profile-recorded boolean-ish flag is set.
///
/// Used for the `uncertainty_*` keys, which record whether the platform treats a
/// structural interpretation as established. Absent means "not established", the
/// conservative reading.
pub fn flag_from(profile: &OemProfile, key: &str) -> bool {
    profile.layout.get(key).copied().unwrap_or(0) != 0
}

/// Resolve a profile-declared signature pattern by rule name.
///
/// Returns `None` when the profile declares no such signature, which callers must treat
/// as "this structure cannot be verified" rather than "assume it matched". A parser that
/// substituted a hard-coded pattern here would be reintroducing exactly the OEM source
/// constant the profile system exists to prevent.
pub fn magic(profile: &OemProfile, name: &str) -> Option<Vec<u8>> {
    profile
        .signatures
        .iter()
        .find(|s| s.name == name)
        .and_then(|s| s.pattern_bytes().ok())
        .filter(|p| !p.is_empty())
}

// ── Little-endian readers (filesystem structures) ───────────────────────────────

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

// ── Big-endian readers (MPEG-PS / PES headers) ──────────────────────────────────

/// Big-endian `u16` at `off`, or `None` when the field is out of range.
///
/// MPEG-PS and PES header fields are big-endian. Kept as a separate function from
/// [`u16_at`] so no call site can pick the wrong endianness by accident.
pub fn u16_be_at(buf: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    buf.get(off..end).map(|s| u16::from_be_bytes([s[0], s[1]]))
}

/// Big-endian `u32` at `off`, or `None` when the field is out of range.
pub fn u32_be_at(buf: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    buf.get(off..end)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
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

/// Render bytes as `HEX (ascii)` for an evidence string.
///
/// Non-printable bytes become `.` so an evidence reason stays readable when the field is
/// damaged or was never text to begin with.
pub fn hex_ascii(bytes: &[u8]) -> String {
    let hex = bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ");
    let ascii: String = bytes
        .iter()
        .map(|b| {
            if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            }
        })
        .collect();
    format!("{hex} ({ascii})")
}

/// Build a [`ValidationState`] without introducing a fallible call site.
///
/// `ValidationState::new` only rejects an empty reason, and the static fallback reason is
/// non-empty, so this helper is total: Hikvision parsing never gains a panic path from
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
/// The profile loader here reads the **real** versioned profile from `profiles/hikvision/`
/// rather than a hand-written stub. That is deliberate: it means the unit tests exercise
/// the same offsets production does, so a profile that drifts from the parser fails the
/// test suite instead of passing against a private copy of the numbers.
pub mod tests_support {
    use forensic_core::OemProfile;
    use std::path::{Path, PathBuf};

    /// Relative path of the shipped Hikvision profile from the workspace root.
    pub const PROFILE_RELATIVE_PATH: &str = "profiles/hikvision/hikvision-hik-v1.0.toml";

    /// Locate the shipped Hikvision profile by walking up from the crate directory.
    pub fn profile_path() -> PathBuf {
        let mut dir: PathBuf = env!("CARGO_MANIFEST_DIR").into();
        loop {
            let candidate = dir.join(PROFILE_RELATIVE_PATH);
            if candidate.is_file() {
                return candidate;
            }
            if !dir.pop() {
                panic!("could not locate {PROFILE_RELATIVE_PATH} from the crate dir");
            }
        }
    }

    /// The real, versioned Hikvision profile.
    pub fn hikvision_profile() -> OemProfile {
        let path = profile_path();
        OemProfile::from_file(Path::new(&path)).expect("the shipped Hikvision profile must load")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tests_support::hikvision_profile;

    #[test]
    fn the_shipped_profile_loads_and_declares_the_structures_the_parser_reads() {
        let p = hikvision_profile();
        assert_eq!(p.oem, "hikvision");
        // Every signature the parser resolves by name must exist, or the corresponding
        // structure silently becomes unverifiable.
        for name in [
            sig::BOOT_IDENTIFIER,
            sig::HIKBTREE_MAGIC,
            sig::OFNI_PART,
            sig::CARVE_SENTINEL,
            sig::PS_PACK_HEADER,
            sig::PS_VIDEO_STREAM_0,
        ] {
            assert!(
                magic(&p, name).is_some(),
                "the profile must declare signature '{name}'"
            );
        }
    }

    #[test]
    fn the_boot_identifier_is_the_real_hikvision_string_not_a_fictional_tag() {
        let p = hikvision_profile();
        let pattern = magic(&p, sig::BOOT_IDENTIFIER).expect("identifier declared");
        assert_eq!(
            pattern.as_slice(),
            b"HIKVISION@HANGZHOU",
            "the identifier must be the real filesystem string"
        );
        // The fictional tags the previous implementation used must be gone.
        assert_ne!(pattern.as_slice(), b"HIK_");
        for s in &p.signatures {
            let bytes = s.pattern_bytes().unwrap_or_default();
            assert_ne!(
                bytes.as_slice(),
                b"HIK_",
                "signature '{}' is fictional",
                s.name
            );
            assert_ne!(
                bytes.as_slice(),
                b"HKSEG",
                "signature '{}' is fictional",
                s.name
            );
        }
    }

    #[test]
    fn the_hikbtree_magic_is_declared_as_eight_bytes() {
        let p = hikvision_profile();
        let m = magic(&p, sig::HIKBTREE_MAGIC).expect("declared");
        assert_eq!(m.as_slice(), b"HIKBTREE");
        assert_eq!(m.len() as u64, u64_from(&p, key::BTREE_MAGIC_LENGTH, 0));
    }

    #[test]
    fn declared_layout_values_win_over_the_fallback() {
        let p = hikvision_profile();
        assert_eq!(u64_from(&p, key::BTREE_PAGE_SIZE, 1), 4096);
        assert_eq!(u64_from(&p, key::BTREE_ENTRY_SIZE, 1), 48);
        assert_eq!(u64_from(&p, key::BLOCK_FOOTER_SIZE, 1), 1024 * 1024);
        assert_eq!(u64_from(&p, key::BOOT_BLOCK_SIZE_DEFAULT, 1), 1 << 30);
    }

    #[test]
    fn the_blank_entry_sentinel_round_trips_through_the_signed_profile_encoding() {
        // The profile records 0xFFFFFFFFFFFFFFFF as -1 because TOML integers are signed.
        // Reading it back as bits must produce the real on-disk value, not 0 and not 1.
        let p = hikvision_profile();
        assert_eq!(
            u64_bits_from(&p, key::BTREE_ENTRY_SENTINEL_BLANK, 0),
            0xFFFF_FFFF_FFFF_FFFF
        );
        assert_eq!(u64_bits_from(&p, key::BTREE_ENTRY_SENTINEL_POPULATED, 1), 0);
        // The plain accessor must refuse the negative encoding rather than wrap it.
        assert_eq!(u64_from(&p, key::BTREE_ENTRY_SENTINEL_BLANK, 7), 7);
    }

    #[test]
    fn the_declared_leaf_entry_capacity_matches_the_page_geometry() {
        let p = hikvision_profile();
        let page = u64_from(&p, key::BTREE_PAGE_SIZE, 0);
        let base = u64_from(&p, key::BTREE_LEAF_ENTRIES_OFFSET, 0);
        let size = u64_from(&p, key::BTREE_ENTRY_SIZE, 1);
        let derived = (page - base) / size;
        assert_eq!(
            u64_from(&p, key::BTREE_LEAF_ENTRY_COUNT_MAX, 0),
            derived,
            "the declared max entry count must be the count that physically fits"
        );
    }

    #[test]
    fn the_declared_clip_capacity_matches_the_footer_geometry() {
        let p = hikvision_profile();
        let footer = u64_from(&p, key::BLOCK_FOOTER_SIZE, 0);
        let base = u64_from(&p, key::BLOCK_INDEX_CLIP_BASE_OFFSET, 0);
        let stride = u64_from(&p, key::BLOCK_INDEX_CLIP_STRIDE, 1);
        assert_eq!(
            u64_from(&p, key::BLOCK_INDEX_CLIP_COUNT_MAX, 0),
            (footer - base) / stride
        );
    }

    #[test]
    fn a_block_must_be_larger_than_its_own_footer() {
        let p = hikvision_profile();
        assert!(
            u64_from(&p, key::BOOT_BLOCK_SIZE_MIN, 0)
                >= u64_from(&p, key::BLOCK_FOOTER_SIZE, u64::MAX),
            "a block smaller than its footer would leave a negative video-data range"
        );
    }

    #[test]
    fn the_traversal_guard_never_truncates_a_well_formed_tree() {
        let p = hikvision_profile();
        assert!(
            u64_from(&p, key::BTREE_TRAVERSAL_MAX_PAGES, 0)
                >= u64_from(&p, key::BTREE_PAGE_COUNT_MAX, u64::MAX),
            "the loop guard must be at least the max legal page count, or it becomes a \
             semantic limit that silently drops pages"
        );
    }

    #[test]
    fn the_carve_overlap_is_large_enough_for_a_straddling_structure() {
        let p = hikvision_profile();
        let overlap = u64_from(&p, key::CARVE_WINDOW_OVERLAP_BYTES, 0);
        assert!(overlap >= u64_from(&p, key::PS_PACK_HEADER_SIZE, u64::MAX));
        assert!(overlap >= u64_from(&p, key::BTREE_ENTRY_SIZE, u64::MAX));
    }

    #[test]
    fn readers_return_none_past_the_end_instead_of_zero() {
        let buf = [1u8, 2, 3];
        assert_eq!(u8_at(&buf, 2), Some(3));
        assert_eq!(u8_at(&buf, 3), None);
        assert_eq!(u16_at(&buf, 2), None);
        assert_eq!(u32_at(&buf, 0), None);
        assert_eq!(u64_at(&buf, 0), None);
        assert_eq!(u16_be_at(&buf, 2), None);
        assert_eq!(u32_be_at(&buf, 0), None);
    }

    #[test]
    fn readers_do_not_overflow_on_hostile_offsets() {
        let buf = [0u8; 8];
        assert_eq!(u32_at(&buf, usize::MAX), None);
        assert_eq!(u64_at(&buf, usize::MAX - 2), None);
        assert_eq!(u32_be_at(&buf, usize::MAX), None);
        assert_eq!(ascii_at(&buf, usize::MAX, 4), None);
    }

    #[test]
    fn little_and_big_endian_readers_disagree_as_they_must() {
        // 0x1BA in the MPEG sense: the byte order is the whole point of keeping the two
        // reader families separate.
        let buf = [0x00, 0x00, 0x01, 0xBA];
        assert_eq!(u32_be_at(&buf, 0), Some(0x0000_01BA));
        assert_eq!(u32_at(&buf, 0), Some(0xBA01_0000));
        let len = [0x01, 0x00];
        assert_eq!(u16_be_at(&len, 0), Some(0x0100));
        assert_eq!(u16_at(&len, 0), Some(0x0001));
    }

    #[test]
    fn signed_fields_decode_as_twos_complement() {
        let buf = (-1i32).to_le_bytes();
        assert_eq!(i32_at(&buf, 0), Some(-1));
        let buf64 = (-2i64).to_le_bytes();
        assert_eq!(i64_at(&buf64, 0), Some(-2));
    }

    #[test]
    fn hex_ascii_renders_damaged_fields_without_panicking() {
        assert_eq!(hex_ascii(b"HIK"), "48 49 4B (HIK)");
        assert_eq!(hex_ascii(&[0x00, 0xFF]), "00 FF (..)");
        assert_eq!(hex_ascii(&[]), " ()");
    }

    #[test]
    fn vs_is_total_even_for_an_empty_reason() {
        let state = vs(ValidationStateKind::Review, "", "op", "subject");
        assert_eq!(state.state, ValidationStateKind::Review);
        assert!(!state.reason.is_empty());
    }

    #[test]
    fn uncertainty_flags_default_to_not_established() {
        let p = hikvision_profile();
        // Established structural facts.
        assert!(flag_from(&p, key::UNCERTAINTY_BOOT_IDENTIFIER));
        assert!(flag_from(&p, key::UNCERTAINTY_BTREE_PAGE_LAYOUT));
        // Deliberately provisional: these must not claim to be established.
        assert!(!flag_from(&p, key::UNCERTAINTY_CLIP_SLOT_SEMANTICS));
        assert!(!flag_from(&p, key::UNCERTAINTY_ALLOCATION_STATE));
        // A key that does not exist is "not established", never "established".
        assert!(!flag_from(&p, "uncertainty_key_that_does_not_exist"));
    }
}
