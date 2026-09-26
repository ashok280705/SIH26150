//! # Channel normalization
//!
//! Two Hikvision structures carry a channel byte: the `+17` field of a HIKBTREE entry and
//! the `+13` field of a footer clip slot. Both are normalized here so the two paths cannot
//! drift apart, and so there is exactly one place where the encoding assumption lives.
//!
//! ## The raw byte always survives
//!
//! The profile declares an addend that turns the stored byte into the 1-based channel
//! number an examiner sees. That mapping is marked **provisional**: firmware variation in
//! the channel encoding has not been ruled out. So every normalization records the raw
//! byte, the addend applied, and a sentence describing what was done. If the assumption
//! turns out to be wrong for some model, the evidence already contains everything needed
//! to re-derive the correct channel without re-acquiring the disk.
//!
//! A byte above the profile's plausible maximum yields **no** channel number rather than a
//! truncated or masked one. A wrong channel attribution puts a recording on the wrong
//! camera, which is worse than reporting the channel as unknown.

use forensic_core::OemProfile;
use serde::{Deserialize, Serialize};

use crate::layout::{key, u32_from};

/// A channel byte, with the normalization that was applied to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelEvidence {
    /// The byte exactly as stored.
    pub raw: u8,
    /// Absolute physical offset of the byte, for provenance.
    pub field_offset: u64,
    /// The 1-based channel number, when the raw value was plausible.
    pub normalized: Option<u32>,
    /// The addend the profile declared, so the mapping is re-derivable from a report.
    pub addend: u32,
    /// Why the value is or is not usable.
    pub note: String,
}

impl ChannelEvidence {
    /// Whether a channel number was established.
    pub fn is_known(&self) -> bool {
        self.normalized.is_some()
    }

    /// The channel for display, or a stable placeholder.
    pub fn label(&self) -> String {
        self.normalized
            .map(|c| c.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }
}

/// Normalize a channel byte read at `field_offset`.
///
/// `structure` names the field for the evidence sentence (e.g. `"HIKBTREE entry +17"`).
pub fn normalize(
    profile: &OemProfile,
    raw: u8,
    field_offset: u64,
    structure: &str,
    max_key: &str,
) -> ChannelEvidence {
    let max = u32_from(profile, max_key, 127);
    let addend = u32_from(profile, key::CHANNEL_NORMALIZATION_ADDEND, 1);

    if raw as u32 > max {
        return ChannelEvidence {
            raw,
            field_offset,
            normalized: None,
            addend,
            note: format!(
                "the {structure} channel byte at {field_offset} holds {raw}, above the \
                 profile-declared plausible maximum {max}; no channel number was derived rather \
                 than masking the value into a plausible-looking one"
            ),
        };
    }

    let normalized = raw as u32 + addend;
    ChannelEvidence {
        raw,
        field_offset,
        normalized: Some(normalized),
        addend,
        note: format!(
            "the {structure} channel byte at {field_offset} holds {raw}, normalized to channel \
             {normalized} by adding the profile-declared addend {addend}. The encoding is recorded \
             as provisional, so the raw byte is preserved alongside it"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::tests_support::hikvision_profile;

    #[test]
    fn a_zero_based_byte_becomes_a_one_based_channel() {
        let p = hikvision_profile();
        let c = normalize(&p, 0, 0x100, "test", key::BTREE_ENTRY_CHANNEL_MAX);
        assert_eq!(c.raw, 0);
        assert_eq!(c.normalized, Some(1));
        assert_eq!(c.addend, 1);
        assert!(c.is_known());
        assert_eq!(c.label(), "1");
        assert!(
            c.note.contains("provisional"),
            "the note must flag the assumption"
        );
    }

    #[test]
    fn the_raw_byte_is_preserved_for_every_channel() {
        let p = hikvision_profile();
        for raw in [0u8, 1, 7, 15, 63, 127] {
            let c = normalize(&p, raw, 0, "test", key::BTREE_ENTRY_CHANNEL_MAX);
            assert_eq!(c.raw, raw);
            assert_eq!(c.normalized, Some(raw as u32 + 1));
        }
    }

    #[test]
    fn a_byte_above_the_plausible_maximum_yields_no_channel_number() {
        let p = hikvision_profile();
        for raw in [128u8, 200, 254, 255] {
            let c = normalize(&p, raw, 0x20, "clip slot +13", key::CLIP_CHANNEL_MAX);
            assert_eq!(c.raw, raw, "the raw byte still survives");
            assert_eq!(
                c.normalized, None,
                "raw {raw} must not be masked into a plausible channel"
            );
            assert!(!c.is_known());
            assert_eq!(c.label(), "unknown");
        }
    }

    #[test]
    fn the_field_offset_is_recorded_so_the_byte_can_be_found_again() {
        let p = hikvision_profile();
        let c = normalize(&p, 3, 0xDEAD_BEEF, "test", key::CLIP_CHANNEL_MAX);
        assert_eq!(c.field_offset, 0xDEAD_BEEF);
        assert!(c.note.contains(&0xDEAD_BEEFu64.to_string()));
    }

    #[test]
    fn exactly_the_maximum_is_accepted_and_one_above_is_not() {
        let p = hikvision_profile();
        assert!(normalize(&p, 127, 0, "t", key::CLIP_CHANNEL_MAX).is_known());
        assert!(!normalize(&p, 128, 0, "t", key::CLIP_CHANNEL_MAX).is_known());
    }
}
