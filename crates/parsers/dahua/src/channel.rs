//! # Dahua channel decoding
//!
//! Dahua records a camera channel in three different ways depending on the structure and
//! the recorder generation, and this module normalizes all of them to one 1-based channel
//! number **without discarding the OEM-specific evidence**:
//!
//! | Source                                   | Encoding                                  |
//! |------------------------------------------|-------------------------------------------|
//! | block-table entry, legacy                | `(byte@+1 & 0x0F) + 1` — 16 channels max  |
//! | block-table entry, extended              | `byte@+31 & 0x1F` when bit 0 of `+29` set |
//! | DHAV frame header                        | channel field at `+6`, 0-based            |
//!
//! The legacy nibble and the extended field are genuinely different encodings, not two
//! readings of one value: the legacy form adds one and the extended form does not. A
//! normalizer that collapsed them would silently shift every channel number by one on
//! extended-channel recorders.
//!
//! Every decoded channel therefore keeps its raw byte, the encoding that produced it, and
//! a sentence explaining the derivation, so an examiner can see which of the three paths
//! a channel label came from.

use forensic_core::OemProfile;
use serde::{Deserialize, Serialize};

use crate::layout::{key, u8_from};

/// Which on-disk encoding produced a channel number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelEncoding {
    /// Legacy block-table nibble: `(raw & 0x0F) + 1`, so at most 16 channels.
    BlockTableLegacyNibble,
    /// Extended block-table field, selected by the flag byte: `raw & 0x1F`.
    BlockTableExtended,
    /// DHAV frame header channel field, stored 0-based.
    DhavFrameHeader,
}

impl ChannelEncoding {
    /// Stable label for provenance and reports.
    pub fn label(&self) -> &'static str {
        match self {
            Self::BlockTableLegacyNibble => "block-table legacy nibble",
            Self::BlockTableExtended => "block-table extended channel",
            Self::DhavFrameHeader => "DHAV frame header channel field",
        }
    }
}

/// A channel number normalized to 1-based, with its OEM encoding evidence retained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DahuaChannel {
    /// Normalized 1-based channel, matching the recorder's own CH01/CH02 labelling.
    pub normalized: u32,
    /// The raw field exactly as read from disk, before any masking or offsetting.
    pub raw_value: u32,
    /// Which encoding produced `normalized`.
    pub encoding: ChannelEncoding,
    /// How the normalized value was derived, for the evidence layer to show verbatim.
    pub evidence: String,
}

impl DahuaChannel {
    /// Decode a block-table entry's channel, preferring the extended field when the
    /// entry's flag byte selects it.
    ///
    /// `flag_byte` is the byte at the entry's extended-channel-flag offset; bit 0 being
    /// set is what makes the extended field authoritative for that entry. When the flag
    /// is clear the legacy nibble is used, which is the correct reading for recorders
    /// with 16 or fewer channels.
    pub fn from_block_entry(
        legacy_byte: u8,
        flag_byte: u8,
        extended_byte: u8,
        profile: &OemProfile,
    ) -> Self {
        let flag_mask = u8_from(profile, key::BE_EXT_CHANNEL_FLAG_MASK, 0x01);
        let legacy_mask = u8_from(profile, key::BE_LEGACY_CHANNEL_MASK, 0x0F);
        let extended_mask = u8_from(profile, key::BE_EXT_CHANNEL_MASK, 0x1F);

        if flag_byte & flag_mask != 0 {
            let channel = (extended_byte & extended_mask) as u32;
            Self {
                normalized: channel,
                raw_value: extended_byte as u32,
                encoding: ChannelEncoding::BlockTableExtended,
                evidence: format!(
                    "extended-channel flag byte 0x{flag_byte:02X} has bit 0 set, so the extended \
                     field 0x{extended_byte:02X} & 0x{extended_mask:02X} = {channel} is \
                     authoritative for this entry (legacy nibble 0x{legacy_byte:02X} retained but \
                     not used)"
                ),
            }
        } else {
            let channel = ((legacy_byte & legacy_mask) as u32).saturating_add(1);
            Self {
                normalized: channel,
                raw_value: legacy_byte as u32,
                encoding: ChannelEncoding::BlockTableLegacyNibble,
                evidence: format!(
                    "extended-channel flag byte 0x{flag_byte:02X} does not select the extended \
                     field, so the legacy nibble 0x{legacy_byte:02X} & 0x{legacy_mask:02X} + 1 = \
                     {channel} applies"
                ),
            }
        }
    }

    /// Decode a DHAV frame header channel field, which is stored 0-based.
    ///
    /// `raw` is the field as read at the profile-declared offset and width. The low byte
    /// is the channel on every recorder generation this platform has evidence for; public
    /// implementations of the container treat the adjacent byte as a frame sub-number, so a
    /// value above 255 is reported but flagged rather than trusted.
    pub fn from_dhav_field(raw: u32) -> Self {
        let low = raw & 0xFF;
        let normalized = low.saturating_add(1);
        let evidence = if raw > 0xFF {
            format!(
                "DHAV channel field raw 0x{raw:04X}: low byte {low} + 1 = {normalized}. The high \
                 byte is non-zero; independent implementations of this container treat that byte \
                 as a frame sub-number rather than part of the channel, so the channel is reported \
                 from the low byte and the full raw field is retained for review"
            )
        } else {
            format!("DHAV channel field is 0-based: raw {raw} + 1 = {normalized}")
        };
        Self {
            normalized,
            raw_value: raw,
            encoding: ChannelEncoding::DhavFrameHeader,
            evidence,
        }
    }

    /// Whether two decodings name the same camera.
    pub fn agrees_with(&self, other: &DahuaChannel) -> bool {
        self.normalized == other.normalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::tests_support::dahua_profile;

    #[test]
    fn legacy_nibble_is_masked_and_one_based() {
        let p = dahua_profile();
        // 0x30 has high bits set that are not part of the channel.
        let ch = DahuaChannel::from_block_entry(0x30, 0x00, 0x00, &p);
        assert_eq!(ch.normalized, 1);
        assert_eq!(ch.encoding, ChannelEncoding::BlockTableLegacyNibble);
        assert_eq!(ch.raw_value, 0x30, "the raw byte is retained");

        let ch = DahuaChannel::from_block_entry(0x0F, 0x00, 0x00, &p);
        assert_eq!(ch.normalized, 16, "a full nibble is channel 16");
    }

    #[test]
    fn extended_channel_is_used_only_when_its_flag_bit_is_set() {
        let p = dahua_profile();
        // Flag clear: the extended byte is ignored even though it is populated.
        let legacy = DahuaChannel::from_block_entry(0x02, 0x00, 0x11, &p);
        assert_eq!(legacy.normalized, 3);
        assert_eq!(legacy.encoding, ChannelEncoding::BlockTableLegacyNibble);

        // Flag set: the extended byte wins and is NOT incremented.
        let extended = DahuaChannel::from_block_entry(0x02, 0x01, 0x11, &p);
        assert_eq!(extended.normalized, 0x11);
        assert_eq!(extended.encoding, ChannelEncoding::BlockTableExtended);
        assert_eq!(extended.raw_value, 0x11);
    }

    #[test]
    fn extended_channel_is_masked_to_five_bits() {
        let p = dahua_profile();
        let ch = DahuaChannel::from_block_entry(0x00, 0x01, 0xE4, &p);
        assert_eq!(ch.normalized, 0xE4 & 0x1F);
        assert_eq!(ch.raw_value, 0xE4, "the unmasked byte is still reported");
    }

    #[test]
    fn a_flag_byte_with_other_bits_set_still_selects_extended_only_via_bit_zero() {
        let p = dahua_profile();
        // 0x02 sets bit 1, not bit 0, so the extended field must not be selected.
        let ch = DahuaChannel::from_block_entry(0x04, 0x02, 0x1A, &p);
        assert_eq!(ch.encoding, ChannelEncoding::BlockTableLegacyNibble);
        assert_eq!(ch.normalized, 5);
        // 0x03 sets bit 0 as well, so it does select it.
        let ch = DahuaChannel::from_block_entry(0x04, 0x03, 0x1A, &p);
        assert_eq!(ch.encoding, ChannelEncoding::BlockTableExtended);
        assert_eq!(ch.normalized, 0x1A);
    }

    #[test]
    fn dhav_channel_field_is_zero_based() {
        let ch = DahuaChannel::from_dhav_field(0);
        assert_eq!(ch.normalized, 1);
        assert_eq!(ch.encoding, ChannelEncoding::DhavFrameHeader);
        assert_eq!(DahuaChannel::from_dhav_field(7).normalized, 8);
    }

    #[test]
    fn a_dhav_channel_field_above_one_byte_is_flagged_not_silently_trusted() {
        let ch = DahuaChannel::from_dhav_field(0x0105);
        assert_eq!(ch.normalized, 6, "decoded from the low byte");
        assert_eq!(ch.raw_value, 0x0105, "the full raw field is retained");
        assert!(
            ch.evidence.contains("frame sub-number"),
            "the ambiguity must be recorded: {}",
            ch.evidence
        );
    }

    #[test]
    fn encoding_source_is_never_lost() {
        let p = dahua_profile();
        let labels: Vec<&str> = vec![
            DahuaChannel::from_block_entry(0, 0, 0, &p).encoding.label(),
            DahuaChannel::from_block_entry(0, 1, 3, &p).encoding.label(),
            DahuaChannel::from_dhav_field(0).encoding.label(),
        ];
        let unique: std::collections::BTreeSet<_> = labels.iter().collect();
        assert_eq!(unique.len(), 3, "each encoding has a distinct label");
    }

    #[test]
    fn agreement_compares_normalized_values() {
        let p = dahua_profile();
        // Legacy nibble 2 -> channel 3; DHAV field 2 -> channel 3.
        let a = DahuaChannel::from_block_entry(0x02, 0x00, 0x00, &p);
        let b = DahuaChannel::from_dhav_field(2);
        assert!(a.agrees_with(&b));
        assert!(!a.agrees_with(&DahuaChannel::from_dhav_field(5)));
    }
}
