//! # Field-level forensic evidence
//!
//! Every Uniview field this crate reports can be expressed as a [`FieldEvidence`]: where it
//! sits physically, how wide it is, its exact raw bytes, what it decodes to, and how well
//! that interpretation is established. Unknown fields are reported with
//! [`Confidence::Unknown`] and their raw value, never with an invented label.

use serde::{Deserialize, Serialize};

use crate::layout::Confidence;

/// One parsed field, with its physical location and raw bytes preserved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldEvidence {
    /// Stable field name, e.g. `di.entry.sptoi`.
    pub name: String,
    /// Absolute physical byte offset of the first byte holding the field.
    pub physical_offset: u64,
    /// Width of the field in bits. Bit-packed fields (SPtoI, field A, the UI lock) are
    /// narrower than the bytes that hold them.
    pub size_bits: u32,
    /// Bit layout within the holding bytes, for packed fields (e.g. `+0x06[7:2] + +0x07`).
    pub bit_layout: Option<String>,
    /// Exact raw bytes holding the field, hex-encoded.
    pub raw_hex: String,
    /// Integer value, when the field is numeric.
    pub raw_value: Option<u64>,
    /// Decoded reading. For an unknown field this says so rather than naming a meaning.
    pub decoded: String,
    pub confidence: Confidence,
}

impl FieldEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        physical_offset: u64,
        size_bits: u32,
        bit_layout: Option<&str>,
        raw: &[u8],
        raw_value: Option<u64>,
        decoded: impl Into<String>,
        confidence: Confidence,
    ) -> Self {
        Self {
            name: name.into(),
            physical_offset,
            size_bits,
            bit_layout: bit_layout.map(str::to_string),
            raw_hex: hex::encode(raw),
            raw_value,
            decoded: decoded.into(),
            confidence,
        }
    }

    /// An opaque field whose meaning the platform has not established.
    pub fn unknown(name: impl Into<String>, physical_offset: u64, raw: &[u8]) -> Self {
        Self::new(
            name,
            physical_offset,
            (raw.len() as u32).saturating_mul(8),
            None,
            raw,
            None,
            "semantics unknown; preserved raw",
            Confidence::Unknown,
        )
    }
}
