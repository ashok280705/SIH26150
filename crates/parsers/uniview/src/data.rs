//! # DATA block resolution and raw extraction
//!
//! DATA is addressed in 16 KiB blocks by a DI entry's SPtoI:
//!
//! ```text
//!   data_offset = unit_base(gen, unit) + SPtoI * 0x4000        (CONFIRMED)
//! ```
//!
//! The reverse-engineered tooling copies DATA as **raw blocks**. The codec, container and
//! framing inside them are UNKNOWN, so this module:
//!
//! * reads exact bytes at exact physical offsets, read-only and bounds-checked;
//! * hashes what it reads (SHA-256 per region and over the concatenation);
//! * never labels the bytes as H.264, H.265, MP4, MPEG-PS or anything else, and never
//!   strips, inserts or normalises a single byte.
//!
//! Any codec identification is a separate, downstream signal (the recovery engine's own
//! byte classifier), not a Uniview parser claim.

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, Region};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::layout::{Generation, UniviewLayout};

/// Why an SPtoI could not be resolved to a DATA block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AddressError {
    /// Units are 1-based.
    UnitZero,
    /// SPtoI is 14-bit; the value does not fit.
    SptoiOutOfRange { sptoi: u32, limit: u64 },
    /// The block index lands inside the unit's DI region, not DATA.
    PointsIntoDi { sptoi: u32, di_blocks: u64 },
    /// 64-bit offset arithmetic overflowed.
    Overflow,
}

impl std::fmt::Display for AddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnitZero => write!(f, "unit numbers are 1-based; unit 0 does not exist"),
            Self::SptoiOutOfRange { sptoi, limit } => {
                write!(
                    f,
                    "SPtoI {sptoi} does not fit the 14-bit field (limit {limit})"
                )
            }
            Self::PointsIntoDi { sptoi, di_blocks } => write!(
                f,
                "SPtoI {sptoi} selects a block inside the DI region (blocks 0..{di_blocks})"
            ),
            Self::Overflow => write!(f, "physical offset arithmetic overflowed"),
        }
    }
}

/// A resolved DATA block address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataBlockAddress {
    pub generation: Generation,
    pub unit: u32,
    pub sptoi: u32,
    pub unit_base: u64,
    pub physical_offset: u64,
    pub length: u64,
}

impl DataBlockAddress {
    pub fn region(&self) -> Option<Region> {
        Region::new(self.physical_offset, self.length).ok()
    }
}

/// Resolve `(generation, unit, SPtoI)` to the physical DATA block it selects.
pub fn resolve(
    layout: &UniviewLayout,
    generation: Generation,
    unit: u32,
    sptoi: u32,
) -> Result<DataBlockAddress, AddressError> {
    if unit == 0 {
        return Err(AddressError::UnitZero);
    }
    let limit = layout.sptoi_limit();
    if u64::from(sptoi) >= limit {
        return Err(AddressError::SptoiOutOfRange { sptoi, limit });
    }
    let di_blocks = layout.di_blocks();
    if u64::from(sptoi) < di_blocks {
        return Err(AddressError::PointsIntoDi { sptoi, di_blocks });
    }
    let unit_base = layout
        .unit_base(generation, unit)
        .ok_or(AddressError::Overflow)?;
    let physical_offset = layout
        .data_offset(generation, unit, sptoi)
        .ok_or(AddressError::Overflow)?;
    Ok(DataBlockAddress {
        generation,
        unit,
        sptoi,
        unit_base,
        physical_offset,
        length: layout.data_block_size,
    })
}

/// Raw bytes extracted from evidence, with their provenance and digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedData {
    /// Exact physical regions read, in order.
    pub regions: Vec<Region>,
    /// SHA-256 of each region's bytes, hex.
    pub region_sha256: Vec<String>,
    /// SHA-256 of the concatenation, hex.
    pub sha256: String,
    /// The exact bytes, concatenated in region order. Nothing inserted or removed.
    pub bytes: Vec<u8>,
    /// Always the same statement: what the bytes are, and are not, known to be.
    pub content_note: String,
}

/// The fixed content statement attached to every extraction.
pub const CONTENT_NOTE: &str =
    "raw Uniview DATA bytes copied verbatim; codec, container and framing are UNKNOWN and no \
     format is claimed";

/// Read exactly the given regions, in order. Every region must lie wholly inside the image,
/// and the total must not exceed the profile's extraction cap. Read-only.
pub fn extract_regions(
    reader: &dyn EvidenceReader,
    layout: &UniviewLayout,
    regions: &[Region],
) -> Result<ExtractedData, ForensicError> {
    let image_len = reader.len();
    let mut total = 0u64;
    for r in regions {
        let end = r.end().ok_or_else(|| {
            ForensicError::out_of_bounds("uniview_extract", r.offset, r.length, image_len)
        })?;
        if end > image_len {
            return Err(ForensicError::out_of_bounds(
                "uniview_extract",
                r.offset,
                r.length,
                image_len,
            ));
        }
        total = total.saturating_add(r.length);
    }
    if total > layout.max_extract_bytes {
        return Err(ForensicError::corrupt(
            "uniview_extract",
            format!(
                "requested {total} byte(s) exceeds the profile extraction cap of {} byte(s); \
                 extract in smaller parts rather than truncating",
                layout.max_extract_bytes
            ),
        ));
    }

    let mut bytes = Vec::with_capacity(usize::try_from(total).unwrap_or(0));
    let mut region_sha256 = Vec::with_capacity(regions.len());
    let mut all = Sha256::new();
    for r in regions {
        let len = usize::try_from(r.length).map_err(|_| {
            ForensicError::out_of_bounds("uniview_extract", r.offset, r.length, image_len)
        })?;
        let buf = reader.read_exact_at(r.offset, len)?;
        region_sha256.push(hex::encode(Sha256::digest(&buf)));
        all.update(&buf);
        bytes.extend_from_slice(&buf);
    }
    Ok(ExtractedData {
        regions: regions.to_vec(),
        region_sha256,
        sha256: hex::encode(all.finalize()),
        bytes,
        content_note: CONTENT_NOTE.to_string(),
    })
}

/// Read one DATA block by `(generation, unit, SPtoI)`.
pub fn read_data_block(
    reader: &dyn EvidenceReader,
    layout: &UniviewLayout,
    generation: Generation,
    unit: u32,
    sptoi: u32,
) -> Result<(DataBlockAddress, ExtractedData), ForensicError> {
    let addr = resolve(layout, generation, unit, sptoi)
        .map_err(|e| ForensicError::corrupt("uniview_data_block", e.to_string()))?;
    let region = addr.region().ok_or_else(|| {
        ForensicError::out_of_bounds(
            "uniview_data_block",
            addr.physical_offset,
            addr.length,
            reader.len(),
        )
    })?;
    Ok((addr, extract_regions(reader, layout, &[region])?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::tests_support::uniview_profile;
    use crate::testing::{build, SparseReader};

    fn layout() -> UniviewLayout {
        UniviewLayout::from_profile(&uniview_profile())
    }

    #[test]
    fn resolution_uses_block_index_arithmetic() {
        let l = layout();
        let a = resolve(&l, Generation::New, 2, 0x3FFF).unwrap();
        assert_eq!(a.unit_base, 0x2001_4000);
        assert_eq!(a.physical_offset, 0x2001_4000 + 0x3FFF * 0x4000);
        assert_eq!(a.length, 0x4000);
        assert_eq!(
            resolve(&l, Generation::Old, 1, 16).unwrap().physical_offset,
            0x0001_4000 + 0x40000
        );
        assert_eq!(
            resolve(&l, Generation::Old, 0, 16),
            Err(AddressError::UnitZero)
        );
        assert!(matches!(
            resolve(&l, Generation::Old, 1, 0x4000),
            Err(AddressError::SptoiOutOfRange { .. })
        ));
        assert!(matches!(
            resolve(&l, Generation::Old, 1, 15),
            Err(AddressError::PointsIntoDi { .. })
        ));
    }

    #[test]
    fn a_block_is_extracted_verbatim_at_its_offset_with_hashes() {
        let l = layout();
        let block = build::data_block(0x5A);
        let off = 0x0001_4000 + 20 * 0x4000;
        let r = SparseReader::new(0x0001_4000 + 0x1000_0000).with(off, &block);
        let (addr, x) = read_data_block(&r, &l, Generation::Old, 1, 20).unwrap();
        assert_eq!(addr.physical_offset, off);
        assert_eq!(x.bytes, block);
        assert_eq!(x.regions, vec![Region::new(off, 0x4000).unwrap()]);
        assert_eq!(x.sha256, hex::encode(Sha256::digest(&block)));
        assert_eq!(x.region_sha256[0], x.sha256);
        assert!(x.content_note.contains("UNKNOWN"));
    }

    #[test]
    fn extraction_is_bounds_checked_and_never_truncated_to_fit() {
        let l = layout();
        let r = SparseReader::new(0x0001_4000 + 17 * 0x4000 + 10);
        // Block 17 extends past the image end.
        assert!(read_data_block(&r, &l, Generation::Old, 1, 17).is_err());
        assert!(extract_regions(&r, &l, &[Region::new(u64::MAX - 1, 1).unwrap()]).is_err());
        let mut small = l.clone();
        small.max_extract_bytes = 0x3FFF;
        assert!(read_data_block(&r, &small, Generation::Old, 1, 16).is_err());
        // Multi-region concatenation keeps order.
        let r = SparseReader::new(0x100).with(0, &[1, 2, 3, 4]);
        let x = extract_regions(
            &r,
            &l,
            &[Region::new(2, 2).unwrap(), Region::new(0, 2).unwrap()],
        )
        .unwrap();
        assert_eq!(x.bytes, vec![3, 4, 1, 2]);
    }
}
