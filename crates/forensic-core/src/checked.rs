//! # Checked Arithmetic and Bounds Primitives
//!
//! Every offset/size/length computation in the platform MUST go through these helpers —
//! no raw `+`/`*` on evidence-derived offsets (Req 24.1, 24.2, 24.4).
//!
//! Overflowing and out-of-range computations return errors instead of wrapping or
//! panicking. These helpers are the only sanctioned offset arithmetic path.

use crate::error::ForensicError;
use crate::region::Region;

/// Checked addition of two `u64` values. Returns `ArithmeticOverflow` on overflow.
pub fn checked_add(a: u64, b: u64) -> Result<u64, ForensicError> {
    a.checked_add(b)
        .ok_or_else(|| ForensicError::overflow(format!("{a} + {b} overflows u64")))
}

/// Checked multiplication of two `u64` values. Returns `ArithmeticOverflow` on overflow.
pub fn checked_mul(a: u64, b: u64) -> Result<u64, ForensicError> {
    a.checked_mul(b)
        .ok_or_else(|| ForensicError::overflow(format!("{a} * {b} overflows u64")))
}

/// Checked subtraction of two `u64` values. Returns `ArithmeticOverflow` on underflow.
pub fn checked_sub(a: u64, b: u64) -> Result<u64, ForensicError> {
    a.checked_sub(b)
        .ok_or_else(|| ForensicError::overflow(format!("{a} - {b} underflows u64")))
}

/// Compute `sector_size × start_sector` with overflow check.
///
/// This is the canonical way to compute a byte offset from a sector address.
pub fn checked_sector_offset(sector: u64, sector_size: u64) -> Result<u64, ForensicError> {
    if sector_size == 0 {
        return Err(ForensicError::corrupt(
            "checked_sector_offset",
            "sector_size is zero",
        ));
    }
    checked_mul(sector, sector_size)
}

/// Compute `offset + length` as an exclusive end offset with overflow check.
pub fn checked_end_offset(offset: u64, length: u64) -> Result<u64, ForensicError> {
    checked_add(offset, length)
}

/// Validate that a region `[offset, offset+length)` falls within `[0, source_len)`.
///
/// Returns `OutOfBounds` if any part of the region extends beyond the source.
pub fn validate_region_bounds(region: &Region, source_len: u64) -> Result<(), ForensicError> {
    if region.is_empty() {
        // A zero-length region at or before source_len is valid (it's a position marker).
        if region.offset > source_len {
            return Err(ForensicError::out_of_bounds(
                "zero-length region beyond source",
                region.offset,
                0,
                source_len,
            ));
        }
        return Ok(());
    }

    let end = checked_end_offset(region.offset, region.length).map_err(|_| {
        ForensicError::out_of_bounds(
            "region end overflows u64",
            region.offset,
            region.length,
            source_len,
        )
    })?;

    if end > source_len {
        return Err(ForensicError::out_of_bounds(
            "region extends beyond source",
            region.offset,
            region.length,
            source_len,
        ));
    }

    Ok(())
}

/// Validate that a byte offset and length fall within source bounds.
///
/// Convenience wrapper around [`validate_region_bounds`] for callers that don't already
/// have a `Region`.
pub fn validate_bounds(offset: u64, length: u64, source_len: u64) -> Result<(), ForensicError> {
    // Construct a Region just for validation; Region::new already checks overflow.
    let region = Region::new(offset, length).map_err(|_| {
        ForensicError::out_of_bounds("offset + length overflows", offset, length, source_len)
    })?;
    validate_region_bounds(&region, source_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- checked_add ---

    #[test]
    fn add_normal() {
        assert_eq!(checked_add(10, 20).unwrap(), 30);
    }

    #[test]
    fn add_zero() {
        assert_eq!(checked_add(0, 0).unwrap(), 0);
        assert_eq!(checked_add(u64::MAX, 0).unwrap(), u64::MAX);
    }

    #[test]
    fn add_overflow() {
        assert!(checked_add(u64::MAX, 1).is_err());
        assert!(checked_add(u64::MAX, u64::MAX).is_err());
    }

    // --- checked_mul ---

    #[test]
    fn mul_normal() {
        assert_eq!(checked_mul(512, 1000).unwrap(), 512_000);
    }

    #[test]
    fn mul_zero() {
        assert_eq!(checked_mul(0, u64::MAX).unwrap(), 0);
    }

    #[test]
    fn mul_overflow() {
        assert!(checked_mul(u64::MAX, 2).is_err());
        assert!(checked_mul(1 << 40, 1 << 40).is_err());
    }

    // --- checked_sub ---

    #[test]
    fn sub_normal() {
        assert_eq!(checked_sub(100, 30).unwrap(), 70);
    }

    #[test]
    fn sub_underflow() {
        assert!(checked_sub(10, 20).is_err());
    }

    // --- checked_sector_offset ---

    #[test]
    fn sector_offset_normal() {
        assert_eq!(checked_sector_offset(100, 512).unwrap(), 51200);
    }

    #[test]
    fn sector_offset_zero_sector_size() {
        assert!(checked_sector_offset(100, 0).is_err());
    }

    #[test]
    fn sector_offset_overflow() {
        assert!(checked_sector_offset(u64::MAX, 512).is_err());
    }

    // --- validate_region_bounds ---

    #[test]
    fn valid_region() {
        let r = Region::new(0, 1024).unwrap();
        assert!(validate_region_bounds(&r, 2048).is_ok());
    }

    #[test]
    fn region_at_boundary() {
        let r = Region::new(0, 1024).unwrap();
        assert!(validate_region_bounds(&r, 1024).is_ok());
    }

    #[test]
    fn region_beyond_source() {
        let r = Region::new(900, 200).unwrap();
        assert!(validate_region_bounds(&r, 1024).is_err());
    }

    #[test]
    fn zero_length_region_within_source() {
        let r = Region::point(500);
        assert!(validate_region_bounds(&r, 1024).is_ok());
    }

    #[test]
    fn zero_length_region_at_end() {
        let r = Region::point(1024);
        assert!(validate_region_bounds(&r, 1024).is_ok());
    }

    #[test]
    fn zero_length_region_beyond_source() {
        let r = Region::point(1025);
        assert!(validate_region_bounds(&r, 1024).is_err());
    }

    // --- validate_bounds ---

    #[test]
    fn validate_bounds_normal() {
        assert!(validate_bounds(100, 200, 1024).is_ok());
    }

    #[test]
    fn validate_bounds_overflow() {
        assert!(validate_bounds(u64::MAX, 1, 1024).is_err());
    }

    #[test]
    fn validate_bounds_beyond_source() {
        assert!(validate_bounds(1000, 100, 1024).is_err());
    }

    // --- Property test: no input panics ---

    #[test]
    fn no_panic_on_extreme_values() {
        // Exercise extreme values — none should panic.
        let extremes = [0, 1, u64::MAX / 2, u64::MAX - 1, u64::MAX];
        for &a in &extremes {
            for &b in &extremes {
                let _ = checked_add(a, b);
                let _ = checked_mul(a, b);
                let _ = checked_sub(a, b);
                let _ = checked_sector_offset(a, b);
                let _ = checked_end_offset(a, b);
                // Region::new may fail, but must not panic.
                if let Ok(r) = Region::new(a, b) {
                    for &src in &extremes {
                        let _ = validate_region_bounds(&r, src);
                    }
                }
            }
        }
    }
}
