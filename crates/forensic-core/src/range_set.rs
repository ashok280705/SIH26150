//! # RangeSet — canonical half-open range algebra
//!
//! A `RangeSet` is an immutable-by-convention, canonical collection of [`Region`]s
//! (half-open `[start, end)` byte ranges) that always upholds these invariants:
//!
//! * ranges are sorted by start offset,
//! * ranges never overlap,
//! * adjacent ranges are merged (`[100,200)` + `[200,300)` becomes `[100,300)`),
//! * empty (zero-length) ranges are never stored,
//! * the representation is canonical — two `RangeSet`s built from equivalent inputs
//!   are structurally equal.
//!
//! This is the single canonical range-merging implementation for the platform. It is
//! built on the existing [`Region`] type and does **not** introduce a second range
//! model. `Region` semantics (half-open, checked construction) are preserved exactly.
//!
//! All boundary arithmetic uses checked/saturating operations so no evidence-derived
//! computation can overflow or panic (Req 24). Where new `Region`s are created, the
//! fallible [`Region::new`] path is used and the error is propagated rather than
//! unwrapped.

use serde::{Deserialize, Serialize};

use crate::error::ForensicError;
use crate::region::Region;

/// Exclusive end offset of a region, saturating to `u64::MAX` if the declared
/// `offset + length` overflowed (mirrors [`Region::overlaps`] semantics). A region
/// constructed through [`Region::new`] can never overflow, so this only guards against
/// hand-built struct literals.
#[inline]
fn region_end(r: &Region) -> u64 {
    r.end().unwrap_or(u64::MAX)
}

/// A canonical set of non-overlapping, non-adjacent, sorted half-open [`Region`]s.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeSet {
    /// Invariant: sorted by offset, disjoint, non-adjacent, no zero-length entries.
    ranges: Vec<Region>,
}

impl RangeSet {
    /// Create an empty range set.
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Build a canonical range set from an iterator of regions.
    ///
    /// Returns [`ForensicError::ArithmeticOverflow`] if any region's declared
    /// `offset + length` overflows `u64`.
    pub fn from_regions(regions: impl IntoIterator<Item = Region>) -> Result<Self, ForensicError> {
        let mut set = Self::new();
        for r in regions {
            set.add(r)?;
        }
        Ok(set)
    }

    /// Normalize a vector of regions into the canonical form: drop empties, sort by
    /// `(offset, end)`, then merge overlapping **and** adjacent ranges under one
    /// predicate (`next.start <= current.end`).
    fn normalize(mut ranges: Vec<Region>) -> Vec<Region> {
        ranges.retain(|r| !r.is_empty());
        ranges.sort_by(|a, b| {
            a.offset
                .cmp(&b.offset)
                .then_with(|| region_end(a).cmp(&region_end(b)))
        });

        let mut out: Vec<Region> = Vec::with_capacity(ranges.len());
        for r in ranges {
            match out.last_mut() {
                Some(last) => {
                    let last_end = region_end(last);
                    // One canonical merge predicate: touch (==) or overlap (<) merges.
                    if r.offset <= last_end {
                        let new_end = last_end.max(region_end(&r));
                        // `new_end >= last.offset` always holds, so this subtraction is
                        // exact; saturating_sub avoids any panic path.
                        last.length = new_end.saturating_sub(last.offset);
                    } else {
                        out.push(r);
                    }
                }
                None => out.push(r),
            }
        }
        out
    }

    /// Add a region to the set, merging with any overlapping or adjacent ranges.
    ///
    /// Empty regions are ignored (never stored). Returns
    /// [`ForensicError::ArithmeticOverflow`] if the region's declared end overflows.
    pub fn add(&mut self, region: Region) -> Result<(), ForensicError> {
        if region.is_empty() {
            return Ok(());
        }
        if region.end().is_none() {
            return Err(ForensicError::overflow(format!(
                "RangeSet::add: region {region} end overflows u64"
            )));
        }
        let mut ranges = std::mem::take(&mut self.ranges);
        ranges.push(region);
        self.ranges = Self::normalize(ranges);
        Ok(())
    }

    /// Subtract a region's span from the set. Ranges wholly inside the cut are removed;
    /// ranges straddling a boundary are trimmed; ranges spanning the cut are split.
    ///
    /// The canonical invariant is preserved.
    pub fn subtract(&mut self, region: Region) -> Result<(), ForensicError> {
        if region.is_empty() || self.ranges.is_empty() {
            return Ok(());
        }
        let cut_start = region.offset;
        let cut_end = region_end(&region);

        let mut out: Vec<Region> = Vec::with_capacity(self.ranges.len());
        for r in &self.ranges {
            let rs = r.offset;
            let re = region_end(r);
            // No overlap: keep as-is.
            if re <= cut_start || rs >= cut_end {
                out.push(*r);
                continue;
            }
            // Left remainder [rs, cut_start).
            if rs < cut_start {
                out.push(Region::new(rs, cut_start.saturating_sub(rs))?);
            }
            // Right remainder [cut_end, re).
            if cut_end < re {
                out.push(Region::new(cut_end, re.saturating_sub(cut_end))?);
            }
        }
        // Trimming preserves sort order and cannot introduce overlaps/adjacency, but
        // normalize is cheap and guarantees the invariant defensively.
        self.ranges = Self::normalize(out);
        Ok(())
    }

    /// Union with another set. Result is canonical.
    pub fn union(&self, other: &RangeSet) -> RangeSet {
        let mut ranges = self.ranges.clone();
        ranges.extend_from_slice(&other.ranges);
        RangeSet {
            ranges: Self::normalize(ranges),
        }
    }

    /// Intersection with another set: the parts present in both. Result is canonical.
    pub fn intersect(&self, other: &RangeSet) -> RangeSet {
        let mut ranges = Vec::new();
        for a in &self.ranges {
            for b in &other.ranges {
                if let Some(i) = a.intersection(b) {
                    if !i.is_empty() {
                        ranges.push(i);
                    }
                }
            }
        }
        RangeSet {
            ranges: Self::normalize(ranges),
        }
    }

    /// The parts of `universe` **not** covered by this set.
    ///
    /// Returns a canonical set clipped to `universe`. An empty universe yields an empty
    /// set. Any newly created region uses checked construction.
    pub fn complement_within(&self, universe: Region) -> Result<RangeSet, ForensicError> {
        if universe.is_empty() {
            return Ok(RangeSet::new());
        }
        let u_start = universe.offset;
        let u_end = region_end(&universe);

        let mut out: Vec<Region> = Vec::new();
        let mut cursor = u_start;
        for r in &self.ranges {
            let rs = r.offset;
            let re = region_end(r);
            if re <= u_start {
                continue;
            }
            if rs >= u_end {
                break;
            }
            let seg_start = rs.max(u_start);
            if seg_start > cursor {
                out.push(Region::new(cursor, seg_start.saturating_sub(cursor))?);
            }
            cursor = cursor.max(re.min(u_end));
            if cursor >= u_end {
                break;
            }
        }
        if cursor < u_end {
            out.push(Region::new(cursor, u_end.saturating_sub(cursor))?);
        }
        // Produced in order, disjoint, non-adjacent by construction.
        Ok(RangeSet { ranges: out })
    }

    /// Whether `byte_offset` falls within any stored range.
    pub fn contains(&self, byte_offset: u64) -> bool {
        self.ranges.iter().any(|r| r.contains(byte_offset))
    }

    /// Whether the set fully covers every byte of `region`.
    ///
    /// An empty region is vacuously covered. Because the set is non-adjacent and
    /// disjoint, a non-empty region can only be fully covered by a single stored range.
    pub fn covers(&self, region: &Region) -> bool {
        if region.is_empty() {
            return true;
        }
        let start = region.offset;
        let end = region_end(region);
        self.ranges
            .iter()
            .any(|r| r.offset <= start && region_end(r) >= end)
    }

    /// Total number of bytes covered by the set (sum of disjoint range lengths).
    ///
    /// Disjoint ranges within `u64` can never sum beyond `u64::MAX`; saturating_add
    /// guards defensively regardless.
    pub fn total_length(&self) -> u64 {
        self.ranges
            .iter()
            .fold(0u64, |acc, r| acc.saturating_add(r.length))
    }

    /// Number of canonical ranges stored.
    pub fn count(&self) -> usize {
        self.ranges.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// The smallest start offset in the set, or `None` if empty.
    pub fn min(&self) -> Option<u64> {
        self.ranges.first().map(|r| r.offset)
    }

    /// The largest exclusive end offset in the set, or `None` if empty.
    pub fn max(&self) -> Option<u64> {
        self.ranges.last().map(region_end)
    }

    /// Ordered iteration over the canonical ranges.
    pub fn iter(&self) -> std::slice::Iter<'_, Region> {
        self.ranges.iter()
    }

    /// Borrow the canonical ranges as a slice (already sorted and disjoint).
    pub fn ranges(&self) -> &[Region] {
        &self.ranges
    }
}

impl<'a> IntoIterator for &'a RangeSet {
    type Item = &'a Region;
    type IntoIter = std::slice::Iter<'a, Region>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(offset: u64, length: u64) -> Region {
        Region::new(offset, length).unwrap()
    }

    /// Assert the canonical invariants on a set: sorted, disjoint, non-adjacent, no empties.
    fn assert_canonical(set: &RangeSet) {
        let ranges = set.ranges();
        for w in ranges.windows(2) {
            let a = &w[0];
            let b = &w[1];
            assert!(!a.is_empty(), "empty range stored: {a}");
            let a_end = a.end().unwrap();
            // Strictly increasing and non-adjacent: b must start strictly after a ends.
            assert!(
                a_end < b.offset,
                "ranges not disjoint+non-adjacent: {a} then {b}"
            );
        }
        if let Some(last) = ranges.last() {
            assert!(!last.is_empty(), "empty range stored at tail: {last}");
        }
    }

    #[test]
    fn empty_set() {
        let s = RangeSet::new();
        assert!(s.is_empty());
        assert_eq!(s.count(), 0);
        assert_eq!(s.total_length(), 0);
        assert_eq!(s.min(), None);
        assert_eq!(s.max(), None);
        assert!(!s.contains(0));
        assert_canonical(&s);
    }

    #[test]
    fn single_range() {
        let mut s = RangeSet::new();
        s.add(r(100, 50)).unwrap();
        assert_eq!(s.count(), 1);
        assert_eq!(s.total_length(), 50);
        assert_eq!(s.min(), Some(100));
        assert_eq!(s.max(), Some(150));
        assert!(s.contains(100));
        assert!(s.contains(149));
        assert!(!s.contains(150));
        assert!(!s.contains(99));
        assert_canonical(&s);
    }

    #[test]
    fn empty_region_is_not_stored() {
        let mut s = RangeSet::new();
        s.add(Region::point(100)).unwrap();
        s.add(r(0, 0)).unwrap();
        assert!(s.is_empty());
        assert_canonical(&s);
    }

    #[test]
    fn duplicate_insertion_is_idempotent() {
        let mut s = RangeSet::new();
        s.add(r(100, 50)).unwrap();
        s.add(r(100, 50)).unwrap();
        s.add(r(100, 50)).unwrap();
        assert_eq!(s.count(), 1);
        assert_eq!(s.ranges()[0], r(100, 50));
        assert_canonical(&s);
    }

    #[test]
    fn adjacent_ranges_merge() {
        let mut s = RangeSet::new();
        s.add(r(100, 100)).unwrap(); // [100,200)
        s.add(r(200, 100)).unwrap(); // [200,300)
        assert_eq!(s.count(), 1);
        assert_eq!(s.ranges()[0], r(100, 200)); // [100,300)
        assert_canonical(&s);
    }

    #[test]
    fn overlapping_ranges_merge() {
        let mut s = RangeSet::new();
        s.add(r(100, 150)).unwrap(); // [100,250)
        s.add(r(200, 100)).unwrap(); // [200,300)
        assert_eq!(s.count(), 1);
        assert_eq!(s.ranges()[0], r(100, 200)); // [100,300)
        assert_canonical(&s);
    }

    #[test]
    fn disjoint_ranges_stay_separate() {
        let mut s = RangeSet::new();
        s.add(r(100, 50)).unwrap(); // [100,150)
        s.add(r(200, 50)).unwrap(); // [200,250)
        assert_eq!(s.count(), 2);
        assert_eq!(s.total_length(), 100);
        assert_canonical(&s);
    }

    #[test]
    fn nested_ranges_merge_to_outer() {
        let mut s = RangeSet::new();
        s.add(r(100, 200)).unwrap(); // [100,300)
        s.add(r(150, 50)).unwrap(); // [150,200) fully inside
        assert_eq!(s.count(), 1);
        assert_eq!(s.ranges()[0], r(100, 200));
        assert_canonical(&s);
    }

    #[test]
    fn unsorted_insertion_yields_sorted_canonical() {
        let mut s = RangeSet::new();
        s.add(r(500, 50)).unwrap();
        s.add(r(100, 50)).unwrap();
        s.add(r(300, 50)).unwrap();
        let offsets: Vec<u64> = s.iter().map(|r| r.offset).collect();
        assert_eq!(offsets, vec![100, 300, 500]);
        assert_canonical(&s);
    }

    #[test]
    fn subtract_no_overlap_is_noop() {
        let mut s = RangeSet::new();
        s.add(r(100, 100)).unwrap();
        s.subtract(r(300, 100)).unwrap();
        assert_eq!(s.count(), 1);
        assert_eq!(s.ranges()[0], r(100, 100));
        assert_canonical(&s);
    }

    #[test]
    fn subtract_entire_range_yields_empty() {
        let mut s = RangeSet::new();
        s.add(r(100, 100)).unwrap();
        s.subtract(r(100, 100)).unwrap();
        assert!(s.is_empty());
        assert_canonical(&s);
    }

    #[test]
    fn subtract_superset_yields_empty() {
        let mut s = RangeSet::new();
        s.add(r(100, 100)).unwrap();
        s.subtract(r(0, 1000)).unwrap();
        assert!(s.is_empty());
        assert_canonical(&s);
    }

    #[test]
    fn subtract_left_edge_trims() {
        let mut s = RangeSet::new();
        s.add(r(100, 100)).unwrap(); // [100,200)
        s.subtract(r(50, 100)).unwrap(); // remove [50,150)
        assert_eq!(s.count(), 1);
        assert_eq!(s.ranges()[0], r(150, 50)); // [150,200)
        assert_canonical(&s);
    }

    #[test]
    fn subtract_right_edge_trims() {
        let mut s = RangeSet::new();
        s.add(r(100, 100)).unwrap(); // [100,200)
        s.subtract(r(150, 100)).unwrap(); // remove [150,250)
        assert_eq!(s.count(), 1);
        assert_eq!(s.ranges()[0], r(100, 50)); // [100,150)
        assert_canonical(&s);
    }

    #[test]
    fn subtract_middle_splits_into_two() {
        let mut s = RangeSet::new();
        s.add(r(100, 200)).unwrap(); // [100,300)
        s.subtract(r(150, 50)).unwrap(); // remove [150,200)
        assert_eq!(s.count(), 2);
        assert_eq!(s.ranges()[0], r(100, 50)); // [100,150)
        assert_eq!(s.ranges()[1], r(200, 100)); // [200,300)
        assert_canonical(&s);
    }

    #[test]
    fn subtract_spanning_multiple_ranges() {
        let mut s = RangeSet::new();
        s.add(r(100, 50)).unwrap(); // [100,150)
        s.add(r(200, 50)).unwrap(); // [200,250)
        s.add(r(300, 50)).unwrap(); // [300,350)
        s.subtract(r(120, 200)).unwrap(); // remove [120,320)
        assert_eq!(s.count(), 2);
        assert_eq!(s.ranges()[0], r(100, 20)); // [100,120)
        assert_eq!(s.ranges()[1], r(320, 30)); // [320,350)
        assert_canonical(&s);
    }

    #[test]
    fn union_basic() {
        let a = RangeSet::from_regions([r(100, 50), r(300, 50)]).unwrap();
        let b = RangeSet::from_regions([r(200, 50)]).unwrap();
        let u = a.union(&b);
        assert_eq!(u.count(), 3);
        assert_eq!(u.total_length(), 150);
        assert_canonical(&u);
    }

    #[test]
    fn union_merges_across_sets() {
        let a = RangeSet::from_regions([r(100, 100)]).unwrap(); // [100,200)
        let b = RangeSet::from_regions([r(200, 100)]).unwrap(); // [200,300)
        let u = a.union(&b);
        assert_eq!(u.count(), 1);
        assert_eq!(u.ranges()[0], r(100, 200));
        assert_canonical(&u);
    }

    #[test]
    fn union_with_empty_is_identity() {
        let a = RangeSet::from_regions([r(100, 50), r(300, 50)]).unwrap();
        let empty = RangeSet::new();
        assert_eq!(a.union(&empty), a);
        assert_eq!(empty.union(&a), a);
    }

    #[test]
    fn union_is_commutative() {
        let a = RangeSet::from_regions([r(100, 100), r(400, 50)]).unwrap();
        let b = RangeSet::from_regions([r(150, 100), r(500, 50)]).unwrap();
        assert_eq!(a.union(&b), b.union(&a));
    }

    #[test]
    fn intersect_basic() {
        let a = RangeSet::from_regions([r(100, 100)]).unwrap(); // [100,200)
        let b = RangeSet::from_regions([r(150, 100)]).unwrap(); // [150,250)
        let i = a.intersect(&b);
        assert_eq!(i.count(), 1);
        assert_eq!(i.ranges()[0], r(150, 50)); // [150,200)
        assert_canonical(&i);
    }

    #[test]
    fn intersect_with_empty_is_empty() {
        let a = RangeSet::from_regions([r(100, 100)]).unwrap();
        let empty = RangeSet::new();
        assert!(a.intersect(&empty).is_empty());
        assert!(empty.intersect(&a).is_empty());
    }

    #[test]
    fn intersect_self_is_self() {
        let a = RangeSet::from_regions([r(100, 100), r(400, 50)]).unwrap();
        assert_eq!(a.intersect(&a), a);
    }

    #[test]
    fn intersect_is_commutative() {
        let a = RangeSet::from_regions([r(100, 100), r(400, 100)]).unwrap();
        let b = RangeSet::from_regions([r(150, 300)]).unwrap();
        assert_eq!(a.intersect(&b), b.intersect(&a));
    }

    #[test]
    fn intersect_adjacent_is_empty() {
        let a = RangeSet::from_regions([r(100, 100)]).unwrap(); // [100,200)
        let b = RangeSet::from_regions([r(200, 100)]).unwrap(); // [200,300)
        assert!(a.intersect(&b).is_empty());
    }

    #[test]
    fn complement_within_basic() {
        let s = RangeSet::from_regions([r(100, 50), r(200, 50)]).unwrap();
        let comp = s.complement_within(r(0, 300)).unwrap();
        // Gaps: [0,100), [150,200), [250,300)
        assert_eq!(comp.count(), 3);
        assert_eq!(comp.ranges()[0], r(0, 100));
        assert_eq!(comp.ranges()[1], r(150, 50));
        assert_eq!(comp.ranges()[2], r(250, 50));
        assert_canonical(&comp);
    }

    #[test]
    fn complement_of_empty_is_universe() {
        let s = RangeSet::new();
        let comp = s.complement_within(r(0, 500)).unwrap();
        assert_eq!(comp.count(), 1);
        assert_eq!(comp.ranges()[0], r(0, 500));
    }

    #[test]
    fn complement_of_full_universe_is_empty() {
        let s = RangeSet::from_regions([r(0, 500)]).unwrap();
        let comp = s.complement_within(r(0, 500)).unwrap();
        assert!(comp.is_empty());
    }

    #[test]
    fn complement_plus_original_covers_universe() {
        let universe = r(0, 1000);
        let s = RangeSet::from_regions([r(100, 50), r(400, 200), r(900, 50)]).unwrap();
        let comp = s.complement_within(universe).unwrap();
        let recombined = s.union(&comp);
        assert!(recombined.covers(&universe));
        assert_eq!(recombined.count(), 1);
        assert_eq!(recombined.ranges()[0], universe);
        // The two pieces are disjoint, so lengths add up to the universe.
        assert_eq!(s.total_length() + comp.total_length(), universe.length);
    }

    #[test]
    fn covers_semantics() {
        let s = RangeSet::from_regions([r(100, 100)]).unwrap(); // [100,200)
        assert!(s.covers(&r(100, 100)));
        assert!(s.covers(&r(120, 50)));
        assert!(!s.covers(&r(150, 100))); // extends past 200
        assert!(!s.covers(&r(50, 100))); // starts before 100
        assert!(s.covers(&Region::point(500))); // empty region vacuously covered
    }

    #[test]
    fn covers_requires_single_contiguous_range() {
        // Non-adjacent ranges cannot jointly cover a spanning region.
        let s = RangeSet::from_regions([r(100, 50), r(200, 50)]).unwrap();
        assert!(!s.covers(&r(100, 150)));
    }

    #[test]
    fn total_length_equals_sum_of_disjoint_lengths() {
        let s = RangeSet::from_regions([r(0, 10), r(100, 20), r(1000, 30)]).unwrap();
        assert_eq!(s.total_length(), 60);
    }

    #[test]
    fn single_byte_regions() {
        let mut s = RangeSet::new();
        s.add(r(5, 1)).unwrap(); // [5,6)
        s.add(r(6, 1)).unwrap(); // [6,7) adjacent -> merges
        assert_eq!(s.count(), 1);
        assert_eq!(s.ranges()[0], r(5, 2)); // [5,7)
        s.add(r(9, 1)).unwrap(); // [9,10) disjoint
        assert_eq!(s.count(), 2);
        assert!(s.contains(5));
        assert!(s.contains(6));
        assert!(!s.contains(7));
        assert!(s.contains(9));
        assert_canonical(&s);
    }

    #[test]
    fn max_boundary_range() {
        // A region ending exactly at u64::MAX.
        let start = u64::MAX - 100;
        let reg = Region::new(start, 100).unwrap(); // [MAX-100, MAX)
        let mut s = RangeSet::new();
        s.add(reg).unwrap();
        assert_eq!(s.max(), Some(u64::MAX));
        assert_eq!(s.min(), Some(start));
        assert!(s.contains(u64::MAX - 1));
        assert!(!s.contains(u64::MAX)); // half-open: MAX itself not contained
        assert_canonical(&s);
    }

    #[test]
    fn near_max_adjacent_merge() {
        let mut s = RangeSet::new();
        s.add(Region::new(u64::MAX - 100, 50).unwrap()).unwrap(); // [MAX-100, MAX-50)
        s.add(Region::new(u64::MAX - 50, 50).unwrap()).unwrap(); // [MAX-50, MAX)
        assert_eq!(s.count(), 1);
        assert_eq!(s.min(), Some(u64::MAX - 100));
        assert_eq!(s.max(), Some(u64::MAX));
        assert_canonical(&s);
    }

    #[test]
    fn add_overflow_region_is_rejected() {
        // A hand-built struct literal whose end overflows must be rejected, not panic.
        let overflow = Region {
            offset: u64::MAX,
            length: 10,
        };
        let mut s = RangeSet::new();
        assert!(matches!(
            s.add(overflow),
            Err(ForensicError::ArithmeticOverflow { .. })
        ));
        assert!(s.is_empty());
    }

    #[test]
    fn serde_roundtrip() {
        let s = RangeSet::from_regions([r(100, 50), r(300, 50)]).unwrap();
        let json = serde_json::to_string(&s).unwrap();
        let back: RangeSet = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}
