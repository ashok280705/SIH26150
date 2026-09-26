//! Property-based tests for [`RangeSet`] (A16).
//!
//! These use `proptest` to generate difficult inputs — empty, adjacent, overlapping,
//! nested, single-byte, duplicate, unsorted, and `u64::MAX`-adjacent ranges — and assert
//! the canonical invariants and algebraic laws hold for every generated case.
//!
//! Where feasible, operations are cross-checked against a brute-force byte-level model
//! over a small bounded universe, which is the ground truth for set semantics.

use forensic_core::{RangeSet, Region};
use proptest::prelude::*;

/// Universe size for the brute-force byte model. Region generators stay within this so a
/// boolean-per-byte model is a faithful, cheap oracle.
const UNIVERSE: usize = 1200;

fn small_region() -> impl Strategy<Value = Region> {
    // Offsets and lengths deliberately overlap in range so adjacency, overlap, nesting,
    // duplicates, single-byte, and zero-length regions all occur naturally.
    (0u64..1000, 0u64..200).prop_map(|(o, l)| Region::new(o, l).expect("bounded, cannot overflow"))
}

fn small_regions() -> impl Strategy<Value = Vec<Region>> {
    prop::collection::vec(small_region(), 0..12)
}

/// Boolean-per-byte model of a set of regions over `[0, UNIVERSE)`.
fn regions_to_bytes(regions: &[Region]) -> Vec<bool> {
    let mut bits = vec![false; UNIVERSE];
    for r in regions {
        let end = r.end().expect("bounded");
        for b in r.offset..end {
            if (b as usize) < UNIVERSE {
                bits[b as usize] = true;
            }
        }
    }
    bits
}

fn set_to_bytes(set: &RangeSet) -> Vec<bool> {
    let collected: Vec<Region> = set.iter().copied().collect();
    regions_to_bytes(&collected)
}

/// Assert the canonical invariants: sorted, disjoint, non-adjacent, no empty ranges.
fn canonical_ok(set: &RangeSet) -> Result<(), TestCaseError> {
    let ranges = set.ranges();
    for w in ranges.windows(2) {
        let a_end = w[0].end().expect("bounded");
        prop_assert!(!w[0].is_empty(), "empty range stored");
        // Strictly increasing and non-adjacent: next must start strictly after prev ends.
        prop_assert!(
            a_end < w[1].offset,
            "not disjoint/non-adjacent: {} then {}",
            w[0],
            w[1]
        );
    }
    if let Some(last) = ranges.last() {
        prop_assert!(!last.is_empty(), "empty range stored at tail");
    }
    Ok(())
}

proptest! {
    // Invariant 1,2,3: canonical ordering, no overlap, no adjacency, no empties, and the
    // set's byte model equals the union of the input regions' bytes.
    #[test]
    fn prop_canonical_and_faithful(regions in small_regions()) {
        let set = RangeSet::from_regions(regions.clone()).unwrap();
        canonical_ok(&set)?;
        prop_assert_eq!(set_to_bytes(&set), regions_to_bytes(&regions));
    }

    // Invariant 4: add is idempotent.
    #[test]
    fn prop_add_idempotent(regions in small_regions(), extra in small_region()) {
        let mut once = RangeSet::from_regions(regions.clone()).unwrap();
        once.add(extra).unwrap();
        let mut twice = once.clone();
        twice.add(extra).unwrap();
        prop_assert_eq!(once, twice);
    }

    // Invariant 10: repeated normalization is stable (round-trip through its own ranges).
    #[test]
    fn prop_normalization_stable(regions in small_regions()) {
        let set = RangeSet::from_regions(regions).unwrap();
        let reround = RangeSet::from_regions(set.ranges().to_vec()).unwrap();
        prop_assert_eq!(set, reround);
    }

    // Invariant 5: union is commutative, and models the byte-wise OR.
    #[test]
    fn prop_union_commutative_and_or(a in small_regions(), b in small_regions()) {
        let sa = RangeSet::from_regions(a).unwrap();
        let sb = RangeSet::from_regions(b).unwrap();
        let ab = sa.union(&sb);
        let ba = sb.union(&sa);
        prop_assert_eq!(&ab, &ba);
        canonical_ok(&ab)?;

        let expected: Vec<bool> = set_to_bytes(&sa)
            .iter()
            .zip(set_to_bytes(&sb).iter())
            .map(|(x, y)| *x || *y)
            .collect();
        prop_assert_eq!(set_to_bytes(&ab), expected);
    }

    // Invariant 6: intersection is commutative, contained in both operands, and models
    // the byte-wise AND.
    #[test]
    fn prop_intersect_commutative_contained_and(a in small_regions(), b in small_regions()) {
        let sa = RangeSet::from_regions(a).unwrap();
        let sb = RangeSet::from_regions(b).unwrap();
        let ab = sa.intersect(&sb);
        let ba = sb.intersect(&sa);
        prop_assert_eq!(&ab, &ba);
        canonical_ok(&ab)?;

        let ba_bytes = set_to_bytes(&sa);
        let bb_bytes = set_to_bytes(&sb);
        let inter_bytes = set_to_bytes(&ab);
        for i in 0..UNIVERSE {
            // Containment: every intersection byte is present in both operands.
            if inter_bytes[i] {
                prop_assert!(ba_bytes[i] && bb_bytes[i]);
            }
            // Exactness: AND of operands equals intersection.
            prop_assert_eq!(inter_bytes[i], ba_bytes[i] && bb_bytes[i]);
        }
    }

    // Invariant 7: subtraction removes exactly the cut and never introduces bytes outside
    // the original set.
    #[test]
    fn prop_subtract_within_original(regions in small_regions(), cut in small_region()) {
        let original = RangeSet::from_regions(regions).unwrap();
        let mut diff = original.clone();
        diff.subtract(cut).unwrap();
        canonical_ok(&diff)?;

        let orig_bytes = set_to_bytes(&original);
        let cut_bytes = regions_to_bytes(std::slice::from_ref(&cut));
        let diff_bytes = set_to_bytes(&diff);
        for i in 0..UNIVERSE {
            // Never any byte outside the original.
            if diff_bytes[i] {
                prop_assert!(orig_bytes[i], "subtraction introduced a byte outside original");
            }
            // No byte of the cut survives.
            if cut_bytes[i] {
                prop_assert!(!diff_bytes[i], "cut byte survived subtraction");
            }
            // Exactness: original AND NOT cut.
            prop_assert_eq!(diff_bytes[i], orig_bytes[i] && !cut_bytes[i]);
        }
    }

    // Invariant 8,9: complement within a universe models NOT, and complement ∪ original
    // covers the universe; being disjoint, their lengths add up.
    #[test]
    fn prop_complement_covers_universe(regions in small_regions(), u_off in 0u64..500, u_len in 0u64..600) {
        let universe = Region::new(u_off, u_len).unwrap();
        let set = RangeSet::from_regions(regions).unwrap();
        let comp = set.complement_within(universe).unwrap();
        canonical_ok(&comp)?;

        // set ∪ comp covers every byte of the universe.
        let recombined = set.union(&comp);
        prop_assert!(recombined.covers(&universe));

        // Within the universe, comp is exactly the bytes of the universe not in set.
        let set_bytes = set_to_bytes(&set);
        let uni_bytes = regions_to_bytes(std::slice::from_ref(&universe));
        let comp_bytes = set_to_bytes(&comp);
        for i in 0..UNIVERSE {
            prop_assert_eq!(comp_bytes[i], uni_bytes[i] && !set_bytes[i]);
        }

        // The part of `set` inside the universe plus the complement equals the universe,
        // and the two are disjoint, so lengths add.
        let inside = set.intersect(&RangeSet::from_regions([universe]).unwrap());
        prop_assert_eq!(inside.total_length() + comp.total_length(), universe.length);
    }

    // Invariant: total_length equals the number of covered bytes (sum of disjoint lengths).
    #[test]
    fn prop_total_length_matches_bytes(regions in small_regions()) {
        let set = RangeSet::from_regions(regions).unwrap();
        let covered = set_to_bytes(&set).iter().filter(|b| **b).count() as u64;
        prop_assert_eq!(set.total_length(), covered);
    }

    // Invariant: contains agrees with the byte model.
    #[test]
    fn prop_contains_matches_bytes(regions in small_regions(), probe in 0u64..(UNIVERSE as u64)) {
        let set = RangeSet::from_regions(regions).unwrap();
        let bytes = set_to_bytes(&set);
        prop_assert_eq!(set.contains(probe), bytes[probe as usize]);
    }

    // Boundary stress: u64::MAX-adjacent ranges only exercise structural invariants (the
    // byte model cannot represent this universe). Adjacent max ranges must still merge.
    #[test]
    fn prop_near_u64_max_canonical(
        pairs in prop::collection::vec((0u64..1000, 1u64..500), 0..8)
    ) {
        let mut set = RangeSet::new();
        for (back, len) in pairs {
            // Place ranges just below u64::MAX.
            let offset = u64::MAX - 1000 + back;
            // Clamp length so offset + len never overflows past u64::MAX.
            let max_len = u64::MAX - offset;
            let len = len.min(max_len);
            if len == 0 {
                continue;
            }
            set.add(Region::new(offset, len).unwrap()).unwrap();
        }
        canonical_ok(&set)?;
        // The set must remain well-ordered even at the top of the address space.
        if let (Some(min), Some(max)) = (set.min(), set.max()) {
            prop_assert!(min <= max);
        }
    }
}
