//! Reconstruction hypothesis model with deterministic tie-break (Req 13.9, 13.10, 14.2, 20.1).
//!
//! Supports competing hypotheses with content-derived ranking and explicit deterministic
//! tie-break key: lowest source_offset → smallest region set → lexicographic candidate id.
//!
//! The deterministic tie-break exists ONLY to make ordering reproducible; it NEVER resolves
//! genuine forensic ambiguity. Where multiple hypotheses remain plausible, the reconstruction
//! is assigned ValidationState = REVIEW with a reason.

use forensic_core::{Region, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// A single reconstruction hypothesis with a content-derived score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hypothesis {
    pub candidate_id: String,
    pub source_regions: Vec<Region>,
    pub score: f64,
}

impl Hypothesis {
    /// Deterministic tie-break key: lowest source_offset, then smallest region count,
    /// then lexicographic candidate_id.
    fn tie_break_key(&self) -> (u64, usize, &str) {
        let min_offset = self
            .source_regions
            .iter()
            .map(|r| r.offset)
            .min()
            .unwrap_or(u64::MAX);
        (min_offset, self.source_regions.len(), &self.candidate_id)
    }
}

/// Rank hypotheses deterministically. Returns the ranked list and a validation state.
/// If genuinely ambiguous (top two scores equal), returns REVIEW with no arbitrary winner.
pub fn rank_hypotheses(
    mut hypotheses: Vec<Hypothesis>,
    max_hypotheses: u32,
) -> (Vec<Hypothesis>, ValidationState) {
    let considered = hypotheses.len();

    // Rank **before** bounding. Truncating first would keep whichever hypotheses happened to
    // be generated earliest and discard higher-scoring ones unseen, which makes the reported
    // "top" hypothesis an artefact of generation order rather than of the evidence — and
    // makes the result depend on input order even though the sort itself is deterministic.
    hypotheses.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| a.tie_break_key().cmp(&b.tie_break_key()))
    });

    // Bound hypothesis count (Req 13.9), now over a ranked list.
    let truncated = considered > max_hypotheses as usize;
    hypotheses.truncate(max_hypotheses as usize);

    // Check for genuine ambiguity. Argument order is (state, reason, operation, subject): the
    // reason is what an examiner reads, so it carries the explanation, not the function name.
    let validation = if truncated {
        ValidationState::new(
            ValidationStateKind::Review,
            format!(
                "Hypothesis count was bounded: {considered} generated, {} evaluated; the \
                 remainder scored no higher than those kept but were not individually reported",
                hypotheses.len()
            ),
            "rank_hypotheses",
            "Hypotheses",
        )
        .expect("formatted reason is non-empty")
    } else if hypotheses.len() >= 2
        && (hypotheses[0].score - hypotheses[1].score).abs() < f64::EPSILON
    {
        // Genuinely ambiguous — REVIEW, no arbitrary winner
        ValidationState::new(
            ValidationStateKind::Review,
            "Multiple hypotheses with equal scores; genuine ambiguity",
            "rank_hypotheses",
            "Hypotheses",
        )
        .expect("static reason is non-empty")
    } else if hypotheses.is_empty() {
        ValidationState::new(
            ValidationStateKind::Unknown,
            "No hypotheses to evaluate",
            "rank_hypotheses",
            "Hypotheses",
        )
        .expect("static reason is non-empty")
    } else {
        ValidationState::new(
            ValidationStateKind::Pass,
            "Clear winner identified",
            "rank_hypotheses",
            "Hypotheses",
        )
        .expect("static reason is non-empty")
    };

    (hypotheses, validation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_inputs_yield_identical_ordering() {
        let h1 = Hypothesis {
            candidate_id: "a".into(),
            source_regions: vec![Region {
                offset: 100,
                length: 50,
            }],
            score: 0.9,
        };
        let h2 = Hypothesis {
            candidate_id: "b".into(),
            source_regions: vec![Region {
                offset: 200,
                length: 50,
            }],
            score: 0.8,
        };

        let (ranked1, _) = rank_hypotheses(vec![h1.clone(), h2.clone()], 100);
        let (ranked2, _) = rank_hypotheses(vec![h2.clone(), h1.clone()], 100);

        assert_eq!(ranked1[0].candidate_id, ranked2[0].candidate_id);
        assert_eq!(ranked1[1].candidate_id, ranked2[1].candidate_id);
    }

    #[test]
    fn test_genuine_ambiguity_yields_review() {
        let h1 = Hypothesis {
            candidate_id: "a".into(),
            source_regions: vec![Region {
                offset: 100,
                length: 50,
            }],
            score: 0.9,
        };
        let h2 = Hypothesis {
            candidate_id: "b".into(),
            source_regions: vec![Region {
                offset: 200,
                length: 50,
            }],
            score: 0.9,
        };

        let (_, validation) = rank_hypotheses(vec![h1, h2], 100);
        assert_eq!(validation.state, ValidationStateKind::Review);
    }

    #[test]
    fn bounding_keeps_the_highest_scoring_hypotheses_not_the_first_generated() {
        // Generated worst-first: a truncate-before-sort keeps h0..h2 and reports the worst
        // hypothesis as the winner.
        let hypotheses: Vec<Hypothesis> = (0..10)
            .map(|i| Hypothesis {
                candidate_id: format!("h{i}"),
                source_regions: vec![Region {
                    offset: i * 100,
                    length: 50,
                }],
                score: 0.1 * (i as f64),
            })
            .collect();

        let (ranked, validation) = rank_hypotheses(hypotheses, 3);
        assert_eq!(ranked.len(), 3);
        assert_eq!(
            ranked[0].candidate_id, "h9",
            "the highest-scoring hypothesis must survive bounding"
        );
        assert_eq!(ranked[1].candidate_id, "h8");
        assert_eq!(ranked[2].candidate_id, "h7");
        assert_eq!(validation.state, ValidationStateKind::Review);
        // The examiner-facing reason explains the bound rather than naming the function.
        assert!(
            validation.reason.contains("10 generated"),
            "{}",
            validation.reason
        );
        assert_eq!(validation.operation, "rank_hypotheses");
    }

    #[test]
    fn ranking_does_not_depend_on_generation_order_even_when_bounded() {
        let mk = || -> Vec<Hypothesis> {
            (0..10)
                .map(|i| Hypothesis {
                    candidate_id: format!("h{i}"),
                    source_regions: vec![Region {
                        offset: i * 100,
                        length: 50,
                    }],
                    score: 0.1 * (i as f64),
                })
                .collect()
        };
        let (forward, _) = rank_hypotheses(mk(), 4);
        let mut reversed = mk();
        reversed.reverse();
        let (backward, _) = rank_hypotheses(reversed, 4);

        let ids_f: Vec<&str> = forward.iter().map(|h| h.candidate_id.as_str()).collect();
        let ids_b: Vec<&str> = backward.iter().map(|h| h.candidate_id.as_str()).collect();
        assert_eq!(ids_f, ids_b);
    }

    #[test]
    fn test_bounded_hypothesis_count() {
        let hypotheses: Vec<Hypothesis> = (0..10)
            .map(|i| Hypothesis {
                candidate_id: format!("h{}", i),
                source_regions: vec![Region {
                    offset: i * 100,
                    length: 50,
                }],
                score: 0.5 + (i as f64) * 0.01,
            })
            .collect();

        let (ranked, validation) = rank_hypotheses(hypotheses, 3);
        assert_eq!(ranked.len(), 3);
        assert_eq!(validation.state, ValidationStateKind::Review);
    }
}
