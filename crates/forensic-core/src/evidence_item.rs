//! # EvidenceItem Model and RuleMatchStatus
//!
//! Represents an observed forensic structural indicator (magic, header, index tag, boundary)
//! produced by a detector against profile rules (Req 2.2, 2.8, 9.4, 10.8).
//!
//! Key invariants:
//! - `evidence_status` (rule maturity) and `rule_match_status` (observation outcome) are distinct axes (Req 2.8).
//! - Neither axis can be derived from the other: a `validated` rule can yield `Mismatch`, and a `provisional` rule can yield `Match`.
//! - `observed` and `expected` store bounded byte snippets (max 64 bytes), never full file payloads.

use serde::{Deserialize, Serialize};

use crate::evidence_status::EvidenceStatus;
use crate::hash::Hash;
use crate::identifiers::EvidenceId;

/// The outcome of evaluating observed evidence bytes against a profile rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleMatchStatus {
    /// Observed bytes completely matched the expected pattern.
    Match,
    /// Bytes were present at the target offset but did not match the expected pattern.
    Mismatch,
    /// Partial match (e.g. prefix matched or corrupted segment observed).
    Partial,
    /// Target offset or structure was absent/truncated.
    Absent,
}

impl std::fmt::Display for RuleMatchStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Match => write!(f, "match"),
            Self::Mismatch => write!(f, "mismatch"),
            Self::Partial => write!(f, "partial"),
            Self::Absent => write!(f, "absent"),
        }
    }
}

/// A structured forensic evidence observation produced during storage detection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// The evidence source this item was extracted from.
    pub source_evidence_id: EvidenceId,
    /// Indicator kind (e.g. "superblock_magic", "stream_packet_tag", "boundary_arithmetic").
    pub kind: String,
    /// Evidence byte offset where the observation occurred.
    pub offset: u64,
    /// Length of the observed indicator in bytes.
    pub length: u64,
    /// Bounded snippet of observed bytes (max 64 bytes).
    pub observed: Vec<u8>,
    /// Bounded snippet of expected pattern bytes.
    pub expected: Vec<u8>,
    /// Whether the observation matched the rule pattern.
    pub rule_match_status: RuleMatchStatus,
    /// How well established the profile rule is (retained unchanged from profile).
    pub evidence_status: EvidenceStatus,
    /// Score weight assigned by the profile.
    pub score_contribution: f64,
    /// Whether this item represents exclusive evidence for its OEM.
    pub is_exclusive: bool,
    /// Human-readable explanation.
    pub explanation: String,
    /// Profile version that produced this claim.
    pub profile_version: String,
    /// Profile SHA-256 hash that produced this claim.
    pub profile_hash: Hash,
}

impl EvidenceItem {
    const MAX_SNIPPET_BYTES: usize = 64;

    /// Create a new EvidenceItem with bounded snippets.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_evidence_id: EvidenceId,
        kind: impl Into<String>,
        offset: u64,
        length: u64,
        observed: &[u8],
        expected: &[u8],
        rule_match_status: RuleMatchStatus,
        evidence_status: EvidenceStatus,
        score_contribution: f64,
        is_exclusive: bool,
        explanation: impl Into<String>,
        profile_version: impl Into<String>,
        profile_hash: Hash,
    ) -> Self {
        let obs_bounded = if observed.len() > Self::MAX_SNIPPET_BYTES {
            observed[..Self::MAX_SNIPPET_BYTES].to_vec()
        } else {
            observed.to_vec()
        };

        let exp_bounded = if expected.len() > Self::MAX_SNIPPET_BYTES {
            expected[..Self::MAX_SNIPPET_BYTES].to_vec()
        } else {
            expected.to_vec()
        };

        Self {
            source_evidence_id,
            kind: kind.into(),
            offset,
            length,
            observed: obs_bounded,
            expected: exp_bounded,
            rule_match_status,
            evidence_status,
            score_contribution,
            is_exclusive,
            explanation: explanation.into(),
            profile_version: profile_version.into(),
            profile_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_status_and_rule_match_status_are_orthogonal() {
        let ev_id = EvidenceId::new();
        let hash = Hash::sha256(vec![0xAA; 32]);

        // Case 1: Validated rule with Mismatch (e.g. valid DHFS rule tested against corrupted sector)
        let item1 = EvidenceItem::new(
            ev_id,
            "dhfs_magic",
            0,
            4,
            b"XXXX",
            b"DHFS",
            RuleMatchStatus::Mismatch,
            EvidenceStatus::Validated,
            0.85,
            true,
            "expected DHFS magic",
            "1.0.0",
            hash.clone(),
        );

        assert_eq!(item1.evidence_status, EvidenceStatus::Validated);
        assert_eq!(item1.rule_match_status, RuleMatchStatus::Mismatch);

        // Case 2: Provisional rule with Match
        let item2 = EvidenceItem::new(
            ev_id,
            "provisional_tag",
            512,
            4,
            b"TAG1",
            b"TAG1",
            RuleMatchStatus::Match,
            EvidenceStatus::Provisional,
            0.40,
            false,
            "matched provisional tag",
            "1.0.0",
            hash,
        );

        assert_eq!(item2.evidence_status, EvidenceStatus::Provisional);
        assert_eq!(item2.rule_match_status, RuleMatchStatus::Match);
    }

    #[test]
    fn snippet_truncation_bounds_memory() {
        let ev_id = EvidenceId::new();
        let large_bytes = vec![0xFF; 1000];
        let item = EvidenceItem::new(
            ev_id,
            "test",
            0,
            1000,
            &large_bytes,
            &large_bytes,
            RuleMatchStatus::Match,
            EvidenceStatus::Validated,
            1.0,
            true,
            "",
            "1.0.0",
            Hash::sha256(vec![0; 32]),
        );

        assert_eq!(item.observed.len(), 64);
        assert_eq!(item.expected.len(), 64);
    }
}
