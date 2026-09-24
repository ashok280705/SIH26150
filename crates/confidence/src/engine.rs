//! # Confidence Engine
//!
//! Evaluates multi-vendor detector outputs, calculates weighted confidence scores, enforces
//! the strict Req 10.11 decision tree, and assigns forensic attribution (Req 10.1–10.11, 2.3, 2.4, 2.6, 9.6).
//!
//! Key invariants:
//! - Sole producer of `Classification` and `AttributionStatus` (Req 9.6).
//! - Decision tree ordering strictly enforced:
//!   1. Insufficient evidence / lone magic -> `Insufficient` (preempts threshold!)
//!   2. Top confidence < threshold -> `Unknown`
//!   3. Margin < min_margin -> `Ambiguous`
//!   4. Threshold + margin + quality + OEM_Exclusive -> `Confirmed`
//!   5. Otherwise -> `CompatibleCandidate`
//! - `Confirmed` attribution is UNREACHABLE without OEM-exclusive evidence (Req 10.4).
//! - CP Plus / UBS rule: UBS storage alone yields `CompatibleCandidate`, never `Confirmed` (Req 2.4).

use detection::DetectorOutput;
use forensic_core::{ForensicError, ProfileRegistry, ValidationState};

use crate::config::ConfidenceConfig;
use crate::result::{AttributionStatus, Classification, ClassifiedDetectionResult};

/// Candidate evaluation intermediate scores.
#[derive(Debug, Clone)]
struct CandidateScore {
    pub output_index: usize,
    pub oem_key: String,
    pub raw_score: f64,
    pub confidence: f64,
    pub average_quality: f64,
    pub has_exclusive_evidence: bool,
    pub is_insufficient: bool,
}

pub struct ConfidenceEngine;

impl ConfidenceEngine {
    /// Classify multi-vendor detector outputs and produce the authoritative `ClassifiedDetectionResult`.
    pub fn classify(
        outputs: &[DetectorOutput],
        registry: &ProfileRegistry,
        config: &ConfidenceConfig,
    ) -> Result<ClassifiedDetectionResult, ForensicError> {
        if outputs.is_empty() {
            return Err(ForensicError::corrupt(
                "confidence_engine",
                "no detector outputs provided",
            ));
        }

        // 1. Compute weighted scores for each detector output
        let mut scores = Vec::new();

        for (idx, out) in outputs.iter().enumerate() {
            let profile = registry.find_applicable(&out.oem_key, None, None, None);
            let max_possible_score = profile
                .map(|p| p.confidence_weights.max_possible_score)
                .unwrap_or(1.0)
                .max(0.01);

            let mut raw_score = 0.0;
            let mut total_quality = 0.0;
            let mut quality_count = 0;
            let mut has_exclusive = false;

            for item in &out.evidence {
                let v_factor = config.validation_factor(item.evidence_status);
                let q_factor = config.quality_factor(item.rule_match_status);

                let item_score = item.score_contribution * v_factor * q_factor;
                raw_score += item_score;

                total_quality += q_factor;
                quality_count += 1;

                if item.is_exclusive
                    && item.rule_match_status == forensic_core::RuleMatchStatus::Match
                {
                    has_exclusive = true;
                }
            }

            let confidence = (raw_score / max_possible_score).clamp(0.0, 1.0);
            let average_quality = if quality_count > 0 {
                total_quality / quality_count as f64
            } else {
                0.0
            };
            let is_insufficient = out.status == detection::DetectionStatus::Insufficient;

            scores.push(CandidateScore {
                output_index: idx,
                oem_key: out.oem_key.clone(),
                raw_score,
                confidence,
                average_quality,
                has_exclusive_evidence: has_exclusive,
                is_insufficient,
            });
        }

        // 2. Sort candidates by confidence descending
        scores.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let top = &scores[0];
        let second = scores.get(1);

        let margin = if let Some(sec) = second {
            (top.confidence - sec.confidence).max(0.0)
        } else {
            top.confidence
        };

        let top_output = &outputs[top.output_index];

        // 3. Strict Decision Order (Req 10.11)
        let (classification, attribution_status, explanation, val_state) = if top.is_insufficient
            || top_output.evidence.is_empty()
        {
            // (1) Structurally insufficient evidence OR lone magic -> Insufficient
            let expl = format!("Structural evidence for '{}' is insufficient (lone magic or incomplete indicators)", top.oem_key);
            let vs =
                ValidationState::review(&expl, "detection_classification", &top_output.oem_key)
                    .map_err(|e| ForensicError::corrupt("classify", format!("{e}")))?;
            (
                Classification::Insufficient,
                AttributionStatus::Unknown,
                expl,
                vs,
            )
        } else if top.confidence < config.min_confidence {
            // (2) No candidate reaches threshold -> Unknown
            let expl = format!(
                "Top candidate '{}' confidence ({:.2}) below threshold ({:.2})",
                top.oem_key, top.confidence, config.min_confidence
            );
            let vs = ValidationState::pass(&expl, "detection_classification", "evidence_source")
                .map_err(|e| ForensicError::corrupt("classify", format!("{e}")))?;
            (
                Classification::Unknown,
                AttributionStatus::Unknown,
                expl,
                vs,
            )
        } else if second.is_some() && margin < config.min_margin {
            // (3) Top-two margin below minimum -> Ambiguous
            let sec_name = &second.unwrap().oem_key;
            let expl = format!("Ambiguous detection between '{}' ({:.2}) and '{}' ({:.2}); margin ({:.2}) < min_margin ({:.2})", top.oem_key, top.confidence, sec_name, second.unwrap().confidence, margin, config.min_margin);
            let vs =
                ValidationState::review(&expl, "detection_classification", &top_output.oem_key)
                    .map_err(|e| ForensicError::corrupt("classify", format!("{e}")))?;
            (
                Classification::Ambiguous,
                AttributionStatus::Unknown,
                expl,
                vs,
            )
        } else if top.confidence >= config.min_confidence
            && margin >= config.min_margin
            && top.average_quality >= config.min_quality
            && top.has_exclusive_evidence
        {
            // (4) Threshold + margin + quality satisfied AND OEM_Exclusive_Evidence present -> Confirmed
            let expl = format!("Confirmed attribution for '{}' (confidence: {:.2}, margin: {:.2}, exclusive evidence present)", top.oem_key, top.confidence, margin);
            let vs = ValidationState::pass(&expl, "detection_classification", &top_output.oem_key)
                .map_err(|e| ForensicError::corrupt("classify", format!("{e}")))?;
            (
                Classification::Confirmed,
                AttributionStatus::Confirmed,
                expl,
                vs,
            )
        } else {
            // (5) Otherwise -> CompatibleCandidate (covers CP Plus / UBS non-exclusive cases — Req 2.4)
            let expl = format!("Compatible candidate attribution for '{}' (confidence: {:.2}, non-exclusive storage structures)", top.oem_key, top.confidence);
            let vs = ValidationState::pass(&expl, "detection_classification", &top_output.oem_key)
                .map_err(|e| ForensicError::corrupt("classify", format!("{e}")))?;
            (
                Classification::CompatibleCandidate,
                AttributionStatus::CompatibleCandidate,
                expl,
                vs,
            )
        };

        let top_result = ClassifiedDetectionResult {
            detector_output: top_output.clone(),
            raw_score: top.raw_score,
            confidence: top.confidence,
            top_candidate: top.oem_key.clone(),
            second_candidate: second.map(|s| s.oem_key.clone()),
            margin,
            evidence_quality: top.average_quality,
            classification,
            attribution_status,
            validation_state: val_state,
            explanation,
            config_version: config.config_version.clone(),
            config_hash: config.config_hash.clone(),
        };

        Ok(top_result)
    }

    /// Evaluates and returns classified results for all candidate OEM detectors, sorted by confidence descending.
    pub fn classify_all(
        outputs: &[DetectorOutput],
        registry: &ProfileRegistry,
        config: &ConfidenceConfig,
    ) -> Result<Vec<ClassifiedDetectionResult>, ForensicError> {
        if outputs.is_empty() {
            return Ok(vec![]);
        }

        let primary_result = Self::classify(outputs, registry, config)?;

        // Compute individual scores for all candidates
        let mut results = vec![primary_result.clone()];

        for out in outputs {
            if out.oem_key == primary_result.top_candidate {
                continue; // Already included as primary
            }

            let profile = registry.find_applicable(&out.oem_key, None, None, None);
            let max_possible_score = profile
                .map(|p| p.confidence_weights.max_possible_score)
                .unwrap_or(1.0)
                .max(0.01);

            let mut raw_score = 0.0;
            let mut total_quality = 0.0;
            let mut quality_count = 0;

            for item in &out.evidence {
                let v_factor = config.validation_factor(item.evidence_status);
                let q_factor = config.quality_factor(item.rule_match_status);
                raw_score += item.score_contribution * v_factor * q_factor;
                total_quality += q_factor;
                quality_count += 1;
            }

            let confidence = (raw_score / max_possible_score).clamp(0.0, 1.0);
            let average_quality = if quality_count > 0 {
                total_quality / quality_count as f64
            } else {
                0.0
            };

            let val_state = ValidationState::new(
                forensic_core::ValidationStateKind::Unknown,
                if out.evidence.is_empty() {
                    "No matching signatures found"
                } else {
                    "Candidate score evaluated"
                },
                "detection_classification",
                &out.oem_key,
            )
            .unwrap();

            results.push(ClassifiedDetectionResult {
                detector_output: out.clone(),
                raw_score,
                confidence,
                top_candidate: out.oem_key.clone(),
                second_candidate: None,
                margin: 0.0,
                evidence_quality: average_quality,
                classification: if out.evidence.is_empty() {
                    Classification::Unknown
                } else {
                    Classification::Insufficient
                },
                attribution_status: AttributionStatus::Unknown,
                validation_state: val_state,
                explanation: if out.evidence.is_empty() {
                    format!(
                        "No matching structural signatures detected for '{}'",
                        out.oem_key
                    )
                } else {
                    format!(
                        "Candidate evaluated with confidence {:.2}%",
                        confidence * 100.0
                    )
                },
                config_version: config.config_version.clone(),
                config_hash: config.config_hash.clone(),
            });
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_core::{
        EvidenceId, EvidenceItem, EvidenceStatus, Hash, OemProfile, RuleMatchStatus,
    };

    fn dummy_item(name: &str, score: f64, is_exclusive: bool) -> EvidenceItem {
        EvidenceItem::new(
            EvidenceId::new(),
            name,
            0,
            4,
            b"TEST",
            b"TEST",
            RuleMatchStatus::Match,
            EvidenceStatus::Validated,
            score,
            is_exclusive,
            "test match",
            "1.0.0",
            Hash::sha256(vec![0; 32]),
        )
    }

    #[test]
    fn decision_order_confirmed_with_exclusive() {
        let dahua_profile = OemProfile::from_toml_str(
            r#"

profile_id = "dahua-1"
profile_version = "1.0"
schema_version = "1.0"
oem = "dahua"
storage_family = "DHFS"
[applicability]
[[signatures]]
name = "sig1"
pattern_hex = "44 48 46 53"
evidence_status = "validated"
weight = 0.85
is_exclusive = true
[confidence_weights]
max_possible_score = 1.0
"#,
        )
        .unwrap();

        let registry = ProfileRegistry::from_profiles(vec![dahua_profile]);
        let config = ConfidenceConfig::provisional_default();

        let output = DetectorOutput {
            oem_key: "dahua".into(),
            storage_family: "DHFS".into(),
            status: detection::DetectionStatus::Confirmed,
            evidence: vec![
                dummy_item("sig1", 0.85, true),
                dummy_item("sig2", 0.30, false),
            ],
            candidate_regions: vec![],
            warnings: vec![],
            profile_version: "1.0".into(),
            profile_hash: Hash::sha256(vec![0; 32]),
        };

        let classified = ConfidenceEngine::classify(&[output], &registry, &config).unwrap();
        assert_eq!(classified.classification, Classification::Confirmed);
        assert_eq!(classified.attribution_status, AttributionStatus::Confirmed);
    }

    #[test]
    fn decision_order_non_exclusive_yields_compatible_candidate() {
        let registry = ProfileRegistry::from_profiles(vec![]);
        let config = ConfidenceConfig::provisional_default();

        let output = DetectorOutput {
            oem_key: "cpplus_ubs".into(),
            storage_family: "CPPLUS_UBS".into(),
            status: detection::DetectionStatus::Confirmed,
            evidence: vec![
                dummy_item("ubs_marker", 0.80, false), // Non-exclusive!
                dummy_item("page_tag", 0.30, false),
            ],
            candidate_regions: vec![],
            warnings: vec![],
            profile_version: "1.0".into(),
            profile_hash: Hash::sha256(vec![0; 32]),
        };

        let classified = ConfidenceEngine::classify(&[output], &registry, &config).unwrap();
        assert_eq!(
            classified.classification,
            Classification::CompatibleCandidate
        );
        assert_eq!(
            classified.attribution_status,
            AttributionStatus::CompatibleCandidate
        );
    }
}
