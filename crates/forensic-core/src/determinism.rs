//! # Deterministic Forensic-Result Comparison Harness
//!
//! Compares `ForensicResult`s while excluding environment-dependent metadata (execution
//! timestamps, DB IDs, temp paths, durations). Captures the full determinism input set:
//! evidence bytes/hash, OEM_Profile version + hash, ConfidenceConfig version + hash,
//! recovery configuration, and component versions (Req 20.1–20.4).
//!
//! The ConfidenceConfig version + hash and recovery configuration are first-class
//! determinism inputs — omitting either makes a determinism claim invalid.

use serde::{Deserialize, Serialize};

use crate::hash::Hash;

/// The complete determinism input set for a forensic run.
///
/// Two runs with the same `DeterminismKey` MUST produce identical forensic results
/// (excluding environment metadata). If any key field differs, the runs are
/// incomparable for determinism.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterminismKey {
    /// Hash of the evidence source.
    pub evidence_hash: Hash,
    /// OEM profile version applied.
    pub profile_version: String,
    /// Hash of the OEM profile applied.
    pub profile_hash: Hash,
    /// ConfidenceConfig version — omitting this invalidates a determinism claim.
    pub config_version: String,
    /// Hash of the ConfidenceConfig — omitting this invalidates a determinism claim.
    pub config_hash: Hash,
    /// Recovery configuration identifier (if recovery was performed).
    pub recovery_config: Option<String>,
    /// Versions of all forensic components used.
    pub component_versions: ComponentVersions,
}

/// Versions of all forensic components.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentVersions {
    pub detector_version: String,
    pub parser_version: String,
    pub confidence_engine_version: String,
    pub recovery_engine_version: String,
}

/// A forensic result that can be compared for determinism.
///
/// Contains the forensic fields that MUST be identical for the same determinism key,
/// and the environment metadata that is excluded from comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicResult {
    /// The determinism key for this result.
    pub key: DeterminismKey,
    /// The forensic fields that must be deterministic.
    pub forensic_fields: serde_json::Value,
    /// Environment metadata excluded from comparison.
    pub metadata: ResultMetadata,
}

/// Environment-dependent metadata excluded from deterministic comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultMetadata {
    /// Execution timestamp.
    pub execution_timestamp: Option<String>,
    /// Database row IDs.
    pub db_ids: Vec<String>,
    /// Temporary file paths.
    pub temp_paths: Vec<String>,
    /// Operation durations in milliseconds.
    pub durations_ms: Vec<u64>,
}

/// Comparison result between two forensic runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComparisonResult {
    /// Forensic fields are identical (determinism holds).
    Equal,
    /// Forensic fields differ (determinism violation).
    ForensicFieldsDiffer {
        /// Description of the differences.
        differences: Vec<String>,
    },
    /// Determinism keys differ (runs are incomparable).
    KeysDiffer {
        /// Which key fields differ.
        differing_fields: Vec<String>,
    },
}

/// Compare two forensic results for determinism.
///
/// The harness:
/// 1. Checks that determinism keys match (same inputs).
/// 2. Compares forensic fields (excluding environment metadata).
/// 3. Reports equality or lists differences.
pub fn compare_forensic_results(a: &ForensicResult, b: &ForensicResult) -> ComparisonResult {
    // Step 1: Check determinism keys
    let key_diffs = compare_keys(&a.key, &b.key);
    if !key_diffs.is_empty() {
        return ComparisonResult::KeysDiffer {
            differing_fields: key_diffs,
        };
    }

    // Step 2: Compare forensic fields
    if a.forensic_fields == b.forensic_fields {
        ComparisonResult::Equal
    } else {
        let differences = diff_json_values("", &a.forensic_fields, &b.forensic_fields);
        ComparisonResult::ForensicFieldsDiffer { differences }
    }
}

/// Compare determinism keys and return a list of differing field names.
fn compare_keys(a: &DeterminismKey, b: &DeterminismKey) -> Vec<String> {
    let mut diffs = Vec::new();
    if a.evidence_hash != b.evidence_hash {
        diffs.push("evidence_hash".into());
    }
    if a.profile_version != b.profile_version {
        diffs.push("profile_version".into());
    }
    if a.profile_hash != b.profile_hash {
        diffs.push("profile_hash".into());
    }
    if a.config_version != b.config_version {
        diffs.push("config_version".into());
    }
    if a.config_hash != b.config_hash {
        diffs.push("config_hash".into());
    }
    if a.recovery_config != b.recovery_config {
        diffs.push("recovery_config".into());
    }
    if a.component_versions != b.component_versions {
        diffs.push("component_versions".into());
    }
    diffs
}

/// Recursively diff two JSON values and return paths where they differ.
fn diff_json_values(path: &str, a: &serde_json::Value, b: &serde_json::Value) -> Vec<String> {
    use serde_json::Value;
    let mut diffs = Vec::new();

    match (a, b) {
        (Value::Object(map_a), Value::Object(map_b)) => {
            for key in map_a.keys().chain(map_b.keys()) {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                match (map_a.get(key), map_b.get(key)) {
                    (Some(va), Some(vb)) => {
                        diffs.extend(diff_json_values(&child_path, va, vb));
                    }
                    (Some(_), None) => diffs.push(format!("{child_path}: present in A, missing in B")),
                    (None, Some(_)) => diffs.push(format!("{child_path}: missing in A, present in B")),
                    (None, None) => unreachable!(),
                }
            }
        }
        (Value::Array(arr_a), Value::Array(arr_b)) => {
            if arr_a.len() != arr_b.len() {
                diffs.push(format!(
                    "{path}: array length differs ({} vs {})",
                    arr_a.len(),
                    arr_b.len()
                ));
            }
            for (i, (va, vb)) in arr_a.iter().zip(arr_b.iter()).enumerate() {
                let child_path = format!("{path}[{i}]");
                diffs.extend(diff_json_values(&child_path, va, vb));
            }
        }
        _ => {
            if a != b {
                diffs.push(format!("{path}: {a} ≠ {b}"));
            }
        }
    }
    diffs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> DeterminismKey {
        DeterminismKey {
            evidence_hash: Hash::sha256(vec![0xaa; 32]),
            profile_version: "dahua-v1.0".into(),
            profile_hash: Hash::sha256(vec![0xbb; 32]),
            config_version: "conf-v1.0".into(),
            config_hash: Hash::sha256(vec![0xcc; 32]),
            recovery_config: Some("default".into()),
            component_versions: ComponentVersions {
                detector_version: "0.1.0".into(),
                parser_version: "0.1.0".into(),
                confidence_engine_version: "0.1.0".into(),
                recovery_engine_version: "0.1.0".into(),
            },
        }
    }

    fn sample_result(key: DeterminismKey) -> ForensicResult {
        ForensicResult {
            key,
            forensic_fields: serde_json::json!({
                "detection_status": "confirmed",
                "oem": "dahua",
                "evidence_items": [{"offset": 0, "kind": "magic"}],
            }),
            metadata: ResultMetadata {
                execution_timestamp: Some("2025-01-01T00:00:00Z".into()),
                db_ids: vec!["row-1".into()],
                temp_paths: vec!["/tmp/work".into()],
                durations_ms: vec![42],
            },
        }
    }

    #[test]
    fn identical_results_compare_equal() {
        let key = sample_key();
        let a = sample_result(key.clone());
        let b = sample_result(key);
        assert_eq!(compare_forensic_results(&a, &b), ComparisonResult::Equal);
    }

    #[test]
    fn different_metadata_ignored() {
        let key = sample_key();
        let a = sample_result(key.clone());
        let mut b = sample_result(key);
        // Change metadata (should be ignored).
        b.metadata.execution_timestamp = Some("2025-12-31T23:59:59Z".into());
        b.metadata.db_ids = vec!["row-999".into()];
        b.metadata.durations_ms = vec![9999];
        assert_eq!(compare_forensic_results(&a, &b), ComparisonResult::Equal);
    }

    #[test]
    fn different_forensic_fields_detected() {
        let key = sample_key();
        let a = sample_result(key.clone());
        let mut b = sample_result(key);
        b.forensic_fields = serde_json::json!({
            "detection_status": "ambiguous",
            "oem": "dahua",
            "evidence_items": [{"offset": 0, "kind": "magic"}],
        });
        match compare_forensic_results(&a, &b) {
            ComparisonResult::ForensicFieldsDiffer { differences } => {
                assert!(!differences.is_empty());
            }
            other => panic!("expected ForensicFieldsDiffer, got {other:?}"),
        }
    }

    #[test]
    fn different_config_hash_flags_different_input_set() {
        let key_a = sample_key();
        let mut key_b = sample_key();
        key_b.config_hash = Hash::sha256(vec![0xff; 32]);

        let a = sample_result(key_a);
        let b = sample_result(key_b);
        match compare_forensic_results(&a, &b) {
            ComparisonResult::KeysDiffer { differing_fields } => {
                assert!(differing_fields.contains(&"config_hash".to_string()));
            }
            other => panic!("expected KeysDiffer, got {other:?}"),
        }
    }

    #[test]
    fn different_recovery_config_flags_different_input_set() {
        let key_a = sample_key();
        let mut key_b = sample_key();
        key_b.recovery_config = Some("aggressive".into());

        let a = sample_result(key_a);
        let b = sample_result(key_b);
        match compare_forensic_results(&a, &b) {
            ComparisonResult::KeysDiffer { differing_fields } => {
                assert!(differing_fields.contains(&"recovery_config".to_string()));
            }
            other => panic!("expected KeysDiffer, got {other:?}"),
        }
    }

    #[test]
    fn determinism_key_serde_roundtrip() {
        let key = sample_key();
        let json = serde_json::to_string(&key).unwrap();
        let back: DeterminismKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key, back);
    }
}
