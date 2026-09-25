//! # OEM Profile Schema, Loader, and Versioning
//!
//! Defines the strict TOML profile types, applicability matching, strict validation,
//! and SHA-256 profile hashing (Req 6.1, 6.5, 6.6, 11.1–11.8).
//!
//! Key invariants:
//! - Profiles are data artifacts loaded from `profiles/`, never Rust source constants (Req 6.1).
//! - Every signature and rule MUST have an explicit `evidence_status` (Req 11.5).
//! - Profile version and SHA-256 hash are recorded with every detection result (Req 11.2, 20.1).

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ForensicError;
use crate::evidence_status::EvidenceStatus;
use crate::hash::Hash;

/// Hardware and firmware applicability constraints for a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Applicability {
    /// Supported hardware models (empty means any model of this OEM).
    #[serde(default)]
    pub models: Vec<String>,
    /// Supported firmware versions/ranges.
    #[serde(default)]
    pub firmwares: Vec<String>,
    /// Storage topology variants (e.g. "single_disk", "jbod", "raid_0").
    #[serde(default)]
    pub storage_variants: Vec<String>,
    /// Forensic reference / documentation source.
    pub reference: Option<String>,
}

impl Applicability {
    /// Check if this profile applies to the given model/firmware query.
    pub fn matches(
        &self,
        model: Option<&str>,
        firmware: Option<&str>,
        variant: Option<&str>,
    ) -> bool {
        if let Some(m) = model {
            if !self.models.is_empty()
                && !self.models.iter().any(|item| item.eq_ignore_ascii_case(m))
            {
                return false;
            }
        }
        if let Some(f) = firmware {
            if !self.firmwares.is_empty()
                && !self
                    .firmwares
                    .iter()
                    .any(|item| item.eq_ignore_ascii_case(f))
            {
                return false;
            }
        }
        if let Some(v) = variant {
            if !self.storage_variants.is_empty()
                && !self
                    .storage_variants
                    .iter()
                    .any(|item| item.eq_ignore_ascii_case(v))
            {
                return false;
            }
        }
        true
    }
}

/// Permitted byte offsets or search regions for a signature pattern.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OffsetConstraint {
    /// Pattern must be located at exact byte offset.
    Exact { offset: u64 },
    /// Pattern must be aligned to sector/block boundaries within a range.
    AlignedRange {
        start: u64,
        end: u64,
        alignment: u64,
    },
    /// Anywhere within initial header extent.
    HeaderWindow { max_offset: u64 },
}

/// A signature rule defined within an OEM profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignatureRule {
    /// Descriptive name of the signature (e.g. "dhfs_magic", "hik_header_tag").
    pub name: String,
    /// Hex-encoded byte sequence to search for.
    pub pattern_hex: String,
    /// Offset constraints restricting valid matches.
    #[serde(default)]
    pub offset_constraints: Vec<OffsetConstraint>,
    /// How well established this rule is — MANDATORY field (Req 11.5).
    pub evidence_status: EvidenceStatus,
    /// Signature weight for confidence scoring (provisional, from profile).
    pub weight: f64,
    /// Whether this signature is exclusive to this OEM (required for Confirmed attribution).
    #[serde(default)]
    pub is_exclusive: bool,
    /// Explanation or description of the signature.
    #[serde(default)]
    pub explanation: String,
}

impl SignatureRule {
    /// Decoded raw pattern bytes from pattern_hex.
    pub fn pattern_bytes(&self) -> Result<Vec<u8>, ForensicError> {
        let clean = self.pattern_hex.replace(' ', "").replace("0x", "");
        hex::decode(&clean).map_err(|e| {
            ForensicError::corrupt(
                "signature_rule",
                format!("invalid hex in rule '{}': {e}", self.name),
            )
        })
    }
}

/// Structural validation check declared in profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationRule {
    pub name: String,
    pub description: String,
    pub evidence_status: EvidenceStatus,
    pub weight: f64,
}

/// Weights and scoring factors configured for an OEM.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceWeights {
    pub max_possible_score: f64,
    #[serde(default = "default_min_score")]
    pub min_threshold: f64,
}

fn default_min_score() -> f64 {
    0.60
}

/// Complete versioned OEM profile data model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OemProfile {
    pub profile_id: String,
    pub profile_version: String,
    pub schema_version: String,
    pub oem: String,
    pub storage_family: String,
    pub applicability: Applicability,
    pub signatures: Vec<SignatureRule>,
    #[serde(default)]
    pub validation_rules: Vec<ValidationRule>,
    #[serde(default)]
    pub layout: std::collections::HashMap<String, i64>,
    pub confidence_weights: ConfidenceWeights,
    /// Computed SHA-256 hash of the profile file contents.
    #[serde(skip)]
    pub profile_hash: Option<Hash>,
}

impl OemProfile {
    /// Validate profile structure and rule integrity.
    pub fn validate(&self) -> Result<(), ForensicError> {
        if self.profile_id.trim().is_empty() {
            return Err(ForensicError::corrupt(
                "profile_validate",
                "missing profile_id",
            ));
        }
        if self.profile_version.trim().is_empty() {
            return Err(ForensicError::corrupt(
                "profile_validate",
                "missing profile_version",
            ));
        }
        if self.signatures.is_empty() {
            return Err(ForensicError::corrupt(
                "profile_validate",
                "profile must declare at least one signature",
            ));
        }

        // Verify each signature pattern decodes properly
        for sig in &self.signatures {
            sig.pattern_bytes()?;
            if sig.weight <= 0.0 {
                return Err(ForensicError::corrupt(
                    "profile_validate",
                    format!("signature '{}' weight must be positive", sig.name),
                ));
            }
        }

        Ok(())
    }

    /// Load and validate a profile from a TOML string, computing its SHA-256 hash.
    pub fn from_toml_str(content: &str) -> Result<Self, ForensicError> {
        let mut profile: Self = toml::from_str(content).map_err(|e| {
            ForensicError::corrupt(
                "profile_loader",
                format!("failed to parse profile TOML: {e}"),
            )
        })?;

        profile.validate()?;

        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        profile.profile_hash = Some(Hash::sha256(hasher.finalize().to_vec()));

        Ok(profile)
    }

    /// Load a profile from a TOML file on disk.
    pub fn from_file(path: &Path) -> Result<Self, ForensicError> {
        let content = fs::read_to_string(path)
            .map_err(|e| ForensicError::io(format!("reading profile at {}", path.display()), e))?;
        Self::from_toml_str(&content)
    }
}

/// Directory-based profile registry and selector.
pub struct ProfileRegistry {
    profiles: Vec<OemProfile>,
}

impl ProfileRegistry {
    /// Create a registry directly from a list of profiles.
    pub fn from_profiles(profiles: Vec<OemProfile>) -> Self {
        Self { profiles }
    }

    /// Load all `.toml` profiles from the `profiles/` directory hierarchy.
    pub fn load_from_dir(dir: &Path) -> Result<Self, ForensicError> {
        let mut profiles = Vec::new();

        let target_dir = if dir.exists() {
            dir.to_path_buf()
        } else if Path::new("../profiles").exists() {
            Path::new("../profiles").to_path_buf()
        } else if Path::new("../../profiles").exists() {
            Path::new("../../profiles").to_path_buf()
        } else {
            return Ok(Self { profiles });
        };

        fn walk_dir(path: &Path, acc: &mut Vec<OemProfile>) -> Result<(), ForensicError> {
            if path.is_dir() {
                for entry in fs::read_dir(path)
                    .map_err(|e| ForensicError::io(format!("reading {}", path.display()), e))?
                {
                    let entry = entry.map_err(|e| ForensicError::io("dir entry", e))?;
                    walk_dir(&entry.path(), acc)?;
                }
            } else if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                let profile = OemProfile::from_file(path)?;
                acc.push(profile);
            }
            Ok(())
        }

        walk_dir(&target_dir, &mut profiles)?;
        Ok(Self { profiles })
    }

    /// Find the best matching profile for an OEM and optional model/firmware.
    pub fn find_applicable(
        &self,
        oem: &str,
        model: Option<&str>,
        firmware: Option<&str>,
        variant: Option<&str>,
    ) -> Option<&OemProfile> {
        self.profiles.iter().find(|p| {
            p.oem.eq_ignore_ascii_case(oem) && p.applicability.matches(model, firmware, variant)
        })
    }

    /// All loaded profiles.
    pub fn all(&self) -> &[OemProfile] {
        &self.profiles
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TOML: &str = r#"
profile_id = "dahua-dhfs-v1.0"
profile_version = "1.0.0"
schema_version = "1.0"
oem = "dahua"
storage_family = "DHFS"

[applicability]
models = ["XVR", "NVR5xxx"]
firmwares = []
storage_variants = ["single_disk"]
reference = "Dahua Forensics Research 2024"

[[signatures]]
name = "dhfs_magic"
pattern_hex = "44 48 46 53" # "DHFS"
evidence_status = "validated"
weight = 0.85
is_exclusive = true
explanation = "Dahua file system superblock identifier"

[[signatures.offset_constraints]]
type = "exact"
offset = 0

[confidence_weights]
max_possible_score = 1.0
min_threshold = 0.70
"#;

    #[test]
    fn parse_valid_profile_with_hash() {
        let profile = OemProfile::from_toml_str(SAMPLE_TOML).unwrap();
        assert_eq!(profile.oem, "dahua");
        assert_eq!(profile.signatures.len(), 1);
        assert_eq!(
            profile.signatures[0].evidence_status,
            EvidenceStatus::Validated
        );
        assert!(profile.profile_hash.is_some());
        assert_eq!(profile.signatures[0].pattern_bytes().unwrap(), b"DHFS");
    }

    #[test]
    fn missing_evidence_status_fails() {
        let invalid_toml = r#"
profile_id = "test"
profile_version = "1.0"
schema_version = "1.0"
oem = "test"
storage_family = "test"

[applicability]
models = []

[[signatures]]
name = "test_sig"
pattern_hex = "12 34"
# missing evidence_status!
weight = 0.5

[confidence_weights]
max_possible_score = 1.0
"#;
        let res = OemProfile::from_toml_str(invalid_toml);
        assert!(res.is_err());
    }

    #[test]
    fn applicability_matching() {
        let profile = OemProfile::from_toml_str(SAMPLE_TOML).unwrap();
        assert!(profile.applicability.matches(Some("XVR"), None, None));
        assert!(profile.applicability.matches(Some("xvr"), None, None)); // case insensitive
        assert!(!profile.applicability.matches(Some("DS-7204"), None, None)); // not in models list
    }
}
