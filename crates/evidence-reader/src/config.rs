//! # Reader Configuration
//!
//! Loads the read-window configuration from `config/reader.toml` (OPEN-2 decision).
//! All values are provisional engineering defaults, not forensic constants.

use serde::Deserialize;
use std::path::Path;

/// Reader configuration loaded from `config/reader.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct ReaderConfig {
    pub config_id: String,
    pub config_version: String,
    pub status: String,
    pub read_window: ReadWindowConfig,
}

/// Read window / bounded buffer configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ReadWindowConfig {
    /// Maximum read window in bytes (provisional default: 16 MiB).
    pub max_bytes: u64,
    /// Minimum read window in bytes (floor: 4 KiB).
    pub min_bytes: u64,
    /// Allowed range for validation.
    pub allowed: Option<ReadWindowAllowed>,
}

/// Allowed ranges for read window configuration values.
#[derive(Debug, Clone, Deserialize)]
pub struct ReadWindowAllowed {
    pub max_bytes: AllowedRange,
    pub min_bytes: AllowedRange,
}

/// An allowed range for a configuration value.
#[derive(Debug, Clone, Deserialize)]
pub struct AllowedRange {
    pub min: u64,
    pub max: u64,
}

impl ReaderConfig {
    /// Load the reader configuration from a TOML file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read reader config at {}: {e}", path.display()))?;
        let config: Self = toml::from_str(&content)
            .map_err(|e| format!("failed to parse reader config: {e}"))?;
        config.validate()?;
        Ok(config)
    }

    /// Load from the default workspace path.
    pub fn load_default() -> Result<Self, String> {
        // Try common paths relative to the workspace root.
        let candidates = ["config/reader.toml", "../config/reader.toml"];
        for candidate in &candidates {
            let path = Path::new(candidate);
            if path.exists() {
                return Self::load(path);
            }
        }
        // Fall back to provisional defaults if config file is not found.
        Ok(Self::provisional_default())
    }

    /// Provisional engineering defaults (matching config/reader.toml).
    pub fn provisional_default() -> Self {
        Self {
            config_id: "reader".into(),
            config_version: "reader-1.0.0".into(),
            status: "provisional".into(),
            read_window: ReadWindowConfig {
                max_bytes: 16 * 1024 * 1024, // 16 MiB
                min_bytes: 4096,              // 4 KiB
                allowed: Some(ReadWindowAllowed {
                    max_bytes: AllowedRange {
                        min: 8 * 1024 * 1024,  // 8 MiB
                        max: 64 * 1024 * 1024, // 64 MiB
                    },
                    min_bytes: AllowedRange {
                        min: 512,
                        max: 16 * 1024 * 1024, // 16 MiB
                    },
                }),
            },
        }
    }

    /// Validate configuration values against allowed ranges.
    fn validate(&self) -> Result<(), String> {
        if let Some(ref allowed) = self.read_window.allowed {
            let max = self.read_window.max_bytes;
            if max < allowed.max_bytes.min || max > allowed.max_bytes.max {
                return Err(format!(
                    "read_window.max_bytes ({max}) outside allowed range [{}, {}]",
                    allowed.max_bytes.min, allowed.max_bytes.max
                ));
            }
            let min = self.read_window.min_bytes;
            if min < allowed.min_bytes.min || min > allowed.min_bytes.max {
                return Err(format!(
                    "read_window.min_bytes ({min}) outside allowed range [{}, {}]",
                    allowed.min_bytes.min, allowed.min_bytes.max
                ));
            }
            if min > max {
                return Err(format!(
                    "read_window.min_bytes ({min}) > read_window.max_bytes ({max})"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisional_default_is_valid() {
        let config = ReaderConfig::provisional_default();
        assert_eq!(config.read_window.max_bytes, 16 * 1024 * 1024);
        assert_eq!(config.read_window.min_bytes, 4096);
    }

    #[test]
    fn validation_rejects_out_of_range() {
        let mut config = ReaderConfig::provisional_default();
        config.read_window.max_bytes = 1024; // Way below minimum (8 MiB)
        assert!(config.validate().is_err());
    }

    #[test]
    fn validation_rejects_min_above_max() {
        let mut config = ReaderConfig::provisional_default();
        config.read_window.min_bytes = config.read_window.max_bytes + 1;
        assert!(config.validate().is_err());
    }
}
