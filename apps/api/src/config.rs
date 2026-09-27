//! # Application Configuration and Path Resolution
//!
//! Provides environment, desktop, and directory path resolution for:
//! - SQLite database
//! - OEM / forensic profiles
//! - Forensic artifacts directory
//! - Evidence samples directory
//! - FFmpeg runtime resolution
//!
//! Desktop production paths are isolated and configurable without hardcoding
//! OS-specific paths or assuming the current working directory.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub database_url: String,
    pub profiles_dir: PathBuf,
    pub artifacts_dir: PathBuf,
    pub evidence_samples_dir: PathBuf,
    pub ffmpeg_path: Option<PathBuf>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self::from_env_or_cwd()
    }
}

impl AppConfig {
    /// Loads configuration from environment variables or falls back to development/CWD defaults.
    pub fn from_env_or_cwd() -> Self {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "sqlite:forensic_metadata.db".to_string());

        let profiles_dir = std::env::var("VIDFORGE_PROFILES_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| Self::resolve_profiles_dir());

        let artifacts_dir = std::env::var("VIDFORGE_ARTIFACTS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("artifacts"));

        let evidence_samples_dir = std::env::var("VIDFORGE_EVIDENCE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("evidence_samples"));

        let ffmpeg_path = std::env::var("FORENSIC_FFMPEG_PATH")
            .ok()
            .map(PathBuf::from);

        Self {
            database_url,
            profiles_dir,
            artifacts_dir,
            evidence_samples_dir,
            ffmpeg_path,
        }
    }

    /// Construct configuration for desktop mode, isolating database and artifacts
    /// under a dedicated user data directory (e.g. %APPDATA%/VidForge on Windows).
    pub fn for_desktop(app_data_dir: &Path) -> Self {
        // Ensure directories exist
        let _ = std::fs::create_dir_all(app_data_dir);
        let artifacts_dir = app_data_dir.join("artifacts");
        let _ = std::fs::create_dir_all(&artifacts_dir);
        let evidence_samples_dir = app_data_dir.join("evidence_samples");
        let _ = std::fs::create_dir_all(&evidence_samples_dir);

        let db_path = app_data_dir.join("forensic_metadata.db");
        let database_url = format!("sqlite:{}?mode=rwc", db_path.display());
        let profiles_dir = Self::resolve_profiles_dir();

        let ffmpeg_path = std::env::var("FORENSIC_FFMPEG_PATH")
            .ok()
            .map(PathBuf::from);

        Self {
            database_url,
            profiles_dir,
            artifacts_dir,
            evidence_samples_dir,
            ffmpeg_path,
        }
    }

    /// Resolves the profiles directory using precedence:
    /// 1. CWD `profiles/`
    /// 2. Executable parent `profiles/`
    /// 3. Executable sibling/ancestor resources
    pub fn resolve_profiles_dir() -> PathBuf {
        let cwd_profiles = PathBuf::from("profiles");
        if cwd_profiles.is_dir() {
            return cwd_profiles;
        }

        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                let candidate1 = parent.join("profiles");
                if candidate1.is_dir() {
                    return candidate1;
                }
                let candidate2 = parent.join("../profiles");
                if candidate2.is_dir() {
                    return candidate2;
                }
                let candidate3 = parent.join("../Resources/profiles");
                if candidate3.is_dir() {
                    return candidate3;
                }
            }
        }

        PathBuf::from("profiles")
    }
}
