//! # Case and Evidence Domain Model
//!
//! `Case` and `Evidence` structs with required acquisition fields, optional tool fields,
//! and the `source_state` field that defaults to `Unknown` (Req 7.1–7.6, 1.8).
//!
//! Key invariants:
//! - Optional tool fields must not block registration when unknown (Req 7.6).
//! - Each evidence belongs to exactly one case (Req 7.3).
//! - `source_state` defaults to `Unknown` and is never asserted as `ReadOnly` without
//!   inspection (Req 1.12).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::identifiers::{AcquisitionId, CaseId, EvidenceId, ExaminerId};

/// The state of the evidence source as determined by inspection.
///
/// Defaults to `Unknown` — never asserted as `ReadOnly` without actual inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceState {
    /// The source was inspected and found to be read-only (e.g. hardware write blocker).
    ReadOnly,
    /// The source was inspected and found to be read-write (mount, no write blocker).
    ReadWrite,
    /// The source state could not be determined, or inspection has not run.
    Unknown,
}

impl Default for SourceState {
    /// Defaults to `Unknown` — never assume read-only without inspection (Req 1.12).
    fn default() -> Self {
        Self::Unknown
    }
}

impl std::fmt::Display for SourceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadOnly => write!(f, "read_only"),
            Self::ReadWrite => write!(f, "read_write"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// The format of an evidence image file.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageFormat {
    /// Raw binary image (.raw).
    Raw,
    /// dd image (.dd).
    Dd,
    /// Disk image (.img).
    Img,
    /// Expert Witness Format (.E01) — NOT implemented, gated by OPEN-1.
    E01,
    /// Physical block device.
    PhysicalDisk,
    /// Another format.
    Other(String),
}

impl std::fmt::Display for ImageFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Raw => write!(f, "raw"),
            Self::Dd => write!(f, "dd"),
            Self::Img => write!(f, "img"),
            Self::E01 => write!(f, "e01"),
            Self::PhysicalDisk => write!(f, "physical_disk"),
            Self::Other(s) => write!(f, "other:{s}"),
        }
    }
}

/// A forensic case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Case {
    /// Unique case identifier.
    pub id: CaseId,
    /// Human-readable case name.
    pub name: String,
    /// Case description or notes.
    pub description: String,
    /// The examiner who created this case.
    pub examiner: ExaminerId,
    /// When the case was created.
    pub created_at: DateTime<Utc>,
    /// When the case was last updated.
    pub updated_at: DateTime<Utc>,
}

impl Case {
    /// Create a new case with the current timestamp.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        examiner: ExaminerId,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: CaseId::new(),
            name: name.into(),
            description: description.into(),
            examiner,
            created_at: now,
            updated_at: now,
        }
    }
}

/// A piece of forensic evidence (disk image, physical device, etc.).
///
/// Each evidence belongs to exactly one case (Req 7.3). Optional fields
/// (`acquisition_tool`, `acquisition_tool_version`) never block registration (Req 7.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Unique evidence identifier.
    pub id: EvidenceId,
    /// The case this evidence belongs to. Exactly one case per evidence (Req 7.3).
    pub case_id: CaseId,
    /// Description of the source device (make, model, serial number if available).
    pub source_device: String,
    /// When the acquisition was performed.
    pub acquisition_time: DateTime<Utc>,
    /// Total capacity of the source in bytes.
    pub capacity: u64,
    /// The format of the image file.
    pub image_format: ImageFormat,
    /// The examiner responsible for this evidence.
    pub responsible_examiner: ExaminerId,
    /// The acquisition tool used (optional — must not block registration, Req 7.6).
    pub acquisition_tool: Option<String>,
    /// Version of the acquisition tool (optional, Req 7.6).
    pub acquisition_tool_version: Option<String>,
    /// The state of the source as determined by inspection. Defaults to `Unknown`.
    #[serde(default)]
    pub source_state: SourceState,
    /// Link to the acquisition record, if available.
    pub acquisition_id: Option<AcquisitionId>,
    /// Path to the evidence file (for the reader to open).
    pub path: String,
    /// When this evidence was registered.
    pub registered_at: DateTime<Utc>,
}

impl Evidence {
    /// Create a new evidence record with `source_state` defaulting to `Unknown`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        case_id: CaseId,
        source_device: impl Into<String>,
        acquisition_time: DateTime<Utc>,
        capacity: u64,
        image_format: ImageFormat,
        responsible_examiner: ExaminerId,
        path: impl Into<String>,
    ) -> Self {
        Self {
            id: EvidenceId::new(),
            case_id,
            source_device: source_device.into(),
            acquisition_time,
            capacity,
            image_format,
            responsible_examiner,
            acquisition_tool: None,
            acquisition_tool_version: None,
            source_state: SourceState::Unknown,
            acquisition_id: None,
            path: path.into(),
            registered_at: Utc::now(),
        }
    }

    /// Set optional acquisition tool information.
    pub fn with_tool(
        mut self,
        tool: impl Into<String>,
        version: Option<impl Into<String>>,
    ) -> Self {
        self.acquisition_tool = Some(tool.into());
        self.acquisition_tool_version = version.map(|v| v.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_serde_roundtrip() {
        let case = Case::new("Test Case", "A test", ExaminerId::new("examiner-1"));
        let json = serde_json::to_string(&case).unwrap();
        let back: Case = serde_json::from_str(&json).unwrap();
        assert_eq!(case, back);
    }

    #[test]
    fn evidence_serde_roundtrip() {
        let case_id = CaseId::new();
        let ev = Evidence::new(
            case_id,
            "Dahua XVR 4108HS",
            Utc::now(),
            500_000_000_000,
            ImageFormat::Raw,
            ExaminerId::new("det-jane"),
            "/evidence/disk.raw",
        );
        let json = serde_json::to_string(&ev).unwrap();
        let back: Evidence = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn default_source_state_is_unknown() {
        let case_id = CaseId::new();
        let ev = Evidence::new(
            case_id,
            "device",
            Utc::now(),
            0,
            ImageFormat::Raw,
            ExaminerId::new("ex"),
            "/path",
        );
        assert_eq!(ev.source_state, SourceState::Unknown);
    }

    #[test]
    fn optional_tool_fields() {
        let case_id = CaseId::new();

        // Without tool info — should work (Req 7.6).
        let ev_no_tool = Evidence::new(
            case_id,
            "device",
            Utc::now(),
            0,
            ImageFormat::Raw,
            ExaminerId::new("ex"),
            "/path",
        );
        assert!(ev_no_tool.acquisition_tool.is_none());
        assert!(ev_no_tool.acquisition_tool_version.is_none());

        // With tool info.
        let ev_with_tool = Evidence::new(
            case_id,
            "device",
            Utc::now(),
            0,
            ImageFormat::Raw,
            ExaminerId::new("ex"),
            "/path",
        )
        .with_tool("FTK Imager", Some("4.7.1"));
        assert_eq!(ev_with_tool.acquisition_tool.as_deref(), Some("FTK Imager"));
        assert_eq!(
            ev_with_tool.acquisition_tool_version.as_deref(),
            Some("4.7.1")
        );
    }

    #[test]
    fn evidence_belongs_to_one_case() {
        let case_id = CaseId::new();
        let ev = Evidence::new(
            case_id,
            "device",
            Utc::now(),
            0,
            ImageFormat::Raw,
            ExaminerId::new("ex"),
            "/path",
        );
        assert_eq!(ev.case_id, case_id);
    }

    #[test]
    fn source_state_values() {
        for state in [SourceState::ReadOnly, SourceState::ReadWrite, SourceState::Unknown] {
            let json = serde_json::to_string(&state).unwrap();
            let back: SourceState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, back);
        }
    }

    #[test]
    fn image_format_values() {
        let formats = [
            ImageFormat::Raw,
            ImageFormat::Dd,
            ImageFormat::Img,
            ImageFormat::E01,
            ImageFormat::PhysicalDisk,
            ImageFormat::Other("dmg".into()),
        ];
        for fmt in &formats {
            let json = serde_json::to_string(fmt).unwrap();
            let back: ImageFormat = serde_json::from_str(&json).unwrap();
            assert_eq!(fmt, &back);
        }
    }
}
