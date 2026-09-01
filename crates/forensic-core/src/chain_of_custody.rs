//! # Chain of Custody Logging
//!
//! Append-only event log for significant forensic actions: ingest, source-safety decision,
//! detection run, parse, recovery, export, report, and write-denied events (Req 5.3, 5.5).
//!
//! Events are append-only within a case and cannot be mutated after creation. The source
//! safety decision and its reason are logged here (Req 1.11).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::identifiers::{ArtifactId, CaseId, ExaminerId};

/// The type of action being logged.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyAction {
    /// Evidence was ingested into the case.
    Ingest,
    /// A source safety decision was made (accepted or rejected).
    SourceSafetyDecision,
    /// A detection run was performed.
    DetectionRun,
    /// Evidence was parsed.
    Parse,
    /// Data recovery was performed.
    Recovery,
    /// An artifact was exported.
    Export,
    /// A report was generated.
    Report,
    /// A write attempt was denied.
    WriteDenied,
    /// Hash was computed for an artifact.
    HashComputed,
}

impl std::fmt::Display for CustodyAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ingest => write!(f, "ingest"),
            Self::SourceSafetyDecision => write!(f, "source_safety_decision"),
            Self::DetectionRun => write!(f, "detection_run"),
            Self::Parse => write!(f, "parse"),
            Self::Recovery => write!(f, "recovery"),
            Self::Export => write!(f, "export"),
            Self::Report => write!(f, "report"),
            Self::WriteDenied => write!(f, "write_denied"),
            Self::HashComputed => write!(f, "hash_computed"),
        }
    }
}

/// A single chain-of-custody event.
///
/// Events are append-only: once created they cannot be modified or deleted within a case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyEvent {
    /// When this event occurred.
    pub timestamp: DateTime<Utc>,
    /// The examiner who performed the action.
    pub examiner: ExaminerId,
    /// What action was performed.
    pub action: CustodyAction,
    /// The artifact involved, if any.
    pub artifact_id: Option<ArtifactId>,
    /// The result or outcome of the action.
    pub result: String,
    /// The case this event belongs to.
    pub case_id: CaseId,
}

impl CustodyEvent {
    /// Create a new chain-of-custody event with the current timestamp.
    pub fn new(
        examiner: ExaminerId,
        action: CustodyAction,
        result: impl Into<String>,
        case_id: CaseId,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            examiner,
            action,
            artifact_id: None,
            result: result.into(),
            case_id,
        }
    }

    /// Associate an artifact with this event.
    pub fn with_artifact(mut self, artifact_id: ArtifactId) -> Self {
        self.artifact_id = Some(artifact_id);
        self
    }
}

impl std::fmt::Display for CustodyEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} by {} (case {}): {}",
            self.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            self.action,
            self.examiner,
            self.case_id,
            self.result
        )
    }
}

/// An append-only chain-of-custody log for a case.
///
/// Events can only be appended; no mutation or deletion is possible (Req 5.3, 5.5).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CustodyLog {
    events: Vec<CustodyEvent>,
}

impl CustodyLog {
    /// Create a new empty custody log.
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Append an event to the log. This is the only way to add events.
    pub fn append(&mut self, event: CustodyEvent) {
        self.events.push(event);
    }

    /// Get all events (read-only).
    pub fn events(&self) -> &[CustodyEvent] {
        &self.events
    }

    /// Number of events in the log.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Get events filtered by action type.
    pub fn events_by_action(&self, action: &CustodyAction) -> Vec<&CustodyEvent> {
        self.events.iter().filter(|e| &e.action == action).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_creation() {
        let event = CustodyEvent::new(
            ExaminerId::new("det-jane"),
            CustodyAction::Ingest,
            "evidence registered successfully",
            CaseId::new(),
        );
        assert_eq!(event.action, CustodyAction::Ingest);
        assert!(!event.result.is_empty());
    }

    #[test]
    fn event_serde_roundtrip() {
        let event = CustodyEvent::new(
            ExaminerId::new("det-jane"),
            CustodyAction::SourceSafetyDecision,
            "source rejected: read-write mount detected",
            CaseId::new(),
        )
        .with_artifact(ArtifactId::new());

        let json = serde_json::to_string(&event).unwrap();
        let back: CustodyEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn log_append_only() {
        let mut log = CustodyLog::new();
        assert!(log.is_empty());

        let case_id = CaseId::new();
        log.append(CustodyEvent::new(
            ExaminerId::new("ex"),
            CustodyAction::Ingest,
            "ingested",
            case_id,
        ));
        log.append(CustodyEvent::new(
            ExaminerId::new("ex"),
            CustodyAction::DetectionRun,
            "detection complete",
            case_id,
        ));

        assert_eq!(log.len(), 2);
        assert_eq!(log.events()[0].action, CustodyAction::Ingest);
        assert_eq!(log.events()[1].action, CustodyAction::DetectionRun);
    }

    #[test]
    fn filter_by_action() {
        let mut log = CustodyLog::new();
        let case_id = CaseId::new();
        log.append(CustodyEvent::new(
            ExaminerId::new("ex"),
            CustodyAction::Ingest,
            "a",
            case_id,
        ));
        log.append(CustodyEvent::new(
            ExaminerId::new("ex"),
            CustodyAction::WriteDenied,
            "b",
            case_id,
        ));
        log.append(CustodyEvent::new(
            ExaminerId::new("ex"),
            CustodyAction::Ingest,
            "c",
            case_id,
        ));

        let ingests = log.events_by_action(&CustodyAction::Ingest);
        assert_eq!(ingests.len(), 2);
        let writes = log.events_by_action(&CustodyAction::WriteDenied);
        assert_eq!(writes.len(), 1);
    }

    #[test]
    fn all_actions_serialize() {
        let actions = [
            CustodyAction::Ingest,
            CustodyAction::SourceSafetyDecision,
            CustodyAction::DetectionRun,
            CustodyAction::Parse,
            CustodyAction::Recovery,
            CustodyAction::Export,
            CustodyAction::Report,
            CustodyAction::WriteDenied,
            CustodyAction::HashComputed,
        ];
        for action in &actions {
            let json = serde_json::to_string(action).unwrap();
            let back: CustodyAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, &back);
        }
    }

    #[test]
    fn log_serde_roundtrip() {
        let mut log = CustodyLog::new();
        let case_id = CaseId::new();
        log.append(CustodyEvent::new(
            ExaminerId::new("ex"),
            CustodyAction::Ingest,
            "ok",
            case_id,
        ));
        let json = serde_json::to_string(&log).unwrap();
        let back: CustodyLog = serde_json::from_str(&json).unwrap();
        assert_eq!(log.len(), back.len());
    }
}
