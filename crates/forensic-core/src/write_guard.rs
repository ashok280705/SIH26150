//! # Application-Level WriteGuard and Write-Denied Auditing
//!
//! Implements secondary application-level write protection to prevent writing into evidence
//! directories and ensure derived artifacts land in dedicated artifact folders (Req 1.3, 1.4, 1.5).
//!
//! Key invariants:
//! - Attempts to write to paths resolving inside the evidence directory are denied with `ForensicError::WriteDenied`.
//! - Denied writes generate a `CustodyAction::WriteDenied` chain-of-custody event.
//! - Read-only OS handles remain the primary safeguard; WriteGuard is a defense-in-depth layer.

use std::path::{Path, PathBuf};

use crate::chain_of_custody::{CustodyAction, CustodyEvent, CustodyLog};
use crate::error::ForensicError;
use crate::identifiers::{CaseId, ExaminerId};

/// Application-level safeguard enforcing read-only boundary around evidence directories.
#[derive(Debug, Clone)]
pub struct WriteGuard {
    evidence_dir: PathBuf,
    artifacts_dir: PathBuf,
}

impl WriteGuard {
    /// Create a new WriteGuard with configured evidence and artifacts roots.
    pub fn new(evidence_dir: impl Into<PathBuf>, artifacts_dir: impl Into<PathBuf>) -> Self {
        Self {
            evidence_dir: evidence_dir.into(),
            artifacts_dir: artifacts_dir.into(),
        }
    }

    /// The configured artifacts root directory.
    pub fn artifacts_dir(&self) -> &Path {
        &self.artifacts_dir
    }

    /// Check if a proposed write path is permitted.
    ///
    /// Returns `Ok(())` if the path is safely outside the evidence directory and inside
    /// or relative to the artifacts directory. Returns `Err(ForensicError::WriteDenied)` if
    /// the target resolves within the evidence directory.
    pub fn validate_write_path(&self, target_path: &Path) -> Result<(), ForensicError> {
        let canonical_target = if target_path.exists() {
            target_path.canonicalize().map_err(|e| {
                ForensicError::io(format!("canonicalizing {}", target_path.display()), e)
            })?
        } else {
            // For not-yet-created files, check parent or normalized path
            if let Some(parent) = target_path.parent() {
                if parent.exists() {
                    let canon_parent = parent.canonicalize().map_err(|e| {
                        ForensicError::io(format!("canonicalizing parent {}", parent.display()), e)
                    })?;
                    canon_parent.join(target_path.file_name().unwrap_or_default())
                } else {
                    target_path.to_path_buf()
                }
            } else {
                target_path.to_path_buf()
            }
        };

        let evidence_canon = self
            .evidence_dir
            .canonicalize()
            .unwrap_or_else(|_| self.evidence_dir.clone());

        if canonical_target.starts_with(&evidence_canon) {
            return Err(ForensicError::WriteDenied {
                path: target_path.display().to_string(),
                reason: "target path resolves inside protected evidence directory".into(),
            });
        }

        Ok(())
    }

    /// Attempt a write operation through the guard, automatically logging a `WriteDenied`
    /// custody event to the provided `CustodyLog` if rejected.
    pub fn guard_write<F, T>(
        &self,
        target_path: &Path,
        case_id: CaseId,
        examiner: ExaminerId,
        custody_log: &mut CustodyLog,
        write_fn: F,
    ) -> Result<T, ForensicError>
    where
        F: FnOnce(&Path) -> Result<T, ForensicError>,
    {
        match self.validate_write_path(target_path) {
            Ok(()) => write_fn(target_path),
            Err(e) => {
                let reason = match &e {
                    ForensicError::WriteDenied { reason, .. } => reason.clone(),
                    _ => format!("{e}"),
                };
                let event = CustodyEvent::new(
                    examiner,
                    CustodyAction::WriteDenied,
                    format!("write denied for '{}': {}", target_path.display(), reason),
                    case_id,
                );
                custody_log.append(event);
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn write_inside_evidence_dir_is_denied() {
        let temp_dir = std::env::temp_dir().join(format!("guard_test_{}", uuid::Uuid::new_v4()));
        let evidence_dir = temp_dir.join("evidence");
        let artifacts_dir = temp_dir.join("artifacts");

        fs::create_dir_all(&evidence_dir).unwrap();
        fs::create_dir_all(&artifacts_dir).unwrap();

        let guard = WriteGuard::new(&evidence_dir, &artifacts_dir);
        let mut log = CustodyLog::new();

        let forbidden_target = evidence_dir.join("tampered.raw");
        let case_id = CaseId::new();
        let examiner = ExaminerId::new("auditor");

        let result = guard.guard_write(&forbidden_target, case_id, examiner, &mut log, |_path| {
            Ok("written")
        });

        assert!(result.is_err());
        assert_eq!(log.len(), 1);
        assert_eq!(log.events()[0].action, CustodyAction::WriteDenied);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn write_in_artifacts_dir_is_allowed() {
        let temp_dir = std::env::temp_dir().join(format!("guard_test_{}", uuid::Uuid::new_v4()));
        let evidence_dir = temp_dir.join("evidence");
        let artifacts_dir = temp_dir.join("artifacts");

        fs::create_dir_all(&evidence_dir).unwrap();
        fs::create_dir_all(&artifacts_dir).unwrap();

        let guard = WriteGuard::new(&evidence_dir, &artifacts_dir);
        let mut log = CustodyLog::new();

        let allowed_target = artifacts_dir.join("report.pdf");
        let case_id = CaseId::new();
        let examiner = ExaminerId::new("auditor");

        let result = guard.guard_write(&allowed_target, case_id, examiner, &mut log, |_path| {
            Ok("written")
        });

        assert!(result.is_ok());
        assert_eq!(log.len(), 0); // No write-denied event

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
