//! Overwritten/unrecoverable classification rules (Req 13.3, 13.7, 13.8, 13.11).
//!
//! Constraints:
//! - Corrupted != Unrecoverable (Req 13.7)
//! - DataState and RecoveryStatus are independent (Req 13.8)
//! - Missing index != overwritten (Req 13.11)
//! - Only confirmed physical overwrite evidence → Overwritten state (Req 13.3)

use forensic_core::{DataState, RecoveryAssessment, RecoveryStatus};

/// Classifies a candidate's data state and recovery status based on evidence.
/// This function enforces all the independence constraints from the requirements.
pub fn classify_recovery(
    has_index_entry: bool,
    is_physically_present: bool,
    is_structurally_valid: bool,
    has_overwrite_evidence: bool,
) -> RecoveryAssessment {
    let data_state = if has_overwrite_evidence {
        // Only confirmed physical overwrite evidence → Overwritten (Req 13.3)
        DataState::Overwritten
    } else if !has_index_entry && is_physically_present {
        // Missing index but payload exists → Orphaned, NOT Overwritten (Req 13.11)
        DataState::Orphaned
    } else if !is_structurally_valid {
        DataState::Corrupted
    } else if has_index_entry && !is_physically_present {
        DataState::Deleted
    } else {
        DataState::Active
    };

    let recovery_status = if has_overwrite_evidence && !is_physically_present {
        RecoveryStatus::Unrecoverable
    } else if !is_structurally_valid && is_physically_present {
        // Corrupted != Unrecoverable (Req 13.7) — corrupted data may still be partially recoverable
        RecoveryStatus::PartiallyRecoverable
    } else if is_physically_present {
        RecoveryStatus::Recoverable
    } else {
        RecoveryStatus::Unrecoverable
    };

    RecoveryAssessment {
        data_state,
        recovery_status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_corrupted_is_not_automatically_unrecoverable() {
        // Req 13.7: Corrupted != Unrecoverable
        let assessment = classify_recovery(true, true, false, false);
        assert_eq!(assessment.data_state, DataState::Corrupted);
        assert_eq!(assessment.recovery_status, RecoveryStatus::PartiallyRecoverable);
    }

    #[test]
    fn test_missing_index_is_orphaned_not_overwritten() {
        // Req 13.11: Missing index != overwritten
        let assessment = classify_recovery(false, true, true, false);
        assert_eq!(assessment.data_state, DataState::Orphaned);
        assert_eq!(assessment.recovery_status, RecoveryStatus::Recoverable);
    }

    #[test]
    fn test_confirmed_overwrite_is_overwritten() {
        let assessment = classify_recovery(true, false, false, true);
        assert_eq!(assessment.data_state, DataState::Overwritten);
        assert_eq!(assessment.recovery_status, RecoveryStatus::Unrecoverable);
    }

    #[test]
    fn test_active_data() {
        let assessment = classify_recovery(true, true, true, false);
        assert_eq!(assessment.data_state, DataState::Active);
        assert_eq!(assessment.recovery_status, RecoveryStatus::Recoverable);
    }

    #[test]
    fn test_deleted_data() {
        let assessment = classify_recovery(true, false, true, false);
        assert_eq!(assessment.data_state, DataState::Deleted);
        assert_eq!(assessment.recovery_status, RecoveryStatus::Unrecoverable);
    }
}
