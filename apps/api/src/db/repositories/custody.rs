use forensic_core::chain_of_custody::{CustodyAction, CustodyEvent};
use forensic_core::{CaseId, ExaminerId, ForensicError};
use sqlx::{SqlitePool, Row};

pub async fn insert_event(
    pool: &SqlitePool,
    event: &CustodyEvent,
) -> Result<(), ForensicError> {
    let action_str = event.action.to_string();
    let id = uuid::Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO chain_of_custody (
            id, case_id, timestamp, examiner, action, artifact_id, result
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#
    )
    .bind(id)
    .bind(event.case_id.0)
    .bind(event.timestamp)
    .bind(&event.examiner.0)
    .bind(&action_str)
    .bind(event.artifact_id.as_ref().map(|a| a.0))
    .bind(&event.result)
    .execute(pool)
    .await
    .map_err(|e| ForensicError::corrupt("insert_event_db", format!("Failed to insert custody event: {e}")))?;

    Ok(())
}

fn parse_action(s: &str) -> CustodyAction {
    match s {
        "ingest" => CustodyAction::Ingest,
        "source_safety_decision" => CustodyAction::SourceSafetyDecision,
        "detection_run" => CustodyAction::DetectionRun,
        "parse" => CustodyAction::Parse,
        "recovery" => CustodyAction::Recovery,
        "export" => CustodyAction::Export,
        "report" => CustodyAction::Report,
        "write_denied" => CustodyAction::WriteDenied,
        "hash_computed" => CustodyAction::HashComputed,
        _ => CustodyAction::Ingest, // default fallback
    }
}

pub async fn get_custody_log(
    pool: &SqlitePool,
    case_id: &CaseId,
) -> Result<Vec<CustodyEvent>, ForensicError> {
    let rows = sqlx::query(
        r#"
        SELECT
            id, case_id, timestamp, examiner, action, artifact_id, result
        FROM chain_of_custody
        WHERE case_id = ?1
        ORDER BY timestamp ASC
        "#
    )
    .bind(case_id.0)
    .fetch_all(pool)
    .await
    .map_err(|e| ForensicError::corrupt("get_custody_log_db", format!("Failed to fetch custody log: {e}")))?;

    let mut events = Vec::new();
    for r in rows {
        let _id_val: uuid::Uuid = r.try_get("id").unwrap();
        let case_id_val: uuid::Uuid = r.try_get("case_id").unwrap();
        let examiner_str: String = r.try_get("examiner").unwrap();
        let action_str: String = r.try_get("action").unwrap();
        let artifact_id_val: Option<uuid::Uuid> = r.try_get("artifact_id").unwrap();
        let artifact_id = artifact_id_val.map(forensic_core::identifiers::ArtifactId);

        events.push(CustodyEvent {
            timestamp: r.try_get("timestamp").unwrap(),
            examiner: ExaminerId::new(examiner_str),
            action: parse_action(&action_str),
            artifact_id,
            result: r.try_get("result").unwrap(),
            case_id: CaseId(case_id_val),
        });
    }

    Ok(events)
}
