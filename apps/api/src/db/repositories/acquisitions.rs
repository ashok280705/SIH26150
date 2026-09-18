use forensic_core::acquisition::{Acquisition, AcquisitionStatus};
use forensic_core::{EvidenceId, ForensicError};
use forensic_core::identifiers::AcquisitionId;
use sqlx::{SqlitePool, Row};

pub async fn create_acquisition(
    pool: &SqlitePool,
    acq: &Acquisition,
) -> Result<(), ForensicError> {
    let status_str = acq.status.to_string();
    let bad_sectors_json = serde_json::to_string(&acq.bad_sector_ranges).unwrap();
    let unresolved_json = serde_json::to_string(&acq.unresolved_ranges).unwrap();
    let verification_state_str = acq.verification.state.to_string();
    let map_hash_bytes = acq.map_hash.as_ref().map(|h| h.value.clone());

    sqlx::query(
        r#"
        INSERT INTO acquisitions (
            id, evidence_id, status, tool, tool_version,
            map_reference, map_hash, bad_sector_ranges, unresolved_ranges,
            verification_state, verification_reason, created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#
    )
    .bind(acq.id.0)
    .bind(acq.evidence_id.0)
    .bind(status_str)
    .bind(&acq.tool)
    .bind(&acq.tool_version)
    .bind(&acq.map_reference)
    .bind(map_hash_bytes)
    .bind(bad_sectors_json)
    .bind(unresolved_json)
    .bind(&verification_state_str)
    .bind(&acq.verification.reason)
    .bind(acq.created_at)
    .execute(pool)
    .await
    .map_err(|e| ForensicError::corrupt("create_acquisition_db", format!("Failed to insert acquisition: {e}")))?;

    Ok(())
}

fn parse_status(s: &str) -> AcquisitionStatus {
    match s {
        "complete" => AcquisitionStatus::Complete,
        "partial" => AcquisitionStatus::Partial,
        "failed" => AcquisitionStatus::Failed,
        _ => AcquisitionStatus::Unknown,
    }
}

pub async fn get_acquisition(
    pool: &SqlitePool,
    id: &AcquisitionId,
) -> Result<Option<Acquisition>, ForensicError> {
    let row = sqlx::query(
        r#"
        SELECT
            id, evidence_id, status, tool, tool_version,
            map_reference, map_hash, bad_sector_ranges, unresolved_ranges,
            verification_state, verification_reason, created_at
        FROM acquisitions
        WHERE id = ?1
        "#
    )
    .bind(id.0)
    .fetch_optional(pool)
    .await
    .map_err(|e| ForensicError::corrupt("get_acquisition_db", format!("Failed to fetch acquisition: {e}")))?;

    if let Some(r) = row {
        Ok(Some(row_to_acquisition(&r)?))
    } else {
        Ok(None)
    }
}

pub async fn get_acquisition_for_evidence(
    pool: &SqlitePool,
    evidence_id: &EvidenceId,
) -> Result<Option<Acquisition>, ForensicError> {
    let row = sqlx::query(
        r#"
        SELECT
            id, evidence_id, status, tool, tool_version,
            map_reference, map_hash, bad_sector_ranges, unresolved_ranges,
            verification_state, verification_reason, created_at
        FROM acquisitions
        WHERE evidence_id = ?1
        ORDER BY created_at DESC
        LIMIT 1
        "#
    )
    .bind(evidence_id.0)
    .fetch_optional(pool)
    .await
    .map_err(|e| ForensicError::corrupt("get_acquisition_for_evidence_db", format!("Failed to fetch acquisition: {e}")))?;

    if let Some(r) = row {
        Ok(Some(row_to_acquisition(&r)?))
    } else {
        Ok(None)
    }
}

fn row_to_acquisition(r: &sqlx::sqlite::SqliteRow) -> Result<Acquisition, ForensicError> {
    let id_val: uuid::Uuid = r.try_get("id").unwrap();
    let evidence_id_val: uuid::Uuid = r.try_get("evidence_id").unwrap();
    let status_str: String = r.try_get("status").unwrap();
    let bad_sectors_json: String = r.try_get("bad_sector_ranges").unwrap();
    let unresolved_json: String = r.try_get("unresolved_ranges").unwrap();
    
    let verification_state_str: String = r.try_get("verification_state").unwrap();
    let verification_reason: String = r.try_get("verification_reason").unwrap();

    let map_hash_bytes: Option<Vec<u8>> = r.try_get("map_hash").unwrap();
    let map_hash = map_hash_bytes.map(forensic_core::hash::Hash::sha256);

    // Reconstruct VerificationState
    let val_state_kind = match verification_state_str.as_str() {
        "PASS" | "pass" => forensic_core::validation::ValidationStateKind::Pass,
        "FAIL" | "fail" => forensic_core::validation::ValidationStateKind::Fail,
        "REVIEW" | "review" => forensic_core::validation::ValidationStateKind::Review,
        _ => forensic_core::validation::ValidationStateKind::Unknown,
    };
    
    let verification = forensic_core::validation::ValidationState {
        state: val_state_kind,
        reason: verification_reason,
        operation: "acquisition_verification".into(),
        subject: evidence_id_val.to_string(),
    };

    let bad_sector_ranges = serde_json::from_str(&bad_sectors_json).unwrap_or_default();
    let unresolved_ranges = serde_json::from_str(&unresolved_json).unwrap_or_default();

    let acq = Acquisition {
        id: AcquisitionId(id_val),
        evidence_id: EvidenceId(evidence_id_val),
        status: parse_status(&status_str),
        tool: r.try_get("tool").unwrap(),
        tool_version: r.try_get("tool_version").unwrap(),
        map_reference: r.try_get("map_reference").unwrap(),
        map_hash,
        bad_sector_ranges,
        unresolved_ranges,
        verification,
        created_at: r.try_get("created_at").unwrap(),
    };

    Ok(acq)
}
