use forensic_core::{
    CaseId, Evidence, EvidenceId, ExaminerId, ForensicError, ImageFormat, SourceState,
};
use sqlx::{Row, SqlitePool};

pub async fn create_evidence(pool: &SqlitePool, evidence: &Evidence) -> Result<(), ForensicError> {
    let image_format_str = evidence.image_format.to_string();
    let source_state_str = evidence.source_state.to_string();
    let capacity_i64 = evidence.capacity as i64; // sqlite uses i64
    let examiner_tz_json = evidence
        .examiner_timezone
        .as_ref()
        .map(|t| serde_json::to_string(t).unwrap_or_default());

    sqlx::query(
        r#"
        INSERT INTO evidence (
            id, case_id, source_device, acquisition_time, capacity, image_format,
            responsible_examiner, acquisition_tool, acquisition_tool_version,
            source_state, acquisition_id, path, registered_at, examiner_timezone
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
        "#,
    )
    .bind(evidence.id.0)
    .bind(evidence.case_id.0)
    .bind(&evidence.source_device)
    .bind(evidence.acquisition_time)
    .bind(capacity_i64)
    .bind(image_format_str)
    .bind(&evidence.responsible_examiner.0)
    .bind(&evidence.acquisition_tool)
    .bind(&evidence.acquisition_tool_version)
    .bind(source_state_str)
    .bind(evidence.acquisition_id.map(|id| id.0))
    .bind(&evidence.path)
    .bind(evidence.registered_at)
    .bind(examiner_tz_json)
    .execute(pool)
    .await
    .map_err(|e| {
        ForensicError::corrupt(
            "create_evidence_db",
            format!("Failed to insert evidence: {e}"),
        )
    })?;

    Ok(())
}

fn parse_image_format(s: &str) -> ImageFormat {
    match s {
        "raw" => ImageFormat::Raw,
        "dd" => ImageFormat::Dd,
        "img" => ImageFormat::Img,
        "e01" => ImageFormat::E01,
        "physical_disk" => ImageFormat::PhysicalDisk,
        other => {
            if let Some(rest) = other.strip_prefix("other:") {
                ImageFormat::Other(rest.to_string())
            } else {
                ImageFormat::Other(other.to_string())
            }
        }
    }
}

fn parse_source_state(s: &str) -> SourceState {
    match s {
        "read_only" => SourceState::ReadOnly,
        "read_write" => SourceState::ReadWrite,
        _ => SourceState::Unknown,
    }
}

pub async fn get_evidence(
    pool: &SqlitePool,
    id: &EvidenceId,
) -> Result<Option<Evidence>, ForensicError> {
    let row = sqlx::query(
        r#"
        SELECT
            id, case_id, source_device, acquisition_time, capacity, image_format,
            responsible_examiner, acquisition_tool, acquisition_tool_version,
            source_state, acquisition_id, path, registered_at, examiner_timezone
        FROM evidence
        WHERE id = ?1
        "#,
    )
    .bind(id.0)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        ForensicError::corrupt("get_evidence_db", format!("Failed to fetch evidence: {e}"))
    })?;

    if let Some(r) = row {
        Ok(Some(row_to_evidence(&r)?))
    } else {
        Ok(None)
    }
}

pub async fn get_evidence_for_case(
    pool: &SqlitePool,
    case_id: &CaseId,
) -> Result<Vec<Evidence>, ForensicError> {
    let rows = sqlx::query(
        r#"
        SELECT
            id, case_id, source_device, acquisition_time, capacity, image_format,
            responsible_examiner, acquisition_tool, acquisition_tool_version,
            source_state, acquisition_id, path, registered_at, examiner_timezone
        FROM evidence
        WHERE case_id = ?1
        ORDER BY registered_at ASC
        "#,
    )
    .bind(case_id.0)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        ForensicError::corrupt(
            "get_evidence_for_case_db",
            format!("Failed to fetch evidence: {e}"),
        )
    })?;

    let mut res = Vec::new();
    for r in rows {
        res.push(row_to_evidence(&r)?);
    }

    Ok(res)
}

pub async fn update_evidence_timezone(
    pool: &SqlitePool,
    id: &EvidenceId,
    tz: Option<&forensic_core::ExaminerTimezone>,
) -> Result<(), ForensicError> {
    let val = tz.map(|t| serde_json::to_string(t).unwrap_or_default());
    sqlx::query("UPDATE evidence SET examiner_timezone = ?1 WHERE id = ?2")
        .bind(val)
        .bind(id.0)
        .execute(pool)
        .await
        .map_err(|e| {
            ForensicError::corrupt(
                "update_evidence_timezone_db",
                format!("Failed to update evidence timezone: {e}"),
            )
        })?;
    Ok(())
}

fn row_to_evidence(r: &sqlx::sqlite::SqliteRow) -> Result<Evidence, ForensicError> {
    let id_val: uuid::Uuid = r.try_get("id").unwrap();
    let case_id_val: uuid::Uuid = r.try_get("case_id").unwrap();
    let examiner_str: String = r.try_get("responsible_examiner").unwrap();
    let image_format_str: String = r.try_get("image_format").unwrap();
    let source_state_str: String = r.try_get("source_state").unwrap();
    let capacity_i64: i64 = r.try_get("capacity").unwrap();
    let acq_id_val: Option<uuid::Uuid> = r.try_get("acquisition_id").unwrap();
    let examiner_tz_raw: Option<String> = r.try_get("examiner_timezone").unwrap_or(None);
    let examiner_timezone: Option<forensic_core::ExaminerTimezone> =
        examiner_tz_raw.and_then(|s| serde_json::from_str(&s).ok());

    let ev = Evidence {
        id: EvidenceId(id_val),
        case_id: CaseId(case_id_val),
        source_device: r.try_get("source_device").unwrap(),
        acquisition_time: r.try_get("acquisition_time").unwrap(),
        capacity: capacity_i64 as u64,
        image_format: parse_image_format(&image_format_str),
        responsible_examiner: ExaminerId::new(examiner_str),
        acquisition_tool: r.try_get("acquisition_tool").unwrap(),
        acquisition_tool_version: r.try_get("acquisition_tool_version").unwrap(),
        source_state: parse_source_state(&source_state_str),
        acquisition_id: acq_id_val.map(forensic_core::identifiers::AcquisitionId),
        path: r.try_get("path").unwrap(),
        registered_at: r.try_get("registered_at").unwrap(),
        examiner_timezone,
    };

    Ok(ev)
}
