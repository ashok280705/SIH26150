use chrono::Utc;
use forensic_core::{Case, CaseId, ExaminerId, ForensicError};
use sqlx::{Row, SqlitePool};

pub async fn create_case(
    pool: &SqlitePool,
    name: &str,
    description: &str,
    examiner: &ExaminerId,
) -> Result<Case, ForensicError> {
    let id = CaseId::new();
    let now = Utc::now();
    let examiner_str = &examiner.0;

    // SQLite doesn't natively support UUID or TIMESTAMPTZ, sqlx-sqlite handles them as string/blob depending on settings.
    // However, with `uuid` and `chrono` features enabled, we can bind UUIDs and DateTime<Utc> directly.
    sqlx::query(
        r#"
        INSERT INTO cases (id, name, description, examiner, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#,
    )
    .bind(id.0)
    .bind(name)
    .bind(description)
    .bind(examiner_str)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await
    .map_err(|e| ForensicError::corrupt("create_case_db", format!("Failed to insert case: {e}")))?;

    Ok(Case {
        id,
        name: name.to_string(),
        description: description.to_string(),
        examiner: examiner.clone(),
        created_at: now,
        updated_at: now,
    })
}

pub async fn get_case(pool: &SqlitePool, id: &CaseId) -> Result<Option<Case>, ForensicError> {
    let row = sqlx::query(
        r#"
        SELECT id, name, description, examiner, created_at, updated_at
        FROM cases
        WHERE id = ?1
        "#,
    )
    .bind(id.0)
    .fetch_optional(pool)
    .await
    .map_err(|e| ForensicError::corrupt("get_case_db", format!("Failed to fetch case: {e}")))?;

    if let Some(r) = row {
        let examiner_str: String = r
            .try_get("examiner")
            .map_err(|e| ForensicError::corrupt("get_case_db", format!("Invalid examiner: {e}")))?;

        Ok(Some(Case {
            id: CaseId(r.try_get("id").unwrap()),
            name: r.try_get("name").unwrap(),
            description: r.try_get("description").unwrap(),
            examiner: ExaminerId::new(examiner_str),
            created_at: r.try_get("created_at").unwrap(),
            updated_at: r.try_get("updated_at").unwrap(),
        }))
    } else {
        Ok(None)
    }
}

pub async fn get_all_cases(pool: &SqlitePool) -> Result<Vec<Case>, ForensicError> {
    let rows = sqlx::query(
        r#"
        SELECT id, name, description, examiner, created_at, updated_at
        FROM cases
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| {
        ForensicError::corrupt("get_all_cases_db", format!("Failed to fetch cases: {e}"))
    })?;

    let mut cases = Vec::new();
    for r in rows {
        let examiner_str: String = r.try_get("examiner").map_err(|e| {
            ForensicError::corrupt("get_all_cases_db", format!("Invalid examiner: {e}"))
        })?;

        cases.push(Case {
            id: CaseId(r.try_get("id").unwrap()),
            name: r.try_get("name").unwrap(),
            description: r.try_get("description").unwrap(),
            examiner: ExaminerId::new(examiner_str),
            created_at: r.try_get("created_at").unwrap(),
            updated_at: r.try_get("updated_at").unwrap(),
        });
    }

    Ok(cases)
}
