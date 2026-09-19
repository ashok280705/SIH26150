//! Database repository for forensic artifacts, provenance chains, and hash records.

use sqlx::{SqlitePool, Row};
use chrono::Utc;
use forensic_core::{
    DerivedArtifact, DerivedKind, EvidenceId, ForensicError, ValidationStateKind,
};

/// DTO representing an artifact record stored in SQLite along with its provenance details.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredArtifactRecord {
    pub id: uuid::Uuid,
    pub kind: String,
    pub evidence_id: uuid::Uuid,
    pub output_path: String,
    pub description: String,
    pub created_at: String,
    pub sha256: String,
    pub producing_component: String,
    pub component_version: String,
    pub validation_state: String,
    pub validation_reason: String,
    pub source_regions: Vec<SourceRegionDto>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SourceRegionDto {
    pub offset: u64,
    pub length: u64,
    pub description: Option<String>,
}

/// Atomically persists a DerivedArtifact along with its Provenance, Hashes, and ValidationState.
pub async fn save_derived_artifact(
    pool: &SqlitePool,
    evidence_id: &EvidenceId,
    artifact: &DerivedArtifact,
    raw_sha256_hex: &str,
    file_size_bytes: u64,
    duration_ms: u64,
) -> Result<uuid::Uuid, ForensicError> {
    let mut tx = pool.begin().await.map_err(|e| {
        ForensicError::corrupt("save_derived_artifact", format!("Starting SQLite transaction: {e}"))
    })?;

    let now = Utc::now();
    let val_id = uuid::Uuid::new_v4();
    let prov_id = uuid::Uuid::new_v4();
    let hash_id = uuid::Uuid::new_v4();
    let art_id = artifact.id.0;

    let val = &artifact.provenance.validation_state;
    let val_state_str = match val.state {
        ValidationStateKind::Pass => "PASS",
        ValidationStateKind::Review => "REVIEW",
        ValidationStateKind::Fail => "FAIL",
        ValidationStateKind::Unknown => "UNKNOWN",
    };

    // 1. Insert validation_states row
    sqlx::query(
        r#"
        INSERT INTO validation_states (
            id, state, reason, operation, subject, recorded_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#
    )
    .bind(val_id)
    .bind(val_state_str)
    .bind(&val.reason)
    .bind(&val.operation)
    .bind(&val.subject)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| ForensicError::corrupt("save_derived_artifact", format!("Inserting validation state: {e}")))?;

    // 2. Insert provenance row
    let trans_json = serde_json::to_string(&artifact.provenance.transformation_history).unwrap_or_else(|_| "[]".into());
    let source_hash_bytes = artifact.provenance.source_hash.value.clone();
    let output_hash_bytes = hex::decode(raw_sha256_hex).unwrap_or_else(|_| artifact.provenance.output_hash.value.clone());

    sqlx::query(
        r#"
        INSERT INTO provenance (
            id, source_evidence_id, source_hash, producing_component, component_version,
            profile_version, profile_hash, parser_version, recovery_level,
            output_hash, transformation_history, validation_state_id, created_at
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5,
            ?6, ?7, ?8, ?9,
            ?10, ?11, ?12, ?13
        )
        "#
    )
    .bind(prov_id)
    .bind(evidence_id.0)
    .bind(&source_hash_bytes)
    .bind(&artifact.provenance.producing_component)
    .bind(&artifact.provenance.component_version)
    .bind(artifact.provenance.profile_version.as_deref())
    .bind(artifact.provenance.profile_hash.as_ref().map(|h| h.value.clone()))
    .bind(artifact.provenance.parser_version.as_deref())
    .bind(artifact.provenance.recovery_level.as_deref())
    .bind(&output_hash_bytes)
    .bind(&trans_json)
    .bind(val_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| ForensicError::corrupt("save_derived_artifact", format!("Inserting provenance: {e}")))?;

    // 3. Insert source_regions
    for sr in &artifact.provenance.source_regions {
        let sr_id = uuid::Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO source_regions (
                id, provenance_id, evidence_id, offset_bytes, length_bytes, description
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#
        )
        .bind(sr_id)
        .bind(prov_id)
        .bind(sr.evidence_id.0)
        .bind(sr.region.offset as i64)
        .bind(sr.region.length as i64)
        .bind(sr.description.as_deref())
        .execute(&mut *tx)
        .await
        .map_err(|e| ForensicError::corrupt("save_derived_artifact", format!("Inserting source region: {e}")))?;
    }

    // 4. Insert hash record
    sqlx::query(
        r#"
        INSERT INTO hashes (
            id, subject_id, algorithm, value, computed_at, validation_state_id, duration_ms, bytes_hashed
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#
    )
    .bind(hash_id)
    .bind(art_id)
    .bind("sha256")
    .bind(&output_hash_bytes)
    .bind(now)
    .bind(val_id)
    .bind(duration_ms as i64)
    .bind(file_size_bytes as i64)
    .execute(&mut *tx)
    .await
    .map_err(|e| ForensicError::corrupt("save_derived_artifact", format!("Inserting hash record: {e}")))?;

    // 5. Insert artifacts row
    let kind_str = match &artifact.kind {
        DerivedKind::ElementaryStream => "elementary_stream",
        DerivedKind::Remux => "remux",
        DerivedKind::ReviewCopy => "review_copy",
        DerivedKind::AiOutput => "ai_output",
        DerivedKind::Other(s) => s.as_str(),
    };

    sqlx::query(
        r#"
        INSERT INTO artifacts (
            id, kind, evidence_id, provenance_id, output_path, description, created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#
    )
    .bind(art_id)
    .bind(kind_str)
    .bind(evidence_id.0)
    .bind(prov_id)
    .bind(&artifact.output_path)
    .bind(&artifact.description)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| ForensicError::corrupt("save_derived_artifact", format!("Inserting artifact record: {e}")))?;

    tx.commit().await.map_err(|e| {
        ForensicError::corrupt("save_derived_artifact", format!("Committing artifact transaction: {e}"))
    })?;

    Ok(art_id)
}

/// Retrieves a stored artifact record with its provenance and hash details.
pub async fn get_artifact(
    pool: &SqlitePool,
    artifact_id: uuid::Uuid,
) -> Result<Option<StoredArtifactRecord>, ForensicError> {
    let row = sqlx::query(
        r#"
        SELECT
            a.id, a.kind, a.evidence_id, a.output_path, a.description, a.created_at,
            p.id as prov_id, p.producing_component, p.component_version, p.output_hash,
            v.state as val_state, v.reason as val_reason
        FROM artifacts a
        LEFT JOIN provenance p ON a.provenance_id = p.id
        LEFT JOIN validation_states v ON p.validation_state_id = v.id
        WHERE a.id = ?1
        "#
    )
    .bind(artifact_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ForensicError::corrupt("get_artifact", format!("Fetching artifact: {e}")))?;

    let Some(r) = row else {
        return Ok(None);
    };

    let id: uuid::Uuid = r.try_get("id").unwrap();
    let kind: String = r.try_get("kind").unwrap();
    let evidence_id: uuid::Uuid = r.try_get("evidence_id").unwrap();
    let output_path: String = r.try_get("output_path").unwrap_or_default();
    let description: String = r.try_get("description").unwrap_or_default();
    let created_at: chrono::DateTime<Utc> = r.try_get("created_at").unwrap();
    let producing_component: String = r.try_get("producing_component").unwrap_or_default();
    let component_version: String = r.try_get("component_version").unwrap_or_default();
    let output_hash_bytes: Vec<u8> = r.try_get("output_hash").unwrap_or_default();
    let val_state: String = r.try_get("val_state").unwrap_or_else(|_| "UNKNOWN".into());
    let val_reason: String = r.try_get("val_reason").unwrap_or_default();
    let prov_id: Option<uuid::Uuid> = r.try_get("prov_id").ok();

    let mut source_regions = Vec::new();
    if let Some(p_id) = prov_id {
        let sr_rows = sqlx::query(
            r#"
            SELECT offset_bytes, length_bytes, description
            FROM source_regions
            WHERE provenance_id = ?1
            "#
        )
        .bind(p_id)
        .fetch_all(pool)
        .await
        .unwrap_or_default();

        for sr_r in sr_rows {
            let off: i64 = sr_r.try_get("offset_bytes").unwrap_or(0);
            let len: i64 = sr_r.try_get("length_bytes").unwrap_or(0);
            let desc: Option<String> = sr_r.try_get("description").ok();
            source_regions.push(SourceRegionDto {
                offset: off as u64,
                length: len as u64,
                description: desc,
            });
        }
    }

    Ok(Some(StoredArtifactRecord {
        id,
        kind,
        evidence_id,
        output_path,
        description,
        created_at: created_at.to_rfc3339(),
        sha256: hex::encode(output_hash_bytes),
        producing_component,
        component_version,
        validation_state: val_state,
        validation_reason: val_reason,
        source_regions,
    }))
}

/// Lists all artifacts derived from or associated with an evidence item.
pub async fn list_artifacts_for_evidence(
    pool: &SqlitePool,
    evidence_id: &EvidenceId,
) -> Result<Vec<StoredArtifactRecord>, ForensicError> {
    let rows = sqlx::query(
        r#"
        SELECT
            a.id, a.kind, a.evidence_id, a.output_path, a.description, a.created_at,
            p.id as prov_id, p.producing_component, p.component_version, p.output_hash,
            v.state as val_state, v.reason as val_reason
        FROM artifacts a
        LEFT JOIN provenance p ON a.provenance_id = p.id
        LEFT JOIN validation_states v ON p.validation_state_id = v.id
        WHERE a.evidence_id = ?1
        ORDER BY a.created_at DESC
        "#
    )
    .bind(evidence_id.0)
    .fetch_all(pool)
    .await
    .map_err(|e| ForensicError::corrupt("list_artifacts_for_evidence", format!("Fetching artifacts: {e}")))?;

    let mut records = Vec::new();
    for r in rows {
        let id: uuid::Uuid = r.try_get("id").unwrap();
        let kind: String = r.try_get("kind").unwrap();
        let ev_id: uuid::Uuid = r.try_get("evidence_id").unwrap();
        let output_path: String = r.try_get("output_path").unwrap_or_default();
        let description: String = r.try_get("description").unwrap_or_default();
        let created_at: chrono::DateTime<Utc> = r.try_get("created_at").unwrap();
        let producing_component: String = r.try_get("producing_component").unwrap_or_default();
        let component_version: String = r.try_get("component_version").unwrap_or_default();
        let output_hash_bytes: Vec<u8> = r.try_get("output_hash").unwrap_or_default();
        let val_state: String = r.try_get("val_state").unwrap_or_else(|_| "UNKNOWN".into());
        let val_reason: String = r.try_get("val_reason").unwrap_or_default();

        records.push(StoredArtifactRecord {
            id,
            kind,
            evidence_id: ev_id,
            output_path,
            description,
            created_at: created_at.to_rfc3339(),
            sha256: hex::encode(output_hash_bytes),
            producing_component,
            component_version,
            validation_state: val_state,
            validation_reason: val_reason,
            source_regions: vec![],
        });
    }

    Ok(records)
}
