//! Database repository for recordings and recording source regions.

use sqlx::{SqlitePool, Row};
use chrono::Utc;
use forensic_core::{EvidenceId, ForensicError, Recording, Region, TimeEvidence, Provenance};
use forensic_core::identifiers::ProfileId;

/// Inserts a recording and its source regions into SQLite.
pub async fn insert_recording(
    pool: &SqlitePool,
    evidence_id: &EvidenceId,
    parser_run_id: uuid::Uuid,
    recording: &Recording,
    sha256_hash: Option<&str>,
    exported_video_path: Option<&str>,
) -> Result<uuid::Uuid, ForensicError> {
    let rec_id = uuid::Uuid::new_v4();
    let now = Utc::now();

    let raw_ts_json = serde_json::to_value(&recording.time.raw)
        .map_err(|e| ForensicError::corrupt("insert_recording", format!("Serializing raw_ts: {e}")))?;
    let integrity_json = serde_json::json!({
        "parser_id": recording.parser_id,
        "parser_version": recording.parser_version,
        "profile_id": recording.profile_id.0,
        "profile_hash": recording.profile_hash.hex(),
    });

    let mut tx = pool.begin().await.map_err(|e| {
        ForensicError::corrupt("insert_recording", format!("Beginning SQLite transaction: {e}"))
    })?;

    let tz_str = match &recording.time.timezone {
        forensic_core::TimeZoneState::Known(tz) => format!("known:{}", tz),
        forensic_core::TimeZoneState::Unknown => "unknown".to_string(),
    };

    sqlx::query(
        r#"
        INSERT INTO recordings (
            id, evidence_id, parser_run_id, channel,
            raw_ts, recorder_native_ts, normalized_ts, reference_ts,
            timezone_state, normalization_method, clock_correction,
            source_image, integrity, exported_video_path, sha256, created_at
        ) VALUES (
            ?1, ?2, ?3, ?4,
            ?5, ?6, ?7, ?8,
            ?9, ?10, ?11,
            ?12, ?13, ?14, ?15, ?16
        )
        "#
    )
    .bind(rec_id)
    .bind(evidence_id.0)
    .bind(parser_run_id)
    .bind(recording.channel as i32)
    .bind(raw_ts_json.to_string())
    .bind(recording.time.recorder_native.as_ref().map(|t| t.iso_8601.clone()))
    .bind(recording.time.normalized.as_ref().map(|t| t.iso_8601.clone()))
    .bind(recording.time.reference.as_ref().map(|t| t.iso_8601.clone()))
    .bind(tz_str)
    .bind(recording.time.normalized.as_ref().map(|t| t.method.clone()))
    .bind(recording.time.correction.as_ref().map(|c| serde_json::to_string(c).unwrap_or_default()))
    .bind(&recording.source_image)
    .bind(integrity_json.to_string())
    .bind(exported_video_path)
    .bind(sha256_hash)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| ForensicError::corrupt("insert_recording", format!("Inserting recording row: {e}")))?;

    for region in &recording.source_offsets {
        let region_id = uuid::Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO recording_source_regions (
                id, recording_id, offset_start, length
            ) VALUES (?1, ?2, ?3, ?4)
            "#
        )
        .bind(region_id)
        .bind(rec_id)
        .bind(region.offset as i64)
        .bind(region.length as i64)
        .execute(&mut *tx)
        .await
        .map_err(|e| ForensicError::corrupt("insert_recording_region", format!("Inserting recording region: {e}")))?;
    }

    tx.commit().await.map_err(|e| {
        ForensicError::corrupt("insert_recording", format!("Committing SQLite transaction: {e}"))
    })?;

    Ok(rec_id)
}

/// Fetches a recording and its source regions by ID.
pub async fn get_recording(
    pool: &SqlitePool,
    recording_id: uuid::Uuid,
) -> Result<Option<(Recording, EvidenceId, Option<String>)>, ForensicError> {
    let row = sqlx::query(
        r#"
        SELECT
            id, evidence_id, channel, raw_ts, recorder_native_ts, normalized_ts,
            timezone_state, source_image, integrity, exported_video_path, sha256
        FROM recordings
        WHERE id = ?1
        "#
    )
    .bind(recording_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ForensicError::corrupt("get_recording", format!("Fetching recording: {e}")))?;

    let Some(r) = row else {
        return Ok(None);
    };

    let ev_id_raw: uuid::Uuid = r.try_get("evidence_id").unwrap();
    let evidence_id = EvidenceId(ev_id_raw);
    let channel: i32 = r.try_get("channel").unwrap();
    let source_image: String = r.try_get("source_image").unwrap();
    let exported_path: Option<String> = r.try_get("exported_video_path").unwrap();
    let native_ts_str: Option<String> = r.try_get("recorder_native_ts").unwrap();
    let normalized_ts_str: Option<String> = r.try_get("normalized_ts").unwrap();
    let tz_str: String = r.try_get("timezone_state").unwrap();

    // Query source regions
    let region_rows = sqlx::query(
        r#"
        SELECT offset_start, length
        FROM recording_source_regions
        WHERE recording_id = ?1
        ORDER BY offset_start ASC
        "#
    )
    .bind(recording_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ForensicError::corrupt("get_recording_regions", format!("Fetching recording regions: {e}")))?;

    let mut source_offsets = Vec::new();
    for reg_row in region_rows {
        let off: i64 = reg_row.try_get("offset_start").unwrap();
        let len: i64 = reg_row.try_get("length").unwrap();
        if let Ok(reg) = Region::new(off as u64, len as u64) {
            source_offsets.push(reg);
        }
    }

    let raw_prov = Provenance::new(
        evidence_id,
        forensic_core::Hash::sha256(vec![0; 32]),
        vec![],
        "sqlite_repo",
        "1.0.0",
        forensic_core::Hash::sha256(vec![0; 32]),
        forensic_core::ValidationState::pass("db", "loaded from sqlite", "recording").unwrap(),
    );

    let time_evidence = TimeEvidence {
        raw: forensic_core::RawTimestamp {
            value: 0,
            format: "UNIX_LE".into(),
            source: raw_prov,
        },
        recorder_native: native_ts_str.map(|s| forensic_core::RecorderNativeTime { iso_8601: s }),
        normalized: normalized_ts_str.map(|s| forensic_core::NormalizedTime {
            iso_8601: s,
            method: "db_retrieved".into(),
        }),
        reference: None,
        timezone: if tz_str.starts_with("known:") {
            forensic_core::TimeZoneState::Known(tz_str.trim_start_matches("known:").to_string())
        } else {
            forensic_core::TimeZoneState::Unknown
        },
        correction: None,
    };

    let recording = Recording::new(
        channel as u32,
        time_evidence,
        source_image,
        source_offsets,
        "sqlite_recording".to_string(),
        "1.0.0".to_string(),
        ProfileId("loaded_recording".into()),
        forensic_core::Hash::sha256(vec![0; 32]),
    );

    Ok(Some((recording, evidence_id, exported_path)))
}
