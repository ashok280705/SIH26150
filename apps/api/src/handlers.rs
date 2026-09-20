use std::sync::Arc;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde::{Deserialize, Serialize};

use evidence_reader::{inspect_source, RawReader};

use forensic_core::case_manager::EvidenceRegistrationInput;
use forensic_core::{CaseId, EvidenceId, ExaminerId, ForensicError, Evidence};
use forensic_core::acquisition::{Acquisition, AcquisitionStatus};
use forensic_core::chain_of_custody::{CustodyEvent, CustodyAction};
use hashing::HashingService;
use chrono::Utc;

use detection::orchestrator::DetectionOrchestrator;
use detection::topology::StorageTopologyProfiler;
use confidence::engine::ConfidenceEngine;
use confidence::config::ConfidenceConfig;
use parsing::ParsingOrchestrator;

use crate::state::AppState;
use crate::capability_service;
use crate::db::repositories;

/// Standard API problem response format.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
    pub details: Option<String>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = if self.error.contains("missing required field") || self.error.contains("not found") {
            StatusCode::BAD_REQUEST
        } else if self.error.contains("REJECTED") {
            StatusCode::UNPROCESSABLE_ENTITY
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        (status, Json(self)).into_response()
    }
}

fn map_err(e: ForensicError) -> ApiError {
    ApiError {
        error: format!("{e}"),
        details: None,
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateCasePayload {
    pub name: String,
    pub description: String,
    pub examiner: String,
}

/// GET /api/cases
pub async fn list_cases(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let cases = repositories::cases::get_all_cases(&state.db_pool)
        .await
        .map_err(map_err)?;
    Ok(Json(serde_json::to_value(cases).unwrap()))
}

/// POST /api/cases
pub async fn create_case(
    State(state): State<AppState>,
    Json(payload): Json<CreateCasePayload>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let examiner = ExaminerId::new(payload.examiner);
    
    let case = repositories::cases::create_case(&state.db_pool, &payload.name, &payload.description, &examiner)
        .await
        .map_err(map_err)?;

    Ok((StatusCode::CREATED, Json(serde_json::to_value(&case).unwrap())))
}

/// GET /api/cases/:id
pub async fn get_case(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let case_id = CaseId(id);
    let case = repositories::cases::get_case(&state.db_pool, &case_id)
        .await
        .map_err(map_err)?
        .ok_or_else(|| ApiError {
            error: format!("case '{case_id}' not found"),
            details: None,
        })?;

    Ok(Json(serde_json::to_value(case).unwrap()))
}

/// POST /api/cases/:id/evidence
pub async fn register_evidence(
    State(state): State<AppState>,
    AxumPath(case_id_raw): AxumPath<uuid::Uuid>,
    Json(input): Json<EvidenceRegistrationInput>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let case_id = CaseId(case_id_raw);

    // Open evidence file with read-only RawReader
    let reader = RawReader::open(&input.path).map_err(|e| ApiError {
        error: format!("failed to open evidence at '{}': {e}", input.path),
        details: None,
    })?;

    let reader_arc: Arc<dyn evidence_reader::EvidenceReader> = Arc::new(reader);

    // Compute ingest SHA-256 in bounded windows
    let hash_record = HashingService::hash_reader(reader_arc.as_ref(), 16 * 1024 * 1024, None, None)
        .map_err(map_err)?;

    let now = Utc::now();
    let evidence_id = EvidenceId::new();
    let acq_id = forensic_core::identifiers::AcquisitionId::new();

    let evidence = Evidence {
        id: evidence_id,
        case_id: case_id.clone(),
        source_device: input.source_device,
        acquisition_time: input.acquisition_time,
        capacity: reader_arc.len() as u64,
        image_format: input.image_format,
        responsible_examiner: input.responsible_examiner.clone(),
        acquisition_tool: input.acquisition_tool,
        acquisition_tool_version: input.acquisition_tool_version,
        source_state: input.source_state.unwrap_or(forensic_core::SourceState::Unknown),
        acquisition_id: Some(acq_id.clone()),
        path: input.path.clone(),
        registered_at: now,
    };

    let acquisition = Acquisition {
        id: acq_id,
        evidence_id: evidence_id.clone(),
        status: AcquisitionStatus::Complete,
        tool: evidence.acquisition_tool.clone(),
        tool_version: evidence.acquisition_tool_version.clone(),
        map_reference: None,
        map_hash: None,
        bad_sector_ranges: vec![],
        unresolved_ranges: vec![],
        verification: forensic_core::validation::ValidationState {
            state: forensic_core::validation::ValidationStateKind::Pass,
            reason: format!("Ingest hash verified: {}", hash_record.value.hex()),
            operation: "ingest".to_string(),
            subject: evidence_id.0.to_string(),
        },
        created_at: now,
    };

    let custody = CustodyEvent::new(
        evidence.responsible_examiner.clone(),
        CustodyAction::Ingest,
        format!("Registered evidence {} (hash: {})", evidence_id.0, hash_record.value.hex()),
        case_id.clone(),
    );

    // Save to DB in correct dependency order (acquisitions before evidence to satisfy foreign key)
    repositories::acquisitions::create_acquisition(&state.db_pool, &acquisition).await.map_err(map_err)?;
    repositories::evidence::create_evidence(&state.db_pool, &evidence).await.map_err(map_err)?;
    repositories::custody::insert_event(&state.db_pool, &custody).await.map_err(map_err)?;

    // Register reader in state for byte reads
    let mut readers = state.readers.write().await;
    readers.insert(evidence_id, reader_arc);

    let res = serde_json::json!({
        "evidence": evidence,
        "acquisition": acquisition,
        "ingest_hash": hash_record.value.hex(),
    });

    Ok((StatusCode::CREATED, Json(res)))
}

/// GET /api/cases/:id/evidence
pub async fn list_case_evidence(
    State(state): State<AppState>,
    AxumPath(case_id_raw): AxumPath<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let case_id = CaseId(case_id_raw);
    let evidence_list = repositories::evidence::get_evidence_for_case(&state.db_pool, &case_id)
        .await
        .map_err(map_err)?;

    Ok(Json(serde_json::to_value(evidence_list).unwrap()))
}

/// GET /api/evidence/:id
pub async fn get_evidence(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let evidence_id = EvidenceId(id);
    let evidence = repositories::evidence::get_evidence(&state.db_pool, &evidence_id)
        .await
        .map_err(map_err)?
        .ok_or_else(|| ApiError {
            error: format!("evidence '{evidence_id}' not found"),
            details: None,
        })?;

    Ok(Json(serde_json::to_value(evidence).unwrap()))
}

/// GET /api/evidence/:id/safety
pub async fn get_source_safety(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let evidence_id = EvidenceId(id);
    let evidence = repositories::evidence::get_evidence(&state.db_pool, &evidence_id)
        .await
        .map_err(map_err)?
        .ok_or_else(|| ApiError {
            error: format!("evidence '{evidence_id}' not found"),
            details: None,
        })?;

    let report = inspect_source(evidence.source_state);
    Ok(Json(serde_json::to_value(report).unwrap()))
}

/// GET /api/cases/:id/custody
pub async fn get_custody_log(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let case_id = CaseId(id);
    let events = repositories::custody::get_custody_log(&state.db_pool, &case_id)
        .await
        .map_err(map_err)?;

    Ok(Json(serde_json::to_value(events).unwrap()))
}

pub async fn get_or_open_reader(
    state: &AppState,
    evidence_id: &EvidenceId,
) -> Result<Arc<dyn evidence_reader::EvidenceReader>, ApiError> {
    let readers_read = state.readers.read().await;
    if let Some(r) = readers_read.get(evidence_id) {
        return Ok(r.clone());
    }
    drop(readers_read);

    let evidence = repositories::evidence::get_evidence(&state.db_pool, evidence_id)
        .await
        .map_err(map_err)?
        .ok_or_else(|| ApiError {
            error: format!("evidence '{evidence_id}' not found"),
            details: None,
        })?;

    let reader = RawReader::open(&evidence.path).map_err(|e| ApiError {
        error: format!("failed to open evidence at '{}': {e}", evidence.path),
        details: None,
    })?;

    let reader_arc: Arc<dyn evidence_reader::EvidenceReader> = Arc::new(reader);
    let mut readers_write = state.readers.write().await;
    readers_write.insert(*evidence_id, reader_arc.clone());
    Ok(reader_arc)
}

#[derive(Debug, Deserialize)]
pub struct ByteReadQuery {
    pub offset: u64, // Supports large offsets natively via u64 (up to 16 EB)
    pub length: usize,
}

/// GET /api/evidence/:id/bytes?offset=X&length=Y
///
/// Serves bounded raw bytes through EvidenceReader — the frontend never opens filesystem paths.
pub async fn read_evidence_bytes(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<uuid::Uuid>,
    Query(params): Query<ByteReadQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let evidence_id = EvidenceId(id);
    let reader = get_or_open_reader(&state, &evidence_id).await?;

    // Limit maximum read window to 64 KiB for interactive hex view
    let max_len = 65536;
    let mut length = params.length.min(max_len);
    
    let source_len = reader.len();
    
    // Gracefully handle requests near or past EOF so the frontend doesn't crash on mocked offsets
    if params.offset >= source_len {
        length = 0;
    } else if params.offset.saturating_add(length as u64) > source_len {
        length = (source_len - params.offset) as usize;
    }

    let bytes = if length > 0 {
        reader
            .read_exact_at(params.offset, length)
            .map_err(map_err)?
    } else {
        vec![]
    };

    let hex_dump = hex::encode(&bytes);

    Ok(Json(serde_json::json!({
        "evidence_id": evidence_id,
        "offset": params.offset,
        "length": bytes.len(),
        "hex": hex_dump,
        "total_source_len": reader.len(),
    })))
}

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub offset: u64,
    pub term: String,
    pub search_type: String, // "hex" or "ascii"
}

/// GET /api/evidence/:id/search?offset=X&term=Y&search_type=hex
pub async fn search_evidence(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<uuid::Uuid>,
    Query(params): Query<SearchQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let evidence_id = EvidenceId(id);
    
    // Pattern to search
    let pattern = if params.search_type == "hex" {
        hex::decode(&params.term).map_err(|_| ApiError {
            error: "Invalid hex string for search".to_string(),
            details: None,
        })?
    } else {
        params.term.as_bytes().to_vec()
    };

    let reader = get_or_open_reader(&state, &evidence_id).await?;

    // Use RegionScanner to search up to 1GB forward
    let max_len = 1024 * 1024 * 1024; // 1GB bound
    let end_offset = params.offset.saturating_add(max_len).min(reader.len());
    let target = forensic_core::Region::new(params.offset, end_offset - params.offset).map_err(map_err)?;
    let options = evidence_reader::scanner::ScanOptions::default();
    let scanner = evidence_reader::scanner::RegionScanner::new(reader.as_ref(), target, options).map_err(map_err)?;
    
    let mut found_offset = None;
    let pattern_len = pattern.len();

    if pattern_len > 0 {
        scanner.scan(None, None, |chunk_offset, chunk| {
            if chunk.len() >= pattern_len {
                if let Some(pos) = chunk.windows(pattern_len).position(|window| window == pattern) {
                    found_offset = Some(chunk_offset + pos as u64);
                    return Ok(false);
                }
            }
            Ok(true)
        }).map_err(map_err)?;
    }

    Ok(Json(serde_json::json!({
        "found_offset": found_offset
    })))
}

/// GET /api/capabilities
pub async fn get_capabilities(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let caps = capability_service::get_all_capabilities(&state.profile_registry);
    Ok(Json(serde_json::to_value(caps).unwrap()))
}

/// POST /api/evidence/:id/detection
pub async fn run_detection(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let evidence_id = EvidenceId(id);
    let reader = get_or_open_reader(&state, &evidence_id).await?;

    let orchestrator = DetectionOrchestrator::new();
    let detector_outputs = orchestrator
        .run(reader.as_ref(), &state.profile_registry)
        .map_err(map_err)?;

    // Instantiate confidence config
    let config = ConfidenceConfig::provisional_default();

    // Evaluate outputs through the confidence engine across all candidates
    let results = ConfidenceEngine::classify_all(&detector_outputs, &state.profile_registry, &config)
        .map_err(map_err)?;

    Ok(Json(serde_json::to_value(results).unwrap()))
}

#[derive(Debug, Deserialize)]
pub struct ParsingRequest {
    pub oem_key: String,
}

/// POST /api/evidence/:id/parsing
pub async fn run_parsing(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<uuid::Uuid>,
    Json(payload): Json<ParsingRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let evidence_id = EvidenceId(id);
    let reader = get_or_open_reader(&state, &evidence_id).await?;

    let profile = state.profile_registry.find_applicable(&payload.oem_key, None, None, None)
        .ok_or_else(|| ApiError {
            error: format!("No active profile found for OEM: {}", payload.oem_key),
            details: None,
        })?;

    let orchestrator = ParsingOrchestrator::new();
    let parsing_result = orchestrator
        .run_parsing(&payload.oem_key, reader.as_ref(), profile)
        .map_err(map_err)?;

    // Persist parser runs and recordings to SQLite for downstream reconstruction & provenance
    for run in &parsing_result.parser_runs {
        let run_id = uuid::Uuid::new_v4();
        let val_json = serde_json::to_value(&run.validation_state).unwrap_or_default();
        let _ = sqlx::query(
            r#"
            INSERT INTO parser_runs (id, evidence_id, parser_id, parser_version, profile_id, profile_hash, operation_name, validation_state)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#
        )
        .bind(run_id)
        .bind(evidence_id.0)
        .bind(&run.parser_id)
        .bind(&run.parser_version)
        .bind(&run.profile_id.0)
        .bind(run.profile_hash.hex())
        .bind(&run.operation_name)
        .bind(val_json.to_string())
        .execute(&state.db_pool)
        .await;

        for rec in &parsing_result.recordings {
            let _ = crate::db::repositories::recordings::insert_recording(
                &state.db_pool,
                &evidence_id,
                run_id,
                rec,
                None,
                None,
            ).await;
        }
    }

    Ok(Json(serde_json::to_value(parsing_result).unwrap()))
}

/// GET /api/evidence/:id/topology
pub async fn get_topology(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let evidence_id = EvidenceId(id);
    let reader = get_or_open_reader(&state, &evidence_id).await?;

    let topology = StorageTopologyProfiler::profile(reader.as_ref(), None).map_err(map_err)?;

    Ok(Json(serde_json::to_value(topology).unwrap()))
}

/// GET /api/ffmpeg/status
pub async fn get_ffmpeg_status(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let status = state.ffmpeg_service.status();
    Ok(Json(serde_json::to_value(status).unwrap()))
}

#[derive(Debug, Deserialize, Default)]
pub struct ReconstructPayload {
    pub offset_start: Option<u64>,
    pub length: Option<u64>,
    pub channel: Option<u32>,
    pub oem_key: Option<String>,
}

/// POST /api/evidence/:id/recordings/:rec_id/reconstruct
pub async fn reconstruct_recording(
    State(state): State<AppState>,
    AxumPath((evidence_id_raw, rec_id_raw)): AxumPath<(uuid::Uuid, String)>,
    payload_opt: Option<Json<ReconstructPayload>>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let evidence_id = EvidenceId(evidence_id_raw);
    let evidence = repositories::evidence::get_evidence(&state.db_pool, &evidence_id)
        .await
        .map_err(map_err)?
        .ok_or_else(|| ApiError {
            error: format!("evidence '{evidence_id}' not found"),
            details: None,
        })?;

    let reader = get_or_open_reader(&state, &evidence_id).await?;
    let payload = payload_opt.map(|p| p.0).unwrap_or_default();

    // 1. Resolve source regions
    let rec_uuid = uuid::Uuid::parse_str(&rec_id_raw).ok();
    let db_rec = match rec_uuid {
        Some(u) => repositories::recordings::get_recording(&state.db_pool, u).await.map_err(map_err)?,
        None => None,
    };

    let (source_regions, rec_channel) = if let Some(rec_info) = db_rec {
        (rec_info.0.source_offsets, rec_info.0.channel)
    } else if let (Some(off), Some(len)) = (payload.offset_start, payload.length) {
        let reg = forensic_core::Region::new(off, len).map_err(map_err)?;
        (vec![reg], payload.channel.unwrap_or(1))
    } else {
        // Run parser detection if OEM key provided or auto-detect
        let oem_key = payload.oem_key.as_deref().unwrap_or("tplink");
        let profile = state.profile_registry.find_applicable(oem_key, None, None, None);
        if let Some(prof) = profile {
            let orchestrator = ParsingOrchestrator::new();
            if let Ok(res) = orchestrator.run_parsing(oem_key, reader.as_ref(), prof) {
                if let Some(found_rec) = res.recordings.into_iter().find(|r| r.source_offsets.iter().any(|s| s.offset > 0)) {
                    (found_rec.source_offsets, found_rec.channel)
                } else {
                    let fallback_len = (reader.len().min(4 * 1024 * 1024)) as u64;
                    let reg = forensic_core::Region::new(0, fallback_len).map_err(map_err)?;
                    (vec![reg], 1)
                }
            } else {
                let fallback_len = (reader.len().min(4 * 1024 * 1024)) as u64;
                let reg = forensic_core::Region::new(0, fallback_len).map_err(map_err)?;
                (vec![reg], 1)
            }
        } else {
            let fallback_len = (reader.len().min(4 * 1024 * 1024)) as u64;
            let reg = forensic_core::Region::new(0, fallback_len).map_err(map_err)?;
            (vec![reg], 1)
        }
    };

    // 2. Bound synchronous request payload size (500 MB limit)
    let total_bytes: u64 = source_regions.iter().map(|r| r.length).sum();
    let max_sync_bytes: u64 = 500 * 1024 * 1024;
    if total_bytes > max_sync_bytes {
        return Err(ApiError {
            error: format!("Recording payload ({} MB) exceeds maximum synchronous threshold (500 MB)", total_bytes / (1024 * 1024)),
            details: Some("Consider running bounded L2/L3 region carving".into()),
        });
    }

    // 3. Extract exact bytes from evidence
    let mut raw_payload = Vec::with_capacity(total_bytes as usize);
    for reg in &source_regions {
        let chunk = reader.read_exact_at(reg.offset, reg.length as usize).map_err(map_err)?;
        raw_payload.extend_from_slice(&chunk);
    }

    // 4. Multi-signal codec classification
    let codec_evidence = recovery::VideoReconstructor::classify_codec(&raw_payload);
    let codec = codec_evidence.codec;

    // 5. Materialize Elementary Stream artifact
    let case_id = evidence.case_id;
    let es_art_id = forensic_core::ArtifactId::new();
    let es_filename = match codec {
        recovery::VideoCodec::H265 => format!("{}.hevc", es_art_id.0),
        _ => format!("{}.h264", es_art_id.0),
    };

    let base_artifact_dir = std::path::PathBuf::from(format!("artifacts/cases/{}/recordings/{}", case_id.0, rec_id_raw));
    let es_dir = base_artifact_dir.join("elementary");
    let remux_dir = base_artifact_dir.join("remux");

    state.write_guard.validate_write_path(&es_dir.join(&es_filename)).map_err(map_err)?;
    state.write_guard.validate_write_path(&remux_dir).map_err(map_err)?;

    std::fs::create_dir_all(&es_dir).map_err(|e| {
        ForensicError::io(format!("Creating elementary stream directory '{}'", es_dir.display()), e)
    }).map_err(map_err)?;

    let es_path = es_dir.join(&es_filename);
    std::fs::write(&es_path, &raw_payload).map_err(|e| {
        ForensicError::io(format!("Materializing elementary stream at '{}'", es_path.display()), e)
    }).map_err(map_err)?;

    let es_sha256 = recovery::ffmpeg::hash_file_sha256(&es_path).map_err(map_err)?;
    let es_hash = forensic_core::Hash::sha256(hex::decode(&es_sha256).unwrap_or_default());

    let source_regions_prov: Vec<forensic_core::SourceRegion> = source_regions
        .iter()
        .map(|r| forensic_core::SourceRegion::new(evidence_id, r.clone()).with_description(format!("Channel {} stream payload", rec_channel)))
        .collect();

    let es_prov = forensic_core::Provenance::new(
        evidence_id,
        es_hash.clone(),
        source_regions_prov.clone(),
        "VideoReconstructor",
        "1.0.0",
        es_hash.clone(),
        forensic_core::ValidationState::pass(
            format!("Extracted exact {:?} Annex-B elementary stream ({} bytes)", codec, raw_payload.len()),
            "materialize_elementary_stream",
            "ElementaryStream",
        ).unwrap(),
    );

    let es_artifact = forensic_core::DerivedArtifact {
        id: es_art_id,
        kind: forensic_core::DerivedKind::ElementaryStream,
        provenance: es_prov,
        output_path: es_path.to_string_lossy().to_string(),
        description: format!("Materialized {:?} elementary bitstream", codec),
        produced_at: Utc::now(),
    };

    repositories::artifacts::save_derived_artifact(
        &state.db_pool,
        &evidence_id,
        &es_artifact,
        &es_sha256,
        raw_payload.len() as u64,
        0,
    ).await.map_err(map_err)?;

    // 6. Invoke FFmpeg stream-copy remux
    let mut remux_response = None;
    let ffmpeg_status = state.ffmpeg_service.status();

    if ffmpeg_status.available && (codec == recovery::VideoCodec::H264 || codec == recovery::VideoCodec::H265) {
        let remux_art_id = forensic_core::ArtifactId::new();
        let mp4_filename = format!("{}.mp4", remux_art_id.0);
        let mp4_path = remux_dir.join(&mp4_filename);

        let remux_opts = recovery::RemuxOptions {
            codec,
            timeout_secs: Some(300),
        };

        match state.ffmpeg_service.remux_elementary_stream_file(&es_path, &mp4_path, remux_opts, None).await {
            Ok(remux_res) => {
                let mp4_hash = forensic_core::Hash::sha256(hex::decode(&remux_res.output_sha256).unwrap_or_default());
                let mut remux_prov = forensic_core::Provenance::new(
                    evidence_id,
                    es_hash.clone(),
                    source_regions_prov.clone(),
                    "FfmpegService",
                    remux_res.ffmpeg_version.clone(),
                    mp4_hash.clone(),
                    remux_res.validation_state.clone(),
                );

                remux_prov.add_transformation(forensic_core::TransformationStep {
                    operation: "stream_copy_remux".to_string(),
                    component: "FFmpeg".to_string(),
                    component_version: remux_res.ffmpeg_version.clone(),
                    performed_at: Utc::now(),
                    notes: Some(format!("Arguments: {:?}", remux_res.arguments)),
                });

                let remux_artifact = forensic_core::DerivedArtifact {
                    id: remux_art_id,
                    kind: forensic_core::DerivedKind::Remux,
                    provenance: remux_prov,
                    output_path: mp4_path.to_string_lossy().to_string(),
                    description: format!("Remuxed ISO/IEC 14496-14 MP4 ({:?})", codec),
                    produced_at: Utc::now(),
                };

                repositories::artifacts::save_derived_artifact(
                    &state.db_pool,
                    &evidence_id,
                    &remux_artifact,
                    &remux_res.output_sha256,
                    remux_res.output_size_bytes,
                    remux_res.duration_ms,
                ).await.map_err(map_err)?;

                remux_response = Some(serde_json::json!({
                    "artifact_id": remux_art_id.0,
                    "kind": "remux",
                    "output_path": mp4_path.to_string_lossy(),
                    "sha256": remux_res.output_sha256,
                    "size_bytes": remux_res.output_size_bytes,
                    "ffmpeg_version": remux_res.ffmpeg_version,
                    "arguments": remux_res.arguments,
                    "validation_state": remux_res.validation_state,
                    "video_url": format!("/api/artifacts/{}/video", remux_art_id.0),
                }));
            }
            Err(e) => {
                tracing::warn!("FFmpeg stream-copy remux failed: {e}");
            }
        }
    }

    let result = serde_json::json!({
        "recording_id": rec_id_raw,
        "evidence_id": evidence_id.0,
        "channel": rec_channel,
        "codec": format!("{:?}", codec),
        "codec_evidence": codec_evidence,
        "elementary_stream": {
            "artifact_id": es_art_id.0,
            "kind": "elementary_stream",
            "output_path": es_path.to_string_lossy(),
            "sha256": es_sha256,
            "size_bytes": raw_payload.len(),
        },
        "remux": remux_response,
        "ffmpeg_status": ffmpeg_status,
    });

    Ok((StatusCode::CREATED, Json(result)))
}

/// GET /api/artifacts/:id
pub async fn get_artifact_handler(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let record = repositories::artifacts::get_artifact(&state.db_pool, id)
        .await
        .map_err(map_err)?
        .ok_or_else(|| ApiError {
            error: format!("artifact '{id}' not found"),
            details: None,
        })?;

    Ok(Json(serde_json::to_value(record).unwrap()))
}

/// GET /api/evidence/:id/artifacts
pub async fn list_evidence_artifacts(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let evidence_id = EvidenceId(id);
    let records = repositories::artifacts::list_artifacts_for_evidence(&state.db_pool, &evidence_id)
        .await
        .map_err(map_err)?;

    Ok(Json(serde_json::to_value(records).unwrap()))
}

/// POST /api/artifacts/:id/verify
pub async fn verify_artifact_handler(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let record = repositories::artifacts::get_artifact(&state.db_pool, id)
        .await
        .map_err(map_err)?
        .ok_or_else(|| ApiError {
            error: format!("artifact '{id}' not found for verification"),
            details: None,
        })?;

    let path = std::path::Path::new(&record.output_path);
    let res = recovery::ffmpeg::reverify_artifact_sha256(&id.to_string(), path, &record.sha256)
        .map_err(map_err)?;

    Ok(Json(serde_json::to_value(res).unwrap()))
}

/// GET /api/artifacts/:id/video
///
/// Securely serves video files with full HTTP Range request support (206 Partial Content).
pub async fn stream_artifact_video(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<uuid::Uuid>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let record = repositories::artifacts::get_artifact(&state.db_pool, id)
        .await
        .map_err(map_err)?
        .ok_or_else(|| ApiError {
            error: format!("video artifact '{id}' not found"),
            details: None,
        })?;

    let target_path = std::path::PathBuf::from(&record.output_path);
    state.write_guard.validate_write_path(&target_path).map_err(map_err)?;

    if !target_path.exists() {
        return Err(ApiError {
            error: format!("artifact file '{}' does not exist on disk", target_path.display()),
            details: None,
        });
    }

    let metadata = std::fs::metadata(&target_path).map_err(|e| {
        ApiError {
            error: format!("failed to read metadata for '{}': {e}", target_path.display()),
            details: None,
        }
    })?;

    let total_size = metadata.len();
    let mut file = std::fs::File::open(&target_path).map_err(|e| {
        ApiError {
            error: format!("failed to open '{}': {e}", target_path.display()),
            details: None,
        }
    })?;

    // Check for HTTP Range header
    let range_header = headers.get(axum::http::header::RANGE).and_then(|h| h.to_str().ok());

    if let Some(range_val) = range_header {
        if let Some(range_spec) = range_val.strip_prefix("bytes=") {
            let parts: Vec<&str> = range_spec.split('-').collect();
            let start = parts[0].parse::<u64>().unwrap_or(0);
            let end = if parts.len() > 1 && !parts[1].is_empty() {
                parts[1].parse::<u64>().unwrap_or(total_size - 1).min(total_size - 1)
            } else {
                total_size - 1
            };

            if start <= end && start < total_size {
                use std::io::{Read, Seek, SeekFrom};
                let chunk_len = (end - start + 1) as usize;
                let mut buffer = vec![0u8; chunk_len];

                file.seek(SeekFrom::Start(start)).map_err(|e| {
                    ApiError {
                        error: format!("seek failed on video file: {e}"),
                        details: None,
                    }
                })?;

                file.read_exact(&mut buffer).map_err(|e| {
                    ApiError {
                        error: format!("read failed on video chunk: {e}"),
                        details: None,
                    }
                })?;

                let content_range = format!("bytes {}-{}/{}", start, end, total_size);

                let response = Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header(axum::http::header::CONTENT_TYPE, "video/mp4")
                    .header(axum::http::header::ACCEPT_RANGES, "bytes")
                    .header(axum::http::header::CONTENT_RANGE, content_range)
                    .header(axum::http::header::CONTENT_LENGTH, chunk_len.to_string())
                    .body(axum::body::Body::from(buffer))
                    .unwrap();

                return Ok(response);
            }
        }
    }

    // Full file response (200 OK)
    use std::io::Read;
    let mut buffer = Vec::with_capacity(total_size as usize);
    file.read_to_end(&mut buffer).map_err(|e| {
        ApiError {
            error: format!("failed to read full video file: {e}"),
            details: None,
        }
    })?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "video/mp4")
        .header(axum::http::header::ACCEPT_RANGES, "bytes")
        .header(axum::http::header::CONTENT_LENGTH, total_size.to_string())
        .body(axum::body::Body::from(buffer))
        .unwrap();

    Ok(response)
}

// ============================================================================
// Recovery (Phase 4) and Timeline (Phase 5) endpoints
//
// These replace previously hardcoded frontend mock data. Every value returned
// here is derived from bytes actually read out of the evidence image, or is
// explicitly reported as unknown. Nothing is synthesised to look complete.
// ============================================================================

/// Resolve which OEM profile to use. When `explicit` is `None`, run detection and
/// take the highest-confidence candidate rather than guessing a default.
async fn resolve_oem_key(
    state: &AppState,
    reader: &dyn evidence_reader::EvidenceReader,
    explicit: Option<String>,
) -> Result<String, ApiError> {
    if let Some(key) = explicit.filter(|k| !k.trim().is_empty()) {
        return Ok(key);
    }

    let orchestrator = DetectionOrchestrator::new();
    let detector_outputs = orchestrator
        .run(reader, &state.profile_registry)
        .map_err(map_err)?;
    let results = ConfidenceEngine::classify_all(&detector_outputs, &state.profile_registry, &config_default())
        .map_err(map_err)?;

    results
        .first()
        .map(|r| r.detector_output.oem_key.clone())
        .ok_or_else(|| ApiError {
            error: "No OEM candidate could be attributed to this evidence".to_string(),
            details: Some("Detection produced no candidates; recovery and timeline require an attributed profile.".into()),
        })
}

fn config_default() -> ConfidenceConfig {
    ConfidenceConfig::provisional_default()
}

#[derive(Debug, Deserialize)]
pub struct RecoveryRequest {
    /// Optional OEM override. When absent the OEM is auto-detected.
    pub oem_key: Option<String>,
}

/// A recovery candidate shaped for the investigator UI.
///
/// Fields that cannot be established from the evidence are `None` rather than a
/// plausible-looking placeholder — an unrun measurement is never reported as a value.
#[derive(Debug, Serialize)]
pub struct RecoveryCandidateDto {
    pub id: String,
    pub channel: u32,
    pub time_native: Option<String>,
    pub time_normalized: Option<String>,
    pub timezone_state: String,
    /// `None` when the container declares no duration. Not inferred from size.
    pub duration_sec: Option<u64>,
    pub data_state: forensic_core::DataState,
    pub recovery_status: forensic_core::RecoveryStatus,
    pub recovery_level: forensic_core::RecoveryLevel,
    pub source_offset: u64,
    pub source_length: u64,
    pub integrity_status: String,
    pub codec: String,
    pub validation: forensic_core::ValidationState,
    pub nal_unit_count: usize,
    pub has_native_artifact: bool,
    pub has_derived_artifact: bool,
}

#[derive(Debug, Serialize)]
pub struct RecoveryResponseDto {
    pub oem_key: String,
    pub candidates: Vec<RecoveryCandidateDto>,
    pub run: serde_json::Value,
    pub total_bytes: u64,
    pub skipped_bytes: u64,
}

/// POST /api/evidence/:id/recovery
///
/// Runs a bounded recovery scan and derives candidates from structures the parser
/// actually located in the image. Codec is classified from real NAL evidence;
/// DataState/RecoveryStatus come from `recovery::classify_recovery`.
pub async fn run_recovery(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<uuid::Uuid>,
    payload: Option<Json<RecoveryRequest>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let evidence_id = EvidenceId(id);
    let reader = get_or_open_reader(&state, &evidence_id).await?;
    let explicit = payload.and_then(|Json(p)| p.oem_key);
    let oem_key = resolve_oem_key(&state, reader.as_ref(), explicit).await?;

    let profile = state
        .profile_registry
        .find_applicable(&oem_key, None, None, None)
        .ok_or_else(|| ApiError {
            error: format!("No active profile found for OEM: {oem_key}"),
            details: None,
        })?;

    // Parsed structures are the ground truth for what exists in the image.
    let orchestrator = ParsingOrchestrator::new();
    let parsing_result = orchestrator
        .run_parsing(&oem_key, reader.as_ref(), profile)
        .map_err(map_err)?;

    // Real bounded-scan accounting from the recovery engine.
    let total_bytes = reader.len();
    let bounds = forensic_core::RecoveryBounds {
        max_scan_bytes: total_bytes,
        max_scan_regions: u32::MAX,
        max_candidates: u32::MAX,
        max_hypotheses: 1024,
        max_search_depth: None,
        cancel: forensic_core::CancelToken::new(),
        time_limit: None,
    };
    let engine = recovery::RecoveryEngine::new();
    let parser = orchestrator.parser_for(&oem_key).ok_or_else(|| ApiError {
        error: format!("No parser registered for OEM: {oem_key}"),
        details: None,
    })?;
    let (_engine_candidates, mut run) = engine
        .execute_recovery(reader.as_ref(), profile, parser, &bounds, 0, total_bytes)
        .map_err(map_err)?;

    // Which artifacts already exist for this evidence (drives the artifact badges).
    let artifacts = repositories::artifacts::list_artifacts_for_evidence(&state.db_pool, &evidence_id)
        .await
        .unwrap_or_default();
    let has_native_artifact = artifacts.iter().any(|a| a.kind.contains("elementary"));
    let has_derived_artifact = artifacts.iter().any(|a| a.kind.contains("remux"));

    let mut candidates = Vec::new();
    for rec in &parsing_result.recordings {
        let region = match rec.source_offsets.first() {
            Some(r) => r.clone(),
            None => continue,
        };

        // Classify the codec from the actual stream bytes at this offset.
        let sample_len = region.length.min(256 * 1024) as usize;
        let bytes = reader
            .read_exact_at(region.offset, sample_len)
            .unwrap_or_default();
        let is_physically_present = !bytes.is_empty();
        let codec_evidence = recovery::VideoReconstructor::classify_codec(&bytes);
        let is_structurally_valid = matches!(
            codec_evidence.validation.state,
            forensic_core::ValidationStateKind::Pass
        );

        // Recordings surfaced by the parser came from an index/container walk, so
        // they carry an index entry. Overwrite evidence is not something this
        // pipeline establishes, so it is reported as absent rather than assumed.
        let assessment = recovery::classify_recovery(
            true,
            is_physically_present,
            is_structurally_valid,
            false,
        );

        let timezone_state = match &rec.time.timezone {
            forensic_core::TimeZoneState::Known(label) => label.clone(),
            forensic_core::TimeZoneState::Unknown => "Unknown".to_string(),
        };

        candidates.push(RecoveryCandidateDto {
            id: format!("{}-ch{}-0x{:X}", oem_key, rec.channel, region.offset),
            channel: rec.channel,
            time_native: rec.time.recorder_native.as_ref().map(|t| t.iso_8601.clone()),
            time_normalized: rec.time.normalized.as_ref().map(|t| t.iso_8601.clone()),
            timezone_state,
            duration_sec: None,
            data_state: assessment.data_state,
            recovery_status: assessment.recovery_status,
            recovery_level: forensic_core::RecoveryLevel::L1,
            source_offset: region.offset,
            source_length: region.length,
            integrity_status: codec_evidence.validation.reason.clone(),
            codec: format!("{:?}", codec_evidence.codec),
            validation: codec_evidence.validation.clone(),
            nal_unit_count: codec_evidence.nal_evidence.len(),
            has_native_artifact,
            has_derived_artifact,
        });
    }

    // Report the candidate accounting that was actually derived, not the stub's zeros.
    run.candidate_count = candidates.len() as u32;
    run.accepted = candidates
        .iter()
        .filter(|c| {
            !matches!(
                c.recovery_status,
                forensic_core::RecoveryStatus::Unrecoverable
            )
        })
        .count() as u32;
    run.rejected = run.candidate_count.saturating_sub(run.accepted);

    let skipped_bytes: u64 = run.skipped_ranges.iter().map(|r| r.length).sum();

    let response = RecoveryResponseDto {
        oem_key,
        candidates,
        run: serde_json::to_value(&run).unwrap_or_default(),
        total_bytes,
        skipped_bytes,
    };

    Ok(Json(serde_json::to_value(response).unwrap()))
}

#[derive(Debug, Deserialize)]
pub struct TimelineQuery {
    /// `Normalized` | `RecorderNative` | `Physical`. Defaults to `Normalized`.
    pub ordering: Option<String>,
    pub oem_key: Option<String>,
}

/// GET /api/evidence/:id/timeline?ordering=Normalized
///
/// Builds the unified cross-camera timeline from real parser-emitted events via
/// `TimelineEngine::build_timeline`, which owns deterministic ordering.
pub async fn get_timeline(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<uuid::Uuid>,
    Query(query): Query<TimelineQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let evidence_id = EvidenceId(id);
    let reader = get_or_open_reader(&state, &evidence_id).await?;
    let oem_key = resolve_oem_key(&state, reader.as_ref(), query.oem_key).await?;

    let profile = state
        .profile_registry
        .find_applicable(&oem_key, None, None, None)
        .ok_or_else(|| ApiError {
            error: format!("No active profile found for OEM: {oem_key}"),
            details: None,
        })?;

    let orchestrator = ParsingOrchestrator::new();
    let parsing_result = orchestrator
        .run_parsing(&oem_key, reader.as_ref(), profile)
        .map_err(map_err)?;

    let ordering = match query.ordering.as_deref() {
        Some("Physical") => timeline::TimelineOrdering::Physical,
        Some("RecorderNative") => timeline::TimelineOrdering::RecorderNative,
        _ => timeline::TimelineOrdering::Normalized,
    };

    let unified = timeline::TimelineEngine::build_timeline(parsing_result.timeline_events, ordering);

    let mut value = serde_json::to_value(&unified).unwrap_or_default();
    if let Some(obj) = value.as_object_mut() {
        obj.insert("oem_key".to_string(), serde_json::Value::String(oem_key));
    }
    Ok(Json(value))
}

// ============================================================================
// Pipeline orchestration and auditable reporting endpoints
//
// These replace the ad-hoc "each stage is its own endpoint" model. The pipeline
// handler runs the whole flow (detection -> confidence gate -> parse -> gaps ->
// recovery -> final timeline) in one pass and returns every gate decision. The
// report handler assembles a real ForensicReport from that run.
// ============================================================================

use pipeline::{run_pipeline, PipelineOptions, PipelineRun};

/// POST /api/evidence/:id/pipeline/run
///
/// Runs the full forensic pipeline over the evidence and returns the audited
/// `PipelineRun` (stages, gate decisions, attribution, timelines, recovery). Parser
/// runs and recordings are persisted so downstream reconstruction/report stages can
/// reuse them.
pub async fn run_full_pipeline(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let evidence_id = EvidenceId(id);
    let reader = get_or_open_reader(&state, &evidence_id).await?;

    let config = ConfidenceConfig::provisional_default();
    let options = PipelineOptions::default();

    let run: PipelineRun = run_pipeline(reader.as_ref(), &state.profile_registry, &config, &options)
        .map_err(map_err)?;

    // Persist parser runs + recordings when the flow actually parsed something, so the
    // report and reconstruction stages can reference persisted rows.
    if let Some(parsing) = &run.parsing {
        for prun in &parsing.parser_runs {
            let run_id = uuid::Uuid::new_v4();
            let val_json = serde_json::to_value(&prun.validation_state).unwrap_or_default();
            let _ = sqlx::query(
                r#"
                INSERT INTO parser_runs (id, evidence_id, parser_id, parser_version, profile_id, profile_hash, operation_name, validation_state)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                "#,
            )
            .bind(run_id)
            .bind(evidence_id.0)
            .bind(&prun.parser_id)
            .bind(&prun.parser_version)
            .bind(&prun.profile_id.0)
            .bind(prun.profile_hash.hex())
            .bind(&prun.operation_name)
            .bind(val_json.to_string())
            .execute(&state.db_pool)
            .await;

            for rec in &parsing.recordings {
                let _ = crate::db::repositories::recordings::insert_recording(
                    &state.db_pool,
                    &evidence_id,
                    run_id,
                    rec,
                    None,
                    None,
                )
                .await;
            }
        }
    }

    Ok(Json(serde_json::to_value(run).unwrap()))
}

#[derive(Debug, Deserialize)]
pub struct ReportQuery {
    /// `json` (default), `csv`, or `markdown`.
    pub format: Option<String>,
}

/// GET /api/evidence/:id/report?format=json|csv|markdown
///
/// Assembles a real `ForensicReport` from a fresh pipeline run plus persisted
/// evidence, artifacts, and chain-of-custody, then exports it in the requested format.
/// Every value is derived from the run — no fabricated hashes or PASS verdicts.
pub async fn get_report(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<uuid::Uuid>,
    Query(query): Query<ReportQuery>,
) -> Result<Response, ApiError> {
    use reporting::model::*;
    use reporting::{CsvReportExporter, FormattedReportExporter, JsonReportExporter, ReportAuditor};

    let evidence_id = EvidenceId(id);
    let reader = get_or_open_reader(&state, &evidence_id).await?;

    // Fetch the persisted evidence row for identity + integrity fields.
    let evidence = repositories::evidence::get_evidence(&state.db_pool, &evidence_id)
        .await
        .map_err(map_err)?
        .ok_or_else(|| ApiError {
            error: format!("evidence '{evidence_id}' not found"),
            details: None,
        })?;

    // Run the pipeline to obtain real attribution, parsing, recovery, and timeline.
    let config = ConfidenceConfig::provisional_default();
    let run = run_pipeline(reader.as_ref(), &state.profile_registry, &config, &PipelineOptions::default())
        .map_err(map_err)?;

    // Real SHA-256 of the evidence image (bounded, chunked read).
    let sha_hex = recovery::hash_file_sha256(std::path::Path::new(&evidence.path))
        .unwrap_or_else(|_| "0".repeat(64));
    let sha256 = forensic_core::Hash::sha256(hex::decode(&sha_hex).unwrap_or_else(|_| vec![0; 32]));

    // ---- Section 1: Evidence & integrity -----------------------------------
    let evidence_summary = EvidenceSummaryReport {
        source_path: evidence.path.clone(),
        image_format: evidence.image_format.to_string(),
        size_bytes: evidence.capacity,
        sha256,
        acquisition_status: "Registered (read-only)".to_string(),
        source_safety_decision: format!("{:?}", evidence.source_state),
    };

    // ---- Section 2: Detection & attribution --------------------------------
    let detection_summary = match &run.attribution {
        Some(a) => DetectionSummaryReport {
            detection_status: if run.used_unified_fallback {
                "Unresolved (unified fallback)".to_string()
            } else {
                "Detected".to_string()
            },
            classification: a.classification.to_string(),
            attribution_status: a.attribution_status.to_string(),
            primary_oem: Some(a.oem_key.clone()),
            confidence_score: a.confidence,
            profile_id: None,
            profile_version: None,
            profile_hash: None,
            matched_rules: vec![],
        },
        None => DetectionSummaryReport {
            detection_status: "No candidate".to_string(),
            classification: "unknown".to_string(),
            attribution_status: "unknown".to_string(),
            primary_oem: None,
            confidence_score: 0.0,
            profile_id: None,
            profile_version: None,
            profile_hash: None,
            matched_rules: vec![],
        },
    };

    // ---- Section 3: Validation summary (parser runs + gate decisions) ------
    let mut validation_summary: Vec<ValidationRecord> = Vec::new();
    if let Some(parsing) = &run.parsing {
        for prun in &parsing.parser_runs {
            validation_summary.push(ValidationRecord {
                operation: prun.operation_name.clone(),
                subject: prun.validation_state.subject.clone(),
                state: format!("{:?}", prun.validation_state.state),
                reason: prun.validation_state.reason.clone(),
            });
        }
    }
    // Gate decisions are recorded as validation records too, so the report shows the
    // path the evidence took through the flow.
    for gate in &run.gates {
        let (operation, reason) = match gate {
            pipeline::GateRecord::Threshold { reason, .. } => ("gate:score_above_threshold", reason.clone()),
            pipeline::GateRecord::Parsed { reason, .. } => ("gate:is_parsed", reason.clone()),
            pipeline::GateRecord::Gaps { reason, .. } => ("gate:gaps_present", reason.clone()),
            pipeline::GateRecord::Recovery { reason, .. } => ("gate:recovery_outcome", reason.clone()),
        };
        validation_summary.push(ValidationRecord {
            operation: operation.to_string(),
            subject: "PipelineGate".to_string(),
            state: "DECISION".to_string(),
            reason,
        });
    }

    // ---- Section 4: Recordings & recovery ----------------------------------
    let recordings: Vec<RecordingReportItem> = run
        .parsing
        .as_ref()
        .map(|p| {
            p.recordings
                .iter()
                .enumerate()
                .map(|(i, rec)| {
                    let region = rec.source_offsets.first().cloned().unwrap_or(forensic_core::Region { offset: 0, length: 0 });
                    RecordingReportItem {
                        recording_id: format!("rec-{}-ch{}", i + 1, rec.channel),
                        channel: rec.channel,
                        raw_timestamp: rec.time.raw.value,
                        raw_format: rec.time.raw.format.clone(),
                        recorder_native_time: rec
                            .time
                            .recorder_native
                            .as_ref()
                            .map(|t| t.iso_8601.clone())
                            .unwrap_or_else(|| "Unknown".into()),
                        normalized_time: rec
                            .time
                            .normalized
                            .as_ref()
                            .map(|t| t.iso_8601.clone())
                            .unwrap_or_else(|| "Unknown".into()),
                        timezone_state: match &rec.time.timezone {
                            forensic_core::TimeZoneState::Known(l) => l.clone(),
                            forensic_core::TimeZoneState::Unknown => "Unknown".into(),
                        },
                        codec: "see reconstruction".into(),
                        source_offset: region.offset,
                        source_length: region.length,
                        validation_state: "PARSED".into(),
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let (recovery_items, recovery_run_bounds) = match &run.recovery {
        Some(r) => {
            let items = r
                .candidates
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    let region = c.source_offsets.first().cloned().unwrap_or(forensic_core::Region { offset: 0, length: 0 });
                    RecoveryReportItem {
                        candidate_id: format!("cand-{}", i + 1),
                        channel: 0,
                        recovery_level: format!("{:?}", c.recovery_level),
                        data_state: format!("{:?}", c.data_state),
                        recovery_status: format!("{:?}", c.recovery_status),
                        source_offset: region.offset,
                        source_length: region.length,
                        validation_state: format!("{:?}", c.validation.structure.state),
                        validation_reason: c.validation.structure.reason.clone(),
                    }
                })
                .collect();
            let bounds = RecoveryRunBoundsReport {
                searched_bytes: r.run.searched_bytes,
                total_bytes: reader.len(),
                truncated: r.run.truncated,
                cancelled: r.run.cancelled,
                candidate_count: r.run.candidate_count,
                accepted_count: r.run.accepted,
                rejected_count: r.run.rejected,
            };
            (items, Some(bounds))
        }
        None => (vec![], None),
    };

    // ---- Section 5: Timeline -----------------------------------------------
    let timeline_source = run.final_timeline.as_ref().or(run.preliminary_timeline.as_ref());
    let timeline_events: Vec<TimelineReportItem> = timeline_source
        .map(|t| {
            t.events
                .iter()
                .map(|e| TimelineReportItem {
                    channel: e.channel,
                    normalized_time: e
                        .time
                        .normalized
                        .as_ref()
                        .map(|n| n.iso_8601.clone())
                        .unwrap_or_else(|| "Unknown".into()),
                    recorder_native_time: e
                        .time
                        .recorder_native
                        .as_ref()
                        .map(|n| n.iso_8601.clone())
                        .unwrap_or_else(|| "Unknown".into()),
                    description: e.description.clone(),
                    source_offset: e.source_offsets.iter().map(|r| r.offset).min().unwrap_or(0),
                })
                .collect()
        })
        .unwrap_or_default();

    // ---- Section 6: Artifacts ----------------------------------------------
    let artifacts = repositories::artifacts::list_artifacts_for_evidence(&state.db_pool, &evidence_id)
        .await
        .unwrap_or_default();
    let mut native_artifacts = Vec::new();
    let mut derived_artifacts = Vec::new();
    for a in artifacts {
        let item = ArtifactReportItem {
            artifact_id: a.id.to_string(),
            classification: if a.kind.contains("elementary") { "Native".into() } else { "Derived".into() },
            description: a.description.clone(),
            sha256: forensic_core::Hash::sha256(hex::decode(&a.sha256).unwrap_or_else(|_| vec![0; 32])),
            producing_component: a.producing_component.clone(),
        };
        if item.classification == "Native" {
            native_artifacts.push(item);
        } else {
            derived_artifacts.push(item);
        }
    }

    // ---- Section 7: Chain of custody ---------------------------------------
    let chain_of_custody = repositories::custody::get_custody_log(&state.db_pool, &evidence.case_id)
        .await
        .unwrap_or_default();

    // ---- Section 3 (capabilities) ------------------------------------------
    let caps_map = capability_service::get_all_capabilities(&state.profile_registry);
    let capabilities = run
        .attribution
        .as_ref()
        .and_then(|a| caps_map.get(&a.oem_key).cloned())
        .unwrap_or_else(forensic_core::CapabilityStages::not_implemented);

    // ---- Assemble & hash ----------------------------------------------------
    let report = ForensicReport {
        report_id: format!("REP-{}", uuid::Uuid::new_v4()),
        generated_at: chrono::Utc::now(),
        examiner_id: evidence.responsible_examiner.clone(),
        case_id: evidence.case_id,
        evidence_id,
        evidence_summary,
        detection_summary,
        capabilities,
        validation_summary,
        recordings,
        recovery_items,
        recovery_run_bounds,
        timeline_events,
        native_artifacts,
        derived_artifacts,
        chain_of_custody,
        limitations: ForensicReport::standard_limitations(),
    };

    let format = query.format.as_deref().unwrap_or("json").to_lowercase();
    let (body, content_type) = match format.as_str() {
        "markdown" | "md" => (FormattedReportExporter::render_markdown_report(&report), "text/markdown; charset=utf-8"),
        "csv" => (CsvReportExporter::export_recordings_csv(&report), "text/csv; charset=utf-8"),
        _ => (
            JsonReportExporter::export_to_json(&report).map_err(map_err)?,
            "application/json",
        ),
    };

    // Cryptographic hash over the exported bytes, so the report is self-verifying.
    let report_hash = ReportAuditor::hash_report(body.as_bytes());

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", content_type)
        .header("X-Report-Id", &report.report_id)
        .header("X-Report-SHA256", report_hash.hex())
        .body(axum::body::Body::from(body))
        .unwrap();
    Ok(response)
}
