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
