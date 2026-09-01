//! # Axum HTTP Request Handlers
//!
//! Exposes REST endpoints for case creation, evidence registration, source safety audit,
//! acquisition verification, custody log retrieval, and bounded byte reads (Req 7.1, 7.2, 7.4, 7.7, 1.10, 18.8).

use std::sync::Arc;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde::{Deserialize, Serialize};

use evidence_reader::{inspect_source, RawReader};

use forensic_core::case_manager::EvidenceRegistrationInput;
use forensic_core::{CaseId, EvidenceId, ExaminerId, ForensicError};
use hashing::HashingService;

use detection::orchestrator::DetectionOrchestrator;
use detection::topology::StorageTopologyProfiler;
use confidence::engine::ConfidenceEngine;
use confidence::config::ConfidenceConfig;

use crate::state::AppState;
use crate::capability_service;

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

/// POST /api/cases
pub async fn create_case(
    State(state): State<AppState>,
    Json(payload): Json<CreateCasePayload>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let mut cm = state.case_manager.write().await;
    let examiner = ExaminerId::new(payload.examiner);
    let case = cm
        .create_case(payload.name, payload.description, examiner)
        .map_err(map_err)?;

    Ok((StatusCode::CREATED, Json(serde_json::to_value(&case).unwrap())))
}

/// GET /api/cases/:id
pub async fn get_case(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let cm = state.case_manager.read().await;
    let case_id = CaseId(id);
    let case = cm.get_case(&case_id).ok_or_else(|| ApiError {
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

    let mut cm = state.case_manager.write().await;
    let (evidence, acquisition) = cm
        .register_evidence(case_id, input, hash_record.value.clone())
        .map_err(map_err)?;

    let evidence_id = evidence.id;

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

/// GET /api/evidence/:id
pub async fn get_evidence(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let cm = state.case_manager.read().await;
    let evidence_id = EvidenceId(id);
    let evidence = cm.get_evidence(&evidence_id).ok_or_else(|| ApiError {
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
    let cm = state.case_manager.read().await;
    let evidence_id = EvidenceId(id);
    let evidence = cm.get_evidence(&evidence_id).ok_or_else(|| ApiError {
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
    let cm = state.case_manager.read().await;
    let case_id = CaseId(id);
    let log = cm.get_custody_log(&case_id).ok_or_else(|| ApiError {
        error: format!("case '{case_id}' not found"),
        details: None,
    })?;

    Ok(Json(serde_json::to_value(log.events()).unwrap()))
}

#[derive(Debug, Deserialize)]
pub struct ByteReadQuery {
    pub offset: u64,
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

    // Limit maximum read window to 64 KiB for interactive hex view
    let max_len = 65536;
    let length = params.length.min(max_len);

    let readers = state.readers.read().await;
    let reader = readers.get(&evidence_id).ok_or_else(|| ApiError {
        error: format!("reader for evidence '{evidence_id}' not active"),
        details: None,
    })?;

    let bytes = reader
        .read_exact_at(params.offset, length)
        .map_err(map_err)?;

    let hex_dump = hex::encode(&bytes);

    Ok(Json(serde_json::json!({
        "evidence_id": evidence_id,
        "offset": params.offset,
        "length": bytes.len(),
        "hex": hex_dump,
        "total_source_len": reader.len(),
    })))
}

/// GET /api/capabilities
///
/// Returns the capability maturity (CapabilityStages) for all OEMs based on current loaded registry.
pub async fn get_capabilities(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let caps = capability_service::get_all_capabilities(&state.profile_registry);
    Ok(Json(serde_json::to_value(caps).unwrap()))
}

/// POST /api/evidence/:id/detection
///
/// Runs the DetectionOrchestrator and ConfidenceEngine to return ClassifiedDetectionResults.
pub async fn run_detection(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let evidence_id = EvidenceId(id);
    let readers = state.readers.read().await;
    let reader = readers.get(&evidence_id).ok_or_else(|| ApiError {
        error: format!("reader for evidence '{evidence_id}' not active"),
        details: None,
    })?;

    let orchestrator = DetectionOrchestrator::new();
    let detector_outputs = orchestrator
        .run(reader.as_ref(), &state.profile_registry)
        .map_err(map_err)?;

    // Instantiate confidence config
    let config = ConfidenceConfig::provisional_default();

    // Evaluate outputs through the confidence engine
    let result = ConfidenceEngine::classify(&detector_outputs, &state.profile_registry, &config)
        .map_err(map_err)?;

    Ok(Json(serde_json::to_value(vec![result]).unwrap()))
}

/// GET /api/evidence/:id/topology
///
/// Runs the StorageTopologyProfiler and returns geometry candidates.
pub async fn get_topology(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let evidence_id = EvidenceId(id);
    let readers = state.readers.read().await;
    let reader = readers.get(&evidence_id).ok_or_else(|| ApiError {
        error: format!("reader for evidence '{evidence_id}' not active"),
        details: None,
    })?;

    let topology = StorageTopologyProfiler::profile(reader.as_ref(), None).map_err(map_err)?;

    Ok(Json(serde_json::to_value(topology).unwrap()))
}
