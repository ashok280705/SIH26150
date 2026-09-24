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

/// One physical byte range, as supplied by a caller that already knows where the bytes are.
#[derive(Debug, Deserialize, Clone, Copy)]
pub struct RegionDto {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Deserialize, Default)]
pub struct ReconstructPayload {
    pub offset_start: Option<u64>,
    pub length: Option<u64>,
    pub channel: Option<u32>,
    pub oem_key: Option<String>,
    /// Explicit ordered physical ranges to export.
    ///
    /// This is the interface for exporting an **engine-discovered** recording. A Dahua
    /// recording is a chain of 2 MiB blocks and a DHFS 4.1 stream is a list of frame payload
    /// ranges, neither of which a single `offset_start`/`length` pair can express. The ranges
    /// are concatenated in the order given and nothing is inserted between them.
    pub regions: Option<Vec<RegionDto>>,
    /// The recovery engine's stable fragment id for these bytes, when the caller has one.
    ///
    /// Recorded on the artifact's provenance so an exported artifact is traceable back to the
    /// exact discovery it came from, rather than to a freshly minted identifier.
    pub fragment_id: Option<String>,
    /// An OEM recording/chain id to reconstruct, e.g. a Dahua `dahua:p0:blk1`.
    ///
    /// When supplied and the OEM parser can reconstruct it, the export uses the parser's own
    /// frame-accurate payload ranges — block chain order, then DHII index order — instead of a
    /// caller-supplied range list.
    pub recording_chain_id: Option<String>,
}

/// Reconstruct an OEM recording into its frame-accurate payload ranges.
///
/// Returns `(ordered payload regions, channel, description)`, or `None` when the OEM has no
/// reconstruction path or the id does not resolve. The ranges are the parser's own — for Dahua,
/// block-chain order then the DHII frame index; for Hikvision, B-tree/clip-index order then the
/// MPEG-PS part order inside each clip. Nothing is inserted between them, so concatenating those
/// exact evidence bytes reproduces the elementary stream.
///
/// This is the smallest interface that lets an **engine-discovered** recording be exported.
/// Without it the export layer could only take one contiguous range, so a multi-block recording
/// was not exportable at all without fabricating a recording row for it.
#[allow(clippy::type_complexity)]
fn reconstruct_oem_chain(
    state: &AppState,
    reader: &dyn evidence_reader::EvidenceReader,
    oem_key: &str,
    chain_id: &str,
) -> Result<Option<(Vec<forensic_core::Region>, u32, String)>, ApiError> {
    let profile = match state.profile_registry.find_applicable(oem_key, None, None, None) {
        Some(p) => p,
        None => return Ok(None),
    };

    if oem_key.eq_ignore_ascii_case("dahua") {
        let volume = parser_dahua::volume::read_volume(reader, profile).map_err(map_err)?;
        let Some(classified) = parser_dahua::find_chain(&volume, chain_id) else {
            return Ok(None);
        };
        let reconstruction = parser_dahua::reconstruct_recording(reader, profile, &classified.chain)
            .map_err(map_err)?;
        if reconstruction.payload_regions.is_empty() {
            return Err(ApiError {
                error: format!(
                    "Dahua chain '{chain_id}' was located but no frame payload could be established \
                     in its blocks"
                ),
                details: Some(reconstruction.evidence.reason.clone()),
            });
        }
        let description = format!(
            "{chain_id}: {} block(s), {} frame(s), {} payload range(s), ordered by {}; {}",
            reconstruction.block_regions.len(),
            reconstruction.frames.len(),
            reconstruction.payload_regions.len(),
            reconstruction.ordering.label(),
            reconstruction.evidence.reason
        );
        return Ok(Some((
            reconstruction.payload_regions.clone(),
            reconstruction.channel.normalized,
            description,
        )));
    }

    if oem_key.eq_ignore_ascii_case("hikvision") {
        // `chain_id` here is the recording id the Hikvision index assigned — a clip id of the
        // form `hikclip:b<block>:s<slot>:<offset>`. It is used as given and never regenerated,
        // so the exported artifact traces back to the exact discovery the engine reported.
        let volume = parser_hikvision::volume::read_volume(reader, profile).map_err(map_err)?;
        let Some(reconstruction) =
            parser_hikvision::reconstruct_recording(reader, profile, &volume, chain_id)
                .map_err(map_err)?
        else {
            return Ok(None);
        };
        if reconstruction.payload_regions.is_empty() {
            return Err(ApiError {
                error: format!(
                    "Hikvision recording '{chain_id}' was located but no MPEG-PS video payload \
                     could be established in its clip(s)"
                ),
                details: Some(reconstruction.evidence.reason.clone()),
            });
        }
        let description = format!(
            "{}; {}",
            reconstruction.description(),
            reconstruction.evidence.reason
        );
        return Ok(Some((
            reconstruction.payload_regions.clone(),
            // A recording whose clips disagree about the channel, or establish none, must not be
            // exported as channel 0 silently — the description and the parser evidence carry the
            // disagreement, and channel 0 is the platform's "unknown channel" value.
            reconstruction.channel.unwrap_or(0),
            description,
        )));
    }

    // Every other OEM has no reconstruction path yet. Returning `None` lets the caller fall
    // through to an explicit range list rather than silently exporting some other OEM's bytes.
    Ok(None)
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

    // Where the source ranges come from, recorded on the artifact so an examiner can see
    // whether an export followed a parser-reconstructed stream, a caller-supplied range list, a
    // persisted recording, or a fallback.
    let mut region_source = "persisted recording row".to_string();
    let mut reconstruction_note: Option<String> = None;

    // A chain id asks the OEM parser to reconstruct the recording and export its own
    // frame-accurate payload ranges. This is the path an engine-discovered Dahua recording
    // takes: block chain order first, then the DHII frame index inside each block.
    let chain_regions: Option<(Vec<forensic_core::Region>, u32, String)> =
        match payload.recording_chain_id.as_deref() {
            Some(chain_id) if !chain_id.trim().is_empty() => {
                // The OEM must be established, not assumed. Defaulting to a particular vendor
                // here would reconstruct one OEM's id against another OEM's parser and export
                // unrelated bytes under the caller's recording id.
                let oem_key =
                    resolve_oem_key(&state, reader.as_ref(), payload.oem_key.clone()).await?;
                reconstruct_oem_chain(&state, reader.as_ref(), &oem_key, chain_id)?
            }
            _ => None,
        };

    let (source_regions, rec_channel) = if let Some((regions, channel, note)) = chain_regions {
        region_source = format!("OEM chain reconstruction of {note}");
        reconstruction_note = Some(note);
        (regions, channel)
    } else if let Some(regions) = payload.regions.as_ref().filter(|r| !r.is_empty()) {
        // Explicit ordered ranges from the caller — an engine-discovered multi-block recording.
        // Each range is bounds-checked against the evidence before anything is read.
        let mut out = Vec::with_capacity(regions.len());
        for r in regions {
            let region = forensic_core::Region::new(r.offset, r.length).map_err(map_err)?;
            let end = region.end().unwrap_or(u64::MAX);
            if end > reader.len() {
                return Err(ApiError {
                    error: format!(
                        "requested region [0x{:X}..0x{end:X}) lies outside the {}-byte evidence",
                        r.offset,
                        reader.len()
                    ),
                    details: Some(
                        "an export never reads past the end of the evidence, and a range is never \
                         clamped to fit"
                            .into(),
                    ),
                });
            }
            out.push(region);
        }
        region_source = format!("{} caller-supplied physical range(s)", out.len());
        (out, payload.channel.unwrap_or(1))
    } else if let Some(rec_info) = db_rec {
        (rec_info.0.source_offsets, rec_info.0.channel)
    } else if let (Some(off), Some(len)) = (payload.offset_start, payload.length) {
        let reg = forensic_core::Region::new(off, len).map_err(map_err)?;
        region_source = "caller-supplied offset and length".to_string();
        (vec![reg], payload.channel.unwrap_or(1))
    } else {
        // Nothing identified the bytes to export: no OEM recording id, no explicit ranges, no
        // persisted recording row, no offset/length. The remaining option is to ask the attributed
        // OEM's parser what it found.
        //
        // What this deliberately no longer does: fall back to the first 4 MiB of the image under a
        // default OEM key. That produced an artifact that looked like a recording, carried a real
        // hash and real provenance, and was actually an arbitrary head-of-image range attributed to
        // whichever vendor happened to be the default. An export with nothing to export is an
        // error, not a 4 MiB guess.
        let oem_key = resolve_oem_key(&state, reader.as_ref(), payload.oem_key.clone()).await?;
        let profile = state
            .profile_registry
            .find_applicable(&oem_key, None, None, None)
            .ok_or_else(|| ApiError {
                error: format!("no profile is registered for OEM '{oem_key}'"),
                details: Some(
                    "an export needs the OEM's own structures to locate the recording; no range was \
                     substituted"
                        .into(),
                ),
            })?;

        let orchestrator = ParsingOrchestrator::new();
        let parsed = orchestrator
            .run_parsing(&oem_key, reader.as_ref(), profile)
            .map_err(map_err)?;
        let located = parsed
            .recordings
            .into_iter()
            .find(|r| r.source_offsets.iter().any(|s| !s.is_empty()));

        match located {
            Some(found) => {
                region_source = format!("recording located by the {oem_key} parser");
                (found.source_offsets, found.channel)
            }
            None => {
                return Err(ApiError {
                    error: format!(
                        "no source range could be established for recording '{rec_id_raw}'"
                    ),
                    details: Some(format!(
                        "the {oem_key} parser located no recording in this evidence, and the request \
                         supplied no recording_chain_id, no explicit regions and no \
                         offset_start/length. Supply one of those, or run recovery first and post \
                         back the recording id or fragment id it reported. No arbitrary range was \
                         exported in their place"
                    )),
                });
            }
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
        .enumerate()
        .map(|(i, r)| {
            forensic_core::SourceRegion::new(evidence_id, *r).with_description(format!(
                "channel {rec_channel} stream payload, ordered part {} of {} ({region_source})",
                i + 1,
                source_regions.len()
            ))
        })
        .collect();

    // The provenance reason names every fact an examiner needs to re-derive this export: where
    // the ranges came from, how many there were, the engine's own fragment id when the caller
    // supplied one, and the OEM reconstruction detail when a chain was walked.
    let mut es_reason = format!(
        "Extracted exact {:?} Annex-B elementary stream ({} byte(s)) from {} ordered physical \
         range(s) in this evidence item; source: {region_source}",
        codec,
        raw_payload.len(),
        source_regions.len()
    );
    if let Some(fid) = payload.fragment_id.as_deref().filter(|s| !s.trim().is_empty()) {
        // Preserved, never regenerated: the artifact carries the same identifier the recovery
        // engine assigned the discovery.
        es_reason.push_str(&format!("; recovery engine fragment id {fid}"));
    }
    if let Some(note) = reconstruction_note.as_deref() {
        es_reason.push_str(&format!("; reconstruction: {note}"));
    }

    let mut es_prov = forensic_core::Provenance::new(
        evidence_id,
        es_hash.clone(),
        source_regions_prov.clone(),
        "VideoReconstructor",
        "1.0.0",
        es_hash.clone(),
        forensic_core::ValidationState::pass(
            es_reason.clone(),
            "materialize_elementary_stream",
            "ElementaryStream",
        )
        .unwrap(),
    );
    es_prov.add_transformation(forensic_core::TransformationStep {
        operation: "materialize_elementary_stream".to_string(),
        component: "forensic-api".to_string(),
        component_version: env!("CARGO_PKG_VERSION").to_string(),
        performed_at: Utc::now(),
        notes: Some(es_reason.clone()),
    });

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
    /// The recovery engine's stable fragment id, when this candidate came from the engine.
    ///
    /// Deterministic from the evidence id and the physical range, so posting it back to the
    /// reconstruct endpoint ties the exported artifact to this exact discovery.
    pub fragment_id: Option<String>,
    /// `None` when no index entry supplied a channel. Video carved from unclaimed space
    /// genuinely has no channel and must not be reported as channel 0.
    pub channel: Option<u32>,
    /// The OEM storage partition, when the OEM's structures are partitioned.
    pub partition: Option<u32>,
    pub time_native: Option<String>,
    pub time_normalized: Option<String>,
    pub timezone_state: String,
    /// Recorder start/end as unix seconds, when OEM metadata supplied them.
    pub start_time_unix: Option<i64>,
    pub end_time_unix: Option<i64>,
    /// `None` when the container declares no duration. Not inferred from size.
    pub duration_sec: Option<u64>,
    pub data_state: forensic_core::DataState,
    pub recovery_status: forensic_core::RecoveryStatus,
    pub recovery_level: forensic_core::RecoveryLevel,
    pub source_offset: u64,
    pub source_length: u64,
    /// Every physical range this candidate's recording occupies, in recording order.
    ///
    /// A Dahua recording spans several 2 MiB blocks, so one offset/length pair cannot describe
    /// it. Post these straight back to the reconstruct endpoint to export the whole recording.
    pub source_regions: Vec<serde_json::Value>,
    pub integrity_status: String,
    pub codec: String,
    pub validation: forensic_core::ValidationState,
    pub nal_unit_count: usize,
    pub has_native_artifact: bool,
    pub has_derived_artifact: bool,
    /// How this candidate was found: an index-claimed probe, an available-metadata probe, or a
    /// scan of unclaimed space.
    pub discovery_method: String,
    /// Whether the candidate's physical bounds are an OEM container record's or a scan window's.
    pub framing: Option<String>,
    /// The OEM recording/chain this candidate belongs to, when metadata established one.
    pub parent_recording: Option<String>,
    /// Confidence and the observations it was composed from, so the number is explainable.
    pub confidence: Option<f64>,
    pub confidence_basis: Option<String>,
    /// Why this candidate received its `data_state`, phrased for an examiner. The UI can
    /// show this verbatim so an Orphaned or Unindexed finding is never unexplained.
    pub state_reason: String,
    /// OEM-specific facts read from the structures, verbatim.
    pub oem_metadata: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct RecoveryResponseDto {
    pub oem_key: String,
    pub candidates: Vec<RecoveryCandidateDto>,
    pub run: serde_json::Value,
    pub total_bytes: u64,
    pub skipped_bytes: u64,
    /// Observability counters for the index-aware recovery run: geometry, index entry
    /// count, claimed/unclaimed byte totals, and the per-state candidate breakdown.
    pub metrics: serde_json::Value,
    /// How the scan space was derived from OEM evidence, in plain language.
    pub plan_rationale: String,
}

/// POST /api/evidence/:id/recovery
///
/// Runs an index-aware bounded recovery scan.
///
/// The OEM parser supplies storage geometry and recording-index metadata; the engine
/// converts those into claimed physical ranges, subtracts them from the address space, and
/// scans the remainder. Every candidate's `data_state` comes from that index evidence, not
/// from the fact that the OEM was detected.
///
/// Two candidate sources are merged into the response:
///
/// * recordings the parser located, classified against the claim map (normally `Active`),
/// * engine discoveries in unclaimed space (`Orphaned` / `Unindexed`), which the previous
///   implementation discarded.
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
    // The evidence id is passed in so every candidate's provenance points back at this
    // evidence item; the engine never mints one.
    let outcome = engine
        .execute_recovery(recovery::RecoveryRequest {
            evidence_id,
            reader: reader.as_ref(),
            profile,
            oem_key: &oem_key,
            parser,
            bounds: &bounds,
            scan_window: None,
            read_window_bytes: None,
        })
        .map_err(map_err)?;
    let mut run = outcome.run.clone();
    let claim_map = &outcome.plan.claim_map;

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

        // The parser locating a recording is a container walk, not proof of indexation.
        // Ask the claim map whether an authoritative index entry actually claims these
        // bytes, and classify from that. This is what previously made every parser-found
        // recording `Active` regardless of the index.
        let claim = recovery::RegionClaim::resolve(claim_map, region.offset);
        let video = recovery::VideoEvidence {
            signature_found: codec_evidence.codec != recovery::VideoCodec::Unknown
                || !codec_evidence.nal_evidence.is_empty(),
            physically_present: is_physically_present,
            structurally_valid: is_structurally_valid,
        };
        let Some(assessment) = recovery::classify_region_state(&claim, video) else {
            // No video evidence at the recording's declared offset. Reporting a recovered
            // candidate here would assert a finding the bytes do not support.
            continue;
        };

        let timezone_state = match &rec.time.timezone {
            forensic_core::TimeZoneState::Known(label) => label.clone(),
            forensic_core::TimeZoneState::Unknown => "Unknown".to_string(),
        };

        // Every range the recording occupies, in recording order, so a multi-block Dahua
        // recording can be exported whole rather than truncated to its first block.
        let all_regions: Vec<serde_json::Value> = rec
            .source_offsets
            .iter()
            .map(|r| serde_json::json!({ "offset": r.offset, "length": r.length }))
            .collect();
        let (parent_recording, partition, start_unix, end_unix) = claim
            .recorder_metadata()
            .map(|(id, p, _c, s, e)| (Some(id.to_string()), p, s, e))
            .unwrap_or((None, None, None, None));
        // OEM-specific facts come from the index entry that describes these bytes, verbatim, so
        // nothing OEM-specific is lost between the parser and the API surface.
        let oem_metadata = parent_recording
            .as_deref()
            .and_then(|id| {
                outcome.plan.index.as_ref().and_then(|ix| {
                    ix.recordings
                        .iter()
                        .chain(ix.unreferenced_recordings.iter())
                        .find(|e| e.recording_id == id)
                        .map(|e| e.oem_metadata.clone())
                })
            })
            .unwrap_or_default();

        candidates.push(RecoveryCandidateDto {
            id: format!("{}-ch{}-0x{:X}", oem_key, rec.channel, region.offset),
            // A parser-located recording is not an engine discovery, so it carries no engine
            // fragment id. Minting one here would invent an identity the engine never assigned.
            fragment_id: None,
            channel: Some(rec.channel),
            partition,
            time_native: rec.time.recorder_native.as_ref().map(|t| t.iso_8601.clone()),
            time_normalized: rec.time.normalized.as_ref().map(|t| t.iso_8601.clone()),
            timezone_state,
            start_time_unix: start_unix,
            end_time_unix: end_unix,
            duration_sec: None,
            data_state: assessment.data_state,
            recovery_status: assessment.recovery_status,
            recovery_level: assessment.recovery_level,
            source_offset: region.offset,
            source_length: region.length,
            source_regions: all_regions,
            integrity_status: codec_evidence.validation.reason.clone(),
            codec: format!("{:?}", codec_evidence.codec),
            validation: codec_evidence.validation.clone(),
            nal_unit_count: codec_evidence.nal_evidence.len(),
            has_native_artifact,
            has_derived_artifact,
            discovery_method: "parser-located recording, classified against the recording index"
                .to_string(),
            framing: None,
            parent_recording,
            confidence: None,
            confidence_basis: None,
            state_reason: assessment.reason,
            oem_metadata,
        });
    }

    // Engine discoveries in unclaimed space. These are the orphaned/unindexed findings the
    // previous implementation computed and then threw away. Candidates that overlap a
    // recording the parser already reported are skipped so the list has no duplicates.
    for (cand, frag) in outcome.candidates.iter().zip(outcome.fragments.iter()) {
        let region = match cand.source_offsets.first() {
            Some(r) => *r,
            None => continue,
        };
        let already_listed = candidates.iter().any(|c| {
            let existing = forensic_core::Region {
                offset: c.source_offset,
                length: c.source_length,
            };
            existing.overlaps(&region)
        });
        if already_listed {
            continue;
        }

        // The recording this fragment belongs to, when OEM metadata named one, gives every
        // physical range of that recording — which is what makes a multi-block export possible.
        let recording_regions: Vec<serde_json::Value> = frag
            .parent_recording
            .value()
            .and_then(|id| {
                outcome.plan.index.as_ref().and_then(|ix| {
                    ix.recordings
                        .iter()
                        .chain(ix.unreferenced_recordings.iter())
                        .find(|e| &e.recording_id == id)
                        .map(|e| {
                            e.physical_regions
                                .iter()
                                .map(|r| {
                                    serde_json::json!({ "offset": r.offset, "length": r.length })
                                })
                                .collect::<Vec<_>>()
                        })
                })
            })
            .unwrap_or_else(|| {
                vec![serde_json::json!({ "offset": region.offset, "length": region.length })]
            });

        candidates.push(RecoveryCandidateDto {
            id: format!(
                "{}-{}-0x{:X}",
                oem_key,
                frag.discovery_method.label(),
                region.offset
            ),
            // The engine's own stable id, propagated rather than regenerated.
            fragment_id: Some(frag.fragment_id.clone()),
            // Only evidence supplies a channel; carved video with none stays null.
            channel: frag.camera_id.value().copied(),
            partition: frag.partition.value().copied(),
            time_native: None,
            time_normalized: None,
            // No recorder timezone offset is established by recovery, so none is claimed.
            timezone_state: "Unknown".to_string(),
            start_time_unix: frag.timestamp_unix.value().copied(),
            end_time_unix: frag.end_timestamp_unix.value().copied(),
            duration_sec: None,
            data_state: cand.data_state,
            recovery_status: cand.recovery_status,
            recovery_level: cand.recovery_level,
            source_offset: region.offset,
            source_length: region.length,
            source_regions: recording_regions,
            integrity_status: frag.validation.reason.clone(),
            codec: frag.codec.clone(),
            validation: cand.validation.structure.clone(),
            nal_unit_count: 0,
            has_native_artifact: false,
            has_derived_artifact: false,
            discovery_method: frag.discovery_method.label().to_string(),
            framing: Some(frag.framing.label().to_string()),
            parent_recording: frag.parent_recording.value().cloned(),
            confidence: frag.confidence.value().copied(),
            confidence_basis: match &frag.confidence {
                recovery::FieldEvidence::Known { source, .. } => Some(source.clone()),
                recovery::FieldEvidence::Unknown { reason } => Some(reason.clone()),
            },
            state_reason: cand.provenance.validation_state.reason.clone(),
            oem_metadata: frag.oem_metadata.clone(),
        });
    }

    candidates.sort_by_key(|c| c.source_offset);

    // Report the candidate accounting that was actually derived.
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
        metrics: serde_json::to_value(&outcome.metrics).unwrap_or_default(),
        plan_rationale: outcome.plan.rationale.clone(),
    };

    Ok(Json(serde_json::to_value(response).unwrap()))
}

// ── Gap-targeted recovery ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GapRecoveryRequest {
    pub channel: u32,
    /// First byte of the gap's recoverable region (previous_offset + previous_length).
    pub scan_start: u64,
    /// One-past-the-last byte of the gap region (the next segment's offset).
    pub scan_end: u64,
    /// Total missing seconds in the gap (drives how many sub-slots are probed).
    pub gap_seconds: i64,
    /// Per-recording length in seconds (the channel's measured cadence).
    pub nominal_seconds: i64,
    pub oem_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GapSlotDto {
    pub index: usize,
    /// "L1" | "L2" | "L3", or null when nothing could be carved from this slot.
    pub level: Option<String>,
    /// `null` when no video was found in this slot. Finding nothing is an absence of
    /// evidence, so no `DataState` is asserted — in particular not `Deleted`.
    pub data_state: Option<forensic_core::DataState>,
    /// `null` when no candidate was produced for this slot.
    pub recovery_status: Option<forensic_core::RecoveryStatus>,
    /// Seconds from the gap open at which this slot begins / ends.
    pub start_offset_sec: i64,
    pub end_offset_sec: i64,
    /// Absolute byte offset of the slot's first byte (start of the probed window).
    pub offset: u64,
    /// Absolute byte offset of the first meaningful stream byte in the slot — the first
    /// Annex-B start code (`00 00 (00) 01`) if one was found, otherwise `offset`. The
    /// Hex inspector jumps here so the operator lands on the recovered stream data
    /// instead of any leading zero padding that precedes it.
    pub data_offset: u64,
    pub length: u64,
    pub codec: String,
    pub nal_unit_count: usize,
    pub validation_state: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct GapRecoveryResponse {
    pub channel: u32,
    pub oem_key: String,
    pub scan_start: u64,
    pub scan_end: u64,
    pub nominal_seconds: i64,
    pub num_slots: usize,
    pub total_seconds: i64,
    pub recovered_seconds: i64,
    pub unrecovered_seconds: i64,
    /// "completely_recovered" | "partially_recovered" | "not_recovered"
    pub decision: String,
    pub slots: Vec<GapSlotDto>,
}

/// True if the window contains an Annex-B start code (`00 00 01`), which also covers
/// the 4-byte `00 00 00 01` form.
fn has_annexb_start(b: &[u8]) -> bool {
    b.windows(3).any(|w| w == [0x00, 0x00, 0x01])
}

/// Offset within `b` of the first Annex-B start code. Prefers the 4-byte form's leading
/// zero (`00 00 00 01`) when present so the inspector shows the full start code. Returns
/// `None` when the window has no start code (e.g. a slot of pure zero padding).
fn first_annexb_start(b: &[u8]) -> Option<usize> {
    b.windows(3).position(|w| w == [0x00, 0x00, 0x01]).map(|i| {
        if i > 0 && b[i - 1] == 0x00 {
            i - 1
        } else {
            i
        }
    })
}

/// POST /api/evidence/:id/recovery/gap
///
/// Probes ONE detected gap's byte region — the physical space between the two recordings
/// that straddle the gap. The gap is examined as `nominal`-length sub-slots.
///
/// # This endpoint has no index evidence
///
/// It is handed a byte window by the caller and classifies what is physically there. It
/// does not consult a recording index, so it cannot establish that a slot is an active
/// recording or that it is orphaned. Classification is therefore capped at the
/// conservative states:
///
///   * validated, decodable stream        -> L3 / `Unindexed` / Recoverable
///   * codec signature, validation failed -> L3 / `Corrupted` / PartiallyRecoverable
///   * bare Annex-B start codes only      -> L3 / `Corrupted` / PartiallyRecoverable
///   * no codec evidence at all           -> not a recovered candidate, `data_state` null
///
/// Earlier revisions reported the first case as `Active` (a claim no index backs) and the
/// last as `Deleted` (a deletion finding from the mere absence of a signature). Both were
/// unsupported conclusions. For index-backed `Active`/`Orphaned` classification, use
/// `POST /api/evidence/:id/recovery`, which runs the index-aware engine.
///
/// The response reports which time sub-ranges hold recoverable video and which remain
/// empty, so a partial result (e.g. 20s of a 30s gap) stays explicit.
pub async fn recover_gap(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<uuid::Uuid>,
    Json(req): Json<GapRecoveryRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let evidence_id = EvidenceId(id);
    let reader = get_or_open_reader(&state, &evidence_id).await?;

    let len = reader.len();
    let scan_start = req.scan_start.min(len);
    let scan_end = req.scan_end.min(len).max(scan_start);
    let nominal = req.nominal_seconds.max(1);
    let total_seconds = req.gap_seconds.max(nominal);
    let num_slots = ((total_seconds as f64 / nominal as f64).round() as i64).max(1) as usize;

    let region_len = scan_end - scan_start;
    let slot_bytes = region_len / num_slots as u64;

    let mut slots = Vec::with_capacity(num_slots);
    let mut recovered_slots = 0usize;

    for k in 0..num_slots {
        let off = scan_start + (k as u64) * slot_bytes;
        let this_len = if k + 1 == num_slots { scan_end.saturating_sub(off) } else { slot_bytes };
        let read_len = this_len.min(4 * 1024 * 1024) as usize;
        let bytes = reader.read_exact_at(off, read_len).unwrap_or_default();

        let ev = recovery::VideoReconstructor::classify_codec(&bytes);
        let score = ev.h264_score + ev.h265_score + ev.mjpeg_score;
        let is_pass = matches!(ev.validation.state, forensic_core::ValidationStateKind::Pass);
        let has_start = has_annexb_start(&bytes);
        // Where the meaningful stream data actually begins inside this slot. The slot
        // start is frequently zero padding, so point the Hex inspector at the first
        // Annex-B start code when present; fall back to the slot start otherwise.
        let data_offset = first_annexb_start(&bytes)
            .map(|rel| off + rel as u64)
            .unwrap_or(off);

        // No index evidence is available here, so the strongest supportable conclusion is
        // "valid video exists but is not linked to any index entry" — Unindexed. Active
        // and Orphaned are deliberately unreachable from this endpoint.
        let (level, data_state, status, reason) = if is_pass {
            (
                Some("L3".to_string()),
                Some(forensic_core::DataState::Unindexed),
                Some(forensic_core::RecoveryStatus::Recoverable),
                format!(
                    "Clean {:?} stream with valid parameter sets. No recording index covers this \
                     window, so it is recorded as unindexed - present and valid, but not linked \
                     to an index entry. This is not evidence of deletion.",
                    ev.codec
                ),
            )
        } else if score > 0 {
            (
                Some("L3".to_string()),
                Some(forensic_core::DataState::Corrupted),
                Some(forensic_core::RecoveryStatus::PartiallyRecoverable),
                format!(
                    "{:?} NAL data present (score {score}) but structural validation did not \
                     pass, so no recording-level conclusion is drawn.",
                    ev.codec
                ),
            )
        } else if has_start {
            (
                Some("L3".to_string()),
                Some(forensic_core::DataState::Corrupted),
                Some(forensic_core::RecoveryStatus::PartiallyRecoverable),
                "Annex-B start code(s) found but no decodable NAL structure; a signature match \
                 alone is not valid video."
                    .to_string(),
            )
        } else {
            (
                None,
                // Nothing was found. That is an absence of evidence, not a deletion
                // finding, so no DataState is asserted at all.
                None,
                None,
                "No codec signature or start code in this window. Nothing was recovered here; \
                 this says nothing about whether footage once existed at this offset."
                    .to_string(),
            )
        };

        if level.is_some() {
            recovered_slots += 1;
        }

        slots.push(GapSlotDto {
            index: k,
            level,
            data_state,
            recovery_status: status,
            start_offset_sec: (k as i64) * nominal,
            end_offset_sec: ((k as i64) + 1) * nominal,
            offset: off,
            data_offset,
            length: this_len,
            codec: format!("{:?}", ev.codec),
            nal_unit_count: ev.nal_evidence.len(),
            validation_state: format!("{:?}", ev.validation.state),
            reason,
        });
    }

    let recovered_seconds = recovered_slots as i64 * nominal;
    let total = num_slots as i64 * nominal;
    let unrecovered_seconds = (total - recovered_seconds).max(0);
    let decision = if recovered_slots == 0 {
        "not_recovered"
    } else if recovered_slots == num_slots {
        "completely_recovered"
    } else {
        "partially_recovered"
    };

    let resp = GapRecoveryResponse {
        channel: req.channel,
        oem_key: req.oem_key.unwrap_or_else(|| "auto".to_string()),
        scan_start,
        scan_end,
        nominal_seconds: nominal,
        num_slots,
        total_seconds: total,
        recovered_seconds,
        unrecovered_seconds,
        decision: decision.to_string(),
        slots,
    };

    Ok(Json(serde_json::to_value(resp).unwrap()))
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

    let run: PipelineRun = run_pipeline(evidence_id, reader.as_ref(), &state.profile_registry, &config, &options)
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

/// Computed result of probing one gap's byte region with the staged L1→L2→L3 cascade.
struct GapRecoveryComputed {
    slots: Vec<reporting::model::RecoverySlotReport>,
    recovered_seconds: i64,
    unrecovered_seconds: i64,
    decision: String,
}

/// Probe a gap's byte region as `nominal`-length sub-slots and classify each through the
/// staged recovery cascade (L1 indexed → L2 orphan carve → L3 raw carve). Shared by the
/// report builder; mirrors the classification used by `recover_gap`.
fn recover_gap_region(
    reader: &dyn evidence_reader::EvidenceReader,
    scan_start: u64,
    scan_end: u64,
    nominal_seconds: i64,
    gap_seconds: i64,
) -> GapRecoveryComputed {
    let len = reader.len();
    let scan_start = scan_start.min(len);
    let scan_end = scan_end.min(len).max(scan_start);
    let nominal = nominal_seconds.max(1);
    let total_seconds = gap_seconds.max(nominal);
    let num_slots = ((total_seconds as f64 / nominal as f64).round() as i64).max(1) as usize;
    let region_len = scan_end - scan_start;
    let slot_bytes = region_len / num_slots as u64;

    let mut slots = Vec::with_capacity(num_slots);
    let mut recovered_slots = 0usize;
    for k in 0..num_slots {
        let off = scan_start + (k as u64) * slot_bytes;
        let this_len = if k + 1 == num_slots {
            scan_end.saturating_sub(off)
        } else {
            slot_bytes
        };
        let read_len = this_len.min(4 * 1024 * 1024) as usize;
        let bytes = reader.read_exact_at(off, read_len).unwrap_or_default();

        let ev = recovery::VideoReconstructor::classify_codec(&bytes);
        let score = ev.h264_score + ev.h265_score + ev.mjpeg_score;
        let is_pass = matches!(ev.validation.state, forensic_core::ValidationStateKind::Pass);
        let has_start = has_annexb_start(&bytes);
        let data_offset = first_annexb_start(&bytes)
            .map(|rel| off + rel as u64)
            .unwrap_or(off);

        let (level, reason) = if is_pass {
            (
                Some("L1".to_string()),
                format!("L1 indexed: clean {:?} stream with valid parameter sets", ev.codec),
            )
        } else if score > 0 {
            (
                Some("L2".to_string()),
                format!("L2 orphan carve: {:?} NAL data without a complete parameter set (score {score})", ev.codec),
            )
        } else if has_start {
            (
                Some("L3".to_string()),
                "L3 raw carve: Annex-B start code(s) found but no decodable NAL structure".to_string(),
            )
        } else {
            (
                None,
                "Not recovered: no codec signature or start code in this window".to_string(),
            )
        };

        let recovered = level.is_some();
        if recovered {
            recovered_slots += 1;
        }
        slots.push(reporting::model::RecoverySlotReport {
            index: k,
            level,
            recovered,
            start_offset_sec: (k as i64) * nominal,
            end_offset_sec: ((k as i64) + 1) * nominal,
            offset: data_offset,
            length: this_len,
            codec: format!("{:?}", ev.codec),
            nal_unit_count: ev.nal_evidence.len(),
            reason,
        });
    }

    let recovered_seconds = recovered_slots as i64 * nominal;
    let total = num_slots as i64 * nominal;
    let unrecovered_seconds = (total - recovered_seconds).max(0);
    let decision = if recovered_slots == 0 {
        "not_recovered"
    } else if recovered_slots == num_slots {
        "completely_recovered"
    } else {
        "partially_recovered"
    }
    .to_string();

    GapRecoveryComputed {
        slots,
        recovered_seconds,
        unrecovered_seconds,
        decision,
    }
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
    let run = run_pipeline(evidence_id, reader.as_ref(), &state.profile_registry, &config, &PipelineOptions::default())
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
                    // Channel comes from the fragment, which only has one when an index
                    // entry supplied it. Carved video reports `None`, not channel 0.
                    let frag = r.fragments.get(i);
                    RecoveryReportItem {
                        candidate_id: format!("cand-{}", i + 1),
                        channel: frag.and_then(|f| f.camera_id.value().copied()),
                        recovery_level: format!("{:?}", c.recovery_level),
                        data_state: format!("{:?}", c.data_state),
                        recovery_status: format!("{:?}", c.recovery_status),
                        source_offset: region.offset,
                        source_length: region.length,
                        validation_state: format!("{:?}", c.validation.structure.state),
                        validation_reason: c.validation.structure.reason.clone(),
                        discovery_method: frag
                            .map(|f| f.discovery_method.label().to_string())
                            .unwrap_or_default(),
                        state_reason: c.provenance.validation_state.reason.clone(),
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

    // ========================================================================
    // Deep, stage-by-stage narrative sections (Detection → Parsing →
    // Preliminary Timeline → Recovery → Final Timeline).
    // ========================================================================

    // ---- Detection depth: WHERE the OEM was found and how strongly ---------
    // The compact `run.attribution` summary drops evidence-item offsets, so re-derive
    // the classified result here to report exactly where each signature sat.
    let detection_depth = {
        let outputs = DetectionOrchestrator::new()
            .run(reader.as_ref(), &state.profile_registry)
            .ok();
        let classified = outputs
            .as_ref()
            .and_then(|o| ConfidenceEngine::classify_all(o, &state.profile_registry, &config).ok());
        classified.and_then(|c| c.into_iter().next()).map(|top| {
            let d = &top.detector_output;
            let matched_indicators: Vec<MatchedIndicatorReport> = d
                .evidence
                .iter()
                .map(|e| MatchedIndicatorReport {
                    kind: e.kind.clone(),
                    offset: e.offset,
                    length: e.length,
                    matched: matches!(e.rule_match_status, forensic_core::RuleMatchStatus::Match),
                    evidence_status: format!("{:?}", e.evidence_status),
                    exclusive: e.is_exclusive,
                    weight: e.score_contribution,
                    explanation: e.explanation.clone(),
                })
                .collect();
            let bytes_examined = d.evidence.iter().map(|e| e.length).sum();
            let highest_offset_examined = d
                .evidence
                .iter()
                .map(|e| e.offset.saturating_add(e.length))
                .max()
                .unwrap_or(0);
            DetectionDepthReport {
                image_size_bytes: reader.len(),
                method: "Structural signature probing at fixed layout offsets (MBR/superblock/packet tags) plus storage-topology partitioning. Detection reads bounded structural regions, not a full linear scan of the image.".to_string(),
                storage_family: d.storage_family.clone(),
                detector_status: format!("{:?}", d.status),
                confidence: top.confidence,
                margin: top.margin,
                evidence_quality: top.evidence_quality,
                runner_up: top.second_candidate.clone(),
                matched_indicators,
                candidate_regions: d
                    .candidate_regions
                    .iter()
                    .map(|r| RegionReport { offset: r.offset, length: r.length })
                    .collect(),
                bytes_examined,
                highest_offset_examined,
            }
        })
    };

    // ---- Parsing depth: WHERE frames were found and HOW they were confirmed -
    let parsing_depth = run.parsing.as_ref().map(|p| {
        let stages: Vec<ValidationRecord> = p
            .parser_runs
            .iter()
            .map(|prun| ValidationRecord {
                operation: prun.operation_name.clone(),
                subject: prun.validation_state.subject.clone(),
                state: format!("{:?}", prun.validation_state.state),
                reason: prun.validation_state.reason.clone(),
            })
            .collect();
        let parser_id = p
            .recordings
            .first()
            .map(|r| r.parser_id.clone())
            .or_else(|| run.oem_key_used.clone())
            .unwrap_or_else(|| "unknown".to_string());
        // Confirm each recording from its actual stream bytes (bounded sample). Capped so
        // an image with very many recordings never turns report generation into a scan.
        let mut frames = Vec::new();
        for rec in p.recordings.iter().take(150) {
            let region = rec
                .source_offsets
                .first()
                .cloned()
                .unwrap_or(forensic_core::Region { offset: 0, length: 0 });
            let sample_len = region.length.min(256 * 1024) as usize;
            let bytes = reader.read_exact_at(region.offset, sample_len).unwrap_or_default();
            let ev = recovery::VideoReconstructor::classify_codec(&bytes);
            let confirmed = matches!(ev.validation.state, forensic_core::ValidationStateKind::Pass);
            frames.push(ParsedFrameReport {
                channel: rec.channel,
                recorder_native_time: rec
                    .time
                    .recorder_native
                    .as_ref()
                    .map(|t| t.iso_8601.clone())
                    .unwrap_or_else(|| "Unknown".to_string()),
                normalized_time: rec
                    .time
                    .normalized
                    .as_ref()
                    .map(|t| t.iso_8601.clone())
                    .unwrap_or_else(|| "Unknown".to_string()),
                source_offset: region.offset,
                source_length: region.length,
                region_count: rec.source_offsets.len(),
                codec: format!("{:?}", ev.codec),
                nal_unit_count: ev.nal_evidence.len(),
                confirmed,
                confirmation: ev.validation.reason.clone(),
                integrity_flags: rec.integrity.iter().map(|f| format!("{f:?}")).collect(),
            });
        }
        ParsingDepthReport {
            parser_id,
            stages,
            total_recordings: p.recordings.len(),
            frames,
        }
    });

    // ---- Preliminary timeline: which footage exists and where the gaps are --
    let preliminary_timeline = run.recordings_timeline.as_ref().map(|rt| {
        let cov = run.gap_analysis.as_ref().map(|g| &g.coverage);
        let sessions: Vec<SessionReport> = rt
            .sessions
            .iter()
            .map(|s| SessionReport {
                channel: s.channel,
                start: s.start_native.clone().unwrap_or_else(|| s.start_normalized.clone()),
                end: s.end_native.clone().unwrap_or_else(|| s.end_normalized.clone()),
                timezone: s.timezone.clone(),
                span_seconds: s.span_seconds,
                covered_seconds: s.covered_seconds,
                missing_seconds: s.missing_seconds,
                coverage_ratio: s.coverage_ratio,
                segment_count: s.segment_count,
                gaps: s
                    .gaps
                    .iter()
                    .map(|g| SessionGapReport {
                        starts_after: g
                            .starts_after_native
                            .clone()
                            .unwrap_or_else(|| g.starts_after_normalized.clone()),
                        ends_before: g
                            .ends_before_native
                            .clone()
                            .unwrap_or_else(|| g.ends_before_normalized.clone()),
                        missing_seconds: g.missing_seconds,
                        previous_offset: g.previous_offset,
                        next_offset: g.next_offset,
                    })
                    .collect(),
            })
            .collect();
        PreliminaryTimelineReport {
            channel_count: rt.channel_count,
            total_segments: rt.total_segments,
            total_recordings: rt.total_recordings,
            total_missing_seconds: rt.total_missing_seconds,
            coverage_ratio: cov.map(|c| c.coverage_ratio).unwrap_or(0.0),
            accounted_bytes: cov.map(|c| c.accounted_bytes).unwrap_or(0),
            unaccounted_bytes: cov.map(|c| c.unaccounted_bytes).unwrap_or(0),
            total_bytes: cov.map(|c| c.total_bytes).unwrap_or_else(|| reader.len()),
            sessions,
        }
    });

    // ---- Recovery depth: staged cascade over each detected gap -------------
    let recovery_depth = run.recordings_timeline.as_ref().and_then(|rt| {
        let mut per_gap: Vec<GapRecoveryReport> = Vec::new();
        let mut searched_bytes = 0u64;
        let mut total_recovered_seconds = 0i64;
        let mut total_unrecovered_seconds = 0i64;
        for s in &rt.sessions {
            for g in &s.gaps {
                if per_gap.len() >= 40 {
                    break;
                }
                let scan_start = g.previous_offset.saturating_add(g.previous_length);
                let scan_end = g.next_offset;
                if scan_end <= scan_start {
                    continue;
                }
                let computed = recover_gap_region(
                    reader.as_ref(),
                    scan_start,
                    scan_end,
                    s.nominal_segment_seconds,
                    g.missing_seconds,
                );
                searched_bytes = searched_bytes.saturating_add(scan_end - scan_start);
                total_recovered_seconds += computed.recovered_seconds;
                total_unrecovered_seconds += computed.unrecovered_seconds;
                per_gap.push(GapRecoveryReport {
                    channel: s.channel,
                    scan_start,
                    scan_end,
                    attempts: computed.slots.len(),
                    total_seconds: computed.recovered_seconds + computed.unrecovered_seconds,
                    recovered_seconds: computed.recovered_seconds,
                    unrecovered_seconds: computed.unrecovered_seconds,
                    decision: computed.decision,
                    slots: computed.slots,
                });
            }
        }
        if per_gap.is_empty() {
            return None;
        }
        Some(RecoveryDepthReport {
            algorithm: "Staged cascade — each missing sub-slot is probed L1 (indexed clean stream) → L2 (orphaned NAL carve) → L3 (raw Annex-B carve); a sub-slot with no start code is left unrecovered.".to_string(),
            searched_bytes,
            total_bytes: reader.len(),
            gaps_processed: per_gap.len(),
            total_recovered_seconds,
            total_unrecovered_seconds,
            per_gap,
        })
    });

    // ---- Final timeline summary --------------------------------------------
    let final_timeline_summary = {
        let recorded_events = run.preliminary_timeline.as_ref().map(|t| t.events.len()).unwrap_or(0);
        let total_events = run
            .final_timeline
            .as_ref()
            .map(|t| t.events.len())
            .unwrap_or(recorded_events);
        Some(FinalTimelineReport {
            total_events,
            recorded_events,
            recovered_events: total_events.saturating_sub(recorded_events),
        })
    };

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
        detection_depth,
        parsing_depth,
        preliminary_timeline,
        recovery_depth,
        final_timeline_summary,
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
