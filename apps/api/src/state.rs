//! # API Application State
//!
//! Holds shared thread-safe state for the Axum REST service.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use evidence_reader::EvidenceReader;
use forensic_core::profile::ProfileRegistry;
use forensic_core::write_guard::WriteGuard;
use forensic_core::EvidenceId;
use media::MediaPipeline;
use recovery::FfmpegService;
use sqlx::SqlitePool;

#[derive(Clone)]
pub struct AppState {
    pub db_pool: SqlitePool,
    pub readers: Arc<RwLock<HashMap<EvidenceId, Arc<dyn EvidenceReader>>>>,
    pub profile_registry: Arc<ProfileRegistry>,
    pub ffmpeg_service: Arc<FfmpegService>,
    /// The downstream media pipeline: ffprobe validation, FFmpeg decoding to real frames,
    /// image processing and the AI boundary.
    ///
    /// It is built once at startup so its bounded process runner is shared by every request —
    /// a single pool of FFmpeg permits for the whole service, rather than one per request.
    pub media_pipeline: Arc<MediaPipeline>,
    pub write_guard: Arc<WriteGuard>,
}

impl AppState {
    pub fn new(db_pool: SqlitePool) -> Self {
        // Load profiles from the `profiles` directory at startup
        let registry = ProfileRegistry::load_from_dir(std::path::Path::new("profiles")).unwrap_or_else(|e| {
            tracing::warn!("Failed to load profiles from 'profiles' dir: {e}. Falling back to empty registry.");
            ProfileRegistry::from_profiles(vec![])
        });
        let ffmpeg_service = Arc::new(FfmpegService::default());
        // No analysis engine is registered, so the media pipeline reports
        // AI_ANALYSIS_NOT_CONFIGURED and produces no findings. That is the honest state until
        // a real engine exists; nothing here fabricates detections in its absence.
        let media_pipeline = Arc::new(MediaPipeline::default());
        let write_guard = Arc::new(WriteGuard::new("evidence_samples", "artifacts"));

        Self {
            db_pool,
            readers: Arc::new(RwLock::new(HashMap::new())),
            profile_registry: Arc::new(registry),
            ffmpeg_service,
            media_pipeline,
            write_guard,
        }
    }
}
