//! # API Application State
//!
//! Holds shared thread-safe state for the Axum REST service.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::AppConfig;
use crate::jobs::JobCoordinator;
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
    pub config: Arc<AppConfig>,
    pub jobs: Arc<JobCoordinator>,
    pub ai_gateway: Arc<crate::ai::AiGateway>,
}

impl AppState {
    pub fn new(db_pool: SqlitePool) -> Self {
        Self::new_with_config(db_pool, AppConfig::default())
    }

    pub fn new_with_config(db_pool: SqlitePool, config: AppConfig) -> Self {
        let registry = ProfileRegistry::load_from_dir(&config.profiles_dir).unwrap_or_else(|e| {
            tracing::warn!(
                "Failed to load profiles from '{}': {e}. Falling back to empty registry.",
                config.profiles_dir.display()
            );
            ProfileRegistry::from_profiles(vec![])
        });

        let ffmpeg_service = Arc::new(match &config.ffmpeg_path {
            Some(p) => FfmpegService::discover(Some(p)),
            None => FfmpegService::default(),
        });

        let media_pipeline = Arc::new(MediaPipeline::default());
        let write_guard = Arc::new(WriteGuard::new(
            config.evidence_samples_dir.to_string_lossy().as_ref(),
            config.artifacts_dir.to_string_lossy().as_ref(),
        ));
        let jobs = Arc::new(JobCoordinator::new());
        let ai_gateway = Arc::new(crate::ai::AiGateway::from_env());

        Self {
            db_pool,
            readers: Arc::new(RwLock::new(HashMap::new())),
            profile_registry: Arc::new(registry),
            ffmpeg_service,
            media_pipeline,
            write_guard,
            config: Arc::new(config),
            jobs,
            ai_gateway,
        }
    }
}
