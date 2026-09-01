//! # API Application State
//!
//! Holds shared thread-safe state for the Axum REST service.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use evidence_reader::EvidenceReader;
use forensic_core::profile::ProfileRegistry;
use forensic_core::EvidenceId;
use sqlx::SqlitePool;

#[derive(Clone)]
pub struct AppState {
    pub db_pool: SqlitePool,
    pub readers: Arc<RwLock<HashMap<EvidenceId, Arc<dyn EvidenceReader>>>>,
    pub profile_registry: Arc<ProfileRegistry>,
}

impl AppState {
    pub fn new(db_pool: SqlitePool) -> Self {
        // Load profiles from the `profiles` directory at startup
        let registry = ProfileRegistry::load_from_dir(std::path::Path::new("profiles")).unwrap_or_else(|e| {
            tracing::warn!("Failed to load profiles from 'profiles' dir: {e}. Falling back to empty registry.");
            ProfileRegistry::from_profiles(vec![])
        });
        Self {
            db_pool,
            readers: Arc::new(RwLock::new(HashMap::new())),
            profile_registry: Arc::new(registry),
        }
    }
}
