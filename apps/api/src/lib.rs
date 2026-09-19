//! # forensic-api Library Interface

pub mod state;
pub mod handlers;
pub mod capability_service;
pub mod db;

use std::path::PathBuf;
use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};

pub use state::AppState;

fn find_frontend_dir() -> Option<PathBuf> {
    let candidates = [
        PathBuf::from("frontend"),
        PathBuf::from("dist"),
        PathBuf::from("apps/frontend/dist"),
        PathBuf::from("../frontend"),
        PathBuf::from("../dist"),
    ];

    for candidate in &candidates {
        if candidate.join("index.html").exists() {
            return Some(candidate.clone());
        }
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            let exe_candidates = [
                parent.join("frontend"),
                parent.join("dist"),
                parent.join("../Resources/frontend"),
                parent.join("../Resources/dist"),
            ];
            for candidate in &exe_candidates {
                if candidate.join("index.html").exists() {
                    return Some(candidate.clone());
                }
            }
        }
    }

    None
}

pub fn app_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let mut router = Router::new()
        .route("/api/cases", post(handlers::create_case).get(handlers::list_cases))
        .route("/api/cases/:id", get(handlers::get_case))
        .route("/api/cases/:id/evidence", post(handlers::register_evidence).get(handlers::list_case_evidence))
        .route("/api/cases/:id/custody", get(handlers::get_custody_log))
        .route("/api/evidence/:id", get(handlers::get_evidence))
        .route("/api/evidence/:id/safety", get(handlers::get_source_safety))
        .route("/api/evidence/:id/bytes", get(handlers::read_evidence_bytes))
        .route("/api/evidence/:id/search", get(handlers::search_evidence))
        .route("/api/evidence/:id/detection", post(handlers::run_detection))
        .route("/api/evidence/:id/parsing", post(handlers::run_parsing))
        .route("/api/evidence/:id/topology", get(handlers::get_topology))
        .route("/api/evidence/:id/recordings/:rec_id/reconstruct", post(handlers::reconstruct_recording))
        .route("/api/evidence/:id/artifacts", get(handlers::list_evidence_artifacts))
        .route("/api/artifacts/:id", get(handlers::get_artifact_handler))
        .route("/api/artifacts/:id/verify", post(handlers::verify_artifact_handler))
        .route("/api/artifacts/:id/video", get(handlers::stream_artifact_video))
        .route("/api/ffmpeg/status", get(handlers::get_ffmpeg_status))
        .route("/api/capabilities", get(handlers::get_capabilities));

    if let Some(frontend_dir) = find_frontend_dir() {
        let index_file = frontend_dir.join("index.html");
        let serve_service = ServeDir::new(&frontend_dir).fallback(ServeFile::new(index_file));
        router = router.fallback_service(serve_service);
    }

    router.layer(cors).with_state(state)
}
