//! # forensic-api Library Interface

pub mod state;
pub mod handlers;
pub mod capability_service;
pub mod db;

use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::{Any, CorsLayer};

pub use state::AppState;

pub fn app_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/api/cases", post(handlers::create_case).get(handlers::list_cases))
        .route("/api/cases/:id", get(handlers::get_case))
        .route("/api/cases/:id/evidence", post(handlers::register_evidence).get(handlers::list_case_evidence))
        .route("/api/cases/:id/custody", get(handlers::get_custody_log))
        .route("/api/evidence/:id", get(handlers::get_evidence))
        .route("/api/evidence/:id/safety", get(handlers::get_source_safety))
        .route("/api/evidence/:id/bytes", get(handlers::read_evidence_bytes))
        .route("/api/evidence/:id/search", get(handlers::search_evidence))
        .route("/api/evidence/:id/detection", post(handlers::run_detection))
        .route("/api/evidence/:id/topology", get(handlers::get_topology))
        .route("/api/capabilities", get(handlers::get_capabilities))
        .layer(cors)
        .with_state(state)
}
