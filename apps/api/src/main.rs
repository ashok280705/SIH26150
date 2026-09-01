//! # forensic-api
//!
//! Axum/Tokio HTTP API for the DVR/NVR forensic platform (Req 7.1, 7.2, 7.4, 7.7, 1.10, 18.8).

use forensic_api::{app_router, AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let db_pool = forensic_api::db::connection::init_pool("sqlite:forensic_metadata.db").await?;
    let state = AppState::new(db_pool);
    let app = app_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("DVR/NVR Forensic Analysis API listening on http://127.0.0.1:3000");

    axum::serve(listener, app).await?;
    Ok(())
}
