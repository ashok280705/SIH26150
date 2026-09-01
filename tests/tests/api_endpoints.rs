//! # API Endpoints Integration Test
//!
//! Tests the Axum HTTP REST endpoints for case creation, evidence registration,
//! source safety inspection, custody retrieval, and bounded byte reads.

use std::fs;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use forensic_api::{app_router, AppState};
use forensic_tests::fixtures::{generate_fixture, FixtureShape, OemShape};

#[tokio::test]
async fn test_api_case_creation_and_evidence_flow() {
    let state = AppState::new();
    let app = app_router(state);

    // 1. Create Case
    let create_payload = serde_json::json!({
        "name": "Burglary Investigation",
        "description": "Store CCTV footage extraction",
        "examiner": "Det. Smith",
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/cases")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&create_payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let case_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let case_id = case_json["id"].as_str().unwrap().replace("case-", "");

    // 2. Prepare Synthetic Evidence on disk
    let temp_dir = std::env::temp_dir().join(format!("api_test_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();
    let evidence_path = temp_dir.join("evidence.raw");
    let fixture = generate_fixture(OemShape::Dahua, FixtureShape::Normal, 100);
    fs::write(&evidence_path, &fixture.bytes).unwrap();

    // 3. Register Evidence
    let register_payload = serde_json::json!({
        "source_device": "Dahua DH-XVR5108HS-4KL-I3",
        "acquisition_time": "2026-09-01T12:00:00Z",
        "capacity": fixture.bytes.len(),
        "image_format": "raw",
        "responsible_examiner": "Det. Smith",
        "acquisition_tool": "dd",
        "acquisition_tool_version": "8.32",
        "path": evidence_path.display().to_string(),
        "acquisition_status": "complete",
        "bad_sector_ranges": [],
        "unresolved_ranges": [],
        "source_state": "read_only",
    });

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/cases/{case_id}/evidence"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&register_payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let ev_res: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let evidence_id = ev_res["evidence"]["id"].as_str().unwrap().replace("evidence-", "");

    // 4. Read Evidence Bytes through API
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/evidence/{evidence_id}/bytes?offset=0&length=16"))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let bytes_res: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let hex_val = bytes_res["hex"].as_str().unwrap();
    assert_eq!(hex_val, hex::encode(&fixture.bytes[..16]));

    // 5. Get Source Safety
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/evidence/{evidence_id}/safety"))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let _ = fs::remove_dir_all(&temp_dir);
}
