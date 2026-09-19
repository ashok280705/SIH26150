//! # Video Pipeline Integration Test
//!
//! Tests the complete forensic video artifact pipeline:
//! 1. FFmpeg status probe endpoint (`GET /api/ffmpeg/status`)
//! 2. Parsing TP-Link/VIGI evidence containing H.264 video
//! 3. Reconstructing recording (`POST /api/evidence/{id}/recordings/{rec_id}/reconstruct`)
//! 4. Verifying artifact retrieval (`GET /api/artifacts/{id}`)
//! 5. On-disk artifact SHA-256 integrity verification (`POST /api/artifacts/{id}/verify`)
//! 6. HTTP Range video streaming with partial content (`GET /api/artifacts/{id}/video`)
//! 7. Verifying original evidence immutability (evidence hash unchanged)

use std::fs;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use forensic_api::{app_router, AppState};

#[tokio::test]
async fn test_ffmpeg_status_endpoint() {
    let pool = forensic_api::db::connection::init_pool("sqlite::memory:").await.unwrap();
    let state = AppState::new(pool);
    let app = app_router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/api/ffmpeg/status")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let status_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    
    assert!(status_json.get("available").is_some());
    assert!(status_json.get("source").is_some());
}

#[tokio::test]
async fn test_video_reconstruction_pipeline_and_streaming() {
    let pool = forensic_api::db::connection::init_pool("sqlite::memory:").await.unwrap();
    let state = AppState::new(pool);
    let app = app_router(state);

    // 1. Create Case
    let create_payload = serde_json::json!({
        "name": "Video Forensics Test Case",
        "description": "Stream-copy remux pipeline verification",
        "examiner": "Forensic Examiner",
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

    // 2. Synthesize TP-Link / VIGI synthetic evidence with valid H.264 Annex-B NAL units
    let temp_dir = std::env::temp_dir().join(format!("video_test_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();
    let evidence_path = temp_dir.join("tplink_evidence.raw");

    // Build synthetic TP-Link payload with TPREC stream header and H.264 SPS/PPS/IDR frames
    let mut fixture_bytes = vec![0u8; 256 * 1024]; // 256 KB
    
    // Stream 1 header at offset 512
    let frame_offset = 512;
    fixture_bytes[frame_offset..frame_offset + 7].copy_from_slice(b"TPREC\x01\x00"); // needle
    fixture_bytes[frame_offset + 7] = 0x01; // Channel 1
    let ts: u64 = 1726000000;
    fixture_bytes[frame_offset + 8..frame_offset + 16].copy_from_slice(&ts.to_le_bytes());
    fixture_bytes[frame_offset + 16..frame_offset + 21].copy_from_slice(b"H.264");
    fixture_bytes[frame_offset + 40..frame_offset + 44].copy_from_slice(&100u32.to_le_bytes()); // 100 frames
    fixture_bytes[frame_offset + 48..frame_offset + 58].copy_from_slice(b"MainStream");

    // Write H.264 SPS/PPS/IDR Annex-B NAL units inside payload at offset 512 + 64
    let nal_start = frame_offset + 64;
    // SPS: 00 00 00 01 67 42 00 1f ...
    let sps = [0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1f, 0x8d, 0x68, 0x05, 0x00, 0x5b, 0xa1, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0x32, 0x84];
    // PPS: 00 00 00 01 68 ce 3c 80
    let pps = [0x00, 0x00, 0x00, 0x01, 0x68, 0xce, 0x3c, 0x80];
    // IDR slice: 00 00 00 01 65 88 80 ...
    let idr = [0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x80, 0x10, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00];

    fixture_bytes[nal_start..nal_start + sps.len()].copy_from_slice(&sps);
    let pps_offset = nal_start + sps.len();
    fixture_bytes[pps_offset..pps_offset + pps.len()].copy_from_slice(&pps);
    let idr_offset = pps_offset + pps.len();
    fixture_bytes[idr_offset..idr_offset + idr.len()].copy_from_slice(&idr);

    fs::write(&evidence_path, &fixture_bytes).unwrap();
    let initial_evidence_hash = recovery::hash_file_sha256(&evidence_path).unwrap();

    // 3. Register Evidence
    let register_payload = serde_json::json!({
        "source_device": "TP-Link VIGI NVR1008H",
        "acquisition_time": "2026-09-01T12:00:00Z",
        "capacity": fixture_bytes.len(),
        "image_format": "raw",
        "responsible_examiner": "Forensic Examiner",
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

    // 4. Run Parser
    let parse_payload = serde_json::json!({
        "oem_key": "tplink"
    });

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/evidence/{evidence_id}/parsing"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&parse_payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let parse_res: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let recordings = parse_res["recordings"].as_array().unwrap();
    assert!(!recordings.is_empty(), "Expected parsed recordings from TP-Link synthetic fixture");

    let rec_id = "rec-001";

    // 5. Trigger Video Reconstruction
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/evidence/{evidence_id}/recordings/{rec_id}/reconstruct"))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let recon_res: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    let elem_artifact_id = recon_res["elementary_stream"]["artifact_id"].as_str().unwrap();
    assert!(recon_res["elementary_stream"]["sha256"].as_str().is_some());

    // 6. Verify Artifact retrieval API
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/artifacts/{elem_artifact_id}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 7. Verify Artifact on-disk verification API
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/artifacts/{elem_artifact_id}/verify"))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let verify_res: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(verify_res["status"].as_str().unwrap(), "MATCH");

    // 8. Test Video Streaming / Range Request
    let stream_target_id = if let Some(mp4) = recon_res.get("remux").and_then(|r| r.as_object()) {
        mp4["artifact_id"].as_str().unwrap()
    } else {
        elem_artifact_id
    };

    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/artifacts/{stream_target_id}/video"))
        .header("Range", "bytes=0-15")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(resp.headers().get("accept-ranges").unwrap(), "bytes");
    let content_range = resp.headers().get("content-range").unwrap().to_str().unwrap();
    assert!(content_range.starts_with("bytes 0-15/"));

    let chunk = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(chunk.len(), 16);

    // 9. CRITICAL FORENSIC REQUIREMENT: Original evidence MUST NOT be altered
    let post_evidence_hash = recovery::hash_file_sha256(&evidence_path).unwrap();
    assert_eq!(initial_evidence_hash, post_evidence_hash, "Original evidence was modified during video reconstruction!");

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}
