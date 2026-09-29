use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use uuid::Uuid;

use acquisition::{
    AcquisitionConfig, AcquisitionResult, AcquisitionStatus, ExaminerWriteBlockerAttestation,
    PhysicalSource, VerificationRecord, VerificationStatus,
};
use forensic_api::jobs::{JobCoordinator, JobState};
use forensic_api::{app_router, AppConfig, AppState};

#[tokio::test]
async fn test_acquisition_job_coordinator() {
    let coordinator = JobCoordinator::new();
    let case_id = Uuid::new_v4();

    let config = AcquisitionConfig {
        source_path: r"\\.\PhysicalDrive1".to_string(),
        destination_path: r"C:\cases\evidence.raw".to_string(),
        chunk_size: 1024 * 1024,
        max_retries: 3,
        case_id,
        examiner: "Investigator".to_string(),
        attestation: ExaminerWriteBlockerAttestation::default(),
        attempt_volume_lock: true,
    };

    // 1. Create acquisition job
    let (job_id, entry, cancel_token) = coordinator.create_acquisition_job(config.clone()).await;
    let initial_status = coordinator.get_job_status(&job_id).await.unwrap();
    assert_eq!(initial_status.job_id, job_id);
    assert_eq!(initial_status.state, JobState::Queued);
    assert!(initial_status.evidence_id.is_none());

    // 2. Update progress
    {
        let mut guard = entry.write().await;
        guard.state = JobState::Running;
        guard.stage = Some("acquiring".to_string());
        guard.acquisition_progress = Some(acquisition::AcquisitionProgress {
            bytes_processed: 500_000_000,
            total_bytes: 1_000_000_000,
            percentage: 50.0,
            throughput_bytes_per_sec: 125_000_000,
            elapsed_seconds: 4.0,
            eta_seconds: Some(4),
            bad_sector_count: 0,
            unreadable_bytes: 0,
            current_phase: "acquiring".to_string(),
        });
    }

    let running_status = coordinator.get_job_status(&job_id).await.unwrap();
    assert_eq!(running_status.state, JobState::Running);
    let p = running_status.acquisition_progress.unwrap();
    assert_eq!(p.percentage, 50.0);
    assert_eq!(p.throughput_bytes_per_sec, 125_000_000);

    // 3. Cancel job
    assert!(!cancel_token.is_cancelled());
    let cancel_res = coordinator.cancel_job(&job_id).await.unwrap();
    assert_eq!(cancel_res.state, JobState::Cancelled);
    assert!(cancel_token.is_cancelled());
}

#[tokio::test]
async fn test_acquisition_api_endpoints_and_registration() {
    let pool = forensic_api::db::connection::init_pool("sqlite::memory:")
        .await
        .unwrap();

    let state = AppState::new_with_config(pool.clone(), AppConfig::default());
    let router = app_router(state.clone());

    // 1. GET /api/acquisition/devices
    let req = Request::builder()
        .uri("/api/acquisition/devices")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // 2. POST /api/acquisition/assess
    let dummy_source = PhysicalSource {
        drive_number: 1,
        device_path: r"\\.\PhysicalDrive1".to_string(),
        vendor: Some("Synthetic".to_string()),
        model: Some("TestDrive".to_string()),
        serial: None,
        bus_type: acquisition::BusType::Unknown,
        capacity: 10_000,
        logical_sector_size: 512,
        physical_sector_size: 512,
        removable: false,
        os_write_protected: false,
        volumes: vec![],
    };

    let assess_payload = serde_json::json!({
        "source": dummy_source,
        "config": {
            "source_path": r"\\.\PhysicalDrive1",
            "destination_path": r"C:\tmp\test.raw",
            "chunk_size": 1024,
            "max_retries": 1,
            "case_id": Uuid::new_v4(),
            "examiner": "Examiner",
            "attestation": {
                "hardware_write_blocker_used": true,
                "blocker_make_model": "Tableau T8u",
                "examiner_notes": null
            },
            "attempt_volume_lock": false
        }
    });

    let req = Request::builder()
        .uri("/api/acquisition/assess")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&assess_payload).unwrap()))
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // 3. Create a Case in DB
    let examiner_id = forensic_core::ExaminerId("Lead Examiner".to_string());
    let case_obj = forensic_api::db::repositories::cases::create_case(
        &pool,
        "Test Physical Case",
        "Testing acquisition workflow",
        &examiner_id,
    )
    .await
    .unwrap();
    let case_id = case_obj.id;

    // 4. Create an acquired RAW file on disk
    let temp_image_dir = std::env::temp_dir().join(format!("acq_api_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&temp_image_dir).unwrap();
    let temp_image_path = temp_image_dir.join("acquired.raw");
    let test_bytes = vec![0xEFu8; 4096];
    std::fs::write(&temp_image_path, &test_bytes).unwrap();

    let manifest_path = temp_image_dir.join("acquired.raw.json");
    std::fs::write(&manifest_path, b"{}").unwrap();

    // 5. Create a completed acquisition job in state.jobs
    let config = AcquisitionConfig {
        source_path: r"\\.\PhysicalDrive1".to_string(),
        destination_path: temp_image_path.to_string_lossy().to_string(),
        chunk_size: 1024,
        max_retries: 1,
        case_id: case_id.0,
        examiner: "Lead Examiner".to_string(),
        attestation: ExaminerWriteBlockerAttestation::default(),
        attempt_volume_lock: false,
    };
    let (job_id, entry, _) = state.jobs.create_acquisition_job(config).await;
    {
        let mut guard = entry.write().await;
        guard.state = JobState::Completed;
        guard.stage = Some("completed".to_string());
        guard.acquisition_result = Some(AcquisitionResult {
            acquisition_id: Uuid::new_v4(),
            case_id: case_id.0,
            status: AcquisitionStatus::Complete,
            image_path: temp_image_path.clone(),
            manifest_path: manifest_path.clone(),
            bytes_written: test_bytes.len() as u64,
            bad_sectors: vec![],
            verification: VerificationRecord {
                pass1_md5: "md5hash".to_string(),
                pass1_sha256: "sha256hash".to_string(),
                pass2_md5: Some("md5hash".to_string()),
                pass2_sha256: Some("sha256hash".to_string()),
                status: VerificationStatus::Verified,
                details: None,
                verified_at: Some(chrono::Utc::now()),
            },
            elapsed_seconds: 1.2,
        });
    }

    // 6. Register evidence via POST /api/acquisition/jobs/:id/register
    let req = Request::builder()
        .uri(format!("/api/acquisition/jobs/{job_id}/register"))
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(b"{}" as &[u8]))
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let registered_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let evidence_id_str = registered_json["evidence"]["id"].as_str().unwrap();
    assert_eq!(registered_json["acquisition"]["status"], "complete");

    // 7. Verify registered evidence can be queried and read by existing EvidenceReader
    let req = Request::builder()
        .uri(format!("/api/evidence/{evidence_id_str}/bytes?offset=0&length=16"))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let byte_resp_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let hex_val: serde_json::Value = serde_json::from_slice(&byte_resp_bytes).unwrap();
    assert_eq!(hex_val["length"], 16);
    assert_eq!(hex_val["hex"], "ef".repeat(16));

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_image_dir);
}
