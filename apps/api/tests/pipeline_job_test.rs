use axum::body::Body;
use axum::http::{Request, StatusCode};
use forensic_api::jobs::{JobCoordinator, JobProgressInfo, JobState};
use forensic_api::{app_router, AppConfig, AppState};
use forensic_core::EvidenceId;
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
async fn test_job_coordinator_lifecycle() {
    let coordinator = JobCoordinator::new();
    let evidence_id = EvidenceId(Uuid::new_v4());

    // 1. Create / Start
    let (job_id, entry, _cancel_token) = coordinator.create_job(evidence_id).await;
    let initial_status = coordinator.get_job_status(&job_id).await.unwrap();
    assert_eq!(initial_status.job_id, job_id);
    assert_eq!(initial_status.evidence_id, evidence_id.0);
    assert_eq!(initial_status.state, JobState::Queued);
    assert!(initial_status.progress.is_none());

    // 2. Progress update
    {
        let mut guard = entry.write().await;
        guard.state = JobState::Running;
        guard.stage = Some("detection".to_string());
        guard.progress = Some(JobProgressInfo {
            stage: "detection".to_string(),
            stage_name: "OEM Signature Detection".to_string(),
            stage_index: 1,
            total_stages: 6,
            description: "Scanning evidence for known DVR/NVR structures".to_string(),
            fraction: Some(0.15),
        });
    }

    let running_status = coordinator.get_job_status(&job_id).await.unwrap();
    assert_eq!(running_status.state, JobState::Running);
    assert_eq!(running_status.stage.as_deref(), Some("detection"));
    let progress = running_status.progress.unwrap();
    assert_eq!(progress.fraction, Some(0.15));
    assert_eq!(progress.stage_name, "OEM Signature Detection");

    // 3. Completion
    {
        let mut guard = entry.write().await;
        guard.state = JobState::Completed;
        guard.stage = Some("completed".to_string());
    }

    let completed_status = coordinator.get_job_status(&job_id).await.unwrap();
    assert_eq!(completed_status.state, JobState::Completed);

    // 4. Cancellation test on a second job
    let (job2_id, _entry2, cancel_token2) = coordinator.create_job(evidence_id).await;
    assert!(!cancel_token2.is_cancelled());
    let cancel_res = coordinator.cancel_job(&job2_id).await.unwrap();
    assert_eq!(cancel_res.state, JobState::Cancelled);
    assert!(cancel_token2.is_cancelled());

    let cancelled_status = coordinator.get_job_status(&job2_id).await.unwrap();
    assert_eq!(cancelled_status.state, JobState::Cancelled);

    // 5. Failure test on a third job
    let (job3_id, entry3, _) = coordinator.create_job(evidence_id).await;
    {
        let mut guard = entry3.write().await;
        guard.state = JobState::Failed;
        guard.error = Some("Corrupt evidence header encountered".to_string());
    }
    let failed_status = coordinator.get_job_status(&job3_id).await.unwrap();
    assert_eq!(failed_status.state, JobState::Failed);
    assert_eq!(
        failed_status.error.as_deref(),
        Some("Corrupt evidence header encountered")
    );
}

#[tokio::test]
async fn test_job_api_endpoints() {
    let test_db = "test_jobs_endpoint.db";
    let _ = std::fs::remove_file(test_db);
    let db_url = format!("sqlite:{}", test_db);
    let pool = forensic_api::db::connection::init_pool(&db_url)
        .await
        .unwrap();

    let state = AppState::new_with_config(pool, AppConfig::default());
    let router = app_router(state.clone());

    // Query non-existent job -> 400 (not found returns BAD_REQUEST in ApiError)
    let dummy_id = Uuid::new_v4();
    let req = Request::builder()
        .uri(format!("/api/jobs/{dummy_id}"))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Create a job directly via coordinator and query it via GET /api/jobs/:id
    let evidence_id = EvidenceId(Uuid::new_v4());
    let (job_id, entry, _) = state.jobs.create_job(evidence_id).await;
    {
        let mut guard = entry.write().await;
        guard.state = JobState::Running;
        guard.stage = Some("intake".to_string());
        guard.progress = Some(JobProgressInfo {
            stage: "intake".to_string(),
            stage_name: "Evidence Intake".to_string(),
            stage_index: 0,
            total_stages: 6,
            description: "Opening read-only handle".to_string(),
            fraction: Some(0.05),
        });
    }

    let req = Request::builder()
        .uri(format!("/api/jobs/{job_id}"))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let status_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(status_json["job_id"], job_id.to_string());
    assert_eq!(status_json["state"], "running");
    assert_eq!(status_json["stage"], "intake");
    assert_eq!(status_json["progress"]["fraction"], 0.05);

    // Cancel job via POST /api/jobs/:id/cancel
    let cancel_req = Request::builder()
        .uri(format!("/api/jobs/{job_id}/cancel"))
        .method("POST")
        .body(Body::empty())
        .unwrap();
    let cancel_res = router.clone().oneshot(cancel_req).await.unwrap();
    assert_eq!(cancel_res.status(), StatusCode::OK);

    // Verify it is now marked cancelled
    let req2 = Request::builder()
        .uri(format!("/api/jobs/{job_id}"))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res2 = router.oneshot(req2).await.unwrap();
    let body_bytes2 = axum::body::to_bytes(res2.into_body(), usize::MAX)
        .await
        .unwrap();
    let status2: serde_json::Value = serde_json::from_slice(&body_bytes2).unwrap();
    assert_eq!(status2["state"], "cancelled");

    let _ = std::fs::remove_file(test_db);
}
