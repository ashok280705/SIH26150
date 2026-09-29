use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use chrono::Utc;
use forensic_api::{app_router, AppConfig, AppState};
use forensic_core::{
    ArtifactId, DerivedArtifact, DerivedKind, Evidence, EvidenceId, ExaminerId, Hash,
    ImageFormat, Provenance, SourceState, ValidationState,
};
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
async fn test_video_streaming_endpoint_range_and_headers() {
    let pool = forensic_api::db::connection::init_pool("sqlite::memory:")
        .await
        .unwrap();

    let temp_dir = std::env::temp_dir().join(format!("vidforge_test_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let mp4_file = temp_dir.join("sample_test.mp4");
    // Write 4096 bytes of dummy MP4 data
    let mut dummy_data = vec![0u8; 4096];
    for (i, b) in dummy_data.iter_mut().enumerate() {
        *b = (i % 256) as u8;
    }
    std::fs::write(&mp4_file, &dummy_data).unwrap();

    let mut config = AppConfig::default();
    config.artifacts_dir = temp_dir.clone();
    let state = AppState::new_with_config(pool.clone(), config);
    let router = app_router(state.clone());

    // Register a case and evidence
    let examiner = ExaminerId("Lead Examiner".to_string());
    let case_obj = forensic_api::db::repositories::cases::create_case(
        &pool,
        "Test Video Case",
        "Testing video streaming",
        &examiner,
    )
    .await
    .unwrap();

    let evidence_id = EvidenceId::new();
    let evidence = Evidence {
        id: evidence_id,
        case_id: case_obj.id,
        source_device: "test_device".to_string(),
        acquisition_time: Utc::now(),
        capacity: 4096,
        image_format: ImageFormat::Raw,
        responsible_examiner: examiner,
        acquisition_tool: Some("VidForge".to_string()),
        acquisition_tool_version: Some("0.1.0".to_string()),
        source_state: SourceState::ReadOnly,
        acquisition_id: None,
        path: mp4_file.to_string_lossy().to_string(),
        registered_at: Utc::now(),
        examiner_timezone: None,
    };
    forensic_api::db::repositories::evidence::create_evidence(&pool, &evidence)
        .await
        .unwrap();

    // Save a derived artifact record
    let artifact_id = ArtifactId::new();
    let prov = Provenance::new(
        evidence_id,
        Hash::sha256(vec![0; 32]),
        vec![],
        "test",
        "1.0",
        Hash::sha256(vec![0; 32]),
        ValidationState::pass("test pass", "test", "Remux").unwrap(),
    );
    let artifact = DerivedArtifact {
        id: artifact_id,
        kind: DerivedKind::Remux,
        provenance: prov,
        output_path: mp4_file.to_string_lossy().to_string(),
        description: "Test remux MP4".to_string(),
        produced_at: chrono::Utc::now(),
    };

    forensic_api::db::repositories::artifacts::save_derived_artifact(
        &pool,
        &evidence_id,
        &artifact,
        "0000000000000000000000000000000000000000000000000000000000000000",
        4096,
        1000,
    )
    .await
    .unwrap();

    // 1. Full GET request -> 200 OK
    {
        let req = Request::builder()
            .uri(format!("/api/artifacts/{}/video", artifact_id.0))
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let res = router.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get(header::CONTENT_TYPE).unwrap(),
            "video/mp4"
        );
        assert_eq!(
            res.headers().get(header::ACCEPT_RANGES).unwrap(),
            "bytes"
        );
        assert_eq!(
            res.headers().get(header::CONTENT_LENGTH).unwrap(),
            "4096"
        );

        let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body_bytes.len(), 4096);
        assert_eq!(&body_bytes[..], &dummy_data[..]);
    }

    // 2. Closed Range GET -> 206 Partial Content (bytes 0-1023)
    {
        let req = Request::builder()
            .uri(format!("/api/artifacts/{}/video", artifact_id.0))
            .method("GET")
            .header(header::RANGE, "bytes=0-1023")
            .body(Body::empty())
            .unwrap();
        let res = router.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            res.headers().get(header::CONTENT_TYPE).unwrap(),
            "video/mp4"
        );
        assert_eq!(
            res.headers().get(header::CONTENT_RANGE).unwrap(),
            "bytes 0-1023/4096"
        );
        assert_eq!(
            res.headers().get(header::CONTENT_LENGTH).unwrap(),
            "1024"
        );

        let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body_bytes.len(), 1024);
        assert_eq!(&body_bytes[..], &dummy_data[0..1024]);
    }

    // 3. Open-ended Range GET -> 206 Partial Content (bytes 1024-)
    {
        let req = Request::builder()
            .uri(format!("/api/artifacts/{}/video", artifact_id.0))
            .method("GET")
            .header(header::RANGE, "bytes=1024-")
            .body(Body::empty())
            .unwrap();
        let res = router.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            res.headers().get(header::CONTENT_RANGE).unwrap(),
            "bytes 1024-4095/4096"
        );
        assert_eq!(
            res.headers().get(header::CONTENT_LENGTH).unwrap(),
            "3072"
        );

        let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body_bytes.len(), 3072);
        assert_eq!(&body_bytes[..], &dummy_data[1024..4096]);
    }

    // 4. Suffix Range GET -> 206 Partial Content (bytes=-512)
    {
        let req = Request::builder()
            .uri(format!("/api/artifacts/{}/video", artifact_id.0))
            .method("GET")
            .header(header::RANGE, "bytes=-512")
            .body(Body::empty())
            .unwrap();
        let res = router.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            res.headers().get(header::CONTENT_RANGE).unwrap(),
            "bytes 3584-4095/4096"
        );
        assert_eq!(
            res.headers().get(header::CONTENT_LENGTH).unwrap(),
            "512"
        );

        let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body_bytes.len(), 512);
        assert_eq!(&body_bytes[..], &dummy_data[3584..4096]);
    }

    // 5. Unsatisfiable Range -> 416 Range Not Satisfiable
    {
        let req = Request::builder()
            .uri(format!("/api/artifacts/{}/video", artifact_id.0))
            .method("GET")
            .header(header::RANGE, "bytes=5000-6000")
            .body(Body::empty())
            .unwrap();
        let res = router.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            res.headers().get(header::CONTENT_RANGE).unwrap(),
            "bytes */4096"
        );
    }

    // 6. Non-existent artifact ID -> 400 Bad Request
    {
        let missing_id = Uuid::new_v4();
        let req = Request::builder()
            .uri(format!("/api/artifacts/{}/video", missing_id))
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let res = router.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    // 7. Path traversal attempt is rejected (invalid UUID / route mismatch)
    {
        let req = Request::builder()
            .uri("/api/artifacts/..%2F..%2Fwindows/video")
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let res = router.clone().oneshot(req).await.unwrap();
        assert!(res.status() == StatusCode::BAD_REQUEST || res.status() == StatusCode::NOT_FOUND);
    }

    // Clean up
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_actual_forensic_artifact_playback() {
    let mp4_path = std::path::Path::new("artifacts/cases/9e4c1240-8cfc-4e3a-b42f-2bcf0537e49a/recordings/REC-DAHUA-001/remux/503460a7-34b5-4bed-9896-f05837da1232.mp4");
    if !mp4_path.exists() {
        return;
    }

    let file_bytes = std::fs::read(mp4_path).unwrap();
    let total_size = file_bytes.len() as u64;
    assert_eq!(total_size, 229091);

    let pool = forensic_api::db::connection::init_pool("sqlite::memory:")
        .await
        .unwrap();

    let mut config = AppConfig::default();
    config.artifacts_dir = std::env::current_dir().unwrap().join("artifacts");
    let state = AppState::new_with_config(pool.clone(), config);
    let router = app_router(state.clone());

    let examiner = ExaminerId("Lead Examiner".to_string());
    let case_obj = forensic_api::db::repositories::cases::create_case(
        &pool,
        "Dahua Forensic Case",
        "Dahua playback test",
        &examiner,
    )
    .await
    .unwrap();

    let evidence_id = EvidenceId::new();
    let evidence = Evidence {
        id: evidence_id,
        case_id: case_obj.id,
        source_device: "Dahua DVR".to_string(),
        acquisition_time: Utc::now(),
        capacity: total_size,
        image_format: ImageFormat::Raw,
        responsible_examiner: examiner,
        acquisition_tool: Some("VidForge".to_string()),
        acquisition_tool_version: Some("0.1.0".to_string()),
        source_state: SourceState::ReadOnly,
        acquisition_id: None,
        path: mp4_path.to_string_lossy().to_string(),
        registered_at: Utc::now(),
        examiner_timezone: None,
    };
    forensic_api::db::repositories::evidence::create_evidence(&pool, &evidence)
        .await
        .unwrap();

    let artifact_uuid = Uuid::parse_str("503460a7-34b5-4bed-9896-f05837da1232").unwrap();
    let artifact_id = ArtifactId(artifact_uuid);
    let prov = Provenance::new(
        evidence_id,
        Hash::sha256(vec![0; 32]),
        vec![],
        "ffmpeg",
        "6.0",
        Hash::sha256(vec![0; 32]),
        ValidationState::pass("Stream-copy remux succeeded", "ffmpeg", "Remux").unwrap(),
    );
    let artifact = DerivedArtifact {
        id: artifact_id,
        kind: DerivedKind::Remux,
        provenance: prov,
        output_path: mp4_path.to_string_lossy().to_string(),
        description: "Actual Dahua remux MP4".to_string(),
        produced_at: chrono::Utc::now(),
    };

    forensic_api::db::repositories::artifacts::save_derived_artifact(
        &pool,
        &evidence_id,
        &artifact,
        "0395d6a18b135a97dd8963b781917f3a03946980be408f8d5ed5d6eb927f3392",
        total_size,
        1920,
    )
    .await
    .unwrap();

    // 1. Full GET
    {
        let req = Request::builder()
            .uri(format!("/api/artifacts/{}/video", artifact_id.0))
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let res = router.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get(header::CONTENT_TYPE).unwrap(),
            "video/mp4"
        );
        assert_eq!(
            res.headers().get(header::ACCEPT_RANGES).unwrap(),
            "bytes"
        );
        assert_eq!(
            res.headers().get(header::CONTENT_LENGTH).unwrap(),
            "229091"
        );
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.len(), 229091);
        assert_eq!(&body[..], &file_bytes[..]);
    }

    // 2. Initial probe Range: bytes=0-1023
    {
        let req = Request::builder()
            .uri(format!("/api/artifacts/{}/video", artifact_id.0))
            .method("GET")
            .header(header::RANGE, "bytes=0-1023")
            .body(Body::empty())
            .unwrap();
        let res = router.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            res.headers().get(header::CONTENT_TYPE).unwrap(),
            "video/mp4"
        );
        assert_eq!(
            res.headers().get(header::CONTENT_RANGE).unwrap(),
            "bytes 0-1023/229091"
        );
        assert_eq!(
            res.headers().get(header::CONTENT_LENGTH).unwrap(),
            "1024"
        );
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.len(), 1024);
        assert_eq!(&body[..], &file_bytes[0..1024]);
    }

    // 3. Tail probe (moov atom search) Range: bytes=-2048
    {
        let req = Request::builder()
            .uri(format!("/api/artifacts/{}/video", artifact_id.0))
            .method("GET")
            .header(header::RANGE, "bytes=-2048")
            .body(Body::empty())
            .unwrap();
        let res = router.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            res.headers().get(header::CONTENT_TYPE).unwrap(),
            "video/mp4"
        );
        let expected_range = format!("bytes {}-{}/{}", total_size - 2048, total_size - 1, total_size);
        assert_eq!(
            res.headers().get(header::CONTENT_RANGE).unwrap(),
            expected_range.as_str()
        );
        assert_eq!(
            res.headers().get(header::CONTENT_LENGTH).unwrap(),
            "2048"
        );
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.len(), 2048);
        assert_eq!(&body[..], &file_bytes[(total_size as usize - 2048)..]);
    }

    // 4. Mid-stream Seek Range: bytes=100000-150000
    {
        let req = Request::builder()
            .uri(format!("/api/artifacts/{}/video", artifact_id.0))
            .method("GET")
            .header(header::RANGE, "bytes=100000-150000")
            .body(Body::empty())
            .unwrap();
        let res = router.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            res.headers().get(header::CONTENT_RANGE).unwrap(),
            "bytes 100000-150000/229091"
        );
        assert_eq!(
            res.headers().get(header::CONTENT_LENGTH).unwrap(),
            "50001"
        );
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.len(), 50001);
        assert_eq!(&body[..], &file_bytes[100000..=150000]);
    }
}

