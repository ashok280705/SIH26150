use forensic_api::ai::{AiChatRequest, AiGateway, ChatMessage, ReportSummaryRequest};
use serde_json::json;

fn setup_env() {
    let candidates = [".env", "../.env", "../../.env"];
    for path in &candidates {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = trimmed.split_once('=') {
                    let key = k.trim();
                    let val = v.trim().trim_matches('"').trim_matches('\'');
                    if std::env::var(key).is_err() {
                        std::env::set_var(key, val);
                    }
                }
            }
            break;
        }
    }
}

#[tokio::test]
async fn test_ai_gateway_status() {
    setup_env();
    let gateway = AiGateway::from_env();
    let status = gateway.status();

    assert_eq!(status["status"], "ready");
    assert_eq!(status["supported_providers"].as_array().unwrap().len(), 4);
}

#[tokio::test]
async fn test_ai_gateway_chat_with_gemini() {
    setup_env();
    let gateway = AiGateway::from_env();

    // Use Gemini key from environment
    let req = AiChatRequest {
        messages: vec![
            ChatMessage {
                role: "system".to_string(),
                content: "You are VidForge's AI assistant. Answer in one brief sentence.".to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: "State the purpose of a digital video recorder forensic analysis tool.".to_string(),
            },
        ],
        provider: Some("gemini".to_string()),
        api_key: None,
        model: Some("gemini-3.8-flash".to_string()),
        temperature: Some(0.1),
    };

    let res = gateway.chat(req).await;
    assert!(res.is_ok(), "Gemini chat failed: {:?}", res.err());

    let response = res.unwrap();
    assert_eq!(response.provider, "gemini");
    assert!(!response.message.is_empty());
    assert!(response.is_ai_assisted);
    println!("Gemini Chat Response: {}", response.message);
}

#[tokio::test]
async fn test_ai_gateway_report_summary() {
    setup_env();
    let gateway = AiGateway::from_env();

    let sample_report = json!({
        "report_id": "REP-2026-TEST",
        "evidence_id": "EV-DAHUA-001",
        "evidence_summary": {
            "source_device": "Dahua DHFS 4.1 Sample Image",
            "capacity": 19638334,
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        },
        "detection_summary": {
            "oem": "Dahua (DHFS)",
            "confidence": 0.984,
            "margin": 0.65
        },
        "recordings": [
            { "recording_id": "REC-01", "channel": 1, "duration_sec": 120, "data_state": "Active" },
            { "recording_id": "REC-02", "channel": 1, "duration_sec": 85, "data_state": "Deleted" }
        ],
        "timeline_events": [
            { "channel": 1, "start": "2026-09-24T08:00:00Z", "end": "2026-09-24T08:02:00Z" }
        ]
    });

    let req = ReportSummaryRequest {
        report: sample_report,
        provider: Some("gemini".to_string()),
        api_key: None,
        model: Some("gemini-3.8-flash".to_string()),
    };

    let res = gateway.generate_report_summary(req).await;
    assert!(res.is_ok(), "Report summary failed: {:?}", res.err());

    let response = res.unwrap();
    assert_eq!(response.provider, "gemini");
    assert!(!response.raw_markdown.is_empty());
    assert!(response.raw_markdown.contains("Executive Summary") || response.raw_markdown.contains("Dahua"));
    println!("Executive Summary Sample:\n{}", response.raw_markdown);
}

#[tokio::test]
async fn test_ai_gateway_chat_with_groq() {
    setup_env();
    let gateway = AiGateway::from_env();

    let req = AiChatRequest {
        messages: vec![
            ChatMessage {
                role: "system".to_string(),
                content: "You are VidForge's AI assistant. Answer in one brief sentence.".to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: "Explain what DHFS is in forensic video recovery in one sentence.".to_string(),
            },
        ],
        provider: Some("groq".to_string()),
        api_key: None,
        model: Some("qwen/qwen3.8-27b".to_string()),
        temperature: Some(0.1),
    };

    let res = gateway.chat(req).await;
    assert!(res.is_ok(), "Groq chat failed: {:?}", res.err());

    let response = res.unwrap();
    assert_eq!(response.provider, "groq");
    assert!(!response.message.is_empty());
    println!("Groq Chat Response: {}", response.message);
}
