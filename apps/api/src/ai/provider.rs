use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiChatRequest {
    pub messages: Vec<ChatMessage>,
    pub provider: Option<String>,
    pub api_key: Option<String>,
    pub model: Option<String>,
    pub temperature: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiChatResponse {
    pub provider: String,
    pub model: String,
    pub message: String,
    pub is_ai_assisted: bool,
    pub disclaimer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummaryRequest {
    pub report: serde_json::Value,
    pub provider: Option<String>,
    pub api_key: Option<String>,
    pub model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummaryResponse {
    pub provider: String,
    pub model: String,
    pub raw_markdown: String,
    pub is_ai_assisted: bool,
    pub disclaimer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionCategory {
    pub count: u32,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiVisionAnalysisRequest {
    /// Base64 encoded JPEG or PNG image data (raw or data URL)
    pub image_base64: String,
    pub evidence_id: Option<String>,
    pub recording_id: Option<String>,
    pub channel: Option<u32>,
    pub timestamp: Option<String>,
    pub frame_index: Option<u64>,
    pub provider: Option<String>,
    pub api_key: Option<String>,
    pub model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiVisionAnalysisResponse {
    pub evidence_id: Option<String>,
    pub recording_id: Option<String>,
    pub channel: Option<u32>,
    pub timestamp: String,
    pub frame_index: Option<u64>,
    pub frame_sha256: String,
    pub provider: String,
    pub model: String,
    pub persons: DetectionCategory,
    pub faces: DetectionCategory,
    pub vehicles: DetectionCategory,
    pub objects: Vec<String>,
    pub scene_description: String,
    pub visual_clarity: String,
    pub limitations: Vec<String>,
    pub is_ai_assisted: bool,
    pub disclaimer: String,
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait AiProvider: Send + Sync {
    fn provider_name(&self) -> &'static str;
    fn default_model(&self) -> &'static str;
    
    fn chat<'a>(
        &'a self,
        messages: &'a [ChatMessage],
        model: Option<&'a str>,
        api_key: Option<&'a str>,
        temperature: Option<f32>,
    ) -> BoxFuture<'a, Result<String, String>>;

    fn analyze_image<'a>(
        &'a self,
        _image_bytes: &'a [u8],
        _mime_type: &'a str,
        _prompt: &'a str,
        _model: Option<&'a str>,
        _api_key: Option<&'a str>,
    ) -> BoxFuture<'a, Result<String, String>> {
        Box::pin(async move {
            Err(format!("Provider {} does not support multimodal image analysis", self.provider_name()))
        })
    }
}

