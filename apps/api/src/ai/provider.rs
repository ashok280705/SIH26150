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
}
