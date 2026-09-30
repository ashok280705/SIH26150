pub mod gemini;
pub mod groq;
pub mod ollama;
pub mod openai;
pub mod prompts;
pub mod provider;

use std::collections::HashMap;
use std::sync::Arc;

pub use prompts::{FORENSIC_COPILOT_SYSTEM_PROMPT, REPORT_SUMMARY_SYSTEM_PROMPT};
pub use provider::{
    AiChatRequest, AiChatResponse, AiProvider, ChatMessage, ReportSummaryRequest,
    ReportSummaryResponse,
};

pub struct AiGateway {
    providers: HashMap<String, Arc<dyn AiProvider>>,
    default_provider: String,
}

impl AiGateway {
    pub fn from_env() -> Self {
        let gemini_key = std::env::var("GEMINI_API_KEY").ok();
        let groq_key = std::env::var("GROQ_API_KEY").ok();
        let openai_key = std::env::var("OPENAI_API_KEY").ok();
        let ollama_base = std::env::var("OLLAMA_BASE_URL").ok();

        let mut providers: HashMap<String, Arc<dyn AiProvider>> = HashMap::new();
        providers.insert(
            "gemini".to_string(),
            Arc::new(gemini::GeminiProvider::new(gemini_key)),
        );
        providers.insert(
            "groq".to_string(),
            Arc::new(groq::GroqProvider::new(groq_key)),
        );
        providers.insert(
            "openai".to_string(),
            Arc::new(openai::OpenAiProvider::new(openai_key)),
        );
        providers.insert(
            "ollama".to_string(),
            Arc::new(ollama::OllamaProvider::new(ollama_base)),
        );

        let default_provider = std::env::var("AI_PROVIDER").unwrap_or_else(|_| "gemini".to_string());

        Self {
            providers,
            default_provider,
        }
    }

    pub fn get_provider(&self, name: Option<&str>) -> Result<Arc<dyn AiProvider>, String> {
        let key = name.unwrap_or(&self.default_provider).to_lowercase();
        self.providers
            .get(&key)
            .cloned()
            .ok_or_else(|| format!("Unknown AI provider '{key}'. Available: gemini, groq, openai, ollama"))
    }

    pub async fn chat(&self, req: AiChatRequest) -> Result<AiChatResponse, String> {
        let provider_name = req.provider.as_deref().unwrap_or(&self.default_provider);
        let provider = self.get_provider(Some(provider_name))?;

        let model = req.model.as_deref().unwrap_or(provider.default_model());
        let res = provider
            .chat(
                &req.messages,
                Some(model),
                req.api_key.as_deref(),
                req.temperature,
            )
            .await?;

        Ok(AiChatResponse {
            provider: provider.provider_name().to_string(),
            model: model.to_string(),
            message: res,
            is_ai_assisted: true,
            disclaimer: "AI-Assisted Forensic Analysis. Advisory interpretation derived from deterministic VidForge metadata. Examiner verification required.".to_string(),
        })
    }

    pub async fn generate_report_summary(
        &self,
        req: ReportSummaryRequest,
    ) -> Result<ReportSummaryResponse, String> {
        let provider_name = req.provider.as_deref().unwrap_or(&self.default_provider);
        let provider = self.get_provider(Some(provider_name))?;

        let model = req.model.as_deref().unwrap_or(provider.default_model());

        // Extract key structured forensic facts from the report to prevent context exhaustion
        let report_str = serde_json::to_string_pretty(&req.report)
            .map_err(|e| format!("Failed to serialize report: {e}"))?;

        let messages = vec![
            ChatMessage {
                role: "system".to_string(),
                content: REPORT_SUMMARY_SYSTEM_PROMPT.to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: format!(
                    "Generate a comprehensive, courtroom-ready Executive Forensic Summary from the following VidForge ForensicReport JSON:\n\n```json\n{}\n```",
                    report_str
                ),
            },
        ];

        let res = provider
            .chat(
                &messages,
                Some(model),
                req.api_key.as_deref(),
                Some(0.2),
            )
            .await?;

        Ok(ReportSummaryResponse {
            provider: provider.provider_name().to_string(),
            model: model.to_string(),
            raw_markdown: res,
            is_ai_assisted: true,
            disclaimer: "AI-Assisted Forensic Report. Advisory interpretation derived from deterministic VidForge metadata. Original evidence verified by cryptographic hashing.".to_string(),
        })
    }

    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({
            "status": "ready",
            "default_provider": self.default_provider,
            "supported_providers": ["gemini", "groq", "openai", "ollama"],
            "models": {
                "gemini": "gemini-3.8-flash",
                "groq": "qwen/qwen3.8-27b",
                "openai": "gpt-4o-mini",
                "ollama": "qwen2.5:0.5b"
            }
        })
    }
}
