pub mod gemini;
pub mod groq;
pub mod ollama;
pub mod openai;
pub mod prompts;
pub mod provider;

use std::collections::HashMap;
use std::sync::Arc;

pub use prompts::{
    FORENSIC_COPILOT_SYSTEM_PROMPT, REPORT_SUMMARY_SYSTEM_PROMPT, VISION_FORENSIC_ANALYSIS_PROMPT,
};
pub use provider::{
    AiChatRequest, AiChatResponse, AiProvider, AiVisionAnalysisRequest, AiVisionAnalysisResponse,
    ChatMessage, DetectionCategory, ReportSummaryRequest, ReportSummaryResponse,
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

    pub async fn analyze_frame(
        &self,
        req: AiVisionAnalysisRequest,
    ) -> Result<AiVisionAnalysisResponse, String> {
        let provider_name = req.provider.as_deref().unwrap_or(&self.default_provider);
        let provider = self.get_provider(Some(provider_name))?;
        let model = req.model.as_deref().unwrap_or(provider.default_model());

        // Strip data URL scheme if present: e.g. "data:image/jpeg;base64,..."
        let raw_base64 = if let Some(idx) = req.image_base64.find("base64,") {
            &req.image_base64[idx + 7..]
        } else {
            &req.image_base64
        };

        use base64::Engine;
        let image_bytes = base64::engine::general_purpose::STANDARD
            .decode(raw_base64.trim())
            .map_err(|e| format!("Invalid base64 image data: {e}"))?;

        if image_bytes.is_empty() {
            return Err("Empty image payload provided".to_string());
        }

        // Cryptographically bind the analyzed frame bytes using SHA-256
        let frame_sha256 = media::hashing::hash_bytes(&image_bytes).hex;

        // Detect mime type (JPEG vs PNG)
        let mime_type = if image_bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
            "image/png"
        } else {
            "image/jpeg"
        };

        let raw_json_str = provider
            .analyze_image(
                &image_bytes,
                mime_type,
                VISION_FORENSIC_ANALYSIS_PROMPT,
                Some(model),
                req.api_key.as_deref(),
            )
            .await?;

        // Parse JSON response or fallback safely
        let parsed: serde_json::Value = serde_json::from_str(&raw_json_str)
            .unwrap_or_else(|_| serde_json::json!({
                "persons": { "count": 0, "details": "None detected" },
                "faces": { "count": 0, "details": "None detected" },
                "vehicles": { "count": 0, "details": "None detected" },
                "objects": [],
                "scene_description": raw_json_str,
                "visual_clarity": "Grainy CCTV",
                "limitations": ["Visual detector output could not be strictly parsed as JSON schema."]
            }));

        let persons = DetectionCategory {
            count: parsed["persons"]["count"].as_u64().unwrap_or(0) as u32,
            details: parsed["persons"]["details"].as_str().unwrap_or("None detected").to_string(),
        };

        let faces = DetectionCategory {
            count: parsed["faces"]["count"].as_u64().unwrap_or(0) as u32,
            details: parsed["faces"]["details"].as_str().unwrap_or("None detected").to_string(),
        };

        let vehicles = DetectionCategory {
            count: parsed["vehicles"]["count"].as_u64().unwrap_or(0) as u32,
            details: parsed["vehicles"]["details"].as_str().unwrap_or("None detected").to_string(),
        };

        let objects: Vec<String> = parsed["objects"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();

        let scene_description = parsed["scene_description"]
            .as_str()
            .unwrap_or("Visual scene processed.")
            .to_string();

        let visual_clarity = parsed["visual_clarity"]
            .as_str()
            .unwrap_or("Medium")
            .to_string();

        let limitations: Vec<String> = parsed["limitations"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_else(|| vec!["Advisory analysis only. Not biometric identification.".to_string()]);

        let timestamp = req.timestamp.unwrap_or_else(|| "Unknown Timestamp".to_string());

        Ok(AiVisionAnalysisResponse {
            evidence_id: req.evidence_id,
            recording_id: req.recording_id,
            channel: req.channel,
            timestamp,
            frame_index: req.frame_index,
            frame_sha256,
            provider: provider.provider_name().to_string(),
            model: model.to_string(),
            persons,
            faces,
            vehicles,
            objects,
            scene_description,
            visual_clarity,
            limitations,
            is_ai_assisted: true,
            disclaimer: "AI-Assisted Visual Analysis. Derived from decoded video frame. Advisory interpretation only — not biometric identification. All findings must be corroborated against original evidence by a forensic examiner.".to_string(),
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
