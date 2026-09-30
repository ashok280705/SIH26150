use super::provider::{AiProvider, BoxFuture, ChatMessage};
use reqwest::Client;
use serde_json::json;

pub struct GroqProvider {
    client: Client,
    default_key: Option<String>,
}

impl GroqProvider {
    pub fn new(default_key: Option<String>) -> Self {
        Self {
            client: Client::builder().build().unwrap_or_default(),
            default_key,
        }
    }
}

impl AiProvider for GroqProvider {
    fn provider_name(&self) -> &'static str {
        "groq"
    }

    fn default_model(&self) -> &'static str {
        "qwen/qwen3.8-27b"
    }

    fn chat<'a>(
        &'a self,
        messages: &'a [ChatMessage],
        model: Option<&'a str>,
        api_key: Option<&'a str>,
        temperature: Option<f32>,
    ) -> BoxFuture<'a, Result<String, String>> {
        Box::pin(async move {
            let key = api_key
                .or(self.default_key.as_deref())
                .ok_or_else(|| "Groq API key is required. Provide GROQ_API_KEY environment variable or enter it in settings.".to_string())?;

            let model_name = model.unwrap_or(self.default_model());
            let url = "https://api.groq.com/openai/v1/chat/completions";

            let api_messages: Vec<serde_json::Value> = messages
                .iter()
                .map(|m| {
                    json!({
                        "role": m.role,
                        "content": m.content
                    })
                })
                .collect();

            let body = json!({
                "model": model_name,
                "messages": api_messages,
                "temperature": temperature.unwrap_or(0.2)
            });

            let resp = self.client
                .post(url)
                .header("Authorization", format!("Bearer {}", key))
                .header("User-Agent", "VidForge-Forensic-Workstation/1.0")
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("Groq network request failed: {e}"))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let err_text = resp.text().await.unwrap_or_else(|_| "unknown error".into());
                return Err(format!("Groq API error ({status}): {err_text}"));
            }

            let res_json: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| format!("Failed to parse Groq response: {e}"))?;

            let text = res_json["choices"][0]["message"]["content"]
                .as_str()
                .ok_or_else(|| "Groq returned empty choices content".to_string())?;

            Ok(text.to_string())
        })
    }
}
