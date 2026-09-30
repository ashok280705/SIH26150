use super::provider::{AiProvider, BoxFuture, ChatMessage};
use reqwest::Client;
use serde_json::json;

pub struct OllamaProvider {
    client: Client,
    base_url: String,
}

impl OllamaProvider {
    pub fn new(base_url: Option<String>) -> Self {
        Self {
            client: Client::builder().build().unwrap_or_default(),
            base_url: base_url.unwrap_or_else(|| "http://127.0.0.1:11434".to_string()),
        }
    }
}

impl AiProvider for OllamaProvider {
    fn provider_name(&self) -> &'static str {
        "ollama"
    }

    fn default_model(&self) -> &'static str {
        "qwen2.5:0.5b"
    }

    fn chat<'a>(
        &'a self,
        messages: &'a [ChatMessage],
        model: Option<&'a str>,
        _api_key: Option<&'a str>,
        temperature: Option<f32>,
    ) -> BoxFuture<'a, Result<String, String>> {
        Box::pin(async move {
            let model_name = model.unwrap_or(self.default_model());
            let url = format!("{}/api/chat", self.base_url.trim_end_matches('/'));

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
                "stream": false,
                "options": {
                    "temperature": temperature.unwrap_or(0.2)
                }
            });

            let resp = self.client
                .post(&url)
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("Ollama local service unreachable: {e}"))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let err_text = resp.text().await.unwrap_or_else(|_| "unknown error".into());
                return Err(format!("Ollama error ({status}): {err_text}"));
            }

            let res_json: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| format!("Failed to parse Ollama response: {e}"))?;

            let text = res_json["message"]["content"]
                .as_str()
                .ok_or_else(|| "Ollama returned empty message content".to_string())?;

            Ok(text.to_string())
        })
    }
}
