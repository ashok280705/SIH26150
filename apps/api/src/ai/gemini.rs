use super::provider::{AiProvider, BoxFuture, ChatMessage};
use reqwest::Client;
use serde_json::json;

pub struct GeminiProvider {
    client: Client,
    default_key: Option<String>,
}

impl GeminiProvider {
    pub fn new(default_key: Option<String>) -> Self {
        Self {
            client: Client::builder().build().unwrap_or_default(),
            default_key,
        }
    }
}

impl AiProvider for GeminiProvider {
    fn provider_name(&self) -> &'static str {
        "gemini"
    }

    fn default_model(&self) -> &'static str {
        "gemini-3.8-flash"
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
                .ok_or_else(|| "Gemini API key is required. Provide GEMINI_API_KEY environment variable or enter it in settings.".to_string())?;

            let requested_model = model.unwrap_or(self.default_model());
            let candidate_models = [
                requested_model,
                "gemini-3.7-flash",
                "gemini-3.5-flash",
                "gemini-3.1-flash-lite",
                "gemini-2.5-flash-lite",
            ];

            // Separate system message if present
            let mut system_instruction = None;
            let mut contents = Vec::new();

            for msg in messages {
                if msg.role == "system" {
                    system_instruction = Some(json!({
                        "parts": [{ "text": msg.content }]
                    }));
                } else {
                    let role = if msg.role == "assistant" { "model" } else { "user" };
                    contents.push(json!({
                        "role": role,
                        "parts": [{ "text": msg.content }]
                    }));
                }
            }

            if contents.is_empty() {
                contents.push(json!({
                    "role": "user",
                    "parts": [{ "text": "Analyze the forensic context." }]
                }));
            }

            let mut body = json!({
                "contents": contents,
                "generationConfig": {
                    "temperature": temperature.unwrap_or(0.2)
                }
            });

            if let Some(sys) = system_instruction {
                body.as_object_mut().unwrap().insert("systemInstruction".to_string(), sys);
            }

            let mut last_error = String::new();

            for model_name in candidate_models {
                let url = format!(
                    "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
                    model_name, key
                );

                for attempt in 0..2 {
                    let resp = match self.client
                        .post(&url)
                        .json(&body)
                        .send()
                        .await {
                            Ok(r) => r,
                            Err(e) => {
                                last_error = format!("Gemini network request failed: {e}");
                                break;
                            }
                        };

                    if !resp.status().is_success() {
                        let status = resp.status();
                        let err_text = resp.text().await.unwrap_or_else(|_| "unknown error".into());
                        last_error = format!("Gemini API error on {model_name} ({status}): {err_text}");
                        if status.as_u16() == 503 || status.as_u16() == 429 {
                            if attempt == 0 {
                                tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                                continue;
                            }
                        }
                        break;
                    }

                    let res_json: serde_json::Value = resp
                        .json()
                        .await
                        .map_err(|e| format!("Failed to parse Gemini response: {e}"))?;

                    if let Some(text) = res_json["candidates"][0]["content"]["parts"][0]["text"].as_str() {
                        return Ok(text.to_string());
                    } else {
                        last_error = format!("Gemini returned empty candidate content on {model_name}");
                        break;
                    }
                }
            }

            Err(last_error)
        })
    }
}
