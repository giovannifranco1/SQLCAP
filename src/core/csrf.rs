use crate::core::models::{CsrfCache, CsrfConfig};
use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use regex::Regex;
use reqwest::Client;
use scraper::{Html, Selector};
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct CsrfExtractor {
    client: Client,
    config: CsrfConfig,
    cache: Arc<Mutex<CsrfCache>>,
}

impl CsrfExtractor {
    pub fn new(config: CsrfConfig) -> Self {
        Self {
            client: Client::new(),
            config,
            cache: Arc::new(Mutex::new(CsrfCache {
                token: None,
                expiry: None,
            })),
        }
    }

    /// Extract CSRF token using configured strategy
    pub async fn get_token(&self) -> Result<String> {
        // Check cache first
        {
            let cache = self.cache.lock().await;
            if let Some(expiry) = cache.expiry {
                if Utc::now() < expiry {
                    if let Some(token) = &cache.token {
                        return Ok(token.clone());
                    }
                }
            }
        }

        // Fetch new token
        let token = self.extract_token().await?;

        // Update cache
        let mut cache = self.cache.lock().await;
        cache.token = Some(token.clone());
        if let Some(duration) = self.config.cache_duration {
            cache.expiry = Some(Utc::now() + Duration::seconds(duration as i64));
        }

        Ok(token)
    }

    async fn extract_token(&self) -> Result<String> {
        let response = self
            .client
            .get(&self.config.token_url)
            .headers((&self.config.headers).try_into()?)
            .send()
            .await
            .context("Failed to fetch CSRF token")?
            .text()
            .await
            .context("Failed to read response body")?;

        match self.config.extraction_method.as_str() {
            "regex" => self.extract_with_regex(&response),
            "html" => self.extract_from_html(&response),
            "json" => self.extract_from_json(&response),
            _ => Err(anyhow::anyhow!("Invalid extraction method")),
        }
    }

    fn extract_with_regex(&self, content: &str) -> Result<String> {
        let re = Regex::new(&self.config.token_selector).context("Invalid regex pattern")?;

        if let Some(captures) = re.captures(content) {
            if let Some(token) = captures.get(1) {
                return Ok(token.as_str().to_string());
            }
        }
        Err(anyhow::anyhow!("Token not found with regex"))
    }

    fn extract_from_html(&self, content: &str) -> Result<String> {
        let document = Html::parse_document(content);
        let selector = Selector::parse(&self.config.token_selector)
            .map_err(|e| anyhow::anyhow!("Invalid CSS selector: {}", e))?;

        if let Some(element) = document.select(&selector).next() {
            if let Some(token) = element.value().attr("value") {
                return Ok(token.to_string());
            }
        }
        Err(anyhow::anyhow!("Token not found in HTML"))
    }

    fn extract_from_json(&self, content: &str) -> Result<String> {
        let json: serde_json::Value =
            serde_json::from_str(content).context("Invalid JSON response")?;

        let pointer = self
            .config
            .json_pointer
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("JSON pointer not configured"))?;

        if let Some(token) = json.pointer(pointer) {
            if let Some(token_str) = token.as_str() {
                return Ok(token_str.to_string());
            }
        }
        Err(anyhow::anyhow!("Token not found in JSON"))
    }
}
