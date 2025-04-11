use crate::core::logger::RequestLogger;
use crate::core::models::{Baseline, RequestDebugInfo, ScanResult};
use anyhow::{Context, Result};
use chrono::Utc;
use reqwest::{Client, Method};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Scanner principal para detecção de vulnerabilidades SQL Injection em headers
pub struct SqliScanner {
    client: Client,
    baseline: Option<Baseline>,
    logger: Option<RequestLogger>,
}

impl SqliScanner {
    /// Cria uma nova instância do scanner
    pub fn new(timeout_ms: u64) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_millis(timeout_ms * 2)) // Dobro do timeout para dar margem
            .connect_timeout(Duration::from_millis(10000)) // 10s para conexão
            .danger_accept_invalid_certs(true) // Aceitar certificados inválidos
            .redirect(reqwest::redirect::Policy::limited(10)) // Seguir até 10 redirecionamentos
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            client,
            baseline: None,
            logger: None,
        })
    }

    /// Configura o logger para debug
    pub fn with_logger(&mut self, logger: RequestLogger) -> &mut Self {
        self.logger = Some(logger);
        self
    }

    /// Estabelece uma linha de base para comparação de respostas
    pub async fn establish_baseline(&mut self, url: &str) -> Result<&Baseline> {
        let baseline = self.get_baseline(url).await?;
        self.baseline = Some(baseline);
        Ok(self.baseline.as_ref().unwrap())
    }

    /// Realiza um único teste de injeção SQL
    pub async fn test_injection(
        &self,
        url: &str,
        header_or_field_name: &str,
        payload: &str,
        method: &str,
        csrf_token: Option<&str>,
        csrf_field: &str,
        csrf_cookie_field: Option<&str>,
        is_body_injection: bool,
    ) -> Result<ScanResult> {
        let method = Method::from_bytes(method.as_bytes()).context("Invalid HTTP method")?;

        let mut request = self.client.request(method.clone(), url);

        // Criar HashMap para armazenar headers para debug
        let mut debug_headers = HashMap::new();

        // Headers comuns
        let common_headers = [
            ("Host", url.split("://").nth(1).unwrap_or(url).split('/').next().unwrap_or("")),
            ("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"),
            ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
            ("Accept-Language", "pt-BR,pt;q=0.7"),
            ("Connection", "keep-alive"),
        ];

        for (name, value) in common_headers {
            request = request.header(name, value);
            debug_headers.insert(name.to_string(), value.to_string());
        }

        // Adicionar CSRF token no cookie se disponível
        if let Some(token) = csrf_token {
            // Usar o nome do campo CSRF no cookie, ou o nome padrão se não especificado
            let cookie_field = csrf_cookie_field.unwrap_or(csrf_field);
            let cookie_header = format!("{}={}", cookie_field, token);
            request = request.header("Cookie", &cookie_header);
            debug_headers.insert("Cookie".to_string(), cookie_header);
        }

        // Variável para armazenar o body para debug
        let mut debug_body = None;

        // Decidir entre injeção em header ou body
        if is_body_injection {
            // Injection no body
            if method == Method::POST {
                let content_type = "application/x-www-form-urlencoded";
                debug_headers.insert("Content-Type".to_string(), content_type.to_string());
                request = request.header("Content-Type", content_type);

                // No modo form-urlencoded, criamos o body apenas com o campo a ser injetado
                let mut form_data = String::new();

                // Formata o campo e o payload para URL encoded
                let encoded_payload = urlencoding::encode(payload)
                    .to_string()
                    .replace("%20", "+") // Alguns servidores esperam + em vez de %20 para espaços
                    .replace("%3B", ";") // Alguns servidores precisam de ; sem codificação
                    .replace("%2D%2D", "--"); // Comentários SQL sem codificação

                form_data.push_str(&format!("{}={}", header_or_field_name, encoded_payload));

                // Adiciona o CSRF token se disponível
                if let Some(token) = csrf_token {
                    if !form_data.is_empty() {
                        form_data.push('&');
                    }
                    form_data.push_str(&format!("{}={}", csrf_field, token));
                }

                debug_body = Some(form_data.clone());
                request = request.header("Content-Length", form_data.len().to_string());
                request = request.body(form_data);
            }
        } else {
            // Injeção no header (comportamento original)
            request = request.header(header_or_field_name, payload);
            debug_headers.insert(header_or_field_name.to_string(), payload.to_string());
        }

        // Log da requisição antes de enviar
        if let Some(logger) = &self.logger {
            let debug_info = RequestDebugInfo {
                url: url.to_string(),
                method: method.to_string(),
                headers: debug_headers,
                body: debug_body,
                timestamp: Utc::now(),
            };

            logger.log_request(&debug_info)?;
        }

        // Execute request and measure time
        let start_time = Instant::now();
        let response = request
            .send()
            .await
            .with_context(|| format!("Failed to send request to: {}", url))?;

        let status = response.status();
        let duration = start_time.elapsed();

        let body = response
            .text()
            .await
            .context("Failed to read response body")?;
        let body_size = body.len();

        // Compare with baseline
        let mut suspicious = false;
        let mut reason = None;

        if let Some(baseline) = &self.baseline {
            // Check for significant time difference (2x baseline)
            if duration.as_millis() > baseline.duration_ms * 2 {
                suspicious = true;
                reason = Some("Response time significantly higher than baseline".to_string());
            }

            // Check for significant size difference (>20%)
            let size_diff = (body_size as f64 - baseline.body_size as f64).abs();
            let size_diff_percent = (size_diff / baseline.body_size as f64) * 100.0;
            if size_diff_percent > 20.0 {
                suspicious = true;
                reason = Some("Response size significantly different from baseline".to_string());
            }

            // Check for status code changes
            if status != baseline.status {
                suspicious = true;
                reason = Some(format!(
                    "Status code changed from {} to {}",
                    baseline.status, status
                ));
            }
        }

        Ok(ScanResult {
            header: header_or_field_name.to_string(),
            payload: payload.to_string(),
            status: status.as_u16(),
            duration_ms: duration.as_millis(),
            body_size,
            suspicious,
            reason,
        })
    }

    /// Obtém a linha de base para comparação
    async fn get_baseline(&self, url: &str) -> Result<Baseline> {
        let start_time = Instant::now();
        let response = self
            .client
            .get(url)
            .send()
            .await
            .with_context(|| format!("Failed to establish baseline for: {}", url))?;

        let duration = start_time.elapsed();
        let status = response.status();
        let body = response
            .text()
            .await
            .context("Failed to read baseline response body")?;

        Ok(Baseline::new(status, duration.as_millis(), body.len()))
    }
}
