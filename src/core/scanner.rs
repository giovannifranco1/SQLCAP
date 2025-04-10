use crate::core::models::{Baseline, ScanResult};
use anyhow::{Context, Result};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Client, StatusCode,
};
use std::str::FromStr;
use std::time::{Duration, Instant};

/// Scanner principal para detecção de vulnerabilidades SQL Injection em headers
pub struct SqliScanner {
    client: Client,
    timeout: u64,
    baseline: Option<Baseline>,
}

impl SqliScanner {
    /// Cria uma nova instância do scanner
    pub fn new(timeout_ms: u64) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .context("Falha ao criar cliente HTTP")?;

        Ok(Self {
            client,
            timeout: timeout_ms,
            baseline: None,
        })
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
        header_name: &str,
        payload: &str,
    ) -> Result<ScanResult> {
        // Garante que a linha de base foi estabelecida
        let baseline = self
            .baseline
            .as_ref()
            .context("A linha de base deve ser estabelecida antes do teste")?;

        // Cria mapa de headers para a requisição
        let mut header_map = HeaderMap::new();
        let header_key = HeaderName::from_str(header_name)
            .with_context(|| format!("Nome de header inválido: {}", header_name))?;
        let header_value = HeaderValue::from_str(payload)
            .with_context(|| format!("Valor de header inválido: {}", payload))?;
        header_map.insert(header_key, header_value);

        // Envia a requisição GET com o header injetado
        let start_time = Instant::now();
        let response = self
            .client
            .get(url)
            .headers(header_map)
            .send()
            .await
            .with_context(|| format!("Falha ao enviar requisição para: {}", url))?;

        // Calcula o tempo de resposta
        let duration = start_time.elapsed();
        let duration_ms = duration.as_millis();

        let status = response.status();
        let body = response
            .text()
            .await
            .context("Falha ao ler corpo da resposta")?;
        let body_size = body.len();

        // Analisa a resposta para detecção de vulnerabilidades
        let (suspicious, reason) = self.analyze_response(
            status,
            duration_ms,
            body_size,
            &baseline.status,
            baseline.duration_ms,
            baseline.body_size,
        );

        Ok(ScanResult {
            header: header_name.to_string(),
            payload: payload.to_string(),
            status: status.as_u16(),
            duration_ms,
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
            .with_context(|| format!("Falha ao estabelecer linha de base para: {}", url))?;

        let duration = start_time.elapsed();
        let status = response.status();
        let body = response
            .text()
            .await
            .context("Falha ao ler corpo da resposta base")?;

        Ok(Baseline::new(status, duration.as_millis(), body.len()))
    }

    /// Analisa a resposta para detecção de vulnerabilidades
    fn analyze_response(
        &self,
        status: StatusCode,
        duration_ms: u128,
        body_size: usize,
        baseline_status: &StatusCode,
        baseline_duration: u128,
        baseline_size: usize,
    ) -> (bool, Option<String>) {
        let mut suspicious = false;
        let mut reason = None;

        // Verificação de time-based SQLi
        if duration_ms > self.timeout as u128 && duration_ms > (baseline_duration * 2) {
            suspicious = true;
            reason = Some(format!(
                "⏱️  Tempo de resposta anômalo: {}ms (base: {}ms)",
                duration_ms, baseline_duration
            ));
        }

        // Verificação de diferença no tamanho da resposta (boolean-based)
        let size_ratio = if baseline_size > 0 {
            body_size as f64 / baseline_size as f64
        } else {
            0.0
        };

        if body_size != baseline_size && (size_ratio > 1.5 || size_ratio < 0.5) {
            suspicious = true;
            if let Some(r) = reason {
                reason = Some(format!(
                    "{}, 📏 tamanho de resposta anômalo: {} bytes (base: {} bytes)",
                    r, body_size, baseline_size
                ));
            } else {
                reason = Some(format!(
                    "📏 Tamanho de resposta anômalo: {} bytes (base: {} bytes)",
                    body_size, baseline_size
                ));
            }
        }

        // Verificação de códigos de status diferentes
        if status != *baseline_status {
            suspicious = true;
            if let Some(r) = reason {
                reason = Some(format!(
                    "{}, 🔢 código de status diferente: {} (base: {})",
                    r, status, baseline_status
                ));
            } else {
                reason = Some(format!(
                    "🔢 Código de status diferente: {} (base: {})",
                    status, baseline_status
                ));
            }
        }

        (suspicious, reason)
    }
}
