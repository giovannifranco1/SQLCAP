use crate::core::models::{Baseline, ScanResult};
use crate::core::scanner::SqliScanner;
use crate::infra::file_reader::FileReader;
use crate::shared::ui::TerminalUI;
use anyhow::{Context, Result};
use reqwest::StatusCode;
use std::collections::HashMap;
use std::path::Path;
use tokio::time::Duration;

/// Serviço responsável por orquestrar o processo de escaneamento
pub struct ScanService {
    pub scanner: SqliScanner,
    url: String,
    headers: Vec<String>,
    payloads: Vec<String>,
}

impl ScanService {
    /// Cria uma nova instância do serviço de escaneamento
    pub async fn new<P1, P2>(
        url: &str,
        header_file: P1,
        payload_file: P2,
        timeout_ms: u64,
    ) -> Result<Self>
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>,
    {
        // Cria o scanner
        let scanner = SqliScanner::new(timeout_ms)?;

        // Lê os arquivos de headers e payloads
        let headers = FileReader::read_lines_from_file(header_file)?;
        let payloads = FileReader::read_lines_from_file(payload_file)?;

        Ok(Self {
            scanner,
            url: url.to_string(),
            headers,
            payloads,
        })
    }

    /// Estabelece a linha de base para comparação
    pub async fn establish_baseline(&mut self) -> Result<&Baseline> {
        self.scanner.establish_baseline(&self.url).await
    }

    /// Executa o escaneamento completo
    pub async fn run_scan(&mut self) -> Result<(Vec<ScanResult>, HashMap<String, Vec<u128>>)> {
        // Estabelece a linha de base se ainda não foi feito
        if self.scanner.establish_baseline(&self.url).await.is_err() {
            return Err(anyhow::anyhow!("Falha ao estabelecer linha de base"));
        }

        let mut suspicious_results: Vec<ScanResult> = Vec::new();
        let mut header_results: HashMap<String, Vec<u128>> = HashMap::new();

        let total_tests = self.total_tests();
        let mut completed_tests = 0;

        // Para cada header, testa todos os payloads
        for header_name in &self.headers {
            let mut times_for_header: Vec<u128> = Vec::new();

            // Exibe início dos testes para este header
            TerminalUI::print_header_test_start(header_name, true);

            for payload in &self.payloads {
                completed_tests += 1;

                // Atualiza a barra de progresso
                TerminalUI::update_progress_bar(completed_tests, total_tests, header_name, payload);

                // Executa o teste de injeção
                match self
                    .scanner
                    .test_injection(&self.url, header_name, payload)
                    .await
                {
                    Ok(result) => {
                        times_for_header.push(result.duration_ms);

                        // Exibe o resultado do teste
                        TerminalUI::print_test_result(
                            &self.url,
                            header_name,
                            payload,
                            StatusCode::from_u16(result.status).unwrap_or(StatusCode::OK),
                            result.duration_ms as f64 / 1000.0,
                            result.body_size,
                            result.suspicious,
                            &result.reason,
                        );

                        // Se a resposta for suspeita, adiciona aos resultados
                        if result.suspicious {
                            suspicious_results.push(result);
                        }
                    }
                    Err(e) => {
                        eprintln!("Erro ao testar injeção: {}", e);
                    }
                }

                // Pausa breve entre requisições para não sobrecarregar o servidor
                tokio::time::sleep(Duration::from_millis(100)).await;
            }

            // Armazena resultados de tempo para este header
            header_results.insert(header_name.clone(), times_for_header);
        }

        Ok((suspicious_results, header_results))
    }

    /// Retorna o número total de testes que serão realizados
    pub fn total_tests(&self) -> usize {
        self.headers.len() * self.payloads.len()
    }

    /// Retorna referências aos headers e payloads
    pub fn get_test_data(&self) -> (&[String], &[String]) {
        (&self.headers, &self.payloads)
    }
}
