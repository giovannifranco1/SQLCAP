use super::super::cli::ui::TerminalUI;
use crate::core::logger::RequestLogger;
use crate::core::models::{Baseline, ScanResult};
use crate::core::scanner::SqliScanner;
use crate::infra::file_reader::FileReader;
use anyhow::Result;
use reqwest::StatusCode;
use std::collections::HashMap;
use std::path::Path;
use tokio::time::Duration;

/// Service responsible for orchestrating the scanning process
pub struct ScanService {
    pub scanner: SqliScanner,
    url: String,
    headers: Vec<String>,
    fields: Vec<String>,
    payloads: Vec<String>,
    method: String,
    csrf_token: Option<String>,
    csrf_field: String,
    csrf_cookie_field: Option<String>,
    debug: bool,
    debug_file: String,
    body_injection: bool,
    injection_field: String,
    field_array: Vec<String>,
}

impl ScanService {
    /// Creates a new instance of the scanning service
    #[allow(clippy::too_many_arguments)]
    pub async fn new<P1, P2, P3, P4>(
        url: &str,
        header_file: Option<P1>,
        fields_file: Option<P2>,
        payload_file: P3,
        timeout_ms: u64,
        method: String,
        csrf_token: Option<String>,
        csrf_field: &str,
        csrf_cookie_field: Option<&str>,
        debug: bool,
        debug_file: P4,
        body_injection: bool,
        injection_field: &str,
    ) -> Result<Self>
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>,
        P3: AsRef<Path>,
        P4: AsRef<Path>,
    {
        // Create scanner
        let mut scanner = SqliScanner::new(timeout_ms)?;

        // Configurar logger se debug estiver habilitado
        if debug {
            let debug_path = debug_file.as_ref().to_string_lossy().to_string();
            let logger = RequestLogger::new(&debug_path, true);

            // Limpar arquivo de log antes de iniciar
            logger.clear_log()?;

            // Configurar scanner com logger
            scanner.with_logger(logger);

            // Log de inicialização
            TerminalUI::print_debug_enabled(&debug_path);
        }

        // Ler arquivo de payload
        let payloads = FileReader::read_lines_from_file(payload_file)?;

        // Ler arquivo de headers ou fields, dependendo do modo
        let (headers, fields) = if body_injection {
            // No modo body injection, lemos o arquivo de fields se fornecido
            let fields = if let Some(fields_path) = fields_file {
                FileReader::read_lines_from_file(fields_path)?
            } else {
                // Se não tiver arquivo de fields, usa apenas o campo de injeção especificado
                vec![injection_field.to_string()]
            };
            (Vec::new(), fields)
        } else {
            // No modo header injection, lemos o arquivo de headers
            let headers = if let Some(header_path) = header_file {
                FileReader::read_lines_from_file(header_path)?
            } else {
                return Err(anyhow::anyhow!(
                    "Header file is required for header injection mode"
                ));
            };
            (headers, Vec::new())
        };

        Ok(Self {
            scanner,
            url: url.to_string(),
            headers,
            fields,
            payloads,
            method,
            csrf_token,
            csrf_field: csrf_field.to_string(),
            csrf_cookie_field: csrf_cookie_field.map(|s| s.to_string()),
            debug,
            debug_file: debug_file.as_ref().to_string_lossy().to_string(),
            body_injection,
            injection_field: injection_field.to_string(),
            field_array: Vec::new(),
        })
    }

    /// Establishes baseline for comparison
    pub async fn establish_baseline(&mut self) -> Result<&Baseline> {
        self.scanner.establish_baseline(&self.url).await
    }

    /// Executes complete scan
    pub async fn run_scan(&mut self) -> Result<(Vec<ScanResult>, HashMap<String, Vec<u128>>)> {
        // Establish baseline if not done yet
        if self.scanner.establish_baseline(&self.url).await.is_err() {
            return Err(anyhow::anyhow!("Failed to establish baseline"));
        }

        let mut suspicious_results: Vec<ScanResult> = Vec::new();
        let mut header_results: HashMap<String, Vec<u128>> = HashMap::new();

        let total_tests = self.total_tests();
        let mut completed_tests = 0;

        // Define os itens a serem testados (headers ou campos do body)
        let test_items = if self.body_injection {
            // No modo de injeção no body, usamos os campos do arquivo fields.txt
            if self.fields.is_empty() {
                vec![self.injection_field.clone()]
            } else {
                self.fields.clone()
            }
        } else {
            // No modo tradicional, usamos os headers do arquivo
            self.headers.clone()
        };

        // Para cada item (header ou campo do body), testa todos os payloads
        for item_name in &test_items {
            let mut times_for_item: Vec<u128> = Vec::new();

            // Display start of tests for this item
            let display_name = if self.body_injection {
                format!("body field: {}", item_name)
            } else {
                format!("header: {}", item_name)
            };

            TerminalUI::print_header_test_start(&display_name, true);

            for payload in &self.payloads {
                completed_tests += 1;

                // Update progress bar
                TerminalUI::update_progress_bar(completed_tests, total_tests, item_name, payload);

                // Execute injection test
                match self
                    .scanner
                    .test_injection(
                        &self.url,
                        item_name,
                        payload,
                        &self.method,
                        self.csrf_token.as_deref(),
                        &self.csrf_field,
                        self.csrf_cookie_field.as_deref(),
                        self.body_injection,
                    )
                    .await
                {
                    Ok(result) => {
                        times_for_item.push(result.duration_ms);

                        // Display test result
                        TerminalUI::print_test_result(
                            &self.url,
                            item_name,
                            payload,
                            StatusCode::from_u16(result.status).unwrap_or(StatusCode::OK),
                            result.duration_ms as f64 / 1000.0,
                            result.body_size,
                            result.suspicious,
                            &result.reason,
                        );

                        // If response is suspicious, add to results
                        if result.suspicious {
                            suspicious_results.push(result);
                        }
                    }
                    Err(e) => {
                        eprintln!("Error testing injection: {}", e);
                    }
                }

                // Brief pause between requests to not overload the server
                tokio::time::sleep(Duration::from_millis(100)).await;
            }

            // Store time results for this header/field
            header_results.insert(item_name.clone(), times_for_item);
        }

        Ok((suspicious_results, header_results))
    }

    /// Returns total number of tests to be performed
    pub fn total_tests(&self) -> usize {
        if self.body_injection {
            // No modo body, testamos todos os campos do arquivo fields.txt
            if self.fields.is_empty() {
                self.payloads.len()
            } else {
                self.fields.len() * self.payloads.len()
            }
        } else {
            // No modo header, todos os headers são testados
            self.headers.len() * self.payloads.len()
        }
    }

    /// Returns references to headers and payloads
    pub fn get_test_data(&self) -> (Vec<String>, Vec<String>) {
        if self.body_injection {
            if self.fields.is_empty() {
                (vec![self.injection_field.clone()], self.payloads.clone())
            } else {
                (self.fields.clone(), self.payloads.clone())
            }
        } else {
            (self.headers.clone(), self.payloads.clone())
        }
    }
}
