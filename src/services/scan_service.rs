use super::super::cli::ui::TerminalUI;
use crate::core::models::{Baseline, ScanResult};
use crate::core::scanner::SqliScanner;
use crate::infra::file_reader::FileReader;
use anyhow::{Context, Result};
use reqwest::StatusCode;
use std::collections::HashMap;
use std::path::Path;
use tokio::time::Duration;

/// Service responsible for orchestrating the scanning process
pub struct ScanService {
    pub scanner: SqliScanner,
    url: String,
    headers: Vec<String>,
    payloads: Vec<String>,
}

impl ScanService {
    /// Creates a new instance of the scanning service
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
        // Create scanner
        let scanner = SqliScanner::new(timeout_ms)?;

        // Read headers and payloads files
        let headers = FileReader::read_lines_from_file(header_file)?;
        let payloads = FileReader::read_lines_from_file(payload_file)?;

        Ok(Self {
            scanner,
            url: url.to_string(),
            headers,
            payloads,
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

        // For each header, test all payloads
        for header_name in &self.headers {
            let mut times_for_header: Vec<u128> = Vec::new();

            // Display start of tests for this header
            TerminalUI::print_header_test_start(header_name, true);

            for payload in &self.payloads {
                completed_tests += 1;

                // Update progress bar
                TerminalUI::update_progress_bar(completed_tests, total_tests, header_name, payload);

                // Execute injection test
                match self
                    .scanner
                    .test_injection(&self.url, header_name, payload)
                    .await
                {
                    Ok(result) => {
                        times_for_header.push(result.duration_ms);

                        // Display test result
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

            // Store time results for this header
            header_results.insert(header_name.clone(), times_for_header);
        }

        Ok((suspicious_results, header_results))
    }

    /// Returns total number of tests to be performed
    pub fn total_tests(&self) -> usize {
        self.headers.len() * self.payloads.len()
    }

    /// Returns references to headers and payloads
    pub fn get_test_data(&self) -> (&[String], &[String]) {
        (&self.headers, &self.payloads)
    }
}
