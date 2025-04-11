use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// SQL Injection vulnerability scanner CLI based on headers
#[derive(Parser, Debug)]
#[clap(author, version, about)]
pub struct Args {
    /// URL endpoint where the request will be sent
    #[clap(short, long)]
    pub url: String,

    /// Path to the file containing payloads (one per line)
    #[clap(short, long)]
    pub payload: PathBuf,

    /// Path to the file containing headers to be tested (one per line)
    #[clap(short = 'H', long, required_unless_present = "body_injection")]
    pub header: Option<PathBuf>,

    /// Path to the file containing body fields to be tested (one per line)
    #[clap(short = 'F', long, required_if_eq("body_injection", "true"))]
    pub fields: Option<PathBuf>,

    /// Time threshold (in ms) to consider a response suspicious (time-based)
    #[clap(short, long, default_value = "3000")]
    pub timeout: u64,

    /// Display detailed information during execution
    #[clap(short, long)]
    pub verbose: bool,

    /// HTTP method to use (GET or POST)
    #[clap(short = 'm', long, default_value = "GET")]
    pub method: String,

    /// CSRF token field name in forms/JSON (default: csrf_token)
    #[clap(long, default_value = "csrf_token")]
    pub csrf_field: String,

    /// CSRF token field name in the cookie (default: same as csrf_field)
    #[clap(long)]
    pub csrf_cookie_field: Option<String>,

    /// CSRF token value (if known)
    #[clap(long)]
    pub csrf_token: Option<String>,

    /// Enable request debugging and log to file
    #[clap(long)]
    pub debug: bool,

    /// Path to debug log file
    #[clap(long, default_value = "debug_requests_log.txt")]
    pub debug_file: PathBuf,

    /// Inject payloads in body fields instead of headers
    #[clap(long)]
    pub body_injection: bool,

    /// For body injection, specify the field name to inject into
    #[clap(long, default_value = "id")]
    pub injection_field: String,
}

/// Result of a SQL injection test
#[derive(Debug)]
pub struct ScanResult {
    pub header: String,
    pub payload: String,
    pub status: u16,
    pub duration_ms: u128,
    pub body_size: usize,
    pub suspicious: bool,
    pub reason: Option<String>,
}

/// Baseline result
#[derive(Debug, Clone)]
pub struct Baseline {
    pub status: reqwest::StatusCode,
    pub duration_ms: u128,
    pub body_size: usize,
}

impl Baseline {
    pub fn new(status: reqwest::StatusCode, duration_ms: u128, body_size: usize) -> Self {
        Self {
            status,
            duration_ms,
            body_size,
        }
    }
}

/// Configuration for CSRF token extraction
#[derive(Debug, Deserialize, Serialize)]
pub struct CsrfConfig {
    /// URL to fetch the CSRF token
    pub token_url: String,
    /// CSS selector or regex pattern to extract the token
    pub token_selector: String,
    /// Additional headers needed for token extraction
    pub headers: HashMap<String, String>,
    /// Extraction method (regex, html, json)
    pub extraction_method: String,
    /// JSON pointer for token extraction (if using json method)
    pub json_pointer: Option<String>,
    /// Cache duration in seconds
    pub cache_duration: Option<u64>,
}

/// Cache structure for CSRF tokens
#[derive(Debug)]
pub struct CsrfCache {
    pub token: Option<String>,
    pub expiry: Option<chrono::DateTime<chrono::Utc>>,
}

/// Request debug information for logging
#[derive(Debug)]
pub struct RequestDebugInfo {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}
