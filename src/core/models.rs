use clap::Parser;
use std::path::PathBuf;

/// Scanner CLI para detecção de vulnerabilidades SQL Injection baseada em headers
#[derive(Parser, Debug)]
#[clap(author, version, about)]
pub struct Args {
    /// URL endpoint para onde será enviada a requisição
    #[clap(short, long)]
    pub url: String,

    /// Caminho para o arquivo contendo os payloads (um por linha)
    #[clap(short, long)]
    pub payload: PathBuf,

    /// Caminho para o arquivo contendo os headers a serem testados (um por linha)
    #[clap(short = 'H', long)]
    pub header: PathBuf,

    /// Limiar de tempo (em ms) para considerar uma resposta suspeita (time-based)
    #[clap(short, long, default_value = "3000")]
    pub timeout: u64,

    /// Exibir informações detalhadas durante a execução
    #[clap(short, long)]
    pub verbose: bool,
}

/// Resultado de um teste de injeção SQL
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

/// Resultado de uma linha de base
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
