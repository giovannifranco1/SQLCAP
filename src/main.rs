use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Client,
};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, Instant};

/// Scanner CLI para detecção de vulnerabilidades SQL Injection baseada em headers
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// URL endpoint para onde será enviada a requisição
    #[clap(short, long)]
    url: String,

    /// Caminho para o arquivo contendo os payloads (um por linha)
    #[clap(short, long)]
    payload: PathBuf,

    /// Caminho para o arquivo contendo os headers a serem testados (um por linha)
    #[clap(short = 'H', long)]
    header: PathBuf,

    /// Limiar de tempo (em ms) para considerar uma resposta suspeita (time-based)
    #[clap(short, long, default_value = "3000")]
    timeout: u64,

    /// Exibir informações detalhadas durante a execução
    #[clap(short, long)]
    verbose: bool,
}

#[derive(Debug)]
struct ScanResult {
    header: String,
    payload: String,
    status: u16,
    duration_ms: u128,
    body_size: usize,
    suspicious: bool,
    reason: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.verbose {
        println!("{}", "Modo verbose ativado".cyan());
        println!("{} {}", "URL:".yellow(), args.url);
        println!(
            "{} {}",
            "Arquivo de payloads:".yellow(),
            args.payload.display()
        );
        println!(
            "{} {}",
            "Arquivo de headers:".yellow(),
            args.header.display()
        );
        println!(
            "{} {} ms",
            "Limiar de tempo para detecção:".yellow(),
            args.timeout
        );
    }

    // Lê o conteúdo dos arquivos
    let payloads = fs::read_to_string(&args.payload).with_context(|| {
        format!(
            "Erro ao ler o arquivo de payloads: {}",
            args.payload.display()
        )
    })?;

    let headers = fs::read_to_string(&args.header).with_context(|| {
        format!(
            "Erro ao ler o arquivo de headers: {}",
            args.header.display()
        )
    })?;

    // Separa os payloads e headers por linha
    let payloads: Vec<&str> = payloads
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    let headers: Vec<&str> = headers
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();

    if args.verbose {
        println!(
            "{} {} headers para testar",
            "Encontrados:".yellow(),
            headers.len()
        );
        println!(
            "{} {} payloads para injetar",
            "Encontrados:".yellow(),
            payloads.len()
        );
    }

    // Configura o cliente HTTP com timeout generoso para detectar time-based SQLi
    let client = Client::builder().timeout(Duration::from_secs(60)).build()?;

    println!(
        "{}",
        "Iniciando testes de SQL Injection via headers...".green()
    );
    println!(
        "{} {}",
        "Total de requisições a serem enviadas:".yellow(),
        headers.len() * payloads.len()
    );

    // Estabelece uma linha de base com uma requisição sem injeção
    println!(
        "{}",
        "Estabelecendo linha de base para comparação...".blue()
    );
    let baseline = get_baseline(&client, &args.url).await?;

    println!(
        "{} Status: {}, Tempo: {:.2?}, Tamanho: {} bytes",
        "Linha de base:".blue(),
        baseline.0,
        baseline.1,
        baseline.2
    );

    let mut suspicious_results: Vec<ScanResult> = Vec::new();
    let mut header_results: HashMap<String, Vec<u128>> = HashMap::new();

    // Armazena o total de testes para estatísticas finais
    let total_tests = headers.len() * payloads.len();

    // Para cada header, testa todos os payloads
    for header_name in &headers {
        let header_name = header_name.trim();
        let mut times_for_header: Vec<u128> = Vec::new();

        for payload in &payloads {
            let payload = payload.trim();

            if args.verbose {
                println!(
                    "\n{} '{}': '{}'",
                    "Testando header".blue(),
                    header_name,
                    payload
                );
            }

            // Cria mapa de headers para a requisição
            let mut header_map = HeaderMap::new();
            let header_key = match HeaderName::from_str(header_name) {
                Ok(key) => key,
                Err(_) => {
                    eprintln!("{} Nome de header inválido: {}", "ERRO:".red(), header_name);
                    continue;
                }
            };
            let header_value = match HeaderValue::from_str(payload) {
                Ok(value) => value,
                Err(_) => {
                    eprintln!("{} Valor de header inválido: {}", "ERRO:".red(), payload);
                    continue;
                }
            };
            header_map.insert(header_key, header_value);

            // Envia a requisição GET com o header injetado
            let start_time = Instant::now();
            let response = match client.get(&args.url).headers(header_map).send().await {
                Ok(resp) => resp,
                Err(e) => {
                    eprintln!("{} Falha ao enviar requisição: {}", "ERRO:".red(), e);
                    continue;
                }
            };

            // Calcula o tempo de resposta
            let duration = start_time.elapsed();
            let duration_ms = duration.as_millis();
            times_for_header.push(duration_ms);

            let status = response.status();
            let body = match response.text().await {
                Ok(text) => text,
                Err(e) => {
                    eprintln!("{} Falha ao ler corpo da resposta: {}", "ERRO:".red(), e);
                    continue;
                }
            };

            let body_size = body.len();

            // Verifica se a resposta é suspeita (time-based)
            let mut suspicious = false;
            let mut reason = None;

            // Verificação de time-based SQLi
            if duration_ms > args.timeout as u128 && duration_ms > (baseline.1 * 2) {
                suspicious = true;
                reason = Some(format!(
                    "Tempo de resposta anômalo: {}ms (base: {}ms)",
                    duration_ms, baseline.1
                ));
            }

            // Verificação de diferença no tamanho da resposta (boolean-based)
            let size_ratio = if baseline.2 > 0 {
                body_size as f64 / baseline.2 as f64
            } else {
                0.0
            };

            if body_size != baseline.2 && (size_ratio > 1.5 || size_ratio < 0.5) {
                suspicious = true;
                if let Some(r) = reason {
                    reason = Some(format!(
                        "{}, tamanho de resposta anômalo: {} bytes (base: {} bytes)",
                        r, body_size, baseline.2
                    ));
                } else {
                    reason = Some(format!(
                        "Tamanho de resposta anômalo: {} bytes (base: {} bytes)",
                        body_size, baseline.2
                    ));
                }
            }

            // Verificação de códigos de status diferentes
            if status != baseline.0 {
                suspicious = true;
                if let Some(r) = reason {
                    reason = Some(format!(
                        "{}, código de status diferente: {} (base: {})",
                        r, status, baseline.0
                    ));
                } else {
                    reason = Some(format!(
                        "Código de status diferente: {} (base: {})",
                        status, baseline.0
                    ));
                }
            }

            // Status emoji
            let status_emoji = if suspicious { "🔴" } else { "🟢" };

            println!(
                "{} Header: '{}', Payload: '{}', Status: {}, Tempo: {:.2?}, Tamanho: {} bytes{}",
                status_emoji,
                header_name,
                payload,
                status,
                duration,
                body_size,
                if suspicious {
                    format!(" - {}", reason.as_ref().unwrap().red())
                } else {
                    String::from("")
                }
            );

            if suspicious {
                suspicious_results.push(ScanResult {
                    header: header_name.to_string(),
                    payload: payload.to_string(),
                    status: status.as_u16(),
                    duration_ms,
                    body_size,
                    suspicious,
                    reason,
                });
            }

            // Pausa breve entre requisições para não sobrecarregar o servidor
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Armazena resultados de tempo para este header
        header_results.insert(header_name.to_string(), times_for_header);
    }

    // Resumo dos resultados
    println!("\n{}", "Resumo dos resultados".green().bold());
    println!("{} {}", "Total de testes realizados:".yellow(), total_tests);
    println!(
        "{} {}",
        "Pontos suspeitos encontrados:".yellow(),
        suspicious_results.len()
    );

    if !suspicious_results.is_empty() {
        println!("\n{}", "Detalhes dos pontos suspeitos:".red().bold());
        for (i, result) in suspicious_results.iter().enumerate() {
            println!(
                "{}. Header: '{}', Payload: '{}'",
                i + 1,
                result.header,
                result.payload
            );
            println!(
                "   Status: {}, Tempo: {}ms, Tamanho: {} bytes",
                result.status, result.duration_ms, result.body_size
            );
            if let Some(reason) = &result.reason {
                println!("   Motivo: {}", reason.red());
            }
            println!();
        }

        println!(
            "{}",
            "Possíveis vulnerabilidades encontradas! Analise os resultados para confirmação."
                .red()
                .bold()
        );
    } else {
        println!(
            "{}",
            "Nenhuma vulnerabilidade SQL Injection óbvia detectada.".green()
        );
    }

    Ok(())
}

async fn get_baseline(client: &Client, url: &str) -> Result<(reqwest::StatusCode, u128, usize)> {
    let start_time = Instant::now();
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("Falha ao estabelecer linha de base para: {}", url))?;

    let duration = start_time.elapsed();
    let status = response.status();
    let body = response.text().await?;

    Ok((status, duration.as_millis(), body.len()))
}
