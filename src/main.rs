use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use reqwest::Client;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

/// Scanner CLI para detecção de vulnerabilidades SQL Injection
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// URL endpoint para onde será enviada a requisição
    #[clap(short, long)]
    url: String,

    /// Caminho para o arquivo contendo o payload
    #[clap(short, long)]
    payload: PathBuf,

    /// Exibir informações detalhadas durante a execução
    #[clap(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.verbose {
        println!("{}", "Modo verbose ativado".cyan());
        println!("{} {}", "URL:".yellow(), args.url);
        println!(
            "{} {}",
            "Arquivo de payload:".yellow(),
            args.payload.display()
        );
    }

    // Lê o conteúdo do arquivo de forma assíncrona
    let payload = fs::read_to_string(&args.payload)
        .with_context(|| format!("Erro ao ler o arquivo: {}", args.payload.display()))?;

    if args.verbose {
        println!("{}", "Conteúdo do payload:".yellow());
        println!("{}", payload);
    }

    // Configura o cliente HTTP com timeout
    let client = Client::builder().timeout(Duration::from_secs(30)).build()?;

    println!("{}", "Enviando requisição...".green());

    // Envia a requisição POST
    let response = client
        .post(&args.url)
        .body(payload)
        .send()
        .await
        .with_context(|| format!("Falha ao enviar requisição para: {}", args.url))?;

    // Exibe o status da resposta
    let status = response.status();
    println!("{} {}", "Status:".yellow(), status);

    // Exibe o corpo da resposta
    let body = response.text().await?;
    println!("{}", "Corpo da resposta:".yellow());
    println!("{}", body);

    Ok(())
}
