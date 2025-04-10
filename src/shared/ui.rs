use crate::core::models::{Baseline, ScanResult};
use chrono::Local;
use colored::Colorize;
use reqwest::StatusCode;
use std::io::Write;

/// Módulo responsável pela interface do usuário no terminal
pub struct TerminalUI;

impl TerminalUI {
    /// Exibe o banner inicial do programa
    pub fn print_banner() {
        println!();
        println!(
            "{}",
            r#"
  ██████   █████   ██▓     ▄████▄   ▄▄▄       ██▓███  
▒██    ▒ ▒██▓  ██▒▓██▒    ▒██▀ ▀█  ▒████▄    ▓██░  ██▒
░ ▓██▄   ▒██▒  ██░▒██░    ▒▓█    ▄ ▒██  ▀█▄  ▓██░ ██▓▒
  ▒   ██▒░██  █▀ ░▒██░    ▒▓▓▄ ▄██▒░██▄▄▄▄██ ▒██▄█▓▒ ▒
▒██████▒▒░▒███▒█▄ ░██████▒▒ ▓███▀ ░ ▓█   ▓██▒▒██▒ ░  ░
▒ ▒▓▒ ▒ ░░░ ▒▒░ ▒ ░ ▒░▓  ░░ ░▒ ▒  ░ ▒▒   ▓▒█░▒▓▒░ ░  ░
░ ░▒  ░ ░ ░ ▒░  ░ ░ ░ ▒  ░  ░  ▒     ▒   ▒▒ ░░▒ ░     
░  ░  ░     ░   ░   ░ ░   ░          ░   ▒   ░░       
      ░      ░        ░  ░░ ░            ░  ░         
                          ░                                                
"#
            .bright_yellow()
        );

        println!(
            "{}",
            "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓".bright_blue()
        );
        println!(
            "{}",
            "┃                                                                  ┃".bright_blue()
        );
        println!(
            "{} {} {}",
            "┃".bright_blue(),
            "               🔐 SQL INJECTION SCANNER TOOL 🔐                 "
                .bright_green()
                .bold(),
            "┃".bright_blue()
        );
        println!(
            "{} {} {}",
            "┃".bright_blue(),
            "                    [ HEADER EDITION ]                        ".bright_yellow(),
            "┃".bright_blue()
        );
        println!(
            "{}",
            "┃                                                                  ┃".bright_blue()
        );
        println!(
            "{}",
            "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛".bright_blue()
        );
        println!();
    }

    /// Exibe um cabeçalho de seção
    pub fn print_section_header(text: &str) {
        println!();
        println!("{} {}", "━━━━".bright_cyan(), text.bold().bright_white());
    }

    /// Cria uma barra de progresso visual
    pub fn create_progress_bar(progress: u32) -> String {
        let bar_length = 25;
        let completed = (progress as f32 / 100.0 * bar_length as f32) as usize;

        let mut bar = String::new();
        for i in 0..bar_length {
            if i < completed {
                bar.push('█');
            } else {
                bar.push('░');
            }
        }

        bar
    }

    /// Exibe informações de configuração
    pub fn print_config(
        url: &str,
        payload_file: &str,
        header_file: &str,
        timeout: u64,
        verbose: bool,
    ) {
        Self::print_section_header("📋 CONFIGURAÇÃO");
        println!("{} {}", "🌐 URL:".bright_yellow(), url.bright_white());
        println!(
            "{} {}",
            "📄 Payloads:".bright_yellow(),
            payload_file.bright_white()
        );
        println!(
            "{} {}",
            "🔤 Headers:".bright_yellow(),
            header_file.bright_white()
        );
        println!(
            "{} {} ms",
            "⏱️  Timeout:".bright_yellow(),
            timeout.to_string().bright_white()
        );

        if verbose {
            println!(
                "{} {}",
                "🔊 Modo verbose:".bright_yellow(),
                "Ativado".bright_green()
            );
        } else {
            println!(
                "{} {}",
                "🔊 Modo verbose:".bright_yellow(),
                "Desativado".bright_red()
            );
        }
    }

    /// Exibe informações de preparação
    pub fn print_preparation_info(
        headers_count: usize,
        payloads_count: usize,
        verbose: bool,
        headers: &[String],
        payloads: &[String],
    ) {
        Self::print_section_header("🔍 PREPARAÇÃO");
        println!(
            "{} {}",
            "📊 Headers para testar:".bright_yellow(),
            headers_count.to_string().bright_white()
        );
        println!(
            "{} {}",
            "🧪 Payloads para injetar:".bright_yellow(),
            payloads_count.to_string().bright_white()
        );
        println!(
            "{} {}",
            "🔢 Total de testes a realizar:".bright_yellow(),
            (headers_count * payloads_count).to_string().bright_white()
        );

        if verbose {
            Self::print_section_header("📝 DETALHES DOS DADOS");

            println!("{}", "🔤 Headers a testar:".bright_yellow());
            for (i, header) in headers.iter().enumerate() {
                println!(
                    "   {}. {}",
                    (i + 1).to_string().bright_cyan(),
                    header.bright_white()
                );
                if i >= 9 && headers.len() > 12 {
                    println!("   ... mais {} headers", headers.len() - 10);
                    break;
                }
            }
        }

        Self::print_section_header("🚀 EXECUÇÃO");
        println!(
            "{}",
            "Iniciando scan de vulnerabilidades SQL Injection via headers..."
                .bright_green()
                .bold()
        );
    }

    /// Mostra mensagem de inicialização do teste para um header
    pub fn print_header_test_start(header_name: &str, verbose: bool) {
        println!();
        println!(
            "{} '{}'",
            "🔍 Testando header:".bright_cyan().bold(),
            header_name.bright_white()
        );

        if verbose {
            println!();
            println!(
                "{}",
                "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓".bright_blue()
            );
            println!(
                "{} {} {}",
                "┃".bright_blue(),
                " [*] Iniciando testes de injeção...".bright_green(),
                "┃".bright_blue()
            );
            println!(
                "{} {} {}",
                "┃".bright_blue(),
                " [*] Analisando vulnerabilidades...".bright_green(),
                "┃".bright_blue()
            );
            println!(
                "{} {} {}",
                "┃".bright_blue(),
                " [+] Scanner em execução...".bright_green(),
                "┃".bright_blue()
            );
            println!(
                "{}",
                "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛".bright_blue()
            );
        }
    }

    /// Atualiza a barra de progresso
    pub fn update_progress_bar(
        completed_tests: usize,
        total_tests: usize,
        header_name: &str,
        payload: &str,
    ) {
        let progress = (completed_tests as f64 / total_tests as f64 * 100.0) as u32;
        let progress_bar = Self::create_progress_bar(progress);

        // Limpa a linha anterior antes de imprimir a nova atualização
        print!("\r");
        print!(
            "{}",
            "                                                                                "
                .black()
        );
        print!("\r");

        // Imprime a barra de progresso estilo hacking
        print!(
            "{} {} {} {}",
            "[*]".bright_green(),
            format!("Progresso: [{}] {}%", progress_bar, progress).bright_cyan(),
            "| Target:".bright_red(),
            format!("{}:{}", header_name, payload).bright_white()
        );

        // Força a saída a ser impressa imediatamente
        std::io::stdout().flush().ok();
    }

    /// Exibe o resultado de um teste de injeção
    pub fn print_test_result(
        url: &str,
        header_name: &str,
        payload: &str,
        status: StatusCode,
        duration_secs: f64,
        body_size: usize,
        suspicious: bool,
        reason: &Option<String>,
    ) {
        // Formata o status com cor
        let status_text = if status.is_success() {
            status.to_string().bright_green()
        } else if status.is_client_error() {
            status.to_string().bright_yellow()
        } else if status.is_server_error() {
            status.to_string().bright_red()
        } else {
            status.to_string().bright_white()
        };

        // Formato compacto para cada teste (estilo hacking)
        println!("");
        println!(
            "{}",
            "┌───────────────────[ SCAN RESULT ]───────────────────┐".bright_blue()
        );
        println!(
            "{} {}",
            "│ 🎯 Target URL:".bright_yellow(),
            format!("{}", url).bright_white()
        );
        println!(
            "{} {}",
            "│ ⚡ Injection Vector:".bright_yellow(),
            format!("{}: {}", header_name, payload).bright_white()
        );
        println!("{} {}", "│ 🌐 Status code:".bright_blue(), status_text);
        println!(
            "{} {}",
            "│ ⏱️  Response Time:".bright_yellow(),
            format!("{:.5}s", duration_secs).bright_white()
        );
        println!(
            "{} {}",
            "│ 📊 Response Size:".bright_yellow(),
            format!("{} bytes", body_size).bright_white()
        );

        let status_icon = if suspicious { "⛔" } else { "✅" };
        let status_text = if suspicious {
            "VULNERABLE".bright_red().bold()
        } else {
            "NOT VULNERABLE".bright_green()
        };
        println!(
            "{} {} {}",
            "│ 🔐 Result:".bright_cyan(),
            status_icon,
            status_text
        );

        if suspicious && reason.is_some() {
            println!(
                "{} {}",
                "│ ⚠️ Reason:".bright_red(),
                reason.as_ref().unwrap().bright_red().bold()
            );
        }

        println!(
            "{}",
            "└────────────────────────────────────────────────────┘".bright_blue()
        );
    }

    /// Exibe a linha de base estabelecida
    pub fn print_baseline(baseline: &Baseline) {
        println!(
            "{}",
            "⏳ Estabelecendo linha de base para comparação...".bright_blue()
        );
        println!(
            "{} Status: {}, Tempo: {:.2?}, Tamanho: {} bytes",
            "📊 Linha de base:".bright_blue(),
            baseline.status.to_string().bright_white(),
            baseline.duration_ms,
            baseline.body_size.to_string().bright_white()
        );
    }

    /// Exibe o resumo final do scan
    pub fn print_summary(url: &str, total_tests: usize, suspicious_results: &[ScanResult]) {
        Self::print_section_header("📊 RESULTADOS");

        // Box de resumo estilo hacking
        println!(
            "{}",
            "┌────────────────[ SCAN SUMMARY ]─────────────────┐".bright_green()
        );
        println!("{} {}", "│ 🎯 Target:".bright_yellow(), url.bright_white());
        println!(
            "{} {}",
            "│ 🔢 Total requests:".bright_yellow(),
            total_tests.to_string().bright_white()
        );

        let alerts_count = suspicious_results.len();
        let alerts_text = if alerts_count > 0 {
            alerts_count.to_string().bright_red().bold()
        } else {
            alerts_count.to_string().bright_green()
        };

        println!(
            "{} {}",
            "│ ⚠️  Vulnerabilities found:".bright_yellow(),
            alerts_text
        );

        // Timestamp
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        println!(
            "{} {}",
            "│ 🕒 Scan completed at:".bright_yellow(),
            timestamp.bright_white()
        );

        println!(
            "{}",
            "└────────────────────────────────────────────────┘".bright_green()
        );

        // Detalhes das vulnerabilidades encontradas
        if !suspicious_results.is_empty() {
            Self::print_vulnerability_details(suspicious_results);
        } else {
            println!(
                "\n{}",
                "✅ Nenhuma vulnerabilidade SQL Injection óbvia detectada."
                    .bright_green()
                    .bold()
            );
        }
    }

    /// Exibe os detalhes das vulnerabilidades encontradas
    pub fn print_vulnerability_details(results: &[ScanResult]) {
        Self::print_section_header("🚨 DETALHES DAS VULNERABILIDADES");

        println!(
            "{}",
            "┌──────────────[ VULNERABILITY DETAILS ]─────────────┐".bright_red()
        );

        for (i, result) in results.iter().enumerate() {
            println!(
                "{} {}",
                "│ 🚨 Vulnerability #".bright_red(),
                (i + 1).to_string().bright_white().bold()
            );
            println!(
                "│ {} '{}'",
                "🔑 Header:".bright_yellow(),
                result.header.bright_white().bold()
            );
            println!(
                "│ {} '{}'",
                "💥 Payload:".bright_yellow(),
                result.payload.bright_red().bold()
            );

            // Status com cor
            let status_text = if result.status >= 200 && result.status < 300 {
                result.status.to_string().bright_green()
            } else if result.status >= 400 && result.status < 500 {
                result.status.to_string().bright_yellow()
            } else if result.status >= 500 {
                result.status.to_string().bright_red()
            } else {
                result.status.to_string().bright_white()
            };

            println!(
                "│ {} {}, {} {}ms, {} {} bytes",
                "📡 Status:".bright_yellow(),
                status_text,
                "⏱️  Tempo:".bright_yellow(),
                result.duration_ms.to_string().bright_white(),
                "📏 Tamanho:".bright_yellow(),
                result.body_size.to_string().bright_white()
            );

            if let Some(reason) = &result.reason {
                println!(
                    "│ {} {}",
                    "⚠️  Motivo:".bright_yellow(),
                    reason.bright_red()
                );
            }
            println!("│");
        }

        println!(
            "{}",
            "└────────────────────────────────────────────────────┘".bright_red()
        );

        println!(
            "\n{}",
            "🚨 Possíveis vulnerabilidades encontradas! Analise os resultados para confirmação."
                .bright_red()
                .bold()
        );
    }
}
