use crate::core::models::{Baseline, ScanResult};
use chrono::Local;
use colored::Colorize;
use reqwest::StatusCode;
use std::io::Write;
use std::thread::sleep;
use std::time::Duration;

/// Module responsible for the terminal user interface
pub struct TerminalUI;

impl TerminalUI {
    /// Displays the initial program banner
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
            .bright_red()
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

        // Add a 1 second sleep after showing the banner
        sleep(Duration::from_secs(1));
    }

    /// Displays a section header
    pub fn print_section_header(text: &str) {
        println!();
        println!("{} {}", "━━━━".bright_cyan(), text.bold().bright_white());
    }

    /// Creates a visual progress bar
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

    /// Displays configuration information
    pub fn print_config(
        url: &str,
        payload_file: &str,
        header_file: &str,
        timeout: u64,
        verbose: bool,
    ) {
        Self::print_section_header("📋 CONFIGURATION");
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
                "🔊 Verbose mode:".bright_yellow(),
                "Enabled".bright_green()
            );
        } else {
            println!(
                "{} {}",
                "🔊 Verbose mode:".bright_yellow(),
                "Disabled".bright_red()
            );
        }
    }

    /// Displays preparation information
    pub fn print_preparation_info(
        headers_count: usize,
        payloads_count: usize,
        verbose: bool,
        headers: &[String],
        payloads: &[String],
    ) {
        Self::print_section_header("🔍 PREPARATION");
        println!(
            "{} {}",
            "📊 Headers to test:".bright_yellow(),
            headers_count.to_string().bright_white()
        );
        println!(
            "{} {}",
            "🧪 Payloads to inject:".bright_yellow(),
            payloads_count.to_string().bright_white()
        );
        println!(
            "{} {}",
            "🔢 Total tests to run:".bright_yellow(),
            (headers_count * payloads_count).to_string().bright_white()
        );

        if verbose {
            Self::print_section_header("📝 DATA DETAILS");

            println!("{}", "🔤 Headers to test:".bright_yellow());
            for (i, header) in headers.iter().enumerate() {
                println!(
                    "   {}. {}",
                    (i + 1).to_string().bright_cyan(),
                    header.bright_white()
                );
                if i >= 9 && headers.len() > 12 {
                    println!("   ... and {} more headers", headers.len() - 10);
                    break;
                }
            }
        }

        Self::print_section_header("🚀 EXECUTION");
        println!(
            "{}",
            "Starting SQL Injection vulnerability scan via headers..."
                .bright_green()
                .bold()
        );
    }

    /// Shows initialization message for a header test
    pub fn print_header_test_start(header_name: &str, verbose: bool) {
        println!();
        println!(
            "{} '{}'",
            "🔍 Testing header:".bright_cyan().bold(),
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
                " [*] Starting injection tests...".bright_green(),
                "┃".bright_blue()
            );
            println!(
                "{} {} {}",
                "┃".bright_blue(),
                " [*] Analyzing vulnerabilities...".bright_green(),
                "┃".bright_blue()
            );
            println!(
                "{} {} {}",
                "┃".bright_blue(),
                " [+] Scanner running...".bright_green(),
                "┃".bright_blue()
            );
            println!(
                "{}",
                "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛".bright_blue()
            );
        }
    }

    /// Updates the progress bar
    pub fn update_progress_bar(
        completed_tests: usize,
        total_tests: usize,
        header_name: &str,
        payload: &str,
    ) {
        let progress = (completed_tests as f64 / total_tests as f64 * 100.0) as u32;
        let progress_bar = Self::create_progress_bar(progress);

        // Clear the previous line before printing the new update
        print!("\r");
        print!(
            "{}",
            "                                                                                "
                .black()
        );
        print!("\r");

        // Print the progress bar hacking style with highlighted header and payload
        print!(
            "{} {} {} {}{} {}",
            "[*]".bright_green(),
            format!("Progress: [{}] {}%", progress_bar, progress).bright_cyan(),
            "| Target:".bright_red(),
            header_name.bright_white().bold(),
            ":".bright_white(),
            payload.bright_green().bold()
        );

        // Force the output to be printed immediately
        std::io::stdout().flush().ok();
    }

    /// Displays the result of an injection test
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
        // Format the status with color
        let status_text = if status.is_success() {
            status.to_string().bright_green()
        } else if status.is_client_error() {
            status.to_string().bright_yellow()
        } else if status.is_server_error() {
            status.to_string().bright_red()
        } else {
            status.to_string().bright_white()
        };

        // Compact format for each test (hacking style)
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

    /// Displays the established baseline
    pub fn print_baseline(baseline: &Baseline) {
        println!(
            "{}",
            "⏳ Establishing baseline for comparison...".bright_blue()
        );
        println!(
            "{} Status: {}, Time: {:.2?}, Size: {} bytes",
            "📊 Baseline:".bright_blue(),
            baseline.status.to_string().bright_white(),
            baseline.duration_ms,
            baseline.body_size.to_string().bright_white()
        );
    }

    /// Displays the final scan summary
    pub fn print_summary(url: &str, total_tests: usize, suspicious_results: &[ScanResult]) {
        Self::print_section_header("📊 RESULTS");

        // Summary box hacking style
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

        // Details of vulnerabilities found
        if !suspicious_results.is_empty() {
            Self::print_vulnerability_details(suspicious_results);
        } else {
            println!(
                "\n{}",
                "✅ No obvious SQL Injection vulnerabilities detected."
                    .bright_green()
                    .bold()
            );
        }
    }

    /// Displays the details of vulnerabilities found
    pub fn print_vulnerability_details(results: &[ScanResult]) {
        Self::print_section_header("🚨 VULNERABILITY DETAILS");

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

            // Status with color
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
                "⏱️  Time:".bright_yellow(),
                result.duration_ms.to_string().bright_white(),
                "📏 Size:".bright_yellow(),
                result.body_size.to_string().bright_white()
            );

            if let Some(reason) = &result.reason {
                println!(
                    "│ {} {}",
                    "⚠️  Reason:".bright_yellow(),
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
            "🚨 Possible vulnerabilities found! Analyze results for confirmation."
                .bright_red()
                .bold()
        );
    }
}
