use super::super::cli::ui::TerminalUI;
use crate::core::models::Args;
use crate::services::scan_service::ScanService;
use anyhow::Result;
use colored::Colorize;

/// Executes the scan according to the provided arguments
pub async fn run_scan(args: Args) -> Result<()> {
    // Display banner and configuration information
    TerminalUI::print_banner();
    TerminalUI::print_config(
        &args.url,
        args.payload.to_str().unwrap_or("not available"),
        args.header
            .as_ref()
            .map_or("not available", |p| p.to_str().unwrap_or("not available")),
        args.timeout,
        args.verbose,
    );

    // Initialize scanning service
    let mut scan_service = ScanService::new(
        &args.url,
        args.header.as_ref(),
        args.fields.as_ref(),
        &args.payload,
        args.timeout,
        args.method,
        args.csrf_token,
        &args.csrf_field,
        args.csrf_cookie_field.as_deref(),
        args.debug,
        &args.debug_file,
        args.body_injection,
        &args.injection_field,
    )
    .await?;

    // Establish and display baseline
    let baseline = scan_service.establish_baseline().await?;
    TerminalUI::print_baseline(baseline);

    // Get data for display
    let (headers, payloads) = scan_service.get_test_data();
    let total_tests = scan_service.total_tests();

    // Display preparation information
    TerminalUI::print_preparation_info(
        headers.len(),
        payloads.len(),
        args.verbose,
        &headers,
        &payloads,
    );

    // Show information about injection mode
    if args.body_injection {
        println!(
            "{}",
            "🔄 Using BODY INJECTION mode - payloads will be injected into body fields"
                .bright_blue()
        );
        println!(
            "{}{}{}",
            "💉 Injecting into field: '".bright_yellow(),
            args.injection_field.bright_white().bold(),
            "'".bright_yellow()
        );
    } else {
        println!(
            "{}",
            "🔄 Using HEADER INJECTION mode - payloads will be injected into headers".bright_blue()
        );
    }

    // Execute complete scan
    let (suspicious_results, _) = scan_service.run_scan().await?;

    // Display final summary
    TerminalUI::print_summary(&args.url, total_tests, &suspicious_results);

    Ok(())
}
