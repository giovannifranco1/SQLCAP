use super::super::cli::ui::TerminalUI;
use crate::core::models::Args;
use crate::services::scan_service::ScanService;
use anyhow::Result;
use std::time::Duration;

/// Executes the scan according to the provided arguments
pub async fn run_scan(args: Args) -> Result<()> {
    // Display banner and configuration information
    TerminalUI::print_banner();
    TerminalUI::print_config(
        &args.url,
        args.payload.to_str().unwrap_or("not available"),
        args.header.to_str().unwrap_or("not available"),
        args.timeout,
        args.verbose,
    );

    // Initialize scanning service
    let mut scan_service =
        ScanService::new(&args.url, &args.header, &args.payload, args.timeout).await?;

    // Get data for display
    let (headers, payloads) = scan_service.get_test_data();
    let total_tests = scan_service.total_tests();

    // Display preparation information
    TerminalUI::print_preparation_info(
        headers.len(),
        payloads.len(),
        args.verbose,
        headers,
        payloads,
    );

    // Establish and display baseline
    let baseline = scan_service.establish_baseline().await?;
    TerminalUI::print_baseline(baseline);

    // Execute complete scan
    let (suspicious_results, _) = scan_service.run_scan().await?;

    // Display final summary
    TerminalUI::print_summary(&args.url, total_tests, &suspicious_results);

    Ok(())
}
