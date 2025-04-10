use crate::core::models::Args;
use crate::services::scan_service::ScanService;
use crate::shared::ui::TerminalUI;
use anyhow::Result;
use std::time::Duration;

/// Executa o scan de acordo com os argumentos fornecidos
pub async fn run_scan(args: Args) -> Result<()> {
    // Exibe o banner e as informações de configuração
    TerminalUI::print_banner();
    TerminalUI::print_config(
        &args.url,
        args.payload.to_str().unwrap_or("não disponível"),
        args.header.to_str().unwrap_or("não disponível"),
        args.timeout,
        args.verbose,
    );

    // Inicializa o serviço de escaneamento
    let mut scan_service =
        ScanService::new(&args.url, &args.header, &args.payload, args.timeout).await?;

    // Obtém dados para exibição
    let (headers, payloads) = scan_service.get_test_data();
    let total_tests = scan_service.total_tests();

    // Exibe informações de preparação
    TerminalUI::print_preparation_info(
        headers.len(),
        payloads.len(),
        args.verbose,
        headers,
        payloads,
    );

    // Estabelece e exibe a linha de base
    let baseline = scan_service.establish_baseline().await?;
    TerminalUI::print_baseline(baseline);

    // Executa o scan completo
    let (suspicious_results, _) = scan_service.run_scan().await?;

    // Exibe o resumo final
    TerminalUI::print_summary(&args.url, total_tests, &suspicious_results);

    Ok(())
}
