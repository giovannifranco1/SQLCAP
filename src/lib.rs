pub mod cli;
pub mod core;
pub mod handlers;
pub mod infra;
pub mod services;

use crate::core::models::Args;
use crate::handlers::cli_handler;
use anyhow::Result;

/// Executa o scanner de injeção SQL
pub async fn run(args: Args) -> Result<()> {
    cli_handler::run_scan(args).await
}
