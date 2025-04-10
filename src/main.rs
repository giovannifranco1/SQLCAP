use crate::core::models::Args;
use crate::handlers::cli_handler;
use anyhow::Result;
use clap::Parser;

mod core;
mod handlers;
mod infra;
mod services;
mod shared;

#[tokio::main]
async fn main() -> Result<()> {
    // Parseia os argumentos da linha de comando
    let args = Args::parse();

    // Inicia o handler da CLI para conduzir o scan
    cli_handler::run_scan(args).await
}
