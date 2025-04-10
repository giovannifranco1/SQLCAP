use anyhow::Result;
use clap::Parser;
use sqlcap::core::models::Args;

#[tokio::main]
async fn main() -> Result<()> {
    // Parseia os argumentos da linha de comando
    let args = Args::parse();

    // Executa o scanner usando a lib
    sqlcap::run(args).await
}
