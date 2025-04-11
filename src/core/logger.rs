use crate::core::models::RequestDebugInfo;
use anyhow::{Context, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Logger para armazenar detalhes de requisições para debug
pub struct RequestLogger {
    debug_file: String,
    is_enabled: bool,
}

impl RequestLogger {
    /// Cria uma nova instância do logger
    pub fn new<P: AsRef<Path>>(debug_file: P, is_enabled: bool) -> Self {
        Self {
            debug_file: debug_file.as_ref().to_string_lossy().to_string(),
            is_enabled,
        }
    }

    /// Registra uma requisição no arquivo de debug
    pub fn log_request(&self, request_info: &RequestDebugInfo) -> Result<()> {
        if !self.is_enabled {
            return Ok(());
        }

        let mut log_entry = String::new();

        // Linha de requisição no formato HTTP
        log_entry.push_str(&format!(
            "{} {} HTTP/1.1\n",
            request_info.method, request_info.url
        ));

        // Host extraído da URL
        if let Some(host) = request_info.url.split("://").nth(1) {
            if let Some(hostname) = host.split('/').next() {
                log_entry.push_str(&format!("Host: {}\n", hostname));
            }
        }

        // Headers
        // Organizamos os headers em ordem específica para melhor legibilidade
        let important_headers = ["Content-Type", "Cookie", "Content-Length", "User-Agent"];

        // Primeiro adicionamos headers importantes
        for header in important_headers.iter() {
            if let Some(value) = request_info.headers.get(*header) {
                log_entry.push_str(&format!("{}: {}\n", header, value));
            }
        }

        // Depois os headers restantes, exceto os que foram injetados com payload
        for (name, value) in &request_info.headers {
            if !important_headers.contains(&name.as_str()) && !name.contains("payload") {
                log_entry.push_str(&format!("{}: {}\n", name, value));
            }
        }

        // Corpo da requisição se existir
        if let Some(body) = &request_info.body {
            log_entry.push_str("\n");

            // Se for um JSON, tenta formatar para melhor legibilidade
            match serde_json::from_str::<serde_json::Value>(body) {
                Ok(json_value) => {
                    if let Ok(pretty) = serde_json::to_string_pretty(&json_value) {
                        log_entry.push_str(&pretty);
                    } else {
                        log_entry.push_str(body);
                    }
                }
                Err(_) => {
                    // Não é um JSON válido, registra como está
                    log_entry.push_str(body);
                }
            }
        }

        // Separador de requisições
        log_entry.push_str("\n__________\n\n");

        // Abre o arquivo em modo append ou cria se não existir
        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .create(true)
            .open(&self.debug_file)
            .with_context(|| format!("Failed to open debug log file: {}", self.debug_file))?;

        // Escreve a entrada no arquivo
        file.write_all(log_entry.as_bytes())
            .with_context(|| format!("Failed to write to debug log file: {}", self.debug_file))?;

        Ok(())
    }

    /// Limpa o arquivo de log
    pub fn clear_log(&self) -> Result<()> {
        if !self.is_enabled {
            return Ok(());
        }

        fs::write(&self.debug_file, "")
            .with_context(|| format!("Failed to clear debug log file: {}", self.debug_file))?;

        Ok(())
    }
}
