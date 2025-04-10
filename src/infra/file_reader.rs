use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Estrutura responsável por ler e processar arquivos
pub struct FileReader;

impl FileReader {
    /// Lê o conteúdo de um arquivo de texto e retorna as linhas não vazias e não comentadas
    pub fn read_lines_from_file<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Erro ao ler o arquivo: {}", path.as_ref().display()))?;

        // Filtra linhas vazias e comentários
        let lines: Vec<String> = content
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.trim().to_string())
            .collect();

        Ok(lines)
    }
}
