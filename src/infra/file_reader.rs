use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Estrutura responsável por ler e processar arquivos
pub struct FileReader;

impl FileReader {
    /// Reads the content of a text file and returns non-empty and non-commented lines
    pub fn read_lines_from_file<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Error reading file: {}", path.as_ref().display()))?;

        // Filter empty lines and comments
        let lines: Vec<String> = content
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.trim().to_string())
            .collect();

        Ok(lines)
    }
}
