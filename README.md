# SQLCAP - Scanner de SQL Injection baseado em Headers

SQLCAP (SQL Injection Headers Scanner) é uma ferramenta de linha de comando em Rust para detectar vulnerabilidades de SQL Injection em headers HTTP, utilizando uma abordagem modular e orientada a objetos.

## Recursos

- Detecção de SQL Injection em headers HTTP
- Suporte a múltiplos headers e payloads
- Análise de vulnerabilidades baseada em:
  - Tempo de resposta (time-based)
  - Diferenças no tamanho da resposta (boolean-based)
  - Alterações no código de status HTTP
- Interface visual rica com cores e ícones
- Arquitetura modular seguindo boas práticas de Rust

## Estrutura do Projeto

```
src/
├── main.rs                # Ponto de entrada da aplicação
├── core/                  # Regras de negócio e modelos
│   ├── mod.rs
│   ├── models.rs          # Estruturas de dados principais
│   └── scanner.rs         # Lógica central de escaneamento
├── services/              # Serviços de aplicação
│   ├── mod.rs
│   └── scan_service.rs    # Serviço de orquestração de scan
├── infra/                 # Implementações técnicas
│   ├── mod.rs
│   └── file_reader.rs     # Leitor de arquivos
├── handlers/              # Manipuladores de entrada
│   ├── mod.rs
│   └── cli_handler.rs     # Handler da interface de linha de comando
└── shared/                # Componentes compartilhados
    ├── mod.rs
    └── ui.rs              # Interface do usuário no terminal
```

## Uso

```bash
cargo run -- --url <URL> --payload <ARQUIVO_PAYLOADS> --header <ARQUIVO_HEADERS> [--timeout <MS>] [--verbose]
```

### Parâmetros

- `--url`: URL do alvo a ser testado
- `--payload`: Caminho para o arquivo com os payloads de SQL Injection (um por linha)
- `--header`: Caminho para o arquivo com os nomes dos headers a serem testados (um por linha)
- `--timeout`: Limiar em milissegundos para considerar uma resposta suspeita (padrão: 3000ms)
- `--verbose`: Ativar modo detalhado

## Exemplo

```bash
cargo run -- --url https://exemplo.com/api --payload payloads/sqli_payloads.txt --header payloads/headers.txt --verbose
```

## Instalação

Clone o repositório e compile o projeto:

```bash
git clone https://github.com/seu-usuario/sqlcap.git
cd sqlcap
cargo build --release
```

O binário compilado estará disponível em `target/release/sqlcap`.

## Desenvolvimento

O projeto segue uma arquitetura modular onde:

- **Core**: Contém a lógica central e as estruturas de dados
- **Services**: Orquestra a execução de operações complexas
- **Infra**: Fornece implementações técnicas (IO, rede, etc.)
- **Handlers**: Gerencia a interação com o usuário
- **Shared**: Disponibiliza utilidades reutilizáveis

## Contribuições

Contribuições são bem-vindas! Sinta-se à vontade para enviar pull requests ou abrir issues. 