# SQLCAP - HTTP Headers SQL Injection Scanner

SQLCAP (SQL Injection Headers Scanner) is a Rust command-line tool designed to detect SQL Injection vulnerabilities in HTTP headers, using a modular and object-oriented approach.

## Features

- SQL Injection detection in HTTP headers
- Support for multiple headers and payloads
- Vulnerability analysis based on:
  - Response time (time-based)
  - Differences in response size (boolean-based)
  - Changes in HTTP status code
- Rich visual interface with colors and icons
- Modular architecture following Rust best practices

## Project Structure

```
src/
├── main.rs                # Application entry point
├── core/                  # Business rules and models
│   ├── mod.rs
│   ├── models.rs          # Main data structures
│   └── scanner.rs         # Core scanning logic
├── services/              # Application services
│   ├── mod.rs
│   └── scan_service.rs    # Scan orchestration service
├── infra/                 # Technical implementations
│   ├── mod.rs
│   └── file_reader.rs     # File reader
├── handlers/              # Input handlers
│   ├── mod.rs
│   └── cli_handler.rs     # Command-line interface handler
└── shared/                # Shared components
    ├── mod.rs
    └── ui.rs              # Terminal user interface
```

## Usage

```bash
cargo run -- --url <URL> --payload <PAYLOADS_FILE> --header <HEADERS_FILE> [--timeout <MS>] [--verbose]
```

### Parameters

- `--url`: Target URL to be tested
- `--payload`: Path to the file with SQL Injection payloads (one per line)
- `--header`: Path to the file with the names of headers to be tested (one per line)
- `--timeout`: Threshold in milliseconds to consider a response suspicious (default: 3000ms)
- `--verbose`: Enable detailed mode

## Example

```bash
cargo run -- --url https://example.com/api --payload payloads/sqli_payloads.txt --header payloads/headers.txt --verbose
```

## Installation

Clone the repository and build the project:

```bash
git clone https://github.com/your-username/sqlcap.git
cd sqlcap
cargo build --release
```

The compiled binary will be available at `target/release/sqlcap`.

## Development

The project follows a modular architecture where:

- **Core**: Contains the central logic and data structures
- **Services**: Orchestrates the execution of complex operations
- **Infra**: Provides technical implementations (IO, network, etc.)
- **Handlers**: Manages user interaction
- **Shared**: Provides reusable utilities

## Contributions

Contributions are welcome! Feel free to submit pull requests or open issues. 