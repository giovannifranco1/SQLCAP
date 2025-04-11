```
  ██████   █████   ██▓     ▄████▄   ▄▄▄       ██▓███  
 ▒██    ▒ ▒██▓  ██▒▓██▒    ▒██▀ ▀█  ▒████▄    ▓██░  ██▒
 ░ ▓██▄   ▒██▒  ██░▒██░    ▒▓█    ▄ ▒██  ▀█▄  ▓██░ ██▓▒
   ▒   ██▒░██  █▀ ░▒██░    ▒▓▓▄ ▄██▒░██▄▄▄▄██ ▒██▄█▓▒ ▒
 ▒██████▒▒░▒███▒█▄ ░██████▒▒ ▓███▀ ░ ▓█   ▓██▒▒██▒ ░  ░
 ▒ ▒▓▒ ▒ ░░░ ▒▒░ ▒ ░ ▒░▓  ░░ ░▒ ▒  ░ ▒▒   ▓▒█░▒▓▒░ ░  ░
 ░ ░▒  ░ ░ ░ ▒░  ░ ░ ░ ▒  ░  ░  ▒     ▒   ▒▒ ░░▒ ░     
 ░  ░  ░     ░   ░   ░ ░   ░          ░   ▒   ░░       
       ░      ░        ░  ░░ ░            ░  ░         
                           ░                           
```

# SQLCAP - SQL Capture and Analysis Platform

SQLCAP (SQL Capture and Analysis Platform) is a Rust command-line tool designed to detect SQL injection vulnerabilities in HTTP headers and form parameters, using a modular and object-oriented approach.

## Features

- SQL Injection detection in HTTP headers and form parameters
- Support for multiple headers and payloads
- Support for injection in HTML and JSON form fields
- Support for CSRF tokens in cookies and forms
- Detection based on:
  - Response time (time-based)
  - Differences in response size (boolean-based)
  - Changes in HTTP status code
- Rich visual interface with colors and icons
- Modular architecture following Rust best practices
- Complete request logging for debugging

## Project Structure

```
src/
├── lib.rs                 # Library entry point
├── main.rs                # Binary entry point
├── core/                  # Business rules and models
│   ├── mod.rs
│   ├── models.rs          # Main data structures
│   ├── scanner.rs         # Main scanning logic
│   ├── csrf.rs            # CSRF token handling
│   └── logger.rs          # Request logger for debugging
├── services/              # Application services
│   ├── mod.rs
│   └── scan_service.rs    # Scan orchestration service
├── infra/                 # Technical implementations
│   ├── mod.rs
│   └── file_reader.rs     # File reader
├── handlers/              # Input handlers
│   ├── mod.rs
│   └── cli_handler.rs     # Command line interface handler
└── cli/                   # CLI components
    ├── mod.rs
    └── ui.rs              # Terminal user interface
```

## Usage

### Header Injection Mode

```bash
sqlcap --url <URL> --payload <PAYLOADS_FILE> --header <HEADERS_FILE> [--timeout <MS>] [--verbose] [--debug]
```

### Form Parameter Injection Mode

```bash
sqlcap --url <URL> --payload <PAYLOADS_FILE> --fields <FIELDS_FILE> --method POST --body-injection [--csrf-token <TOKEN>] [--csrf-field <FIELD>] [--csrf-cookie-field <COOKIE_FIELD>] [--debug]
```

### Parameters

- `--url`: Target URL to be tested
- `--payload`: Path to file with SQL injection payloads (one per line)
- `--header`: Path to file with header names to be tested (one per line)
- `--fields`: Path to file with form field names to be tested (one per line)
- `--method`: HTTP method to be used (GET or POST)
- `--body-injection`: Activates body field injection mode
- `--csrf-token`: CSRF token value, if known
- `--csrf-field`: Name of the CSRF token field in the form (default: csrf_token)
- `--csrf-cookie-field`: Name of the CSRF token field in the cookie (if different from the form field)
- `--timeout`: Threshold in milliseconds to consider a response suspicious (default: 3000ms)
- `--verbose`: Activates verbose mode
- `--debug`: Activates debug mode and logs requests to a file

## Examples

### Testing Headers

```bash
sqlcap --url https://example.com/api --payload payloads/sqli_payloads.txt --header payloads/headers.txt --verbose
```

### Testing Form Fields

```bash
sqlcap --url https://example.com/login --payload payloads/sqli_payloads.txt --fields payloads/fields.txt --method POST --body-injection --csrf-token "token123" --csrf-field "csrf_token" --csrf-cookie-field "CSRF_COOKIE" --debug
```

## Installation

Clone the repository and build the project:

```bash
git clone https://github.com/your-username/sqlcap.git
cd sqlcap
cargo build --release
```

The compiled binary will be available in `target/release/sqlcap`.

## Development

The project follows a modular architecture where:

- **Core**: Contains core logic and data structures
- **Services**: Orchestrates the execution of complex operations
- **Infra**: Provides technical implementations (IO, network, etc.)
- **Handlers**: Manages user interaction
- **CLI**: Provides terminal user interface and CLI components

## How to Create Payload and Field Files

### payloads/sqli_payloads.txt
```
' OR '1'='1
' OR 1=1 -- 
' UNION SELECT SLEEP(5)--
' AND 1=1 --
```

### payloads/headers.txt
```
User-Agent
X-Forwarded-For
Authorization
Referer
```

### payloads/fields.txt
```
username
password
email
id
search
```

## Contributions

Contributions are welcome! Feel free to send pull requests or open issues.

## Disclaimer

This tool is provided for educational and professional security testing purposes only. The author is not responsible for any misuse or damage caused by this program. Always ensure you have explicit permission to test the target systems before using this tool. Using this scanner against systems without proper authorization may be illegal and is not condoned. 