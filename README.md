# SQLCAP - Detector de SQL Injection baseado em Headers

SQLCAP (SQL Injection Blind Headers Capture) é uma ferramenta de linha de comando para testar vulnerabilidades de SQL Injection em headers HTTP. A ferramenta funciona enviando múltiplas requisições para um alvo, injetando payloads maliciosos em diferentes headers HTTP e analisando as respostas em busca de padrões que possam indicar vulnerabilidades.

## Recursos

- Teste de múltiplos headers com múltiplos payloads
- Detecção de injeção SQL baseada em tempo (time-based blind)
- Detecção de injeção SQL baseada em diferenças de resposta (boolean-based blind)
- Análise de anomalias em status HTTP, tempo de resposta e tamanho do corpo
- Relatório detalhado de pontos suspeitos
- Modo verbose para depuração

## Requisitos

- Rust 2021 edition ou superior
- Cargo

## Instalação

Clone o repositório e compile o projeto:

```bash
git clone https://github.com/seu-usuario/sqlcap.git
cd sqlcap
cargo build --release
```

O binário compilado estará disponível em `target/release/sqlcap`.

## Uso

```bash
sqlcap --url <URL> --payload <ARQUIVO_PAYLOADS> --header <ARQUIVO_HEADERS> [--timeout <MS>] [--verbose]
```

### Parâmetros

- `--url`: URL do alvo a ser testado
- `--payload`: Caminho para o arquivo contendo payloads de SQL Injection (um por linha)
- `--header`: Caminho para o arquivo contendo nomes de headers a serem testados (um por linha)
- `--timeout`: Limiar de tempo em milissegundos para considerar uma resposta suspeita (padrão: 3000ms)
- `--verbose`: Ativa o modo detalhado de output

### Exemplo

```bash
sqlcap --url https://exemplo.com/api/dados --payload payloads/sqli_payloads.txt --header payloads/headers.txt --timeout 5000
```

## Formato dos Arquivos

### Arquivo de Headers

Um arquivo de texto simples com um header por linha. Exemplo:

```
# headers.txt
User-Agent
X-Forwarded-For
User-Id
```

### Arquivo de Payloads

Um arquivo de texto simples com um payload por linha. Exemplo:

```
# sqli_payloads.txt
' OR '1'='1
1' AND SLEEP(5) -- -
' waitfor delay '0:0:5' --
```

## Como a Ferramenta Funciona

1. A ferramenta estabelece uma linha de base enviando uma requisição sem modificações
2. Para cada header no arquivo de headers, substitui o valor por cada payload no arquivo de payloads
3. Compara as respostas com a linha de base, procurando:
   - Diferenças significativas no tempo de resposta (indicativo de time-based SQLi)
   - Diferenças no tamanho da resposta (indicativo de boolean-based SQLi)
   - Mudanças no código de status HTTP
4. Gera um relatório com os pontos suspeitos encontrados

## Limitações

- A ferramenta não confirma automaticamente a existência de vulnerabilidades, apenas identifica pontos suspeitos
- Falsos positivos podem ocorrer, especialmente em aplicações com respostas variáveis
- O teste não inclui payloads para outras vulnerabilidades além de SQL Injection

## Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para enviar pull requests ou abrir issues no GitHub. 