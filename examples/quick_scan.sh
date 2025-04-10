#!/bin/bash
# Script para executar um scan rápido em um alvo específico

# Verifica se foi fornecido um URL
if [ $# -lt 1 ]; then
    echo "Uso: ./quick_scan.sh <URL> [timeout]"
    echo "Exemplo: ./quick_scan.sh https://exemplo.com/api 5000"
    exit 1
fi

URL=$1
TIMEOUT=${2:-3000}  # Valor padrão de 3000ms se não for fornecido

# Verifica se o binário existe
if [ ! -f "./target/debug/sqlcap" ]; then
    echo "Compilando o projeto primeiro..."
    cargo build
fi

echo "=== SQLCAP - SQL Injection Scanner ==="
echo "Alvo: $URL"
echo "Timeout: ${TIMEOUT}ms"
echo "Iniciando scan..."

# Executa o SQLCAP com os parâmetros fornecidos
./target/debug/sqlcap \
    --url "$URL" \
    --payload "payloads/sqli_payloads.txt" \
    --header "payloads/headers.txt" \
    --timeout "$TIMEOUT"

echo ""
echo "Scan concluído!" 