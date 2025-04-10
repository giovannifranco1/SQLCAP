#!/bin/bash
# Script de exemplo para demonstrar o uso da ferramenta SQLCAP

echo "Testando SQLCAP contra um servidor de teste..."
echo ""

# Verifica se o binário existe
if [ ! -f "./target/debug/sqlcap" ]; then
    echo "Compilando o projeto primeiro..."
    cargo build
fi

# Executa o SQLCAP com os parâmetros de exemplo
./target/debug/sqlcap \
    --url "https://httpbin.org/anything" \
    --payload "payloads/sqli_payloads.txt" \
    --header "payloads/headers.txt" \
    --timeout 5000 \
    --verbose

echo ""
echo "Teste concluído!" 