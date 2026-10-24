#!/usr/bin/env bash
# ==============================================================================
# IP SCAN IGT — Inicializador Rápido com Verificação de Dependências
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! python3 -c "import PyQt5, psutil" 2>/dev/null; then
    echo "[!] Dependências essenciais ausentes detectadas."
    echo "[*] Executando instalador automático do sistema..."
    exec ./instalar_linux.sh
fi

exec python3 main.py "$@"
