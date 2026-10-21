#!/usr/bin/env bash
set -e
echo "======================================================================"
echo "          IP SCAN IGT - COMPILADOR AUTOMATICO PARA LINUX"
echo "======================================================================"

if ! python3 -c "import PyQt5, PyInstaller" 2>/dev/null; then
    echo "[*] Instalando dependências ausentes (PyQt5 e PyInstaller)..."
    python3 -m pip install --user --break-system-packages -r requirements.txt
else
    echo "[OK] PyQt5 e PyInstaller já estão instalados!"
fi
python3 -m PyInstaller --clean ipscan_linux.spec

echo ""
echo "======================================================================"
echo "Compilação concluída! Executável Linux gerado em: dist/IPScanIGT"
echo "======================================================================"
