#!/usr/bin/env bash
set -e
echo "======================================================================"
echo "          IP SCAN IGT - COMPILADOR AUTOMATICO PARA LINUX"
echo "======================================================================"

python3 -m pip install --user --break-system-packages -r requirements.txt
python3 -m PyInstaller --clean ipscan_linux.spec

echo ""
echo "======================================================================"
echo "Compilação concluída! Executável Linux gerado em: dist/IPScanIGT"
echo "======================================================================"
