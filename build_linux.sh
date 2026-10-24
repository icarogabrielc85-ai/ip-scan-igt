#!/usr/bin/env bash
set -e
echo "======================================================================"
echo "          IP SCAN IGT - COMPILADOR AUTOMATICO PARA LINUX"
echo "======================================================================"

if ! python3 -c "import PyQt5, PyInstaller, psutil" 2>/dev/null; then
    echo "[*] Instalando dependências ausentes (PyQt5, psutil e PyInstaller)..."
    python3 -m pip install --user --break-system-packages -r requirements.txt || \
    python3 -m pip install --user -r requirements.txt
else
    echo "[OK] Dependências já estão instaladas!"
fi

python3 -m PyInstaller --clean ipscan_linux.spec

echo ""
echo "[*] Gerando pacote Debian (.deb)..."
chmod +x build_deb.sh
./build_deb.sh

echo ""
echo "======================================================================"
echo "Compilação concluída!"
echo "• Executável Linux: dist/IPScanIGT"
echo "• Pacote Debian:   dist/ipscan-igt_*.deb"
echo "======================================================================"
