#!/usr/bin/env bash
# ==============================================================================
# IP SCAN IGT — Gerador de Pacote Debian (.deb)
# Empacota o executável compilado e metadados em um pacote .deb padrão
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VERSION=$(python3 -c "from version import APP_VERSION; print(APP_VERSION)" 2>/dev/null || echo "2.5.0")
ARCH="amd64"
PKG_NAME="ipscan-igt_${VERSION}_${ARCH}"
BUILD_DIR="$SCRIPT_DIR/build/deb/${PKG_NAME}"
DIST_DIR="$SCRIPT_DIR/dist"

echo "=============================================================================="
echo "          IP SCAN IGT — GERADOR DE PACOTE DEBIAN (.DEB)"
echo "          Versão: $VERSION • Arquitetura: $ARCH"
echo "=============================================================================="

# 1. Garantir que o binário foi compilado
if [ ! -f "$DIST_DIR/IPScanIGT" ]; then
    echo "[*] Binário dist/IPScanIGT não encontrado. Iniciando compilação com PyInstaller..."
    python3 -m PyInstaller --clean ipscan_linux.spec
fi

echo "[*] Preparando estrutura do pacote Debian em: $BUILD_DIR..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/DEBIAN"
mkdir -p "$BUILD_DIR/opt/ipscan-igt"
mkdir -p "$BUILD_DIR/usr/bin"
mkdir -p "$BUILD_DIR/usr/share/applications"
mkdir -p "$BUILD_DIR/usr/share/pixmaps"

# 2. Copiar arquivos da aplicação para /opt/ipscan-igt
cp "$DIST_DIR/IPScanIGT" "$BUILD_DIR/opt/ipscan-igt/IPScanIGT"
chmod +x "$BUILD_DIR/opt/ipscan-igt/IPScanIGT"

if [ -f "$SCRIPT_DIR/mac-vendors.txt" ]; then
    cp "$SCRIPT_DIR/mac-vendors.txt" "$BUILD_DIR/opt/ipscan-igt/"
fi
if [ -f "$SCRIPT_DIR/icon.png" ]; then
    cp "$SCRIPT_DIR/icon.png" "$BUILD_DIR/opt/ipscan-igt/"
    cp "$SCRIPT_DIR/icon.png" "$BUILD_DIR/usr/share/pixmaps/ipscan-igt.png"
fi

# 3. Criar link simbólico /usr/bin/ipscan-igt
ln -sf "/opt/ipscan-igt/IPScanIGT" "$BUILD_DIR/usr/bin/ipscan-igt"

# 4. Criar arquivo .desktop em /usr/share/applications/
cat << 'EOF' > "$BUILD_DIR/usr/share/applications/ipscan-igt.desktop"
[Desktop Entry]
Name=IP Scan IGT
GenericName=Scanner de Rede Local
Comment=Varredura ultrarrápida, descoberta de câmeras ONVIF, RTSP, osciloscópio de ping e auditoria Nmap
Exec=/usr/bin/ipscan-igt
Icon=ipscan-igt
Terminal=false
Type=Application
Categories=Network;System;Utility;
Keywords=network;scanner;ip;ping;onvif;nmap;rdp;ssh;
StartupNotify=true
EOF
chmod 644 "$BUILD_DIR/usr/share/applications/ipscan-igt.desktop"

# 5. Criar arquivo DEBIAN/control
cat << EOF > "$BUILD_DIR/DEBIAN/control"
Package: ipscan-igt
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: Icaro Gabriel <icarogabrielc85-ai@users.noreply.github.com>
Depends: libgl1, libxcb-xinerama0
Recommends: ffmpeg, vlc, nmap, remmina, openssh-client
Homepage: https://github.com/icarogabrielc85-ai/ip-scan-igt
Description: IP Scan IGT - Ferramenta Grafica de Auditoria e Diagnostico de Rede
 Scanner de rede rapido inspirado no Advanced IP Scanner com deteccao
 automatica de cameras ONVIF, player RTSP em baixa latencia, osciloscopio
 de ping em tempo real, auditoria profunda de portas com Nmap, Wake-on-LAN
 e conexao remota via RDP e terminal SSH.
EOF

# 6. Criar scripts de pós-instalação e pós-remoção para atualizar cache de ícones/desktop
cat << 'EOF' > "$BUILD_DIR/DEBIAN/postinst"
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
exit 0
EOF
chmod 755 "$BUILD_DIR/DEBIAN/postinst"

cat << 'EOF' > "$BUILD_DIR/DEBIAN/postrm"
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
exit 0
EOF
chmod 755 "$BUILD_DIR/DEBIAN/postrm"

# 7. Empacotar via dpkg-deb
mkdir -p "$DIST_DIR"
DEB_FILE="$DIST_DIR/${PKG_NAME}.deb"
echo "[*] Gerando pacote .deb com dpkg-deb..."
dpkg-deb --build "$BUILD_DIR" "$DEB_FILE"

# Criar link genérico ipscan-igt_latest_amd64.deb
cp "$DEB_FILE" "$DIST_DIR/ipscan-igt_latest_amd64.deb"

echo ""
echo "=============================================================================="
echo "✔ Pacote Debian (.deb) gerado com sucesso!"
echo "• Arquivo: $DEB_FILE"
echo "• Tamanho: $(du -h "$DEB_FILE" | cut -f1)"
echo ""
echo "Para instalar no Ubuntu/Debian/Mint/Pop!_OS, execute:"
echo "sudo apt install ./dist/${PKG_NAME}.deb"
echo "=============================================================================="
