#!/usr/bin/env bash
# ==============================================================================
# IP SCAN IGT — Script Inteligente de Verificação, Instalação e Atualização
# Compatível com Ubuntu, Debian, Pop!_OS, Linux Mint, Fedora, Arch, Manjaro e openSUSE
# ==============================================================================

set -e

GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
RED="\033[1;31m"
BOLD="\033[1m"
RESET="\033[0m"

echo -e "${CYAN}${BOLD}"
echo "=============================================================================="
echo "          🔍 IP SCAN IGT — INSTALADOR & VERIFICADOR DE APTIDÃO DO SISTEMA     "
echo "=============================================================================="
echo -e "${RESET}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
if [ -z "$SCRIPT_DIR" ] || [ ! -f "$SCRIPT_DIR/main.py" ]; then
    INSTALL_DIR="$HOME/.local/share/ip-scan-igt"
    SCRIPT_DIR="$INSTALL_DIR"
fi

# 1. Identificar Distribuição Linux
DISTRO="generic"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
fi

echo -e "[*] Distribuição identificada: ${YELLOW}${NAME:-$DISTRO}${RESET}"

# Função auxiliar para sudo
run_sudo() {
    if [ "$EUID" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            sudo "$@"
        else
            echo -e "${RED}[ERRO] Privilégios de root (sudo) necessários para instalar pacotes de sistema.${RESET}"
            "$@"
        fi
    else
        "$@"
    fi
}

# 2. Instalar Pacotes de Sistema Ausentes
echo -e "\n[*] ${BOLD}Etapa 1/4: Verificando ferramentas e dependências de sistema...${RESET}"

SYS_PACKAGES_DEBIAN="python3 python3-pip python3-pyqt5 python3-psutil ffmpeg vlc nmap remmina openssh-client wakeonlan libgl1 libxcb-xinerama0"
SYS_PACKAGES_FEDORA="python3 python3-pip python3-qt5 python3-psutil ffmpeg vlc nmap remmina openssh-clients"
SYS_PACKAGES_ARCH="python python-pip python-pyqt5 python-psutil ffmpeg vlc nmap remmina openssh"

case "$DISTRO" in
    ubuntu|debian|pop|linuxmint|kali|zorin)
        echo -e "[*] Atualizando repositórios APT e instalando dependências essenciais..."
        run_sudo apt-get update -y
        run_sudo apt-get install -y --no-install-recommends \
            git curl python3 python3-pip python3-venv \
            ffmpeg vlc nmap remmina openssh-client \
            libgl1 libegl1 libxcb-xinerama0 libxcb-cursor0 \
            || true
        ;;
    fedora|rhel|centos|rocky|alma)
        echo -e "[*] Instalando dependências via DNF..."
        run_sudo dnf install -y python3 python3-pip ffmpeg vlc nmap remmina openssh-clients || true
        ;;
    arch|manjaro|endeavouros)
        echo -e "[*] Instalando dependências via Pacman..."
        run_sudo pacman -Sy --noconfirm --needed python python-pip ffmpeg vlc nmap remmina openssh || true
        ;;
    *)
        echo -e "${YELLOW}[!] Distribuição genérica detectada. Verifique se Python3 e Qt5 estão disponíveis.${RESET}"
        ;;
esac

# 2.1 Garantir código do repositório em disco (para execução remota via curl | bash)
if [ ! -f "$SCRIPT_DIR/main.py" ]; then
    echo -e "\n[*] Baixando a versão oficial mais recente do IP Scan IGT do GitHub..."
    mkdir -p "$SCRIPT_DIR"
    if [ -d "$SCRIPT_DIR/.git" ]; then
        git -C "$SCRIPT_DIR" pull --rebase
    else
        git clone https://github.com/icarogabrielc85-ai/ip-scan-igt.git "$SCRIPT_DIR"
    fi
fi
cd "$SCRIPT_DIR"

# 3. Verificação do Python e Bibliotecas PIP
echo -e "\n[*] ${BOLD}Etapa 2/4: Verificando ambiente Python e bibliotecas necessárias...${RESET}"

if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${RED}[ERRO] Python 3 não pôde ser instalado automaticamente. Instale manualmente antes de prosseguir.${RESET}"
    exit 1
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "    ${GREEN}✔${RESET} Python detectado: ${CYAN}v$PY_VER${RESET}"

# Instala PyQt5 e psutil se não estiverem presentes
python3 -c "import PyQt5, psutil" 2>/dev/null || {
    echo -e "[*] Instalando bibliotecas Python (PyQt5, psutil)..."
    python3 -m pip install --user --upgrade pip 2>/dev/null || true
    python3 -m pip install --user --break-system-packages -r requirements.txt 2>/dev/null || \
    python3 -m pip install --user -r requirements.txt 2>/dev/null || \
    python3 -m pip install -r requirements.txt || true
}

if python3 -c "import PyQt5, psutil" 2>/dev/null; then
    echo -e "    ${GREEN}✔${RESET} Bibliotecas gráficas (PyQt5) e monitor (psutil) verificadas com sucesso!"
else
    echo -e "${YELLOW}[!] Tentando instalar PyQt5 via pacote de sistema...${RESET}"
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ] || [ "$DISTRO" = "pop" ] || [ "$DISTRO" = "linuxmint" ]; then
        run_sudo apt-get install -y python3-pyqt5 python3-psutil || true
    fi
fi

# 4. Criar Atalho Desktop e Comando de Terminal
echo -e "\n[*] ${BOLD}Etapa 3/4: Configurando atalho no menu de aplicativos e comando no terminal...${RESET}"

mkdir -p "$HOME/.local/bin"
mkdir -p "$HOME/.local/share/applications"

# Script executável global no PATH
LAUNCHER="$HOME/.local/bin/ipscan-igt"
cat << EOF > "$LAUNCHER"
#!/usr/bin/env bash
cd "$SCRIPT_DIR"
exec python3 "$SCRIPT_DIR/main.py" "\$@"
EOF
chmod +x "$LAUNCHER"
echo -e "    ${GREEN}✔${RESET} Comando de terminal criado: ${CYAN}ipscan-igt${RESET}"

# Atalho .desktop para menu de aplicativos
DESKTOP_ENTRY="$HOME/.local/share/applications/ipscan-igt.desktop"
cat << EOF > "$DESKTOP_ENTRY"
[Desktop Entry]
Name=IP Scan IGT
GenericName=Scanner de Rede Local
Comment=Varredura, auditoria de portas, câmeras ONVIF e osciloscópio de ping
Exec=$LAUNCHER
Icon=$SCRIPT_DIR/icon.png
Terminal=false
Type=Application
Categories=Network;System;Utility;
Keywords=network;scanner;ip;ping;onvif;nmap;rdp;ssh;
StartupNotify=true
EOF
chmod +x "$DESKTOP_ENTRY"
echo -e "    ${GREEN}✔${RESET} Atalho de aplicativo criado no lançador do sistema!"

# 5. Execução do Diagnóstico Interno e Inicialização
echo -e "\n[*] ${BOLD}Etapa 4/4: Validando aptidão completa do sistema...${RESET}"
python3 -c "
from system_doctor_dialog import check_system_readiness
d = check_system_readiness()
print('    Status Geral:', d['badge_text'])
for i in d['items']:
    symbol = '✔' if i['status'] == 'ok' else ('⚠' if i['status'] == 'warning' else '✖')
    print(f'     [{symbol}] {i[\"name\"]}: {i[\"summary\"]}')
" || true

echo -e "\n${GREEN}${BOLD}==============================================================================${RESET}"
echo -e "${GREEN}${BOLD}✔ INSTALAÇÃO CONCLUÍDA! O SISTEMA ESTÁ APTO E PRONTO PARA O IP SCAN IGT!${RESET}"
echo -e "${GREEN}${BOLD}==============================================================================${RESET}"
echo -e "Você pode iniciar o programa de três maneiras:"
echo -e "  1. Pelo terminal digitando: ${CYAN}ipscan-igt${RESET}"
echo -e "  2. Pelo menu de aplicativos do seu Linux: buscando por ${CYAN}IP Scan IGT${RESET}"
echo -e "  3. Executando diretamente nesta pasta: ${CYAN}./executar_linux.sh${RESET}\n"

if [ -e /dev/tty ]; then
    read -p "Deseja iniciar o IP Scan IGT agora? [S/n]: " -n 1 -r < /dev/tty || REPLY="s"
    echo
else
    REPLY="s"
fi

if [[ $REPLY =~ ^[Nn]$ ]]; then
    echo "Instalação concluída com sucesso! Para abrir mais tarde, digite: ipscan-igt"
else
    echo "[*] Iniciando IP Scan IGT..."
    nohup python3 "$SCRIPT_DIR/main.py" >/dev/null 2>&1 &
fi
