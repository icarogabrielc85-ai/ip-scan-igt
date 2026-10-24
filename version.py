"""
Módulo de Versionamento do IP Scan IGT
Controla a versão semântica, numeração de compilação (build) e histórico de atualizações.
"""
import os
import subprocess

# Versão Semântica Oficial (MAJOR.MINOR.PATCH)
APP_VERSION = "2.5.0"
APP_RELEASE_DATE = "24/10/2026"


def get_git_info(repo_dir: str = None) -> tuple:
    """
    Obtém a contagem total de commits e o hash curto do Git para compor o build do versionamento.
    """
    if not repo_dir:
        repo_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        count = subprocess.check_output(
            ["git", "rev-list", "--count", "HEAD"],
            cwd=repo_dir,
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=1.5,
        ).strip()
        short_hash = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=repo_dir,
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=1.5,
        ).strip()
        return count, short_hash
    except Exception:
        return "", ""


def get_full_version(repo_dir: str = None) -> str:
    """
    Retorna a versão completa formatada:
    Exemplo: v2.3.0 (Build 8 • 5dc18e1)
    """
    count, short_hash = get_git_info(repo_dir)
    if count and short_hash:
        return f"v{APP_VERSION} (Build {count} • {short_hash})"
    return f"v{APP_VERSION}"


def get_short_version() -> str:
    """
    Retorna a versão semântica simples:
    Exemplo: v2.3.0
    """
    return f"v{APP_VERSION}"


VERSION_HISTORY = [
    {
        "version": "v2.5.0",
        "date": "24/10/2026",
        "title": "Doutor de Aptidão do Sistema, Auto-Instalador de Dependências & Resolução 800x600",
        "changes": [
            "Script inteligente de instalação e resolução automática de dependências para Linux (instalar_linux.sh) e Windows (instalar_windows.bat).",
            "Módulo de Diagnóstico e Aptidão do Sistema (System Doctor) integrado diretamente na interface gráfica.",
            "Detecção em tempo real e comando de instalação em 1 clique para pacotes ausentes (FFplay, VLC, Nmap, Remmina, OpenSSH).",
            "Configuração oficial da resolução padrão de exibição de câmeras para 800x600 (SVGA) com persistência contínua.",
            "Criação automática de lançador de terminal (ipscan-igt) e atalho de aplicativo (.desktop) integrado ao sistema operacional.",
            "Atualização de requirements.txt com psutil e proteção contra falhas de bibliotecas ausentes.",
        ],
    },
    {
        "version": "v2.4.0",
        "date": "24/10/2026",
        "title": "Gerenciamento de Credenciais SSH Persistentes & Resolução de Câmeras Configurável",
        "changes": [
            "Prompt de credenciais ao conectar via SSH, com opção de salvar usuário e senha para acessos rápidos posteriores.",
            "Armazenamento ofuscado de credenciais SSH por IP em ~/.config/linux-ipscan/ssh_credentials.json.",
            "Botão dedicado '⚙️ Resolução'/'⚙️ Vídeo' no Ribbon e no painel de ações para configurar exibição de câmeras.",
            "Presets de resolução RTSP (HD 720p, Full HD 1080p, XGA, SVGA, VGA leve, auto nativo e largura x altura personalizada).",
            "Controle de protocolo de transporte (TCP/UDP), seleção de player (FFplay/VLC) e modo de ultra baixa latência.",
            "Redimensionamento ergonômico das caixas de faixa de IP e máscara eliminando cortes de texto em qualquer resolução.",
        ],
    },
    {
        "version": "v2.3.0",
        "date": "22/10/2026",
        "title": "Integração RDP, SSH, Wake-on-LAN, Relatório HTML/PDF e OUI Online",
        "changes": [
            "Conexão nativa RDP (Área de Trabalho Remota) em 1 clique via Remmina/xfreerdp no Linux e mstsc no Windows.",
            "Terminal SSH integrado disparando konsole / gnome-terminal / xterm automaticamente.",
            "Wake-on-LAN (Magic Packet UDP 9) para ligar estações remotas a partir do endereço MAC.",
            "Exportação de Relatório Executivo HTML Interativo com estatísticas de rede e modo de impressão para PDF.",
            "Consulta Online OUI Fallback para identificar fabricantes recentes não presentes no banco offline.",
            "Branding moderno com exibição da versão oficial e build diretamente ao lado do nome do programa.",
        ],
    },
    {
        "version": "v2.2.0",
        "date": "22/10/2026",
        "title": "Auto-Identificação de Máscara de Rede e Auto-Atualização em 1 Clique",
        "changes": [
            "Identificação automática e inteligente da máscara de rede real da placa na inicialização.",
            "Exibição clara de CIDR e máscara decimal (/24 • 255.255.255.0, /16 • 255.255.0.0, etc.).",
            "Cálculo bidirecional em tempo real: ao digitar qualquer faixa de IP, a máscara é detectada.",
            "Botão de 1 clique '🔄 Atualizar' com verificação direta no repositório GitHub.",
            "Auto-reinicialização do aplicativo após atualizar com sucesso.",
            "Sistema oficial de versionamento dinâmico com rastreamento de Build e Git Hash.",
        ],
    },
    {
        "version": "v2.1.0",
        "date": "21/10/2026",
        "title": "Edição Multiplataforma (Linux & Windows)",
        "changes": [
            "Compatibilidade nativa total com Windows 10/11 e distribuições Linux.",
            "Descoberta automática de câmeras de segurança e gravadores via ONVIF (WS-Discovery).",
            "Reprodução instantânea de streams RTSP via VLC / FFplay.",
            "Integração profunda de auditoria de portas e serviços com Nmap em espaço de usuário.",
            "Scripts de compilação automatizada (build_linux.sh e build_windows.bat).",
        ],
    },
    {
        "version": "v2.0.0",
        "date": "20/10/2026",
        "title": "Lançamento da Interface Moderna IP Scan IGT",
        "changes": [
            "Interface visual inspirada no clássico Advanced IP Scanner com abas [Resultados] e [Favoritos].",
            "Osciloscópio de Ping Instantâneo em tempo real com gráfico dinâmico.",
            "Resolução de nomes via NetBIOS, mDNS, SMB2 e certificados SSL.",
            "Base de dados offline IEEE OUI com mais de 40.000 fabricantes de placas de rede.",
        ],
    },
]
