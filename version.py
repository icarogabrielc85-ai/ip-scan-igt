"""
Módulo de Versionamento do IP Scan IGT
Controla a versão semântica, numeração de compilação (build) e histórico de atualizações.
"""
import os
import subprocess

# Versão Semântica Oficial (MAJOR.MINOR.PATCH)
APP_VERSION = "2.9.0"
APP_RELEASE_DATE = "26/10/2026"


def get_git_info(repo_dir: str = None) -> tuple:
    """
    Obtém a contagem total de commits e o hash curto do Git para compor o build do versionamento.
    Suporta fallback para metadados de instalação ZIP (.version_meta.json) quando o Git não estiver disponível.
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
        if count and short_hash:
            return count, short_hash
    except Exception:
        pass

    # Fallback to .version_meta.json for non-git / manual zip installations
    try:
        meta_file = os.path.join(repo_dir, ".version_meta.json")
        if os.path.exists(meta_file):
            import json
            with open(meta_file, "r", encoding="utf-8") as f:
                d = json.load(f)
                sha = d.get("commit_sha", "").strip()
                if sha:
                    return "Release", sha
    except Exception:
        pass

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
        "version": "v2.9.0",
        "date": "26/10/2026",
        "title": "Network Guard (ARP Spoofing & Intrusos), Snapshots de Auditoria (Diff), Relatório Executivo c/ Topologia & UPnP/Traceroute",
        "changes": [
            "Network Guard (Segurança L2): detecção passiva e ativa de ataques de ARP Spoofing (sequestro de Gateway), Conflito de IP (troca abrupta de MAC) e Novos Dispositivos Intrusos não autorizados, com gerenciamento de Whitelist de MACs confiáveis.",
            "Snapshots de Auditoria & Comparador de Mudanças (Baseline Diff): salvamento de fotografias da rede e comparação instantânea destacando novos dispositivos (🟢), servidores ausentes (🔴) e alterações de portas/CVEs/MAC (🟠).",
            "Relatório Executivo HTML / PDF Autocontido Avançado: inclui cálculo do Score de Segurança da Rede (0–100), Mapa Visual de Topologia embutido em Base64 PNG, Matriz de Vulnerabilidades (CVEs) e Telemetria SNMP/Impressoras/UPnP.",
            "Descoberta UPnP / SSDP (UDP 1900) & Traceroute Visual: extração de fabricante, modelo e número de série de Smart TVs, roteadores e IoT via XML UPnP + ferramenta gráfica de Traceroute por saltos (TTL) com grafo de latência.",
            "Refinamento Visual & UX: Tema Claro com paleta de tons de cinza inspirada no VirtualBox, abertura automática em tela cheia, espaçamento compacto entre linhas de itens escaneados e rótulos otimizados sem cortes (ex: 'Resultado Scan').",
        ],
    },
    {
        "version": "v2.8.0",
        "date": "25/10/2026",
        "title": "Correlação de Vulnerabilidades (CVEs), Watchdog Contínuo, Auditoria SNMP (UDP 161) & Mapa Visual de Topologia",
        "changes": [
            "Auditoria via SNMP (UDP 161) em Python puro (ASN.1 BER): extração de descrição de hardware, hostname, tempo de atividade (uptime), contagem de portas de switches e nível de toner/páginas impressas (Printer-MIB).",
            "Correlação de Vulnerabilidades (CVEs) com base SQLite local: cruzamento automático de banners HTTP/SSH/SSL/SNMP, portas expostas e versões do Nmap, destacando ativos em risco com score CVSS e recomendações de mitigação.",
            "Monitoramento Contínuo (Watchdog): execução em segundo plano para monitorar os dispositivos da aba Favoritos com histerese de falhas, notificações nativas no desktop (QSystemTrayIcon / notify-send) e log de incidentes.",
            "Mapeamento Visual Interativo de Topologia: nova aba com grafo interativo (QGraphicsView) conectando o Gateway padrão, infraestrutura (Switches, Proxmox, NVRs) e endpoints com zoom, arraste e exportação PNG.",
        ],
    },
    {
        "version": "v2.7.1",
        "date": "24/10/2026",
        "title": "Tradução Completa dos Resultados de Scan, Propriedades e Sub-Recursos nos 9 Idiomas & Otimização do Projeto",
        "changes": [
            "Tradução integral dinâmica de todos os itens escaneados na rede nos 9 idiomas suportados (pt_BR, en, es, it, uk, ru, zh_CN, pl, fr).",
            "Tradução de todas as classificações de dispositivos (NVR ONVIF, Câmeras IP, RTSP, Access Points, Proxmox VE, VMs, Servidores Windows/Linux, Impressoras, etc.).",
            "Tradução das linhas filhas de sub-recursos (Stream RTSP, Serviços ONVIF SOAP, Portas NVR, Web HTTP/HTTPS, SMB, FTP, RDP, SSH, Interface de Rede).",
            "Tradução completa da tabela de propriedades do dispositivo (15 campos traduzidos dinamicamente) e do osciloscópio de ping em tempo real.",
            "Re-renderização instantânea de todos os nós das tabelas ao alternar o idioma no menu sem necessidade de reiniciar ou refazer a varredura.",
            "Otimização do ciclo de vida das threads (LivePingWorker e PingSweepWorker) com parada responsiva imediata em menos de 50ms.",
            "Bateria de testes automatizados de ponta a ponta (E2E) com validação de 50 ciclos de stress e 100% de sucesso sem vazamentos.",
        ],
    },
    {
        "version": "v2.7.0",
        "date": "24/10/2026",
        "title": "Suporte Multilíngue (9 Idiomas) & Gerenciamento Customizado da Lista DNS",
        "changes": [
            "Suporte completo a 9 idiomas: Português (Brasil), Inglês, Espanhol, Italiano, Ucraniano, Russo, Chinês Simplificado, Polonês e Francês.",
            "Troca dinâmica de idioma em tempo real via menu ou seletor rápido no Ribbon, com persistência em settings.json.",
            "Gerenciamento completo da lista de servidores DNS: adicionar novo DNS, editar existente, excluir e restaurar padrões de fábrica.",
            "Diálogo dedicado de cadastro com validação de formato IPv4, categorias e seleção de ícones representativos.",
            "Menu de contexto rápido com o botão direito na tabela de benchmark de DNS para edição e remoção direta.",
            "Persistência automática da lista personalizada em ~/.config/linux-ipscan/dns_targets.json.",
        ],
    },
    {
        "version": "v2.6.2",
        "date": "24/10/2026",
        "title": "Abertura Maximizada Auto-Ajustável, Controle de Janela de Diagnóstico, Ping Silencioso & Correção SSL no Windows",
        "changes": [
            "Abertura padrão da janela principal em modo maximizado e auto-ajustado à resolução do monitor.",
            "Cálculo ergonômico da geometria ao desmaximizar (restaurar), centralizando a janela em 90% da área útil do display.",
            "Janela de Teste de Conexão e Benchmark de DNS inicia em tela cheia/maximizada por padrão.",
            "Inclusão de botões nativos de minimizar, maximizar/restaurar e fechar na janela de Diagnóstico de Internet.",
            "Execução 100% silenciosa de testes de ping e ipconfig no Windows (CREATE_NO_WINDOW + SW_HIDE), eliminando o piscar de janelas CMD.",
            "Correção de verificação SSL (CERTIFICATE_VERIFY_FAILED) com suporte a certifi e fallback seguro para auto-atualização no Windows.",
        ],
    },
    {
        "version": "v2.6.1",
        "date": "24/10/2026",
        "title": "Auto-Atualização Universal sem Git, Expansão DNS & Ordenação Dinâmica",
        "changes": [
            "Auto-atualização universal via download direto de ZIP do GitHub para instalações manuais sem Git no Windows e Linux.",
            "Detecção automática de instaladores compilados (.exe / .msi) com integração direta ao GitHub Releases.",
            "Expansão do benchmark com 10 novos provedores DNS primários e secundários (GigaDNS, CleanBrowsing, Control D, Alternate DNS, Mullvad, Comodo, Yandex, Level3, SafeDNS, Neustar UltraDNS).",
            "Tabela dedicada exclusiva para servidores DNS públicos, desacoplando o Gateway e o DNS local para seus próprios cards de métricas.",
            "Ordenação dinâmica crescente e decrescente por tempo de resposta DNS, ping ICMP, perda de pacotes e classificação de qualidade.",
            "Correção de ordenação numérica real (NumericTableWidgetItem) evitando distorção alfabética em milissegundos.",
        ],
    },
    {
        "version": "v2.6.0",
        "date": "24/10/2026",
        "title": "Diagnóstico de Saúde da Internet & Benchmark de Servidores DNS Mundiais",
        "changes": [
            "Botão dedicado '🌐 Testar Internet' no Ribbon e no menu Ações/Ajuda para auditoria completa de conexão WAN.",
            "Teste de latência e integridade do Gateway local e de todos os servidores DNS configurados na placa de rede.",
            "Benchmark comparativo em paralelo dos principais DNS globais e nacionais (Cloudflare, Google, GigaDNS Brasil, CleanBrowsing, Control D, OpenDNS, Quad9, AdGuard, Mullvad, Comodo, Yandex, Level3, SafeDNS, Neustar UltraDNS).",
            "Medição precisa de RTT via query DNS RFC 1035 UDP 53, ping ICMP (mín/méd/máx) e porcentagem de perda de pacotes.",
            "Detecção automática de IP Público (WAN) e exibição de badges com classificação colorida.",
            "Recomendação inteligente destacando o provedor DNS mais veloz (🏆) para a rota do usuário.",
            "Função de exportação com 1 clique do relatório técnico de diagnóstico de conexão para o Clipboard.",
        ],
    },
    {
        "version": "v2.5.0",
        "date": "24/10/2026",
        "title": "Doutor de Aptidão do Sistema, Auto-Instalador de Dependências & Resolução 800x600",
        "changes": [
            "Geração oficial de pacotes pré-compilados: pacote Debian (.deb) para Linux e instaladores .msi e .exe (Inno Setup) para Windows.",
            "Pipeline de compilação contínua no GitHub Actions publicando automaticamente os instaladores (.deb, .msi, .exe) na aba Releases.",
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
