# BLUEPRINT — IP SCAN IGT
**Versão:** 2.11.3 (Edição Multiplataforma: Linux & Windows)  
**Projeto:** IP Scan IGT  
**Repositório GitHub:** [https://github.com/icarogabrielc85-ai/ip-scan-igt](https://github.com/icarogabrielc85-ai/ip-scan-igt)  
**Diretório Local (PC):** `/home/icaro/linux-ipscan`  
**Executável do Sistema (Linux):** `/home/icaro/.local/bin/ip-scan-igt`  
**Pacote Debian (.deb):** `/home/icaro/Área de trabalho/ipscan-igt_2.11.3_amd64.deb`  
**Atalho da Área de Trabalho:** `/home/icaro/Área de trabalho/ip-scan-igt.desktop`  
**Atalho do Menu do Sistema:** `~/.local/share/applications/ip-scan-igt.desktop`  
**Data da Última Atualização:** 29/10/2026  

---

## 1. Visão Geral do Produto

O **IP Scan IGT** é uma ferramenta gráfica profissional de escaneamento, auditoria e diagnóstico de redes locais (LAN) desenvolvida para ambientes **Linux** e **Windows (10/11/Server)** utilizando **Python 3** e **PyQt5**.

Inspirado na usabilidade ágil e visual clássico do consagrado *Advanced IP Scanner*, o IP Scan IGT expande essas capacidades trazendo recursos avançados nativos para ambas as plataformas:
- **Suporte Multilíngue Completo (9 Idiomas) com Tradução Dinâmica Instantânea:**
  - Português do Brasil (`pt_BR`), Inglês (`en`), Espanhol (`es`), Italiano (`it`), Ucraniano (`uk`), Russo (`ru`), Chinês Simplificado (`zh_CN`), Polonês (`pl`) e Francês (`fr`).
  - Tradução integral de resultados de varredura, classificações de dispositivos, sub-recursos filhos, painel de propriedades, osciloscópio de ping e relatórios executivos.
  - Alternância instantânea de idioma em tempo real via menu ou barra superior sem necessidade de reiniciar o programa ou refazer a varredura.
- **Teste de Velocidade da Internet (Speed Test), Velocímetro Gráfico & Benchmark DNS:**
  - Diagnóstico completo organizado em duas abas modernas: `[🚀 Teste de Velocidade]` e `[⚡ Benchmark de Servidores DNS]`.
  - Medição em tempo real de latência (Ping), Jitter, velocidade de Download (Mbps), Upload (Mbps) e taxa prática de transferência (MB/s) via Cloudflare Edge.
  - Velocímetro gráfico estilizado (`SpeedometerWidget`) com arco gradiente, ponteiro luminoso e auto-escala dinâmica até 1000 Mbps.
  - Matriz de Experiência Real (QoE) para Streaming 4K/8K HDR, Jogos Online (gaming competitivo), Videochamadas HD e download prático de arquivos.
  - Benchmark automatizado de provedores globais com classificação de qualidade em cores de alto contraste e gerenciador customizado de DNS.
  - Relatório unificado copiável para a Área de Transferência.
- **Identificador Visual de Porta de Switch (LLDP, Cisco CDP & SNMP Bridge-MIB):**
  - Renderização gráfica realista em rack 19" 1U de switches gerenciáveis (8, 16, 24 ou 48 portas RJ45 com pinos banhados a ouro e uplinks SFP+ de fibra óptica).
  - Identificação exata da porta física em que o computador local está conectado, destacada com animação pulsante, patch cord conectado, LEDs de link (UP/DOWN), VLAN Nativa (PVID), velocidade e diagnóstico.
  - Escuta passiva L2 Ethernet multicast (LLDP IEEE 802.1AB e Cisco CDP) e mapeamento ativo sem necessidade de root via SNMP Bridge-MIB (`dot1dTpFdbTable`).
  - Presets demonstrativos de switches Cisco, Ubiquiti UniFi, MikroTik e Aruba, cópia de relatório técnico e exportação do painel em imagem PNG.
- **Abertura Inteligente Maximizada & Auto-Ajustável:**
  - Aplicação e diálogo de teste iniciam maximizados por padrão adaptados à resolução nativa do monitor.
  - Ao desmaximizar (restaurar), a janela centraliza suavemente em 90% da resolução da tela mantendo o controle ergonômico.
  - Ping e diagnósticos no Windows executados de forma 100% oculta e silenciosa sem popups de janelas CMD.
- **Descoberta Automática de Câmeras IP & NVRs via ONVIF (WS-Discovery UDP 3702)** com extração de perfis e URI tokenizada de streaming RTSP em tempo real.
- **Reprodução Imediata de Transmissões de Vídeo ao Vivo (RTSP 554) via VLC / FFplay** com aceleração por hardware e suporte a H.264 e HEVC/H.265 (4K/5MP).
- **Auditoria via SNMP (UDP 161) em Python Puro:** Codificador/decodificador ASN.1 BER nativo (`snmp_engine.py`) para extrair descrição de hardware, hostname, uptime, número de portas de switches e nível de toner/contador de páginas impressas em impressoras de rede (Printer-MIB).
- **Correlação Automática de Vulnerabilidades (CVEs) via SQLite Local:** Cruza banners HTTP/SSH/SSL/SNMP, modelos ONVIF, portas críticas expostas e versões do Nmap com uma base curada SQLite (`cve_knowledge.db`), destacando dispositivos em risco com score CVSS e orientações de mitigação.
- **Monitoramento Contínuo em Segundo Plano (Watchdog):** Vigia 24/7 os ativos da aba Favoritos com histerese configurável de falhas, emitindo notificações nativas no desktop (`QSystemTrayIcon` e `notify-send`) em caso de queda ou recuperação e registrando histórico persistente de incidentes.
- **Mapeamento Visual Interativo de Topologia (NOC Graph):** Grafo interativo (`QGraphicsView`/`QGraphicsScene`) na 3ª aba principal ilustrando como Gateway, Switches/Proxmox/NVRs e Endpoints se interconectam, com layouts Radial e em Camadas, cores por latência, alerta visual de risco CVE e exportação PNG.
- **Network Guard (Detecção de Intrusos L2, Conflito de IP e ARP Spoofing):** Vigia os vínculos IP-MAC e o MAC do Gateway para detectar sequestro de rota (*ARP Spoofing / MitM*), troca abrupta de placa (*Conflito de IP*) e entrada de dispositivos não autorizados (*Intrusos*), com controle de Whitelist de MACs confiáveis.
- **Snapshots de Auditoria & Comparador de Mudanças (Baseline Diff):** Permite salvar fotografias completas da rede e compará-las com qualquer varredura futura, destacando em cores novos hosts (`🟢 +Novo`), servidores que sumiram (`🔴 -Ausente`) e portas/CVEs modificadas (`🟠 ~Modificado`).
- **Relatório Executivo HTML / PDF Autocontido com Topologia Embutida:** Gera laudo técnico completo com **Score de Segurança da Rede (0–100)**, **Mapa Visual de Topologia em Base64 PNG**, **Matriz de Vulnerabilidades (CVEs)** e **Telemetria de Infraestrutura SNMP/Impressoras/UPnP**.
- **Descoberta UPnP / SSDP (UDP 1900) & Traceroute Visual por Saltos (TTL):** Identifica modelo exato, fabricante e número de série de Smart TVs, roteadores Mesh e IoT via XML UPnP, além de rastrear visualmente cada salto (hop) de rota com grafo de latência.
- **Integração Total com Nmap** operando em espaço de usuário (*user-space* sem necessidade de `sudo` no Linux e detecção automática no Windows).
- **Osciloscópio de Ping Instantâneo Dinâmico** com gráfico em tempo real e resolução sub-milissegundo.
- **Compilação e Empacotamento Automatizado Multiplataforma:**
  - Pacote Debian `.deb` oficial para Ubuntu, Debian, Mint e Pop!_OS.
  - Instalador Assistente `.exe` (Inno Setup) e Pacote corporativo `.msi` (WiX) para Windows.
  - Executável portátil standalone `.exe` sem dependências para Windows.

---

## 2. Diagrama de Arquitetura do Sistema

```mermaid
flowchart TD
    subgraph UI_Layer["Camada de Apresentação (PyQt5 Modern 2-Tier Ribbon & NOC Suite)"]
        MW["MainWindow (IP Scan IGT v2.9.2)"]
        TB1["Tier 1 Header: Brand, Scan ▶, Seletor IP ▾, Faixa IP, Máscara, Busca, Atualizar 🔄"]
        TB2["Tier 2 Ribbon: Expandir/Recolher, ONVIF, Nmap, Internet Test, Watchdog 🛡️, Relatório ▾, Tema, Idioma, KPIs (Online, Ping, Serviços, CVEs ⚠️)"]
        TABS["Abas Principais: [Resultados] • [Favoritos] • [🗺️ Topologia da Rede]"]
        TREE["QTreeWidget com DeviceTreeWidgetItem (Ordenação Numérica IP / Ping, Badges CVE & SNMP)"]
        TOPO["topology_widget.py (Grafo Interativo QGraphicsView: Gateway ➔ Infra ➔ Endpoints)"]
        BP["Painel Inferior: Osciloscópio Live Ping & Ações Categorizadas (Web, RDP, SSH, WoL, RTSP)"]
        NMAP_DLG["NmapDialog (Relatório Estruturado, Aba Vulnerabilidades CVEs & Terminal Nmap)"]
        WD_DLG["WatchdogDialog & QSystemTrayIcon (Configuração, Histerese & Histórico de Quedas)"]
        IFACE_DLG["NetworkInterfaceDialog (Seletor Detalhado de Placas de Rede)"]
    end

    subgraph Core_Engines["Motores de Escaneamento, Segurança e Observabilidade"]
        SE["scanner_engine.py (Multithread: 64 Threads, Dual-Platform)"]
        SNMP["snmp_engine.py (Cliente UDP 161 ASN.1 BER: MIB-II & Printer-MIB)"]
        CVE["cve_engine.py (Correlação SQLite de Vulnerabilidades CVEs & CVSS)"]
        WD["watchdog_engine.py (WatchdogWorker Background Ping & Notificações Nativas)"]
        OE["onvif_engine.py (WS-Discovery Multicast UDP 3702, GetStreamUri & Players)"]
        NE["nmap_engine.py (Nmap Portátil & Regex Parser de Versões)"]
        OUI["oui_db.py (Base OUI IEEE: 40.000+ Fabricantes em Memória)"]
        TH["ui_theme.py (Advanced IP Scanner Light & Dark Themes)"]
    end

    subgraph Dual_Platform_OS["Abstração de Sistema Operacional (Linux & Windows)"]
        direction TB
        subgraph Linux_OS["Linux"]
            L_ARP["/proc/net/arp & ip neigh"]
            L_NET["/sys/class/net/* & ip route"]
            L_PING["ping -n -c 1 -W"]
            L_VID["/usr/bin/ffplay & /usr/bin/vlc"]
            L_NOTIFY["QSystemTrayIcon & notify-send"]
        end
        subgraph Windows_OS["Windows"]
            W_ARP["arp -a"]
            W_NET["ipconfig /all & route print"]
            W_PING["ping -n 1 -w (CREATE_NO_WINDOW)"]
            W_VID["Program Files VLC / ffplay.exe"]
            W_NOTIFY["QSystemTrayIcon & AppUserModelID"]
        end
    end

    MW --> TB1
    MW --> TB2
    MW --> TABS
    TABS --> TREE
    TABS --> TOPO
    MW --> BP
    MW --> NMAP_DLG
    MW --> WD_DLG
    MW --> IFACE_DLG

    MW --> SE
    MW --> WD
    SE --> SNMP
    SE --> CVE
    NE --> CVE
    SE --> OE
    MW --> NE
    SE --> OUI
    MW --> TH

    SE --> Linux_OS
    SE --> Windows_OS
    WD --> Linux_OS
    WD --> Windows_OS
    TOPO --> Linux_OS
    TOPO --> Windows_OS
```

---

## 3. Módulos e Estrutura de Arquivos

| Arquivo / Caminho | Responsabilidade / Função |
| :--- | :--- |
| [`main.py`](file:///home/icaro/linux-ipscan/main.py) | Ponto de entrada da aplicação, janela principal (`MainWindow`), ciclo de vida de threads (`ScanWorker`, `LivePingWorker`), menu bar, atalhos, exportação de relatórios (CSV, JSON, TXT), registro de AppID no Windows e persistência de Favoritos. |
| [`scanner_engine.py`](file:///home/icaro/linux-ipscan/scanner_engine.py) | Motor de varredura multithread (ThreadPoolExecutor). Abstração multiplataforma para ping com sub-milissegundo (Linux e Windows), tabela ARP (`/proc/net/arp` e `arp -a`), enumeração de placas (`iproute2` e `ipconfig`), banners HTTP/SSH, inspeção de certificados SSL em Python puro (`ssl.get_server_certificate`), classificação automática de SO e gateways padrão. |
| [`onvif_engine.py`](file:///home/icaro/linux-ipscan/onvif_engine.py) | Motor de descoberta ONVIF via WS-Discovery multicast (`239.255.255.250:3702`), decodificador de scopes XML, resolução de token RTSP dinâmico via `GetStreamUri` (suporte a Xiongmai XM530, Hikvision, Dahua, Intelbras), probe RTSP (554) e detecção/disparo automático de players de vídeo (FFplay / VLC) em Linux e Windows. |
| [`nmap_engine.py`](file:///home/icaro/linux-ipscan/nmap_engine.py) | Wrapper portável para execução assíncrona do Nmap sem privilégios de root (`-sT`), streaming de saída linha a linha (`NmapScannerThread`), parser regex de portas/serviços/versões, detecção automática do `nmap.exe` no Windows e gerador de diagnóstico inteligente de dispositivos. |
| [`nmap_dialog.py`](file:///home/icaro/linux-ipscan/nmap_dialog.py) | Interface moderna de auditoria do Nmap (`NmapDialog`) com abas divididas entre **Relatório Estruturado**, **Vulnerabilidades (CVEs)** e **Terminal Nmap**. |
| [`snmp_engine.py`](file:///home/icaro/linux-ipscan/snmp_engine.py) | Motor SNMPv1/v2c (UDP 161) em Python puro (ASN.1 BER) para extração de `sysDescr`, `sysName`, `sysUpTime`, contagem de interfaces de switches e níveis de toner/páginas em impressoras (Printer-MIB). |
| [`cve_engine.py`](file:///home/icaro/linux-ipscan/cve_engine.py) | Motor de correlação de vulnerabilidades (CVEs) com banco SQLite local (`cve_knowledge.db`), cruzando banners HTTP/SSH/SSL/SNMP, portas expostas e versões do Nmap com cálculo de risco CVSS e recomendações de mitigação. |
| [`watchdog_engine.py`](file:///home/icaro/linux-ipscan/watchdog_engine.py) | Motor de monitoramento contínuo em segundo plano (`WatchdogWorker` + `WatchdogDialog`) para os dispositivos em Favoritos com histerese de falhas, notificações nativas no desktop (`QSystemTrayIcon` / `notify-send`) e histórico persistente de incidentes. |
| [`topology_widget.py`](file:///home/icaro/linux-ipscan/topology_widget.py) | Grafo visual interativo de topologia de rede (`NetworkTopologyWidget` via `QGraphicsView`/`QGraphicsScene`) conectando Gateway, Switches/Hipervisores/NVRs e Endpoints com zoom, arraste, filtro por risco, barra deslizante de espaçamento/densidade de nós (50% a 300%) e exportação PNG / Base64. |
| [`network_guard_engine.py`](file:///home/icaro/linux-ipscan/network_guard_engine.py) | Motor de segurança L2 (`NetworkGuardEngine` + `NetworkGuardDialog`) para detecção de ataques de **ARP Spoofing** (sequestro de MAC do Gateway), **Conflito de IP** (troca de placa) e **Novos Dispositivos Intrusos**, com Whitelist de MACs confiáveis. |
| [`snapshot_engine.py`](file:///home/icaro/linux-ipscan/snapshot_engine.py) | Motor de **Snapshots de Auditoria & Comparador de Mudanças (Baseline Diff)** (`SnapshotManager` + `SnapshotDiffDialog`), destacando novos hosts (`🟢`), servidores ausentes (`🔴`) e portas/CVEs/MAC modificados (`🟠`). |
| [`upnp_engine.py`](file:///home/icaro/linux-ipscan/upnp_engine.py) | Descoberta multicast e unicast **UPnP / SSDP (UDP 1900)** com parser de XML RootDevice para extrair fabricante, modelo exato e número de série de Smart TVs, roteadores Wi-Fi Mesh, Chromecasts e IoT. |
| [`traceroute_dialog.py`](file:///home/icaro/linux-ipscan/traceroute_dialog.py) | Ferramenta gráfica de **Traceroute Visual por Saltos (TTL)** (`TracerouteWorker` + `TracerouteDialog`) com grafo encadeado de roteadores intermediários e diagnóstico de latência por salto. |
| [`lldp_engine.py`](file:///home/icaro/linux-ipscan/lldp_engine.py) | Motor de descoberta L2 **LLDP (IEEE 802.1AB)**, **Cisco CDP** e mapeamento SNMP Bridge-MIB (`dot1dTpFdbTable`), extraindo modelo do switch, IP de gerência, VLAN, capacidades, número total de portas e a porta física exata em que o computador está conectado. |
| [`lldp_dialog.py`](file:///home/icaro/linux-ipscan/lldp_dialog.py) | Janela dedicada (`LLDPSwitchDialog`) com controles de escuta passiva L2, consulta SNMP, seletor de placas e cards informativos detalhados de infraestrutura. |
| [`switch_visual_widget.py`](file:///home/icaro/linux-ipscan/switch_visual_widget.py) | Componente gráfico vetorial de alta precisão (`SwitchFrontPanelWidget`) que renderiza o painel frontal 1U de switch em rack de 19" (8, 16, 24 ou 48 portas RJ45 + SFP+ uplinks), destacando com animação pulsante, patch cord conectado e badge a porta física conectada. |
| [`interface_dialog.py`](file:///home/icaro/linux-ipscan/interface_dialog.py) | Janela modal de seleção de placas de rede (`NetworkInterfaceDialog`), listando adaptadores físicos, Wi-Fi, VPNs e bridges com IP, CIDR, faixa calculada, MAC, Gateway e velocidade de link. |
| [`config_paths.py`](file:///home/icaro/linux-ipscan/config_paths.py) | Abstração de caminhos e diretórios de configuração multiplataforma (`get_config_dir` / `get_config_file`), garantindo persistência nativa em `%APPDATA%\IPScanIGT` no Windows e `~/.config/linux-ipscan/` no Linux, com migração automática transparente. |
| [`oui_db.py`](file:///home/icaro/linux-ipscan/oui_db.py) | Mecanismo de resolução OUI (Organizationally Unique Identifier) com suporte a pacotes congelados PyInstaller (`sys._MEIPASS`) para tradução instantânea de MACs para nomes de fabricantes. |
| [`mac-vendors.txt`](file:///home/icaro/linux-ipscan/mac-vendors.txt) | Base de dados offline contendo mais de 40.000 prefixos MAC catalogados pela IEEE. |
| [`ui_theme.py`](file:///home/icaro/linux-ipscan/ui_theme.py) | Folhas de estilo QSS (Light Theme idêntico ao Advanced IP Scanner e Dark Theme moderno), além da implementação do componente gráfico de osciloscópio (`LivePingOscilloscope`). |
| [`icon.png`](file:///home/icaro/linux-ipscan/icon.png) | Ícone oficial PNG em alta resolução. |
| [`icon.ico`](file:///home/icaro/linux-ipscan/icon.ico) | Ícone oficial multi-resolução para Windows (16x16 até 256x256). |
| [`build_windows.bat`](file:///home/icaro/linux-ipscan/build_windows.bat) | Script em lote de 1 clique para compilação do executável portátil `dist\IPScanIGT.exe` no Windows. |
| [`build_linux.sh`](file:///home/icaro/linux-ipscan/build_linux.sh) | Script em lote para compilação do binário portátil `dist/IPScanIGT` no Linux. |
| [`ipscan_windows.spec`](file:///home/icaro/linux-ipscan/ipscan_windows.spec) | Arquivo de especificação do PyInstaller para empacotar a versão Windows sem console e com ícones. |
| [`ipscan_linux.spec`](file:///home/icaro/linux-ipscan/ipscan_linux.spec) | Arquivo de especificação do PyInstaller para empacotar o executável Linux autônomo. |
| [`.github/workflows/build.yml`](file:///home/icaro/linux-ipscan/.github/workflows/build.yml) | Automação de CI/CD que compila executáveis oficiais de Linux e Windows na nuvem a cada `git push`. |
| `~/.local/bin/ip-scan-igt` | Shell script wrapper que resolve `DISPLAY`, `XAUTHORITY` dinâmico e executa o aplicativo em qualquer sessão gráfica. |
| `~/Área de trabalho/ip-scan-igt.desktop` | Atalho da Área de Trabalho com permissão de execução liberada no desktop. |
| `~/.local/share/applications/ip-scan-igt.desktop` | Arquivo `.desktop` padrão FreeDesktop para integração com KDE Plasma, GNOME, XFCE e menus de aplicativos do sistema. |

---

## 4. Protocolos e Técnicas de Descoberta

### 4.1. Camada de Sondagem de Presença (Host Alive)
1. **Sondagem ICMP / TCP Syn-Connect:**
   - Linux: `ping -n -c 1 -W <sec> <ip>`.
   - Windows: `ping -n 1 -w <ms> <ip>` com flag de processo oculto (`CREATE_NO_WINDOW = 0x08000000`).
   - Medição de latência com precisão de microssegundos via `time.perf_counter()`.
2. **Resolução de Hardware ARP em Camada 2:**
   - Linux: leitura direta de `/proc/net/arp` e `ip neigh show`.
   - Windows: leitura via `arp -a` com normalização de formatos de hífens para dois-pontos.
   - Garante **zero falsos negativos** mesmo para dispositivos que silenciam ping ICMP.

### 4.2. Descoberta de Nomes e Serviços
- **NetBIOS Name Service (UDP 137):** Envio de query de status de nó (`CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`) para extrair nome da estação e grupo de trabalho/domínio Windows.
- **mDNS / Bonjour (UDP 5353) & LLMNR (UDP 5355):** Resolução de nomes locais para dispositivos Apple, Linux, impressoras e Smart TVs.
- **SMB2 / NTLMSSP Negotiate (TCP 445):** Extração de nomes DNS completos e domínio corporativo sem necessidade de autenticação.
- **Banners HTTP / HTTPS (TCP 80, 443, 8080, 8443, 8006):** Obtenção de títulos HTML e cabeçalhos `Server`.
- **Inspeção de Certificados SSL/TLS (TCP 443, 8443, 8006):** Decodificação nativa em Python via `ssl` (extração de CommonName e Subject Alternative Name DNS) sem dependência de utilitários externos.
- **Banner SSH (TCP 22):** Identificação exata da distribuição Linux (ex: `OpenSSH_8.9p1 Ubuntu`).

### 4.3. Câmeras de Segurança e Gravadores (ONVIF & RTSP)
- **WS-Discovery Multicast (UDP 3702 para 239.255.255.250):** Probe SOAP com tipo `dn:NetworkVideoTransmitter`.
- **Parsing de Scopes & Media Service (`GetStreamUri`):** Extração de Fabricante, Modelo de Hardware, Nome da Câmera e resolução dinâmica do URI exato de streaming RTSP via SOAP (`GetProfiles` e `GetStreamUri`), resolvendo autenticação de sessão e caminhos específicos de fabricantes (ex: Xiongmai XM530, Hikvision, Dahua, Intelbras).
- **Verificação e Reprodução RTSP (TCP 554):** Handshake `OPTIONS rtsp://...` com envio de User-Agent `IPScanIGT`. Execução instantânea com baixa latência via FFplay (`-rtsp_transport tcp`) com suporte total a streams 1080p H.264 e 5MP HEVC/H.265, com fallback para VLC player em Linux e Windows.

### 4.4. Auditoria Nmap em Espaço de Usuário
- Linux: Executável Nmap 7.94 com carregamento de bibliotecas dinâmicas via `LD_LIBRARY_PATH` próprio e `NMAPDIR`.
- Windows: Detecção automática da instalação padrão do Nmap (`C:\Program Files (x86)\Nmap\nmap.exe` e `PATH`).
- Perfis de escaneamento sem privilégios de root (`-sT` TCP Connect), permitindo auditoria profunda de portas altas, serviços e versões sem exigir senha de administrador.

### 4.5. Auditoria de Infraestrutura via SNMP (UDP 161)
- Implementação **100% Python puro** com codificação e decodificação ASN.1 BER (`SNMPv2c` / `SNMPv1` `GetRequest`), sem necessidade de bibliotecas C externas.
- **MIB-II (`1.3.6.1.2.1.1.*` e `1.3.6.1.2.1.2.1.0`):** Extração de `sysDescr` (modelo/OS de roteador ou switch), `sysUpTime` formatado em dias/horas/minutos, `sysName`, `sysLocation` e contagem de interfaces de rede (`ifNumber`) para identificar switches gerenciáveis.
- **Printer-MIB (`1.3.6.1.2.1.43.*`):** Consulta automática de `prtMarkerLifeCount` (contador total de páginas impressas) e cálculo percentual do nível de suprimento/toner (`prtMarkerSuppliesLevel` / `prtMarkerSuppliesMaxCapacity`).

### 4.6. Correlação de Vulnerabilidades (CVEs via SQLite)
- Base de conhecimento local em SQLite (`~/.config/linux-ipscan/cve_knowledge.db` no Linux ou `%APPDATA%\IPScanIGT\cve_knowledge.db` no Windows) inicializada automaticamente pelo módulo [`cve_engine.py`](file:///home/icaro/linux-ipscan/cve_engine.py).
- Cruza expressões regulares e faixas SemVer (`version_min`..`version_max`) contra banners HTTP, SSH, SMB, SSL, SNMP (`public` exposto), portas legadas de alto risco (Telnet 23, FTP 21, RDP 3389) e a saída detalhada de versões do Nmap (`-sV`).
- Classifica vulnerabilidades por severidade (**CRITICAL**, **HIGH**, **MEDIUM**) com pontuação CVSS, destacando em vermelho/laranja os hosts vulneráveis na árvore principal e exibindo um painel dedicado de CVEs na janela do Nmap.

### 4.7. Monitoramento Contínuo em Segundo Plano (Watchdog)
- Motor assíncrono [`WatchdogWorker`](file:///home/icaro/linux-ipscan/watchdog_engine.py) (`QThread`) que monitora periodicamente os dispositivos salvos na aba **Favoritos** usando o motor de ping silencioso.
- **Histerese de Falhas:** Só dispara alerta de *Host Down* após atingir o limiar configurável de falhas consecutivas (padrão: 2 falhas), evitando falsos positivos por perda isolada de pacote.
- **Notificações Desktop & Log Persistente:** Emite alertas nativos via `QSystemTrayIcon.showMessage()` e `notify-send` (Linux) tanto na queda quanto na recuperação (*Host Recovered*), gravando o histórico de incidentes em `~/.config/linux-ipscan/watchdog_events.json` (Linux) ou `%APPDATA%\IPScanIGT\watchdog_events.json` (Windows).

### 4.8. Mapeamento Visual de Topologia (Grafo NOC Interativo)
- Renderização vetorial via `QGraphicsView` / `QGraphicsScene` ([`NetworkTopologyWidget`](file:///home/icaro/linux-ipscan/topology_widget.py)) integrada diretamente como a 3ª aba principal (**`🗺️ Topologia da Rede`**).
- Descoberta automática do **Default Gateway** local (`/proc/net/route`, `ip route` ou `route print`) posicionado como nó central da topologia.
- **Inferência Inteligente de Enlaces:** Conecta automaticamente VMs ao hipervisor Proxmox da rede, câmeras IP ao NVR/Gravador correspondente e demais estações aos Switches gerenciáveis ou ao Gateway principal.
- **Modos Radial (NOC) e Hierárquico (Camadas):** Nós arrastáveis, zoom suave via roda do mouse, links coloridos pela latência de ping (`<5ms` verde, `5-30ms` azul, `>30ms` âmbar), halos pulsantes de alerta para hosts com CVEs críticas e exportação direta do mapa para imagem **PNG** e **Base64**.

### 4.9. Network Guard — Detecção de Intrusos, Conflito de IP e ARP Spoofing
- Monitoramento em Camada 2 ([`network_guard_engine.py`](file:///home/icaro/linux-ipscan/network_guard_engine.py)) com persistência em `~/.config/linux-ipscan/network_guard.json` (Linux) ou `%APPDATA%\IPScanIGT\network_guard.json` (Windows).
- **ARP Spoofing (`CRITICAL`):** Alerta imediatamente se o MAC do Gateway padrão mudar ou se outro endereço IP na rede passar a anunciar o mesmo endereço MAC físico do Gateway.
- **Conflito de IP (`HIGH`):** Detecta quando um endereço IP ativo na sub-rede muda abruptamente de endereço MAC físico.
- **Novos Dispositivos / Intrusos (`WARNING`):** Identifica placas de rede inéditas que ainda não constam na Whitelist de MACs confiáveis aprovados pelo administrador.

### 4.10. Snapshots de Auditoria & Comparador de Mudanças (Baseline Diff)
- Armazenamento de fotografias completas da rede ([`snapshot_engine.py`](file:///home/icaro/linux-ipscan/snapshot_engine.py)) em `~/.config/linux-ipscan/snapshots.json` (Linux) ou `%APPDATA%\IPScanIGT\snapshots.json` (Windows).
- Algoritmo de comparação estrutural (`compare_host_maps`) que cruza qualquer Snapshot Base com a varredura ao vivo, classificando:
  - 🟢 **Novos Hosts (`ADDED`):** Dispositivos que entraram na rede desde a última auditoria;
  - 🔴 **Hosts Ausentes (`REMOVED`):** Servidores ou equipamentos que saíram da rede;
  - 🟠 **Hosts Modificados (`MODIFIED`):** Alterações exatas de portas TCP (`+Portas Abertas`, `-Portas Fechadas`), novas CVEs (`+Novas CVEs`), troca de MAC ou mudança de Hostname.

### 4.11. Relatório Executivo de Auditoria HTML / PDF Autocontido
- Gerador de laudo executivo e técnico (`generate_executive_html_report` em [`main.py`](file:///home/icaro/linux-ipscan/main.py)) pronto para impressão nativa em PDF (`window.print()`).
- Inclui **Score de Segurança da Rede (0–100 e Conceito A–F)**, **Mapa Visual de Topologia da Rede embutido em Base64 PNG**, **Matriz Completa de Vulnerabilidades (CVEs)** com CVSS e mitigação, e tabela dedicada de **Infraestrutura SNMP, Impressoras e UPnP**.

### 4.12. Descoberta UPnP / SSDP (UDP 1900) & Traceroute Visual
- **SSDP Multicast & Unicast ([`upnp_engine.py`](file:///home/icaro/linux-ipscan/upnp_engine.py)):** Envia pacotes `M-SEARCH` para `239.255.255.250:1900`, coleta o header `LOCATION` e faz o parse do XML UPnP (`friendlyName`, `manufacturer`, `modelName`, `serialNumber`, `presentationURL`).
- **Traceroute Visual ([`traceroute_dialog.py`](file:///home/icaro/linux-ipscan/traceroute_dialog.py)):** Sondagem iterativa salto a salto (`TTL 1..30`) compatível com Linux e Windows sem exigir privilégios de root, desenhando um grafo encadeado de roteadores com código de cores por latência RTT.

### 4.13. Identificador Visual de Porta de Switch (LLDP, Cisco CDP & SNMP Bridge-MIB)
- **Painel Frontal Vetorial 1U ([`switch_visual_widget.py`](file:///home/icaro/linux-ipscan/switch_visual_widget.py)):** Renderização gráfica ultra-precisa da carcaça de 19 polegadas com aletas de montagem em rack, slots modulares de 8, 16, 24 e 48 portas RJ45 com pinos de contato em ouro, slots SFP/SFP+ de fibra óptica, LEDs de link ativo/down e animação contínua de pulso neon com patch cord conectado indicando a porta física onde a estação está conectada.
- **Escuta Passiva L2 ([`lldp_engine.py`](file:///home/icaro/linux-ipscan/lldp_engine.py)):** Sniffer nativo de pacotes multicast Ethernet L2 (`01:80:C2:00:00:0E` para LLDP IEEE 802.1AB e `01:00:0C:CC:CC:CC` para Cisco CDP) com decodificador completo de TLVs: Chassis ID, Port ID, TTL, Port Description, System Name, System Description, System Capabilities (Bridge/Router), Management Address IPv4 e VLAN Nativa / PVID (IEEE 802.1 OUI `00:80:c2`).
- **Mapeamento Ativo via SNMP Bridge-MIB:** Para ambientes sem permissões de socket raw, consulta direta via UDP 161 nas tabelas padrão `dot1dBasePortIfIndex` e `dot1dTpFdbTable`, cruzando o endereço MAC da placa de rede local contra as tabelas de forwarding do switch para localização física exata da porta sem precisar de privilégios de administrador.
- **Janela Interativa & Exportação ([`lldp_dialog.py`](file:///home/icaro/linux-ipscan/lldp_dialog.py)):** Seletor de placas de rede locais, campo para IP do switch alvo, credenciais de autenticação Web (usuário/senha), foco exclusivo em switches reais encontrados na rede local (sem modos simulados artificiais), consulta automática na inicialização, cards detalhados com informações L2/L3, cópia de relatório técnico formatado e exportação de foto do painel frontal em alta resolução PNG.

### 4.14. Auditoria Híbrida Web/SNMP, Decodificação de Bitmaps L2 e Blindagem do Sniffer (v2.11.3)
- **Motor Híbrido Web/SNMP para Switches Airoha / EcoNet / FreeRTOS (`probe_switch_web_airoha` em [`lldp_engine.py`](file:///home/icaro/linux-ipscan/lldp_engine.py)):**
  - Muitos switches compactos modernos (SoCs Airoha EN8851, MediaTek, EcoNet, Realtek gerenciáveis sob FreeRTOS) respondem a SNMP MIB-II básico (SysDescr, SysName, Uptime, ifNumber=24), mas retornam `noSuchName` para tabelas Bridge-MIB (`dot1dTpFdbTable`) e `ifOperStatus`.
  - O motor híbrido detecta esse padrão de assinatura e aciona automaticamente a auditoria via API Web HTTP:
    1. **Autenticação Segura:** POST para `/logon.cgi` com senha hash SHA-256 e extração do cookie de sessão `Cookies=user=admin`.
    2. **Extração de Estado Elétrico Real das Portas:** Leitura de `/portCur.xml`, identificando individualmente o link físico (UP/DOWN) de cada uma das 24 portas RJ45.
    3. **Tabela de Encaminhamento MAC (FDB):** Inicialização via `/freshdynamicmac.cgi?firstreq=1&times=4` seguida de extração em lote de `/dynamicmacentry.xml`.
    4. **Desconexão Limpa Obrigatória:** Execução imediata de GET `/logout.cgi` ao final da auditoria, prevenindo bloqueio monousuário (`allow = 0`) no firmware do switch.
- **Decodificação de Bitmaps de Portas Físicas (L2 Port Bitmap Architecture):**
  - Switches baseados no SDK Airoha/EcoNet codificam a associação porta-MAC como uma máscara de bits onde o **Bit 0 (`0x1`) é reservado para a CPU/gerenciamento interno**, e cada porta física `r` corresponde a `(1 << r)` (`0x2` = Porta 1, `0x10000` = Porta 16).
  - O algoritmo traduz com fidelidade matemática essa topologia:
    - **Porta 1 (Bit 1 / `0x2`):** Porta de Uplink ativa (`🟢 UP`) onde trafegam os múltiplos MACs de Gateway, Proxmox, servidores e Access Points.
    - **Porta 16 (Bit 16 / `0x10000`):** Porta local conectada (`🟢 CONNECTED`) onde reside exclusivamente o MAC da placa do usuário (`enp7s0`).
    - **Portas 2–15 e 17–24:** Portas sem link (`⚪ DOWN`).
- **Medição Física de Cabo de Rede via TDR (Time Domain Reflectometry / Virtual Cable Tester):**
  - Switches gerenciáveis modernos (incluindo o Airoha EN8851) possuem reflectômetro por hardware acoplado aos transceivers Gigabit PHY (`/cablediag.cgi` e `/cableCur.xml`).
  - O IP Scan IGT dispara automaticamente a reflectometria na porta conectada (e sob demanda em qualquer porta clicada no rack 1U via botão `⚡ Medir Cabo (TDR)`), calculando com precisão:
    - **Comprimento Físico Real do Cabo em Metros:** Resolução de 0,1 metro (ex: 8,0 metros para a Porta 16 / PC, 2,4 metros para a Porta 1 / Uplink).
    - **Integridade Elétrica dos 4 Pares de Fios de Cobre:** Análise individual do Par A (pinos 1-2), Par B (pinos 3-6), Par C (pinos 4-5) e Par D (pinos 7-8), classificando o estado em **Normal (Íntegro)**, **Aberto (Rompido / Desconectado)** ou **Curto-circuito**.
    - **Exibição Gráfica no Card de Porta & Exportação:** Resultados destacados com badges coloridos e incorporados ao relatório técnico executivo da auditoria.

- **Blindagem do Sniffer L2 e Teste Proativo de Capacidades (`l2_sniffer.c`):**
  - Implementação da flag `--test-cap` / `-t` no executável C auxiliar para validar se o kernel Linux autoriza a criação do raw socket `AF_PACKET` / `SOCK_RAW`.
  - A função `check_sniffer_binary_cap()` do Python executa o teste prévio, impedindo o erro de permissão *"Address family not supported"* e selecionando dinamicamente o melhor binário com `CAP_NET_RAW` (`~/.local/bin/ipscan-l2-sniffer`).
  - Suporte expandido a tags 802.1Q (VLAN ID) e 802.1ad (QinQ) no tratador do sniffer C.

### 4.15. Diagnóstico e Medição de Cabo de Rede via Placa Local (NIC)
- **Operação Direta pela Interface de Rede Selecionada ([`cable_diagnostic_engine.py`](file:///home/icaro/linux-ipscan/cable_diagnostic_engine.py)):**
  - Permite realizar o diagnóstico elétrico e a medição métrica do cabo de rede diretamente pela placa de rede selecionada pelo usuário (ex: `enp7s0`, Realtek RTL8111/8168/8411, Intel e1000e/I219/I225, etc.), sem depender de credenciais de switch, firmwares remotos ou modelos específicos de equipamentos.
  - **Identificação do Controlador Físico:** Extrai via `ethtool -i` e `lspci` o nome do hardware, fabricante, versão de firmware e barramento PCI.
  - **Validação de Continuidade dos 4 Pares Trançados (8 Vias):** Baseado na norma IEEE 802.3ab 1000BASE-T (PAM-5), onde a negociação de link Gigabit requer obrigatoriamente a integridade simultânea dos 4 pares (Par A pinos 1-2, Par B pinos 3-6, Par C pinos 4-5 e Par D pinos 7-8). Detecta degradação de link (ex: queda para 100 Mbps Fast Ethernet por rompimento nos pares C ou D).
  - **Medição do Comprimento do Cabo em Metros:** Calcula a extensão física do lance de cabo de rede com base no tempo de propagação do sinal e latência física sub-microssegundo da camada de enlace ($V_p \approx 0.66c \approx 200\text{ m/}\mu s$), fornecendo a métrica precisa (ex: 8,0 metros).
  - **Análise de Ruído Eletromagnético (EMI / CRC):** Monitoramento de contadores de hardware em `/sys/class/net/<iface>/statistics/` (`rx_crc_errors`, `rx_frame_errors`) para certificar que o cabo opera livre de indução eletromagnética e perda de frames.
  - **Estabilidade do Conector Físico RJ45:** Avaliação de transições de portadora (`carrier_changes`) para detectar mau contato, conectores mal crimpados ou oscilações de link (flapping).
  - **Certificação da Categoria do Cabo:** Emite parecer técnico validando se o cabo cumpre os requisitos normativos para Cat 5e / Cat 6 Gigabit Ethernet.
- **Janela Interativa de Diagnóstico de Cabo ([`cable_diagnostic_dialog.py`](file:///home/icaro/linux-ipscan/cable_diagnostic_dialog.py)):**
  - Acessível pelo atalho global **`Ctrl + K`** na tela principal ou pelo menu **Ferramentas > Diagnóstico de Cabo de Rede (NIC)**.
  - Botão dedicado **`⚡ Medir Cabo da Placa`** integrado diretamente no Identificador de Switch (`lldp_dialog.py`) ao lado do seletor de interfaces.
  - Interface moderna com display de grande escala para o comprimento métrico, grid visual dos 4 pares com badges coloridos de integridade (`🟢 Normal / Conectado`), painel de ruído/EMI e estabilidade, e botão para copiar o laudo técnico completo para a área de transferência.

---

## 5. UI/UX Design System e Regras de Interface

1. **Aparência e Fidelidade Visual:**
   - Barra de ferramentas clássica superior com botão verde vibrante `▶  Verificar`, botão seletor de sub-rede `IP ▾`, campos de faixa de IP, seletor de máscara (`/24`, `/16`, etc.) e botão de monitoramento `🛡️ Watchdog`.
   - Abas principais de largura total: **[Resultados]**, **[Favoritos]** e **[🗺️ Topologia da Rede]**.
2. **Classificação Dinâmica Inteligente ([`DeviceTreeWidgetItem`](file:///home/icaro/linux-ipscan/main.py)):**
   - **IP (Col 2):** Ordenação numérica por octetos `(192, 168, 111, 1)` em vez de texto bruto.
   - **Ping (Col 5):** Ordenação por milissegundos numéricos; estações offline são empurradas para o final no modo crescente.
   - **Nome / Fabricante / MAC:** Ordenação alfabética case-insensitive.
   - **Status (Col 0):** Dispositivos online (`●`) ordenados prioritariamente.
   - Indicador visual nativo com setas **▲ / ▼** no cabeçalho e feedback textual na barra de status.
3. **Hierarquia, Segurança e Limpeza Visual:**
   - Itens de dispositivos mantêm-se **recolhidos por padrão**, apresentando uma linha limpa por host online.
   - Dispositivos com CVEs detectadas exibem badge `[⚠️ N CVE]` e coloração semântica de risco (vermelho para `CRITICAL`/`HIGH`, laranja para `MEDIUM`).
   - Sub-recursos `[+]` agrupam portas, serviços web/vídeo, telemetria SNMP (uptime, portas, toner/páginas) e alertas de CVE sem quebrar a visualização principal.
4. **Osciloscópio de Ping em Tempo Real ([`LivePingOscilloscope`](file:///home/icaro/linux-ipscan/ui_theme.py)):**
   - Gráfico de onda contínua atualizado a cada 500ms para o dispositivo selecionado, com histórico dos últimos 60 pings, média, pico e indicação de perda de pacotes.

---

## 6. Comandos e Guia de Execução

### Como iniciar o aplicativo no Linux:
- **Pela Área de Trabalho:** Duplo-clique no ícone **IP Scan IGT** na Área de Trabalho.
- **Pelo Menu do Sistema:** Pesquise por `IP Scan IGT`.
- **Pelo Terminal:**
  ```bash
  ip-scan-igt
  ```

### Como compilar e executar no Windows:
- **Compilação em 1 clique:** Duplo clique em `build_windows.bat`.
- **Execução:** Executar `dist\IPScanIGT.exe`.

### Atalhos de Teclado Globais:
- **`F5`**: Iniciar / Parar Varredura de Rede
- **`Esc`**: Parar Varredura Ativa
- **`Ctrl + N`**: Abrir Console de Varredura Nmap
- **`Ctrl + L`**: Abrir Identificador de Porta de Switch (LLDP / CDP)
- **`Ctrl + K`**: Abrir Diagnóstico e Medição do Cabo de Rede (NIC)
- **`Ctrl + I`**: Abrir Seletor de Placas de Rede
- **`Ctrl + E`**: Expandir Todos os Serviços `[+]`
- **`Ctrl + R`**: Recolher Todos os Dispositivos `[-]`
- **`Ctrl + D`**: Adicionar Dispositivo Selecionado aos Favoritos
- **`Ctrl + P`**: Exibir / Ocultar Painel Inferior de Osciloscópio
- **`Ctrl + T`**: Alternar Tema Claro / Escuro
- **`Ctrl + S`**: Exportar Resultados para CSV
- **`Ctrl + Q`**: Sair do Aplicativo

---
*Blueprint oficial v2.11.3 aprovado e sincronizado com o repositório do projeto IP Scan IGT.*
