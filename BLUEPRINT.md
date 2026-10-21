# BLUEPRINT — IP SCAN IGT
**Versão:** 2.1.0 (Edição Multiplataforma: Linux & Windows)  
**Projeto:** IP Scan IGT  
**Repositório GitHub:** [https://github.com/icarogabrielc85-ai/ip-scan-igt](https://github.com/icarogabrielc85-ai/ip-scan-igt)  
**Diretório Local (PC):** `/home/icaro/linux-ipscan`  
**Executável do Sistema (Linux):** `/home/icaro/.local/bin/ip-scan-igt`  
**Atalho da Área de Trabalho:** `/home/icaro/Área de trabalho/ip-scan-igt.desktop`  
**Atalho do Menu do Sistema:** `~/.local/share/applications/ip-scan-igt.desktop`  
**Data da Última Atualização:** 21/10/2026  

---

## 1. Visão Geral do Produto

O **IP Scan IGT** é uma ferramenta gráfica profissional de escaneamento, auditoria e diagnóstico de redes locais (LAN) desenvolvida para ambientes **Linux** e **Windows (10/11/Server)** utilizando **Python 3** e **PyQt5**.

Inspirado na usabilidade ágil e visual clássico do consagrado *Advanced IP Scanner*, o IP Scan IGT expande essas capacidades trazendo recursos avançados nativos para ambas as plataformas:
- **Descoberta Automática de Câmeras IP & NVRs via ONVIF (WS-Discovery UDP 3702)** com extração de perfis e URI tokenizada de streaming RTSP em tempo real.
- **Reprodução Imediata de Transmissões de Vídeo ao Vivo (RTSP 554) via VLC / FFplay** com aceleração por hardware e suporte a H.264 e HEVC/H.265 (4K/5MP).
- **Integração Total com Nmap** operando em espaço de usuário (*user-space* sem necessidade de `sudo` no Linux e detecção automática no Windows).
- **Osciloscópio de Ping Instantâneo Dinâmico** com gráfico em tempo real e resolução sub-milissegundo.
- **Classificação Dinâmica Inteligente em 1 Clique** (Crescente ▲ / Decrescente ▼) por IP numérico real, Nome, Latência, MAC e Fabricante.
- **Seletor de Placas de Rede** com preenchimento automático para interfaces cabeadas (Ethernet), Wi-Fi, VPNs (WireGuard/OpenVPN) e Bridges virtuais (Docker/KVM/Hyper-V).
- **Compilação e Empacotamento Automatizado** com executável portátil único para Windows (`IPScanIGT.exe`) e Linux (`IPScanIGT`), além de esteira de CI/CD no GitHub Actions.

---

## 2. Diagrama de Arquitetura do Sistema

```mermaid
flowchart TD
    subgraph UI_Layer["Camada de Apresentação (PyQt5)"]
        MW["MainWindow (IP Scan IGT)"]
        TB["Barra de Ferramentas (Verificar, IP ▾, Faixa, Máscara, Filtro, ONVIF, Nmap)"]
        TABS["Abas: [Resultados] & [Favoritos]"]
        TREE["QTreeWidget com DeviceTreeWidgetItem (Ordenação Numérica IP / Ping)"]
        BP["Painel Inferior: Osciloscópio Live Ping & Inspetor de Propriedades"]
        NMAP_DLG["NmapDialog (Relatório Estruturado & Terminal Nmap)"]
        IFACE_DLG["NetworkInterfaceDialog (Seletor Detalhado de Placas de Rede)"]
    end

    subgraph Core_Engines["Motores de Escaneamento e Descoberta"]
        SE["scanner_engine.py (Multithread: 64 Threads, Dual-Platform)"]
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
            L_TERM["x-terminal-emulator / konsole"]
        end
        subgraph Windows_OS["Windows"]
            W_ARP["arp -a"]
            W_NET["ipconfig /all & route print"]
            W_PING["ping -n 1 -w (CREATE_NO_WINDOW)"]
            W_VID["Program Files VLC / ffplay.exe"]
            W_TERM["cmd.exe /k ping -t"]
            W_SMB["Explorer \\ip"]
            W_APPID["ctypes AppUserModelID"]
        end
    end

    MW --> TB
    MW --> TABS
    TABS --> TREE
    MW --> BP
    MW --> NMAP_DLG
    MW --> IFACE_DLG

    MW --> SE
    MW --> OE
    MW --> NE
    SE --> OUI
    MW --> TH

    SE --> Linux_OS
    SE --> Windows_OS
    OE --> Linux_OS
    OE --> Windows_OS
```

---

## 3. Módulos e Estrutura de Arquivos

| Arquivo / Caminho | Responsabilidade / Função |
| :--- | :--- |
| [`main.py`](file:///home/icaro/linux-ipscan/main.py) | Ponto de entrada da aplicação, janela principal (`MainWindow`), ciclo de vida de threads (`ScanWorker`, `LivePingWorker`), menu bar, atalhos, exportação de relatórios (CSV, JSON, TXT), registro de AppID no Windows e persistência de Favoritos. |
| [`scanner_engine.py`](file:///home/icaro/linux-ipscan/scanner_engine.py) | Motor de varredura multithread (ThreadPoolExecutor). Abstração multiplataforma para ping com sub-milissegundo (Linux e Windows), tabela ARP (`/proc/net/arp` e `arp -a`), enumeração de placas (`iproute2` e `ipconfig`), banners HTTP/SSH, inspeção de certificados SSL em Python puro (`ssl.get_server_certificate`), classificação automática de SO e gateways padrão. |
| [`onvif_engine.py`](file:///home/icaro/linux-ipscan/onvif_engine.py) | Motor de descoberta ONVIF via WS-Discovery multicast (`239.255.255.250:3702`), decodificador de scopes XML, resolução de token RTSP dinâmico via `GetStreamUri` (suporte a Xiongmai XM530, Hikvision, Dahua, Intelbras), probe RTSP (554) e detecção/disparo automático de players de vídeo (FFplay / VLC) em Linux e Windows. |
| [`nmap_engine.py`](file:///home/icaro/linux-ipscan/nmap_engine.py) | Wrapper portável para execução assíncrona do Nmap sem privilégios de root (`-sT`), streaming de saída linha a linha (`NmapScannerThread`), parser regex de portas/serviços/versões, detecção automática do `nmap.exe` no Windows e gerador de diagnóstico inteligente de dispositivos. |
| [`nmap_dialog.py`](file:///home/icaro/linux-ipscan/nmap_dialog.py) | Interface moderna de auditoria do Nmap (`NmapDialog`) com abas divididas entre **Relatório Estruturado** (cards informativos, badges de métricas, tabela com botões de ação direta) e **Terminal Nmap** (saída bruta para auditoria técnica). |
| [`interface_dialog.py`](file:///home/icaro/linux-ipscan/interface_dialog.py) | Janela modal de seleção de placas de rede (`NetworkInterfaceDialog`), listando adaptadores físicos, Wi-Fi, VPNs e bridges com IP, CIDR, faixa calculada, MAC, Gateway e velocidade de link. |
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

---

## 5. UI/UX Design System e Regras de Interface

1. **Aparência e Fidelidade Visual:**
   - Barra de ferramentas clássica superior com botão verde vibrante `▶  Verificar`, botão seletor de sub-rede `IP ▾`, campos de faixa de IP e seletor de máscara (`/24`, `/16`, etc.).
   - Abas principais de largura total: **[Resultados]** e **[Favoritos]**.
2. **Classificação Dinâmica Inteligente ([`DeviceTreeWidgetItem`](file:///home/icaro/linux-ipscan/main.py)):**
   - **IP (Col 2):** Ordenação numérica por octetos `(192, 168, 111, 1)` em vez de texto bruto.
   - **Ping (Col 5):** Ordenação por milissegundos numéricos; estações offline são empurradas para o final no modo crescente.
   - **Nome / Fabricante / MAC:** Ordenação alfabética case-insensitive.
   - **Status (Col 0):** Dispositivos online (`●`) ordenados prioritariamente.
   - Indicador visual nativo com setas **▲ / ▼** no cabeçalho e feedback textual na barra de status.
3. **Hierarquia e Limpeza Visual:**
   - Itens de dispositivos mantêm-se **recolhidos por padrão**, apresentando uma linha limpa por host online.
   - Sub-recursos `[+]` agrupam portas e serviços web/vídeo sem quebrar a visualização principal.
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
- **`Ctrl + I`**: Abrir Seletor de Placas de Rede
- **`Ctrl + E`**: Expandir Todos os Serviços `[+]`
- **`Ctrl + R`**: Recolher Todos os Dispositivos `[-]`
- **`Ctrl + D`**: Adicionar Dispositivo Selecionado aos Favoritos
- **`Ctrl + P`**: Exibir / Ocultar Painel Inferior de Osciloscópio
- **`Ctrl + T`**: Alternar Tema Claro / Escuro
- **`Ctrl + S`**: Exportar Resultados para CSV
- **`Ctrl + Q`**: Sair do Aplicativo

---
*Blueprint oficial v2.1.0 aprovado e sincronizado com o repositório GitHub do projeto IP Scan IGT.*
