# 🔍 IP Scan IGT (Linux & Windows) — v2.9.2

**IP Scan IGT** é uma ferramenta gráfica profissional de escaneamento, auditoria, segurança e diagnóstico de redes locais (LAN) inspirada no *Advanced IP Scanner*, desenvolvida em **Python 3** e **PyQt5** com suporte nativo multiplataforma (**Linux** e **Windows 10/11**).

---

## ✨ Principais Recursos e Motores

- **🌐 Auto-detecção de Sub-rede e Interface (< 0.1 ms):** Resolução de IP ativo via socket UDP de roteamento do kernel, busca dinâmica de binários `iproute2` e fallback direto em Python puro via `ioctl` (`SIOCGIFADDR`/`SIOCGIFNETMASK`) no Linux e decodificação OEM CP850/UTF-8 no Windows.
- **⚡ Varredura Ultrarrápida Multithread (64 workers):** Varre sub-redes inteiras `/24` ou faixas CIDR customizadas em poucos segundos com ping assíncrono e tabela ARP.
- **🗺️ Mapeamento Visual de Topologia (Grafo NOC Interativo):** Grafo dinâmico com layouts em Camadas e Radial, halos de alerta para CVEs, links coloridos por latência e **barra de ajuste de densidade/distância dos nós (50% a 300%)**.
- **🛡️ Network Guard (Segurança L2):** Detecção em tempo real de ataques de **ARP Spoofing** (sequestro de Gateway), **Conflito de IP** (troca de placa) e **Novos Dispositivos Intrusos** com Whitelist de MACs confiáveis.
- **📸 Snapshots de Auditoria & Comparador de Mudanças (Baseline Diff):** Fotografias completas da rede para auditoria comparativa destacando novos hosts (`🟢 +Novo`), servidores ausentes (`🔴 -Ausente`) e modificações de portas/CVEs (`🟠 ~Modificado`).
- **🚨 Correlação de Vulnerabilidades (CVEs via SQLite Local):** Cruza banners HTTP, SSH, SSL, SNMP e serviços do Nmap com base curada SQLite (`cve_knowledge.db`), calculando score de risco CVSS.
- **📊 Auditoria de Infraestrutura via SNMP (UDP 161 em Python Puro):** Extração de `sysDescr`, `sysName`, `sysUpTime`, contagem de interfaces de switches gerenciáveis e níveis de toner/páginas de impressoras (Printer-MIB).
- **👁️ Descoberta Automática de Câmeras & NVRs (ONVIF WS-Discovery):** Resolução dinâmica de URI RTSP com players de vídeo integrados (**FFplay** e **VLC** com aceleração de hardware H.264/HEVC).
- **📡 Descoberta UPnP / SSDP (UDP 1900) & Traceroute Visual (TTL):** Extração de fabricante, modelo e serial de Smart TVs e IoT + grafo visual de latência salto a salto.
- **📈 Osciloscópio de Ping Sub-Milissegundo:** Gráfico dinâmico contínuo de latência e jitter para diagnóstico instantâneo.
- **🔍 Auditoria Avançada com Nmap:** Perfis rápidos sem necessidade de root (`-sT`), streaming assíncrono de terminal e diagnóstico inteligente de vulnerabilidades.
- **🛡️ Monitoramento Contínuo em Segundo Plano (Watchdog):** Vigia 24/7 os ativos da aba Favoritos com histerese de falhas e notificações nativas no desktop (`QSystemTrayIcon` e `notify-send`).
- **📑 Relatório Executivo Autocontido em HTML / PDF:** Laudo completo com **Score de Segurança da Rede (0–100)**, **Topologia embutida em Base64 PNG**, Matriz de CVEs e telemetria SNMP.
- **📖 Manual Completo do Usuário Integrado (`F1`):** Manual interativo com busca instantânea e exportação nativa para PDF.
- **🌍 Suporte Multilíngue Completo (9 Idiomas):** Alternância dinâmica sem reiniciar para Português (`pt_BR`), Inglês (`en`), Espanhol (`es`), Italiano (`it`), Francês (`fr`), Alemão/Polonês (`pl`), Russo (`ru`), Ucraniano (`uk`) e Chinês (`zh_CN`).
- **🎨 Temas Claro e Escuro:** Tema claro moderno em tons de cinza neutro (estilo VirtualBox) e Dark Mode de alto contraste.

---

## 🚀 Instalação e Execução

### 🐧 No Linux (Instalação em 1 Comando via Terminal)
Abra o terminal e execute o comando abaixo para instalar dependências (`PyQt5`, `psutil`, `FFplay`, `VLC`, `Nmap`, `Remmina`), criar o atalho no menu de aplicativos e configurar o binário global:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/icarogabrielc85-ai/ip-scan-igt/main/instalar_linux.sh)"
```

Ou clone manualmente pelo Git:
```bash
git clone https://github.com/icarogabrielc85-ai/ip-scan-igt.git
cd ip-scan-igt
chmod +x instalar_linux.sh
./instalar_linux.sh
```

Para executar a qualquer momento:
```bash
ipscan-igt
```

### 🪟 No Windows (Instalação Automática)
Execute via prompt de comando ou dê duplo-clique:
```cmd
instalar_windows.bat
```
Ou para execução direta:
```cmd
executar_windows.bat
```

---

## 📦 Downloads Oficiais Pré-Compilados (Releases v2.9.2)

Baixe os instaladores prontos direto na aba **[Releases](https://github.com/icarogabrielc85-ai/ip-scan-igt/releases)**:

### 🐧 Para Linux (Ubuntu, Debian, Linux Mint, Pop!_OS, Kali):
- **`ipscan-igt_2.9.2_amd64.deb`** — Pacote Debian oficial. Instale com duplo-clique ou pelo terminal:
  ```bash
  sudo apt install ./ipscan-igt_2.9.2_amd64.deb
  ```
- **`IPScanIGT`** — Executável binário portátil x64 autônomo para qualquer distribuição Linux.

### 🪟 Para Windows 10 e Windows 11:
- **`IPScanIGT-Setup-2.9.2.exe`** — Instalador assistente completo (Inno Setup) com atalhos na Área de Trabalho e Menu Iniciar.
- **`IPScanIGT.msi`** — Instalador corporativo padrão WiX MSI.
- **`IPScanIGT.exe`** — Executável portátil standalone (executa direto sem instalação).

---

## 📁 Persistência de Dados e Configurações

O IP Scan IGT armazena suas configurações, banco de CVEs, histórico de incidentes e snapshots nos diretórios padrão do sistema operacional através do módulo centralizado [`config_paths.py`](file://config_paths.py):

| Sistema Operacional | Diretório Oficial de Dados | Arquivos Armazenados |
| :--- | :--- | :--- |
| **Linux / Unix** | `~/.config/linux-ipscan/` | `cve_knowledge.db`, `dns_targets.json`, `favorites.json`, `network_guard.json`, `snapshots.json`, `watchdog_events.json`, `settings.json`, `device_aliases.json` |
| **Windows** | `%APPDATA%\IPScanIGT\` | `cve_knowledge.db`, `dns_targets.json`, `favorites.json`, `network_guard.json`, `snapshots.json`, `watchdog_events.json`, `settings.json`, `device_aliases.json` |

---

## 📂 Estrutura do Projeto

```text
├── main.py                     # Janela principal, interface 2-Tier Ribbon, atalhos e relatórios
├── config_paths.py             # Resolução nativa de diretórios (%APPDATA% no Windows e ~/.config no Linux)
├── scanner_engine.py           # Motor multithread de varredura, ping assíncrono e auto-detecção de sub-rede
├── network_guard_engine.py     # Motor Network Guard L2 (ARP Spoofing, Conflito de IP e Intrusos)
├── snapshot_engine.py          # Motor de Snapshots de Auditoria e Comparador de Mudanças (Baseline Diff)
├── topology_widget.py          # Grafo interativo de Topologia de Rede (Radial/Camadas) com controle de densidade
├── cve_engine.py               # Motor de correlação de vulnerabilidades SQLite (CVSS)
├── snmp_engine.py              # Cliente SNMPv1/v2c em Python puro (ASN.1 BER MIB-II e Printer-MIB)
├── onvif_engine.py             # Descoberta WS-Discovery ONVIF, token RTSP e players de vídeo
├── nmap_engine.py              # Motor assíncrono do Nmap e regex parser de serviços/versões
├── nmap_dialog.py              # Interface moderna de auditoria Nmap (Relatório, CVEs e Terminal)
├── upnp_engine.py              # Descoberta UPnP / SSDP (UDP 1900) e parser XML RootDevice
├── traceroute_dialog.py        # Traceroute visual com grafo de saltos (TTL) e diagnóstico de latência
├── watchdog_engine.py          # Motor de monitoramento contínuo em segundo plano 24/7 com notificações
├── internet_test_dialog.py     # Diagnóstico de Internet e Benchmark de servidores DNS mundiais
├── interface_dialog.py         # Janela de seleção e diagnóstico de placas de rede ativas
├── manual_dialog.py            # Manual do usuário interativo integrado e exportador PDF
├── system_doctor_dialog.py     # Diagnóstico de integridade do ambiente e dependências do sistema
├── oui_db.py                   # Base de resolução de fabricantes MAC (IEEE OUI)
├── ui_theme.py                 # Folhas de estilo QSS (Temas Claro/Cinza e Escuro) e Osciloscópio
├── version.py                  # Controle de versão semântica, builds e changelog histórico
├── i18n.py                     # Motor de tradução dinâmica em tempo real nos 9 idiomas suportados
├── mac-vendors.txt             # Base offline com mais de 40.000 fabricantes IEEE catalogados
├── build_linux.sh              # Script de compilação do binário e pacote Debian (.deb)
├── build_windows.bat           # Script de compilação do executável portátil para Windows
├── ipscan_linux.spec           # Especificação PyInstaller para Linux
├── ipscan_windows.spec         # Especificação PyInstaller para Windows
├── ipscan_windows.iss          # Script do instalador assistente Inno Setup (Setup.exe)
├── ipscan_windows.wxs          # Especificação do instalador corporativo WiX (MSI)
├── requirements.txt            # Dependências Python (PyQt5, psutil, pyinstaller)
├── BLUEPRINT.md                # Blueprint arquitetural completo do sistema
└── .github/workflows/build.yml # Pipeline de CI/CD GitHub Actions multiplataforma
```

---

## 📄 Licença
Distribuído sob licença MIT. Livre para uso pessoal e comercial.
