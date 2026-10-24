# 🔍 IP Scan IGT (Linux & Windows)

**IP Scan IGT** é uma ferramenta gráfica profissional de escaneamento, auditoria e diagnóstico de redes locais (LAN) inspirada no *Advanced IP Scanner*, com suporte nativo multiplataforma (**Linux** e **Windows 10/11**).

---

## ✨ Principais Funcionalidades

- **Varredura Ultrarrápida Multithread (64 workers):** Varre sub-redes inteiras `/24` ou faixas customizadas em poucos segundos.
- **Detecção Automática de Câmeras & NVRs (ONVIF):** Descoberta via protocolo WS-Discovery UDP 3702 com resolução dinâmica de streams RTSP.
- **Reprodução Imediata de Vídeo (RTSP 554):** Suporte a streams H.264 e HEVC/H.265 em tempo real via **VLC Media Player** e **FFplay**.
- **Osciloscópio de Ping em Tempo Real:** Gráfico dinâmico de latência e jitter sub-milissegundo para o host selecionado.
- **Auditoria Portátil com Nmap:** Perfis de escaneamento pré-configurados com análise de serviços, banners e diagnóstico inteligente de dispositivos.
- **Identificação de Fabricante OUI:** Base offline com mais de 40.000 fabricantes (IEEE OUI).
- **Seletor de Placas de Rede:** Preenchimento automático para placas cabeadas (Ethernet), Wi-Fi, VPNs (WireGuard, OpenVPN) e Bridges virtuais (Docker/Hyper-V).
- **Ações Rápidas:** Abertura direta de HTTP, HTTPS, SMB (Compartilhamento de pastas), terminal de ping contínuo e favoritos.
- **Temas Claro e Escuro:** Interface moderna com tema claro inspirado no Advanced IP Scanner e Dark Mode para ambientes com pouca luz.

---

## 🚀 Instalação e Execução Inteligente (Com Resolução de Dependências)

### 🐧 No Linux (Instalação Automática de Dependências)
Basta rodar o instalador inteligente que analisa a aptidão do seu sistema, instala ferramentas ausentes (`ffmpeg`, `vlc`, `nmap`, `remmina`, `PyQt5`, `psutil`), cria o atalho no menu de aplicativos e configura o comando global `ipscan-igt`:

```bash
git clone https://github.com/icarogabrielc85-ai/ip-scan-igt.git
cd ip-scan-igt
chmod +x instalar_linux.sh
./instalar_linux.sh
```

Para inicialização rápida no dia a dia:
```bash
./executar_linux.sh
# ou simplesmente:
ipscan-igt
```

### 🪟 No Windows (Instalação Automática)
Dê um duplo-clique no arquivo:
```cmd
instalar_windows.bat
```
Ou para inicialização imediata com verificação de bibliotecas:
```cmd
executar_windows.bat
```

---

## 📦 Como Compilar Executáveis Autônomos

### 🪟 No Windows (Gerar `IPScanIGT.exe`)
Basta dar um duplo-clique no arquivo:
```cmd
build_windows.bat
```
Ou via terminal:
```cmd
pip install -r requirements.txt
pyinstaller --clean ipscan_windows.spec
```
O executável portátil único será gerado em: `dist\IPScanIGT.exe`.

### 🐧 No Linux (Gerar binário `IPScanIGT`)
Execute no terminal:
```bash
./build_linux.sh
```
Ou via comando direto:
```bash
pyinstaller --clean ipscan_linux.spec
```
O executável portátil único será gerado em: `dist/IPScanIGT`.

### ☁️ Compilação Automática na Nuvem (GitHub Actions)
Este repositório inclui automação CI em [`.github/workflows/build.yml`](file://.github/workflows/build.yml). Sempre que você enviar o código para o GitHub (`git push`), as versões de **Linux** e **Windows** são compiladas automaticamente e ficam disponíveis para download direto na aba **Actions** do GitHub.

---

## 📂 Estrutura do Projeto

```text
├── main.py                  # Janela principal, interface gráfica e osciloscópio de ping
├── scanner_engine.py        # Motor multithread de varredura, ping assíncrono e interfaces
├── onvif_engine.py          # Descoberta ONVIF, resolução de URI RTSP e players de vídeo
├── nmap_engine.py           # Motor do Nmap e análise de portas/serviços
├── nmap_dialog.py           # Diálogo de auditoria avançada com Nmap
├── interface_dialog.py      # Seletor detalhado de placas e sub-redes
├── oui_db.py                # Base de fabricantes MAC (IEEE OUI)
├── ui_theme.py              # Folhas de estilo QSS (Temas Claro e Escuro)
├── mac-vendors.txt          # Banco de dados de fabricantes MAC
├── icon.png                 # Ícone original PNG
├── icon.ico                 # Ícone multi-resolução para Windows
├── build_windows.bat        # Script de compilação automática para Windows
├── build_linux.sh           # Script de compilação automática para Linux
├── ipscan_windows.spec      # Especificação PyInstaller para Windows
├── ipscan_linux.spec        # Especificação PyInstaller para Linux
├── requirements.txt         # Dependências Python
└── .github/workflows/       # Automação CI GitHub Actions (Multiplataforma)
```

---

## 📄 Licença
Distribuído sob licença MIT. Livre para uso pessoal e comercial.
