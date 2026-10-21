# Guia de Compilação e Execução para Windows (IP Scan IGT)

Este projeto foi totalmente adaptado para funcionar nativamente no **Windows 10, 11 e Server**, além do **Linux**.

---

## 🚀 Método 1: Compilação em 1 Clique (Recomendado)

Se você já possui o **Python 3.10+** instalado no Windows:

1. Dê um duplo-clique no arquivo:
   ```cmd
   build_windows.bat
   ```
2. O script irá:
   - Verificar a instalação do Python.
   - Instalar automaticamente o `PyQt5` e o `PyInstaller`.
   - Empacotar todos os arquivos (`icon.ico`, banco MACs `mac-vendors.txt`, temas, etc.).
   - Gerar o executável único **`dist\IPScanIGT.exe`** (sem necessidade de instalação).

---

## 📦 Método 2: Compilação via Linha de Comando (Prompt / PowerShell)

No terminal da pasta do projeto no Windows:

```cmd
python -m pip install -r requirements.txt
pyinstaller --clean ipscan_windows.spec
```

O executável final estará pronto em:
```text
dist\IPScanIGT.exe
```

---

## ☁️ Método 3: Compilação Automática na Nuvem (GitHub Actions)

O repositório já possui uma rotina de CI configurada em [`.github/workflows/build-windows.yml`](file://.github/workflows/build-windows.yml).

Sempre que você enviar (`git push`) o projeto para o GitHub:
1. O GitHub iniciará uma máquina Windows nativa.
2. Compilará o executável automaticamente.
3. O executável **`IPScanIGT.exe`** estará disponível diretamente na aba **Actions** do GitHub para download.

---

## 🛠️ Recursos Integrados para Windows

- **Ícone e Barra de Tarefas:** Registro nativo via `ctypes` (`SetCurrentProcessExplicitAppUserModelID`) e ícone [.ico](file://icon.ico).
- **Detecção de Placas:** Leitura automática de adaptadores de rede, Wi-Fi, Ethernet e VPNs via `ipconfig`.
- **Ping e ARP:** Ping ICMP assíncrono em segundo plano e leitura de tabela ARP do Windows.
- **Ping no Terminal:** Abre diretamente o prompt do Windows (`cmd.exe /k ping -t <ip>`).
- **Compartilhamento de Pastas (SMB):** Abre diretamente no Windows Explorer (`\\<ip>`).
- **Câmeras e Gravadores (ONVIF/RTSP):**
  - Se você tiver o **VLC** ou **FFmpeg/ffplay** instalado no Windows, o IP Scan IGT detecta automaticamente os caminhos padrões (`C:\Program Files\VideoLAN\VLC\vlc.exe`) e abre o stream de vídeo em alta performance sem lag.
- **Nmap:** Detecta automaticamente a instalação oficial do Nmap para Windows (`C:\Program Files (x86)\Nmap\nmap.exe`).
