#!/usr/bin/env python3
"""
System Readiness & Dependency Doctor for IP Scan IGT.
Inspects system capabilities (Python, PyQt5, psutil, FFplay/VLC, Nmap, RDP, SSH, WoL),
reports readiness status, and generates or executes automatic package installation.
"""

import os
import platform
import shutil
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

IS_WINDOWS = sys.platform.startswith("win") or os.name == "nt"


def detect_linux_distro() -> str:
    """Detects Linux distribution family."""
    if IS_WINDOWS:
        return "windows"
    try:
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release", "r", encoding="utf-8") as f:
                content = f.read().lower()
                if any(x in content for x in ["ubuntu", "debian", "mint", "pop", "kali"]):
                    return "debian"
                elif any(x in content for x in ["fedora", "rhel", "centos", "rocky", "alma"]):
                    return "fedora"
                elif any(x in content for x in ["arch", "manjaro", "endeavouros"]):
                    return "arch"
                elif "suse" in content:
                    return "suse"
    except Exception:
        pass
    if shutil.which("apt") or shutil.which("apt-get"):
        return "debian"
    if shutil.which("dnf"):
        return "fedora"
    if shutil.which("pacman"):
        return "arch"
    return "generic_linux"


def check_system_readiness() -> Dict:
    """
    Performs full diagnosis of Python runtime, GUI libraries, network utilities,
    and media players required or recommended by IP Scan IGT.
    """
    items = []
    missing_packages = []

    # 1. Python Runtime
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    items.append({
        "name": "Python 3 Runtime",
        "category": "Núcleo",
        "status": "ok",
        "required": True,
        "summary": f"Versão {py_ver} ({platform.architecture()[0]})",
        "path": sys.executable,
    })

    # 2. PyQt5 Visual Engine
    try:
        from PyQt5.QtCore import PYQT_VERSION_STR, QT_VERSION_STR
        items.append({
            "name": "PyQt5 & Qt Engine",
            "category": "Interface Gráfica",
            "status": "ok",
            "required": True,
            "summary": f"PyQt v{PYQT_VERSION_STR} • Qt Core v{QT_VERSION_STR}",
            "path": "Módulo Python Carregado",
        })
    except Exception as e:
        items.append({
            "name": "PyQt5 Visual Engine",
            "category": "Interface Gráfica",
            "status": "error",
            "required": True,
            "summary": f"Falha ao carregar: {e}",
            "path": "Ausente",
        })
        missing_packages.append("pyqt5")

    # 3. psutil System Monitor
    try:
        import psutil
        items.append({
            "name": "psutil (Monitor de Recursos e Processos)",
            "category": "Núcleo",
            "status": "ok",
            "required": True,
            "summary": f"v{psutil.__version__} instalado e ativo",
            "path": getattr(psutil, "__file__", "Módulo Python"),
        })
    except Exception:
        items.append({
            "name": "psutil (Monitor de Recursos e Processos)",
            "category": "Núcleo",
            "status": "warning",
            "required": False,
            "summary": "Módulo psutil não encontrado (usando monitoramento simplificado)",
            "path": "Ausente",
        })
        missing_packages.append("psutil")

    # 4. Media Players (FFplay / VLC) for RTSP Camera Streams
    ffplay_path = shutil.which("ffplay") or ("/usr/bin/ffplay" if os.path.exists("/usr/bin/ffplay") else None)
    vlc_path = shutil.which("vlc") or ("/usr/bin/vlc" if os.path.exists("/usr/bin/vlc") else None)

    if ffplay_path and vlc_path:
        items.append({
            "name": "Player de Câmeras (FFplay & VLC)",
            "category": "Multimídia & RTSP",
            "status": "ok",
            "required": False,
            "summary": "FFplay (Ultra baixa latência) e VLC instalados e prontos",
            "path": f"{ffplay_path} | {vlc_path}",
        })
    elif ffplay_path:
        items.append({
            "name": "Player de Câmeras (FFplay)",
            "category": "Multimídia & RTSP",
            "status": "ok",
            "required": False,
            "summary": "FFplay disponível para reprodução com ultra baixa latência",
            "path": ffplay_path,
        })
    elif vlc_path:
        items.append({
            "name": "Player de Câmeras (VLC Media Player)",
            "category": "Multimídia & RTSP",
            "status": "ok",
            "required": False,
            "summary": "VLC Media Player disponível para reprodução de streams",
            "path": vlc_path,
        })
    else:
        items.append({
            "name": "Player de Câmeras (RTSP)",
            "category": "Multimídia & RTSP",
            "status": "warning",
            "required": False,
            "summary": "Nem FFplay nem VLC encontrados (necessário para ver vídeos de câmeras)",
            "path": "Ausente",
        })
        missing_packages.append("video")

    # 5. Nmap Deep Port & Service Scanner
    nmap_path = shutil.which("nmap") or ("/home/icaro/.local/bin/nmap" if os.path.exists("/home/icaro/.local/bin/nmap") else None)
    if nmap_path:
        items.append({
            "name": "Auditoria de Portas com Nmap",
            "category": "Segurança de Rede",
            "status": "ok",
            "required": False,
            "summary": "Binário Nmap detectado e integrado",
            "path": nmap_path,
        })
    else:
        items.append({
            "name": "Auditoria de Portas com Nmap",
            "category": "Segurança de Rede",
            "status": "warning",
            "required": False,
            "summary": "Nmap não encontrado (o scanner nativo do programa continua funcionando)",
            "path": "Ausente",
        })
        missing_packages.append("nmap")

    # 6. Remote Desktop Client (RDP)
    if IS_WINDOWS:
        items.append({
            "name": "Cliente de Área de Trabalho Remota (RDP)",
            "category": "Acesso Remoto",
            "status": "ok",
            "required": False,
            "summary": "Cliente Nativo Windows (mstsc.exe)",
            "path": "C:\\Windows\\System32\\mstsc.exe",
        })
    else:
        remmina_path = shutil.which("remmina")
        xfreerdp_path = shutil.which("xfreerdp")
        if remmina_path:
            items.append({
                "name": "Cliente RDP (Remmina)",
                "category": "Acesso Remoto",
                "status": "ok",
                "required": False,
                "summary": "Remmina instalado para conexão gráfica RDP",
                "path": remmina_path,
            })
        elif xfreerdp_path:
            items.append({
                "name": "Cliente RDP (FreeRDP)",
                "category": "Acesso Remoto",
                "status": "ok",
                "required": False,
                "summary": "xfreerdp disponível para sessões de tela remota",
                "path": xfreerdp_path,
            })
        else:
            items.append({
                "name": "Cliente RDP (Área de Trabalho Remota)",
                "category": "Acesso Remoto",
                "status": "warning",
                "required": False,
                "summary": "Remmina ou FreeRDP não encontrados para abrir RDP",
                "path": "Ausente",
            })
            missing_packages.append("rdp")

    # 7. SSH Terminal Emulator
    if IS_WINDOWS:
        ssh_bin = shutil.which("ssh")
        items.append({
            "name": "Console OpenSSH",
            "category": "Acesso Remoto",
            "status": "ok" if ssh_bin else "warning",
            "required": False,
            "summary": "OpenSSH nativo do Windows" if ssh_bin else "Cliente OpenSSH não encontrado no PATH",
            "path": ssh_bin or "Ausente",
        })
    else:
        terms = ["konsole", "gnome-terminal", "x-terminal-emulator", "xfce4-terminal", "xterm"]
        found_term = next((t for t in terms if shutil.which(t)), None)
        ssh_bin = shutil.which("ssh")
        if found_term and ssh_bin:
            items.append({
                "name": "Terminal SSH Interativo",
                "category": "Acesso Remoto",
                "status": "ok",
                "required": False,
                "summary": f"Terminal ({found_term}) + OpenSSH ({ssh_bin}) prontos",
                "path": f"{shutil.which(found_term)} | {ssh_bin}",
            })
        else:
            items.append({
                "name": "Terminal SSH Interativo",
                "category": "Acesso Remoto",
                "status": "warning",
                "required": False,
                "summary": "Emulador de terminal ou comando ssh ausente",
                "path": "Incompleto",
            })
            missing_packages.append("ssh")

    # 8. Wake-on-LAN Engine
    items.append({
        "name": "Wake-on-LAN (Magic Packet)",
        "category": "Diagnóstico & Energia",
        "status": "ok",
        "required": False,
        "summary": "Motor nativo socket UDP raw integrado + wakeonlan CLI auxiliar",
        "path": shutil.which("wakeonlan") or "Motor Nativo Python Socket",
    })

    # Determine overall status
    has_error = any(it["status"] == "error" for it in items)
    has_warning = any(it["status"] == "warning" for it in items)

    if has_error:
        overall_status = "error"
        badge_text = "Sistema Requer Pacotes Críticos para Executar"
        badge_color = "#ef4444"
    elif has_warning:
        overall_status = "warning"
        badge_text = "Sistema Apto para Operação Básica (Recursos Opcionais Disponíveis)"
        badge_color = "#f59e0b"
    else:
        overall_status = "perfect"
        badge_text = "Sistema 100% Apto — Todos os Recursos e Dependências Estão Prontos!"
        badge_color = "#10b981"

    # Generate install command
    distro = detect_linux_distro()
    install_cmd = generate_install_command(missing_packages, distro)

    return {
        "items": items,
        "missing_packages": missing_packages,
        "overall_status": overall_status,
        "badge_text": badge_text,
        "badge_color": badge_color,
        "distro": distro,
        "install_cmd": install_cmd,
    }


def generate_install_command(missing: List[str], distro: str) -> str:
    """Generates the single-line installation command tailored for the user's OS."""
    if not missing:
        return ""

    if distro == "windows":
        commands = []
        if "pyqt5" in missing or "psutil" in missing:
            commands.append("pip install PyQt5 psutil")
        if "video" in missing:
            commands.append("winget install VideoLAN.VLC")
        if "nmap" in missing:
            commands.append("winget install Insecure.Nmap")
        return " && ".join(commands) if commands else ""

    # Linux Debian / Ubuntu
    if distro == "debian":
        pkgs = []
        if "pyqt5" in missing:
            pkgs.append("python3-pyqt5")
        if "psutil" in missing:
            pkgs.append("python3-psutil")
        if "video" in missing:
            pkgs.append("ffmpeg vlc")
        if "nmap" in missing:
            pkgs.append("nmap")
        if "rdp" in missing:
            pkgs.append("remmina")
        if "ssh" in missing:
            pkgs.append("openssh-client")
        if pkgs:
            return f"sudo apt update && sudo apt install -y {' '.join(pkgs)}"
        return ""

    # Linux Fedora
    if distro == "fedora":
        pkgs = []
        if "pyqt5" in missing:
            pkgs.append("python3-qt5")
        if "psutil" in missing:
            pkgs.append("python3-psutil")
        if "video" in missing:
            pkgs.append("ffmpeg vlc")
        if "nmap" in missing:
            pkgs.append("nmap")
        if "rdp" in missing:
            pkgs.append("remmina")
        if pkgs:
            return f"sudo dnf install -y {' '.join(pkgs)}"
        return ""

    # Linux Arch
    if distro == "arch":
        pkgs = []
        if "pyqt5" in missing:
            pkgs.append("python-pyqt5")
        if "psutil" in missing:
            pkgs.append("python-psutil")
        if "video" in missing:
            pkgs.append("ffmpeg vlc")
        if "nmap" in missing:
            pkgs.append("nmap")
        if "rdp" in missing:
            pkgs.append("remmina")
        if pkgs:
            return f"sudo pacman -S --needed {' '.join(pkgs)}"
        return ""

    # Generic Linux
    return "pip install --user PyQt5 psutil"


class SystemDoctorDialog(QDialog):
    """
    Modern modal dialog presenting a complete health check of the host system,
    with 1-click command copy and automated terminal package installation.
    Fully adaptive to Light and Dark modes.
    """
    def __init__(self, parent=None, is_dark: Optional[bool] = None):
        super().__init__(parent)
        if is_dark is None:
            self.is_dark = getattr(parent, "is_dark_mode", False)
        else:
            self.is_dark = is_dark

        self.setWindowTitle("Diagnóstico de Aptidão do Sistema — IP Scan IGT")
        self.resize(700, 580)
        self.init_palette()
        self.init_ui()
        self.refresh_diagnosis()

    def init_palette(self):
        if self.is_dark:
            self.c_bg = "#0f172a"
            self.c_card_bg = "#1e293b"
            self.c_border = "#334155"
            self.c_text_main = "#f8fafc"
            self.c_text_sub = "#94a3b8"
            self.c_row_bg = "#131c2e"
            self.c_scroll_bg = "#0b1120"
            self.c_accent = "#38bdf8"
        else:
            self.c_bg = "#f8fafc"
            self.c_card_bg = "#ffffff"
            self.c_border = "#cbd5e1"
            self.c_text_main = "#0f172a"
            self.c_text_sub = "#64748b"
            self.c_row_bg = "#ffffff"
            self.c_scroll_bg = "#f1f5f9"
            self.c_accent = "#0284c7"

    def init_ui(self):
        vbox = QVBoxLayout(self)
        vbox.setContentsMargins(18, 16, 18, 16)
        vbox.setSpacing(12)

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {self.c_bg};
                color: {self.c_text_main};
            }}
        """)

        # Header card
        self.header_frame = QFrame()
        self.header_frame.setObjectName("docHeader")
        self.header_frame.setStyleSheet(f"""
            QFrame#docHeader {{
                background-color: {self.c_card_bg};
                border: 1px solid {self.c_border};
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        h_layout = QHBoxLayout(self.header_frame)
        h_layout.setContentsMargins(6, 4, 6, 4)
        h_layout.setSpacing(12)

        self.lbl_icon = QLabel("🩺")
        self.lbl_icon.setStyleSheet("font-size: 32px;")
        h_layout.addWidget(self.lbl_icon)

        info_box = QVBoxLayout()
        info_box.setSpacing(2)
        self.lbl_title = QLabel("Verificador de Dependências & Aptidão do Sistema")
        self.lbl_title.setStyleSheet(f"font-weight: bold; font-size: 15px; color: {self.c_accent};")
        self.lbl_sub = QLabel("Analisando componentes de rede, reprodutores multimídia e bibliotecas gráficas...")
        self.lbl_sub.setStyleSheet(f"font-size: 12px; color: {self.c_text_sub};")
        info_box.addWidget(self.lbl_title)
        info_box.addWidget(self.lbl_sub)
        h_layout.addLayout(info_box)
        vbox.addWidget(self.header_frame)

        # Overall Status Badge Card
        self.badge_frame = QFrame()
        self.badge_layout = QHBoxLayout(self.badge_frame)
        self.badge_layout.setContentsMargins(12, 8, 12, 8)
        self.lbl_badge = QLabel("Verificando...")
        self.lbl_badge.setStyleSheet("font-weight: bold; font-size: 13px;")
        self.badge_layout.addWidget(self.lbl_badge)
        vbox.addWidget(self.badge_frame)

        # Scroll Area for Components Checklist
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"QScrollArea {{ border: 1px solid {self.c_border}; border-radius: 6px; background-color: {self.c_scroll_bg}; }}")

        self.items_container = QWidget()
        self.items_layout = QVBoxLayout(self.items_container)
        self.items_layout.setContentsMargins(10, 10, 10, 10)
        self.items_layout.setSpacing(8)
        scroll.setWidget(self.items_container)
        vbox.addWidget(scroll, 1)

        # Recommendation Card (Install command box)
        self.rec_frame = QFrame()
        self.rec_frame.setStyleSheet(f"background-color: {self.c_card_bg}; border: 1px solid {self.c_border}; border-left: 4px solid {self.c_accent}; border-radius: 6px; padding: 8px;")
        rec_layout = QVBoxLayout(self.rec_frame)
        rec_layout.setContentsMargins(8, 8, 8, 8)
        rec_layout.setSpacing(6)

        self.lbl_rec_title = QLabel("Comando para Instalação Automática dos Recursos Ausentes:")
        self.lbl_rec_title.setStyleSheet(f"font-weight: 600; font-size: 12px; color: {self.c_text_main};")
        rec_layout.addWidget(self.lbl_rec_title)

        self.txt_cmd = QTextEdit()
        self.txt_cmd.setReadOnly(True)
        self.txt_cmd.setFixedHeight(44)
        cmd_bg = "#020617" if self.is_dark else "#f1f5f9"
        self.txt_cmd.setStyleSheet(f"font-family: monospace; font-size: 11px; color: {self.c_accent}; background: {cmd_bg}; border: 1px solid {self.c_border}; border-radius: 4px; padding: 4px;")
        rec_layout.addWidget(self.txt_cmd)
        rec_layout.setContentsMargins(8, 8, 8, 8)
        rec_layout.setSpacing(6)

        self.lbl_rec_title = QLabel("Comando para Instalação Automática dos Recursos Ausentes:")
        self.lbl_rec_title.setStyleSheet("font-weight: 600; font-size: 12px; color: #e2e8f0;")
        rec_layout.addWidget(self.lbl_rec_title)

        self.txt_cmd = QTextEdit()
        self.txt_cmd.setReadOnly(True)
        self.txt_cmd.setFixedHeight(44)
        self.txt_cmd.setStyleSheet("font-family: monospace; font-size: 11px; color: #38bdf8; background: #020617; border: 1px solid #1e293b; border-radius: 4px; padding: 4px;")
        rec_layout.addWidget(self.txt_cmd)

        cmd_actions = QHBoxLayout()
        cmd_actions.setSpacing(8)
        cmd_actions.addStretch()

        self.btn_copy_cmd = QPushButton("📋 Copiar Comando")
        self.btn_copy_cmd.setFixedHeight(28)
        self.btn_copy_cmd.clicked.connect(self.copy_command)
        cmd_actions.addWidget(self.btn_copy_cmd)

        self.btn_run_cmd = QPushButton("⚡ Instalar no Terminal")
        self.btn_run_cmd.setObjectName("btnStart")
        self.btn_run_cmd.setFixedHeight(28)
        self.btn_run_cmd.clicked.connect(self.run_install_terminal)
        cmd_actions.addWidget(self.btn_run_cmd)

        rec_layout.addLayout(cmd_actions)
        vbox.addWidget(self.rec_frame)

        # Bottom Buttons
        btn_box = QHBoxLayout()
        btn_box.setSpacing(10)

        btn_refresh = QPushButton("🔄 Re-verificar")
        btn_refresh.setFixedHeight(34)
        btn_refresh.clicked.connect(self.refresh_diagnosis)
        btn_box.addWidget(btn_refresh)
        btn_box.addStretch()

        btn_close = QPushButton("Fechar")
        btn_close.setFixedHeight(34)
        btn_close.setFixedWidth(100)
        btn_close.clicked.connect(self.accept)
        btn_box.addWidget(btn_close)

        vbox.addLayout(btn_box)

    def refresh_diagnosis(self):
        diag = check_system_readiness()

        # Update Badge
        self.lbl_badge.setText(diag["badge_text"])
        self.badge_frame.setStyleSheet(f"""
            background-color: {diag['badge_color']}20;
            border: 1px solid {diag['badge_color']};
            border-radius: 6px;
            color: {diag['badge_color']};
        """)

        # Clear previous items
        while self.items_layout.count():
            child = self.items_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        # Populate Items
        for it in diag["items"]:
            row = QFrame()
            row.setStyleSheet(f"background-color: {self.c_row_bg}; border: 1px solid {self.c_border}; border-radius: 6px; padding: 6px;")
            r_box = QHBoxLayout(row)
            r_box.setContentsMargins(8, 4, 8, 4)
            r_box.setSpacing(10)

            # Icon
            status_icon = "✔" if it["status"] == "ok" else ("⚠️" if it["status"] == "warning" else "✖")
            icon_color = "#10b981" if it["status"] == "ok" else ("#f59e0b" if it["status"] == "warning" else "#ef4444")
            lbl_st = QLabel(status_icon)
            lbl_st.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {icon_color};")
            lbl_st.setFixedWidth(24)
            r_box.addWidget(lbl_st)

            # Text Info
            t_box = QVBoxLayout()
            t_box.setSpacing(2)

            header_line = QHBoxLayout()
            lbl_name = QLabel(it["name"])
            lbl_name.setStyleSheet(f"font-weight: 600; font-size: 12px; color: {self.c_text_main};")
            lbl_cat = QLabel(f"[{it['category']}]")
            lbl_cat.setStyleSheet(f"font-size: 11px; color: {self.c_text_sub}; font-weight: normal;")
            header_line.addWidget(lbl_name)
            header_line.addWidget(lbl_cat)
            header_line.addStretch()
            t_box.addLayout(header_line)

            lbl_sum = QLabel(it["summary"])
            lbl_sum.setStyleSheet(f"font-size: 11px; color: {self.c_text_sub};")
            t_box.addWidget(lbl_sum)

            if it.get("path") and it["path"] != "Ausente":
                lbl_path = QLabel(f"Caminho: {it['path']}")
                lbl_path.setStyleSheet(f"font-family: monospace; font-size: 10px; color: {self.c_text_sub};")
                t_box.addWidget(lbl_path)

            r_box.addLayout(t_box, 1)
            self.items_layout.addWidget(row)

        self.items_layout.addStretch()

        # Install Command Frame visibility
        cmd = diag["install_cmd"]
        if cmd:
            self.rec_frame.setVisible(True)
            self.txt_cmd.setText(cmd)
            self.current_cmd = cmd
        else:
            self.rec_frame.setVisible(False)
            self.current_cmd = ""

    def copy_command(self):
        if hasattr(self, "current_cmd") and self.current_cmd:
            QApplication.clipboard().setText(self.current_cmd)
            QMessageBox.information(
                self,
                "Copiado",
                "Comando de instalação copiado para a Área de Transferência!\n\nCole no terminal para instalar os componentes."
            )

    def run_install_terminal(self):
        if not hasattr(self, "current_cmd") or not self.current_cmd:
            return

        cmd = self.current_cmd
        if IS_WINDOWS:
            subprocess.Popen(f'cmd.exe /c start "Instalacao IP Scan IGT" cmd.exe /k "{cmd}"', shell=True)
            return

        terms = [
            ("konsole", ["konsole", "-e", "bash", "-c", f"{cmd}; echo ''; echo 'Pressione Enter para fechar...'; read line"]),
            ("gnome-terminal", ["gnome-terminal", "--", "bash", "-c", f"{cmd}; echo ''; echo 'Pressione Enter para fechar...'; read line"]),
            ("x-terminal-emulator", ["x-terminal-emulator", "-e", f"bash -c \"{cmd}; echo 'Pressione Enter para fechar...'; read line\""]),
            ("xfce4-terminal", ["xfce4-terminal", "-e", f"bash -c \"{cmd}; echo 'Pressione Enter para fechar...'; read line\""]),
            ("xterm", ["xterm", "-e", f"bash -c \"{cmd}; echo 'Pressione Enter para fechar...'; read line\""]),
        ]

        for name, term_cmd in terms:
            if shutil.which(name):
                try:
                    subprocess.Popen(term_cmd)
                    QMessageBox.information(
                        self,
                        "Terminal Iniciado",
                        "O terminal foi iniciado para executar a instalação.\nDigite sua senha caso o sistema solicite privilégios sudo."
                    )
                    return
                except Exception:
                    pass

        QMessageBox.warning(
            self,
            "Terminal Não Encontrado",
            f"Não foi possível iniciar o emulador de terminal automaticamente.\nCopie e execute o comando manualmente no seu terminal:\n\n{cmd}"
        )
