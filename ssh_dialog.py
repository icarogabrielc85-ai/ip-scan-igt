#!/usr/bin/env python3
"""
SSH Connection & Credentials Manager for IP Scan IGT.
Allows prompting for username, storing credentials persistently per host/IP,
and launching SSH sessions with credentials pre-injected or passed to terminal emulators.
"""

import base64
import getpass
import json
import os
import shutil
import subprocess
import tempfile
from typing import Dict, Optional, Tuple

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
)

SSH_CREDENTIALS_FILE = os.path.expanduser("~/.config/linux-ipscan/ssh_credentials.json")
IS_WINDOWS = os.name == "nt"


def _obfuscate(text: str) -> str:
    """Simple XOR + base64 obfuscation to prevent plain-text shoulder-surfing on disk."""
    if not text:
        return ""
    try:
        raw_bytes = text.encode("utf-8")
        key = 0x5B
        obf = bytes([b ^ key for b in raw_bytes])
        return base64.b64encode(obf).decode("ascii")
    except Exception:
        return ""


def _deobfuscate(encoded: str) -> str:
    """Deobfuscates stored string."""
    if not encoded:
        return ""
    try:
        raw_bytes = base64.b64decode(encoded.encode("ascii"))
        key = 0x5B
        b = bytes([x ^ key for x in raw_bytes])
        return b.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def load_all_ssh_credentials() -> Dict[str, dict]:
    """Loads all saved SSH credentials from ~/.config/linux-ipscan/ssh_credentials.json."""
    if not os.path.exists(SSH_CREDENTIALS_FILE):
        return {}
    try:
        with open(SSH_CREDENTIALS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def get_ssh_credential_for_ip(ip: str) -> Optional[dict]:
    """Retrieves saved credentials for a specific IP."""
    all_creds = load_all_ssh_credentials()
    entry = all_creds.get(ip)
    if entry:
        return {
            "user": entry.get("user", ""),
            "password": _deobfuscate(entry.get("password_enc", "")),
            "port": entry.get("port", 22),
            "save_password": entry.get("save_password", False),
        }
    return None


def save_ssh_credential(ip: str, user: str, password: str = "", port: int = 22, save_password: bool = True):
    """Saves credentials for an IP to disk."""
    os.makedirs(os.path.dirname(SSH_CREDENTIALS_FILE), exist_ok=True)
    all_creds = load_all_ssh_credentials()
    all_creds[ip] = {
        "user": user.strip(),
        "password_enc": _obfuscate(password) if save_password and password else "",
        "port": port,
        "save_password": save_password,
    }
    try:
        with open(SSH_CREDENTIALS_FILE, "w", encoding="utf-8") as f:
            json.dump(all_creds, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print("Erro salvando credenciais SSH:", e)
        return False


def delete_ssh_credential(ip: str) -> bool:
    """Deletes credentials for an IP from disk."""
    all_creds = load_all_ssh_credentials()
    if ip in all_creds:
        del all_creds[ip]
        try:
            with open(SSH_CREDENTIALS_FILE, "w", encoding="utf-8") as f:
                json.dump(all_creds, f, indent=2, ensure_ascii=False)
            return True
        except Exception:
            pass
    return False


def open_terminal_ssh(ip: str, user: str = "", password: str = "", port: int = 22) -> bool:
    """
    Launches an interactive SSH terminal session connecting to user@ip.
    Supports Linux (konsole, gnome-terminal, x-terminal-emulator, etc.) and Windows (cmd.exe).
    Uses sshpass or SSH_ASKPASS when password is provided.
    """
    if not ip:
        return False

    port = port or 22
    target = f"{user}@{ip}" if user else ip
    port_args = ["-p", str(port)] if port != 22 else []

    # Windows handling
    if IS_WINDOWS:
        try:
            cmd_str = f'ssh {" ".join(port_args)} {target}'.strip()
            if password:
                try:
                    QApplication.clipboard().setText(password)
                except Exception:
                    pass
            subprocess.Popen(f'cmd.exe /c start "SSH {target}" {cmd_str}', shell=True)
            return True
        except Exception as ex:
            print("Erro iniciando SSH no Windows:", ex)
            return False

    # Linux handling
    askpass_file = None
    env = os.environ.copy()

    # If password is provided, try sshpass first
    if password and shutil.which("sshpass"):
        ssh_cmd = ["sshpass", "-p", password, "ssh", *port_args, "-o", "StrictHostKeyChecking=accept-new", target]
    elif password:
        # Create lightweight transient askpass helper
        try:
            askpass_file = tempfile.NamedTemporaryFile(mode="w", delete=False, prefix="ipscan_askpass_", suffix=".sh")
            askpass_file.write(f"#!/bin/sh\ncat << 'EOF'\n{password}\nEOF\n")
            askpass_file.close()
            os.chmod(askpass_file.name, 0o700)
            env["SSH_ASKPASS"] = askpass_file.name
            env["SSH_ASKPASS_REQUIRE"] = "force"
            env["DISPLAY"] = env.get("DISPLAY", ":0")
        except Exception:
            askpass_file = None

        ssh_cmd = ["ssh", *port_args, "-o", "StrictHostKeyChecking=accept-new", target]
        try:
            QApplication.clipboard().setText(password)
        except Exception:
            pass
    else:
        ssh_cmd = ["ssh", *port_args, target]

    terms = [
        ("konsole", ["konsole", "-e", *ssh_cmd]),
        ("gnome-terminal", ["gnome-terminal", "--", *ssh_cmd]),
        ("x-terminal-emulator", ["x-terminal-emulator", "-e", " ".join(ssh_cmd)]),
        ("xfce4-terminal", ["xfce4-terminal", "-e", " ".join(ssh_cmd)]),
        ("xterm", ["xterm", "-e", " ".join(ssh_cmd)]),
    ]

    launched = False
    for name, cmd in terms:
        if shutil.which(name):
            try:
                subprocess.Popen(cmd, env=env)
                launched = True
                break
            except Exception:
                pass

    if not launched:
        try:
            subprocess.Popen(["xterm", "-e", " ".join(ssh_cmd)], env=env)
            launched = True
        except Exception as e:
            print("Erro iniciando terminal SSH:", e)
            launched = False

    # Schedule cleanup of transient askpass file
    if askpass_file:
        try:
            # Clean up after brief delay
            from PyQt5.QtCore import QTimer
            QTimer.singleShot(5000, lambda: os.path.exists(askpass_file.name) and os.unlink(askpass_file.name))
        except Exception:
            pass

    return launched


class SshConnectDialog(QDialog):
    """
    Modern modal dialog for entering SSH credentials with support for saving
    user and password per IP for subsequent instant access.
    """
    def __init__(self, parent=None, ip: str = "", hostname: str = ""):
        super().__init__(parent)
        self.ip = ip.strip()
        self.hostname = hostname.strip()
        self.user = ""
        self.password = ""
        self.port = 22
        self.should_save = True

        self.setWindowTitle(f"Conexão SSH — {self.ip}")
        self.resize(460, 360)
        self.init_ui()
        self.load_saved_credentials()

    def init_ui(self):
        vbox = QVBoxLayout(self)
        vbox.setContentsMargins(18, 16, 18, 16)
        vbox.setSpacing(12)

        is_dark = getattr(self.parent(), "is_dark_mode", False) if self.parent() else False
        hdr_bg = "#162032" if is_dark else "#d2d2d2"
        hdr_border = "#1f2937" if is_dark else "#a8a8a8"
        title_col = "#38bdf8" if is_dark else "#164e78"
        sub_col = "#94a3b8" if is_dark else "#3b424a"

        # Header card
        hdr = QFrame()
        hdr.setObjectName("sshHeaderFrame")
        hdr.setStyleSheet(f"""
            QFrame#sshHeaderFrame {{
                background-color: {hdr_bg};
                border: 1px solid {hdr_border};
                border-radius: 6px;
                padding: 10px;
            }}
        """)
        h_layout = QHBoxLayout(hdr)
        h_layout.setContentsMargins(6, 4, 6, 4)
        h_layout.setSpacing(12)

        lbl_icon = QLabel("💻")
        lbl_icon.setStyleSheet("font-size: 28px; border: none;")
        h_layout.addWidget(lbl_icon)

        info_box = QVBoxLayout()
        info_box.setSpacing(2)
        lbl_title = QLabel(f"Conectar via SSH: {self.ip}")
        lbl_title.setStyleSheet(f"font-weight: bold; font-size: 14px; color: {title_col}; border: none;")
        sub_text = f"Host: {self.hostname}" if self.hostname else "Sessão remota via Terminal seguro OpenSSH"
        lbl_sub = QLabel(sub_text)
        lbl_sub.setStyleSheet(f"font-size: 12px; color: {sub_col}; border: none;")
        info_box.addWidget(lbl_title)
        info_box.addWidget(lbl_sub)
        h_layout.addLayout(info_box)
        vbox.addWidget(hdr)

        # Form container
        form_frame = QFrame()
        form_layout = QVBoxLayout(form_frame)
        form_layout.setContentsMargins(0, 4, 0, 4)
        form_layout.setSpacing(8)

        # Row 1: Username & Port
        row1 = QHBoxLayout()
        row1.setSpacing(10)

        # User
        box_user = QVBoxLayout()
        box_user.setSpacing(3)
        lbl_user = QLabel("Usuário SSH:")
        lbl_user.setStyleSheet("font-weight: 600; font-size: 12px;")
        self.txt_user = QLineEdit()
        self.txt_user.setPlaceholderText("ex: root, ubuntu, admin")
        self.txt_user.setFixedHeight(32)
        box_user.addWidget(lbl_user)
        box_user.addWidget(self.txt_user)
        row1.addLayout(box_user, 3)

        # Port
        box_port = QVBoxLayout()
        box_port.setSpacing(3)
        lbl_port = QLabel("Porta:")
        lbl_port.setStyleSheet("font-weight: 600; font-size: 12px;")
        self.spin_port = QSpinBox()
        self.spin_port.setRange(1, 65535)
        self.spin_port.setValue(22)
        self.spin_port.setFixedHeight(32)
        box_port.addWidget(lbl_port)
        box_port.addWidget(self.spin_port)
        row1.addLayout(box_port, 1)

        form_layout.addLayout(row1)

        # Row 2: Password with Show/Hide toggle
        box_pass = QVBoxLayout()
        box_pass.setSpacing(3)
        lbl_pass = QLabel("Senha (opcional se usar chave SSH):")
        lbl_pass.setStyleSheet("font-weight: 600; font-size: 12px;")
        
        pass_row = QHBoxLayout()
        pass_row.setSpacing(6)
        self.txt_password = QLineEdit()
        self.txt_password.setEchoMode(QLineEdit.Password)
        self.txt_password.setPlaceholderText("Digite a senha do usuário...")
        self.txt_password.setFixedHeight(32)
        
        self.btn_toggle_eye = QPushButton("👁")
        self.btn_toggle_eye.setFixedSize(36, 32)
        self.btn_toggle_eye.setToolTip("Exibir ou ocultar senha")
        self.btn_toggle_eye.setCheckable(True)
        self.btn_toggle_eye.clicked.connect(self._toggle_password_visibility)
        
        pass_row.addWidget(self.txt_password)
        pass_row.addWidget(self.btn_toggle_eye)
        
        box_pass.addWidget(lbl_pass)
        box_pass.addLayout(pass_row)
        form_layout.addLayout(box_pass)

        # Checkbox: Remember credentials
        self.chk_save = QCheckBox("Lembrar usuário e senha para este IP")
        self.chk_save.setChecked(True)
        self.chk_save.setStyleSheet("font-weight: 500; font-size: 12px; margin-top: 4px;")
        form_layout.addWidget(self.chk_save)

        # Optional: Forget button
        self.btn_forget = QPushButton("🗑️ Esquecer Credenciais Salvas")
        self.btn_forget.setFixedHeight(26)
        self.btn_forget.setVisible(False)
        self.btn_forget.setStyleSheet("font-size: 11px; color: #ef4444; text-align: left; background: transparent; border: none;")
        self.btn_forget.setCursor(Qt.PointingHandCursor)
        self.btn_forget.clicked.connect(self.forget_credentials)
        form_layout.addWidget(self.btn_forget)

        vbox.addWidget(form_frame)

        # Buttons
        btn_box = QHBoxLayout()
        btn_box.setSpacing(10)
        btn_box.addStretch()

        btn_cancel = QPushButton("Cancelar")
        btn_cancel.setFixedHeight(34)
        btn_cancel.setFixedWidth(100)
        btn_cancel.clicked.connect(self.reject)
        btn_box.addWidget(btn_cancel)

        self.btn_connect = QPushButton("💻 Conectar")
        self.btn_connect.setObjectName("btnStart")
        self.btn_connect.setFixedHeight(34)
        self.btn_connect.setFixedWidth(120)
        self.btn_connect.setDefault(True)
        self.btn_connect.clicked.connect(self.on_connect_clicked)
        btn_box.addWidget(self.btn_connect)

        vbox.addLayout(btn_box)

    def _toggle_password_visibility(self):
        if self.btn_toggle_eye.isChecked():
            self.txt_password.setEchoMode(QLineEdit.Normal)
            self.btn_toggle_eye.setText("🔒")
        else:
            self.txt_password.setEchoMode(QLineEdit.Password)
            self.btn_toggle_eye.setText("👁")

    def load_saved_credentials(self):
        saved = get_ssh_credential_for_ip(self.ip)
        if saved:
            self.txt_user.setText(saved.get("user", ""))
            self.spin_port.setValue(saved.get("port", 22))
            if saved.get("password"):
                self.txt_password.setText(saved.get("password", ""))
            self.chk_save.setChecked(True)
            self.btn_forget.setVisible(True)
            # Focus on connect button if both user and password exist
            if saved.get("user") and saved.get("password"):
                self.btn_connect.setFocus()
            elif saved.get("user"):
                self.txt_password.setFocus()
        else:
            # Suggest current user as fallback
            default_user = getpass.getuser()
            if default_user and default_user != "root":
                self.txt_user.setText(default_user)
            self.txt_user.setFocus()

    def forget_credentials(self):
        delete_ssh_credential(self.ip)
        self.txt_user.clear()
        self.txt_password.clear()
        self.btn_forget.setVisible(False)
        QMessageBox.information(self, "Credenciais Removidas", f"As credenciais salvas para o host {self.ip} foram removidas com sucesso.")

    def on_connect_clicked(self):
        user = self.txt_user.text().strip()
        if not user:
            QMessageBox.warning(self, "Usuário Obrigatório", "Por favor, informe o nome de usuário SSH para conectar.")
            self.txt_user.setFocus()
            return

        password = self.txt_password.text()
        port = self.spin_port.value()
        save = self.chk_save.isChecked()

        if save:
            save_ssh_credential(self.ip, user=user, password=password, port=port, save_password=bool(password))
        else:
            delete_ssh_credential(self.ip)

        self.user = user
        self.password = password
        self.port = port
        self.should_save = save
        self.accept()
