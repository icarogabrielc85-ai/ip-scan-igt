#!/usr/bin/env python3
"""
Internet Health, Latency & DNS Benchmark Diagnostic Dialog for IP Scan IGT.
Measures gateway ping, network interface DNS servers, and benchmarks major public DNS providers
(Cloudflare, Google, GigaDNS, CleanBrowsing, Control D, OpenDNS, Quad9, AdGuard, Mullvad, Comodo, Yandex, Level3, SafeDNS, Neustar UltraDNS)
with packet loss, jitter, and DNS resolution latency.
Fully adaptive to both Dark Mode and Light Mode with high-contrast, modern UI/UX ergonomics.
"""

import concurrent.futures
import json
import math
import os
import platform
import re
import socket
import statistics
import struct
import subprocess
import sys
import time
import urllib.request
from typing import Dict, List, Optional, Tuple

from scanner_engine import robust_urlopen
from i18n import tr

from PyQt5.QtCore import QObject, QPoint, QPointF, QRectF, QSize, Qt, QThread, pyqtSignal
from PyQt5.QtGui import QBrush, QColor, QFont, QIcon, QLinearGradient, QPainter, QPen
from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTabBar,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

IS_WINDOWS = sys.platform.startswith("win") or os.name == "nt"

DEFAULT_PUBLIC_DNS_TARGETS = [
    # Cloudflare
    {
        "provider": "Cloudflare DNS (Primário)",
        "ip": "1.1.1.1",
        "category": "Público Global",
        "feature": "Ultra Baixa Latência / Foco em Privacidade",
        "icon": "⚡",
    },
    {
        "provider": "Cloudflare DNS (Secundário)",
        "ip": "1.0.0.1",
        "category": "Público Global",
        "feature": "Ultra Baixa Latência / Backup Cloudflare",
        "icon": "⚡",
    },
    # Google Public DNS
    {
        "provider": "Google Public DNS (Primário)",
        "ip": "8.8.8.8",
        "category": "Público Global",
        "feature": "Alta Confiabilidade & Anycast Global",
        "icon": "🔍",
    },
    {
        "provider": "Google Public DNS (Secundário)",
        "ip": "8.8.4.4",
        "category": "Público Global",
        "feature": "Alta Confiabilidade / Backup Google",
        "icon": "🔍",
    },
    # GigaDNS (Latência otimizada para o Brasil)
    {
        "provider": "GigaDNS (Primário)",
        "ip": "189.38.95.95",
        "category": "Brasil / Latência Otimizada",
        "feature": "Latência otimizada para o Brasil",
        "icon": "🇧🇷",
    },
    {
        "provider": "GigaDNS (Secundário)",
        "ip": "189.38.95.96",
        "category": "Brasil / Latência Otimizada",
        "feature": "Latência otimizada para o Brasil",
        "icon": "🇧🇷",
    },
    # CleanBrowsing (Filtro de Segurança)
    {
        "provider": "CleanBrowsing (Primário)",
        "ip": "185.228.168.9",
        "category": "Filtro de Segurança",
        "feature": "Filtro de segurança e proteção para família",
        "icon": "🛡️",
    },
    {
        "provider": "CleanBrowsing (Secundário)",
        "ip": "185.228.169.9",
        "category": "Filtro de Segurança",
        "feature": "Filtro de segurança e proteção para família",
        "icon": "🛡️",
    },
    # Control D (Sem filtros/Alta velocidade)
    {
        "provider": "Control D (Primário)",
        "ip": "76.76.2.0",
        "category": "Velocidade & Neutro",
        "feature": "Sem filtros / Alta velocidade Anycast",
        "icon": "⚡",
    },
    {
        "provider": "Control D (Secundário)",
        "ip": "76.76.10.0",
        "category": "Velocidade & Neutro",
        "feature": "Sem filtros / Alta velocidade Anycast",
        "icon": "⚡",
    },
    # OpenDNS Cisco
    {
        "provider": "OpenDNS Cisco (Primário)",
        "ip": "208.67.222.222",
        "category": "Segurança & Filtro",
        "feature": "Proteção Antiphishing & Bloqueio de Malware",
        "icon": "🛡️",
    },
    {
        "provider": "OpenDNS Cisco (Secundário)",
        "ip": "208.67.220.220",
        "category": "Segurança & Filtro",
        "feature": "Proteção Antiphishing / Backup Cisco",
        "icon": "🛡️",
    },
    # Quad9 DNS
    {
        "provider": "Quad9 DNS (Primário)",
        "ip": "9.9.9.9",
        "category": "Segurança & Privacidade",
        "feature": "Filtro Ativo contra Ameaças e Botnets",
        "icon": "🔒",
    },
    {
        "provider": "Quad9 DNS (Secundário)",
        "ip": "149.112.112.112",
        "category": "Segurança & Privacidade",
        "feature": "Filtro Ativo contra Ameaças / Backup Quad9",
        "icon": "🔒",
    },
    # AdGuard DNS
    {
        "provider": "AdGuard DNS (Primário)",
        "ip": "94.140.14.14",
        "category": "Privacidade & Anti-Ad",
        "feature": "Bloqueio de Anúncios e Rastreadores",
        "icon": "🚫",
    },
    {
        "provider": "AdGuard DNS (Secundário)",
        "ip": "94.140.15.15",
        "category": "Privacidade & Anti-Ad",
        "feature": "Bloqueio de Anúncios / Backup AdGuard",
        "icon": "🚫",
    },
    # Alternate DNS (Bloqueio de anúncios)
    {
        "provider": "Alternate DNS (Primário)",
        "ip": "76.76.19.19",
        "category": "Bloqueio de Anúncios",
        "feature": "Bloqueio de anúncios e rastreadores",
        "icon": "🚫",
    },
    {
        "provider": "Alternate DNS (Secundário)",
        "ip": "76.223.122.150",
        "category": "Bloqueio de Anúncios",
        "feature": "Bloqueio de anúncios e rastreadores",
        "icon": "🚫",
    },
    # Mullvad DNS (Foco em privacidade e sem logs)
    {
        "provider": "Mullvad DNS (Primário)",
        "ip": "194.242.2.2",
        "category": "Privacidade Estrita",
        "feature": "Foco em privacidade e sem logs (No-Log)",
        "icon": "🕵️",
    },
    {
        "provider": "Mullvad DNS (Secundário)",
        "ip": "194.242.2.3",
        "category": "Privacidade Estrita",
        "feature": "Foco em privacidade e sem logs (No-Log)",
        "icon": "🕵️",
    },
    # Comodo Secure DNS (Foco em segurança)
    {
        "provider": "Comodo Secure DNS (Primário)",
        "ip": "8.26.56.26",
        "category": "Foco em Segurança",
        "feature": "Foco em segurança e proteção contra ameaças",
        "icon": "🛡️",
    },
    {
        "provider": "Comodo Secure DNS (Secundário)",
        "ip": "8.20.247.20",
        "category": "Foco em Segurança",
        "feature": "Foco em segurança e proteção contra ameaças",
        "icon": "🛡️",
    },
    # Yandex.DNS (Básico/Confiável)
    {
        "provider": "Yandex.DNS (Primário)",
        "ip": "77.88.8.8",
        "category": "Básico & Confiável",
        "feature": "Básico e confiável Anycast",
        "icon": "🌐",
    },
    {
        "provider": "Yandex.DNS (Secundário)",
        "ip": "77.88.8.1",
        "category": "Básico & Confiável",
        "feature": "Básico e confiável Anycast / Backup",
        "icon": "🌐",
    },
    # Level3 / CenturyLink (Infraestrutura de backbone)
    {
        "provider": "Level3 / CenturyLink (Primário)",
        "ip": "209.244.0.3",
        "category": "Infraestrutura Backbone",
        "feature": "Infraestrutura de backbone Tier-1",
        "icon": "🏢",
    },
    {
        "provider": "Level3 / CenturyLink (Secundário)",
        "ip": "209.244.0.4",
        "category": "Infraestrutura Backbone",
        "feature": "Infraestrutura de backbone Tier-1",
        "icon": "🏢",
    },
    # SafeDNS (Filtro de conteúdo e ameaças)
    {
        "provider": "SafeDNS (Primário)",
        "ip": "195.46.39.39",
        "category": "Filtro de Conteúdo",
        "feature": "Filtro de conteúdo e ameaças cibernéticas",
        "icon": "🔒",
    },
    {
        "provider": "SafeDNS (Secundário)",
        "ip": "195.46.39.40",
        "category": "Filtro de Conteúdo",
        "feature": "Filtro de conteúdo e ameaças cibernéticas",
        "icon": "🔒",
    },
    # Neustar UltraDNS (Proteção contra ameaças)
    {
        "provider": "Neustar UltraDNS (Primário)",
        "ip": "156.154.70.2",
        "category": "Proteção contra Ameaças",
        "feature": "Proteção corporativa contra ameaças",
        "icon": "🛡️",
    },
    {
        "provider": "Neustar UltraDNS (Secundário)",
        "ip": "156.154.71.2",
        "category": "Proteção contra Ameaças",
        "feature": "Proteção corporativa contra ameaças",
        "icon": "🛡️",
    },
]

from config_paths import get_config_file

PUBLIC_DNS_TARGETS = DEFAULT_PUBLIC_DNS_TARGETS
DNS_TARGETS_FILE = get_config_file("dns_targets.json")


def load_dns_targets() -> List[Dict[str, str]]:
    """Carrega lista de servidores DNS personalizados ou os 30 padrões de fábrica."""
    if os.path.exists(DNS_TARGETS_FILE):
        try:
            with open(DNS_TARGETS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list) and len(data) > 0:
                    return data
        except Exception as e:
            print("Erro ao carregar dns_targets.json:", e)
    return [dict(x) for x in DEFAULT_PUBLIC_DNS_TARGETS]


def save_dns_targets(targets: List[Dict[str, str]]) -> bool:
    """Salva a lista de servidores DNS no disco para persistência contínua."""
    try:
        os.makedirs(os.path.dirname(DNS_TARGETS_FILE), exist_ok=True)
        with open(DNS_TARGETS_FILE, "w", encoding="utf-8") as f:
            json.dump(targets, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print("Erro ao salvar dns_targets.json:", e)
        return False


def reset_dns_targets() -> List[Dict[str, str]]:
    """Restaura a lista para os alvos padrão de fábrica e salva."""
    targets = [dict(x) for x in DEFAULT_PUBLIC_DNS_TARGETS]
    save_dns_targets(targets)
    return targets


class DnsEntryDialog(QDialog):
    """
    Diálogo modal moderno para adicionar ou editar servidores DNS na lista de benchmark.
    """
    def __init__(self, parent=None, entry: Optional[Dict[str, str]] = None, is_dark: bool = False):
        super().__init__(parent)
        self.entry = entry
        self.is_edit = entry is not None
        self.is_dark = is_dark
        self.result_entry: Optional[Dict[str, str]] = None

        title = tr("dns_dialog_edit_title") if self.is_edit else tr("dns_dialog_add_title")
        self.setWindowTitle(title)
        self.setFixedSize(480, 390)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        c_bg = "#0f172a" if self.is_dark else "#dcdcdc"
        c_card = "#1e293b" if self.is_dark else "#ededed"
        c_text = "#f8fafc" if self.is_dark else "#1e242b"
        c_sub = "#94a3b8" if self.is_dark else "#3b424a"
        c_border = "#334155" if self.is_dark else "#a8a8a8"
        c_accent = "#38bdf8" if self.is_dark else "#2b6595"

        self.setStyleSheet(f"""
            QDialog {{ background-color: {c_bg}; color: {c_text}; }}
            QLabel {{ font-size: 12px; font-weight: bold; color: {c_text}; }}
            QLineEdit, QComboBox {{
                background-color: {c_card};
                color: {c_text};
                border: 1px solid {c_border};
                border-radius: 5px;
                padding: 6px 10px;
                font-size: 12px;
            }}
            QPushButton {{
                border-radius: 5px;
                padding: 7px 16px;
                font-size: 12px;
                font-weight: bold;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(20, 18, 20, 18)

        # Name
        layout.addWidget(QLabel(tr("dns_field_name")))
        self.txt_name = QLineEdit()
        self.txt_name.setPlaceholderText("Ex: NextDNS (Primário) ou Cisco Umbrella")
        if self.is_edit:
            self.txt_name.setText(self.entry.get("provider", ""))
        layout.addWidget(self.txt_name)

        # IP
        layout.addWidget(QLabel(tr("dns_field_ip")))
        self.txt_ip = QLineEdit()
        self.txt_ip.setPlaceholderText("Ex: 45.90.28.0")
        if self.is_edit:
            self.txt_ip.setText(self.entry.get("ip", ""))
        layout.addWidget(self.txt_ip)

        # Category
        layout.addWidget(QLabel(tr("dns_field_category")))
        self.combo_cat = QComboBox()
        self.combo_cat.setEditable(True)
        common_cats = [
            "Público Global",
            "Segurança & Filtro",
            "Bloqueio de Anúncios",
            "Privacidade Estrita",
            "Brasil / Latência Otimizada",
            "Velocidade & Neutro",
            "Infraestrutura Backbone",
            "Filtro de Conteúdo",
            "Rede Local / Corporativo",
        ]
        for c in common_cats:
            self.combo_cat.addItem(c)
        if self.is_edit:
            self.combo_cat.setCurrentText(self.entry.get("category", "Público Global"))
        layout.addWidget(self.combo_cat)

        # Feature
        layout.addWidget(QLabel(tr("dns_field_feature")))
        self.txt_feat = QLineEdit()
        self.txt_feat.setPlaceholderText("Ex: Ultra Baixa Latência / Foco em Privacidade")
        if self.is_edit:
            self.txt_feat.setText(self.entry.get("feature", ""))
        layout.addWidget(self.txt_feat)

        # Icon
        layout.addWidget(QLabel(tr("dns_field_icon")))
        self.combo_icon = QComboBox()
        icons = ["⚡", "🔍", "🛡️", "🔒", "🚫", "🌐", "🇧🇷", "🏢", "🕵️", "🚀", "🏠"]
        for ic in icons:
            self.combo_icon.addItem(ic)
        if self.is_edit and self.entry.get("icon") in icons:
            self.combo_icon.setCurrentText(self.entry.get("icon"))
        layout.addWidget(self.combo_icon)

        layout.addSpacing(8)

        # Buttons
        btn_box = QHBoxLayout()
        btn_box.addStretch()

        self.btn_cancel = QPushButton(tr("btn_cancel"))
        self.btn_cancel.setCursor(Qt.PointingHandCursor)
        self.btn_cancel.setStyleSheet(f"background-color: {c_card}; border: 1px solid {c_border}; color: {c_text};")
        self.btn_cancel.clicked.connect(self.reject)
        btn_box.addWidget(self.btn_cancel)

        self.btn_save = QPushButton(tr("btn_save"))
        self.btn_save.setCursor(Qt.PointingHandCursor)
        self.btn_save.setStyleSheet(f"background-color: {c_accent}; color: #ffffff; border: none;")
        self.btn_save.clicked.connect(self.save_entry)
        btn_box.addWidget(self.btn_save)

        layout.addLayout(btn_box)

    def save_entry(self):
        name = self.txt_name.text().strip()
        ip = self.txt_ip.text().strip()
        cat = self.combo_cat.currentText().strip() or "Público Global"
        feat = self.txt_feat.text().strip() or name
        icon = self.combo_icon.currentText() or "🌐"

        if not name:
            QMessageBox.warning(self, "Aviso", "Por favor, informe o nome do provedor DNS.")
            self.txt_name.setFocus()
            return

        parts = ip.split(".")
        if len(parts) != 4:
            QMessageBox.warning(self, "IP Inválido", tr("dns_invalid_ip"))
            self.txt_ip.setFocus()
            return
        try:
            for p in parts:
                v = int(p)
                if v < 0 or v > 255:
                    raise ValueError()
        except Exception:
            QMessageBox.warning(self, "IP Inválido", tr("dns_invalid_ip"))
            self.txt_ip.setFocus()
            return

        self.result_entry = {
            "provider": name,
            "ip": ip,
            "category": cat,
            "feature": feat,
            "icon": icon,
        }
        self.accept()



def get_interface_configured_dns() -> List[str]:
    """Retrieves DNS server IPs configured on active local network interfaces."""
    dns_servers = []
    if not IS_WINDOWS:
        # 1. systemd-resolved (resolvectl)
        try:
            out = subprocess.check_output(["resolvectl", "dns"], text=True, stderr=subprocess.DEVNULL, timeout=1.5)
            for m in re.finditer(r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", out):
                ip = m.group(1)
                if ip not in dns_servers and not ip.startswith("127."):
                    dns_servers.append(ip)
        except Exception:
            pass

        # 2. /run/systemd/resolve/resolv.conf and /etc/resolv.conf
        for fpath in ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"]:
            if os.path.exists(fpath):
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        for line in f:
                            if line.strip().startswith("nameserver"):
                                parts = line.split()
                                if len(parts) >= 2:
                                    ip = parts[1].strip()
                                    if ip not in dns_servers and not ip.startswith("127."):
                                        dns_servers.append(ip)
                except Exception:
                    pass
    else:
        # Windows ipconfig /all
        try:
            kwargs = {
                "text": True,
                "stderr": subprocess.DEVNULL,
                "timeout": 2.0,
            }
            if IS_WINDOWS:
                if hasattr(subprocess, "CREATE_NO_WINDOW"):
                    kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
                kwargs["startupinfo"] = startupinfo

            out = subprocess.check_output(["ipconfig", "/all"], **kwargs)
            capture = False
            for line in out.splitlines():
                if "DNS Servers" in line or "Servidores DNS" in line:
                    capture = True
                if capture:
                    m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
                    if m:
                        ip = m.group(1)
                        if ip not in dns_servers:
                            dns_servers.append(ip)
                    elif line.strip() and not line.startswith(" "):
                        capture = False
        except Exception:
            pass

    return dns_servers


def query_dns_latency(dns_ip: str, domain: str = "google.com", timeout: float = 1.8) -> Tuple[Optional[float], bool]:
    """
    Sends a standard RFC 1035 Type A DNS query to port 53 of dns_ip and measures exact RTT in ms.
    Zero external dependencies.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    # Build RFC 1035 DNS Query Header
    packet = bytearray()
    packet.extend(b"\x2a\x7e")  # Transaction ID
    packet.extend(b"\x01\x00")  # Flags: Standard query, Recursion Desired
    packet.extend(b"\x00\x01")  # QDCOUNT: 1 question
    packet.extend(b"\x00\x00\x00\x00\x00\x00")  # ANCOUNT, NSCOUNT, ARCOUNT: 0

    # Question domain labels
    for part in domain.split("."):
        packet.append(len(part))
        packet.extend(part.encode("ascii"))
    packet.append(0)            # End of name
    packet.extend(b"\x00\x01")  # QTYPE: A (Host address)
    packet.extend(b"\x00\x01")  # QCLASS: IN (Internet)

    t0 = time.perf_counter()
    try:
        sock.sendto(packet, (dns_ip, 53))
        data, _ = sock.recvfrom(1024)
        elapsed = (time.perf_counter() - t0) * 1000
        sock.close()
        return round(elapsed, 1), True
    except Exception:
        sock.close()
        return None, False


def ping_target_stats(ip: str, count: int = 3, timeout_sec: int = 1) -> Tuple[Optional[float], Optional[float], Optional[float], int]:
    """
    Executes count ICMP echo pings returning (min_ms, avg_ms, max_ms, packet_loss_pct).
    Executes 100% silently in the background with zero CMD window popups on Windows.
    """
    cmd = ["ping", "-n" if IS_WINDOWS else "-c", str(count), "-w" if IS_WINDOWS else "-W", str(timeout_sec * 1000 if IS_WINDOWS else timeout_sec), ip]
    kwargs = {
        "text": True,
        "stderr": subprocess.DEVNULL,
        "timeout": count * timeout_sec + 2.0,
    }
    if IS_WINDOWS:
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        kwargs["startupinfo"] = startupinfo

    try:
        out = subprocess.check_output(cmd, **kwargs)
        # Packet loss
        loss_m = re.search(r"([0-9]+)%\s*(?:packet\s*loss|perdidos)", out, re.IGNORECASE)
        loss = int(loss_m.group(1)) if loss_m else 0

        # RTT stats
        if not IS_WINDOWS:
            # Linux: min/avg/max/mdev = 7.123/8.456/9.789/0.890 ms
            m = re.search(r"min/avg/max[^=]*=\s*([0-9\.]+)/([0-9\.]+)/([0-9\.]+)", out)
            if m:
                return float(m.group(1)), float(m.group(2)), float(m.group(3)), loss
        else:
            # Windows: Minimum = 7ms, Maximum = 9ms, Average = 8ms
            m_min = re.search(r"(?:Minimum|M.nimo)\s*=\s*([0-9]+)ms", out, re.IGNORECASE)
            m_max = re.search(r"(?:Maximum|M.ximo)\s*=\s*([0-9]+)ms", out, re.IGNORECASE)
            m_avg = re.search(r"(?:Average|M.dia)\s*=\s*([0-9]+)ms", out, re.IGNORECASE)
            if m_avg:
                p_min = float(m_min.group(1)) if m_min else float(m_avg.group(1))
                p_max = float(m_max.group(1)) if m_max else float(m_avg.group(1))
                p_avg = float(m_avg.group(1))
                return p_min, p_avg, p_max, loss
        return None, None, None, loss
    except Exception:
        return None, None, None, 100


def get_public_ip_info() -> Dict[str, str]:
    """Fetches public WAN IP from external IP service."""
    services = [
        "https://api.ipify.org?format=json",
        "https://ifconfig.me/all.json",
        "https://icanhazip.com",
    ]
    for url in services:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "IPScanIGT/2.6.2"})
            with robust_urlopen(req, timeout=1.8) as resp:
                content = resp.read().decode("utf-8").strip()
                if content.startswith("{"):
                    data = json.loads(content)
                    ip = data.get("ip") or data.get("ip_addr")
                    if ip:
                        return {"ip": ip, "status": "online"}
                elif re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", content):
                    return {"ip": content, "status": "online"}
        except Exception:
            continue
    return {"ip": "Indisponível (Sem rota externa)", "status": "offline"}


class NumericTableWidgetItem(QTableWidgetItem):
    """
    Table widget item supporting accurate numeric and hierarchical sorting
    rather than purely alphabetical string comparison.
    """
    def __init__(self, text: str, sort_key=None, raw_data=None):
        super().__init__(text)
        self.sort_key = sort_key
        self.raw_data = raw_data

    def __lt__(self, other):
        if isinstance(other, NumericTableWidgetItem):
            v1 = self.sort_key
            v2 = other.sort_key
            if v1 is not None and v2 is not None:
                try:
                    return v1 < v2
                except TypeError:
                    return str(v1) < str(v2)
            if v1 is None:
                return False
            if v2 is None:
                return True
        return super().__lt__(other)


class InternetTestWorker(QThread):
    """Background worker executing parallel latency, loss, and DNS resolution tests."""
    progress = pyqtSignal(int, int, str)
    target_tested = pyqtSignal(dict)
    finished = pyqtSignal(dict)

    def __init__(self, gateway_ip: str = "", dns_targets: Optional[List[Dict]] = None):
        super().__init__()
        self.gateway_ip = gateway_ip.strip()
        self.dns_targets = dns_targets
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True

    def run(self):
        # 1. Fetch public IP info
        pub_info = get_public_ip_info()
        if self._is_cancelled:
            return

        # 2. Assemble test targets list strictly for public DNS benchmark
        targets = []
        active_targets = self.dns_targets if self.dns_targets is not None else load_dns_targets()
        for p in active_targets:
            p_copy = dict(p)
            p_copy["is_dns"] = True
            targets.append(p_copy)

        total_targets = len(targets)
        results = []

        # Local Gateway test (for KPI summary)
        def _test_gateway():
            if self._is_cancelled or not self.gateway_ip or self.gateway_ip == "N/D":
                return None
            p_min, p_avg, p_max, loss = ping_target_stats(self.gateway_ip, count=3, timeout_sec=1)
            return {
                "provider": "Gateway da Rede Local",
                "ip": self.gateway_ip,
                "ping_avg": p_avg,
                "packet_loss": loss,
                "is_dns": False,
            }

        # Local DNS test (for KPI summary & comparison)
        local_dns_ips = get_interface_configured_dns()
        def _test_local_dns(d_ip, idx):
            if self._is_cancelled:
                return None
            dns_rtt, dns_ok = query_dns_latency(d_ip)
            p_min, p_avg, p_max, loss = ping_target_stats(d_ip, count=3, timeout_sec=1)
            score = dns_rtt if (dns_rtt is not None) else (p_avg if p_avg is not None else 9999.0)
            return {
                "provider": f"DNS da Placa {'(Primário)' if idx == 0 else '(Secundário)'}",
                "ip": d_ip,
                "dns_rtt": dns_rtt,
                "dns_ok": dns_ok,
                "ping_avg": p_avg,
                "packet_loss": loss,
                "score_latency": score,
                "is_dns": True,
            }

        # 3. Test targets in parallel using thread pool
        def _test_single_target(item):
            if self._is_cancelled:
                return None
            ip = item["ip"]
            is_dns = item.get("is_dns", True)

            # DNS Query RTT
            dns_rtt = None
            dns_ok = False
            if is_dns:
                dns_rtt, dns_ok = query_dns_latency(ip)

            # ICMP Ping stats
            p_min, p_avg, p_max, loss = ping_target_stats(ip, count=3, timeout_sec=1)

            # Rating logic
            ref_latency = dns_rtt if (is_dns and dns_rtt is not None) else p_avg
            if loss == 100 or (ref_latency is None and not dns_ok):
                rating_key = "rating_unreachable"
                rating = tr(rating_key, "Inacessível")
                badge_type = "danger"
            elif ref_latency is not None and ref_latency < 20.0:
                rating_key = "rating_excellent"
                rating = tr(rating_key, "Excelente")
                badge_type = "success"
            elif ref_latency is not None and ref_latency < 50.0:
                rating_key = "rating_good"
                rating = tr(rating_key, "Bom")
                badge_type = "info"
            elif ref_latency is not None and ref_latency < 100.0:
                rating_key = "rating_fair"
                rating = tr(rating_key, "Aceitável")
                badge_type = "warning"
            else:
                rating_key = "rating_slow"
                rating = tr(rating_key, "Lento")
                badge_type = "orange"

            res = {
                **item,
                "dns_rtt": dns_rtt,
                "dns_ok": dns_ok,
                "ping_min": p_min,
                "ping_avg": p_avg,
                "ping_max": p_max,
                "packet_loss": loss,
                "rating": rating,
                "rating_key": rating_key,
                "badge_type": badge_type,
                "score_latency": ref_latency if ref_latency is not None else 9999.0,
            }
            return res

        tested_count = 0
        gw_future = None
        local_dns_futures = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            if self.gateway_ip and self.gateway_ip != "N/D":
                gw_future = executor.submit(_test_gateway)
            for idx, d_ip in enumerate(local_dns_ips):
                local_dns_futures.append(executor.submit(_test_local_dns, d_ip, idx))

            future_to_item = {executor.submit(_test_single_target, item): item for item in targets}
            for future in concurrent.futures.as_completed(future_to_item):
                if self._is_cancelled:
                    break
                tested_count += 1
                try:
                    res = future.result()
                    if res:
                        results.append(res)
                        self.progress.emit(tested_count, total_targets, res["provider"])
                        self.target_tested.emit(res)
                except Exception:
                    pass

        # 4. Determine fastest DNS server
        dns_results = [r for r in results if r.get("is_dns") and r.get("score_latency", 9999) < 9999 and r["packet_loss"] < 50]
        fastest_dns = min(dns_results, key=lambda x: x["score_latency"]) if dns_results else None

        gw_res = gw_future.result() if gw_future else None
        local_dns_res = [f.result() for f in local_dns_futures if f.result() is not None]

        summary = {
            "public_ip": pub_info.get("ip", "N/D"),
            "public_status": pub_info.get("status", "offline"),
            "gateway_ip": self.gateway_ip,
            "gateway_result": gw_res,
            "local_dns_results": local_dns_res,
            "fastest_dns": fastest_dns,
            "total_tested": len(results),
            "results": results,
        }
        self.finished.emit(summary)




# ==============================================================================
# SPEED TEST ENGINE & SPEEDOMETER WIDGET
# ==============================================================================

USER_AGENT_BROWSER = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

SPEED_HEADERS = {
    "User-Agent": USER_AGENT_BROWSER,
    "Referer": "https://speed.cloudflare.com/",
    "Origin": "https://speed.cloudflare.com",
    "Accept": "*/*",
}


def calculate_qoe(ping: float, jitter: float, download: float, upload: float) -> dict:
    """
    Computes Quality of Experience (QoE) metrics for real-world scenarios:
    - 4K Streaming
    - Online Gaming
    - HD Video Calls
    - Practical File Transfer Rate
    """
    # 1. 4K Streaming
    if download >= 50.0:
        stream_score = "⭐⭐⭐⭐⭐"
        stream_status = "Excelente (4K HDR)"
        stream_desc = "Perfeito para múltiplos streams 4K HDR simultâneos sem travamentos."
    elif download >= 25.0:
        stream_score = "⭐⭐⭐⭐"
        stream_status = "Muito Bom (4K UHD)"
        stream_desc = "Ótimo para reprodução 4K UHD individual fluida e estável."
    elif download >= 10.0:
        stream_score = "⭐⭐⭐"
        stream_status = "Regular (Full HD)"
        stream_desc = "Suficiente para Full HD 1080p; pode haver espera em 4K."
    else:
        stream_score = "⭐⭐"
        stream_status = "Limitado (720p)"
        stream_desc = "Velocidade baixa; recomendável resolução até 720p/480p."

    # 2. Gaming
    if ping <= 25.0 and jitter <= 5.0:
        game_score = "⭐⭐⭐⭐⭐"
        game_status = "Ultra Baixo Ping"
        game_desc = f"Latência ultrabaixa ({ping:.1f} ms, jitter {jitter:.1f} ms). Nível competitivo para FPS/MOBA."
    elif ping <= 50.0 and jitter <= 12.0:
        game_score = "⭐⭐⭐⭐"
        game_status = "Ótimo para Jogos"
        game_desc = f"Excelente resposta ({ping:.1f} ms, jitter {jitter:.1f} ms). Jogabilidade suave e sem lag perceptível."
    elif ping <= 90.0:
        game_score = "⭐⭐⭐"
        game_status = "Jogável (Casual)"
        game_desc = f"Latência aceitável ({ping:.1f} ms). Adequado para jogos casuais e estratégicos."
    else:
        game_score = "⭐⭐"
        game_status = "Alto Lag"
        game_desc = f"Alta latência ({ping:.1f} ms) ou oscilação. Risco de atraso e delay em partidas."

    # 3. Video Calls
    if upload >= 5.0 and ping <= 60.0 and jitter <= 10.0:
        calls_score = "⭐⭐⭐⭐⭐"
        calls_status = "HD Cristalino"
        calls_desc = "Áudio cristalino e vídeo Full HD sem congelamentos (Zoom, Teams, Meet)."
    elif upload >= 2.0 and ping <= 100.0:
        calls_score = "⭐⭐⭐⭐"
        calls_status = "Boa Qualidade"
        calls_desc = "Chamadas de vídeo em boa qualidade com estabilidade adequada."
    elif upload >= 1.0:
        calls_score = "⭐⭐⭐"
        calls_status = "Qualidade Padrão"
        calls_desc = "Suficiente para reuniões normais; evite compartilhamento pesado."
    else:
        calls_score = "⭐⭐"
        calls_status = "Instável"
        calls_desc = "Upload insuficiente; pode haver áudio robotizado ou cortes."

    # 4. File Download Rate
    real_mbs = download / 8.0
    sec_1gb = int(1024 / max(0.1, real_mbs))
    transfer_str = f"~{real_mbs:.1f} MB/s"
    if sec_1gb < 60:
        transfer_desc = f"Baixa um arquivo de 1 GB em aproximadamente {sec_1gb} segundos."
    else:
        min_1gb = sec_1gb // 60
        rem_sec = sec_1gb % 60
        transfer_desc = f"Baixa um arquivo de 1 GB em ~{min_1gb}min {rem_sec}s."

    return {
        "streaming": {"score": stream_score, "status": stream_status, "desc": stream_desc},
        "gaming": {"score": game_score, "status": game_status, "desc": game_desc},
        "calls": {"score": calls_score, "status": calls_status, "desc": calls_desc},
        "transfer": {"rate": transfer_str, "desc": transfer_desc, "mbs": real_mbs},
    }


class SpeedometerWidget(QWidget):
    """
    Modern high-contrast gauge widget rendering real-time internet speed
    with smooth gradient arc, glowing pointer indicator, and clean typography.
    """
    def __init__(self, parent=None, is_dark: bool = True):
        super().__init__(parent)
        self.is_dark = is_dark
        self._value = 0.0          # Current speed or ping
        self._max_value = 100.0    # Dynamic scale max
        self._phase = "PRONTO"     # "AGUARDANDO", "PING", "DOWNLOAD", "UPLOAD", "CONCLUÍDO"
        self._unit = "Mbps"
        self._sub_text = "Pronto para iniciar"
        self.setMinimumSize(280, 240)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def set_value(self, val: float, max_val: Optional[float] = None, sub_text: str = ""):
        self._value = max(0.0, float(val))
        if max_val is not None and max_val > 0:
            self._max_value = max(10.0, float(max_val))
        else:
            # Auto-scale dynamically based on speed
            if self._value > self._max_value * 0.85:
                if self._max_value < 100:
                    self._max_value = 100
                elif self._max_value < 250:
                    self._max_value = 250
                elif self._max_value < 500:
                    self._max_value = 500
                elif self._max_value < 1000:
                    self._max_value = 1000
                else:
                    self._max_value = max(self._max_value, self._value * 1.25)
        if sub_text:
            self._sub_text = sub_text
        self.update()

    def set_phase(self, phase: str, unit: str = "Mbps", sub_text: str = ""):
        self._phase = phase
        self._unit = unit
        if sub_text:
            self._sub_text = sub_text
        self.update()

    def reset(self):
        self._value = 0.0
        self._max_value = 100.0
        self._phase = "PRONTO"
        self._unit = "Mbps"
        self._sub_text = "Pronto para iniciar"
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setRenderHint(QPainter.TextAntialiasing)

        w, h = self.width(), self.height()
        cx, cy = w / 2.0, h / 2.0 + 8.0
        r = min(w, h) * 0.38
        if r < 40:
            return

        rect = QRectF(cx - r, cy - r, r * 2.0, r * 2.0)

        # Background track arc (neutral muted color)
        track_color = QColor("#334155" if self.is_dark else "#cbd5e1")
        pen_track = QPen(track_color, 14, Qt.SolidLine, Qt.RoundCap)
        painter.setPen(pen_track)
        painter.drawArc(rect, int(225 * 16), int(-270 * 16))

        # Progress arc & glowing pointer
        frac = max(0.0, min(1.0, self._value / max(1.0, self._max_value)))
        if frac > 0.005:
            grad = QLinearGradient(rect.left(), rect.top(), rect.right(), rect.bottom())
            if "UPLOAD" in self._phase:
                grad.setColorAt(0.0, QColor("#10b981"))
                grad.setColorAt(1.0, QColor("#06b6d4"))
                dot_color = QColor("#34d399")
            elif "PING" in self._phase or "LATÊNCIA" in self._phase:
                grad.setColorAt(0.0, QColor("#a855f7"))
                grad.setColorAt(1.0, QColor("#6366f1"))
                dot_color = QColor("#c084fc")
            else:  # DOWNLOAD or default
                grad.setColorAt(0.0, QColor("#0284c7"))
                grad.setColorAt(1.0, QColor("#38bdf8"))
                dot_color = QColor("#7dd3fc")

            pen_prog = QPen(grad, 14, Qt.SolidLine, Qt.RoundCap)
            painter.setPen(pen_prog)
            painter.drawArc(rect, int(225 * 16), int(-frac * 270 * 16))

            # Tip glowing dot
            deg = 225.0 - (frac * 270.0)
            rad = math.radians(deg)
            dot_x = cx + r * math.cos(rad)
            dot_y = cy - r * math.sin(rad)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(dot_color.red(), dot_color.green(), dot_color.blue(), 80))
            painter.drawEllipse(QPointF(dot_x, dot_y), 11, 11)
            painter.setBrush(dot_color)
            painter.drawEllipse(QPointF(dot_x, dot_y), 5, 5)

        # Center Phase Badge
        painter.setFont(QFont("Segoe UI", 10, QFont.Bold))
        phase_fg = QColor("#38bdf8" if self.is_dark else "#0284c7")
        painter.setPen(phase_fg)
        painter.drawText(QRectF(cx - 100, cy - r + 30, 200, 22), Qt.AlignCenter, self._phase)

        # Main numeric speed
        painter.setFont(QFont("Segoe UI", 32, QFont.Bold))
        main_fg = QColor("#f8fafc" if self.is_dark else "#1e242b")
        painter.setPen(main_fg)
        val_str = f"{self._value:.1f}" if self._value > 0 else "---"
        painter.drawText(QRectF(cx - 110, cy - 25, 220, 48), Qt.AlignCenter, val_str)

        # Unit
        painter.setFont(QFont("Segoe UI", 12, QFont.DemiBold))
        unit_fg = QColor("#94a3b8" if self.is_dark else "#64748b")
        painter.setPen(unit_fg)
        painter.drawText(QRectF(cx - 100, cy + 24, 200, 20), Qt.AlignCenter, self._unit)

        # Sub-text (peak or average)
        painter.setFont(QFont("Segoe UI", 10, QFont.Normal))
        painter.setPen(unit_fg)
        painter.drawText(QRectF(cx - 130, cy + 48, 260, 20), Qt.AlignCenter, self._sub_text)
        painter.end()


class SpeedTestWorker(QThread):
    """
    High-performance internet speed test worker measuring:
    1. Public IP, ISP, and Cloudflare edge location
    2. Latency (Ping) and Jitter
    3. Multi-sample Download Speed (Mbps)
    4. Multi-sample Upload Speed (Mbps)
    5. Real-world Quality of Experience (QoE) metrics
    """
    phase_changed = pyqtSignal(str)
    meta_received = pyqtSignal(dict)
    ping_sample = pyqtSignal(float, float)
    sample = pyqtSignal(str, float, float, int)   # phase, current_mbps, peak_mbps, progress_pct
    download_finished = pyqtSignal(float, float)  # avg_mbps, peak_mbps
    upload_finished = pyqtSignal(float, float)    # avg_mbps, peak_mbps
    finished = pyqtSignal(dict)                   # summary
    error_occurred = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        try:
            # 1. Meta / ISP Identification
            self.phase_changed.emit("meta")
            meta = {
                "ip": "N/D",
                "isp": "Identificando...",
                "city": "N/D",
                "country": "N/D",
                "server": "Cloudflare Edge",
            }
            try:
                req_meta = urllib.request.Request("https://speed.cloudflare.com/meta", headers=SPEED_HEADERS)
                with urllib.request.urlopen(req_meta, timeout=3.5) as resp:
                    m = json.loads(resp.read().decode())
                    colo = m.get("colo", {})
                    meta = {
                        "ip": m.get("clientIp", "N/D"),
                        "isp": m.get("asOrganization", "N/D"),
                        "city": m.get("city", "N/D"),
                        "country": m.get("country", "N/D"),
                        "server": f"{colo.get('city', 'Cloudflare Edge')} ({colo.get('iata', 'Edge')})",
                    }
            except Exception:
                try:
                    req_ip = urllib.request.Request(
                        "http://ip-api.com/json/?fields=status,query,country,city,isp,as",
                        headers=SPEED_HEADERS
                    )
                    with urllib.request.urlopen(req_ip, timeout=3.0) as resp:
                        m2 = json.loads(resp.read().decode())
                        if m2.get("status") == "success":
                            meta["ip"] = m2.get("query", "N/D")
                            meta["isp"] = m2.get("isp", m2.get("as", "N/D"))
                            meta["city"] = m2.get("city", "N/D")
                            meta["country"] = m2.get("country", "N/D")
                            meta["server"] = f"{meta['city']}, {meta['country']}"
                except Exception:
                    pass

            self.meta_received.emit(meta)
            if self._cancelled:
                return

            # 2. Latency & Jitter
            self.phase_changed.emit("ping")
            rtts = []
            for i in range(8):
                if self._cancelled:
                    return
                t_p = time.time()
                try:
                    req_p = urllib.request.Request("https://speed.cloudflare.com/__down?bytes=0", headers=SPEED_HEADERS)
                    with urllib.request.urlopen(req_p, timeout=2.5) as resp:
                        resp.read()
                    rtt = (time.time() - t_p) * 1000.0
                    rtts.append(rtt)
                    cur_jitter = (
                        statistics.mean([abs(rtts[j] - rtts[j-1]) for j in range(1, len(rtts))])
                        if len(rtts) > 1 else 0.0
                    )
                    self.ping_sample.emit(rtt, cur_jitter)
                except Exception:
                    pass
                time.sleep(0.04)

            ping_avg = statistics.median(rtts) if rtts else 999.0
            jitter_avg = (
                statistics.mean([abs(rtts[j] - rtts[j-1]) for j in range(1, len(rtts))])
                if len(rtts) > 1 else 0.0
            )

            if self._cancelled:
                return

            # 3. Download Speed Test (~4.0 seconds)
            self.phase_changed.emit("download")
            t_down_start = time.time()
            total_down_bytes = 0
            down_samples = []
            target_down_dur = 4.0

            url_down = "https://speed.cloudflare.com/__down?bytes=25000000"
            while (time.time() - t_down_start) < target_down_dur and not self._cancelled:
                try:
                    req_d = urllib.request.Request(url_down, headers=SPEED_HEADERS)
                    with urllib.request.urlopen(req_d, timeout=5.0) as resp:
                        last_t = time.time()
                        last_b = total_down_bytes
                        while not self._cancelled:
                            chunk = resp.read(65536)
                            if not chunk:
                                break
                            total_down_bytes += len(chunk)
                            now = time.time()
                            if (now - last_t) >= 0.12:
                                dt = now - last_t
                                db = total_down_bytes - last_b
                                cur_mbps = (db * 8) / (dt * 1_000_000)
                                down_samples.append(cur_mbps)
                                peak_mbps = max(down_samples) if down_samples else cur_mbps
                                elapsed = now - t_down_start
                                pct = min(98, int((elapsed / target_down_dur) * 100))
                                self.sample.emit("download", cur_mbps, peak_mbps, pct)
                                last_t = now
                                last_b = total_down_bytes
                            if (now - t_down_start) >= target_down_dur:
                                break
                except Exception:
                    break

            down_duration = max(0.2, time.time() - t_down_start)
            final_down_mbps = (total_down_bytes * 8) / (down_duration * 1_000_000)
            final_down_peak = max(down_samples) if down_samples else final_down_mbps
            self.download_finished.emit(final_down_mbps, final_down_peak)

            if self._cancelled:
                return

            # 4. Upload Speed Test (~3.5 seconds)
            self.phase_changed.emit("upload")
            t_up_start = time.time()
            total_up_bytes = 0
            up_samples = []
            target_up_dur = 3.5

            payload_512k = b"0" * (1024 * 512)
            payload_1m = b"0" * (1024 * 1024)

            while (time.time() - t_up_start) < target_up_dur and not self._cancelled:
                payload = payload_1m if (time.time() - t_up_start) > 1.0 else payload_512k
                t_chunk = time.time()
                try:
                    req_u = urllib.request.Request(
                        "https://speed.cloudflare.com/__up",
                        data=payload,
                        headers=SPEED_HEADERS,
                        method="POST",
                    )
                    with urllib.request.urlopen(req_u, timeout=4.0) as resp:
                        resp.read()
                    dur_chunk = max(0.001, time.time() - t_chunk)
                    total_up_bytes += len(payload)
                    cur_mbps = (len(payload) * 8) / (dur_chunk * 1_000_000)
                    up_samples.append(cur_mbps)
                    peak_up_mbps = max(up_samples) if up_samples else cur_mbps
                    elapsed = time.time() - t_up_start
                    pct = min(98, int((elapsed / target_up_dur) * 100))
                    self.sample.emit("upload", cur_mbps, peak_up_mbps, pct)
                except Exception:
                    break

            up_duration = max(0.2, time.time() - t_up_start)
            final_up_mbps = (total_up_bytes * 8) / (up_duration * 1_000_000)
            final_up_peak = max(up_samples) if up_samples else final_up_mbps
            self.upload_finished.emit(final_up_mbps, final_up_peak)

            if self._cancelled:
                return

            # 5. QoE & Summary Formulation
            qoe = calculate_qoe(ping_avg, jitter_avg, final_down_mbps, final_up_mbps)
            summary = {
                "meta": meta,
                "ping": ping_avg,
                "jitter": jitter_avg,
                "download": final_down_mbps,
                "download_peak": final_down_peak,
                "upload": final_up_mbps,
                "upload_peak": final_up_peak,
                "download_mb_s": final_down_mbps / 8.0,
                "qoe": qoe,
            }
            self.phase_changed.emit("finished")
            self.finished.emit(summary)

        except Exception as e:
            self.error_occurred.emit(str(e))


class InternetQualityDialog(QDialog):
    """
    Modern modal dialog featuring:
    - Tab 0: High-performance Internet Speed Test with animated speedometer gauge,
             Ping, Jitter, Download/Upload bandwidth and QoE matrix.
    - Tab 1: Comprehensive DNS Benchmark evaluating local router/DHCP and 30+ public DNS
             resolvers with ICMP and UDP 53 latency and custom server manager.
    Dynamically styled for both Dark Mode and Light Mode with high-contrast UI/UX.
    """
    def __init__(self, parent=None, gateway_ip: str = "", is_dark: Optional[bool] = None):
        super().__init__(parent)
        self.gateway_ip = gateway_ip.strip()
        self.worker = None
        self.speed_worker = None
        self.results_list = []
        self.dns_targets = load_dns_targets()
        self.speed_summary = {}
        self.speed_meta = {}

        if is_dark is None:
            self.is_dark = getattr(parent, "is_dark_mode", False)
        else:
            self.is_dark = is_dark

        self.setWindowTitle(tr("net_test_title"))
        self.setWindowFlags(self.windowFlags() | Qt.WindowMinMaxButtonsHint | Qt.WindowCloseButtonHint)

        screen = QApplication.primaryScreen()
        if screen:
            geo = screen.availableGeometry()
            w = max(920, min(1400, int(geo.width() * 0.90)))
            h = max(680, min(900, int(geo.height() * 0.88)))
            x = geo.x() + (geo.width() - w) // 2
            y = geo.y() + (geo.height() - h) // 2
            self.setGeometry(x, y, w, h)
        else:
            self.resize(1000, 720)

        self.init_palette_and_styles()
        self.init_ui()
        self.showMaximized()
        self.start_speed_test()

    def init_palette_and_styles(self):
        """Sets up high-contrast design tokens matching the active theme."""
        if self.is_dark:
            self.c_bg = "#0f172a"          # Slate 900
            self.c_card_bg = "#1e293b"     # Slate 800
            self.c_card_hover = "#243248"
            self.c_border = "#334155"       # Slate 700
            self.c_text_main = "#f8fafc"    # Slate 50 (sharp white)
            self.c_text_sub = "#94a3b8"     # Slate 400
            self.c_table_bg = "#0b1120"     # Slate 950
            self.c_table_alt = "#131d31"
            self.c_header_bg = "#1e293b"
            self.c_header_text = "#cbd5e1"
            self.c_accent = "#38bdf8"       # Sky Blue
            self.c_accent_dark = "#0284c7"
            self.c_rec_bg = "#162032"
            self.c_rec_border = "#38bdf8"
            self.c_rec_text = "#f1f5f9"
        else:
            self.c_bg = "#dcdcdc"
            self.c_card_bg = "#e2e2e2"
            self.c_card_hover = "#d2dce6"
            self.c_border = "#a8a8a8"
            self.c_text_main = "#1e242b"
            self.c_text_sub = "#3b424a"
            self.c_table_bg = "#e8e8e8"
            self.c_table_alt = "#dedede"
            self.c_header_bg = "#d2d2d2"
            self.c_header_text = "#1e242b"
            self.c_accent = "#164e78"
            self.c_accent_dark = "#0d3553"
            self.c_rec_bg = "#d0dfed"
            self.c_rec_border = "#2b6595"
            self.c_rec_text = "#164e78"

    def init_ui(self):
        vbox = QVBoxLayout(self)
        vbox.setContentsMargins(18, 14, 18, 14)
        vbox.setSpacing(10)

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {self.c_bg};
                color: {self.c_text_main};
            }}
        """)

        # 1. Dialog Header Card
        self.hdr = QFrame()
        self.hdr.setObjectName("netTestHdr")
        self.hdr.setStyleSheet(f"""
            QFrame#netTestHdr {{
                background-color: {self.c_card_bg};
                border: 1px solid {self.c_border};
                border-radius: 8px;
                padding: 6px;
            }}
        """)
        h_layout = QHBoxLayout(self.hdr)
        h_layout.setContentsMargins(10, 6, 10, 6)
        h_layout.setSpacing(14)

        lbl_icon = QLabel("🌐")
        lbl_icon.setStyleSheet("font-size: 32px;")
        h_layout.addWidget(lbl_icon)

        info_box = QVBoxLayout()
        info_box.setSpacing(2)
        lbl_title = QLabel(tr("net_test_title"))
        lbl_title.setStyleSheet(f"font-weight: bold; font-size: 15px; color: {self.c_accent};")
        lbl_sub = QLabel("Medição de velocidade em tempo real (Cloudflare Edge) e diagnóstico comparativo de servidores DNS.")
        lbl_sub.setStyleSheet(f"font-size: 12px; color: {self.c_text_sub};")
        info_box.addWidget(lbl_title)
        info_box.addWidget(lbl_sub)
        h_layout.addLayout(info_box, 1)

        vbox.addWidget(self.hdr)

        # 2. Main Tab Widget
        self.tabs = QTabWidget()
        tab_bar_style = f"""
            QTabWidget::pane {{
                border: 1px solid {self.c_border};
                border-radius: 8px;
                background-color: {self.c_bg};
                padding: 4px;
            }}
            QTabBar::tab {{
                background-color: {self.c_card_bg};
                color: {self.c_text_sub};
                border: 1px solid {self.c_border};
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                padding: 8px 18px;
                font-size: 13px;
                font-weight: bold;
                margin-right: 4px;
            }}
            QTabBar::tab:selected {{
                background-color: {self.c_accent if self.is_dark else self.c_card_hover};
                color: {"#ffffff" if self.is_dark else self.c_accent};
                border-color: {self.c_accent};
                border-bottom: 2px solid {self.c_accent};
            }}
            QTabBar::tab:hover:!selected {{
                background-color: {self.c_card_hover};
                color: {self.c_text_main};
            }}
        """
        self.tabs.setStyleSheet(tab_bar_style)

        # Tab 0: Speed Test
        self.tab_speed = self._create_speed_test_tab()
        self.tabs.addTab(self.tab_speed, tr("tab_speed_test"))

        # Tab 1: DNS Benchmark
        self.tab_dns = self._create_dns_benchmark_tab()
        self.tabs.addTab(self.tab_dns, tr("tab_dns_benchmark"))

        self.tabs.currentChanged.connect(self.on_tab_changed)
        vbox.addWidget(self.tabs, 1)

        # 3. Dialog Bottom Bar
        btn_box = QHBoxLayout()
        btn_box.setSpacing(10)

        self.btn_copy = QPushButton(tr("btn_copy_report"))
        self.btn_copy.setFixedHeight(34)
        self.btn_copy.setCursor(Qt.PointingHandCursor)
        self.btn_copy.setStyleSheet(f"""
            QPushButton {{
                background-color: {self.c_card_bg};
                color: {self.c_text_main};
                border: 1px solid {self.c_border};
                border-radius: 6px;
                padding: 4px 16px;
                font-size: 12px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {self.c_card_hover};
                border-color: {self.c_accent};
            }}
        """)
        self.btn_copy.clicked.connect(self.copy_report)
        btn_box.addWidget(self.btn_copy)

        btn_box.addStretch()

        btn_close = QPushButton(tr("btn_close"))
        btn_close.setFixedHeight(34)
        btn_close.setFixedWidth(100)
        btn_close.setCursor(Qt.PointingHandCursor)
        btn_close.setStyleSheet(f"""
            QPushButton {{
                background-color: {self.c_card_bg};
                color: {self.c_text_main};
                border: 1px solid {self.c_border};
                border-radius: 6px;
                padding: 4px 16px;
                font-size: 12px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {self.c_card_hover};
            }}
        """)
        btn_close.clicked.connect(self.accept)
        btn_box.addWidget(btn_close)

        vbox.addLayout(btn_box)

    def _create_speed_test_tab(self) -> QWidget:
        widget = QWidget()
        vbox = QVBoxLayout(widget)
        vbox.setContentsMargins(12, 10, 12, 10)
        vbox.setSpacing(10)

        # Top Metadata Card (Public IP, ISP, Server PoP)
        self.card_speed_meta = QFrame()
        self.card_speed_meta.setStyleSheet(f"""
            QFrame {{
                background-color: {self.c_card_bg};
                border: 1px solid {self.c_border};
                border-radius: 6px;
                padding: 4px;
            }}
        """)
        meta_layout = QHBoxLayout(self.card_speed_meta)
        meta_layout.setContentsMargins(12, 6, 12, 6)
        meta_layout.setSpacing(16)

        self.lbl_speed_wan = QLabel("🌐 IP: Identificando...")
        self.lbl_speed_wan.setStyleSheet(f"font-size: 12px; font-weight: bold; color: {self.c_text_main};")
        self.lbl_speed_isp = QLabel("🏢 Provedor: Identificando...")
        self.lbl_speed_isp.setStyleSheet(f"font-size: 12px; font-weight: bold; color: {self.c_accent};")
        self.lbl_speed_server = QLabel("📍 Servidor: Cloudflare Edge")
        self.lbl_speed_server.setStyleSheet(f"font-size: 12px; font-weight: 500; color: {self.c_text_sub};")

        meta_layout.addWidget(self.lbl_speed_wan)
        meta_layout.addWidget(self.lbl_speed_isp, 1)
        meta_layout.addWidget(self.lbl_speed_server)
        vbox.addWidget(self.card_speed_meta)

        # Center Main Area: Speedometer (Left) + 4 Large KPI Cards (Right)
        mid_layout = QHBoxLayout()
        mid_layout.setSpacing(14)

        # Speedometer Gauge
        self.speedometer = SpeedometerWidget(self, is_dark=self.is_dark)
        mid_layout.addWidget(self.speedometer, 1)

        # KPI Cards (2x2 Grid)
        kpi_grid = QGridLayout()
        kpi_grid.setSpacing(10)

        self.card_speed_ping = self._create_kpi_card(
            tr("speed_kpi_ping"), "--- ms", "#a855f7" if self.is_dark else "#7e22ce", sub_val="Jitter: --- ms"
        )
        self.card_speed_down = self._create_kpi_card(
            tr("speed_kpi_download"), "--- Mbps", "#38bdf8" if self.is_dark else "#0284c7", sub_val="Pico: --- Mbps"
        )
        self.card_speed_up = self._create_kpi_card(
            tr("speed_kpi_upload"), "--- Mbps", "#10b981" if self.is_dark else "#16a34a", sub_val="Pico: --- Mbps"
        )
        self.card_speed_transfer = self._create_kpi_card(
            tr("speed_qoe_transfer"), "--- MB/s", "#f59e0b" if self.is_dark else "#d97706", sub_val="1 GB em ---"
        )

        kpi_grid.addWidget(self.card_speed_ping, 0, 0)
        kpi_grid.addWidget(self.card_speed_down, 0, 1)
        kpi_grid.addWidget(self.card_speed_up, 1, 0)
        kpi_grid.addWidget(self.card_speed_transfer, 1, 1)

        mid_layout.addLayout(kpi_grid, 1)
        vbox.addLayout(mid_layout)

        # QoE Matrix Card (Real-World Experience Assessment)
        self.card_speed_qoe = QFrame()
        self.card_speed_qoe.setStyleSheet(f"""
            QFrame {{
                background-color: {self.c_card_bg};
                border: 1px solid {self.c_border};
                border-radius: 8px;
                padding: 6px;
            }}
        """)
        qoe_box = QVBoxLayout(self.card_speed_qoe)
        qoe_box.setContentsMargins(12, 8, 12, 8)
        qoe_box.setSpacing(8)

        lbl_qoe_title = QLabel(f"⭐ {tr('speed_qoe_title')}")
        lbl_qoe_title.setStyleSheet(f"font-size: 12px; font-weight: bold; color: {self.c_accent};")
        qoe_box.addWidget(lbl_qoe_title)

        qoe_grid = QGridLayout()
        qoe_grid.setSpacing(10)

        def _build_qoe_panel(icon: str, title: str):
            p = QFrame()
            p.setStyleSheet(f"""
                QFrame {{
                    background-color: {self.c_bg};
                    border: 1px solid {self.c_border};
                    border-radius: 6px;
                    padding: 4px;
                }}
            """)
            b = QVBoxLayout(p)
            b.setContentsMargins(8, 6, 8, 6)
            b.setSpacing(2)
            lt = QLabel(f"{icon}  {title}")
            lt.setStyleSheet(f"font-size: 11px; font-weight: bold; color: {self.c_text_sub};")
            ls = QLabel("Aguardando teste...")
            ls.setStyleSheet(f"font-size: 12px; font-weight: bold; color: {self.c_text_main};")
            ls.setObjectName("qoe_score")
            ld = QLabel("As métricas serão avaliadas ao final do Speed Test.")
            ld.setStyleSheet(f"font-size: 10px; color: {self.c_text_sub};")
            ld.setWordWrap(True)
            ld.setObjectName("qoe_desc")
            b.addWidget(lt)
            b.addWidget(ls)
            b.addWidget(ld)
            return p

        self.panel_qoe_stream = _build_qoe_panel("🎬", tr("speed_qoe_streaming"))
        self.panel_qoe_game = _build_qoe_panel("🎮", tr("speed_qoe_gaming"))
        self.panel_qoe_calls = _build_qoe_panel("📞", tr("speed_qoe_calls"))
        self.panel_qoe_trans = _build_qoe_panel("📁", tr("speed_qoe_transfer"))

        qoe_grid.addWidget(self.panel_qoe_stream, 0, 0)
        qoe_grid.addWidget(self.panel_qoe_game, 0, 1)
        qoe_grid.addWidget(self.panel_qoe_calls, 1, 0)
        qoe_grid.addWidget(self.panel_qoe_trans, 1, 1)

        qoe_box.addLayout(qoe_grid)
        vbox.addWidget(self.card_speed_qoe)

        # Progress and Action Controls
        ctrl_box = QHBoxLayout()
        ctrl_box.setSpacing(12)

        prog_layout = QVBoxLayout()
        prog_layout.setSpacing(3)
        self.lbl_speed_status = QLabel("Pronto para iniciar o teste de velocidade.")
        self.lbl_speed_status.setStyleSheet(f"font-size: 12px; font-weight: 500; color: {self.c_text_sub};")
        prog_layout.addWidget(self.lbl_speed_status)

        self.speed_prog_bar = QProgressBar()
        self.speed_prog_bar.setFixedHeight(8)
        self.speed_prog_bar.setTextVisible(False)
        self.speed_prog_bar.setRange(0, 100)
        self.speed_prog_bar.setValue(0)
        self.speed_prog_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: {self.c_card_bg};
                border: 1px solid {self.c_border};
                border-radius: 4px;
            }}
            QProgressBar::chunk {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #38bdf8);
                border-radius: 3px;
            }}
        """)
        prog_layout.addWidget(self.speed_prog_bar)
        ctrl_box.addLayout(prog_layout, 1)

        self.btn_speed_toggle = QPushButton(tr("btn_cancel_speed"))
        self.btn_speed_toggle.setFixedHeight(36)
        self.btn_speed_toggle.setFixedWidth(180)
        self.btn_speed_toggle.setCursor(Qt.PointingHandCursor)
        self._update_speed_btn_style(is_running=True)
        self.btn_speed_toggle.clicked.connect(self.toggle_speed_test)
        ctrl_box.addWidget(self.btn_speed_toggle)

        vbox.addLayout(ctrl_box)
        return widget

    def _update_speed_btn_style(self, is_running: bool):
        if is_running:
            self.btn_speed_toggle.setText(tr("btn_cancel_speed"))
            self.btn_speed_toggle.setStyleSheet("""
                QPushButton {
                    background: #dc2626;
                    color: #ffffff;
                    border: none;
                    border-radius: 6px;
                    font-size: 12px;
                    font-weight: bold;
                    padding: 6px 14px;
                }
                QPushButton:hover {
                    background: #ef4444;
                }
            """)
        else:
            self.btn_speed_toggle.setText(tr("btn_start_speed"))
            btn_bg = (
                "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #38bdf8)"
                if self.is_dark else
                "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #164e78, stop:1 #2b6595)"
            )
            self.btn_speed_toggle.setStyleSheet(f"""
                QPushButton {{
                    background: {btn_bg};
                    color: #ffffff;
                    border: none;
                    border-radius: 6px;
                    font-size: 12px;
                    font-weight: bold;
                    padding: 6px 14px;
                }}
                QPushButton:hover {{
                    opacity: 0.9;
                }}
            """)

    def _create_dns_benchmark_tab(self) -> QWidget:
        widget = QWidget()
        vbox = QVBoxLayout(widget)
        vbox.setContentsMargins(12, 10, 12, 10)
        vbox.setSpacing(10)

        # 1. KPI Badges Summary Row (4 spacious cards)
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(10)

        self.card_wan = self._create_kpi_card(
            tr("card_wan"), "Identificando...", "#0284c7" if not self.is_dark else "#38bdf8"
        )
        self.card_gw = self._create_kpi_card(tr("card_gw"), self.gateway_ip or "Testando...", "#10b981")
        self.card_dns = self._create_kpi_card(
            tr("card_dns"), "Testando...", "#9333ea" if not self.is_dark else "#c084fc"
        )
        self.card_fastest = self._create_kpi_card(
            tr("card_fastest"), "Aguardando...", "#d97706" if not self.is_dark else "#facc15"
        )

        kpi_row.addWidget(self.card_wan)
        kpi_row.addWidget(self.card_gw)
        kpi_row.addWidget(self.card_dns)
        kpi_row.addWidget(self.card_fastest)
        vbox.addLayout(kpi_row)

        # 2. Progress bar with status label
        prog_box = QVBoxLayout()
        prog_box.setSpacing(3)

        self.lbl_status = QLabel("Aguardando benchmark de servidores DNS...")
        self.lbl_status.setStyleSheet(f"font-size: 12px; font-weight: 500; color: {self.c_text_sub}; margin-left: 2px;")
        prog_box.addWidget(self.lbl_status)

        self.prog_bar = QProgressBar()
        self.prog_bar.setFixedHeight(8)
        self.prog_bar.setTextVisible(False)
        self.prog_bar.setRange(0, 100)
        self.prog_bar.setValue(0)
        self.prog_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: {self.c_card_bg};
                border: 1px solid {self.c_border};
                border-radius: 4px;
            }}
            QProgressBar::chunk {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #38bdf8);
                border-radius: 3px;
            }}
        """)
        prog_box.addWidget(self.prog_bar)
        vbox.addLayout(prog_box)

        # 3. Sorting and Controls Bar
        sort_bar = QHBoxLayout()
        sort_bar.setContentsMargins(2, 2, 2, 2)
        sort_bar.setSpacing(8)

        lbl_sort = QLabel(tr("sort_label"))
        lbl_sort.setStyleSheet(f"font-size: 12px; font-weight: bold; color: {self.c_text_main};")
        sort_bar.addWidget(lbl_sort)

        self.combo_sort_col = QComboBox()
        self.combo_sort_col.setFixedHeight(28)
        self.combo_sort_col.addItem("⚡ Latência DNS UDP 53", 3)
        self.combo_sort_col.addItem("📶 Ping ICMP (Médio)", 2)
        self.combo_sort_col.addItem("🔤 Provedor / Alvo", 0)
        self.combo_sort_col.addItem("🌐 Endereço IP", 1)
        self.combo_sort_col.addItem("📉 Perda de Pacotes", 4)
        self.combo_sort_col.addItem("⭐ Classificação de Qualidade", 5)
        self.combo_sort_col.setStyleSheet(f"""
            QComboBox {{
                background-color: {self.c_card_bg};
                color: {self.c_text_main};
                border: 1px solid {self.c_border};
                border-radius: 4px;
                padding: 2px 10px;
                font-size: 12px;
                font-weight: 500;
            }}
            QComboBox::drop-down {{
                border: none;
                width: 20px;
            }}
            QComboBox QAbstractItemView {{
                background-color: {self.c_card_bg};
                color: {self.c_text_main};
                selection-background-color: {self.c_accent};
                selection-color: #ffffff;
                border: 1px solid {self.c_border};
            }}
        """)
        self.combo_sort_col.currentIndexChanged.connect(self.on_sort_changed)
        sort_bar.addWidget(self.combo_sort_col)

        self.btn_sort_asc = QPushButton(tr("sort_asc"))
        self.btn_sort_asc.setFixedHeight(28)
        self.btn_sort_asc.setCheckable(True)
        self.btn_sort_asc.setChecked(True)
        self.btn_sort_asc.setCursor(Qt.PointingHandCursor)
        self.btn_sort_asc.setToolTip("Classificação crescente (menor latência / mais veloz primeiro)")

        self.btn_sort_desc = QPushButton(tr("sort_desc"))
        self.btn_sort_desc.setFixedHeight(28)
        self.btn_sort_desc.setCheckable(True)
        self.btn_sort_desc.setChecked(False)
        self.btn_sort_desc.setCursor(Qt.PointingHandCursor)
        self.btn_sort_desc.setToolTip("Classificação decrescente (maior latência primeiro)")

        self.btn_sort_asc.clicked.connect(lambda: self.set_sort_order(Qt.AscendingOrder))
        self.btn_sort_desc.clicked.connect(lambda: self.set_sort_order(Qt.DescendingOrder))

        sort_bar.addWidget(self.btn_sort_asc)
        sort_bar.addWidget(self.btn_sort_desc)

        sort_bar.addSpacing(10)
        sep_dns_bar = QFrame()
        sep_dns_bar.setFrameShape(QFrame.VLine)
        sep_dns_bar.setFrameShadow(QFrame.Sunken)
        sep_dns_bar.setStyleSheet(f"color: {self.c_border};")
        sort_bar.addWidget(sep_dns_bar)

        dns_btn_style = f"""
            QPushButton {{
                background-color: {self.c_card_bg};
                color: {self.c_text_main};
                border: 1px solid {self.c_border};
                border-radius: 4px;
                padding: 3px 10px;
                font-size: 11px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {self.c_card_hover};
                border-color: {self.c_accent};
            }}
        """

        self.btn_add_dns = QPushButton(tr("btn_add_dns"))
        self.btn_add_dns.setFixedHeight(28)
        self.btn_add_dns.setCursor(Qt.PointingHandCursor)
        self.btn_add_dns.setStyleSheet(dns_btn_style)
        self.btn_add_dns.setToolTip("Adicionar um novo servidor DNS personalizado na lista de testes")
        self.btn_add_dns.clicked.connect(self.on_add_dns)
        sort_bar.addWidget(self.btn_add_dns)

        self.btn_edit_dns = QPushButton(tr("btn_edit_dns"))
        self.btn_edit_dns.setFixedHeight(28)
        self.btn_edit_dns.setCursor(Qt.PointingHandCursor)
        self.btn_edit_dns.setStyleSheet(dns_btn_style)
        self.btn_edit_dns.setToolTip("Editar o servidor DNS selecionado na tabela")
        self.btn_edit_dns.clicked.connect(self.on_edit_dns)
        sort_bar.addWidget(self.btn_edit_dns)

        self.btn_delete_dns = QPushButton(tr("btn_delete_dns"))
        self.btn_delete_dns.setFixedHeight(28)
        self.btn_delete_dns.setCursor(Qt.PointingHandCursor)
        self.btn_delete_dns.setStyleSheet(dns_btn_style)
        self.btn_delete_dns.setToolTip("Excluir o servidor DNS selecionado da lista de testes")
        self.btn_delete_dns.clicked.connect(self.on_delete_dns)
        sort_bar.addWidget(self.btn_delete_dns)

        self.btn_reset_dns = QPushButton(tr("btn_reset_dns"))
        self.btn_reset_dns.setFixedHeight(28)
        self.btn_reset_dns.setCursor(Qt.PointingHandCursor)
        self.btn_reset_dns.setStyleSheet(dns_btn_style)
        self.btn_reset_dns.setToolTip("Restaurar a lista para os 30 servidores DNS oficiais padrão")
        self.btn_reset_dns.clicked.connect(self.on_reset_dns)
        sort_bar.addWidget(self.btn_reset_dns)

        sort_bar.addStretch()

        self.btn_restart = QPushButton(tr("btn_restart_test"))
        self.btn_restart.setFixedHeight(28)
        self.btn_restart.setCursor(Qt.PointingHandCursor)
        self.btn_restart.setStyleSheet(f"""
            QPushButton {{
                background-color: {self.c_accent if self.is_dark else self.c_accent_dark};
                color: #ffffff;
                border: none;
                border-radius: 4px;
                padding: 3px 14px;
                font-size: 11px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                opacity: 0.9;
            }}
        """)
        self.btn_restart.clicked.connect(self.start_test)
        sort_bar.addWidget(self.btn_restart)

        vbox.addLayout(sort_bar)

        # 4. Table Widget
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            tr("col_dns_provider"),
            tr("col_dns_ip"),
            tr("col_dns_icmp"),
            tr("col_dns_udp"),
            tr("col_dns_loss"),
            tr("col_dns_quality"),
            tr("col_dns_feature"),
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSortIndicatorShown(True)
        self.table.horizontalHeader().sortIndicatorChanged.connect(self.on_header_sort_changed)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(True)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.on_table_context_menu)
        self._update_sort_btn_styles()

        self.table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {self.c_table_bg};
                alternate-background-color: {self.c_table_alt};
                border: 1px solid {self.c_border};
                border-radius: 6px;
                gridline-color: {self.c_border};
                color: {self.c_text_main};
                font-size: 12px;
                selection-background-color: #0284c7;
                selection-color: #ffffff;
            }}
            QHeaderView::section {{
                background-color: {self.c_header_bg};
                color: {self.c_header_text};
                padding: 7px 6px;
                border: none;
                border-bottom: 2px solid {self.c_border};
                border-right: 1px solid {self.c_border};
                font-weight: bold;
                font-size: 11px;
            }}
            QTableWidget::item {{
                padding: 6px 8px;
            }}
        """)
        vbox.addWidget(self.table, 1)

        # 5. Recommendation banner card
        self.rec_card = QFrame()
        self.rec_card.setStyleSheet(f"""
            QFrame {{
                background-color: {self.c_rec_bg};
                border: 1px solid {self.c_border};
                border-left: 4px solid {self.c_rec_border};
                border-radius: 6px;
                padding: 8px;
            }}
        """)
        rec_box = QHBoxLayout(self.rec_card)
        rec_box.setContentsMargins(10, 6, 10, 6)
        rec_box.setSpacing(10)

        self.lbl_rec_icon = QLabel("💡")
        self.lbl_rec_icon.setStyleSheet("font-size: 20px;")
        rec_box.addWidget(self.lbl_rec_icon)

        self.lbl_recommendation = QLabel("Aguardando conclusão do teste para formular recomendação de desempenho...")
        self.lbl_recommendation.setStyleSheet(f"font-size: 12px; font-weight: 500; color: {self.c_rec_text};")
        self.lbl_recommendation.setWordWrap(True)
        rec_box.addWidget(self.lbl_recommendation, 1)
        vbox.addWidget(self.rec_card)

        return widget

    def _create_kpi_card(self, title: str, default_val: str, accent_color: str, sub_val: str = "") -> QFrame:
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: {self.c_card_bg};
                border: 1px solid {self.c_border};
                border-top: 3px solid {accent_color};
                border-radius: 6px;
                padding: 4px;
            }}
        """)
        box = QVBoxLayout(card)
        box.setContentsMargins(10, 8, 10, 8)
        box.setSpacing(2)

        lbl_t = QLabel(title)
        lbl_t.setStyleSheet(f"font-size: 11px; color: {self.c_text_sub}; font-weight: 600;")
        lbl_v = QLabel(default_val)
        lbl_v.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {self.c_text_main};")
        lbl_v.setObjectName("val")

        box.addWidget(lbl_t)
        box.addWidget(lbl_v)

        if sub_val:
            lbl_s = QLabel(sub_val)
            lbl_s.setStyleSheet(f"font-size: 10px; color: {self.c_text_sub};")
            lbl_s.setObjectName("sub")
            box.addWidget(lbl_s)

        return card

    def _set_kpi_val(self, card: QFrame, text: str, custom_color: str = "", sub_text: str = ""):
        lbl = card.findChild(QLabel, "val")
        if lbl:
            lbl.setText(text)
            if custom_color:
                lbl.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {custom_color};")
        if sub_text:
            lbl_sub = card.findChild(QLabel, "sub")
            if lbl_sub:
                lbl_sub.setText(sub_text)

    # --------------------------------------------------------------------------
    # SPEED TEST ENGINE SLOTS & METHODS
    # --------------------------------------------------------------------------
    def start_speed_test(self):
        if self.speed_worker and self.speed_worker.isRunning():
            self.speed_worker.cancel()
            self.speed_worker.wait(1000)

        self._update_speed_btn_style(is_running=True)
        self.speedometer.reset()
        self.speed_prog_bar.setValue(0)
        self.lbl_speed_status.setText("Iniciando Speed Test...")

        self.speed_worker = SpeedTestWorker(self)
        self.speed_worker.phase_changed.connect(self.on_speed_phase_changed)
        self.speed_worker.meta_received.connect(self.on_speed_meta)
        self.speed_worker.ping_sample.connect(self.on_speed_ping_sample)
        self.speed_worker.sample.connect(self.on_speed_sample)
        self.speed_worker.download_finished.connect(self.on_speed_download_finished)
        self.speed_worker.upload_finished.connect(self.on_speed_upload_finished)
        self.speed_worker.finished.connect(self.on_speed_finished)
        self.speed_worker.error_occurred.connect(self.on_speed_error)
        self.speed_worker.start()

    def cancel_speed_test(self):
        if self.speed_worker and self.speed_worker.isRunning():
            self.speed_worker.cancel()
        self._update_speed_btn_style(is_running=False)
        self.lbl_speed_status.setText("Speed Test cancelado pelo usuário.")
        self.speedometer.set_phase("CANCELADO", unit="", sub_text="Teste interrompido")

    def toggle_speed_test(self):
        if self.speed_worker and self.speed_worker.isRunning():
            self.cancel_speed_test()
        else:
            self.start_speed_test()

    def on_speed_phase_changed(self, phase: str):
        if phase == "meta":
            self.speedometer.set_phase("METADADOS", unit="", sub_text="Identificando provedor...")
            self.lbl_speed_status.setText("Identificando provedor e localização do servidor...")
            self.speed_prog_bar.setValue(5)
        elif phase == "ping":
            self.speedometer.set_phase("LATÊNCIA", unit="ms", sub_text="Medindo ping...")
            self.lbl_speed_status.setText("Medindo tempo de resposta e jitter da rota...")
            self.speed_prog_bar.setValue(15)
        elif phase == "download":
            self.speedometer.set_phase("DOWNLOAD", unit="Mbps", sub_text="Testando download...")
            self.lbl_speed_status.setText("Medindo taxa de transferência de download...")
            self.speed_prog_bar.setValue(25)
        elif phase == "upload":
            self.speedometer.set_phase("UPLOAD", unit="Mbps", sub_text="Testando upload...")
            self.lbl_speed_status.setText("Medindo taxa de transferência de upload...")
            self.speed_prog_bar.setValue(65)
        elif phase == "finished":
            self.speedometer.set_phase("CONCLUÍDO", unit="Mbps", sub_text="Speed test finalizado")
            self.speed_prog_bar.setValue(100)

    def on_speed_meta(self, meta: dict):
        self.speed_meta = meta
        self.lbl_speed_wan.setText(f"🌐 IP: {meta.get('ip', 'N/D')}")
        self.lbl_speed_isp.setText(f"🏢 Provedor: {meta.get('isp', 'N/D')}")
        self.lbl_speed_server.setText(f"📍 Servidor: {meta.get('server', 'Cloudflare Edge')}")
        # Sync with WAN card in Tab 1
        self._set_kpi_val(self.card_wan, meta.get("ip", "N/D"), self.c_accent)

    def on_speed_ping_sample(self, ping: float, jitter: float):
        self.speedometer.set_value(ping, max_val=150.0, sub_text=f"Jitter: {jitter:.1f} ms")
        self._set_kpi_val(self.card_speed_ping, f"{ping:.1f} ms", sub_text=f"Jitter: {jitter:.1f} ms")

    def on_speed_sample(self, phase: str, cur_mbps: float, peak_mbps: float, progress_pct: int):
        self.speedometer.set_value(cur_mbps, sub_text=f"Pico: {peak_mbps:.1f} Mbps")
        if phase == "download":
            pct = 25 + int(progress_pct * 0.38)
            self.speed_prog_bar.setValue(min(64, pct))
            self._set_kpi_val(
                self.card_speed_down, f"{cur_mbps:.1f} Mbps", sub_text=f"Pico: {peak_mbps:.1f} Mbps"
            )
            real_mbs = cur_mbps / 8.0
            self._set_kpi_val(self.card_speed_transfer, f"~{real_mbs:.1f} MB/s", sub_text="Medindo...")
        else:
            pct = 65 + int(progress_pct * 0.34)
            self.speed_prog_bar.setValue(min(98, pct))
            self._set_kpi_val(
                self.card_speed_up, f"{cur_mbps:.1f} Mbps", sub_text=f"Pico: {peak_mbps:.1f} Mbps"
            )

    def on_speed_download_finished(self, avg_mbps: float, peak_mbps: float):
        color = "#38bdf8" if self.is_dark else "#0284c7"
        self._set_kpi_val(
            self.card_speed_down, f"{avg_mbps:.1f} Mbps", custom_color=color, sub_text=f"Pico: {peak_mbps:.1f} Mbps"
        )
        real_mbs = avg_mbps / 8.0
        sec_1gb = int(1024 / max(0.1, real_mbs))
        self._set_kpi_val(self.card_speed_transfer, f"~{real_mbs:.1f} MB/s", sub_text=f"1 GB em ~{sec_1gb}s")

    def on_speed_upload_finished(self, avg_mbps: float, peak_mbps: float):
        color = "#10b981" if self.is_dark else "#16a34a"
        self._set_kpi_val(
            self.card_speed_up, f"{avg_mbps:.1f} Mbps", custom_color=color, sub_text=f"Pico: {peak_mbps:.1f} Mbps"
        )

    def on_speed_finished(self, summary: dict):
        self.speed_summary = summary
        self._update_speed_btn_style(is_running=False)
        self.speed_prog_bar.setValue(100)
        self.lbl_speed_status.setText(
            f"Speed Test concluído: {summary['download']:.1f} Mbps download, {summary['upload']:.1f} Mbps upload, {summary['ping']:.1f} ms ping."
        )

        self.speedometer.set_phase("CONCLUÍDO", unit="Mbps", sub_text=f"Down {summary['download']:.1f} | Up {summary['upload']:.1f}")
        self.speedometer.set_value(summary["download"])

        # Update QoE Panels
        qoe = summary.get("qoe", {})
        stream_data = qoe.get("streaming", {})
        game_data = qoe.get("gaming", {})
        calls_data = qoe.get("calls", {})
        trans_data = qoe.get("transfer", {})

        def _update_qoe_panel(panel: QFrame, score: str, status: str, desc: str):
            lbl_s = panel.findChild(QLabel, "qoe_score")
            lbl_d = panel.findChild(QLabel, "qoe_desc")
            if lbl_s:
                lbl_s.setText(f"{score} {status}")
            if lbl_d:
                lbl_d.setText(desc)

        _update_qoe_panel(self.panel_qoe_stream, stream_data.get("score", "⭐⭐⭐⭐"), stream_data.get("status", ""), stream_data.get("desc", ""))
        _update_qoe_panel(self.panel_qoe_game, game_data.get("score", "⭐⭐⭐⭐"), game_data.get("status", ""), game_data.get("desc", ""))
        _update_qoe_panel(self.panel_qoe_calls, calls_data.get("score", "⭐⭐⭐⭐"), calls_data.get("status", ""), calls_data.get("desc", ""))
        _update_qoe_panel(self.panel_qoe_trans, trans_data.get("rate", "---"), "", trans_data.get("desc", ""))

    def on_speed_error(self, err_msg: str):
        self._update_speed_btn_style(is_running=False)
        self.lbl_speed_status.setText(f"Erro durante medição de velocidade: {err_msg}")
        self.speedometer.set_phase("ERRO", unit="", sub_text=err_msg[:30])

    def on_tab_changed(self, index: int):
        if index == 1:
            # If switching to DNS tab and it hasn't run yet, auto-trigger DNS test
            if not self.results_list and (self.worker is None or not self.worker.isRunning()):
                self.start_test()

    # --------------------------------------------------------------------------
    # DNS BENCHMARK METHODS
    # --------------------------------------------------------------------------
    def _update_sort_btn_styles(self):
        active_bg = "#0284c7" if not self.is_dark else "#0369a1"
        inactive_bg = self.c_card_bg
        border = self.c_border
        base_style = f"""
            QPushButton {{
                border: 1px solid {border};
                border-radius: 4px;
                padding: 3px 12px;
                font-size: 11px;
                font-weight: bold;
            }}
        """
        self.btn_sort_asc.setStyleSheet(base_style + f"""
            QPushButton {{
                background-color: {active_bg if self.btn_sort_asc.isChecked() else inactive_bg};
                color: {"#ffffff" if self.btn_sort_asc.isChecked() else self.c_text_main};
            }}
        """)
        self.btn_sort_desc.setStyleSheet(base_style + f"""
            QPushButton {{
                background-color: {active_bg if self.btn_sort_desc.isChecked() else inactive_bg};
                color: {"#ffffff" if self.btn_sort_desc.isChecked() else self.c_text_main};
            }}
        """)

    def set_sort_order(self, order: Qt.SortOrder):
        self.btn_sort_asc.setChecked(order == Qt.AscendingOrder)
        self.btn_sort_desc.setChecked(order == Qt.DescendingOrder)
        self._update_sort_btn_styles()
        self.apply_sorting(order=order)

    def on_sort_changed(self):
        col = self.combo_sort_col.currentData()
        self.apply_sorting(col=col)

    def on_header_sort_changed(self, col: int, order: Qt.SortOrder):
        idx = self.combo_sort_col.findData(col)
        if idx >= 0:
            self.combo_sort_col.blockSignals(True)
            self.combo_sort_col.setCurrentIndex(idx)
            self.combo_sort_col.blockSignals(False)

        self.btn_sort_asc.setChecked(order == Qt.AscendingOrder)
        self.btn_sort_desc.setChecked(order == Qt.DescendingOrder)
        self._update_sort_btn_styles()

    def apply_sorting(self, col: Optional[int] = None, order: Optional[Qt.SortOrder] = None):
        if col is None:
            col = self.combo_sort_col.currentData()
        if order is None:
            order = Qt.AscendingOrder if self.btn_sort_asc.isChecked() else Qt.DescendingOrder

        self.table.setSortingEnabled(True)
        self.table.sortByColumn(col, order)

    def on_table_context_menu(self, pos: QPoint):
        item = self.table.itemAt(pos)
        menu = QMenu(self)
        menu.setStyleSheet(f"""
            QMenu {{
                background-color: {self.c_card_bg};
                color: {self.c_text_main};
                border: 1px solid {self.c_border};
                border-radius: 4px;
                padding: 4px;
            }}
            QMenu::item {{
                padding: 6px 16px;
                border-radius: 3px;
            }}
            QMenu::item:selected {{
                background-color: {self.c_accent};
                color: #ffffff;
            }}
        """)
        act_add = menu.addAction(tr("btn_add_dns"))
        act_add.triggered.connect(self.on_add_dns)

        if item:
            row = item.row()
            self.table.selectRow(row)
            act_edit = menu.addAction(tr("btn_edit_dns"))
            act_edit.triggered.connect(self.on_edit_dns)
            act_del = menu.addAction(tr("btn_delete_dns"))
            act_del.triggered.connect(self.on_delete_dns)

        menu.addSeparator()
        act_reset = menu.addAction(tr("btn_reset_dns"))
        act_reset.triggered.connect(self.on_reset_dns)

        menu.exec_(self.table.viewport().mapToGlobal(pos))

    def on_add_dns(self):
        dlg = DnsEntryDialog(self, is_dark=self.is_dark)
        if dlg.exec_() == QDialog.Accepted and dlg.result_entry:
            new_item = dlg.result_entry
            existing_idx = next((i for i, x in enumerate(self.dns_targets) if x["ip"] == new_item["ip"]), None)
            if existing_idx is not None:
                self.dns_targets[existing_idx] = new_item
            else:
                self.dns_targets.append(new_item)
            save_dns_targets(self.dns_targets)
            msg = f"Servidor '{new_item['provider']}' ({new_item['ip']}) salvo com sucesso!\n\nDeseja iniciar um novo benchmark de DNS agora?"
            ret = QMessageBox.question(
                self,
                "DNS Adicionado",
                msg,
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            if ret == QMessageBox.Yes:
                self.start_test()

    def on_edit_dns(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(
                self, tr("btn_edit_dns", "Editar"), tr("dns_select_edit", "Selecione um servidor DNS na tabela para editar.")
            )
            return
        item_ip = self.table.item(row, 1)
        if not item_ip:
            return
        ip_str = item_ip.text().strip()
        entry = next((x for x in self.dns_targets if x["ip"] == ip_str), None)
        if not entry:
            item_name = self.table.item(row, 0)
            name_str = item_name.text().strip() if item_name else ip_str
            entry = {"provider": name_str, "ip": ip_str, "category": "Público Global", "feature": name_str, "icon": "🌐"}

        dlg = DnsEntryDialog(self, entry=entry, is_dark=self.is_dark)
        if dlg.exec_() == QDialog.Accepted and dlg.result_entry:
            new_item = dlg.result_entry
            for i, x in enumerate(self.dns_targets):
                if x["ip"] == entry["ip"] or x["ip"] == new_item["ip"]:
                    self.dns_targets[i] = new_item
                    break
            else:
                self.dns_targets.append(new_item)
            save_dns_targets(self.dns_targets)
            msg = f"Servidor '{new_item['provider']}' ({new_item['ip']}) atualizado!\n\nDeseja reiniciar o benchmark agora?"
            ret = QMessageBox.question(
                self,
                "DNS",
                msg,
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            if ret == QMessageBox.Yes:
                self.start_test()

    def on_delete_dns(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(
                self, tr("btn_delete_dns", "Remover"), tr("dns_select_del", "Selecione um servidor DNS na tabela para remover.")
            )
            return
        item_name = self.table.item(row, 0)
        item_ip = self.table.item(row, 1)
        if not item_ip:
            return
        name_str = item_name.text().strip() if item_name else ""
        ip_str = item_ip.text().strip()

        ret = QMessageBox.question(
            self,
            "Confirmar Remoção",
            f"Deseja realmente remover o servidor DNS '{name_str}' ({ip_str}) da lista?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if ret == QMessageBox.Yes:
            self.dns_targets = [x for x in self.dns_targets if x["ip"] != ip_str]
            save_dns_targets(self.dns_targets)
            self.table.removeRow(row)

    def on_reset_dns(self):
        ret = QMessageBox.question(
            self,
            "Restaurar Padrões",
            "Deseja realmente restaurar a lista para os 30 servidores DNS oficiais padrão de fábrica?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if ret == QMessageBox.Yes:
            self.dns_targets = reset_dns_targets()
            self.start_test()

    def start_test(self):
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.worker.wait(1000)

        self.table.setSortingEnabled(False)
        self.results_list.clear()
        self.table.setRowCount(0)
        self.prog_bar.setValue(0)
        self.btn_restart.setEnabled(False)
        self.btn_restart.setText("Testando...")
        self.lbl_status.setText("Disparando testes simultâneos de latência ICMP e queries DNS UDP 53...")
        self.lbl_recommendation.setText("Aguardando finalização das medições para formular a recomendação...")

        self.worker = InternetTestWorker(gateway_ip=self.gateway_ip, dns_targets=self.dns_targets)
        self.worker.progress.connect(self.on_progress)
        self.worker.target_tested.connect(self.on_target_tested)
        self.worker.finished.connect(self.on_finished)
        self.worker.start()

    def on_progress(self, current: int, total: int, target_name: str):
        pct = int((current / total) * 100) if total > 0 else 0
        self.prog_bar.setValue(pct)
        self.lbl_status.setText(f"Avaliando alvo [{current}/{total}]: {target_name}...")

    def on_target_tested(self, res: dict):
        self.results_list.append(res)
        row = self.table.rowCount()
        self.table.insertRow(row)

        # 0. Provider name with icon
        icon = res.get("icon", "🌐")
        item_prov = NumericTableWidgetItem(f"{icon}  {res['provider']}", sort_key=res['provider'], raw_data=res)
        item_prov.setFont(QFont("", -1, QFont.Bold))
        item_prov.setForeground(QColor(self.c_text_main))
        self.table.setItem(row, 0, item_prov)

        # 1. IP (Monospace)
        def _ip_tuple(ip: str):
            try:
                return tuple(int(x) for x in ip.split("."))
            except Exception:
                return (999, 999, 999, 999)

        item_ip = NumericTableWidgetItem(res["ip"], sort_key=_ip_tuple(res["ip"]), raw_data=res)
        item_ip.setTextAlignment(Qt.AlignCenter)
        font_mono = QFont("JetBrains Mono", -1)
        font_mono.setStyleHint(QFont.Monospace)
        item_ip.setFont(font_mono)
        item_ip.setForeground(QColor(self.c_accent))
        self.table.setItem(row, 1, item_ip)

        # 2. Ping ICMP Avg
        p_val = res.get("ping_avg")
        if p_val is not None:
            ping_str = f"{p_val:.1f} ms"
            if p_val < 20.0:
                p_color = "#10b981" if self.is_dark else "#16a34a"
            elif p_val < 50.0:
                p_color = "#38bdf8" if self.is_dark else "#0284c7"
            elif p_val < 100.0:
                p_color = "#f59e0b" if self.is_dark else "#d97706"
            else:
                p_color = "#ef4444" if self.is_dark else "#dc2626"
            sort_ping = p_val
        else:
            ping_str = tr("no_response", "Sem resposta") if res["packet_loss"] == 100 else tr("not_available", "N/D")
            p_color = "#ef4444" if self.is_dark else "#dc2626"
            sort_ping = 999999.0

        item_ping = NumericTableWidgetItem(ping_str, sort_key=sort_ping, raw_data=res)
        item_ping.setTextAlignment(Qt.AlignCenter)
        item_ping.setFont(QFont("", -1, QFont.Bold))
        item_ping.setForeground(QColor(p_color))
        self.table.setItem(row, 2, item_ping)

        # 3. DNS Query RTT
        d_val = res.get("dns_rtt")
        if d_val is not None:
            dns_str = f"{d_val:.1f} ms"
            if d_val < 20.0:
                d_color = "#10b981" if self.is_dark else "#16a34a"
            elif d_val < 50.0:
                d_color = "#38bdf8" if self.is_dark else "#0284c7"
            else:
                d_color = "#f59e0b" if self.is_dark else "#d97706"
            sort_dns = d_val
        elif not res.get("is_dns"):
            dns_str = "—"
            d_color = self.c_text_sub
            sort_dns = 999998.0
        else:
            dns_str = tr("failed", "Falhou")
            d_color = "#ef4444" if self.is_dark else "#dc2626"
            sort_dns = 999999.0

        item_dns = NumericTableWidgetItem(dns_str, sort_key=sort_dns, raw_data=res)
        item_dns.setTextAlignment(Qt.AlignCenter)
        item_dns.setFont(QFont("", -1, QFont.Bold))
        item_dns.setForeground(QColor(d_color))
        self.table.setItem(row, 3, item_dns)

        # 4. Packet Loss
        loss = res.get("packet_loss", 0)
        item_loss = NumericTableWidgetItem(f"{loss}%", sort_key=loss, raw_data=res)
        item_loss.setTextAlignment(Qt.AlignCenter)
        item_loss.setFont(QFont("", -1, QFont.Bold))
        if loss > 0:
            item_loss.setForeground(QColor("#ef4444" if self.is_dark else "#dc2626"))
            item_loss.setBackground(QColor(239, 68, 68, 30 if self.is_dark else 25))
        else:
            item_loss.setForeground(QColor("#10b981" if self.is_dark else "#16a34a"))
        self.table.setItem(row, 4, item_loss)

        # 5. Rating badge
        b_type = res.get("badge_type", "info")
        if b_type == "success":
            badge_fg = "#34d399" if self.is_dark else "#15803d"
            badge_bg = QColor(16, 185, 129, 35) if self.is_dark else QColor(220, 252, 231)
            bullet = "🟢"
        elif b_type == "info":
            badge_fg = "#38bdf8" if self.is_dark else "#0369a1"
            badge_bg = QColor(56, 189, 248, 35) if self.is_dark else QColor(224, 242, 254)
            bullet = "🔵"
        elif b_type == "warning":
            badge_fg = "#fbbf24" if self.is_dark else "#b45309"
            badge_bg = QColor(245, 158, 11, 35) if self.is_dark else QColor(254, 243, 199)
            bullet = "🟡"
        elif b_type == "orange":
            badge_fg = "#fb923c" if self.is_dark else "#c2410c"
            badge_bg = QColor(249, 115, 22, 35) if self.is_dark else QColor(255, 237, 213)
            bullet = "🟠"
        else:
            badge_fg = "#f87171" if self.is_dark else "#b91c1c"
            badge_bg = QColor(239, 68, 68, 35) if self.is_dark else QColor(254, 226, 226)
            bullet = "🔴"

        rank_val = {
            tr("rating_excellent", "Excelente"): 1,
            tr("rating_good", "Bom"): 2,
            tr("rating_fair", "Aceitável"): 3,
            tr("rating_slow", "Lento"): 4,
            tr("rating_unreachable", "Inacessível"): 5,
        }.get(res["rating"], 99)
        item_rating = NumericTableWidgetItem(f"{bullet} {res['rating']}", sort_key=rank_val, raw_data=res)
        item_rating.setTextAlignment(Qt.AlignCenter)
        item_rating.setFont(QFont("", -1, QFont.Bold))
        item_rating.setForeground(QColor(badge_fg))
        item_rating.setBackground(badge_bg)
        self.table.setItem(row, 5, item_rating)

        # 6. Feature/Highlight
        item_feat = NumericTableWidgetItem(res.get("feature", ""), sort_key=res.get("feature", ""), raw_data=res)
        item_feat.setTextAlignment(Qt.AlignCenter)
        item_feat.setForeground(QColor(self.c_text_sub))
        self.table.setItem(row, 6, item_feat)

    def on_finished(self, summary: dict):
        self.prog_bar.setValue(100)
        self.btn_restart.setEnabled(True)
        self.btn_restart.setText("▶  Novo Teste")
        self.lbl_status.setText(f"Diagnóstico concluído: {summary['total_tested']} servidores DNS testados com sucesso.")

        # Update WAN KPI
        wan_ip = summary.get("public_ip", "Indisponível")
        self._set_kpi_val(self.card_wan, wan_ip, self.c_accent)

        # Update Local DNS KPI
        local_dns = summary.get("local_dns_results", [])
        if local_dns:
            d_best = min(local_dns, key=lambda x: x["score_latency"])
            d_ms = f"{d_best['score_latency']:.1f} ms" if d_best['score_latency'] < 9999 else "Offline"
            self._set_kpi_val(self.card_dns, f"{d_best['ip']} ({d_ms})")
        else:
            self._set_kpi_val(self.card_dns, "Router / DHCP")

        # Update Gateway KPI
        gw_res = summary.get("gateway_result")
        if gw_res and gw_res.get("ping_avg") is not None:
            self._set_kpi_val(self.card_gw, f"{gw_res['ip']} ({gw_res['ping_avg']:.1f} ms)", "#10b981")
        elif self.gateway_ip:
            self._set_kpi_val(self.card_gw, self.gateway_ip)

        # Update Fastest DNS KPI & Table highlight
        fastest = summary.get("fastest_dns")
        if fastest:
            prov_short = fastest["provider"].split()[0]
            self._set_kpi_val(
                self.card_fastest,
                f"{prov_short} ({fastest['score_latency']:.1f} ms)",
                "#eab308" if self.is_dark else "#ca8a04"
            )

            for r in range(self.table.rowCount()):
                if self.table.item(r, 1) and self.table.item(r, 1).text() == fastest["ip"]:
                    item_dest = self.table.item(r, 6)
                    if item_dest:
                        item_dest.setText("🏆 Mais Rápido!")
                        item_dest.setFont(QFont("", -1, QFont.Bold))
                        if isinstance(item_dest, NumericTableWidgetItem):
                            item_dest.sort_key = "  0_champion"
                        gold_fg = "#facc15" if self.is_dark else "#854d0e"
                        gold_bg = QColor(234, 179, 8, 45) if self.is_dark else QColor(254, 249, 195)
                        item_dest.setForeground(QColor(gold_fg))
                        item_dest.setBackground(gold_bg)

            # Formulate recommendation
            local_dns_item = next((r for r in local_dns if r.get("score_latency", 9999) < 9999), None)
            if local_dns_item and local_dns_item["ip"] == fastest["ip"]:
                self.lbl_recommendation.setText(
                    f"✔ Excelente configuração! O DNS configurado na sua placa de rede ({fastest['ip']}) é o mais rápido ({fastest['score_latency']:.1f} ms) para sua rota de internet."
                )
            elif local_dns_item and local_dns_item["score_latency"] > (fastest["score_latency"] + 15):
                diff = local_dns_item["score_latency"] - fastest["score_latency"]
                self.lbl_recommendation.setText(
                    f"💡 Dica de Otimização: O servidor {fastest['provider']} ({fastest['ip']}) respondeu em {fastest['score_latency']:.1f} ms ({diff:.1f} ms mais veloz que o DNS da sua placa). Considere configurá-lo para acelerar o carregamento de sites!"
                )
            else:
                self.lbl_recommendation.setText(
                    f"✔ Conexão com a Internet estável e funcional. O servidor com menor tempo de resposta no benchmark foi {fastest['provider']} ({fastest['ip']}) com {fastest['score_latency']:.1f} ms."
                )
        else:
            self._set_kpi_val(self.card_fastest, "Sem resposta DNS", "#ef4444")
            self.lbl_recommendation.setText(
                "⚠️ Não foi possível resolver consultas DNS externas. Verifique sua conexão com o roteador ou firewall de rede."
            )

        self.apply_sorting(col=3, order=Qt.AscendingOrder)

    # --------------------------------------------------------------------------
    # UNIFIED EXECUTIVE REPORT COPY
    # --------------------------------------------------------------------------
    def copy_report(self):
        lines = [
            "==================================================================",
            "   IP SCAN IGT — RELATÓRIO DE QUALIDADE DA INTERNET & SPEED TEST",
            "==================================================================",
            f"• Data/Hora:             {time.strftime('%d/%m/%Y %H:%M:%S')}",
        ]

        # 1. Metadata
        ip_val = self.speed_meta.get("ip") or self.card_wan.findChild(QLabel, "val").text()
        isp_val = self.speed_meta.get("isp", "N/D")
        server_val = self.speed_meta.get("server", "Cloudflare Edge")
        lines.append(f"• IP Público (WAN):      {ip_val}")
        lines.append(f"• Provedor / ISP:        {isp_val}")
        lines.append(f"• Servidor / Local:      {server_val}")

        # 2. Speed Test Section (if tested)
        if self.speed_summary:
            s = self.speed_summary
            lines.extend([
                "------------------------------------------------------------------",
                "   [ MEDIÇÕES DE VELOCIDADE (SPEED TEST) ]",
                "------------------------------------------------------------------",
                f"• Latência (Ping):       {s.get('ping', 0):.1f} ms (Jitter: {s.get('jitter', 0):.1f} ms)",
                f"• Velocidade Download:   {s.get('download', 0):.1f} Mbps (Pico: {s.get('download_peak', 0):.1f} Mbps)",
                f"• Velocidade Upload:     {s.get('upload', 0):.1f} Mbps (Pico: {s.get('upload_peak', 0):.1f} Mbps)",
                f"• Taxa Real de Arquivo:  ~{s.get('download_mb_s', 0):.1f} MB/s",
            ])
            qoe = s.get("qoe", {})
            lines.extend([
                "------------------------------------------------------------------",
                "   [ EXPERIÊNCIA REAL DE CONEXÃO (QoE) ]",
                "------------------------------------------------------------------",
                f"• Streaming (4K UHD):    {qoe.get('streaming', {}).get('score', '')} {qoe.get('streaming', {}).get('status', '')}",
                f"                         {qoe.get('streaming', {}).get('desc', '')}",
                f"• Jogos Online (Gaming): {qoe.get('gaming', {}).get('score', '')} {qoe.get('gaming', {}).get('status', '')}",
                f"                         {qoe.get('gaming', {}).get('desc', '')}",
                f"• Videochamadas (HD):    {qoe.get('calls', {}).get('score', '')} {qoe.get('calls', {}).get('status', '')}",
                f"                         {qoe.get('calls', {}).get('desc', '')}",
                f"• Taxa de Transferência: {qoe.get('transfer', {}).get('desc', '')}",
            ])

        # 3. DNS Benchmark Section
        lines.extend([
            "------------------------------------------------------------------",
            "   [ BENCHMARK DE SERVIDORES DNS ]",
            "------------------------------------------------------------------",
            f"• Gateway Local:         {self.card_gw.findChild(QLabel, 'val').text()}",
            f"• DNS da Placa de Rede:  {self.card_dns.findChild(QLabel, 'val').text()}",
            f"• DNS Mais Rápido:       {self.card_fastest.findChild(QLabel, 'val').text()}",
            "------------------------------------------------------------------",
            f"{'Alvo':<34} | {'IP':<15} | {'Ping Méd':<10} | {'DNS RTT':<10} | {'Perda':<6} | {'Classificação'}",
            "------------------------------------------------------------------",
        ])

        if self.table.rowCount() > 0:
            for r in range(self.table.rowCount()):
                item_prov = self.table.item(r, 0)
                item_ip = self.table.item(r, 1)
                item_ping = self.table.item(r, 2)
                item_dns = self.table.item(r, 3)
                item_loss = self.table.item(r, 4)
                item_rating = self.table.item(r, 5)

                prov_text = item_prov.text() if item_prov else ""
                ip_text = item_ip.text() if item_ip else ""
                ping_text = item_ping.text() if item_ping else tr("not_available", "N/D")
                dns_text = item_dns.text() if item_dns else tr("not_available", "N/D")
                loss_text = item_loss.text() if item_loss else "0%"
                rating_text = item_rating.text() if item_rating else tr("not_available", "N/D")

                lines.append(f"{prov_text:<34} | {ip_text:<15} | {ping_text:<10} | {dns_text:<10} | {loss_text:>6} | {rating_text}")

            lines.append("------------------------------------------------------------------")
            lines.append(f"Recomendação DNS: {self.lbl_recommendation.text()}")

        lines.append("==================================================================")

        report = "\n".join(lines)
        QApplication.clipboard().setText(report)
        QMessageBox.information(
            self,
            tr("dns_report_copied_title", "Relatório Copiado"),
            tr("dns_report_copied_msg", "O relatório completo de velocidade e DNS foi copiado para a Área de Transferência!")
        )

    def closeEvent(self, event):
        if self.speed_worker and self.speed_worker.isRunning():
            self.speed_worker.cancel()
            self.speed_worker.wait(1000)
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.worker.wait(1000)
        super().closeEvent(event)
