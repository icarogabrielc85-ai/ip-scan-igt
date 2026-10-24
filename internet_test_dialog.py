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
import os
import platform
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.request
from typing import Dict, List, Optional, Tuple

from scanner_engine import robust_urlopen

from PyQt5.QtCore import QObject, QPoint, QSize, Qt, QThread, pyqtSignal
from PyQt5.QtGui import QBrush, QColor, QFont, QIcon
from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

IS_WINDOWS = sys.platform.startswith("win") or os.name == "nt"

PUBLIC_DNS_TARGETS = [
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

    def __init__(self, gateway_ip: str = ""):
        super().__init__()
        self.gateway_ip = gateway_ip.strip()
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
        for p in PUBLIC_DNS_TARGETS:
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
                rating = "Inacessível"
                badge_type = "danger"
            elif ref_latency is not None and ref_latency < 20.0:
                rating = "Excelente"
                badge_type = "success"
            elif ref_latency is not None and ref_latency < 50.0:
                rating = "Bom"
                badge_type = "info"
            elif ref_latency is not None and ref_latency < 100.0:
                rating = "Aceitável"
                badge_type = "warning"
            else:
                rating = "Lento"
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


class InternetQualityDialog(QDialog):
    """
    Modern modal dialog for evaluating Internet Health, Gateway, Local DNS,
    and Global Public DNS benchmarks with live metrics and recommendations.
    Dynamically styled for both Dark Mode and Light Mode with high-contrast UI/UX.
    """
    def __init__(self, parent=None, gateway_ip: str = "", is_dark: Optional[bool] = None):
        super().__init__(parent)
        self.gateway_ip = gateway_ip.strip()
        self.worker = None
        self.results_list = []

        if is_dark is None:
            self.is_dark = getattr(parent, "is_dark_mode", False)
        else:
            self.is_dark = is_dark

        self.setWindowTitle("Diagnóstico de Conexão com a Internet & Benchmark de DNS")
        # Permitir maximizar, restaurar e fechar com botões nativos no título da janela
        self.setWindowFlags(self.windowFlags() | Qt.WindowMinMaxButtonsHint | Qt.WindowCloseButtonHint)

        # Geometria padrão ao desmaximizar (auto-ajustada proporcionalmente à resolução)
        screen = QApplication.primaryScreen()
        if screen:
            geo = screen.availableGeometry()
            w = max(880, min(1360, int(geo.width() * 0.88)))
            h = max(640, min(860, int(geo.height() * 0.86)))
            x = geo.x() + (geo.width() - w) // 2
            y = geo.y() + (geo.height() - h) // 2
            self.setGeometry(x, y, w, h)
        else:
            self.resize(960, 680)

        self.init_palette_and_styles()
        self.init_ui()
        self.showMaximized()
        self.start_test()

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
            self.c_rec_bg = "#162032"
            self.c_rec_border = "#38bdf8"
            self.c_rec_text = "#f1f5f9"
        else:
            self.c_bg = "#f8fafc"          # Slate 50
            self.c_card_bg = "#ffffff"     # Pure White
            self.c_card_hover = "#f1f5f9"
            self.c_border = "#cbd5e1"       # Slate 300
            self.c_text_main = "#0f172a"    # Slate 900 (deep black-slate)
            self.c_text_sub = "#64748b"     # Slate 500
            self.c_table_bg = "#ffffff"
            self.c_table_alt = "#f8fafc"
            self.c_header_bg = "#f1f5f9"
            self.c_header_text = "#334155"
            self.c_accent = "#0284c7"       # Vibrant Blue
            self.c_rec_bg = "#f0f9ff"       # Light Sky
            self.c_rec_border = "#0284c7"
            self.c_rec_text = "#0c4a6e"

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

        # 1. Header card
        self.hdr = QFrame()
        self.hdr.setObjectName("netTestHdr")
        self.hdr.setStyleSheet(f"""
            QFrame#netTestHdr {{
                background-color: {self.c_card_bg};
                border: 1px solid {self.c_border};
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        h_layout = QHBoxLayout(self.hdr)
        h_layout.setContentsMargins(8, 6, 8, 6)
        h_layout.setSpacing(14)

        lbl_icon = QLabel("🌐")
        lbl_icon.setStyleSheet("font-size: 34px;")
        h_layout.addWidget(lbl_icon)

        info_box = QVBoxLayout()
        info_box.setSpacing(3)
        lbl_title = QLabel("Teste de Conexão com a Internet & Benchmark de DNS")
        lbl_title.setStyleSheet(f"font-weight: bold; font-size: 15px; color: {self.c_accent};")
        lbl_sub = QLabel("Avalia em tempo real a rota do Gateway, DNS da placa e os principais provedores mundiais e nacionais.")
        lbl_sub.setStyleSheet(f"font-size: 12px; color: {self.c_text_sub};")
        info_box.addWidget(lbl_title)
        info_box.addWidget(lbl_sub)
        h_layout.addLayout(info_box, 1)

        vbox.addWidget(self.hdr)

        # 2. KPI Badges Summary Row (4 spacious cards)
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(10)

        self.card_wan = self._create_kpi_card("🌐 IP Público (WAN)", "Identificando...", "#0284c7" if not self.is_dark else "#38bdf8")
        self.card_gw = self._create_kpi_card("🏠 Gateway Local", self.gateway_ip or "Testando...", "#10b981")
        self.card_dns = self._create_kpi_card("🛡️ DNS da Placa", "Testando...", "#9333ea" if not self.is_dark else "#c084fc")
        self.card_fastest = self._create_kpi_card("🏆 Mais Rápido", "Aguardando...", "#d97706" if not self.is_dark else "#facc15")

        kpi_row.addWidget(self.card_wan)
        kpi_row.addWidget(self.card_gw)
        kpi_row.addWidget(self.card_dns)
        kpi_row.addWidget(self.card_fastest)
        vbox.addLayout(kpi_row)

        # 3. Progress bar with status label
        prog_box = QVBoxLayout()
        prog_box.setSpacing(4)

        self.lbl_status = QLabel("Iniciando diagnósticos de rede e consultas DNS...")
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

        # 4. Sorting and Controls Bar
        sort_bar = QHBoxLayout()
        sort_bar.setContentsMargins(2, 2, 2, 2)
        sort_bar.setSpacing(8)

        lbl_sort = QLabel("⇅ Classificação:")
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

        self.btn_sort_asc = QPushButton("▲ Crescente")
        self.btn_sort_asc.setFixedHeight(28)
        self.btn_sort_asc.setCheckable(True)
        self.btn_sort_asc.setChecked(True)
        self.btn_sort_asc.setCursor(Qt.PointingHandCursor)
        self.btn_sort_asc.setToolTip("Classificação crescente (menor latência / mais veloz primeiro)")

        self.btn_sort_desc = QPushButton("▼ Decrescente")
        self.btn_sort_desc.setFixedHeight(28)
        self.btn_sort_desc.setCheckable(True)
        self.btn_sort_desc.setChecked(False)
        self.btn_sort_desc.setCursor(Qt.PointingHandCursor)
        self.btn_sort_desc.setToolTip("Classificação decrescente (maior latência primeiro)")

        self.btn_sort_asc.clicked.connect(lambda: self.set_sort_order(Qt.AscendingOrder))
        self.btn_sort_desc.clicked.connect(lambda: self.set_sort_order(Qt.DescendingOrder))

        sort_bar.addWidget(self.btn_sort_asc)
        sort_bar.addWidget(self.btn_sort_desc)
        sort_bar.addStretch()

        vbox.addLayout(sort_bar)

        # 5. Table Widget (High contrast, clearly bordered cells)
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "Provedor / Alvo",
            "Endereço IP",
            "Ping ICMP (Médio)",
            "Query DNS UDP 53",
            "Perda de Pacotes",
            "Qualidade",
            "Destaque",
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

        # 6. Bottom Action Buttons
        btn_box = QHBoxLayout()
        btn_box.setSpacing(10)

        self.btn_restart = QPushButton("▶  Novo Teste")
        self.btn_restart.setObjectName("btnStart")
        self.btn_restart.setFixedHeight(34)
        self.btn_restart.setFixedWidth(125)
        self.btn_restart.setCursor(Qt.PointingHandCursor)
        self.btn_restart.clicked.connect(self.start_test)
        btn_box.addWidget(self.btn_restart)

        self.btn_copy = QPushButton("📋 Copiar Relatório")
        self.btn_copy.setFixedHeight(34)
        self.btn_copy.setCursor(Qt.PointingHandCursor)
        self.btn_copy.clicked.connect(self.copy_report)
        btn_box.addWidget(self.btn_copy)

        btn_box.addStretch()

        btn_close = QPushButton("Fechar")
        btn_close.setFixedHeight(34)
        btn_close.setFixedWidth(100)
        btn_close.setCursor(Qt.PointingHandCursor)
        btn_close.clicked.connect(self.accept)
        btn_box.addWidget(btn_close)

        vbox.addLayout(btn_box)

    def _create_kpi_card(self, title: str, default_val: str, accent_color: str) -> QFrame:
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
        box.setSpacing(3)

        lbl_t = QLabel(title)
        lbl_t.setStyleSheet(f"font-size: 11px; color: {self.c_text_sub}; font-weight: 600;")
        lbl_v = QLabel(default_val)
        lbl_v.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {self.c_text_main};")
        lbl_v.setObjectName("val")

        box.addWidget(lbl_t)
        box.addWidget(lbl_v)
        return card

    def _set_kpi_val(self, card: QFrame, text: str, custom_color: str = ""):
        lbl = card.findChild(QLabel, "val")
        if lbl:
            lbl.setText(text)
            if custom_color:
                lbl.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {custom_color};")

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
        self.lbl_recommendation.setText("Aguardando finalização das medições para calcular o melhor provedor...")

        self.worker = InternetTestWorker(gateway_ip=self.gateway_ip)
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
            ping_str = "Sem resposta" if res["packet_loss"] == 100 else "N/D"
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
            dns_str = "Falhou"
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
            # Soft red tint on packet loss cell
            item_loss.setBackground(QColor(239, 68, 68, 30 if self.is_dark else 25))
        else:
            item_loss.setForeground(QColor("#10b981" if self.is_dark else "#16a34a"))
        self.table.setItem(row, 4, item_loss)

        # 5. Rating badge (High contrast colored pill style)
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

        rank_val = {"Excelente": 1, "Bom": 2, "Aceitável": 3, "Lento": 4, "Inacessível": 5}.get(res["rating"], 99)
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

            # Highlight champion row in table
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

        # Apply default sorting: DNS latency ascending (lowest latency on top)
        self.apply_sorting(col=3, order=Qt.AscendingOrder)

    def copy_report(self):
        if self.table.rowCount() == 0:
            QMessageBox.information(self, "Aviso", "Aguarde a conclusão do teste antes de copiar o relatório.")
            return

        lines = [
            "==================================================================",
            "   IP SCAN IGT — RELATÓRIO DE QUALIDADE DA INTERNET & DNS",
            "==================================================================",
            f"• Data/Hora:         {time.strftime('%d/%m/%Y %H:%M:%S')}",
            f"• IP Público (WAN):  {self.card_wan.findChild(QLabel, 'val').text()}",
            f"• Gateway Local:     {self.card_gw.findChild(QLabel, 'val').text()}",
            f"• DNS da Placa:      {self.card_dns.findChild(QLabel, 'val').text()}",
            f"• DNS Mais Rápido:   {self.card_fastest.findChild(QLabel, 'val').text()}",
            "------------------------------------------------------------------",
            f"{'Alvo':<34} | {'IP':<15} | {'Ping Méd':<10} | {'DNS RTT':<10} | {'Perda':<6} | {'Classificação'}",
            "------------------------------------------------------------------",
        ]
        for r in range(self.table.rowCount()):
            item_prov = self.table.item(r, 0)
            item_ip = self.table.item(r, 1)
            item_ping = self.table.item(r, 2)
            item_dns = self.table.item(r, 3)
            item_loss = self.table.item(r, 4)
            item_rating = self.table.item(r, 5)

            prov_text = item_prov.text() if item_prov else ""
            ip_text = item_ip.text() if item_ip else ""
            ping_text = item_ping.text() if item_ping else "N/D"
            dns_text = item_dns.text() if item_dns else "N/D"
            loss_text = item_loss.text() if item_loss else "0%"
            rating_text = item_rating.text() if item_rating else "N/D"

            lines.append(f"{prov_text:<34} | {ip_text:<15} | {ping_text:<10} | {dns_text:<10} | {loss_text:>6} | {rating_text}")

        lines.append("==================================================================")
        lines.append(f"Recomendação: {self.lbl_recommendation.text()}")
        lines.append("==================================================================")

        report = "\n".join(lines)
        QApplication.clipboard().setText(report)
        QMessageBox.information(
            self,
            "Relatório Copiado",
            "O relatório completo do teste de qualidade da internet foi copiado para a Área de Transferência!"
        )

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.worker.wait(1000)
        super().closeEvent(event)
