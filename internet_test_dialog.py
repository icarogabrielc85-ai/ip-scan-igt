#!/usr/bin/env python3
"""
Internet Health, Latency & DNS Benchmark Diagnostic Dialog for IP Scan IGT.
Measures gateway ping, network interface DNS servers, and benchmark major public DNS providers
(Cloudflare, Google, OpenDNS, Quad9, AdGuard) with packet loss, jitter, and DNS resolution latency.
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

from PyQt5.QtCore import QObject, QPoint, QSize, Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QIcon
from PyQt5.QtWidgets import (
    QApplication,
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
    {
        "provider": "Cloudflare DNS (Primário)",
        "ip": "1.1.1.1",
        "category": "Público Global",
        "feature": "Ultra Rápido / Foco em Privacidade",
    },
    {
        "provider": "Cloudflare DNS (Secundário)",
        "ip": "1.0.0.1",
        "category": "Público Global",
        "feature": "Ultra Rápido / Backup Cloudflare",
    },
    {
        "provider": "Google Public DNS (Primário)",
        "ip": "8.8.8.8",
        "category": "Público Global",
        "feature": "Alta Confiabilidade & Anycast Global",
    },
    {
        "provider": "Google Public DNS (Secundário)",
        "ip": "8.8.4.4",
        "category": "Público Global",
        "feature": "Alta Confiabilidade / Backup Google",
    },
    {
        "provider": "OpenDNS Cisco (Primário)",
        "ip": "208.67.222.222",
        "category": "Segurança & Filtro",
        "feature": "Proteção Phishing & Bloqueio Malware",
    },
    {
        "provider": "OpenDNS Cisco (Secundário)",
        "ip": "208.67.220.220",
        "category": "Segurança & Filtro",
        "feature": "Proteção Phishing / Backup Cisco",
    },
    {
        "provider": "Quad9 DNS (Primário)",
        "ip": "9.9.9.9",
        "category": "Segurança & Privacidade",
        "feature": "Bloqueio de Ameaças Cibernéticas",
    },
    {
        "provider": "AdGuard DNS (Público)",
        "ip": "94.140.14.14",
        "category": "Privacidade & Anti-Ad",
        "feature": "Filtro de Anúncios e Rastreadores",
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
            out = subprocess.check_output(["ipconfig", "/all"], text=True, stderr=subprocess.DEVNULL, timeout=2.0)
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
    """
    cmd = ["ping", "-n" if IS_WINDOWS else "-c", str(count), "-w" if IS_WINDOWS else "-W", str(timeout_sec * 1000 if IS_WINDOWS else timeout_sec), ip]
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=count * timeout_sec + 2.0)
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
            req = urllib.request.Request(url, headers={"User-Agent": "IPScanIGT/2.6.0"})
            with urllib.request.urlopen(req, timeout=1.8) as resp:
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

        # 2. Assemble test targets list
        targets = []

        # Local Gateway
        if self.gateway_ip and self.gateway_ip != "N/D":
            targets.append({
                "provider": "Gateway da Rede Local (Roteador)",
                "ip": self.gateway_ip,
                "category": "Rede Local",
                "feature": "Ponto de Saída da LAN",
                "is_dns": False,
            })

        # Configured interface DNS
        local_dns = get_interface_configured_dns()
        for idx, d_ip in enumerate(local_dns):
            targets.append({
                "provider": f"DNS da Placa de Rede {'(Primário)' if idx == 0 else '(Secundário)'}",
                "ip": d_ip,
                "category": "DNS Local Ativo",
                "feature": "Configurado na Interface de Rede",
                "is_dns": True,
            })

        # Public DNS providers
        for p in PUBLIC_DNS_TARGETS:
            # avoid duplicate if already in local_dns
            if not any(t["ip"] == p["ip"] for t in targets):
                p_copy = dict(p)
                p_copy["is_dns"] = True
                targets.append(p_copy)

        total_targets = len(targets)
        results = []

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

            # Rating
            ref_latency = dns_rtt if (is_dns and dns_rtt is not None) else p_avg
            if loss == 100 or (ref_latency is None and not dns_ok):
                rating = "Inacessível"
                color = "#ef4444"
            elif ref_latency is not None and ref_latency < 20.0:
                rating = "Excelente"
                color = "#10b981"
            elif ref_latency is not None and ref_latency < 50.0:
                rating = "Bom"
                color = "#38bdf8"
            elif ref_latency is not None and ref_latency < 100.0:
                rating = "Aceitável"
                color = "#f59e0b"
            else:
                rating = "Lento"
                color = "#f97316"

            res = {
                **item,
                "dns_rtt": dns_rtt,
                "dns_ok": dns_ok,
                "ping_min": p_min,
                "ping_avg": p_avg,
                "ping_max": p_max,
                "packet_loss": loss,
                "rating": rating,
                "color": color,
                "score_latency": ref_latency if ref_latency is not None else 9999.0,
            }
            return res

        tested_count = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
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

        summary = {
            "public_ip": pub_info.get("ip", "N/D"),
            "public_status": pub_info.get("status", "offline"),
            "gateway_ip": self.gateway_ip,
            "fastest_dns": fastest_dns,
            "total_tested": len(results),
            "results": results,
        }
        self.finished.emit(summary)


class InternetQualityDialog(QDialog):
    """
    Modern modal dialog for evaluating Internet Health, Gateway, Local DNS,
    and Global Public DNS benchmarks with live metrics and recommendations.
    """
    def __init__(self, parent=None, gateway_ip: str = ""):
        super().__init__(parent)
        self.gateway_ip = gateway_ip.strip()
        self.worker = None
        self.results_list = []

        self.setWindowTitle("Diagnóstico de Qualidade da Internet & Benchmark de DNS")
        self.resize(840, 580)
        self.init_ui()
        self.start_test()

    def init_ui(self):
        vbox = QVBoxLayout(self)
        vbox.setContentsMargins(16, 14, 16, 14)
        vbox.setSpacing(10)

        # Header card
        hdr = QFrame()
        hdr.setObjectName("netTestHdr")
        hdr.setStyleSheet("""
            QFrame#netTestHdr {
                background-color: #162032;
                border: 1px solid #1f2937;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        h_layout = QHBoxLayout(hdr)
        h_layout.setContentsMargins(6, 4, 6, 4)
        h_layout.setSpacing(12)

        lbl_icon = QLabel("🌐")
        lbl_icon.setStyleSheet("font-size: 32px;")
        h_layout.addWidget(lbl_icon)

        info_box = QVBoxLayout()
        info_box.setSpacing(2)
        lbl_title = QLabel("Teste de Conexão com a Internet & Benchmark de DNS")
        lbl_title.setStyleSheet("font-weight: bold; font-size: 15px; color: #38bdf8;")
        lbl_sub = QLabel("Mede latência ICMP, tempo de resolução DNS UDP 53 e perda de pacotes dos principais provedores.")
        lbl_sub.setStyleSheet("font-size: 12px; color: #94a3b8;")
        info_box.addWidget(lbl_title)
        info_box.addWidget(lbl_sub)
        h_layout.addLayout(info_box, 1)

        vbox.addWidget(hdr)

        # KPI Badges Summary Row
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(8)

        self.card_wan = self._create_kpi_card("IP Público (WAN)", "Detectando...", "#38bdf8")
        self.card_gw = self._create_kpi_card("Gateway Local", self.gateway_ip or "Detectando...", "#10b981")
        self.card_dns = self._create_kpi_card("DNS da Placa", "Detectando...", "#a855f7")
        self.card_fastest = self._create_kpi_card("🏆 Mais Rápido", "Aguardando...", "#eab308")

        kpi_row.addWidget(self.card_wan)
        kpi_row.addWidget(self.card_gw)
        kpi_row.addWidget(self.card_dns)
        kpi_row.addWidget(self.card_fastest)
        vbox.addLayout(kpi_row)

        # Progress bar
        self.prog_bar = QProgressBar()
        self.prog_bar.setFixedHeight(8)
        self.prog_bar.setTextVisible(False)
        self.prog_bar.setRange(0, 100)
        self.prog_bar.setValue(0)
        self.prog_bar.setStyleSheet("""
            QProgressBar {
                background-color: #1e293b;
                border: none;
                border-radius: 4px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #38bdf8);
                border-radius: 4px;
            }
        """)
        vbox.addWidget(self.prog_bar)

        self.lbl_status = QLabel("Iniciando diagnósticos de rede...")
        self.lbl_status.setStyleSheet("font-size: 11px; color: #94a3b8; margin-left: 2px;")
        vbox.addWidget(self.lbl_status)

        # Table Widget
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "Provedor / Alvo",
            "Endereço IP",
            "Ping ICMP (Médio)",
            "Resolução DNS",
            "Perda de Pacotes",
            "Classificação",
            "Destaque",
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #0b1120;
                border: 1px solid #1e293b;
                border-radius: 6px;
                gridline-color: #1e293b;
            }
        """)
        vbox.addWidget(self.table, 1)

        # Recommendation banner card
        self.rec_card = QFrame()
        self.rec_card.setStyleSheet("background-color: #0f172a; border: 1px solid #1e293b; border-radius: 6px; padding: 6px;")
        rec_box = QHBoxLayout(self.rec_card)
        rec_box.setContentsMargins(8, 4, 8, 4)
        rec_box.setSpacing(8)

        self.lbl_rec_icon = QLabel("💡")
        self.lbl_rec_icon.setStyleSheet("font-size: 16px;")
        rec_box.addWidget(self.lbl_rec_icon)

        self.lbl_recommendation = QLabel("Aguardando conclusão do teste para gerar recomendações...")
        self.lbl_recommendation.setStyleSheet("font-size: 12px; color: #cbd5e1;")
        self.lbl_recommendation.setWordWrap(True)
        rec_box.addWidget(self.lbl_recommendation, 1)
        vbox.addWidget(self.rec_card)

        # Bottom Action Buttons
        btn_box = QHBoxLayout()
        btn_box.setSpacing(10)

        self.btn_restart = QPushButton("▶  Novo Teste")
        self.btn_restart.setObjectName("btnStart")
        self.btn_restart.setFixedHeight(34)
        self.btn_restart.setFixedWidth(120)
        self.btn_restart.clicked.connect(self.start_test)
        btn_box.addWidget(self.btn_restart)

        self.btn_copy = QPushButton("📋 Copiar Relatório")
        self.btn_copy.setFixedHeight(34)
        self.btn_copy.clicked.connect(self.copy_report)
        btn_box.addWidget(self.btn_copy)

        btn_box.addStretch()

        btn_close = QPushButton("Fechar")
        btn_close.setFixedHeight(34)
        btn_close.setFixedWidth(100)
        btn_close.clicked.connect(self.accept)
        btn_box.addWidget(btn_close)

        vbox.addLayout(btn_box)

    def _create_kpi_card(self, title: str, default_val: str, accent_color: str) -> QFrame:
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: #0f172a;
                border: 1px solid #1e293b;
                border-top: 3px solid {accent_color};
                border-radius: 6px;
                padding: 4px;
            }}
        """)
        box = QVBoxLayout(card)
        box.setContentsMargins(8, 6, 8, 6)
        box.setSpacing(2)

        lbl_t = QLabel(title)
        lbl_t.setStyleSheet("font-size: 10px; color: #94a3b8; font-weight: 600; text-transform: uppercase;")
        lbl_v = QLabel(default_val)
        lbl_v.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {accent_color};")
        lbl_v.setObjectName("val")

        box.addWidget(lbl_t)
        box.addWidget(lbl_v)
        return card

    def _set_kpi_val(self, card: QFrame, text: str):
        lbl = card.findChild(QLabel, "val")
        if lbl:
            lbl.setText(text)

    def start_test(self):
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.worker.wait(1000)

        self.results_list.clear()
        self.table.setRowCount(0)
        self.prog_bar.setValue(0)
        self.btn_restart.setEnabled(False)
        self.btn_restart.setText("Testando...")
        self.lbl_status.setText("Testando conexão de gateway e servidores DNS...")
        self.lbl_recommendation.setText("Executando baterias de ping e queries DNS em paralelo...")

        self.worker = InternetTestWorker(gateway_ip=self.gateway_ip)
        self.worker.progress.connect(self.on_progress)
        self.worker.target_tested.connect(self.on_target_tested)
        self.worker.finished.connect(self.on_finished)
        self.worker.start()

    def on_progress(self, current: int, total: int, target_name: str):
        pct = int((current / total) * 100) if total > 0 else 0
        self.prog_bar.setValue(pct)
        self.lbl_status.setText(f"Verificando [{current}/{total}]: {target_name}...")

    def on_target_tested(self, res: dict):
        self.results_list.append(res)
        row = self.table.rowCount()
        self.table.insertRow(row)

        # 0. Provider name
        item_prov = QTableWidgetItem(res["provider"])
        item_prov.setFont(QFont("", -1, QFont.Bold))
        self.table.setItem(row, 0, item_prov)

        # 1. IP
        item_ip = QTableWidgetItem(res["ip"])
        item_ip.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, 1, item_ip)

        # 2. Ping ICMP Avg
        if res.get("ping_avg") is not None:
            ping_str = f"{res['ping_avg']:.1f} ms"
        else:
            ping_str = "Sem resposta" if res["packet_loss"] == 100 else "N/D"
        item_ping = QTableWidgetItem(ping_str)
        item_ping.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, 2, item_ping)

        # 3. DNS Query RTT
        if res.get("dns_rtt") is not None:
            dns_str = f"{res['dns_rtt']:.1f} ms"
        elif not res.get("is_dns"):
            dns_str = "— (Gateway)"
        else:
            dns_str = "Falhou"
        item_dns = QTableWidgetItem(dns_str)
        item_dns.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, 3, item_dns)

        # 4. Packet Loss
        loss = res.get("packet_loss", 0)
        item_loss = QTableWidgetItem(f"{loss}%")
        item_loss.setTextAlignment(Qt.AlignCenter)
        if loss > 0:
            item_loss.setForeground(QColor("#ef4444"))
        else:
            item_loss.setForeground(QColor("#10b981"))
        self.table.setItem(row, 4, item_loss)

        # 5. Rating badge
        item_rating = QTableWidgetItem(res["rating"])
        item_rating.setTextAlignment(Qt.AlignCenter)
        item_rating.setFont(QFont("", -1, QFont.Bold))
        item_rating.setForeground(QColor(res["color"]))
        self.table.setItem(row, 5, item_rating)

        # 6. Feature/Highlight
        badge = "🛡️ Placa de Rede" if "Placa" in res["provider"] else ("🏠 Gateway" if "Gateway" in res["provider"] else "")
        item_feat = QTableWidgetItem(badge or res.get("feature", ""))
        item_feat.setTextAlignment(Qt.AlignCenter)
        item_feat.setForeground(QColor("#94a3b8"))
        self.table.setItem(row, 6, item_feat)

    def on_finished(self, summary: dict):
        self.prog_bar.setValue(100)
        self.btn_restart.setEnabled(True)
        self.btn_restart.setText("▶  Novo Teste")
        self.lbl_status.setText(f"Diagnóstico concluído: {summary['total_tested']} alvos testados com sucesso.")

        # Update WAN KPI
        wan_ip = summary.get("public_ip", "Indisponível")
        self._set_kpi_val(self.card_wan, wan_ip)

        # Update Local DNS KPI
        local_dns = [r for r in self.results_list if "Placa" in r.get("provider", "")]
        if local_dns:
            d_best = min(local_dns, key=lambda x: x["score_latency"])
            d_ms = f"{d_best['score_latency']:.1f} ms" if d_best['score_latency'] < 9999 else "Offline"
            self._set_kpi_val(self.card_dns, f"{d_best['ip']} ({d_ms})")
        else:
            self._set_kpi_val(self.card_dns, "Automático / Router")

        # Update Gateway KPI
        gw_res = next((r for r in self.results_list if "Gateway" in r.get("provider", "")), None)
        if gw_res and gw_res.get("ping_avg") is not None:
            self._set_kpi_val(self.card_gw, f"{gw_res['ip']} ({gw_res['ping_avg']:.1f} ms)")
        elif self.gateway_ip:
            self._set_kpi_val(self.card_gw, self.gateway_ip)

        # Update Fastest DNS KPI & Table highlight
        fastest = summary.get("fastest_dns")
        if fastest:
            self._set_kpi_val(self.card_fastest, f"{fastest['provider'].split()[0]} ({fastest['score_latency']:.1f} ms)")

            # Highlight row in table
            for r in range(self.table.rowCount()):
                if self.table.item(r, 1) and self.table.item(r, 1).text() == fastest["ip"]:
                    item_dest = self.table.item(r, 6)
                    if item_dest:
                        item_dest.setText("🏆 Mais Rápido!")
                        item_dest.setFont(QFont("", -1, QFont.Bold))
                        item_dest.setForeground(QColor("#eab308"))

            # Formulate recommendation
            local_dns_item = next((r for r in local_dns if r.get("score_latency", 9999) < 9999), None)
            if local_dns_item and local_dns_item["ip"] == fastest["ip"]:
                self.lbl_recommendation.setText(
                    f"✔ Excelente configuração! O DNS configurado na sua placa de rede ({fastest['ip']}) é o mais rápido ({fastest['score_latency']:.1f} ms) para sua conexão."
                )
            elif local_dns_item and local_dns_item["score_latency"] > (fastest["score_latency"] + 15):
                diff = local_dns_item["score_latency"] - fastest["score_latency"]
                self.lbl_recommendation.setText(
                    f"💡 O provedor {fastest['provider']} ({fastest['ip']}) respondeu em {fastest['score_latency']:.1f} ms ({diff:.1f} ms mais rápido que o DNS da placa de rede). Considere utilizá-lo para otimizar a navegação!"
                )
            else:
                self.lbl_recommendation.setText(
                    f"✔ Conexão com a Internet estável. O provedor mais veloz no teste foi {fastest['provider']} ({fastest['ip']}) com {fastest['score_latency']:.1f} ms."
                )
        else:
            self._set_kpi_val(self.card_fastest, "Sem resposta DNS")
            self.lbl_recommendation.setText(
                "⚠️ Não foi possível resolver consultas DNS públicas. Verifique seu roteador, firewall ou conexão com o provedor de internet."
            )

    def copy_report(self):
        if not self.results_list:
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
            f"{'Alvo':<34} | {'IP':<15} | {'Ping Méd':<10} | {'DNS RTT':<10} | {'Perda':<6} | {'Classif.'}",
            "------------------------------------------------------------------",
        ]
        for r in self.results_list:
            p_str = f"{r['ping_avg']:.1f} ms" if r.get('ping_avg') is not None else "N/D"
            d_str = f"{r['dns_rtt']:.1f} ms" if r.get('dns_rtt') is not None else ("—" if not r.get('is_dns') else "Falhou")
            lines.append(f"{r['provider']:<34} | {r['ip']:<15} | {p_str:<10} | {d_str:<10} | {r['packet_loss']:>3}%  | {r['rating']}")

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
