import os
import re
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from PyQt5.QtCore import QPointF, QRectF, Qt, QThread, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QBrush, QColor, QFont, QPainter, QPainterPath, QPen
from PyQt5.QtWidgets import (
    QDialog,
    QFrame,
    QGraphicsScene,
    QGraphicsView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from i18n import tr
from scanner_engine import IS_WINDOWS, _get_windows_silent_kwargs

@dataclass
class TraceHop:
    ttl: int
    ip: str
    rtt_ms: float
    hostname: str = ""
    reached_target: bool = False
    timed_out: bool = False


def resolve_hop_name(ip: str, known_records: Optional[Dict[str, object]] = None, gateway_ip: str = "") -> str:
    if not ip or ip == "*":
        return "Sem resposta (ICMP bloqueado / Timeout)"
    if known_records and ip in known_records:
        rec = known_records[ip]
        h = getattr(rec, "hostname", "") or ""
        if h:
            return h
    if gateway_ip and ip == gateway_ip:
        return "Gateway Padrão (Roteador Local)"
    try:
        sock_old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(0.35)
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            if name and name != ip:
                return name
        finally:
            socket.setdefaulttimeout(sock_old)
    except Exception:
        pass
    return "Roteador / Nó Intermediário"


def probe_single_ttl_hop(target_ip: str, ttl: int, timeout_ms: int = 800) -> TraceHop:
    """
    Executa sondagem de salto único com TTL específico via ping do sistema operacional.
    Funciona em 100% dos sistemas Linux (`ping -t <ttl>`) e Windows (`ping -i <ttl>`)
    sem exigir pacotes extras ou privilégios de administrador.
    """
    t0 = time.perf_counter()
    try:
        if IS_WINDOWS:
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), "-i", str(ttl), target_ip]
            kwargs = _get_windows_silent_kwargs()
        else:
            w_sec = max(1, int(round(timeout_ms / 1000.0)))
            cmd = ["ping", "-n", "-c", "1", "-W", str(w_sec), "-t", str(ttl), target_ip]
            kwargs = {}

        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=(timeout_ms / 1000.0) + 1.5,
            **kwargs,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        out = proc.stdout or ""

        # Check if Time to live exceeded (Intermediate Router Hop)
        # Linux: "From 192.168.1.1 icmp_seq=1 Time to live exceeded"
        # Windows: "Reply from 192.168.1.1: TTL expired in transit." or "Resposta de 192.168.1.1: A vida útil (TTL) expirou em trânsito."
        m_exceeded = re.search(
            r"(?:From|Reply from|Resposta de)\s+(\d{1,3}(?:\.\d{1,3}){3}).*?(?:exceeded|expired|expirou|transito|trânsito)",
            out,
            re.I | re.S,
        )
        if m_exceeded:
            hop_ip = m_exceeded.group(1)
            return TraceHop(
                ttl=ttl,
                ip=hop_ip,
                rtt_ms=round(elapsed_ms, 2),
                reached_target=(hop_ip == target_ip),
                timed_out=False,
            )

        # Check if target replied directly
        m_reply = re.search(
            r"(?:bytes from|Reply from|Resposta de)\s+(\d{1,3}(?:\.\d{1,3}){3})",
            out,
            re.I,
        )
        if m_reply or proc.returncode == 0:
            hop_ip = m_reply.group(1) if m_reply else target_ip
            m_time = re.search(r"(?:time|tempo)[=<]\s*([0-9\.]+)\s*ms", out, re.I)
            rtt = float(m_time.group(1)) if m_time else round(elapsed_ms, 2)
            return TraceHop(
                ttl=ttl,
                ip=hop_ip,
                rtt_ms=rtt,
                reached_target=True,
                timed_out=False,
            )
    except Exception:
        pass

    return TraceHop(
        ttl=ttl,
        ip="*",
        rtt_ms=-1.0,
        reached_target=False,
        timed_out=True,
    )


class TracerouteWorker(QThread):
    hop_discovered = pyqtSignal(object)  # TraceHop
    trace_finished = pyqtSignal(int, bool)  # total_hops, reached

    def __init__(
        self,
        target: str,
        max_hops: int = 16,
        known_records: Optional[Dict[str, object]] = None,
        gateway_ip: str = "",
    ):
        super().__init__()
        self.target = target.strip()
        self.max_hops = max_hops
        self.known_records = known_records or {}
        self.gateway_ip = gateway_ip
        self._running = True

    def stop(self):
        self._running = False

    def run(self):
        try:
            target_ip = socket.gethostbyname(self.target)
        except Exception:
            target_ip = self.target

        hops_count = 0
        reached = False
        consecutive_timeouts = 0

        for ttl in range(1, self.max_hops + 1):
            if not self._running:
                break
            hop = probe_single_ttl_hop(target_ip, ttl=ttl, timeout_ms=750)
            if not self._running:
                break
            hop.hostname = resolve_hop_name(hop.ip, self.known_records, self.gateway_ip)
            hops_count += 1
            self.hop_discovered.emit(hop)

            if hop.reached_target or hop.ip == target_ip:
                reached = True
                break

            if hop.timed_out:
                consecutive_timeouts += 1
                # If target is on local LAN and hop 1 timed out, try direct ping to see if it's 1 hop away
                if ttl == 1 and consecutive_timeouts >= 1:
                    direct = probe_single_ttl_hop(target_ip, ttl=64, timeout_ms=600)
                    if direct.reached_target:
                        direct.ttl = 1
                        direct.hostname = resolve_hop_name(direct.ip, self.known_records, self.gateway_ip)
                        self.hop_discovered.emit(direct)
                        reached = True
                        break
            else:
                consecutive_timeouts = 0

        self.trace_finished.emit(hops_count, reached)


class TracerouteDialog(QDialog):
    """
    Ferramenta de Traceroute Visual por Saltos (TTL) com Grafo de Rota e Tabela de Latência.
    """

    def __init__(
        self,
        parent=None,
        target_ip: str = "",
        known_records: Optional[Dict[str, object]] = None,
        local_ip: str = "",
        gateway_ip: str = "",
        is_dark: bool = False,
    ):
        super().__init__(parent)
        self.target_ip = target_ip
        self.known_records = known_records or {}
        self.local_ip = local_ip or "Este Computador"
        self.gateway_ip = gateway_ip
        self.is_dark = is_dark
        self.hops: List[TraceHop] = []
        self.worker: Optional[TracerouteWorker] = None

        self.setWindowTitle(
            tr("traceroute_dialog_title", "🧭 Traceroute Visual — Diagnóstico de Rota e Saltos (TTL)")
        )
        self.resize(960, 600)
        self._setup_ui()

        if self.target_ip:
            self.txt_target.setText(self.target_ip)
            self.start_trace()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        hdr = QLabel(
            "<h3>🧭 Traceroute Visual — Mapeamento de Saltos (Hops) e Latência por Roteador</h3>"
            "<p style='color:#64748b; font-size:12px; margin-top:2px;'>"
            "Rastreia o caminho pacote a pacote (TTL 1..N) desde a sua placa de rede até o destino, "
            "identificando gargalos de latência, roteadores intermediários e perdas de pacotes."
            "</p>"
        )
        hdr.setWordWrap(True)
        layout.addWidget(hdr)

        # Controls Bar
        ctrl = QFrame()
        ctrl.setFrameShape(QFrame.StyledPanel)
        ctrl_layout = QHBoxLayout(ctrl)
        ctrl_layout.setContentsMargins(12, 8, 12, 8)
        ctrl_layout.setSpacing(10)

        ctrl_layout.addWidget(QLabel("<b>Destino (IP ou Domínio):</b>"))
        self.txt_target = QLineEdit()
        self.txt_target.setPlaceholderText("Ex: 192.168.1.1, 8.8.8.8 ou cloudflare.com")
        self.txt_target.setMinimumWidth(240)
        self.txt_target.returnPressed.connect(self.start_trace)
        ctrl_layout.addWidget(self.txt_target)

        ctrl_layout.addWidget(QLabel("Máx. Saltos (TTL):"))
        self.spin_hops = QSpinBox()
        self.spin_hops.setRange(1, 30)
        self.spin_hops.setValue(16)
        ctrl_layout.addWidget(self.spin_hops)

        self.btn_run = QPushButton("▶ Iniciar Traceroute")
        self.btn_run.setFixedHeight(32)
        self.btn_run.setStyleSheet(
            "QPushButton { background-color: #059669; color: #ffffff; font-weight: bold; padding: 4px 14px; border-radius: 5px; }"
        )
        self.btn_run.clicked.connect(self.toggle_trace)
        ctrl_layout.addWidget(self.btn_run)

        ctrl_layout.addStretch()
        self.lbl_status = QLabel("Pronto.")
        ctrl_layout.addWidget(self.lbl_status)
        layout.addWidget(ctrl)

        # Splitter: Upper = Visual Hop Graph, Lower = Hop Table
        splitter = QSplitter(Qt.Vertical)

        self.scene = QGraphicsScene(self)
        self.view = QGraphicsView(self.scene)
        self.view.setRenderHints(QPainter.Antialiasing | QPainter.TextAntialiasing)
        self.view.setMinimumHeight(210)
        bg_col = QColor("#0f172a") if self.is_dark else QColor("#f8fafc")
        self.scene.setBackgroundBrush(QBrush(bg_col))
        splitter.addWidget(self.view)

        self.tbl_hops = QTableWidget(0, 5)
        self.tbl_hops.setHorizontalHeaderLabels([
            "Salto (TTL)",
            "Endereço IP do Nó",
            "Identificação / Hostname",
            "Latência (RTT)",
            "Diagnóstico do Salto",
        ])
        self.tbl_hops.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tbl_hops.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tbl_hops.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.tbl_hops.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.tbl_hops.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.tbl_hops.verticalHeader().setVisible(False)
        self.tbl_hops.setAlternatingRowColors(True)
        splitter.addWidget(self.tbl_hops)
        splitter.setSizes([240, 260])

        layout.addWidget(splitter)

        # Footer
        footer = QHBoxLayout()
        footer.addStretch()
        btn_close = QPushButton(tr("btn_close", "Fechar"))
        btn_close.setFixedWidth(110)
        btn_close.clicked.connect(self.close)
        footer.addWidget(btn_close)
        layout.addLayout(footer)

    def toggle_trace(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(500)
            self.btn_run.setText("▶ Iniciar Traceroute")
            self.lbl_status.setText("Traceroute interrompido.")
            return
        self.start_trace()

    def start_trace(self):
        target = self.txt_target.text().strip()
        if not target:
            return
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(400)

        self.hops.clear()
        self.tbl_hops.setRowCount(0)
        self._redraw_visual_chain()

        self.btn_run.setText("⏹ Parar")
        self.lbl_status.setText(f"Rastreando rota até {target}...")

        self.worker = TracerouteWorker(
            target=target,
            max_hops=self.spin_hops.value(),
            known_records=self.known_records,
            gateway_ip=self.gateway_ip,
        )
        self.worker.hop_discovered.connect(self.on_hop_discovered)
        self.worker.trace_finished.connect(self.on_trace_finished)
        self.worker.start()

    @pyqtSlot(object)
    def on_hop_discovered(self, hop: TraceHop):
        # Replace if same TTL already added (e.g. fallback direct check)
        self.hops = [h for h in self.hops if h.ttl != hop.ttl]
        self.hops.append(hop)
        self.hops.sort(key=lambda x: x.ttl)
        self._update_table()
        self._redraw_visual_chain()

    @pyqtSlot(int, bool)
    def on_trace_finished(self, total_hops: int, reached: bool):
        self.btn_run.setText("▶ Iniciar Traceroute")
        status_msg = "Destino alcançado com sucesso!" if reached else "Limite de saltos atingido."
        self.lbl_status.setText(f"Concluído ({ len(self.hops) } salto(s)) — {status_msg}")

    def _update_table(self):
        self.tbl_hops.setRowCount(len(self.hops))
        f_bold = QFont("Segoe UI", 9, QFont.Bold)
        for r, h in enumerate(self.hops):
            it_ttl = QTableWidgetItem(f"#{h.ttl}")
            it_ttl.setFont(f_bold)
            it_ip = QTableWidgetItem(h.ip)
            it_ip.setFont(f_bold)
            it_host = QTableWidgetItem(h.hostname)

            if h.timed_out:
                rtt_str = "* (Timeout)"
                diag = "⚪ Sem resposta ICMP neste salto"
                col = QColor("#64748b")
            else:
                rtt_str = f"{h.rtt_ms:.2f} ms"
                if h.reached_target:
                    diag = "🎯 Destino Final Alcançado"
                    col = QColor("#059669")
                elif h.rtt_ms < 5.0:
                    diag = "🟢 Salto Local Ultra-rápido (<5ms)"
                    col = QColor("#059669")
                elif h.rtt_ms < 35.0:
                    diag = "🔵 Latência Normal"
                    col = QColor("#0284c7")
                else:
                    diag = "🟠 Latência Elevada no Salto"
                    col = QColor("#d97706")

            it_rtt = QTableWidgetItem(rtt_str)
            it_rtt.setForeground(col)
            it_rtt.setFont(f_bold)
            it_diag = QTableWidgetItem(diag)
            it_diag.setForeground(col)

            for c, it in enumerate([it_ttl, it_ip, it_host, it_rtt, it_diag]):
                it.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                self.tbl_hops.setItem(r, c, it)

    def _redraw_visual_chain(self):
        self.scene.clear()
        card_w = 155
        card_h = 74
        gap_x = 48
        gap_y = 38
        cols_per_row = 4

        nodes = [
            {
                "title": "💻 Origem (Este PC)",
                "ip": self.local_ip,
                "rtt": "0.00 ms",
                "color": QColor("#0284c7"),
            }
        ]
        for h in self.hops:
            if h.timed_out:
                c = QColor("#64748b")
                title = f"Salto #{h.ttl} (Timeout)"
                rtt_txt = "* * *"
            elif h.reached_target:
                c = QColor("#059669")
                title = f"🎯 #{h.ttl} Destino"
                rtt_txt = f"{h.rtt_ms:.2f} ms"
            else:
                c = QColor("#0d9488") if h.rtt_ms < 15.0 else QColor("#d97706")
                title = f"🌐 Salto #{h.ttl}"
                rtt_txt = f"{h.rtt_ms:.2f} ms"
            nodes.append({
                "title": title,
                "ip": h.ip,
                "rtt": rtt_txt,
                "color": c,
            })

        centers: List[QPointF] = []
        for idx, n in enumerate(nodes):
            row = idx // cols_per_row
            col = idx % cols_per_row
            if row % 2 == 1:
                col = (cols_per_row - 1) - col
            x = 24 + col * (card_w + gap_x)
            y = 24 + row * (card_h + gap_y)
            centers.append(QPointF(x + card_w / 2, y + card_h / 2))

        # Draw connecting arrows first
        for i in range(len(centers) - 1):
            p1 = centers[i]
            p2 = centers[i + 1]
            pen = QPen(QColor("#38bdf8") if self.is_dark else QColor("#0969da"), 2.4, Qt.SolidLine)
            self.scene.addLine(p1.x(), p1.y(), p2.x(), p2.y(), pen)

        # Draw node cards
        for idx, n in enumerate(nodes):
            c_pt = centers[idx]
            x = c_pt.x() - card_w / 2
            y = c_pt.y() - card_h / 2
            rect = QRectF(x, y, card_w, card_h)

            path = QPainterPath()
            path.addRoundedRect(rect, 8, 8)
            card_bg = QColor("#1e293b") if self.is_dark else QColor("#ffffff")
            self.scene.addPath(path, QPen(n["color"], 2.0), QBrush(card_bg))

            # Header bar
            hdr_rect = QRectF(x, y, card_w, 22)
            hdr_path = QPainterPath()
            hdr_path.addRoundedRect(hdr_rect, 7, 7)
            self.scene.addPath(hdr_path, QPen(Qt.NoPen), QBrush(n["color"]))

            t_hdr = self.scene.addText(n["title"], QFont("Segoe UI", 8, QFont.Bold))
            t_hdr.setDefaultTextColor(QColor("#ffffff"))
            t_hdr.setPos(x + 6, y + 1)

            t_ip = self.scene.addText(n["ip"], QFont("Monospace", 9, QFont.Bold))
            t_ip.setDefaultTextColor(QColor("#f8fafc") if self.is_dark else QColor("#0f172a"))
            t_ip.setPos(x + 8, y + 25)

            t_rtt = self.scene.addText(f"⚡ {n['rtt']}", QFont("Segoe UI", 8, QFont.Bold))
            t_rtt.setDefaultTextColor(n["color"])
            t_rtt.setPos(x + 8, y + 46)

        self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-20, -20, 20, 20))

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(500)
        super().closeEvent(event)
