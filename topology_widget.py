#!/usr/bin/env python3
"""
Mapeamento Visual Interativo de Topologia de Rede para o IP Scan IGT.
Utiliza as tabelas de roteamento locais, o Gateway padrão e a classificação de ativos
para desenhar um grafo interativo (QGraphicsView / QGraphicsScene) ilustrando
como os nós da rede (Switches, Hipervisores, NVRs, Câmeras, Servidores e Estações)
estão interconectados em relação ao roteador principal.
"""
import base64
import math
import subprocess
from typing import Dict, List, Optional, Tuple

from PyQt5.QtCore import QBuffer, QIODevice, QPoint, QPointF, QRectF, Qt, pyqtSignal
from PyQt5.QtGui import (
    QBrush,
    QColor,
    QFont,
    QFontMetrics,
    QImage,
    QPainter,
    QPainterPath,
    QPen,
    QRadialGradient,
)
from PyQt5.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QGraphicsItem,
    QGraphicsObject,
    QGraphicsScene,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSlider,
    QVBoxLayout,
    QWidget,
)

from i18n import tr
from scanner_engine import IS_WINDOWS, HostRecord, _get_windows_silent_kwargs


def get_routing_table_summary() -> List[Dict[str, str]]:
    """
    Lê a tabela de roteamento local do sistema operacional (Linux `ip route` ou Windows `route print`)
    para enriquecer o mapa de topologia com sub-redes e gateways conhecidos.
    """
    routes: List[Dict[str, str]] = []
    if IS_WINDOWS:
        try:
            kwargs = _get_windows_silent_kwargs()
            out = subprocess.check_output(["route", "print", "-4"], text=True, timeout=2.0, **kwargs)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0][0].isdigit() and "." in parts[0]:
                    routes.append({
                        "destination": parts[0],
                        "netmask": parts[1],
                        "gateway": parts[2],
                        "interface": parts[3],
                    })
        except Exception:
            pass
        return routes[:12]

    try:
        out = subprocess.check_output(["ip", "-4", "route", "show"], text=True, timeout=1.5)
        for line in out.splitlines():
            parts = line.split()
            if not parts:
                continue
            dest = parts[0]
            gw = ""
            dev = ""
            if "via" in parts:
                idx = parts.index("via")
                if idx + 1 < len(parts):
                    gw = parts[idx + 1]
            if "dev" in parts:
                idx = parts.index("dev")
                if idx + 1 < len(parts):
                    dev = parts[idx + 1]
            routes.append({
                "destination": dest,
                "gateway": gw or "Direto (L2)",
                "interface": dev,
            })
    except Exception:
        pass
    return routes[:12]


class TopologyEdgeItem(QGraphicsItem):
    """Linha de conexão entre dois nós na topologia, colorida conforme latência e status."""

    def __init__(self, source_node: "TopologyNodeItem", dest_node: "TopologyNodeItem", is_dark: bool = False):
        super().__init__()
        self.source = source_node
        self.dest = dest_node
        self.is_dark = is_dark
        self.setZValue(-10)
        self.source.add_edge(self)
        self.dest.add_edge(self)
        self.adjust()

    def adjust(self):
        self.prepareGeometryChange()
        self.src_pt = self.source.pos()
        self.dst_pt = self.dest.pos()

    def boundingRect(self) -> QRectF:
        extra = 24.0
        x1, y1 = self.src_pt.x(), self.src_pt.y()
        x2, y2 = self.dst_pt.x(), self.dst_pt.y()
        return QRectF(
            min(x1, x2) - extra,
            min(y1, y2) - extra,
            abs(x2 - x1) + 2 * extra,
            abs(y2 - y1) + 2 * extra,
        )

    def paint(self, painter: QPainter, option, widget=None):
        if self.src_pt == self.dst_pt:
            return

        painter.setRenderHint(QPainter.Antialiasing)
        rec = self.dest.record

        # Determina cor e estilo do link pela saúde/latência do nó destino
        if not rec.alive:
            col = QColor("#64748b") if self.is_dark else QColor("#94a3b8")
            pen = QPen(col, 1.5, Qt.DashLine)
        elif rec.rtt_ms >= 0 and rec.rtt_ms < 5.0:
            col = QColor("#10b981") if self.is_dark else QColor("#059669")
            pen = QPen(col, 2.2, Qt.SolidLine)
        elif rec.rtt_ms >= 0 and rec.rtt_ms < 35.0:
            col = QColor("#38bdf8") if self.is_dark else QColor("#0284c7")
            pen = QPen(col, 1.8, Qt.SolidLine)
        else:
            col = QColor("#f59e0b") if self.is_dark else QColor("#d97706")
            pen = QPen(col, 1.8, Qt.SolidLine)

        painter.setPen(pen)

        # Curva suave ou linha direta
        path = QPainterPath(self.src_pt)
        path.lineTo(self.dst_pt)
        painter.drawPath(path)

        # Exibe badge discreto de latência próximo ao nó destino (evita colisão no centro do grafo)
        if rec.alive and rec.rtt_ms >= 0:
            badge_pt = self.src_pt * 0.28 + self.dst_pt * 0.72
            rtt_txt = f"{rec.rtt_ms:.1f}ms" if rec.rtt_ms < 10 else f"{rec.rtt_ms:.0f}ms"
            font = QFont("Segoe UI", 7, QFont.Bold)
            painter.setFont(font)
            bg_col = QColor(15, 23, 42, 210) if self.is_dark else QColor(226, 226, 226, 235)
            txt_col = QColor("#e2e8f0") if self.is_dark else QColor("#1e242b")
            rect = QRectF(badge_pt.x() - 22, badge_pt.y() - 8, 44, 16)
            painter.setPen(QPen(col, 1.0))
            painter.setBrush(QBrush(bg_col))
            painter.drawRoundedRect(rect, 4, 4)
            painter.setPen(txt_col)
            painter.drawText(rect, Qt.AlignCenter, rtt_txt)


class TopologyNodeItem(QGraphicsObject):
    """Nó interativo do grafo de topologia representando um dispositivo de rede."""

    clicked_ip = pyqtSignal(str)
    double_clicked_ip = pyqtSignal(str)
    context_menu_ip = pyqtSignal(str, QPoint)

    def __init__(
        self,
        record: HostRecord,
        role: str = "endpoint",   # "gateway" | "local" | "infra" | "endpoint"
        is_dark: bool = False,
    ):
        super().__init__()
        self.record = record
        self.role = role
        self.is_dark = is_dark
        self.edges: List[TopologyEdgeItem] = []
        self.radius = 32 if role == "gateway" else (26 if role in ("infra", "local") else 22)

        self.setFlags(
            QGraphicsItem.ItemIsMovable
            | QGraphicsItem.ItemIsSelectable
            | QGraphicsItem.ItemSendsGeometryChanges
        )
        self.setCacheMode(QGraphicsItem.DeviceCoordinateCache)
        self.setCursor(Qt.OpenHandCursor)
        self.setZValue(10 if role == "gateway" else (5 if role in ("infra", "local") else 2))

        # Tooltip rico com resumo técnico
        vulns_count = len(getattr(record, "vulnerabilities", []) or [])
        risk_line = f"\n⚠️ Risco de Segurança: {record.risk_level} ({vulns_count} CVEs)" if vulns_count > 0 else ""
        snmp_line = f"\n📊 SNMP: {record.snmp_info}" if record.snmp_info else ""
        alias_line = f"\n✏️ Apelido: {record.alias}" if getattr(record, "alias", "") else ""
        self.setToolTip(
            f"Host: {record.hostname or record.ip}"
            f"{alias_line}\n"
            f"IP: {record.ip}\n"
            f"MAC: {record.mac or 'N/D'} ({record.vendor or 'Desconhecido'})\n"
            f"Tipo: {record.device_type or 'Host'}\n"
            f"Ping: {record.format_ping()}"
            f"{snmp_line}"
            f"{risk_line}\n"
            f"(Arraste para mover • Duplo-clique para abrir • Botão direito para ações)"
        )

    def add_edge(self, edge: TopologyEdgeItem):
        if edge not in self.edges:
            self.edges.append(edge)

    def boundingRect(self) -> QRectF:
        r = self.radius
        return QRectF(-r - 65, -r - 18, (r + 65) * 2, (r + 42) * 2)

    def _get_node_icon(self) -> str:
        if self.role == "gateway":
            return "📡"
        if self.role == "local":
            return "💻"
        dtype = (self.record.device_type or "").lower()
        ports = self.record.open_ports or []
        if self.record.onvif_url or 554 in ports or "câmera" in dtype or "nvr" in dtype or "camera" in dtype:
            return "📹"
        if 9100 in ports or 631 in ports or "impressora" in dtype or "printer" in dtype:
            return "🖨️"
        if 8006 in ports or "proxmox" in dtype:
            return "🖥️"
        if "switch" in dtype or "roteador" in dtype or "router" in dtype or "access point" in dtype:
            return "🖧"
        if 5060 in ports or "voip" in dtype:
            return "📞"
        if 22 in ports or "linux" in dtype:
            return "🐧"
        if 445 in ports or 3389 in ports or "windows" in dtype:
            return "💻"
        return "🔌"

    def paint(self, painter: QPainter, option, widget=None):
        painter.setRenderHint(QPainter.Antialiasing)
        r = self.radius
        rec = self.record
        risk_lvl = getattr(rec, "risk_level", "NONE")
        vulns = getattr(rec, "vulnerabilities", []) or []

        # Cores base conforme função e risco CVE
        if risk_lvl in ("CRITICAL", "HIGH"):
            ring_col = QColor("#ef4444")
            fill_top = QColor("#450a0a") if self.is_dark else QColor("#fef2f2")
            fill_bot = QColor("#7f1d1d") if self.is_dark else QColor("#fee2e2")
        elif self.role == "gateway":
            ring_col = QColor("#8b5cf6") if self.is_dark else QColor("#7c3aed")
            fill_top = QColor("#2e1065") if self.is_dark else QColor("#f5f3ff")
            fill_bot = QColor("#4c1d95") if self.is_dark else QColor("#ede9fe")
        elif self.role == "local":
            ring_col = QColor("#38bdf8") if self.is_dark else QColor("#0284c7")
            fill_top = QColor("#0c4a6e") if self.is_dark else QColor("#f0f9ff")
            fill_bot = QColor("#075985") if self.is_dark else QColor("#e0f2fe")
        elif not rec.alive:
            ring_col = QColor("#64748b")
            fill_top = QColor("#1e293b") if self.is_dark else QColor("#f1f5f9")
            fill_bot = QColor("#0f172a") if self.is_dark else QColor("#e2e8f0")
        else:
            ring_col = QColor("#10b981") if self.is_dark else QColor("#059669")
            fill_top = QColor("#064e3b") if self.is_dark else QColor("#ecfdf5")
            fill_bot = QColor("#065f46") if self.is_dark else QColor("#d1fae5")

        # Halo externo se selecionado ou se for o Gateway
        if self.isSelected() or self.role == "gateway":
            halo_col = QColor(ring_col)
            halo_col.setAlpha(75 if self.isSelected() else 40)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(halo_col))
            painter.drawEllipse(QPointF(0, 0), r + 8, r + 8)

        # Círculo principal com gradiente
        grad = QRadialGradient(0, -r * 0.3, r * 1.3)
        grad.setColorAt(0, fill_top)
        grad.setColorAt(1, fill_bot)

        pen_w = 3.0 if (self.isSelected() or risk_lvl in ("CRITICAL", "HIGH")) else 2.2
        painter.setPen(QPen(ring_col, pen_w))
        painter.setBrush(QBrush(grad))
        painter.drawEllipse(QPointF(0, 0), r, r)

        # Ícone central
        icon_font = QFont("Segoe UI Emoji", int(r * 0.62))
        painter.setFont(icon_font)
        painter.setPen(QColor("#ffffff") if self.is_dark else QColor("#0f172a"))
        painter.drawText(QRectF(-r, -r, r * 2, r * 2), Qt.AlignCenter, self._get_node_icon())

        # Badge de Alerta CVE no canto superior direito do nó
        if vulns:
            badge_r = 9
            bx, by = r * 0.72, -r * 0.72
            painter.setPen(QPen(QColor("#ffffff"), 1.5))
            painter.setBrush(QBrush(QColor("#dc2626") if risk_lvl in ("CRITICAL", "HIGH") else QColor("#d97706")))
            painter.drawEllipse(QPointF(bx, by), badge_r, badge_r)
            b_font = QFont("Segoe UI", 7, QFont.Bold)
            painter.setFont(b_font)
            painter.setPen(QColor("#ffffff"))
            painter.drawText(
                QRectF(bx - badge_r, by - badge_r, badge_r * 2, badge_r * 2),
                Qt.AlignCenter,
                str(len(vulns)),
            )

        # Rótulo inferior: Apelido ou Nome curto + IP (sem truncamento incorreto)
        raw_name = getattr(rec, "alias", "") or rec.hostname or rec.vendor or "Host"
        if self.role == "gateway":
            raw_name = f"GW: {raw_name}"
        elif self.role == "local":
            raw_name = f"Local: {raw_name}"

        lbl_bg = QColor(15, 23, 42, 225) if self.is_dark else QColor(232, 232, 232, 242)
        lbl_border = QColor("#334155") if self.is_dark else QColor("#a8a8a8")
        lbl_rect = QRectF(-72, r + 5, 144, 32)

        painter.setPen(QPen(lbl_border, 1.0))
        painter.setBrush(QBrush(lbl_bg))
        painter.drawRoundedRect(lbl_rect, 5, 5)

        name_font = QFont("Segoe UI", 8, QFont.Bold)
        painter.setFont(name_font)
        fm_name = QFontMetrics(name_font)
        label_name = fm_name.elidedText(raw_name, Qt.ElideRight, 136)
        painter.setPen(QColor("#f8fafc") if self.is_dark else QColor("#0f172a"))
        painter.drawText(QRectF(-68, r + 6, 136, 15), Qt.AlignCenter, label_name)

        ip_font = QFont("Monospace", 7)
        painter.setFont(ip_font)
        painter.setPen(QColor("#38bdf8") if self.is_dark else QColor("#0969da"))
        painter.drawText(QRectF(-68, r + 20, 136, 14), Qt.AlignCenter, rec.ip)

    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionHasChanged:
            for edge in self.edges:
                edge.adjust()
        return super().itemChange(change, value)

    def mousePressEvent(self, event):
        self.setCursor(Qt.ClosedHandCursor)
        if event.button() == Qt.LeftButton:
            self.clicked_ip.emit(self.record.ip)
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        self.setCursor(Qt.OpenHandCursor)
        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.double_clicked_ip.emit(self.record.ip)
        super().mouseDoubleClickEvent(event)

    def contextMenuEvent(self, event):
        self.clicked_ip.emit(self.record.ip)
        self.context_menu_ip.emit(self.record.ip, event.screenPos())


class TopologyGraphicsView(QGraphicsView):
    """Canvas interativo com suporte a Zoom via roda do mouse e Pan via arraste."""

    def __init__(self, scene: QGraphicsScene, parent=None):
        super().__init__(scene, parent)
        self.setRenderHints(QPainter.Antialiasing | QPainter.SmoothPixmapTransform | QPainter.TextAntialiasing)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.AnchorViewCenter)
        self.setViewportUpdateMode(QGraphicsView.FullViewportUpdate)

    def wheelEvent(self, event):
        zoom_in = 1.15
        zoom_out = 1.0 / zoom_in
        if event.angleDelta().y() > 0:
            self.scale(zoom_in, zoom_in)
        else:
            self.scale(zoom_out, zoom_out)


class NetworkTopologyWidget(QWidget):
    """
    Aba completa de Mapeamento Visual de Topologia da Rede para o IP Scan IGT.
    """
    host_selected = pyqtSignal(str)
    host_double_clicked = pyqtSignal(str)
    host_context_menu = pyqtSignal(str, QPoint)

    def __init__(self, parent=None, is_dark: bool = False):
        super().__init__(parent)
        self.is_dark = is_dark
        self.records: Dict[str, HostRecord] = {}
        self.local_info: Dict[str, str] = {}
        self.node_items: Dict[str, TopologyNodeItem] = {}
        self.cached_routes: List[Dict[str, str]] = get_routing_table_summary()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        # Barra superior de controles do grafo
        ctrl_frame = QFrame()
        ctrl_frame.setObjectName("topologyToolbar")
        ctrl_layout = QHBoxLayout(ctrl_frame)
        ctrl_layout.setContentsMargins(8, 4, 8, 4)
        ctrl_layout.setSpacing(6)

        self.lbl_topo_info = QLabel("🗺️ Topologia: Gateway Padrão ➔ Ativos Descobertos")
        self.lbl_topo_info.setStyleSheet("font-weight: bold; font-size: 12px;")
        ctrl_layout.addWidget(self.lbl_topo_info)

        ctrl_layout.addStretch()

        self.lbl_layout_mode = QLabel(tr("topo_layout_lbl", "Layout:"))
        self.lbl_layout_mode.setStyleSheet("font-weight: 600;")
        ctrl_layout.addWidget(self.lbl_layout_mode)

        self.combo_layout = QComboBox()
        self.combo_layout.setFixedHeight(28)
        self.combo_layout.addItem(tr("topo_layout_radial", "🌟 Radial Concêntrico (NOC)"), "radial")
        self.combo_layout.addItem(tr("topo_layout_tiered", "🏛️ Hierárquico em Camadas"), "tiered")
        self.combo_layout.currentIndexChanged.connect(self.rebuild_topology)
        ctrl_layout.addWidget(self.combo_layout)

        self.combo_filter = QComboBox()
        self.combo_filter.setFixedHeight(28)
        self.combo_filter.addItem(tr("topo_filter_all", "🔍 Todos os Nós"), "all")
        self.combo_filter.addItem(tr("topo_filter_infra", "🖧 Infraestrutura & Servidores"), "infra")
        self.combo_filter.addItem(tr("topo_filter_cameras", "📹 Câmeras & NVRs (ONVIF)"), "cameras")
        self.combo_filter.addItem(tr("topo_filter_risk", "⚠️ Dispositivos com Risco (CVEs)"), "risk")
        self.combo_filter.currentIndexChanged.connect(self.rebuild_topology)
        ctrl_layout.addWidget(self.combo_filter)

        # Barra de ajuste de distância entre os equipamentos
        self.lbl_spacing = QLabel(f"↔️ {tr('topo_spacing_lbl', 'Distância:')}")
        self.lbl_spacing.setStyleSheet("font-weight: 600; margin-left: 4px;")
        ctrl_layout.addWidget(self.lbl_spacing)

        self.slider_spacing = QSlider(Qt.Horizontal)
        self.slider_spacing.setObjectName("sliderTopoSpacing")
        self.slider_spacing.setRange(50, 300)
        self.slider_spacing.setSingleStep(5)
        self.slider_spacing.setPageStep(15)
        self.slider_spacing.setValue(100)
        self.slider_spacing.setFixedWidth(125)
        self.slider_spacing.setFixedHeight(26)
        self.slider_spacing.setToolTip(
            tr(
                "topo_spacing_tip",
                "Ajustar a distância / espaçamento entre os equipamentos na topologia (50% a 300%)",
            )
        )
        self.slider_spacing.valueChanged.connect(self._on_spacing_changed)
        ctrl_layout.addWidget(self.slider_spacing)

        self.lbl_spacing_val = QLabel("100%")
        self.lbl_spacing_val.setMinimumWidth(42)
        self.lbl_spacing_val.setAlignment(Qt.AlignCenter)
        self.lbl_spacing_val.setStyleSheet("font-weight: bold; font-size: 11px; color: #0284c7;")
        self.lbl_spacing_val.setToolTip(
            tr("topo_spacing_reset_tip", "Clique em Reorganizar ou arraste a barra para ajustar o espaçamento")
        )
        ctrl_layout.addWidget(self.lbl_spacing_val)

        self.btn_zoom_in = QPushButton("➕")
        self.btn_zoom_in.setFixedSize(30, 28)
        self.btn_zoom_in.setToolTip(tr("topo_zoom_in", "Aproximar Zoom"))
        self.btn_zoom_in.clicked.connect(lambda: self.view.scale(1.2, 1.2))
        ctrl_layout.addWidget(self.btn_zoom_in)

        self.btn_zoom_out = QPushButton("➖")
        self.btn_zoom_out.setFixedSize(30, 28)
        self.btn_zoom_out.setToolTip(tr("topo_zoom_out", "Afastar Zoom"))
        self.btn_zoom_out.clicked.connect(lambda: self.view.scale(1 / 1.2, 1 / 1.2))
        ctrl_layout.addWidget(self.btn_zoom_out)

        self.btn_fit = QPushButton(f"🔲 {tr('topo_btn_fit', 'Ajustar')}")
        self.btn_fit.setFixedHeight(28)
        self.btn_fit.clicked.connect(self.fit_graph_in_view)
        ctrl_layout.addWidget(self.btn_fit)

        self.btn_rebuild = QPushButton(f"🔄 {tr('topo_btn_reorg', 'Reorganizar')}")
        self.btn_rebuild.setFixedHeight(28)
        self.btn_rebuild.clicked.connect(self.rebuild_topology)
        ctrl_layout.addWidget(self.btn_rebuild)

        self.btn_export_png = QPushButton(f"📷 {tr('topo_btn_export', 'Exportar PNG')}")
        self.btn_export_png.setFixedHeight(28)
        self.btn_export_png.clicked.connect(self.export_topology_png)
        ctrl_layout.addWidget(self.btn_export_png)

        layout.addWidget(ctrl_frame)

        # Canvas QGraphicsView
        self.scene = QGraphicsScene(self)
        self.view = TopologyGraphicsView(self.scene, self)
        layout.addWidget(self.view, 1)

        # Legenda inferior
        self.lbl_legend = QLabel(
            tr(
                "topo_legend",
                "🟣 Gateway Principal   •   🔵 Esta Máquina   •   🟢 Online (<5ms)   •   "
                "🔷 Latência Normal   •   🟠 Latência Alta   •   🔴 Risco CVE Detectado",
            )
        )
        self.lbl_legend.setAlignment(Qt.AlignCenter)
        self.lbl_legend.setStyleSheet("font-size: 11px; padding: 3px;")
        layout.addWidget(self.lbl_legend)

        self.apply_theme(self.is_dark)

    def _on_spacing_changed(self, val: int):
        if hasattr(self, "lbl_spacing_val"):
            self.lbl_spacing_val.setText(f"{val}%")
        self.rebuild_topology()

    def retranslate_ui(self):
        self.lbl_layout_mode.setText(tr("topo_layout_lbl", "Layout:"))
        self.lbl_spacing.setText(f"↔️ {tr('topo_spacing_lbl', 'Distância:')}")
        self.slider_spacing.setToolTip(
            tr(
                "topo_spacing_tip",
                "Ajustar a distância / espaçamento entre os equipamentos na topologia (50% a 300%)",
            )
        )
        self.combo_layout.blockSignals(True)
        self.combo_layout.setItemText(0, tr("topo_layout_radial", "🌟 Radial Concêntrico (NOC)"))
        self.combo_layout.setItemText(1, tr("topo_layout_tiered", "🏛️ Hierárquico em Camadas"))
        self.combo_layout.blockSignals(False)

        self.combo_filter.blockSignals(True)
        self.combo_filter.setItemText(0, tr("topo_filter_all", "🔍 Todos os Nós"))
        self.combo_filter.setItemText(1, tr("topo_filter_infra", "🖧 Infraestrutura & Servidores"))
        self.combo_filter.setItemText(2, tr("topo_filter_cameras", "📹 Câmeras & NVRs (ONVIF)"))
        self.combo_filter.setItemText(3, tr("topo_filter_risk", "⚠️ Dispositivos com Risco (CVEs)"))
        self.combo_filter.blockSignals(False)

        self.btn_zoom_in.setToolTip(tr("topo_zoom_in", "Aproximar Zoom"))
        self.btn_zoom_out.setToolTip(tr("topo_zoom_out", "Afastar Zoom"))
        self.btn_fit.setText(f"🔲 {tr('topo_btn_fit', 'Ajustar')}")
        self.btn_rebuild.setText(f"🔄 {tr('topo_btn_reorg', 'Reorganizar')}")
        self.btn_export_png.setText(f"📷 {tr('topo_btn_export', 'Exportar PNG')}")
        self.lbl_legend.setText(
            tr(
                "topo_legend",
                "🟣 Gateway Principal   •   🔵 Esta Máquina   •   🟢 Online (<5ms)   •   "
                "🔷 Latência Normal   •   🟠 Latência Alta   •   🔴 Risco CVE Detectado",
            )
        )
        self.rebuild_topology()

    def apply_theme(self, is_dark: bool):
        self.is_dark = is_dark
        bg_col = QColor("#0f172a") if is_dark else QColor("#dcdcdc")
        self.scene.setBackgroundBrush(QBrush(bg_col))
        border_col = "#334155" if is_dark else "#a8a8a8"
        self.view.setStyleSheet(f"QGraphicsView {{ border: 1px solid {border_col}; border-radius: 6px; }}")
        if hasattr(self, "lbl_spacing_val"):
            val_col = "#38bdf8" if is_dark else "#0284c7"
            self.lbl_spacing_val.setStyleSheet(f"font-weight: bold; font-size: 11px; color: {val_col};")
        self.rebuild_topology()

    def set_network_data(self, records: Dict[str, HostRecord], local_info: Dict[str, str]):
        self.records = dict(records)
        self.local_info = dict(local_info or {})
        self.cached_routes = get_routing_table_summary()
        self.rebuild_topology()

    def _classify_node_tier(self, rec: HostRecord, gw_ip: str, local_ip: str) -> str:
        if rec.ip == gw_ip:
            return "gateway"
        if rec.ip == local_ip:
            return "local"
        dtype = (rec.device_type or "").lower()
        ports = rec.open_ports or []
        if (
            8006 in ports
            or 2443 in ports
            or "switch" in dtype
            or "roteador" in dtype
            or "router" in dtype
            or "access point" in dtype
            or "proxmox" in dtype
            or "nvr" in dtype
            or bool(rec.snmp_info and ("switch" in rec.snmp_info.lower() or "router" in rec.snmp_info.lower()))
        ):
            return "infra"
        return "endpoint"

    def _matches_filter(self, rec: HostRecord, role: str, flt: str) -> bool:
        if role in ("gateway", "local"):
            return True
        if flt == "all":
            return True
        if flt == "infra":
            return role == "infra" or 22 in rec.open_ports or 445 in rec.open_ports or 3389 in rec.open_ports
        if flt == "cameras":
            return bool(rec.onvif_url or rec.rtsp_url or 554 in rec.open_ports or 8899 in rec.open_ports or 2443 in rec.open_ports)
        if flt == "risk":
            return bool(getattr(rec, "vulnerabilities", None))
        return True

    def rebuild_topology(self):
        self.scene.clear()
        self.node_items.clear()

        gw_ip = self.local_info.get("gateway", "") or "192.168.1.1"
        local_ip = self.local_info.get("ip", "")
        iface_name = self.local_info.get("name", "LAN")
        cidr = self.local_info.get("cidr", "24")
        routes = self.cached_routes

        # Fator multiplicador de distância/espaçamento controlado pela barra (0.5x a 3.0x)
        scale = (self.slider_spacing.value() / 100.0) if hasattr(self, "slider_spacing") else 1.0

        # Garante que o Gateway exista como nó central mesmo se ainda não escaneado
        all_records = dict(self.records)
        if gw_ip and gw_ip not in all_records:
            all_records[gw_ip] = HostRecord(
                ip=gw_ip,
                alive=True,
                rtt_ms=1.0,
                hostname="Gateway Padrão",
                device_type="📡 Gateway / Roteador",
            )

        flt = self.combo_filter.currentData() or "all"
        layout_mode = self.combo_layout.currentData() or "radial"

        gw_rec = all_records[gw_ip]
        infra_recs: List[HostRecord] = []
        endpoint_recs: List[HostRecord] = []

        for ip, rec in sorted(all_records.items(), key=lambda kv: kv[1].ip_sort_key()):
            if ip == gw_ip:
                continue
            role = self._classify_node_tier(rec, gw_ip, local_ip)
            if not self._matches_filter(rec, role, flt):
                continue
            if role in ("infra", "local"):
                infra_recs.append(rec)
            else:
                endpoint_recs.append(rec)

        total_shown = 1 + len(infra_recs) + len(endpoint_recs)
        risk_count = sum(1 for r in all_records.values() if getattr(r, "vulnerabilities", None))
        self.lbl_topo_info.setText(
            f"🗺️ Sub-rede: {local_ip}/{cidr} ({iface_name})  •  Gateway: {gw_ip}  •  "
            f"Nós: {total_shown}  •  Rotas: {len(routes)}  •  Em Risco (CVE): {risk_count}"
        )

        n_infra = len(infra_recs)
        n_end = len(endpoint_recs)

        # Cálculo adaptativo de raios e anéis concêntricos no modo radial para evitar sobreposição
        min_arc_infra = 200.0 * scale
        min_arc_end = 195.0 * scale
        r_infra_base = max(250.0 * scale, (n_infra * min_arc_infra) / (2.0 * math.pi)) if n_infra > 0 else 210.0 * scale

        endpoint_rings: List[Tuple[float, List[HostRecord]]] = []
        if layout_mode == "radial" and n_end > 0:
            rem = list(endpoint_recs)
            r_curr = (r_infra_base + 230.0 * scale) if n_infra > 0 else (280.0 * scale)
            ring_gap = 215.0 * scale
            while rem:
                # Capacidade de nós na circunferência garantindo folga horizontal/vertical para os rótulos
                cap = max(8, int((2.0 * math.pi * max(1.0, r_curr)) / max(90.0, min_arc_end)))
                chunk = rem[:cap]
                rem = rem[cap:]
                endpoint_rings.append((r_curr, chunk))
                r_curr += ring_gap

        # Desenha guias visuais de anéis no modo radial sincronizadas com os raios reais
        if layout_mode == "radial":
            ring_pen = QPen(QColor("#1e293b") if self.is_dark else QColor("#bdbdbd"), 1.2, Qt.DotLine)
            guide_radii = []
            if n_infra > 0:
                guide_radii.append(r_infra_base)
            for r_ring, _ in endpoint_rings:
                guide_radii.append(r_ring)
            if not guide_radii:
                guide_radii = [250.0 * scale, 480.0 * scale]
            for radius in guide_radii:
                self.scene.addEllipse(-radius, -radius, radius * 2, radius * 2, ring_pen)

        # 1. Cria Nó Central do Gateway
        gw_node = TopologyNodeItem(gw_rec, role="gateway", is_dark=self.is_dark)
        gw_node.setPos(0, 0 if layout_mode == "radial" else (-260.0 * scale))
        self._connect_node_signals(gw_node)
        self.scene.addItem(gw_node)
        self.node_items[gw_rec.ip] = gw_node

        # Identifica nós agregadores (Proxmox Hypervisor, NVR, Switch) para conectar filhos lógicos
        proxmox_node: Optional[TopologyNodeItem] = None
        nvr_node: Optional[TopologyNodeItem] = None
        switch_node: Optional[TopologyNodeItem] = None

        # 2. Posiciona Nós de Infraestrutura + Máquina Local
        infra_cols = max(1, min(6, n_infra))
        for idx, rec in enumerate(infra_recs):
            role = "local" if rec.ip == local_ip else "infra"
            node = TopologyNodeItem(rec, role=role, is_dark=self.is_dark)
            if layout_mode == "radial":
                angle = (2.0 * math.pi * idx) / max(1, n_infra) - (math.pi / 2.0)
                stagger = (idx % 2) * (36.0 * scale) if n_infra >= 6 else 0.0
                r_dist = r_infra_base + stagger
                node.setPos(r_dist * math.cos(angle), r_dist * math.sin(angle))
            else:
                row = idx // infra_cols
                col = idx % infra_cols
                row_count = min(infra_cols, n_infra - row * infra_cols)
                x_offset = (col - (row_count - 1) / 2.0) * (210.0 * scale)
                y_offset = (-55.0 + row * 155.0) * scale
                node.setPos(x_offset, y_offset)

            self._connect_node_signals(node)
            self.scene.addItem(node)
            self.node_items[rec.ip] = node

            edge = TopologyEdgeItem(gw_node, node, is_dark=self.is_dark)
            self.scene.addItem(edge)

            dtype_low = (rec.device_type or "").lower()
            if 8006 in rec.open_ports or "proxmox" in dtype_low:
                proxmox_node = node
            elif "nvr" in dtype_low or 2443 in rec.open_ports:
                nvr_node = node
            elif "switch" in dtype_low or "access point" in dtype_low:
                switch_node = node

        # 3. Posiciona Nós de Endpoints (Estações, Servidores, Câmeras, Impressoras)
        if layout_mode == "radial":
            for ring_idx, (r_ring, ring_nodes) in enumerate(endpoint_rings):
                m = len(ring_nodes)
                angle_offset = ring_idx * (math.pi / max(8, m))
                for i_in_ring, rec in enumerate(ring_nodes):
                    node = TopologyNodeItem(rec, role="endpoint", is_dark=self.is_dark)
                    angle = (2.0 * math.pi * i_in_ring) / max(1, m) + angle_offset
                    stagger = (i_in_ring % 2) * (34.0 * scale) if m >= 10 else 0.0
                    r_dist = r_ring + stagger
                    node.setPos(r_dist * math.cos(angle), r_dist * math.sin(angle))

                    self._connect_node_signals(node)
                    self.scene.addItem(node)
                    self.node_items[rec.ip] = node

                    parent_node = self._resolve_parent_node(rec, gw_node, proxmox_node, nvr_node, switch_node)
                    edge = TopologyEdgeItem(parent_node, node, is_dark=self.is_dark)
                    self.scene.addItem(edge)
        else:
            infra_rows = max(1, math.ceil(n_infra / max(1, infra_cols))) if n_infra > 0 else 0
            y_base_end = (-55.0 + infra_rows * 175.0) * scale if infra_rows > 0 else (120.0 * scale)
            cols = max(1, min(7, n_end))
            for idx, rec in enumerate(endpoint_recs):
                node = TopologyNodeItem(rec, role="endpoint", is_dark=self.is_dark)
                row = idx // cols
                col = idx % cols
                row_count = min(cols, n_end - row * cols)
                x_offset = (col - (row_count - 1) / 2.0) * (205.0 * scale)
                y_offset = y_base_end + row * (165.0 * scale)
                node.setPos(x_offset, y_offset)

                self._connect_node_signals(node)
                self.scene.addItem(node)
                self.node_items[rec.ip] = node

                parent_node = self._resolve_parent_node(rec, gw_node, proxmox_node, nvr_node, switch_node)
                edge = TopologyEdgeItem(parent_node, node, is_dark=self.is_dark)
                self.scene.addItem(edge)

        self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-90, -90, 90, 90))

    def _resolve_parent_node(
        self,
        rec: HostRecord,
        gw_node: TopologyNodeItem,
        proxmox_node: Optional[TopologyNodeItem],
        nvr_node: Optional[TopologyNodeItem],
        switch_node: Optional[TopologyNodeItem],
    ) -> TopologyNodeItem:
        parent_node = gw_node
        v_low = (rec.vendor or "").lower()
        dtype_low = (rec.device_type or "").lower()
        if proxmox_node and ("proxmox" in v_low or "qemu" in v_low or "vm " in dtype_low):
            parent_node = proxmox_node
        elif nvr_node and (rec.onvif_url or 554 in rec.open_ports or "câmera" in dtype_low or "camera" in dtype_low):
            parent_node = nvr_node
        elif switch_node:
            parent_node = switch_node
        return parent_node

    def _connect_node_signals(self, node: TopologyNodeItem):
        node.clicked_ip.connect(self.host_selected.emit)
        node.double_clicked_ip.connect(self.host_double_clicked.emit)
        node.context_menu_ip.connect(self.host_context_menu.emit)

    def fit_graph_in_view(self):
        rect = self.scene.itemsBoundingRect().adjusted(-60, -60, 60, 60)
        if not rect.isEmpty():
            self.view.fitInView(rect, Qt.KeepAspectRatio)

    def export_topology_png(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Exportar Mapa de Topologia",
            "topologia_rede_igt.png",
            "Imagem PNG (*.png)",
        )
        if not path:
            return
        try:
            rect = self.scene.itemsBoundingRect().adjusted(-60, -60, 60, 60)
            img = QImage(max(800, int(rect.width())), max(600, int(rect.height())), QImage.Format_ARGB32)
            img.fill(QColor("#0f172a") if self.is_dark else QColor("#dcdcdc"))
            painter = QPainter(img)
            painter.setRenderHint(QPainter.Antialiasing)
            self.scene.render(painter, QRectF(img.rect()), rect)
            painter.end()
            img.save(path)
            QMessageBox.information(self, "Sucesso", f"Mapa de topologia salvo com sucesso em:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Erro ao Exportar", str(e))

    def render_to_base64_png(self) -> str:
        """Renderiza o grafo de topologia atual como uma imagem PNG codificada em Base64."""
        try:
            rect = self.scene.itemsBoundingRect().adjusted(-50, -50, 50, 50)
            if rect.isEmpty():
                return ""
            w = max(840, min(1600, int(rect.width())))
            h = max(480, min(1100, int(rect.height())))
            img = QImage(w, h, QImage.Format_ARGB32)
            img.fill(QColor("#0f172a") if self.is_dark else QColor("#dcdcdc"))
            painter = QPainter(img)
            painter.setRenderHint(QPainter.Antialiasing)
            self.scene.render(painter, QRectF(img.rect()), rect, Qt.KeepAspectRatio)
            painter.end()

            buf = QBuffer()
            buf.open(QIODevice.WriteOnly)
            img.save(buf, "PNG")
            raw_bytes = bytes(buf.data())
            buf.close()
            return base64.b64encode(raw_bytes).decode("ascii")
        except Exception:
            return ""

