#!/usr/bin/env python3
"""
Componente Gráfico de Visualização do Painel Frontal de um Switch Gerenciável (1U Rackmount).
Renderiza com precisão milimétrica a carcaça de 19 polegadas, aletas de rack,
matriz de portas RJ45 (8, 16, 24 ou 48 portas), slots de uplink SFP/SFP+,
LEDs de link/atividade e destaca com animação pulsante e conector inserido
a porta física exata em que o computador está conectado.
"""
import math
from typing import Dict, Optional, Tuple

from PyQt5.QtCore import QPointF, QRectF, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import (
    QBrush,
    QColor,
    QFont,
    QFontMetrics,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QRadialGradient,
)
from PyQt5.QtWidgets import QSizePolicy, QToolTip, QWidget


class SwitchFrontPanelWidget(QWidget):
    """
    Widget visual customizado que desenha o painel frontal de um switch de rede.
    """
    port_clicked = pyqtSignal(int)
    port_hovered = pyqtSignal(int)

    def __init__(self, parent=None, is_dark: bool = True):
        super().__init__(parent)
        self.is_dark = is_dark
        self.total_ports = 24
        self.connected_port = 0
        self.connected_port_name = ""
        self.switch_brand = "CISCO"
        self.switch_model = "Catalyst 2960X-24TD-L"
        self.port_status_map: Dict[int, str] = {}  # {port: "connected"|"up"|"down"}
        self.hovered_port = 0
        self.selected_port = 0

        # Controle de animação de pulso para a porta conectada
        self._pulse_phase = 0.0
        self._pulse_timer = QTimer(self)
        self._pulse_timer.timeout.connect(self._on_pulse_tick)
        self._pulse_timer.start(50)  # ~20 FPS suave

        # Mapeamento de retângulos das portas para cliques e hover
        self._port_rects: Dict[int, QRectF] = {}

        self.setMouseTracking(True)
        self.setMinimumSize(780, 230)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

    def _on_pulse_tick(self):
        if self.connected_port > 0:
            self._pulse_phase = (self._pulse_phase + 0.08) % (2 * math.pi)
            self.update()

    def set_switch_data(
        self,
        total_ports: int,
        connected_port: int = 0,
        connected_port_name: str = "",
        switch_brand: str = "",
        switch_model: str = "",
        port_status_map: Optional[Dict[int, str]] = None,
    ):
        """Atualiza todas as informações do switch e redesenha o painel."""
        if total_ports in [8, 16, 24, 48]:
            self.total_ports = total_ports
        elif total_ports > 24:
            self.total_ports = 48
        elif total_ports > 16:
            self.total_ports = 24
        elif total_ports > 8:
            self.total_ports = 16
        else:
            self.total_ports = 8

        self.connected_port = connected_port
        self.connected_port_name = connected_port_name
        if switch_brand:
            self.switch_brand = switch_brand.upper()
        if switch_model:
            self.switch_model = switch_model
        if port_status_map is not None:
            self.port_status_map = port_status_map.copy()
        if self.connected_port > 0:
            self.port_status_map[self.connected_port] = "connected"
            self.selected_port = self.connected_port

        self.update()

    def set_connected_port(self, port_num: int, port_name: str = ""):
        self.connected_port = port_num
        if port_name:
            self.connected_port_name = port_name
        if port_num > 0:
            self.port_status_map[port_num] = "connected"
            self.selected_port = port_num
        self.update()

    def set_total_ports(self, total: int):
        if total in [8, 16, 24, 48]:
            self.total_ports = total
            self.update()

    def mouseMoveEvent(self, event):
        pos = event.pos()
        found_port = 0
        for port_num, rect in self._port_rects.items():
            if rect.contains(pos.x(), pos.y()):
                found_port = port_num
                break

        if found_port != self.hovered_port:
            self.hovered_port = found_port
            self.port_hovered.emit(found_port)
            if found_port > 0:
                st = self.port_status_map.get(found_port, "down")
                tip = f"<b>Porta {found_port}</b>"
                if found_port == self.connected_port:
                    tip += f"<br/><span style='color:#00e5ff;'><b>📍 SUA CONEXÃO LOCAL ATIVA</b></span>"
                    if self.connected_port_name:
                        tip += f"<br/>ID: {self.connected_port_name}"
                elif st == "up":
                    tip += "<br/><span style='color:#10b981;'>● Link Ativo (Conectado)</span>"
                else:
                    tip += "<br/><span style='color:#9ca3af;'>○ Sem Link (Desconectado)</span>"
                QToolTip.showText(event.globalPos(), tip, self)
            else:
                QToolTip.hideText()
            self.update()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            pos = event.pos()
            for port_num, rect in self._port_rects.items():
                if rect.contains(pos.x(), pos.y()):
                    self.selected_port = port_num
                    self.port_clicked.emit(port_num)
                    self.update()
                    break

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setRenderHint(QPainter.TextAntialiasing)

        w = self.width()
        h = self.height()

        # Fundo do widget
        bg_col = QColor("#080b11") if self.is_dark else QColor("#e5e7eb")
        painter.fillRect(0, 0, w, h, bg_col)

        # Dimensões da carcaça do switch (Chassis 19" 1U)
        margin_x = 12
        margin_top = 28  # Espaço para o badge de chamada da porta conectada
        margin_bottom = 26 # Espaço para o cabo RJ45 saindo da porta
        switch_h = max(130.0, min(160.0, h - margin_top - margin_bottom))
        switch_w = w - (margin_x * 2)
        switch_y = margin_top

        # 1. Desenha as orelhas de montagem em Rack 19" (Rack Ears)
        ear_width = 30.0
        self._draw_rack_ear(painter, margin_x, switch_y, ear_width, switch_h, is_left=True)
        self._draw_rack_ear(painter, margin_x + switch_w - ear_width, switch_y, ear_width, switch_h, is_left=False)

        # 2. Desenha o chassi principal metálico
        chassis_x = margin_x + ear_width
        chassis_w = switch_w - (ear_width * 2)
        chassis_rect = QRectF(chassis_x, switch_y, chassis_w, switch_h)
        self._draw_switch_chassis(painter, chassis_rect)

        # 3. Painel esquerdo: Logotipo da marca, modelo, LEDs de sistema e ventilação
        left_panel_w = max(130.0, min(175.0, chassis_w * 0.18))
        left_rect = QRectF(chassis_x + 6, switch_y + 6, left_panel_w, switch_h - 12)
        self._draw_left_branding_panel(painter, left_rect)

        # 4. Painel direito: Cages de Uplink SFP / SFP+
        num_sfp = 4 if self.total_ports >= 48 else 2
        sfp_panel_w = max(75.0, min(100.0, chassis_w * 0.11))
        sfp_rect = QRectF(chassis_x + chassis_w - sfp_panel_w - 6, switch_y + 6, sfp_panel_w, switch_h - 12)
        self._draw_sfp_uplinks(painter, sfp_rect, num_sfp)

        # 5. Painel central: Matriz de portas RJ45 (8, 16, 24 ou 48 portas)
        matrix_x = chassis_x + left_panel_w + 10
        matrix_w = chassis_w - left_panel_w - sfp_panel_w - 24
        matrix_rect = QRectF(matrix_x, switch_y + 6, matrix_w, switch_h - 12)
        self._draw_rj45_matrix(painter, matrix_rect)

        # 6. Desenha o conector de cabo RJ45 e o Badge "📍 SUA PORTA" se houver porta conectada
        if self.connected_port > 0 and self.connected_port in self._port_rects:
            self._draw_connected_cable_and_badge(painter, self.connected_port, switch_y, switch_h)

    def _draw_rack_ear(self, painter: QPainter, x: float, y: float, w: float, h: float, is_left: bool):
        """Desenha as abas metálicas de fixação do switch no rack com parafusos."""
        ear_rect = QRectF(x, y, w, h)
        grad = QLinearGradient(x, y, x + w, y)
        if is_left:
            grad.setColorAt(0.0, QColor("#1e232d"))
            grad.setColorAt(0.7, QColor("#2b3240"))
            grad.setColorAt(1.0, QColor("#1f242e"))
        else:
            grad.setColorAt(0.0, QColor("#1f242e"))
            grad.setColorAt(0.3, QColor("#2b3240"))
            grad.setColorAt(1.0, QColor("#1e232d"))

        painter.setBrush(QBrush(grad))
        painter.setPen(QPen(QColor("#3d4659"), 1.2))
        painter.drawRoundedRect(ear_rect, 3, 3)

        # Furos ovais do rack com parafusos
        screw_r = 4.5
        screw_y1 = y + 16
        screw_y2 = y + h - 16
        screw_x = x + (w / 2.0)

        for sy in [screw_y1, screw_y2]:
            # Furo oval do rack
            painter.setBrush(QBrush(QColor("#0d1017")))
            painter.setPen(QPen(QColor("#4b5563"), 1.0))
            painter.drawEllipse(QPointF(screw_x, sy), screw_r + 1.5, screw_r)

            # Parafuso sextavado zincado
            p_grad = QRadialGradient(screw_x, sy, screw_r)
            p_grad.setColorAt(0.0, QColor("#cbd5e1"))
            p_grad.setColorAt(0.7, QColor("#64748b"))
            p_grad.setColorAt(1.0, QColor("#334155"))
            painter.setBrush(QBrush(p_grad))
            painter.drawEllipse(QPointF(screw_x, sy), screw_r - 0.5, screw_r - 0.5)

            # Fenda do parafuso
            painter.setPen(QPen(QColor("#1e293b"), 1.2))
            painter.drawLine(QPointF(screw_x - 2.5, sy), QPointF(screw_x + 2.5, sy))

    def _draw_switch_chassis(self, painter: QPainter, rect: QRectF):
        """Desenha o chassi metálico em alumínio escuro anodizado."""
        grad = QLinearGradient(rect.left(), rect.top(), rect.left(), rect.bottom())
        grad.setColorAt(0.0, QColor("#1a202c"))
        grad.setColorAt(0.08, QColor("#222a3a"))
        grad.setColorAt(0.5, QColor("#1e2533"))
        grad.setColorAt(0.92, QColor("#191f2b"))
        grad.setColorAt(1.0, QColor("#11151e"))

        painter.setBrush(QBrush(grad))
        painter.setPen(QPen(QColor("#3b4457"), 1.2))
        painter.drawRect(rect)

        # Linha de chanfro superior (borda metálica refletiva)
        painter.setPen(QPen(QColor("#4f5d75"), 1.0))
        painter.drawLine(QPointF(rect.left(), rect.top() + 1), QPointF(rect.right(), rect.top() + 1))

        # Linha de chanfro inferior (sombra de profundidade)
        painter.setPen(QPen(QColor("#0a0d13"), 1.5))
        painter.drawLine(QPointF(rect.left(), rect.bottom() - 1), QPointF(rect.right(), rect.bottom() - 1))

    def _draw_left_branding_panel(self, painter: QPainter, rect: QRectF):
        """Desenha o logotipo, modelo do switch, LEDs de sistema (PWR, SYS, PoE) e grade de resfriamento."""
        # Moldura interna sutil
        painter.setBrush(QBrush(QColor("#141822")))
        painter.setPen(QPen(QColor("#272f3f"), 1.0))
        painter.drawRoundedRect(rect, 4, 4)

        x = rect.left() + 8
        y = rect.top() + 14

        # 1. Marca / Logo (CISCO, UBIQUITI, MIKROTIK, ARUBA, etc.)
        painter.setFont(QFont("Segoe UI", 9, QFont.Bold))
        painter.setPen(QPen(QColor("#f8fafc")))
        brand_text = self.switch_brand or "SWITCH GERENCIÁVEL"
        if len(brand_text) > 16:
            brand_text = brand_text[:14] + ".."
        painter.drawText(int(x), int(y), brand_text)

        # 2. Modelo do Switch
        y += 14
        painter.setFont(QFont("Segoe UI", 7, QFont.Normal))
        painter.setPen(QPen(QColor("#94a3b8")))
        model_text = self.switch_model or f"{self.total_ports}-Port Gigabit Switch"
        if len(model_text) > 22:
            model_text = model_text[:20] + ".."
        painter.drawText(int(x), int(y), model_text)

        # 3. LEDs de Diagnóstico (PWR, SYS, PoE, ACT)
        y += 18
        leds = [
            ("PWR", QColor("#10b981")),  # Verde sólido
            ("SYS", QColor("#10b981")),  # Verde sólido
            ("PoE", QColor("#f59e0b")),  # Âmbar
            ("ACT", QColor("#38bdf8")),  # Azul ciano
        ]

        led_spacing = (rect.width() - 16) / len(leds)
        for i, (label, color) in enumerate(leds):
            lx = x + (i * led_spacing) + 4
            ly = y + 4

            # Brilho radial suave do LED
            r_glow = QRadialGradient(lx, ly, 7)
            r_glow.setColorAt(0.0, color)
            r_glow.setColorAt(0.4, QColor(color.red(), color.green(), color.blue(), 180))
            r_glow.setColorAt(1.0, QColor(color.red(), color.green(), color.blue(), 0))
            painter.setBrush(QBrush(r_glow))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(QPointF(lx, ly), 6, 6)

            # Núcleo do LED
            painter.setBrush(QBrush(color.lighter(130)))
            painter.drawEllipse(QPointF(lx, ly), 2.2, 2.2)

            # Rótulo do LED
            painter.setFont(QFont("Segoe UI", 6, QFont.Bold))
            painter.setPen(QPen(QColor("#64748b")))
            painter.drawText(int(lx - 8), int(ly + 12), label)

        # 4. Aletas de Ventilação / Grade de Resfriamento
        vent_y = y + 26
        vent_h = max(10.0, rect.bottom() - vent_y - 6)
        painter.setPen(QPen(QColor("#0f131a"), 1.2))
        for vy in range(int(vent_y), int(vent_y + vent_h), 4):
            painter.drawLine(int(x), vy, int(rect.right() - 8), vy)

    def _draw_sfp_uplinks(self, painter: QPainter, rect: QRectF, num_sfp: int):
        """Desenha os módulos de Uplink em Fibra Óptica (SFP/SFP+)."""
        painter.setBrush(QBrush(QColor("#141822")))
        painter.setPen(QPen(QColor("#272f3f"), 1.0))
        painter.drawRoundedRect(rect, 4, 4)

        # Título "SFP UPLINK"
        painter.setFont(QFont("Segoe UI", 6, QFont.Bold))
        painter.setPen(QPen(QColor("#64748b")))
        painter.drawText(int(rect.left() + 6), int(rect.top() + 12), "SFP+ UPLINK")

        cage_w = 18.0
        cage_h = 24.0
        start_y = rect.top() + 18
        spacing_y = 30.0

        for i in range(min(num_sfp, 4)):
            # Organiza em 1 coluna ou 2 colunas
            if num_sfp <= 2:
                cx = rect.left() + (rect.width() - cage_w) / 2.0
                cy = start_y + (i * spacing_y)
            else:
                col = i % 2
                row = i // 2
                cx = rect.left() + 8 + (col * (cage_w + 10))
                cy = start_y + (row * spacing_y)

            cage_rect = QRectF(cx, cy, cage_w, cage_h)

            # Blindagem do cage SFP
            painter.setBrush(QBrush(QColor("#0d1117")))
            painter.setPen(QPen(QColor("#475569"), 1.0))
            painter.drawRect(cage_rect)

            # Trava metálica do transceiver óptico
            painter.setBrush(QBrush(QColor("#334155")))
            painter.setPen(QPen(QColor("#64748b"), 0.8))
            painter.drawRect(QRectF(cx + 2, cy + 2, cage_w - 4, 6))

            # Conector duplex LC interno
            painter.setBrush(QBrush(QColor("#1e293b")))
            painter.drawRect(QRectF(cx + 3, cy + 10, cage_w - 6, cage_h - 13))

            # LED indicador SFP (Porta 25/26 ou 49/50)
            led_x = cx + (cage_w / 2.0)
            led_y = cy + cage_h + 4
            sfp_port_num = self.total_ports + i + 1

            sfp_active = self.port_status_map.get(sfp_port_num, "up") == "up"
            led_col = QColor("#10b981") if sfp_active else QColor("#334155")
            painter.setBrush(QBrush(led_col))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(QPointF(led_x, led_y), 2.0, 2.0)

    def _draw_rj45_matrix(self, painter: QPainter, rect: QRectF):
        """
        Desenha a matriz principal de portas RJ45 organizadas em blocos industriais de 8 portas,
        com numeração dupla (ímpares em cima: 1, 3, 5... e pares embaixo: 2, 4, 6...).
        """
        self._port_rects.clear()

        # Moldura metálica escovada do bloco de portas
        painter.setBrush(QBrush(QColor("#131720")))
        painter.setPen(QPen(QColor("#242c3b"), 1.2))
        painter.drawRoundedRect(rect, 4, 4)

        ports = self.total_ports
        columns = ports // 2  # Ex: 24 portas = 12 colunas de 2 portas cada
        block_size = 8 if ports >= 16 else 4
        num_blocks = math.ceil(ports / block_size)

        available_w = rect.width() - 16
        block_gap = 10.0 if num_blocks > 1 else 0.0
        total_gaps = (num_blocks - 1) * block_gap
        w_for_blocks = available_w - total_gaps

        # Largura de cada porta RJ45 e altura
        port_w = max(18.0, min(28.0, (w_for_blocks / columns) - 3.0))
        port_h = max(24.0, min(34.0, (rect.height() - 40) / 2.0))

        start_x = rect.left() + 8
        center_y = rect.center().y()
        top_row_y = center_y - port_h - 4
        bottom_row_y = center_y + 4

        curr_x = start_x

        for b in range(num_blocks):
            ports_in_this_block = min(block_size, ports - (b * block_size))
            cols_in_block = ports_in_this_block // 2

            # Fundo decorativo do bloco de portas (módulo de 8 portas)
            b_w = (cols_in_block * (port_w + 3.0)) + 4.0
            block_rect = QRectF(curr_x - 2, rect.top() + 4, b_w, rect.height() - 8)
            painter.setBrush(QBrush(QColor("#161b26")))
            painter.setPen(QPen(QColor("#2a3346"), 0.8))
            painter.drawRoundedRect(block_rect, 3, 3)

            for c in range(cols_in_block):
                # Porta ímpar (linha de cima)
                port_odd = (b * block_size) + (c * 2) + 1
                # Porta par (linha de baixo)
                port_even = port_odd + 1

                px = curr_x + (c * (port_w + 3.0)) + 2.0

                # Desenha porta ÍMPAR (Superior)
                odd_rect = QRectF(px, top_row_y, port_w, port_h)
                self._port_rects[port_odd] = odd_rect
                self._draw_single_rj45_port(painter, odd_rect, port_odd, is_top=True)

                # Desenha porta PAR (Inferior)
                even_rect = QRectF(px, bottom_row_y, port_w, port_h)
                self._port_rects[port_even] = even_rect
                self._draw_single_rj45_port(painter, even_rect, port_even, is_top=False)

            curr_x += b_w + block_gap

    def _draw_single_rj45_port(self, painter: QPainter, rect: QRectF, port_num: int, is_top: bool):
        """Desenha uma única porta RJ45 com contatos de cobre, notch e LED de link."""
        is_connected = (port_num == self.connected_port)
        is_hovered = (port_num == self.hovered_port)
        is_selected = (port_num == self.selected_port)
        status = self.port_status_map.get(port_num, "down")

        # 1. Rótulo com o número da porta
        painter.setFont(QFont("Segoe UI", 7, QFont.Bold if is_connected else QFont.Normal))
        num_color = QColor("#00e5ff") if is_connected else (QColor("#f8fafc") if is_hovered else QColor("#94a3b8"))
        painter.setPen(QPen(num_color))

        label_y = rect.top() - 3 if is_top else rect.bottom() + 10
        painter.drawText(
            QRectF(rect.left() - 4, label_y - 8, rect.width() + 8, 12),
            Qt.AlignCenter,
            str(port_num),
        )

        # 2. LED Indicador de Link/Atividade
        led_x = rect.center().x()
        led_y = rect.top() - 9 if is_top else rect.bottom() + 16

        if is_connected:
            # LED Neon Pulsante para a porta conectada
            pulse_val = 0.5 + (0.5 * math.sin(self._pulse_phase))
            led_color = QColor("#00e5ff")
            glow_r = 5.0 + (3.0 * pulse_val)

            # Brilho radial
            r_glow = QRadialGradient(led_x, led_y, glow_r)
            r_glow.setColorAt(0.0, QColor(0, 229, 255, 230))
            r_glow.setColorAt(0.5, QColor(0, 229, 255, int(120 * pulse_val)))
            r_glow.setColorAt(1.0, QColor(0, 229, 255, 0))
            painter.setBrush(QBrush(r_glow))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(QPointF(led_x, led_y), glow_r, glow_r)

            # Núcleo do LED
            painter.setBrush(QBrush(QColor("#ffffff")))
            painter.drawEllipse(QPointF(led_x, led_y), 2.2, 2.2)

        elif status == "up":
            # LED Verde Link UP
            painter.setBrush(QBrush(QColor("#10b981")))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(QPointF(led_x, led_y), 2.2, 2.2)
        else:
            # LED Desligado / Escuro
            painter.setBrush(QBrush(QColor("#2d3748")))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(QPointF(led_x, led_y), 1.8, 1.8)

        # 3. Cavidade Externa da Porta RJ45 (Metal Shielding Bezel)
        bezel_col = QColor("#475569")
        if is_connected:
            bezel_col = QColor("#00e5ff")
        elif is_selected:
            bezel_col = QColor("#38bdf8")
        elif is_hovered:
            bezel_col = QColor("#94a3b8")

        painter.setBrush(QBrush(QColor("#0a0d13")))
        painter.setPen(QPen(bezel_col, 1.5 if (is_connected or is_selected) else 1.0))
        painter.drawRoundedRect(rect, 2, 2)

        # 4. Desenha a cavidade plástica interna com trava (Key Notch)
        inner_m = 2.0
        inner_rect = QRectF(rect.left() + inner_m, rect.top() + inner_m, rect.width() - (inner_m * 2), rect.height() - (inner_m * 2))

        # Encaixe da trava do conector (em cima ou embaixo)
        notch_w = inner_rect.width() * 0.45
        notch_h = 3.5
        notch_x = inner_rect.center().x() - (notch_w / 2.0)
        notch_y = inner_rect.bottom() - notch_h if is_top else inner_rect.top()

        painter.setBrush(QBrush(QColor("#05070a")))
        painter.setPen(Qt.NoPen)
        painter.drawRect(inner_rect)

        # Recorte do encaixe
        painter.setBrush(QBrush(QColor("#131720")))
        painter.drawRect(QRectF(notch_x, notch_y, notch_w, notch_h))

        # 5. Contatos elétricos de ouro (8 Pinos RJ45)
        pin_count = 8
        pin_spacing = (inner_rect.width() - 4) / pin_count
        pin_y_start = inner_rect.top() + 3 if is_top else inner_rect.bottom() - 3
        pin_y_end = inner_rect.top() + 9 if is_top else inner_rect.bottom() - 9

        painter.setPen(QPen(QColor("#f59e0b"), 1.0))  # Ouro metálico
        for p in range(pin_count):
            pin_x = inner_rect.left() + 2 + (p * pin_spacing) + (pin_spacing / 2.0)
            painter.drawLine(QPointF(pin_x, pin_y_start), QPointF(pin_x, pin_y_end))

        # Efeito de Halo Pulsante de destaque na porta conectada
        if is_connected:
            pulse_alpha = int(140 + 100 * math.sin(self._pulse_phase))
            glow_pen = QPen(QColor(0, 229, 255, pulse_alpha), 2.2)
            painter.setBrush(Qt.NoBrush)
            painter.setPen(glow_pen)
            painter.drawRoundedRect(rect.adjusted(-2, -2, 2, 2), 3, 3)

    def _draw_connected_cable_and_badge(self, painter: QPainter, port_num: int, switch_y: float, switch_h: float):
        """
        Desenha o conector RJ45 (patch cable) inserido na porta conectada
        e o badge indicador '📍 SUA CONEXÃO LOCAL' de alta visibilidade.
        """
        rect = self._port_rects[port_num]
        is_top = (port_num % 2 != 0)
        cx = rect.center().x()

        # 1. Desenha o Boot/Cabo Ethernet conectado
        plug_w = rect.width() * 0.8
        plug_h = 16.0
        plug_x = cx - (plug_w / 2.0)
        plug_y = rect.top() - plug_h if is_top else rect.bottom()

        # Corpo do conector RJ45 (Azul Royal / Ciano com trava)
        plug_grad = QLinearGradient(plug_x, plug_y, plug_x + plug_w, plug_y)
        plug_grad.setColorAt(0.0, QColor("#0284c7"))
        plug_grad.setColorAt(0.5, QColor("#38bdf8"))
        plug_grad.setColorAt(1.0, QColor("#0369a1"))

        painter.setBrush(QBrush(plug_grad))
        painter.setPen(QPen(QColor("#e0f2fe"), 1.0))
        painter.drawRoundedRect(QRectF(plug_x, plug_y, plug_w, plug_h), 2, 2)

        # Cabo flexível descendo ou subindo
        cable_w = 6.0
        cable_x = cx - (cable_w / 2.0)
        cable_y1 = plug_y if is_top else plug_y + plug_h
        cable_y2 = 0 if is_top else self.height()

        c_grad = QLinearGradient(cable_x, 0, cable_x + cable_w, 0)
        c_grad.setColorAt(0.0, QColor("#0369a1"))
        c_grad.setColorAt(0.5, QColor("#38bdf8"))
        c_grad.setColorAt(1.0, QColor("#075985"))

        painter.setBrush(QBrush(c_grad))
        painter.setPen(Qt.NoPen)
        painter.drawRect(QRectF(cable_x, min(cable_y1, cable_y2), cable_w, abs(cable_y2 - cable_y1)))

        # 2. Badge Chamativo '📍 SUA PORTA (Porta X)'
        badge_text = f"📍 SUA PORTA ({port_num})"
        if self.connected_port_name:
            badge_text = f"📍 {self.connected_port_name}"

        painter.setFont(QFont("Segoe UI", 8, QFont.Bold))
        fm = QFontMetrics(painter.font())
        tw = fm.horizontalAdvance(badge_text) + 18
        th = 20.0

        badge_x = cx - (tw / 2.0)
        badge_y = switch_y - th - 5 if is_top else switch_y + switch_h + 8

        # Impede que saia dos limites do widget
        badge_x = max(10.0, min(self.width() - tw - 10.0, badge_x))

        badge_rect = QRectF(badge_x, badge_y, tw, th)

        # Sombra do badge
        painter.setBrush(QBrush(QColor(0, 0, 0, 160)))
        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(badge_rect.adjusted(1, 2, 1, 2), 10, 10)

        # Gradiente brilhante do badge
        b_grad = QLinearGradient(badge_x, badge_y, badge_x + tw, badge_y)
        b_grad.setColorAt(0.0, QColor("#0284c7"))
        b_grad.setColorAt(0.5, QColor("#0ea5e9"))
        b_grad.setColorAt(1.0, QColor("#0284c7"))

        painter.setBrush(QBrush(b_grad))
        painter.setPen(QPen(QColor("#ffffff"), 1.2))
        painter.drawRoundedRect(badge_rect, 10, 10)

        # Texto do badge
        painter.setPen(QPen(QColor("#ffffff")))
        painter.drawText(badge_rect, Qt.AlignCenter, badge_text)
