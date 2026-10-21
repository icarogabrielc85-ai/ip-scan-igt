from PyQt5.QtCore import QPointF, QRectF, Qt
from PyQt5.QtGui import (
    QBrush,
    QColor,
    QFont,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
)
from PyQt5.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget

DARK_STYLESHEET = """
QMainWindow, QDialog {
    background-color: #0f141c;
    color: #e2e8f0;
}

QMenuBar {
    background-color: #161f2e;
    color: #e2e8f0;
    border-bottom: 1px solid #243447;
    font-size: 12px;
}

QMenuBar::item {
    background: transparent;
    padding: 5px 12px;
    border-radius: 4px;
}

QMenuBar::item:selected {
    background-color: #0284c7;
    color: #ffffff;
}

QWidget {
    font-family: "Noto Sans", "Ubuntu", "DejaVu Sans", "Segoe UI", Roboto, sans-serif, "Noto Color Emoji";
    font-size: 13px;
    color: #e2e8f0;
}

QFrame#topBar {
    background-color: #161f2e;
    border-bottom: 1px solid #243447;
    padding: 6px 10px;
}

QFrame#bottomPanel {
    background-color: #111827;
    border: 1px solid #1f2937;
    border-radius: 6px;
}

QFrame#panelHeader {
    background-color: #162032;
    border-bottom: 1px solid #1f2937;
    border-top-left-radius: 5px;
    border-top-right-radius: 5px;
    padding: 4px 8px;
}

QGroupBox {
    background-color: #161f2e;
    border: 1px solid #243447;
    border-radius: 8px;
    margin-top: 18px;
    font-weight: bold;
    padding-top: 14px;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    color: #38bdf8;
}

QLineEdit, QComboBox, QSpinBox {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 4px;
    padding: 6px 10px;
    color: #f8fafc;
    selection-background-color: #0284c7;
}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 1px solid #38bdf8;
    background-color: #0f172a;
}

QPushButton {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 4px;
    padding: 6px 14px;
    font-weight: 600;
    color: #f1f5f9;
}

QPushButton:hover {
    background-color: #334155;
    border-color: #475569;
}

QPushButton:pressed {
    background-color: #0f172a;
}

QPushButton#btnStart {
    background-color: #059669;
    border: 1px solid #10b981;
    color: #ffffff;
    font-weight: bold;
    font-size: 13px;
    padding: 7px 18px;
}

QPushButton#btnStart:hover {
    background-color: #10b981;
    border-color: #34d399;
}

QPushButton#btnStop {
    background-color: #dc2626;
    border: 1px solid #ef4444;
    color: #ffffff;
    font-weight: bold;
    font-size: 13px;
    padding: 7px 18px;
}

QPushButton#btnStop:hover {
    background-color: #ef4444;
}

QPushButton#btnSubnet {
    background-color: #0284c7;
    border: 1px solid #38bdf8;
    color: #ffffff;
    font-weight: bold;
}

QPushButton#btnSubnet:hover {
    background-color: #0369a1;
}

QTreeWidget, QTableWidget {
    background-color: #111827;
    border: 1px solid #1f2937;
    border-radius: 4px;
    alternate-background-color: #162032;
    selection-background-color: #0369a1;
    selection-color: #ffffff;
    gridline-color: #1f2937;
}

QTreeWidget::item {
    padding: 4px 2px;
}

QTreeWidget::item:hover {
    background-color: #1e293b;
}

QTreeWidget::item:selected {
    background-color: #0284c7;
    color: #ffffff;
}

QHeaderView::section {
    background-color: #1e293b;
    color: #94a3b8;
    padding: 7px 8px;
    font-weight: bold;
    font-size: 12px;
    border: none;
    border-right: 1px solid #334155;
    border-bottom: 2px solid #334155;
}

QHeaderView::section:hover {
    background-color: #334155;
    color: #38bdf8;
}

QProgressBar {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 4px;
    text-align: center;
    color: #f8fafc;
    font-weight: bold;
}

QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #38bdf8);
    border-radius: 3px;
}

QTabWidget::pane {
    border: 1px solid #1f2937;
    background-color: #111827;
    border-radius: 4px;
}

QTabBar::tab {
    background-color: #162032;
    color: #94a3b8;
    padding: 8px 24px;
    border-top-left-radius: 5px;
    border-top-right-radius: 5px;
    margin-right: 2px;
    font-weight: bold;
    font-size: 13px;
}

QTabBar::tab:selected {
    background-color: #111827;
    color: #38bdf8;
    border-top: 3px solid #38bdf8;
}

QStatusBar {
    background-color: #0b0f17;
    color: #94a3b8;
    border-top: 1px solid #1e293b;
}

QSplitter::handle {
    background-color: #1f2937;
}

QSplitter::handle:hover {
    background-color: #38bdf8;
}

QMenu {
    background-color: #1e293b;
    color: #f8fafc;
    border: 1px solid #334155;
    border-radius: 4px;
    padding: 4px;
}

QMenu::item {
    padding: 6px 24px;
    border-radius: 3px;
}

QMenu::item:selected {
    background-color: #0284c7;
    color: #ffffff;
}
"""

LIGHT_STYLESHEET = """
QMainWindow, QDialog {
    background-color: #f0f2f5;
    color: #1f2937;
}

QMenuBar {
    background-color: #f6f8fa;
    color: #24292f;
    border-bottom: 1px solid #d0d7de;
    font-size: 12px;
}

QMenuBar::item {
    background: transparent;
    padding: 5px 12px;
    border-radius: 4px;
}

QMenuBar::item:selected {
    background-color: #0969da;
    color: #ffffff;
}

QWidget {
    font-family: "Noto Sans", "Ubuntu", "DejaVu Sans", "Segoe UI", Roboto, sans-serif, "Noto Color Emoji";
    font-size: 13px;
    color: #1f2937;
}

/* Advanced IP Scanner classic Top Toolbar */
QFrame#topBar {
    background-color: #f6f8fa;
    border-bottom: 1px solid #d0d7de;
    padding: 6px 10px;
}

QFrame#bottomPanel {
    background-color: #ffffff;
    border: 1px solid #d0d7de;
    border-radius: 6px;
}

QFrame#panelHeader {
    background-color: #f6f8fa;
    border-bottom: 1px solid #d0d7de;
    border-top-left-radius: 5px;
    border-top-right-radius: 5px;
    padding: 4px 8px;
}

QLineEdit, QComboBox, QSpinBox {
    background-color: #ffffff;
    border: 1px solid #d0d7de;
    border-radius: 4px;
    padding: 6px 10px;
    color: #1f2937;
    font-weight: 500;
    selection-background-color: #0969da;
}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 1.5px solid #0969da;
}

QPushButton {
    background-color: #f6f8fa;
    border: 1px solid #d0d7de;
    border-radius: 4px;
    padding: 6px 14px;
    font-weight: 600;
    color: #24292f;
}

QPushButton:hover {
    background-color: #f3f4f6;
    border-color: #1b1f2426;
}

QPushButton:pressed {
    background-color: #ebecf0;
}

/* Advanced IP Scanner signature green "Verificar" button */
QPushButton#btnStart {
    background-color: #107c41;
    border: 1px solid #0e6c38;
    border-radius: 4px;
    color: #ffffff;
    font-weight: bold;
    font-size: 13px;
    padding: 7px 20px;
}

QPushButton#btnStart:hover {
    background-color: #15803d;
}

QPushButton#btnStart:pressed {
    background-color: #0d6535;
}

QPushButton#btnStop {
    background-color: #d13438;
    border: 1px solid #b82d30;
    border-radius: 4px;
    color: #ffffff;
    font-weight: bold;
    font-size: 13px;
    padding: 7px 20px;
}

QPushButton#btnStop:hover {
    background-color: #b91c1c;
}

/* Advanced IP Scanner Subnet IP Button */
QPushButton#btnSubnet {
    background-color: #0969da;
    border: 1px solid #0860ca;
    border-radius: 4px;
    color: #ffffff;
    font-weight: bold;
    font-size: 12px;
    padding: 6px 14px;
}

QPushButton#btnSubnet:hover {
    background-color: #0860ca;
}

/* Tree & Tables style (Advanced IP Scanner Look) */
QTreeWidget, QTableWidget {
    background-color: #ffffff;
    border: 1px solid #d0d7de;
    border-radius: 4px;
    alternate-background-color: #f8fafc;
    selection-background-color: #0969da;
    selection-color: #ffffff;
    gridline-color: #f0f2f5;
}

QTreeWidget::item {
    padding: 4px 2px;
}

QTreeWidget::item:hover {
    background-color: #f0f4f9;
}

QTreeWidget::item:selected {
    background-color: #0969da;
    color: #ffffff;
}

QHeaderView::section {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #fafbfc, stop:1 #edf2f7);
    color: #24292f;
    padding: 7px 8px;
    font-weight: bold;
    font-size: 12px;
    border: none;
    border-right: 1px solid #d0d7de;
    border-bottom: 2px solid #cbd5e1;
}

QHeaderView::section:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #f0f4f9, stop:1 #e2e8f0);
    color: #0969da;
}

/* Advanced IP Scanner Tabs: [Resultados] [Favoritos] */
QTabWidget::pane {
    border: 1px solid #d0d7de;
    background-color: #ffffff;
    border-radius: 4px;
}

QTabBar::tab {
    background-color: #e4e7eb;
    color: #4b5563;
    padding: 8px 24px;
    border-top-left-radius: 5px;
    border-top-right-radius: 5px;
    margin-right: 2px;
    font-weight: bold;
    font-size: 13px;
    border: 1px solid #d0d7de;
    border-bottom: none;
}

QTabBar::tab:selected {
    background-color: #ffffff;
    color: #0969da;
    border-top: 3px solid #0969da;
    border-bottom: none;
}

QStatusBar {
    background-color: #f3f4f6;
    color: #4b5563;
    border-top: 1px solid #d0d7de;
    padding: 3px 6px;
}

QProgressBar {
    background-color: #e5e7eb;
    border: 1px solid #d0d7de;
    border-radius: 4px;
    text-align: center;
    color: #1f2937;
    font-weight: bold;
}

QProgressBar::chunk {
    background-color: #107c41;
    border-radius: 3px;
}

QSplitter::handle {
    background-color: #d0d7de;
    height: 4px;
}

QSplitter::handle:hover {
    background-color: #0969da;
}

QMenu {
    background-color: #ffffff;
    color: #1f2937;
    border: 1px solid #d0d7de;
    border-radius: 4px;
    padding: 4px;
}

QMenu::item {
    padding: 6px 24px;
    border-radius: 3px;
}

QMenu::item:selected {
    background-color: #0969da;
    color: #ffffff;
}
"""


class KpiCard(QFrame):
    def __init__(self, title: str, initial_value: str, icon_str: str, badge_color: str = "#0284c7"):
        super().__init__()
        self.setObjectName("kpiCard")
        self.badge_color = badge_color
        self.is_dark = False

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(10)

        self.icon_label = QLabel(icon_str)
        layout.addWidget(self.icon_label)

        v_layout = QVBoxLayout()
        v_layout.setSpacing(2)

        self.title_label = QLabel(title)
        v_layout.addWidget(self.title_label)

        self.val_label = QLabel(initial_value)
        v_layout.addWidget(self.val_label)

        layout.addLayout(v_layout)
        self.apply_theme(False)

    def apply_theme(self, is_dark: bool):
        self.is_dark = is_dark
        if is_dark:
            self.setStyleSheet("""
                QFrame#kpiCard {
                    background-color: #162032;
                    border: 1px solid #243447;
                    border-radius: 6px;
                }
            """)
            self.title_label.setStyleSheet("color: #94a3b8; font-size: 11px; font-weight: bold;")
        else:
            self.setStyleSheet("""
                QFrame#kpiCard {
                    background-color: #ffffff;
                    border: 1px solid #d0d7de;
                    border-radius: 6px;
                }
            """)
            self.title_label.setStyleSheet("color: #57606a; font-size: 11px; font-weight: bold;")

        self.icon_label.setStyleSheet(f"color: {self.badge_color}; font-size: 20px; font-weight: bold;")
        self.val_label.setStyleSheet(f"color: {self.badge_color}; font-size: 16px; font-weight: 800;")

    def set_value(self, val: str):
        self.val_label.setText(val)


class LivePingOscilloscope(QWidget):
    """
    Antialiased dynamic oscilloscope/sparkline widget that plots
    the real-time ping latency waveform and metrics.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(80)
        self.samples = []
        self.max_samples = 45
        self.current_ip = ""
        self.current_rtt = -1.0
        self.min_rtt = -1.0
        self.avg_rtt = -1.0
        self.max_rtt = -1.0
        self.ttl = -1
        self.method = ""
        self.loss_pct = 0
        self.is_dark = True

    def add_sample(self, rtt: float, ttl: int = -1, method: str = ""):
        self.current_rtt = rtt
        self.ttl = ttl if ttl > 0 else self.ttl
        self.method = method or self.method

        if len(self.samples) >= self.max_samples:
            self.samples.pop(0)
        self.samples.append(rtt)

        valid = [s for s in self.samples if s >= 0]
        if valid:
            self.min_rtt = min(valid)
            self.max_rtt = max(valid)
            self.avg_rtt = sum(valid) / len(valid)
            total = len(self.samples)
            losses = sum(1 for s in self.samples if s < 0)
            self.loss_pct = int((losses / total) * 100)
        else:
            self.loss_pct = 100
        self.update()

    def clear(self, ip: str = ""):
        self.current_ip = ip
        self.samples.clear()
        self.current_rtt = -1.0
        self.min_rtt = -1.0
        self.avg_rtt = -1.0
        self.max_rtt = -1.0
        self.ttl = -1
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        w = self.width()
        h = self.height()

        # Background
        bg_col = QColor(15, 23, 42) if self.is_dark else QColor(255, 255, 255)
        border_col = QColor(36, 52, 71) if self.is_dark else QColor(208, 215, 222)
        painter.setBrush(QBrush(bg_col))
        painter.setPen(QPen(border_col, 1))
        painter.drawRoundedRect(QRectF(1, 1, w - 2, h - 2), 6, 6)

        # Grid lines
        grid_col = QColor(30, 41, 59) if self.is_dark else QColor(240, 243, 246)
        painter.setPen(QPen(grid_col, 1, Qt.DashLine))
        painter.drawLine(10, int(h * 0.35), w - 10, int(h * 0.35))
        painter.drawLine(10, int(h * 0.70), w - 10, int(h * 0.70))

        # Metrics text
        text_col = QColor(226, 232, 240) if self.is_dark else QColor(36, 41, 47)
        dim_col = QColor(148, 163, 184) if self.is_dark else QColor(87, 96, 106)
        font = QFont("Noto Sans", 9)
        painter.setFont(font)

        if not self.current_ip:
            painter.setPen(dim_col)
            painter.drawText(QRectF(12, 10, w - 24, h - 20), Qt.AlignCenter | Qt.TextWordWrap, "Selecione um dispositivo para monitorar o Ping Dinâmico Instantâneo em tempo real")
            return

        # Header metrics
        painter.setPen(text_col)
        ip_header = f"● Monitorando: {self.current_ip}"
        painter.drawText(12, 18, ip_header)

        accent_color = QColor(56, 189, 248) if self.is_dark else QColor(9, 105, 218)
        if self.current_rtt >= 0:
            status_text = f"Agora: {self.current_rtt:.2f} ms  |  Mín: {self.min_rtt:.2f} ms  •  Méd: {self.avg_rtt:.2f} ms  •  Máx: {self.max_rtt:.2f} ms"
            if self.ttl > 0:
                status_text += f"  •  TTL: {self.ttl}"
            if self.method:
                status_text += f" ({self.method})"
            painter.setPen(accent_color)
            painter.drawText(12, 34, status_text)
        else:
            painter.setPen(QColor(239, 68, 68) if self.is_dark else QColor(207, 34, 46))
            painter.drawText(12, 34, "● Sem resposta no momento")

        # Plot latency waveform
        if not self.samples or w < 40 or h < 55:
            return

        valid_vals = [s for s in self.samples if s >= 0]
        max_val = max(valid_vals) if valid_vals else 10.0
        max_val = max(max_val * 1.3, 1.5)

        plot_top = 44
        plot_bottom = h - 10
        plot_h = max(10, plot_bottom - plot_top)
        count = len(self.samples)
        step_x = max(1.0, (w - 24) / max(self.max_samples - 1, 1))

        points = []
        for i, val in enumerate(self.samples):
            x = 12 + i * step_x
            if val < 0:
                y = plot_bottom
            else:
                y = plot_bottom - (val / max_val) * plot_h
            points.append(QPointF(x, y))

        if len(points) >= 2:
            # Gradient fill under the curve
            fill_path = QPainterPath()
            fill_path.moveTo(points[0].x(), plot_bottom)
            for p in points:
                fill_path.lineTo(p)
            fill_path.lineTo(points[-1].x(), plot_bottom)
            fill_path.closeSubpath()

            grad = QLinearGradient(0, plot_top, 0, plot_bottom)
            if self.is_dark:
                grad.setColorAt(0, QColor(56, 189, 248, 120))
                grad.setColorAt(1, QColor(2, 132, 199, 10))
            else:
                grad.setColorAt(0, QColor(9, 105, 218, 70))
                grad.setColorAt(1, QColor(9, 105, 218, 5))
            painter.fillPath(fill_path, QBrush(grad))

            # Waveform stroke
            stroke_col = QColor(56, 189, 248) if self.is_dark else QColor(9, 105, 218)
            stroke_pen = QPen(stroke_col, 2)
            painter.setPen(stroke_pen)
            for i in range(len(points) - 1):
                painter.drawLine(points[i], points[i + 1])

            # Draw glowing dot on the last point
            last_p = points[-1]
            dot_brush = QColor(52, 211, 153) if self.is_dark else QColor(16, 124, 65)
            dot_pen = QColor(16, 185, 129) if self.is_dark else QColor(21, 128, 61)
            painter.setBrush(QBrush(dot_brush))
            painter.setPen(QPen(dot_pen, 2))
            painter.drawEllipse(last_p, 4, 4)
