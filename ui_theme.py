from PyQt5.QtCore import QPointF, QRectF, Qt
from PyQt5.QtGui import (
    QBrush,
    QColor,
    QFont,
    QFontMetrics,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
)
from PyQt5.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget

DARK_STYLESHEET = """
QMainWindow, QDialog {
    background-color: #0b0f17;
    color: #f1f5f9;
}

QMenuBar {
    background-color: #111827;
    color: #e2e8f0;
    border-bottom: 1px solid #1f2937;
    font-size: 12px;
}

QMenuBar::item {
    background: transparent;
    padding: 6px 12px;
    border-radius: 4px;
}

QMenuBar::item:selected {
    background-color: #0284c7;
    color: #ffffff;
}

QWidget {
    font-family: "Segoe UI", "Noto Sans", "Ubuntu", -apple-system, Roboto, sans-serif, "Noto Color Emoji";
    font-size: 13px;
    color: #f1f5f9;
}

/* Tier 1 Header Toolbar */
QFrame#topBar {
    background-color: #111827;
    border-bottom: 1px solid #1f2937;
    padding: 6px 12px;
}

/* Tier 2 Ribbon Toolbar */
QFrame#ribbonBar {
    background-color: #162032;
    border-bottom: 1px solid #1f2937;
    padding: 4px 12px;
}

/* Bottom Collapsible Panel */
QFrame#bottomPanel {
    background-color: #0e141f;
    border: 1px solid #1f2937;
    border-radius: 6px;
}

QFrame#panelHeader {
    background-color: #162032;
    border-bottom: 1px solid #1f2937;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    padding: 5px 10px;
}

QGroupBox {
    background-color: #111827;
    border: 1px solid #1f2937;
    border-radius: 6px;
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
    border-radius: 5px;
    padding: 2px 6px;
    color: #f8fafc;
    selection-background-color: #0284c7;
}

QLineEdit#txtStartIp, QLineEdit#txtEndIp {
    font-family: "JetBrains Mono", "Segoe UI Mono", "Ubuntu Mono", "DejaVu Sans Mono", monospace;
    font-size: 13px;
    font-weight: 600;
    padding: 2px 5px;
    letter-spacing: 0.5px;
    color: #38bdf8;
}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 1.5px solid #38bdf8;
    background-color: #0f172a;
}

QComboBox {
    padding: 2px 6px;
}

QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 20px;
    border-left: 1px solid #334155;
    border-top-right-radius: 5px;
    border-bottom-right-radius: 5px;
}

QComboBox QAbstractItemView {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 6px;
    selection-background-color: #0284c7;
    selection-color: #ffffff;
    padding: 4px;
}

QPushButton {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 5px;
    padding: 5px 12px;
    font-weight: 600;
    color: #e2e8f0;
}

QPushButton:hover {
    background-color: #334155;
    border-color: #475569;
    color: #ffffff;
}

QPushButton:pressed {
    background-color: #0f172a;
}

/* Primary Start / Stop Scan Buttons */
QPushButton#btnStart {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #10b981, stop:1 #059669);
    border: 1px solid #047857;
    border-radius: 6px;
    color: #ffffff;
    font-weight: bold;
    font-size: 13px;
    padding: 7px 18px;
}

QPushButton#btnStart:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #34d399, stop:1 #10b981);
    border-color: #059669;
}

QPushButton#btnStart:pressed {
    background-color: #047857;
}

QPushButton#btnStop {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #ef4444, stop:1 #dc2626);
    border: 1px solid #b91c1c;
    border-radius: 6px;
    color: #ffffff;
    font-weight: bold;
    font-size: 13px;
    padding: 7px 18px;
}

QPushButton#btnStop:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #f87171, stop:1 #ef4444);
}

QPushButton#btnStop:pressed {
    background-color: #b91c1c;
}

/* Subnet Picker Button */
QPushButton#btnSubnet {
    background-color: #0284c7;
    border: 1px solid #38bdf8;
    border-radius: 6px;
    color: #ffffff;
    font-weight: bold;
}

QPushButton#btnSubnet:hover {
    background-color: #0369a1;
}

/* 1-Click Update Button */
QPushButton#btnUpdate {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0284c7, stop:1 #0369a1);
    border: 1px solid #38bdf8;
    border-radius: 6px;
    color: #ffffff;
    font-weight: bold;
    font-size: 12px;
    padding: 6px 14px;
}

QPushButton#btnUpdate:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #38bdf8, stop:1 #0284c7);
    color: #0f172a;
}

/* Ribbon Tool Buttons & Scroll Area */
QScrollArea#ribbonScroll {
    background: transparent;
    border: none;
}

QScrollArea#ribbonScroll > QWidget > QWidget {
    background: transparent;
}

QPushButton#ribbonBtn {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 5px;
    padding: 3px 8px;
    font-size: 12px;
    font-weight: 600;
    color: #cbd5e1;
    min-height: 22px;
}

QPushButton#ribbonBtn:hover {
    background-color: #334155;
    border-color: #475569;
    color: #ffffff;
}

QPushButton#ribbonBtn:checked {
    background-color: #0369a1;
    border-color: #38bdf8;
    color: #ffffff;
}

/* Inspector Action Buttons - Group Color Coding */
QPushButton#btnActionWeb {
    background-color: #0c4a6e;
    border: 1px solid #0284c7;
    color: #e0f2fe;
    border-radius: 5px;
    font-weight: 600;
    padding: 5px 10px;
}
QPushButton#btnActionWeb:hover {
    background-color: #0284c7;
    color: #ffffff;
}

QPushButton#btnActionRemote {
    background-color: #2e1065;
    border: 1px solid #7c3aed;
    color: #ede9fe;
    border-radius: 5px;
    font-weight: 600;
    padding: 5px 10px;
}
QPushButton#btnActionRemote:hover {
    background-color: #7c3aed;
    color: #ffffff;
}

QPushButton#btnActionDiag {
    background-color: #1e293b;
    border: 1px solid #475569;
    color: #f1f5f9;
    border-radius: 5px;
    font-weight: 600;
    padding: 5px 10px;
}
QPushButton#btnActionDiag:hover {
    background-color: #334155;
    border-color: #64748b;
    color: #ffffff;
}

/* Brand and Version Tag */
QLabel#lblAppName {
    font-weight: 800;
    font-size: 14px;
    color: #f8fafc;
    letter-spacing: 0.5px;
}

QLabel#lblVersionBadge {
    color: #38bdf8;
    background-color: #0c4a6e;
    border: 1px solid #0369a1;
    border-radius: 12px;
    font-weight: bold;
    font-size: 11px;
    padding: 2px 9px;
}

QLabel#lblVersionBadge:hover {
    background-color: #075985;
    color: #e0f2fe;
}

/* Ribbon KPI Badges */
QLabel#kpiOnline {
    background-color: #064e3b;
    color: #34d399;
    border: 1px solid #059669;
    border-radius: 12px;
    padding: 2px 10px;
    font-weight: bold;
    font-size: 11px;
    min-height: 20px;
}

QLabel#kpiLatency {
    background-color: #082f49;
    color: #38bdf8;
    border: 1px solid #0284c7;
    border-radius: 12px;
    padding: 2px 10px;
    font-weight: bold;
    font-size: 11px;
    min-height: 20px;
}

QLabel#kpiServices {
    background-color: #451a03;
    color: #fbbf24;
    border: 1px solid #d97706;
    border-radius: 12px;
    padding: 2px 10px;
    font-weight: bold;
    font-size: 11px;
    min-height: 20px;
}

/* Device Tree & Tables */
QTreeWidget, QTableWidget {
    background-color: #0e141f;
    border: 1px solid #1f2937;
    border-radius: 6px;
    alternate-background-color: #141d2c;
    selection-background-color: #0284c7;
    selection-color: #ffffff;
    gridline-color: #1f2937;
}

QTreeWidget::item {
    min-height: 22px;
    padding: 2px 4px;
}

QTreeWidget::item:hover {
    background-color: #1e293b;
}

QTreeWidget::item:selected {
    background-color: #0284c7;
    color: #ffffff;
}

QHeaderView::section {
    background-color: #162032;
    color: #94a3b8;
    padding: 5px 8px;
    font-weight: bold;
    font-size: 12px;
    border: none;
    border-right: 1px solid #243447;
    border-bottom: 2px solid #243447;
}

QHeaderView::section:hover {
    background-color: #1e2d44;
    color: #38bdf8;
}

QProgressBar {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 5px;
    text-align: center;
    color: #f8fafc;
    font-weight: bold;
}

QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #38bdf8);
    border-radius: 4px;
}

QTabWidget::pane {
    border: 1px solid #1f2937;
    background-color: #0e141f;
    border-radius: 6px;
}

QTabBar::tab {
    background-color: #162032;
    color: #94a3b8;
    padding: 6px 14px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    margin-right: 3px;
    font-weight: bold;
    font-size: 13px;
    min-width: 90px;
}

QTabBar::tab:selected {
    background-color: #0e141f;
    color: #38bdf8;
    border-top: 3px solid #38bdf8;
}

QStatusBar {
    background-color: #080c14;
    color: #94a3b8;
    border-top: 1px solid #1f2937;
    padding: 3px 8px;
}

QSplitter::handle {
    background-color: #1f2937;
    height: 4px;
}

QSplitter::handle:hover {
    background-color: #38bdf8;
}

QMenu {
    background-color: #1e293b;
    color: #f8fafc;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 4px;
}

QMenu::item {
    padding: 6px 20px;
    border-radius: 4px;
}

QMenu::item:selected {
    background-color: #0284c7;
    color: #ffffff;
}

QMenu::separator {
    height: 1px;
    background-color: #334155;
    margin: 4px 6px;
}

/* Modern slim scrollbars */
QScrollBar:vertical {
    background: transparent;
    width: 8px;
    margin: 0px;
    border-radius: 4px;
}

QScrollBar::handle:vertical {
    background: #334155;
    min-height: 25px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background: #475569;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    background: transparent;
    height: 8px;
    margin: 0px;
    border-radius: 4px;
}

QScrollBar::handle:horizontal {
    background: #334155;
    min-width: 25px;
    border-radius: 4px;
}

QScrollBar::handle:horizontal:hover {
    background: #475569;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

QSlider::groove:horizontal {
    border: 1px solid #334155;
    height: 6px;
    background: #1e293b;
    margin: 2px 0;
    border-radius: 3px;
}

QSlider::sub-page:horizontal {
    background: #0284c7;
    border: 1px solid #0369a1;
    height: 6px;
    border-radius: 3px;
}

QSlider::handle:horizontal {
    background: #38bdf8;
    border: 1px solid #0284c7;
    width: 14px;
    height: 14px;
    margin: -5px 0;
    border-radius: 7px;
}

QSlider::handle:horizontal:hover {
    background: #7dd3fc;
    border-color: #38bdf8;
}
"""

LIGHT_STYLESHEET = """
QMainWindow, QDialog {
    background-color: #dcdcdc;
    color: #1e242b;
}

QMenuBar {
    background-color: #d2d2d2;
    color: #1e242b;
    border-bottom: 1px solid #b4b4b4;
    font-size: 12px;
}

QMenuBar::item {
    background: transparent;
    padding: 6px 12px;
    border-radius: 4px;
}

QMenuBar::item:selected {
    background-color: #2b6595;
    color: #ffffff;
}

QWidget {
    font-family: "Segoe UI", "Noto Sans", "Ubuntu", -apple-system, Roboto, sans-serif, "Noto Color Emoji";
    font-size: 13px;
    color: #1e242b;
}

/* Tier 1 Header Toolbar */
QFrame#topBar {
    background-color: #d2d2d2;
    border-bottom: 1px solid #b4b4b4;
    padding: 5px 10px;
}

/* Tier 2 Ribbon Toolbar */
QFrame#ribbonBar {
    background-color: #d8d8d8;
    border-bottom: 1px solid #b4b4b4;
    padding: 4px 10px;
}

/* Bottom Collapsible Panel */
QFrame#bottomPanel {
    background-color: #e2e2e2;
    border: 1px solid #b0b0b0;
    border-radius: 6px;
}

QFrame#panelHeader {
    background-color: #d4d4d4;
    border-bottom: 1px solid #b4b4b4;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    padding: 4px 10px;
}

QGroupBox {
    background-color: #e2e2e2;
    border: 1px solid #b0b0b0;
    border-radius: 6px;
    margin-top: 18px;
    font-weight: bold;
    padding-top: 14px;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    color: #1d4f7a;
}

QLineEdit, QComboBox, QSpinBox {
    background-color: #ededed;
    border: 1px solid #a8a8a8;
    border-radius: 4px;
    padding: 2px 6px;
    color: #1e242b;
    font-weight: 500;
    selection-background-color: #2b6595;
    selection-color: #ffffff;
}

QLineEdit#txtStartIp, QLineEdit#txtEndIp {
    font-family: "JetBrains Mono", "Segoe UI Mono", "Ubuntu Mono", "DejaVu Sans Mono", monospace;
    font-size: 13px;
    font-weight: 600;
    padding: 2px 5px;
    letter-spacing: 0.4px;
    color: #164e78;
}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 1.5px solid #2b6595;
    background-color: #f4f7fa;
}

QComboBox {
    padding: 2px 6px;
}

QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 20px;
    border-left: 1px solid #a8a8a8;
    border-top-right-radius: 4px;
    border-bottom-right-radius: 4px;
}

QComboBox QAbstractItemView {
    background-color: #eaeaea;
    border: 1px solid #a0a0a0;
    border-radius: 4px;
    selection-background-color: #2b6595;
    selection-color: #ffffff;
    padding: 4px;
}

QPushButton {
    background-color: #e0e0e0;
    border: 1px solid #a8a8a8;
    border-radius: 4px;
    padding: 4px 10px;
    font-weight: 600;
    color: #1e242b;
}

QPushButton:hover {
    background-color: #d2dce6;
    border-color: #7c96ab;
}

QPushButton:pressed {
    background-color: #c2cedb;
}

/* Primary Start / Stop Scan Buttons */
QPushButton#btnStart {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #107c41, stop:1 #0c6334);
    border: 1px solid #0a522b;
    border-radius: 5px;
    color: #ffffff;
    font-weight: bold;
    font-size: 13px;
    padding: 5px 14px;
}

QPushButton#btnStart:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #15803d, stop:1 #107c41);
}

QPushButton#btnStart:pressed {
    background-color: #094725;
}

QPushButton#btnStop {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #d13438, stop:1 #b82d30);
    border: 1px solid #9e2528;
    border-radius: 5px;
    color: #ffffff;
    font-weight: bold;
    font-size: 13px;
    padding: 5px 14px;
}

QPushButton#btnStop:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #e11d48, stop:1 #be123c);
}

QPushButton#btnStop:pressed {
    background-color: #9e2528;
}

/* Subnet Picker Button */
QPushButton#btnSubnet {
    background-color: #2b6595;
    border: 1px solid #1d4f7a;
    border-radius: 5px;
    color: #ffffff;
    font-weight: bold;
    font-size: 12px;
}

QPushButton#btnSubnet:hover {
    background-color: #23537d;
}

/* 1-Click Update Button */
QPushButton#btnUpdate {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #2b6595, stop:1 #1d4f7a);
    border: 1px solid #163d5e;
    border-radius: 5px;
    color: #ffffff;
    font-weight: bold;
    font-size: 12px;
    padding: 5px 12px;
}

QPushButton#btnUpdate:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3579b0, stop:1 #2b6595);
}

/* Ribbon Tool Buttons & Scroll Area */
QScrollArea#ribbonScroll {
    background: transparent;
    border: none;
}

QScrollArea#ribbonScroll > QWidget > QWidget {
    background: transparent;
}

QPushButton#ribbonBtn {
    background-color: #e2e2e2;
    border: 1px solid #a8a8a8;
    border-radius: 4px;
    padding: 3px 8px;
    font-size: 12px;
    font-weight: 600;
    color: #1e242b;
    min-height: 22px;
}

QPushButton#ribbonBtn:hover {
    background-color: #d2dce6;
    border-color: #7c96ab;
}

QPushButton#ribbonBtn:checked {
    background-color: #c8daea;
    border-color: #2b6595;
    color: #164e78;
}

/* Inspector Action Buttons - Group Color Coding */
QPushButton#btnActionWeb {
    background-color: #d8e6f3;
    border: 1px solid #8eb4d9;
    color: #164e78;
    border-radius: 4px;
    font-weight: 600;
    padding: 4px 10px;
}
QPushButton#btnActionWeb:hover {
    background-color: #2b6595;
    color: #ffffff;
}

QPushButton#btnActionRemote {
    background-color: #e6dff0;
    border: 1px solid #b49fd6;
    color: #4c1d95;
    border-radius: 4px;
    font-weight: 600;
    padding: 4px 10px;
}
QPushButton#btnActionRemote:hover {
    background-color: #6d28d9;
    color: #ffffff;
}

QPushButton#btnActionDiag {
    background-color: #dcdcdc;
    border: 1px solid #a8a8a8;
    color: #1e242b;
    border-radius: 4px;
    font-weight: 600;
    padding: 4px 10px;
}
QPushButton#btnActionDiag:hover {
    background-color: #cccccc;
    border-color: #8c8c8c;
}

/* Brand and Version Tag */
QLabel#lblAppName {
    font-weight: 800;
    font-size: 14px;
    color: #1e242b;
    letter-spacing: 0.4px;
}

QLabel#lblVersionBadge {
    color: #164e78;
    background-color: #d0dfed;
    border: 1px solid #8eb4d9;
    border-radius: 12px;
    font-weight: bold;
    font-size: 11px;
    padding: 2px 9px;
}

QLabel#lblVersionBadge:hover {
    background-color: #bdd3e8;
    color: #0f3857;
}

/* Ribbon KPI Badges */
QLabel#kpiOnline {
    background-color: #d5e8dd;
    color: #0b5c36;
    border: 1px solid #8ec2a5;
    border-radius: 11px;
    padding: 2px 8px;
    font-weight: bold;
    font-size: 11px;
    min-height: 18px;
}

QLabel#kpiLatency {
    background-color: #d4e3f0;
    color: #164e78;
    border: 1px solid #8eb4d9;
    border-radius: 11px;
    padding: 2px 8px;
    font-weight: bold;
    font-size: 11px;
    min-height: 18px;
}

QLabel#kpiServices {
    background-color: #ece3cc;
    color: #7c4a08;
    border: 1px solid #cbb17a;
    border-radius: 11px;
    padding: 2px 8px;
    font-weight: bold;
    font-size: 11px;
    min-height: 18px;
}

/* Device Tree & Tables */
QTreeWidget, QTableWidget {
    background-color: #e8e8e8;
    border: 1px solid #b0b0b0;
    border-radius: 5px;
    alternate-background-color: #dedede;
    selection-background-color: #2b6595;
    selection-color: #ffffff;
    gridline-color: #c8c8c8;
}

QTreeWidget::item {
    min-height: 22px;
    padding: 2px 4px;
}

QTreeWidget::item:hover {
    background-color: #d2dce6;
}

QTreeWidget::item:selected {
    background-color: #2b6595;
    color: #ffffff;
}

QHeaderView::section {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #e2e2e2, stop:1 #cecece);
    color: #1e242b;
    padding: 5px 8px;
    font-weight: bold;
    font-size: 12px;
    border: none;
    border-right: 1px solid #b4b4b4;
    border-bottom: 2px solid #a8a8a8;
}

QHeaderView::section:hover {
    background: #c8d6e3;
    color: #164e78;
}

QTabWidget::pane {
    border: 1px solid #b0b0b0;
    background-color: #e2e2e2;
    border-radius: 5px;
}

QTabBar::tab {
    background-color: #cecece;
    color: #3b424a;
    padding: 6px 14px;
    border-top-left-radius: 5px;
    border-top-right-radius: 5px;
    margin-right: 3px;
    font-weight: bold;
    font-size: 13px;
    border: 1px solid #a8a8a8;
    border-bottom: none;
    min-width: 90px;
}

QTabBar::tab:selected {
    background-color: #e2e2e2;
    color: #164e78;
    border-top: 3px solid #2b6595;
    border-bottom: none;
}

QStatusBar {
    background-color: #d2d2d2;
    color: #2c333a;
    border-top: 1px solid #b4b4b4;
    padding: 3px 8px;
}

QProgressBar {
    background-color: #d0d0d0;
    border: 1px solid #a8a8a8;
    border-radius: 4px;
    text-align: center;
    color: #1e242b;
    font-weight: bold;
}

QProgressBar::chunk {
    background-color: #2b6595;
    border-radius: 3px;
}

QSplitter::handle {
    background-color: #c2c2c2;
    height: 4px;
}

QSplitter::handle:hover {
    background-color: #2b6595;
}

QMenu {
    background-color: #e6e6e6;
    color: #1e242b;
    border: 1px solid #a0a0a0;
    border-radius: 5px;
    padding: 4px;
}

QMenu::item {
    padding: 5px 18px;
    border-radius: 4px;
}

QMenu::item:selected {
    background-color: #2b6595;
    color: #ffffff;
}

QMenu::separator {
    height: 1px;
    background-color: #bdbdbd;
    margin: 4px 6px;
}

/* Modern slim scrollbars */
QScrollBar:vertical {
    background: #d6d6d6;
    width: 8px;
    margin: 0px;
    border-radius: 4px;
}

QScrollBar::handle:vertical {
    background: #a0a0a0;
    min-height: 25px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background: #808080;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    background: #d6d6d6;
    height: 8px;
    margin: 0px;
    border-radius: 4px;
}

QScrollBar::handle:horizontal {
    background: #a0a0a0;
    min-width: 25px;
    border-radius: 4px;
}

QScrollBar::handle:horizontal:hover {
    background: #808080;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

QSlider::groove:horizontal {
    border: 1px solid #a8a8a8;
    height: 6px;
    background: #cfcfcf;
    margin: 2px 0;
    border-radius: 3px;
}

QSlider::sub-page:horizontal {
    background: #2b6595;
    border: 1px solid #1d4f7a;
    height: 6px;
    border-radius: 3px;
}

QSlider::handle:horizontal {
    background: #1d4f7a;
    border: 1px solid #163d5e;
    width: 14px;
    height: 14px;
    margin: -5px 0;
    border-radius: 7px;
}

QSlider::handle:horizontal:hover {
    background: #2b6595;
    border-color: #1d4f7a;
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
                    background-color: #e2e2e2;
                    border: 1px solid #b0b0b0;
                    border-radius: 6px;
                }
            """)
            self.title_label.setStyleSheet("color: #3b424a; font-size: 11px; font-weight: bold;")

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
        self.setMinimumHeight(95)
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
        self.is_dark = False

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
        bg_col = QColor(14, 20, 31) if self.is_dark else QColor(228, 228, 228)
        border_col = QColor(31, 41, 55) if self.is_dark else QColor(176, 176, 176)
        painter.setBrush(QBrush(bg_col))
        painter.setPen(QPen(border_col, 1))
        painter.drawRoundedRect(QRectF(1, 1, w - 2, h - 2), 6, 6)

        # Subtle Grid lines
        grid_col = QColor(30, 41, 59) if self.is_dark else QColor(200, 200, 200)
        painter.setPen(QPen(grid_col, 1, Qt.DashLine))
        painter.drawLine(10, int(h * 0.40), w - 10, int(h * 0.40))
        painter.drawLine(10, int(h * 0.72), w - 10, int(h * 0.72))

        # Typography
        text_col = QColor(241, 245, 249) if self.is_dark else QColor(30, 36, 43)
        dim_col = QColor(148, 163, 184) if self.is_dark else QColor(85, 95, 105)
        font = QFont("Segoe UI", 9)
        painter.setFont(font)

        if not self.current_ip:
            painter.setPen(dim_col)
            painter.drawText(QRectF(12, 10, w - 24, h - 20), Qt.AlignCenter | Qt.TextWordWrap, "Selecione um dispositivo da lista para monitorar o Ping Dinâmico Instantâneo em tempo real")
            return

        # Header metrics
        painter.setPen(text_col)
        ip_header = f"● Monitorando: {self.current_ip}"
        painter.drawText(12, 18, ip_header)

        accent_color = QColor(56, 189, 248) if self.is_dark else QColor(2, 132, 199)
        fm = QFontMetrics(font)
        avail_w = max(50, w - 24)
        if self.current_rtt >= 0:
            status_text = f"Agora: {self.current_rtt:.2f} ms   |   Mín: {self.min_rtt:.2f} ms  •  Méd: {self.avg_rtt:.2f} ms  •  Máx: {self.max_rtt:.2f} ms"
            if self.ttl > 0:
                status_text += f"   •   TTL: {self.ttl}"
            if self.method:
                status_text += f" ({self.method})"
            painter.setPen(accent_color)
            painter.drawText(12, 34, fm.elidedText(status_text, Qt.ElideRight, avail_w))
        else:
            painter.setPen(QColor(239, 68, 68) if self.is_dark else QColor(220, 38, 38))
            painter.drawText(12, 34, fm.elidedText("● Sem resposta no momento (Offline / Timeout)", Qt.ElideRight, avail_w))

        # Latency Waveform
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
                grad.setColorAt(1, QColor(2, 132, 199, 8))
            else:
                grad.setColorAt(0, QColor(2, 132, 199, 80))
                grad.setColorAt(1, QColor(2, 132, 199, 5))
            painter.fillPath(fill_path, QBrush(grad))

            # Waveform stroke
            stroke_col = QColor(56, 189, 248) if self.is_dark else QColor(2, 132, 199)
            stroke_pen = QPen(stroke_col, 2)
            painter.setPen(stroke_pen)
            for i in range(len(points) - 1):
                painter.drawLine(points[i], points[i + 1])

            # Draw glowing pulse dot on the last sample
            last_p = points[-1]
            dot_brush = QColor(52, 211, 153) if self.is_dark else QColor(16, 185, 129)
            dot_pen = QColor(16, 185, 129) if self.is_dark else QColor(5, 150, 105)
            painter.setBrush(QBrush(dot_brush))
            painter.setPen(QPen(dot_pen, 2))
            painter.drawEllipse(last_p, 4, 4)
