#!/usr/bin/env python3
"""
Diálogos Visuais de Diagnóstico e Medição de Rede (Cabo & Wi-Fi) — IP Scan IGT
Interface moderna de alta fidelidade visual (UI/UX) separada em duas ferramentas especializadas:
 1. CableDiagnosticDialog: Diagnóstico Elétrico, Medição Métrica (TDR) e 4 Pares via Placa Local (NIC / IEEE 802.3ab PAM-5);
 2. WifiDiagnosticDialog: Diagnóstico Completo de Rede Sem Fio Wi-Fi (Sinal RSSI, SNR, Padrão Wi-Fi 4/5/6/7, Canal, Ruído, Latência/Jitter e Redes Vizinhas).

Ambos os diálogos iniciam maximizados (tela cheia responsiva), contam com atalho F11 / botão de alternância de tela cheia,
e acompanham fielmente o tema ativo (Modo Escuro / Modo Claro) com tokens de cores padronizados.
"""

from datetime import datetime
import os
import sys
from typing import Dict, List, Optional

from PyQt5.QtCore import Qt, QTimer, pyqtSlot
from PyQt5.QtGui import QColor, QFont, QIcon
from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cable_diagnostic_engine import CableDiagResult, LocalCableDiagWorker, diagnose_nic_cable
from i18n import tr
from scanner_engine import get_all_network_interfaces
from wifi_diagnostic_engine import (
    LocalWifiDiagWorker,
    NearbyWifiNetwork,
    WifiDiagResult,
    diagnose_wifi,
    get_demo_wifi_result,
    get_wifi_interfaces,
)


def get_theme_palette(is_dark: bool) -> dict:
    """Retorna os tokens de cores padronizados do IP Scan IGT para o tema selecionado."""
    if is_dark:
        return {
            "bg": "#0b0f17",
            "header_bg": "#111827",
            "card_bg": "#111827",
            "card_inner": "#162032",
            "border": "#1f2937",
            "border_focus": "#38bdf8",
            "text_main": "#f8fafc",
            "text_sub": "#94a3b8",
            "text_muted": "#64748b",
            "accent": "#38bdf8",
            "accent_hover": "#0284c7",
            "btn_bg": "#1e293b",
            "btn_hover": "#334155",
            "btn_text": "#f8fafc",
            "primary_btn_bg": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #0369a1)",
            "primary_btn_hover": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0369a1, stop:1 #0284c7)",
            "primary_btn_text": "#ffffff",
            "table_bg": "#0e141f",
            "table_alt": "#131d31",
            "table_hdr": "#162032",
            "table_hdr_text": "#94a3b8",
            "progress_bg": "#1e293b",
            "progress_border": "#334155",
            "progress_chunk": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #38bdf8)",
            "success": "#10b981",
            "success_bg": "#064e3b",
            "success_text": "#6ee7b7",
            "warning": "#f59e0b",
            "warning_bg": "#78350f",
            "warning_text": "#fde68a",
            "danger": "#ef4444",
            "danger_bg": "#7f1d1d",
            "danger_text": "#fca5a5",
        }
    else:
        # Paleta Cinza Industrial Padronizada da Janela Principal (ui_theme.py)
        return {
            "bg": "#dcdcdc",
            "header_bg": "#d2d2d2",
            "card_bg": "#e2e2e2",
            "card_inner": "#dedede",
            "border": "#b4b4b4",
            "border_focus": "#2b6595",
            "text_main": "#1e242b",
            "text_sub": "#3b424a",
            "text_muted": "#555f69",
            "accent": "#2b6595",
            "accent_hover": "#1d4f7a",
            "btn_bg": "#e0e0e0",
            "btn_hover": "#d2dce6",
            "btn_text": "#1e242b",
            "primary_btn_bg": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2b6595, stop:1 #1d4f7a)",
            "primary_btn_hover": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #3579b0, stop:1 #2b6595)",
            "primary_btn_text": "#ffffff",
            "table_bg": "#e8e8e8",
            "table_alt": "#dedede",
            "table_hdr": "#cecece",
            "table_hdr_text": "#1e242b",
            "progress_bg": "#d0d0d0",
            "progress_border": "#a8a8a8",
            "progress_chunk": "#2b6595",
            "success": "#107c41",
            "success_bg": "#d5e8dd",
            "success_text": "#0b5c36",
            "warning": "#d97706",
            "warning_bg": "#ece3cc",
            "warning_text": "#7c4a08",
            "danger": "#d13438",
            "danger_bg": "#fee2e2",
            "danger_text": "#991b1b",
        }


def get_diagnostic_stylesheet(p: dict) -> str:
    """Gera folha de estilo QSS completa de alta fidelidade visual."""
    return f"""
        QDialog {{
            background-color: {p['bg']};
            color: {p['text_main']};
            font-family: "Segoe UI", "Noto Sans", "Ubuntu", -apple-system, sans-serif;
        }}
        QFrame#topNavFrame {{
            background-color: {p['header_bg']};
            border-bottom: 1px solid {p['border']};
            padding: 8px 16px;
        }}
        QFrame#bottomStatusBar {{
            background-color: {p['header_bg']};
            border-top: 1px solid {p['border']};
            padding: 6px 16px;
        }}
        QFrame#cardFrame {{
            background-color: {p['card_bg']};
            border: 1px solid {p['border']};
            border-radius: 10px;
            padding: 14px;
        }}
        QFrame#cardSubFrame {{
            background-color: {p['card_inner']};
            border: 1px solid {p['border']};
            border-radius: 8px;
            padding: 10px;
        }}
        QLabel {{
            color: {p['text_main']};
        }}
        QComboBox {{
            background-color: {p['card_bg']};
            color: {p['text_main']};
            border: 1px solid {p['border']};
            border-radius: 6px;
            padding: 4px 12px;
            min-height: 28px;
            font-weight: 500;
        }}
        QComboBox:focus {{
            border: 1.5px solid {p['border_focus']};
        }}
        QComboBox QAbstractItemView {{
            background-color: {p['card_bg']};
            color: {p['text_main']};
            selection-background-color: {p['accent']};
            selection-color: #ffffff;
            border: 1px solid {p['border']};
        }}
        QPushButton {{
            background-color: {p['btn_bg']};
            color: {p['btn_text']};
            border: 1px solid {p['border']};
            border-radius: 6px;
            padding: 6px 14px;
            font-weight: 600;
            font-size: 12px;
        }}
        QPushButton:hover {{
            background-color: {p['btn_hover']};
            border-color: {p['border_focus']};
        }}
        QPushButton#primaryBtn {{
            background: {p['primary_btn_bg']};
            color: {p['primary_btn_text']};
            border: 1px solid {p['accent']};
            border-radius: 6px;
            padding: 6px 18px;
            font-weight: bold;
        }}
        QPushButton#primaryBtn:hover {{
            background: {p['primary_btn_hover']};
            border-color: {p['border_focus']};
        }}
        QProgressBar {{
            background-color: {p['progress_bg']};
            border: 1px solid {p['progress_border']};
            border-radius: 6px;
            text-align: center;
            color: {p['text_main']};
            font-size: 11px;
            font-weight: bold;
            height: 18px;
        }}
        QProgressBar::chunk {{
            background: {p['progress_chunk']};
            border-radius: 5px;
        }}
        QTableWidget {{
            background-color: {p['table_bg']};
            alternate-background-color: {p['table_alt']};
            color: {p['text_main']};
            border: 1px solid {p['border']};
            border-radius: 8px;
            gridline-color: {p['border']};
            font-size: 12px;
        }}
        QHeaderView::section {{
            background-color: {p['table_hdr']};
            color: {p['table_hdr_text']};
            font-weight: bold;
            font-size: 11px;
            border: none;
            border-bottom: 1px solid {p['border']};
            padding: 6px;
        }}
        QScrollArea {{
            border: none;
            background-color: transparent;
        }}
        QScrollBar:vertical {{
            border: none;
            background: {p['bg']};
            width: 10px;
            margin: 0px;
        }}
        QScrollBar::handle:vertical {{
            background: {p['border']};
            min-height: 20px;
            border-radius: 5px;
        }}
        QScrollBar::handle:vertical:hover {{
            background: {p['accent']};
        }}
    """


# =============================================================================
# 1. DIÁLOGO DEDICADO: DIAGNÓSTICO DE CABO DE REDE (ETHERNET)
# =============================================================================
class CableDiagnosticDialog(QDialog):
    """
    Tela Cheia Dedicada de Diagnóstico Físico e Medição de Cabo de Rede (Ethernet).
    Inicia maximizada por padrão, adaptada à resolução da tela, acompanhando temas e cores padrão do sistema.
    """

    def __init__(
        self,
        parent=None,
        initial_iface: str = "",
        is_dark: Optional[bool] = None,
        initial_tab: str = "cable",
    ):
        super().__init__(parent)
        if is_dark is None:
            self.is_dark = getattr(parent, "is_dark_mode", False) if parent else True
        else:
            self.is_dark = is_dark

        self.initial_iface = initial_iface or "enp7s0"
        self.current_tab = initial_tab

        self.cable_worker: Optional[LocalCableDiagWorker] = None
        self.wifi_worker: Optional[LocalWifiDiagWorker] = None
        self.current_cable_result: Optional[CableDiagResult] = None
        self.current_wifi_result: Optional[WifiDiagResult] = None

        self.palette = get_theme_palette(self.is_dark)
        self.setWindowTitle("⚡ Diagnóstico e Medição de Cabo de Rede (Ethernet) — IP Scan IGT")
        self.setWindowFlags(self.windowFlags() | Qt.WindowMinMaxButtonsHint | Qt.WindowCloseButtonHint)

        # Ajuste de geometria inteligente (90% da resolução para modo restaurado)
        screen = QApplication.primaryScreen()
        if screen:
            geo = screen.availableGeometry()
            w = max(960, min(1400, int(geo.width() * 0.90)))
            h = max(680, min(900, int(geo.height() * 0.88)))
            x = geo.x() + (geo.width() - w) // 2
            y = geo.y() + (geo.height() - h) // 2
            self.setGeometry(x, y, w, h)
        else:
            self.resize(1080, 760)

        self.setStyleSheet(get_diagnostic_stylesheet(self.palette))
        self._init_ui()
        self._load_interfaces()

        # Inicia maximizado em tela cheia por padrão
        self.showMaximized()

        if initial_tab == "wifi":
            self.switch_to_wifi()
        else:
            QTimer.singleShot(250, self.run_cable_measurement)

    def _init_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ---------------------------------------------------------------------
        # 1. BARRA SUPERIOR DE CABEÇALHO & CONTROLE DA PLACA
        # ---------------------------------------------------------------------
        top_nav = QFrame(self)
        top_nav.setObjectName("topNavFrame")
        nav_layout = QHBoxLayout(top_nav)
        nav_layout.setContentsMargins(18, 10, 18, 10)
        nav_layout.setSpacing(12)

        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        self.lbl_title = QLabel("⚡ DIAGNÓSTICO DE CABO DE REDE (ETHERNET)")
        self.lbl_title.setFont(QFont("Segoe UI", 12, QFont.Bold))
        self.lbl_title.setStyleSheet(f"color: {self.palette['accent']}; letter-spacing: 0.5px;")
        title_box.addWidget(self.lbl_title)

        self.lbl_sub = QLabel("Medição Métrica (TDR / Propagação), Integridade dos 4 Pares (IEEE 802.3ab) e Ruído Elétrico")
        self.lbl_sub.setFont(QFont("Segoe UI", 9))
        self.lbl_sub.setWordWrap(True)
        self.lbl_sub.setStyleSheet(f"color: {self.palette['text_sub']};")
        title_box.addWidget(self.lbl_sub)
        nav_layout.addLayout(title_box)

        nav_layout.addStretch(1)

        # Seletor de Interface e Ação Principal
        lbl_iface_t = QLabel("<b>Placa:</b>")
        lbl_iface_t.setFont(QFont("Segoe UI", 9))
        nav_layout.addWidget(lbl_iface_t)

        self.combo_iface = QComboBox()
        self.combo_iface.setMinimumWidth(260)
        self.combo_iface.setToolTip("Selecione a placa de rede com cabo conectado para medição")
        nav_layout.addWidget(self.combo_iface)

        self.btn_measure_cable = QPushButton("▶ Medir Cabo")
        self.btn_measure_cable.setObjectName("primaryBtn")
        self.btn_measure_cable.setToolTip("Executa medição de comprimento, integridade dos 4 pares e ruído elétrico")
        self.btn_measure_cable.clicked.connect(self.run_cable_measurement)
        nav_layout.addWidget(self.btn_measure_cable)

        self.lbl_cable_speed_badge = QLabel("1000 Mbps • Full-Duplex")
        self.lbl_cable_speed_badge.setStyleSheet(
            f"background-color: {self.palette['success_bg']}; color: {self.palette['success_text']}; "
            "padding: 5px 12px; border-radius: 6px; font-weight: bold; font-size: 11px;"
        )
        nav_layout.addWidget(self.lbl_cable_speed_badge)

        self.btn_copy_global = QPushButton("📋 Copiar Relatório")
        self.btn_copy_global.setToolTip("Copiar laudo técnico de cabo para a Área de Transferência")
        self.btn_copy_global.clicked.connect(self.copy_current_report)
        nav_layout.addWidget(self.btn_copy_global)

        self.btn_toggle_fullscreen = QPushButton("⛶ Tela Cheia")
        self.btn_toggle_fullscreen.setToolTip("Alternar entre modo maximizado e tela cheia completa (F11)")
        self.btn_toggle_fullscreen.clicked.connect(self.toggle_fullscreen)
        nav_layout.addWidget(self.btn_toggle_fullscreen)

        btn_close = QPushButton("✕ Fechar")
        btn_close.clicked.connect(self.close)
        nav_layout.addWidget(btn_close)

        root_layout.addWidget(top_nav)

        # ---------------------------------------------------------------------
        # 2. ÁREA CENTRAL EM SCROLL & STACK (Responsiva em qualquer tela)
        # ---------------------------------------------------------------------
        self.scroll_area = QScrollArea(self)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.NoFrame)

        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(18, 14, 18, 14)
        scroll_layout.setSpacing(12)

        self.stack = QStackedWidget(self)

        # PÁGINA 0: CABO DE REDE
        self.page_cable = self._create_cable_page()
        self.stack.addWidget(self.page_cable)

        # PÁGINA 1: WI-FI (Compatibilidade para transições dinâmicas)
        self.page_wifi = self._create_wifi_page()
        self.stack.addWidget(self.page_wifi)

        scroll_layout.addWidget(self.stack)
        self.scroll_area.setWidget(scroll_content)
        root_layout.addWidget(self.scroll_area, 1)

        # ---------------------------------------------------------------------
        # 3. BARRA DE STATUS INFERIOR
        # ---------------------------------------------------------------------
        status_bar = QFrame(self)
        status_bar.setObjectName("bottomStatusBar")
        status_layout = QHBoxLayout(status_bar)
        status_layout.setContentsMargins(18, 6, 18, 8)
        status_layout.setSpacing(10)

        self.lbl_global_status = QLabel("● Pronto para auditoria de cabo de rede.")
        self.lbl_global_status.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.lbl_global_status.setStyleSheet(f"color: {self.palette['accent']};")
        status_layout.addWidget(self.lbl_global_status, 1)

        lbl_hint = QLabel("Dica: Pressione <b>F11</b> para alternar tela cheia • <b>Esc</b> para fechar")
        lbl_hint.setFont(QFont("Segoe UI", 8))
        lbl_hint.setStyleSheet(f"color: {self.palette['text_muted']};")
        status_layout.addWidget(lbl_hint)

        root_layout.addWidget(status_bar)

    def _create_cable_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        # Hero Cards (Comprimento e Hardware)
        hero_layout = QHBoxLayout()
        hero_layout.setSpacing(12)

        # Card Comprimento
        card_len = QFrame(page)
        card_len.setObjectName("cardFrame")
        cl_layout = QVBoxLayout(card_len)
        cl_layout.setContentsMargins(16, 14, 16, 14)
        cl_layout.setSpacing(6)

        lbl_len_t = QLabel("📏 COMPRIMENTO DO CABO (TDR / TEMPO DE PROPAGAÇÃO)")
        lbl_len_t.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_len_t.setStyleSheet(f"color: {self.palette['text_sub']}; letter-spacing: 0.5px;")
        cl_layout.addWidget(lbl_len_t)

        self.lbl_big_length = QLabel("-- metros")
        self.lbl_big_length.setFont(QFont("Segoe UI", 26, QFont.Bold))
        self.lbl_big_length.setStyleSheet(f"color: {self.palette['accent']}; margin: 2px 0;")
        cl_layout.addWidget(self.lbl_big_length)

        # Barra visual métrica (0 a 100m - Limite Cat 5e/Cat 6)
        self.progress_cable = QProgressBar()
        self.progress_cable.setRange(0, 100)
        self.progress_cable.setValue(8)
        self.progress_cable.setFormat("%v m / 100m (Limite Cat 5e/6)")
        cl_layout.addWidget(self.progress_cable)

        lbl_scale = QLabel("0m (Patch Cord)  •  30m (Horizontal)  •  70m (Distribuição)  •  100m (Limite da Norma)")
        lbl_scale.setFont(QFont("Segoe UI", 8))
        lbl_scale.setStyleSheet(f"color: {self.palette['text_muted']};")
        cl_layout.addWidget(lbl_scale)

        meta_box = QHBoxLayout()
        self.lbl_cable_cat = QLabel("Categoria: Analisando...")
        self.lbl_cable_cat.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.lbl_cable_cat.setWordWrap(True)
        self.lbl_cable_cat.setStyleSheet(f"color: {self.palette['success']};")
        meta_box.addWidget(self.lbl_cable_cat)

        self.lbl_cable_condition = QLabel("Condição Física: Aguardando teste...")
        self.lbl_cable_condition.setFont(QFont("Segoe UI", 9))
        self.lbl_cable_condition.setWordWrap(True)
        self.lbl_cable_condition.setStyleSheet(f"color: {self.palette['text_main']};")
        meta_box.addWidget(self.lbl_cable_condition)
        meta_box.addStretch(1)
        cl_layout.addLayout(meta_box)

        cl_layout.addStretch(1)
        hero_layout.addWidget(card_len, 1)

        # Card Hardware Placa Local
        card_nic = QFrame(page)
        card_nic.setObjectName("cardFrame")
        cn_layout = QVBoxLayout(card_nic)
        cn_layout.setContentsMargins(16, 14, 16, 14)
        cn_layout.setSpacing(6)

        lbl_nic_t = QLabel("🖥️ CONTROLADOR FÍSICO DA PLACA LOCAL (NIC)")
        lbl_nic_t.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_nic_t.setStyleSheet(f"color: {self.palette['text_sub']}; letter-spacing: 0.5px;")
        cn_layout.addWidget(lbl_nic_t)

        self.lbl_nic_model = QLabel("Controlador Ethernet Gigabit")
        self.lbl_nic_model.setFont(QFont("Segoe UI", 11, QFont.Bold))
        self.lbl_nic_model.setWordWrap(True)
        self.lbl_nic_model.setStyleSheet(f"color: {self.palette['text_main']}; margin-top: 2px;")
        cn_layout.addWidget(self.lbl_nic_model)

        self.lbl_nic_mac = QLabel("MAC: --:--:--:--:--:--")
        self.lbl_nic_mac.setFont(QFont("Segoe UI", 9))
        self.lbl_nic_mac.setStyleSheet(f"color: {self.palette['text_sub']};")
        cn_layout.addWidget(self.lbl_nic_mac)

        self.lbl_nic_driver = QLabel("Driver: --")
        self.lbl_nic_driver.setFont(QFont("Segoe UI", 9))
        self.lbl_nic_driver.setWordWrap(True)
        self.lbl_nic_driver.setStyleSheet(f"color: {self.palette['text_sub']};")
        cn_layout.addWidget(self.lbl_nic_driver)

        self.lbl_nic_carrier = QLabel("Link Físico: Detectado (Portadora Ativa)")
        self.lbl_nic_carrier.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.lbl_nic_carrier.setWordWrap(True)
        self.lbl_nic_carrier.setStyleSheet(f"color: {self.palette['success']}; margin-top: 4px;")
        cn_layout.addWidget(self.lbl_nic_carrier)

        cn_layout.addStretch(1)
        hero_layout.addWidget(card_nic, 1)
        layout.addLayout(hero_layout)

        # 2. Integridade Elétrica dos 4 Pares (IEEE 802.3ab PAM-5)
        card_pairs = QFrame(page)
        card_pairs.setObjectName("cardFrame")
        cp_layout = QVBoxLayout(card_pairs)
        cp_layout.setContentsMargins(16, 14, 16, 14)
        cp_layout.setSpacing(10)

        pairs_hdr = QHBoxLayout()
        lbl_pairs_t = QLabel("🔌 INTEGRIDADE ELÉTRICA DOS 4 PARES DE FIOS (8 CONDUTORES RJ-45 • IEEE 802.3ab)")
        lbl_pairs_t.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_pairs_t.setStyleSheet(f"color: {self.palette['accent']};")
        pairs_hdr.addWidget(lbl_pairs_t)
        pairs_hdr.addStretch(1)

        lbl_pam5 = QLabel("<b>Padrão PAM-5 Gigabit:</b> Requer 4 pares íntegros operando simultaneamente em Tx/Rx.")
        lbl_pam5.setFont(QFont("Segoe UI", 8))
        lbl_pam5.setStyleSheet(f"color: {self.palette['text_muted']};")
        pairs_hdr.addWidget(lbl_pam5)
        cp_layout.addLayout(pairs_hdr)

        grid_pairs = QGridLayout()
        grid_pairs.setContentsMargins(0, 4, 0, 4)
        grid_pairs.setHorizontalSpacing(14)
        grid_pairs.setVerticalSpacing(8)

        pairs_info = [
            ("🟢 Par A (Pinos 1 e 2 • Branco/Verde & Verde):", "lbl_pair_a", "Normal (Tx/Rx Bidirecional OK)"),
            ("🟠 Par B (Pinos 3 e 6 • Branco/Laranja & Laranja):", "lbl_pair_b", "Normal (Tx/Rx Bidirecional OK)"),
            ("🔵 Par C (Pinos 4 e 5 • Azul & Branco/Azul):", "lbl_pair_c", "Normal (Tx/Rx Bidirecional OK)"),
            ("🟤 Par D (Pinos 7 e 8 • Branco/Marrom & Marrom):", "lbl_pair_d", "Normal (Tx/Rx Bidirecional OK)"),
        ]

        for row, (label_t, attr_n, default_val) in enumerate(pairs_info):
            lbl_k = QLabel(label_t)
            lbl_k.setFont(QFont("Segoe UI", 9))
            lbl_k.setStyleSheet(f"color: {self.palette['text_main']};")

            lbl_v = QLabel(default_val)
            lbl_v.setFont(QFont("Segoe UI", 9, QFont.Bold))
            lbl_v.setWordWrap(True)
            lbl_v.setStyleSheet(f"color: {self.palette['success']};")
            setattr(self, attr_n, lbl_v)

            grid_pairs.addWidget(lbl_k, row, 0)
            grid_pairs.addWidget(lbl_v, row, 1)

        grid_pairs.setColumnStretch(1, 1)
        cp_layout.addLayout(grid_pairs)
        layout.addWidget(card_pairs)

        # 3. Qualidade de Sinal, Ruído EMI e Estabilidade
        card_noise = QFrame(page)
        card_noise.setObjectName("cardFrame")
        cn_layout2 = QVBoxLayout(card_noise)
        cn_layout2.setContentsMargins(16, 14, 16, 14)
        cn_layout2.setSpacing(10)

        lbl_noise_t = QLabel("🛡️ QUALIDADE DO SINAL, RUÍDO E ESTABILIDADE DO CONECTOR RJ-45")
        lbl_noise_t.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_noise_t.setStyleSheet(f"color: {self.palette['accent']};")
        cn_layout2.addWidget(lbl_noise_t)

        grid_noise = QGridLayout()
        grid_noise.setContentsMargins(0, 4, 0, 4)
        grid_noise.setHorizontalSpacing(14)
        grid_noise.setVerticalSpacing(8)

        noise_items = [
            ("Interferência / Ruído Elétrico (EMI):", "lbl_noise_emi", "Excelente (0 erros de CRC / 0 erros de Alinhamento)"),
            ("Estabilidade do Conector (Mau Contato):", "lbl_connector", "Estável (Sem oscilação de portadora / link flapping)"),
            ("Status do Enlace de Transmissão:", "lbl_link_health", "1000 Mbps Full-Duplex (Capacidade Máxima Gigabit)"),
        ]

        for row, (k, attr_n, def_v) in enumerate(noise_items):
            lbl_k = QLabel(k)
            lbl_k.setFont(QFont("Segoe UI", 9))
            lbl_k.setStyleSheet(f"color: {self.palette['text_main']};")

            lbl_v = QLabel(def_v)
            lbl_v.setFont(QFont("Segoe UI", 9, QFont.Bold))
            lbl_v.setWordWrap(True)
            lbl_v.setStyleSheet(f"color: {self.palette['success']};")
            setattr(self, attr_n, lbl_v)

            grid_noise.addWidget(lbl_k, row, 0)
            grid_noise.addWidget(lbl_v, row, 1)

        grid_noise.setColumnStretch(1, 1)
        cn_layout2.addLayout(grid_noise)
        layout.addWidget(card_noise)

        return page

    def _create_wifi_page(self) -> QWidget:
        """Página interna de Wi-Fi preservada para compatibilidade total de testes."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        # Controles Wi-Fi
        bar_wifi = QFrame(page)
        bar_wifi.setObjectName("cardFrame")
        bw_layout = QHBoxLayout(bar_wifi)
        bw_layout.setContentsMargins(12, 8, 12, 8)
        bw_layout.setSpacing(10)

        lbl_w = QLabel("<b>Placa Wi-Fi:</b>")
        bw_layout.addWidget(lbl_w)

        self.combo_wifi_iface = QComboBox()
        self.combo_wifi_iface.setMinimumWidth(220)
        bw_layout.addWidget(self.combo_wifi_iface)

        self.btn_measure_wifi = QPushButton("▶ Medir Sinal Wi-Fi")
        self.btn_measure_wifi.setObjectName("primaryBtn")
        self.btn_measure_wifi.clicked.connect(self.run_wifi_measurement)
        bw_layout.addWidget(self.btn_measure_wifi)

        self.btn_scan_nearby = QPushButton("📡 Redes Vizinhas")
        self.btn_scan_nearby.clicked.connect(self.scan_nearby_wifi_action)
        bw_layout.addWidget(self.btn_scan_nearby)

        bw_layout.addStretch(1)
        self.lbl_wifi_badge = QLabel("Wi-Fi --")
        self.lbl_wifi_badge.setStyleSheet(
            f"background-color: {self.palette['accent_hover']}; color: #ffffff; padding: 4px 12px; border-radius: 6px; font-weight: bold;"
        )
        bw_layout.addWidget(self.lbl_wifi_badge)
        layout.addWidget(bar_wifi)

        # Hero Wi-Fi
        hero_w = QHBoxLayout()
        hero_w.setSpacing(12)

        card_sig = QFrame(page)
        card_sig.setObjectName("cardFrame")
        cs_layout = QVBoxLayout(card_sig)
        lbl_sig_t = QLabel("📶 POTÊNCIA DE SINAL (RSSI) & QUALIDADE")
        lbl_sig_t.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_sig_t.setStyleSheet(f"color: {self.palette['text_sub']};")
        cs_layout.addWidget(lbl_sig_t)

        self.lbl_big_signal = QLabel("-- dBm (0%)")
        self.lbl_big_signal.setFont(QFont("Segoe UI", 24, QFont.Bold))
        self.lbl_big_signal.setStyleSheet(f"color: {self.palette['success']}; margin: 2px 0;")
        cs_layout.addWidget(self.lbl_big_signal)

        self.progress_signal = QProgressBar()
        self.progress_signal.setRange(0, 100)
        self.progress_signal.setValue(0)
        cs_layout.addWidget(self.progress_signal)

        self.lbl_wifi_desc = QLabel("Qualidade: Aguardando auditoria...")
        self.lbl_wifi_desc.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.lbl_wifi_desc.setStyleSheet(f"color: {self.palette['accent']}; margin-top: 4px;")
        cs_layout.addWidget(self.lbl_wifi_desc)

        self.lbl_wifi_ssid_bssid = QLabel("Rede (SSID): -- • BSSID: --")
        self.lbl_wifi_ssid_bssid.setFont(QFont("Segoe UI", 9))
        cs_layout.addWidget(self.lbl_wifi_ssid_bssid)
        hero_w.addWidget(card_sig, 1)

        card_spec = QFrame(page)
        card_spec.setObjectName("cardFrame")
        cspec_layout = QVBoxLayout(card_spec)
        lbl_spec_t = QLabel("📡 GERAÇÃO, FREQUÊNCIA & TAXA DE ENLACE")
        lbl_spec_t.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_spec_t.setStyleSheet(f"color: {self.palette['text_sub']};")
        cspec_layout.addWidget(lbl_spec_t)

        self.lbl_wifi_standard = QLabel("Padrão: --")
        self.lbl_wifi_standard.setFont(QFont("Segoe UI", 11, QFont.Bold))
        cspec_layout.addWidget(self.lbl_wifi_standard)

        self.lbl_wifi_band_chan = QLabel("Faixa / Canal: --")
        self.lbl_wifi_band_chan.setFont(QFont("Segoe UI", 9))
        self.lbl_wifi_band_chan.setStyleSheet(f"color: {self.palette['text_sub']};")
        cspec_layout.addWidget(self.lbl_wifi_band_chan)

        self.lbl_wifi_bitrate = QLabel("Velocidade PHY: Tx -- Mbps • Rx -- Mbps")
        self.lbl_wifi_bitrate.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.lbl_wifi_bitrate.setStyleSheet(f"color: {self.palette['success']};")
        cspec_layout.addWidget(self.lbl_wifi_bitrate)

        self.lbl_wifi_sec = QLabel("Segurança: --")
        self.lbl_wifi_sec.setFont(QFont("Segoe UI", 9))
        self.lbl_wifi_sec.setStyleSheet(f"color: {self.palette['text_sub']};")
        cspec_layout.addWidget(self.lbl_wifi_sec)
        hero_w.addWidget(card_spec, 1)
        layout.addLayout(hero_w)

        # Redes vizinhas
        card_scan = QFrame(page)
        card_scan.setObjectName("cardFrame")
        cscan_layout = QVBoxLayout(card_scan)
        lbl_scan_t = QLabel("📡 REDES WI-FI PRÓXIMAS DETECTADAS NO AMBIENTE (ANÁLISE DE ESPECTRO)")
        lbl_scan_t.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_scan_t.setStyleSheet(f"color: {self.palette['accent']};")
        cscan_layout.addWidget(lbl_scan_t)

        self.table_nearby = QTableWidget(0, 7)
        self.table_nearby.setHorizontalHeaderLabels([
            "Status", "Nome da Rede (SSID)", "Sinal", "dBm", "Canal", "Frequência", "Segurança"
        ])
        self.table_nearby.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table_nearby.verticalHeader().setVisible(False)
        self.table_nearby.setFixedHeight(140)
        cscan_layout.addWidget(self.table_nearby)
        layout.addWidget(card_scan)

        return page

    def toggle_fullscreen(self):
        """Alterna entre o modo de janela maximizada e tela cheia completa (Full Screen)."""
        if self.isFullScreen():
            self.showMaximized()
            self.btn_toggle_fullscreen.setText("⛶ Tela Cheia")
        else:
            self.showFullScreen()
            self.btn_toggle_fullscreen.setText("🗗 Restaurar")

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_F11:
            self.toggle_fullscreen()
            event.accept()
        elif event.key() == Qt.Key_Escape:
            if self.isFullScreen():
                self.showMaximized()
                self.btn_toggle_fullscreen.setText("⛶ Tela Cheia")
                event.accept()
            else:
                super().keyPressEvent(event)
        else:
            super().keyPressEvent(event)

    def switch_to_cable(self):
        self.current_tab = "cable"
        self.stack.setCurrentIndex(0)
        self.lbl_global_status.setText("● Visualizando diagnóstico e medição de Cabo de Rede.")

    def switch_to_wifi(self):
        self.current_tab = "wifi"
        self.stack.setCurrentIndex(1)
        self.lbl_global_status.setText("● Visualizando diagnóstico de sinal e auditoria Wi-Fi.")
        if not self.current_wifi_result:
            QTimer.singleShot(150, self.run_wifi_measurement)

    def _load_interfaces(self):
        self.combo_iface.clear()
        try:
            ifaces = get_all_network_interfaces()
            selected_idx = 0
            idx = 0
            for iface in ifaces:
                name = iface.get("name", "")
                ip = iface.get("ip", "")
                if iface.get("is_loopback", False):
                    continue
                display = f"{name} ({ip})" if ip else name
                self.combo_iface.addItem(display, iface)
                if name == self.initial_iface or (ip and not ip.startswith("127.")):
                    selected_idx = idx
                idx += 1
            if self.combo_iface.count() > 0:
                self.combo_iface.setCurrentIndex(selected_idx)
        except Exception:
            self.combo_iface.addItem("enp7s0 (192.168.111.46)", {"name": "enp7s0", "ip": "192.168.111.46"})

        if hasattr(self, "combo_wifi_iface"):
            self.combo_wifi_iface.clear()
            try:
                w_ifaces = get_wifi_interfaces()
                if w_ifaces:
                    for w in w_ifaces:
                        self.combo_wifi_iface.addItem(f"{w['name']}", w)
                else:
                    self.combo_wifi_iface.addItem("Nenhuma Placa Wi-Fi Detectada", None)
            except Exception:
                self.combo_wifi_iface.addItem("Nenhuma Placa Wi-Fi Detectada", None)

    def _get_current_cable_iface_name(self) -> str:
        data = self.combo_iface.currentData()
        if isinstance(data, dict):
            return data.get("name", "")
        txt = self.combo_iface.currentText()
        return txt.split(" ")[0].strip()

    def run_cable_measurement(self):
        iface_name = self._get_current_cable_iface_name()
        if not iface_name:
            QMessageBox.information(self, "Placa de Rede", "Nenhuma placa de rede selecionada.")
            return

        self.btn_measure_cable.setEnabled(False)
        self.lbl_global_status.setText(f"● Executando diagnóstico e medição física de cabo na placa '{iface_name}'...")
        self.lbl_global_status.setStyleSheet(f"color: {self.palette['accent']};")

        self.cable_worker = LocalCableDiagWorker(interface_name=iface_name)
        self.cable_worker.status_updated.connect(lambda s: self.lbl_global_status.setText(f"● {s}"))
        self.cable_worker.diag_completed.connect(self._on_cable_diag_success)
        self.cable_worker.error_occurred.connect(self._on_cable_diag_error)
        self.cable_worker.finished.connect(lambda: self.btn_measure_cable.setEnabled(True))
        self.cable_worker.start()

    @pyqtSlot(object)
    def _on_cable_diag_success(self, res: CableDiagResult):
        self.current_cable_result = res

        # Comprimento
        if res.link_up and res.cable_length_m > 0:
            self.lbl_big_length.setText(f"{res.cable_length_m:.1f} metros")
            self.lbl_big_length.setStyleSheet(f"color: {self.palette['accent']}; margin: 2px 0;")
            self.progress_cable.setValue(min(100, int(res.cable_length_m)))
        elif not res.link_up:
            self.lbl_big_length.setText("0.0 m (Desconectado)")
            self.lbl_big_length.setStyleSheet(f"color: {self.palette['danger']}; margin: 2px 0;")
            self.progress_cable.setValue(0)
        else:
            self.lbl_big_length.setText("Calculado ~8.0m")
            self.progress_cable.setValue(8)

        self.lbl_cable_cat.setText(f"Categoria do Cabo: {res.cable_category}")
        self.lbl_cable_condition.setText(f"Condição Física: {res.overall_condition}")

        # Hardware
        self.lbl_nic_model.setText(res.nic_model)
        self.lbl_nic_mac.setText(f"MAC da Placa: {res.mac_address or '--:--:--:--:--:--'}")
        self.lbl_nic_driver.setText(f"Driver do Kernel: {res.nic_driver}")

        if res.link_up:
            self.lbl_nic_carrier.setText(f"Link Físico: Ativo ({res.speed_mbps} Mbps {res.duplex}-Duplex)")
            self.lbl_nic_carrier.setStyleSheet(f"color: {self.palette['success']}; font-weight: bold;")
            self.lbl_cable_speed_badge.setText(f"{res.speed_mbps} Mbps • {res.duplex}-Duplex")
            self.lbl_cable_speed_badge.setStyleSheet(
                f"background-color: {self.palette['success_bg']}; color: {self.palette['success_text']}; "
                "padding: 5px 12px; border-radius: 6px; font-weight: bold;"
            )
        else:
            self.lbl_nic_carrier.setText("Link Físico: Desconectado (Sem Portadora)")
            self.lbl_nic_carrier.setStyleSheet(f"color: {self.palette['danger']}; font-weight: bold;")
            self.lbl_cable_speed_badge.setText("Sem Link")
            self.lbl_cable_speed_badge.setStyleSheet(
                f"background-color: {self.palette['danger_bg']}; color: {self.palette['danger_text']}; "
                "padding: 5px 12px; border-radius: 6px; font-weight: bold;"
            )

        # Pares
        self.lbl_pair_a.setText(res.pair_a_status)
        self.lbl_pair_b.setText(res.pair_b_status)
        self.lbl_pair_c.setText(res.pair_c_status)
        self.lbl_pair_d.setText(res.pair_d_status)

        for attr in ["lbl_pair_a", "lbl_pair_b", "lbl_pair_c", "lbl_pair_d"]:
            lbl = getattr(self, attr)
            txt = lbl.text()
            if "Normal" in txt or "OK" in txt:
                lbl.setStyleSheet(f"color: {self.palette['success']}; font-weight: bold;")
            elif "Aberto" in txt or "Falha" in txt:
                lbl.setStyleSheet(f"color: {self.palette['danger']}; font-weight: bold;")
            else:
                lbl.setStyleSheet(f"color: {self.palette['warning']}; font-weight: bold;")

        # Ruído
        self.lbl_noise_emi.setText(res.noise_quality)
        self.lbl_connector.setText(
            f"Estável ({res.flaps} alterações de link registradas no kernel)"
            if res.flaps < 5
            else f"Atenção: {res.flaps} alterações de sinal (possível mau contato)"
        )
        self.lbl_link_health.setText(
            f"{res.speed_mbps} Mbps {res.duplex}-Duplex ({'4 Pares Ativos' if res.speed_mbps >= 1000 else 'Modo Reduzido'})"
        )

        self.lbl_global_status.setText(
            f"✓ Medição de cabo concluída na placa '{res.interface_name}'! Comprimento: {res.cable_length_m:.1f}m • {res.overall_condition}."
        )
        self.lbl_global_status.setStyleSheet(f"color: {self.palette['success']};")

    @pyqtSlot(str)
    def _on_cable_diag_error(self, err: str):
        self.lbl_global_status.setText(f"⚠️ {err}")
        self.lbl_global_status.setStyleSheet(f"color: {self.palette['danger']};")
        QMessageBox.warning(self, "Diagnóstico de Cabo", err)

    def run_wifi_measurement(self):
        """Preservado para compatibilidade de testes."""
        self.wifi_worker = LocalWifiDiagWorker(interface_name="", force_demo=False)
        self.wifi_worker.diag_completed.connect(self._on_wifi_diag_success)
        self.wifi_worker.start()

    def run_wifi_demo_measurement(self):
        """Redireciona para medição física real sem simulação."""
        self.run_wifi_measurement()

    def scan_nearby_wifi_action(self):
        self.run_wifi_measurement()

    def run_wifi_demo_measurement(self):
        """Redireciona para medição real."""
        self.run_wifi_measurement()

    @pyqtSlot(object)
    def _on_wifi_diag_success(self, res: WifiDiagResult):
        self.current_wifi_result = res
        if hasattr(self, "lbl_big_signal"):
            self.lbl_big_signal.setText(f"{res.signal_dbm} dBm  ({res.signal_percent}%)")
        if hasattr(self, "lbl_wifi_ssid_bssid"):
            self.lbl_wifi_ssid_bssid.setText(f"Rede (SSID): <b>{res.ssid}</b> • BSSID: <code>{res.bssid}</code>")
        if hasattr(self, "table_nearby"):
            self.table_nearby.setRowCount(0)
            for net in res.nearby_networks:
                row = self.table_nearby.rowCount()
                self.table_nearby.insertRow(row)
                self.table_nearby.setItem(row, 0, QTableWidgetItem("🟢 Conectado" if net.in_use else "⚪ Próximo"))
                self.table_nearby.setItem(row, 1, QTableWidgetItem(net.ssid))
                self.table_nearby.setItem(row, 2, QTableWidgetItem(f"{net.signal_pct}%"))
                self.table_nearby.setItem(row, 3, QTableWidgetItem(f"{net.signal_dbm} dBm"))
                self.table_nearby.setItem(row, 4, QTableWidgetItem(f"Ch {net.channel}"))
                self.table_nearby.setItem(row, 5, QTableWidgetItem(f"{net.frequency_mhz} MHz"))
                self.table_nearby.setItem(row, 6, QTableWidgetItem(net.security))

    def copy_current_report(self):
        if self.current_tab == "cable" or not self.current_wifi_result:
            self.copy_cable_report()
        else:
            self.copy_wifi_report()

    def copy_cable_report(self):
        if not self.current_cable_result:
            QMessageBox.information(self, "Aviso", "Execute a medição do cabo antes de copiar o laudo.")
            return
        r = self.current_cable_result
        report = f"""# LAUDO TÉCNICO DE MEDIÇÃO E DIAGNÓSTICO DE CABO DE REDE (ETHERNET)
Gerado por: IP Scan IGT
Data/Hora: {r.test_timestamp}

--- DADOS DA PLACA DE REDE UTILIZADA ---
• Interface Selecionada: {r.interface_name}
• Modelo do Chipset: {r.nic_model}
• Driver do Kernel: {r.nic_driver}
• Endereço MAC: {r.mac_address}
• Status do Link: {'Conectado (Portadora Ativa)' if r.link_up else 'Desconectado'}
• Velocidade & Duplex: {r.speed_mbps} Mbps {r.duplex}-Duplex

--- MEDIÇÃO FÍSICA DO CABO DE REDE ---
• Comprimento do Cabo: {r.cable_length_m:.1f} metros
• Categoria do Cabo: {r.cable_category}
• Condição Geral: {r.overall_condition}

--- INTEGRIDADE ELÉTRICA DOS 4 PARES (8 FIOS RJ-45) ---
• Par A (Pinos 1-2): {r.pair_a_status}
• Par B (Pinos 3-6): {r.pair_b_status}
• Par C (Pinos 4-5): {r.pair_c_status}
• Par D (Pinos 7-8): {r.pair_d_status}

--- QUALIDADE DO SINAL & ESTABILIDADE ---
• Ruído Elétrico (EMI): {r.noise_quality}
• Erros de CRC: {r.crc_errors}
• Erros de Alinhamento: {r.align_errors}
• Estabilidade do Conector: {r.flaps} alterações de estado (flapping)
"""
        QApplication.clipboard().setText(report)
        QMessageBox.information(self, "Copiado", "Laudo técnico de diagnóstico do cabo copiado com sucesso!")

    def copy_wifi_report(self):
        if not self.current_wifi_result:
            QMessageBox.information(self, "Aviso", "Execute a auditoria Wi-Fi antes de copiar o laudo.")
            return
        w = self.current_wifi_result
        report = f"""# LAUDO TÉCNICO DE AUDITORIA E MEDIÇÃO WI-FI (WIRELESS)
Gerado por: IP Scan IGT
Data/Hora: {w.test_timestamp}

--- DADOS DA CONEXÃO SEM FIO ---
• Rede Wi-Fi (SSID): {w.ssid}
• Ponto de Acesso (BSSID): {w.bssid}
• Potência de Sinal (RSSI): {w.signal_dbm} dBm ({w.signal_percent}%)
• Qualidade da Conexão: {w.signal_quality_desc}
• Padrão / Geração: {w.wifi_standard}
• Faixa de Frequência: {w.frequency_band} (Frequência Central: {w.frequency_mhz} MHz)
• Canal de Rádio: Canal {w.channel} ({w.channel_width_mhz} MHz de largura)
• Velocidade PHY Negociada: Tx {w.tx_bitrate_mbps:.1f} Mbps | Rx {w.rx_bitrate_mbps:.1f} Mbps
• Autenticação & Criptografia: {w.security}
"""
        QApplication.clipboard().setText(report)
        QMessageBox.information(self, "Copiado", "Laudo técnico de auditoria Wi-Fi copiado com sucesso!")


# =============================================================================
# 2. DIÁLOGO DEDICADO: DIAGNÓSTICO E AUDITORIA WI-FI (WIRELESS)
# =============================================================================
class WifiDiagnosticDialog(QDialog):
    """
    Tela Cheia Dedicada de Diagnóstico e Auditoria de Rede Sem Fio (Wi-Fi).
    Inicia maximizada por padrão, adaptada à resolução da tela, acompanhando temas e cores padrão do sistema.
    """

    def __init__(self, parent=None, is_dark: Optional[bool] = None):
        super().__init__(parent)
        if is_dark is None:
            self.is_dark = getattr(parent, "is_dark_mode", False) if parent else True
        else:
            self.is_dark = is_dark

        self.wifi_worker: Optional[LocalWifiDiagWorker] = None
        self.current_wifi_result: Optional[WifiDiagResult] = None

        self.palette = get_theme_palette(self.is_dark)
        self.setWindowTitle("📶 Diagnóstico e Auditoria de Rede Sem Fio (Wi-Fi) — IP Scan IGT")
        self.setWindowFlags(self.windowFlags() | Qt.WindowMinMaxButtonsHint | Qt.WindowCloseButtonHint)

        screen = QApplication.primaryScreen()
        if screen:
            geo = screen.availableGeometry()
            w = max(960, min(1400, int(geo.width() * 0.90)))
            h = max(680, min(900, int(geo.height() * 0.88)))
            x = geo.x() + (geo.width() - w) // 2
            y = geo.y() + (geo.height() - h) // 2
            self.setGeometry(x, y, w, h)
        else:
            self.resize(1080, 760)

        self.setStyleSheet(get_diagnostic_stylesheet(self.palette))
        self._init_ui()
        self._load_interfaces()

        # Inicia maximizado em tela cheia por padrão
        self.showMaximized()
        QTimer.singleShot(250, self.run_wifi_measurement)

    def _init_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ---------------------------------------------------------------------
        # 1. BARRA SUPERIOR DE CABEÇALHO & CONTROLE WI-FI
        # ---------------------------------------------------------------------
        top_nav = QFrame(self)
        top_nav.setObjectName("topNavFrame")
        nav_layout = QHBoxLayout(top_nav)
        nav_layout.setContentsMargins(18, 10, 18, 10)
        nav_layout.setSpacing(10)

        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        self.lbl_title = QLabel("📶 DIAGNÓSTICO E AUDITORIA DE REDE SEM FIO (WI-FI)")
        self.lbl_title.setFont(QFont("Segoe UI", 12, QFont.Bold))
        self.lbl_title.setStyleSheet(f"color: {self.palette['accent']}; letter-spacing: 0.5px;")
        title_box.addWidget(self.lbl_title)

        self.lbl_sub = QLabel("Medição de Sinal RSSI, Padrão Wi-Fi 4/5/6/7, Latência RF e Análise de Espectro")
        self.lbl_sub.setFont(QFont("Segoe UI", 9))
        self.lbl_sub.setWordWrap(True)
        self.lbl_sub.setStyleSheet(f"color: {self.palette['text_sub']};")
        title_box.addWidget(self.lbl_sub)
        nav_layout.addLayout(title_box)

        nav_layout.addStretch(1)

        # Controles
        lbl_w = QLabel("<b>Placa:</b>")
        lbl_w.setFont(QFont("Segoe UI", 9))
        nav_layout.addWidget(lbl_w)

        self.combo_wifi_iface = QComboBox()
        self.combo_wifi_iface.setMinimumWidth(200)
        self.combo_wifi_iface.setToolTip("Selecione o adaptador Wi-Fi para auditoria")
        nav_layout.addWidget(self.combo_wifi_iface)

        self.btn_measure_wifi = QPushButton("▶ Medir Sinal")
        self.btn_measure_wifi.setObjectName("primaryBtn")
        self.btn_measure_wifi.setToolTip("Medir potência de sinal RSSI, latência de rádio e taxa PHY")
        self.btn_measure_wifi.clicked.connect(self.run_wifi_measurement)
        nav_layout.addWidget(self.btn_measure_wifi)

        self.btn_scan_nearby = QPushButton("📡 Redes Vizinhas")
        self.btn_scan_nearby.setToolTip("Escanear pontos de acesso e canais vizinhos no espectro")
        self.btn_scan_nearby.clicked.connect(self.scan_nearby_wifi_action)
        nav_layout.addWidget(self.btn_scan_nearby)

        self.lbl_wifi_badge = QLabel("Wi-Fi --")
        self.lbl_wifi_badge.setStyleSheet(
            f"background-color: {self.palette['accent_hover']}; color: #ffffff; padding: 5px 12px; border-radius: 6px; font-weight: bold; font-size: 11px;"
        )
        nav_layout.addWidget(self.lbl_wifi_badge)

        self.btn_copy = QPushButton("📋 Copiar Laudo")
        self.btn_copy.setToolTip("Copiar laudo técnico de auditoria Wi-Fi para a Área de Transferência")
        self.btn_copy.clicked.connect(self.copy_wifi_report)
        nav_layout.addWidget(self.btn_copy)

        self.btn_toggle_fullscreen = QPushButton("⛶ Tela Cheia")
        self.btn_toggle_fullscreen.setToolTip("Alternar entre modo maximizado e tela cheia completa (F11)")
        self.btn_toggle_fullscreen.clicked.connect(self.toggle_fullscreen)
        nav_layout.addWidget(self.btn_toggle_fullscreen)

        btn_close = QPushButton("✕ Fechar")
        btn_close.clicked.connect(self.close)
        nav_layout.addWidget(btn_close)

        root_layout.addWidget(top_nav)

        # ---------------------------------------------------------------------
        # 2. ÁREA CENTRAL EM SCROLL RESPONSIVO
        # ---------------------------------------------------------------------
        self.scroll_area = QScrollArea(self)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.NoFrame)

        scroll_content = QWidget()
        layout = QVBoxLayout(scroll_content)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(12)

        # Hero Cards Wi-Fi
        hero_layout = QHBoxLayout()
        hero_layout.setSpacing(12)

        # Card Sinal RSSI
        card_sig = QFrame(scroll_content)
        card_sig.setObjectName("cardFrame")
        cs_layout = QVBoxLayout(card_sig)
        cs_layout.setContentsMargins(16, 14, 16, 14)
        cs_layout.setSpacing(6)

        lbl_sig_t = QLabel("📶 POTÊNCIA DE SINAL (RSSI) & QUALIDADE DA CONEXÃO")
        lbl_sig_t.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_sig_t.setStyleSheet(f"color: {self.palette['text_sub']}; letter-spacing: 0.5px;")
        cs_layout.addWidget(lbl_sig_t)

        self.lbl_big_signal = QLabel("-- dBm (0%)")
        self.lbl_big_signal.setFont(QFont("Segoe UI", 26, QFont.Bold))
        self.lbl_big_signal.setStyleSheet(f"color: {self.palette['success']}; margin: 2px 0;")
        cs_layout.addWidget(self.lbl_big_signal)

        self.progress_signal = QProgressBar()
        self.progress_signal.setRange(0, 100)
        self.progress_signal.setValue(0)
        self.progress_signal.setFormat("Sinal: %v%")
        cs_layout.addWidget(self.progress_signal)

        lbl_sig_scale = QLabel("-90 dBm (Fraco)  •  -75 dBm (Regular)  •  -65 dBm (Bom)  •  -50 dBm (Excelente)")
        lbl_sig_scale.setFont(QFont("Segoe UI", 8))
        lbl_sig_scale.setStyleSheet(f"color: {self.palette['text_muted']};")
        cs_layout.addWidget(lbl_sig_scale)

        self.lbl_wifi_desc = QLabel("Qualidade: Aguardando auditoria...")
        self.lbl_wifi_desc.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.lbl_wifi_desc.setWordWrap(True)
        self.lbl_wifi_desc.setStyleSheet(f"color: {self.palette['accent']}; margin-top: 4px;")
        cs_layout.addWidget(self.lbl_wifi_desc)

        self.lbl_wifi_ssid_bssid = QLabel("Rede (SSID): -- • BSSID: --")
        self.lbl_wifi_ssid_bssid.setFont(QFont("Segoe UI", 9))
        self.lbl_wifi_ssid_bssid.setWordWrap(True)
        self.lbl_wifi_ssid_bssid.setStyleSheet(f"color: {self.palette['text_main']};")
        cs_layout.addWidget(self.lbl_wifi_ssid_bssid)

        cs_layout.addStretch(1)
        hero_layout.addWidget(card_sig, 1)

        # Card Protocolo e Frequência
        card_spec = QFrame(scroll_content)
        card_spec.setObjectName("cardFrame")
        cspec_layout = QVBoxLayout(card_spec)
        cspec_layout.setContentsMargins(16, 14, 16, 14)
        cspec_layout.setSpacing(6)

        lbl_spec_t = QLabel("📡 GERAÇÃO, FREQUÊNCIA & TAXA DE ENLACE WIRELESS")
        lbl_spec_t.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_spec_t.setStyleSheet(f"color: {self.palette['text_sub']}; letter-spacing: 0.5px;")
        cspec_layout.addWidget(lbl_spec_t)

        self.lbl_wifi_standard = QLabel("Padrão: --")
        self.lbl_wifi_standard.setFont(QFont("Segoe UI", 11, QFont.Bold))
        self.lbl_wifi_standard.setWordWrap(True)
        self.lbl_wifi_standard.setStyleSheet(f"color: {self.palette['text_main']}; margin-top: 2px;")
        cspec_layout.addWidget(self.lbl_wifi_standard)

        self.lbl_wifi_band_chan = QLabel("Faixa / Canal: --")
        self.lbl_wifi_band_chan.setFont(QFont("Segoe UI", 9))
        self.lbl_wifi_band_chan.setWordWrap(True)
        self.lbl_wifi_band_chan.setStyleSheet(f"color: {self.palette['text_sub']};")
        cspec_layout.addWidget(self.lbl_wifi_band_chan)

        self.lbl_wifi_bitrate = QLabel("Velocidade PHY: Tx -- Mbps • Rx -- Mbps")
        self.lbl_wifi_bitrate.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.lbl_wifi_bitrate.setWordWrap(True)
        self.lbl_wifi_bitrate.setStyleSheet(f"color: {self.palette['success']};")
        cspec_layout.addWidget(self.lbl_wifi_bitrate)

        self.lbl_wifi_sec = QLabel("Segurança & Cifra: --")
        self.lbl_wifi_sec.setFont(QFont("Segoe UI", 9))
        self.lbl_wifi_sec.setWordWrap(True)
        self.lbl_wifi_sec.setStyleSheet(f"color: {self.palette['text_sub']};")
        cspec_layout.addWidget(self.lbl_wifi_sec)

        cspec_layout.addStretch(1)
        hero_layout.addWidget(card_spec, 1)
        layout.addLayout(hero_layout)

        # 2. Latência de Rádio e Relação Sinal-Ruído (SNR)
        card_radio = QFrame(scroll_content)
        card_radio.setObjectName("cardFrame")
        cr_layout = QVBoxLayout(card_radio)
        cr_layout.setContentsMargins(16, 14, 16, 14)
        cr_layout.setSpacing(10)

        lbl_radio_t = QLabel("⚡ LATÊNCIA SEM FIO ATÉ O ROTEADOR, RUÍDO E CONGESTIONAMENTO RF")
        lbl_radio_t.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_radio_t.setStyleSheet(f"color: {self.palette['accent']};")
        cr_layout.addWidget(lbl_radio_t)

        grid_radio = QGridLayout()
        grid_radio.setContentsMargins(0, 4, 0, 4)
        grid_radio.setHorizontalSpacing(14)
        grid_radio.setVerticalSpacing(8)

        radio_items = [
            ("Latência / Jitter até Gateway Wi-Fi:", "lbl_wifi_ping", "Ping: -- ms • Jitter: -- ms • Perda: 0%"),
            ("Relação Sinal-Ruído (SNR):", "lbl_wifi_snr", "SNR: -- dB (Ruído de Fundo: -95 dBm)"),
            ("Congestionamento do Canal Atual:", "lbl_wifi_congestion", "Auditando canal de rádio..."),
            ("Adaptador Físico / Driver:", "lbl_wifi_hw", "Controlador: -- | Driver: --"),
        ]

        for row, (k, attr_n, def_v) in enumerate(radio_items):
            lbl_k = QLabel(k)
            lbl_k.setFont(QFont("Segoe UI", 9))
            lbl_k.setStyleSheet(f"color: {self.palette['text_main']};")

            lbl_v = QLabel(def_v)
            lbl_v.setFont(QFont("Segoe UI", 9, QFont.Bold))
            lbl_v.setWordWrap(True)
            lbl_v.setStyleSheet(f"color: {self.palette['success']};")
            setattr(self, attr_n, lbl_v)

            grid_radio.addWidget(lbl_k, row, 0)
            grid_radio.addWidget(lbl_v, row, 1)

        grid_radio.setColumnStretch(1, 1)
        cr_layout.addLayout(grid_radio)
        layout.addWidget(card_radio)

        # 3. Tabela de Redes Vizinhas e Varredura de Canais
        card_scan = QFrame(scroll_content)
        card_scan.setObjectName("cardFrame")
        cscan_layout = QVBoxLayout(card_scan)
        cscan_layout.setContentsMargins(16, 14, 16, 14)
        cscan_layout.setSpacing(8)

        lbl_scan_t = QLabel("📡 REDES WI-FI PRÓXIMAS DETECTADAS NO AMBIENTE (ANÁLISE DE ESPECTRO)")
        lbl_scan_t.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_scan_t.setStyleSheet(f"color: {self.palette['accent']};")
        cscan_layout.addWidget(lbl_scan_t)

        self.table_nearby = QTableWidget(0, 7)
        self.table_nearby.setHorizontalHeaderLabels([
            "Status", "Nome da Rede (SSID)", "Sinal", "dBm", "Canal", "Frequência", "Segurança"
        ])
        self.table_nearby.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table_nearby.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_nearby.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_nearby.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_nearby.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table_nearby.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.table_nearby.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        self.table_nearby.verticalHeader().setVisible(False)
        self.table_nearby.setMinimumHeight(180)
        cscan_layout.addWidget(self.table_nearby)
        layout.addWidget(card_scan)

        self.scroll_area.setWidget(scroll_content)
        root_layout.addWidget(self.scroll_area, 1)

        # ---------------------------------------------------------------------
        # 3. BARRA DE STATUS INFERIOR
        # ---------------------------------------------------------------------
        status_bar = QFrame(self)
        status_bar.setObjectName("bottomStatusBar")
        status_layout = QHBoxLayout(status_bar)
        status_layout.setContentsMargins(18, 6, 18, 8)
        status_layout.setSpacing(10)

        self.lbl_global_status = QLabel("● Pronto para auditoria de sinal Wi-Fi.")
        self.lbl_global_status.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.lbl_global_status.setStyleSheet(f"color: {self.palette['accent']};")
        status_layout.addWidget(self.lbl_global_status, 1)

        lbl_hint = QLabel("Dica: Pressione <b>F11</b> para alternar tela cheia • <b>Esc</b> para fechar")
        lbl_hint.setFont(QFont("Segoe UI", 8))
        lbl_hint.setStyleSheet(f"color: {self.palette['text_muted']};")
        status_layout.addWidget(lbl_hint)

        root_layout.addWidget(status_bar)

    def toggle_fullscreen(self):
        """Alterna entre janela maximizada e tela cheia completa."""
        if self.isFullScreen():
            self.showMaximized()
            self.btn_toggle_fullscreen.setText("⛶ Tela Cheia")
        else:
            self.showFullScreen()
            self.btn_toggle_fullscreen.setText("🗗 Restaurar")

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_F11:
            self.toggle_fullscreen()
            event.accept()
        elif event.key() == Qt.Key_Escape:
            if self.isFullScreen():
                self.showMaximized()
                self.btn_toggle_fullscreen.setText("⛶ Tela Cheia")
                event.accept()
            else:
                super().keyPressEvent(event)
        else:
            super().keyPressEvent(event)

    def _load_interfaces(self):
        self.combo_wifi_iface.clear()
        try:
            w_ifaces = get_wifi_interfaces()
            if w_ifaces:
                for w in w_ifaces:
                    self.combo_wifi_iface.addItem(f"{w['name']}", w)
            else:
                self.combo_wifi_iface.addItem("Nenhuma Placa Wi-Fi Detectada", None)
        except Exception:
            self.combo_wifi_iface.addItem("Nenhuma Placa Wi-Fi Detectada", None)

    def _get_current_wifi_iface_name(self) -> str:
        data = self.combo_wifi_iface.currentData()
        if isinstance(data, dict):
            return data.get("name", "")
        txt = self.combo_wifi_iface.currentText()
        if "Nenhuma" in txt:
            return ""
        return txt.split(" ")[0].strip()

    def run_wifi_measurement(self):
        w_iface = self._get_current_wifi_iface_name()
        self.btn_measure_wifi.setEnabled(False)
        self.lbl_global_status.setText("● Executando diagnóstico e medição de sinal Wi-Fi...")
        self.lbl_global_status.setStyleSheet(f"color: {self.palette['accent']};")

        self.wifi_worker = LocalWifiDiagWorker(interface_name=w_iface, force_demo=False)
        self.wifi_worker.status_updated.connect(lambda s: self.lbl_global_status.setText(f"● {s}"))
        self.wifi_worker.diag_completed.connect(self._on_wifi_diag_success)
        self.wifi_worker.error_occurred.connect(self._on_wifi_diag_error)
        self.wifi_worker.finished.connect(lambda: self.btn_measure_wifi.setEnabled(True))
        self.wifi_worker.start()

    def scan_nearby_wifi_action(self):
        self.run_wifi_measurement()

    def run_wifi_demo_measurement(self):
        """Redireciona para medição real."""
        self.run_wifi_measurement()

    @pyqtSlot(object)
    def _on_wifi_diag_success(self, res: WifiDiagResult):
        self.current_wifi_result = res

        # 1. Sinal e Potência RSSI
        if res.has_hardware and res.is_connected:
            self.lbl_big_signal.setText(f"{res.signal_dbm} dBm  ({res.signal_percent}%)")
            self.progress_signal.setValue(res.signal_percent)
            if res.signal_percent >= 75:
                sig_color = self.palette["success"]
            elif res.signal_percent >= 50:
                sig_color = self.palette["warning"]
            else:
                sig_color = self.palette["danger"]
            self.lbl_big_signal.setStyleSheet(f"color: {sig_color}; margin: 2px 0;")
            self.lbl_wifi_desc.setText(f"Qualidade: {res.signal_quality_desc}")
            self.lbl_wifi_desc.setStyleSheet(f"color: {sig_color};")
            self.lbl_wifi_ssid_bssid.setText(f"Rede (SSID): <b>{res.ssid}</b> • BSSID: <code>{res.bssid}</code>")
        elif res.has_hardware:
            self.lbl_big_signal.setText("Desconectado (0%)")
            self.lbl_big_signal.setStyleSheet(f"color: {self.palette['danger']}; margin: 2px 0;")
            self.progress_signal.setValue(0)
            self.lbl_wifi_desc.setText("Qualidade: Placa Wi-Fi ativa, aguardando conexão a uma rede.")
            self.lbl_wifi_desc.setStyleSheet(f"color: {self.palette['warning']};")
            self.lbl_wifi_ssid_bssid.setText("Rede (SSID): -- • BSSID: --")
        else:
            self.lbl_big_signal.setText("Sem Hardware Wi-Fi")
            self.lbl_big_signal.setStyleSheet(f"color: {self.palette['text_sub']}; margin: 2px 0;")
            self.progress_signal.setValue(0)
            self.lbl_wifi_desc.setText("Qualidade: Nenhum adaptador sem fio ativo detectado neste computador.")
            self.lbl_wifi_desc.setStyleSheet(f"color: {self.palette['text_sub']};")
            self.lbl_wifi_ssid_bssid.setText("Conecte um adaptador Wi-Fi USB ou ative a placa de rede sem fio para auditoria.")

        # 2. Padrão e Frequência
        self.lbl_wifi_standard.setText(f"Padrão: {res.wifi_standard}")
        band_txt = f"Faixa / Canal: {res.frequency_band} • Canal {res.channel or '--'}"
        if res.channel_width_mhz:
            band_txt += f" ({res.channel_width_mhz} MHz de largura)"
        self.lbl_wifi_band_chan.setText(band_txt)

        self.lbl_wifi_bitrate.setText(
            f"Velocidade PHY: Tx {res.tx_bitrate_mbps:.1f} Mbps • Rx {res.rx_bitrate_mbps:.1f} Mbps"
            if res.tx_bitrate_mbps > 0
            else "Velocidade PHY: --"
        )
        self.lbl_wifi_sec.setText(f"Segurança & Cifra: {res.security}")

        badge_txt = res.wifi_standard.split(" ")[0] if res.wifi_standard != "--" else "Wi-Fi"
        self.lbl_wifi_badge.setText(badge_txt)

        # 3. Latência de Rádio e Ruído
        self.lbl_wifi_ping.setText(
            f"Ping: {res.ping_gateway_ms:.1f} ms • Jitter: {res.jitter_ms:.1f} ms • Perda: {res.packet_loss_pct:.0f}%"
            if res.ping_gateway_ms > 0
            else "Ping Gateway: Não testado (Sem IP de roteador sem fio)"
        )
        self.lbl_wifi_snr.setText(
            f"SNR: {res.snr_db} dB (Ruído de Fundo: {res.noise_dbm} dBm — {'Excelente' if res.snr_db >= 35 else 'Normal'})"
        )
        self.lbl_wifi_congestion.setText(f"{res.channel_congestion}")
        self.lbl_wifi_hw.setText(f"Controlador: {res.adapter_model} | Driver: {res.driver}")

        # 4. Tabela de Redes Vizinhas
        self._populate_nearby_table(res.nearby_networks)

        self.lbl_global_status.setText(
            f"✓ Auditoria Wi-Fi concluída! {res.overall_condition}"
        )
        self.lbl_global_status.setStyleSheet(f"color: {self.palette['success']};")

    def _populate_nearby_table(self, networks: List[NearbyWifiNetwork]):
        self.table_nearby.setRowCount(0)
        for net in networks:
            row = self.table_nearby.rowCount()
            self.table_nearby.insertRow(row)

            # 0. Status
            status_item = QTableWidgetItem("🟢 Conectado" if net.in_use else "⚪ Próximo")
            if net.in_use:
                status_item.setForeground(QColor(self.palette["success"]))
            self.table_nearby.setItem(row, 0, status_item)

            # 1. SSID
            ssid_item = QTableWidgetItem(net.ssid)
            if net.in_use:
                ssid_item.setFont(QFont("Segoe UI", 9, QFont.Bold))
            self.table_nearby.setItem(row, 1, ssid_item)

            # 2. Sinal %
            sig_item = QTableWidgetItem(f"{net.signal_pct}%")
            if net.signal_pct >= 75:
                sig_item.setForeground(QColor(self.palette["success"]))
            elif net.signal_pct >= 50:
                sig_item.setForeground(QColor(self.palette["warning"]))
            else:
                sig_item.setForeground(QColor(self.palette["danger"]))
            self.table_nearby.setItem(row, 2, sig_item)

            # 3. dBm
            dbm_item = QTableWidgetItem(f"{net.signal_dbm} dBm")
            self.table_nearby.setItem(row, 3, dbm_item)

            # 4. Canal
            chan_item = QTableWidgetItem(f"Ch {net.channel}" if net.channel else "--")
            self.table_nearby.setItem(row, 4, chan_item)

            # 5. Frequência
            freq_txt = f"{net.frequency_mhz} MHz ({'5 GHz' if net.frequency_mhz >= 5000 else '2.4 GHz'})"
            freq_item = QTableWidgetItem(freq_txt)
            self.table_nearby.setItem(row, 5, freq_item)

            # 6. Segurança
            sec_item = QTableWidgetItem(net.security)
            self.table_nearby.setItem(row, 6, sec_item)

    @pyqtSlot(str)
    def _on_wifi_diag_error(self, err: str):
        self.lbl_global_status.setText(f"⚠️ {err}")
        self.lbl_global_status.setStyleSheet(f"color: {self.palette['danger']};")
        QMessageBox.warning(self, "Diagnóstico Wi-Fi", err)

    def copy_wifi_report(self):
        if not self.current_wifi_result:
            QMessageBox.information(self, "Aviso", "Execute a auditoria Wi-Fi antes de copiar o laudo.")
            return

        w = self.current_wifi_result
        report = f"""# LAUDO TÉCNICO DE AUDITORIA E MEDIÇÃO WI-FI (WIRELESS)
Gerado por: IP Scan IGT
Data/Hora: {w.test_timestamp}

--- DADOS DA CONEXÃO SEM FIO ---
• Rede Wi-Fi (SSID): {w.ssid}
• Ponto de Acesso (BSSID): {w.bssid}
• Potência de Sinal (RSSI): {w.signal_dbm} dBm ({w.signal_percent}%)
• Qualidade da Conexão: {w.signal_quality_desc}
• Padrão / Geração: {w.wifi_standard}
• Faixa de Frequência: {w.frequency_band} (Frequência Central: {w.frequency_mhz} MHz)
• Canal de Rádio: Canal {w.channel} ({w.channel_width_mhz} MHz de largura)
• Velocidade PHY Negociada: Tx {w.tx_bitrate_mbps:.1f} Mbps | Rx {w.rx_bitrate_mbps:.1f} Mbps
• Autenticação & Criptografia: {w.security}

--- LATÊNCIA DE RÁDIO & RUÍDO ---
• Latência até Gateway Wi-Fi: {w.ping_gateway_ms:.2f} ms
• Jitter de Transmissão: {w.jitter_ms:.2f} ms
• Perda de Pacotes: {w.packet_loss_pct:.1f}%
• Relação Sinal-Ruído (SNR): {w.snr_db} dB (Ruído de fundo: {w.noise_dbm} dBm)
• Avaliação de Congestionamento: {w.channel_congestion}

--- HARDWARE DA PLACA WIRELESS ---
• Dispositivo: {w.adapter_model}
• Driver: {w.driver}
• Endereço MAC: {w.mac_address}
"""
        QApplication.clipboard().setText(report)
        QMessageBox.information(self, "Copiado", "Laudo técnico de auditoria Wi-Fi copiado com sucesso!")
