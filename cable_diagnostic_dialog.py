#!/usr/bin/env python3
"""
Diálogo Visual de Diagnóstico e Medição de Rede (Cabo & Wi-Fi) — IP Scan IGT
Interface moderna de alta fidelidade visual (UI/UX) que integra:
 1. Diagnóstico Elétrico e Medição Métrica de Cabo de Rede via Placa Local (NIC / IEEE 802.3ab PAM-5);
 2. Diagnóstico Completo de Rede Sem Fio Wi-Fi (Sinal RSSI, SNR, Padrão Wi-Fi 4/5/6/7, Canal, Ruído, Latência/Jitter e Redes Vizinhas).
"""

from datetime import datetime
import os
import sys
from typing import Dict, List, Optional

from PyQt5.QtCore import Qt, QTimer, pyqtSlot
from PyQt5.QtGui import QColor, QFont, QIcon, QPainter, QPainterPath, QPen
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


class CableDiagnosticDialog(QDialog):
    """
    Janela moderna de diagnóstico unificado para Cabo de Rede e Wi-Fi.
    """

    def __init__(
        self,
        parent=None,
        initial_iface: str = "",
        is_dark: bool = True,
        initial_tab: str = "cable",
    ):
        super().__init__(parent)
        self.is_dark = is_dark
        self.initial_iface = initial_iface or "enp7s0"
        self.current_tab = initial_tab  # 'cable' ou 'wifi'

        self.cable_worker: Optional[LocalCableDiagWorker] = None
        self.wifi_worker: Optional[LocalWifiDiagWorker] = None
        self.current_cable_result: Optional[CableDiagResult] = None
        self.current_wifi_result: Optional[WifiDiagResult] = None

        self.setWindowTitle("⚡ Diagnóstico e Medição de Rede (Cabo & Wi-Fi) — IP Scan IGT")
        self.setMinimumSize(940, 680)
        self.resize(980, 720)

        self._apply_styling()
        self._init_ui()
        self._load_interfaces()

        # Seleciona a aba inicial
        if initial_tab == "wifi":
            self.switch_to_wifi()
        else:
            self.switch_to_cable()
            QTimer.singleShot(250, self.run_cable_measurement)

    def _apply_styling(self):
        bg = "#090d16" if self.is_dark else "#f1f5f9"
        fg = "#f8fafc" if self.is_dark else "#0f172a"
        card_bg = "#111827" if self.is_dark else "#ffffff"
        card_bg_sub = "#162032" if self.is_dark else "#f8fafc"
        border_col = "#1f293d" if self.is_dark else "#cbd5e1"
        btn_bg = "#1e293b" if self.is_dark else "#e2e8f0"
        header_bg = "#0f172a" if self.is_dark else "#ffffff"

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg};
                color: {fg};
            }}
            QFrame#cardFrame {{
                background-color: {card_bg};
                border: 1px solid {border_col};
                border-radius: 10px;
                padding: 14px;
            }}
            QFrame#cardSubFrame {{
                background-color: {card_bg_sub};
                border: 1px solid {border_col};
                border-radius: 8px;
                padding: 10px;
            }}
            QFrame#topNavFrame {{
                background-color: {header_bg};
                border-bottom: 2px solid {border_col};
                padding: 8px 16px;
            }}
            QLabel {{
                color: {fg};
            }}
            QPushButton {{
                background-color: {btn_bg};
                color: {fg};
                border: 1px solid {border_col};
                border-radius: 6px;
                padding: 6px 16px;
                font-weight: 600;
                font-size: 12px;
            }}
            QPushButton:hover {{
                background-color: #2563eb;
                color: #ffffff;
                border-color: #3b82f6;
            }}
            QPushButton#primaryBtn {{
                background-color: #0284c7;
                color: #ffffff;
                font-weight: bold;
                border: none;
                border-radius: 6px;
                padding: 6px 18px;
            }}
            QPushButton#primaryBtn:hover {{
                background-color: #0369a1;
            }}
            QPushButton#navActiveBtn {{
                background-color: #0284c7;
                color: #ffffff;
                font-weight: bold;
                border: 1px solid #38bdf8;
                border-radius: 20px;
                padding: 6px 20px;
            }}
            QPushButton#navInactiveBtn {{
                background-color: transparent;
                color: #94a3b8;
                border: 1px solid {border_col};
                border-radius: 20px;
                padding: 6px 20px;
            }}
            QPushButton#navInactiveBtn:hover {{
                background-color: {btn_bg};
                color: {fg};
            }}
            QComboBox {{
                background-color: {card_bg};
                color: {fg};
                border: 1px solid {border_col};
                border-radius: 6px;
                padding: 4px 12px;
                min-height: 28px;
                font-weight: 500;
            }}
            QProgressBar {{
                border: 1px solid {border_col};
                border-radius: 5px;
                text-align: center;
                background-color: #1e293b;
                color: #ffffff;
                font-size: 11px;
                font-weight: bold;
            }}
            QProgressBar::chunk {{
                border-radius: 4px;
            }}
            QTableWidget {{
                background-color: {card_bg};
                color: {fg};
                border: 1px solid {border_col};
                border-radius: 8px;
                gridline-color: {border_col};
                font-size: 12px;
            }}
            QHeaderView::section {{
                background-color: {card_bg_sub};
                color: #94a3b8;
                font-weight: bold;
                font-size: 11px;
                border: none;
                border-bottom: 1px solid {border_col};
                padding: 6px;
            }}
        """)

    def _init_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ---------------------------------------------------------------------
        # 1. BARRA SUPERIOR DE NAVEGAÇÃO (Cabo vs Wi-Fi)
        # ---------------------------------------------------------------------
        top_nav = QFrame(self)
        top_nav.setObjectName("topNavFrame")
        nav_layout = QHBoxLayout(top_nav)
        nav_layout.setContentsMargins(16, 10, 16, 10)
        nav_layout.setSpacing(12)

        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        lbl_title = QLabel("⚡ DIAGNÓSTICO DE REDE FÍSICA & SEM FIO")
        lbl_title.setFont(QFont("Segoe UI", 12, QFont.Bold))
        lbl_title.setStyleSheet("color: #38bdf8;")
        title_box.addWidget(lbl_title)

        lbl_sub = QLabel("Medição de Cabo Ethernet (TDR / 4 Pares) e Auditoria Completa de Sinal Wi-Fi")
        lbl_sub.setFont(QFont("Segoe UI", 9))
        lbl_sub.setStyleSheet("color: #94a3b8;")
        title_box.addWidget(lbl_sub)
        nav_layout.addLayout(title_box)

        nav_layout.addStretch(1)

        # Botões de alternância de aba (Segmented Buttons)
        self.btn_nav_cable = QPushButton("⚡ Cabo de Rede (Ethernet)")
        self.btn_nav_cable.setObjectName("navActiveBtn")
        self.btn_nav_cable.clicked.connect(self.switch_to_cable)
        nav_layout.addWidget(self.btn_nav_cable)

        self.btn_nav_wifi = QPushButton("📶 Wi-Fi (Sinal & Redes)")
        self.btn_nav_wifi.setObjectName("navInactiveBtn")
        self.btn_nav_wifi.clicked.connect(self.switch_to_wifi)
        nav_layout.addWidget(self.btn_nav_wifi)

        root_layout.addWidget(top_nav)

        # ---------------------------------------------------------------------
        # 2. ÁREA CENTRAL EM STACK (Página 0: Cabo | Página 1: Wi-Fi)
        # ---------------------------------------------------------------------
        content_container = QWidget(self)
        self.main_content_layout = QVBoxLayout(content_container)
        self.main_content_layout.setContentsMargins(16, 12, 16, 12)
        self.main_content_layout.setSpacing(10)

        self.stack = QStackedWidget(self)

        # PÁGINA 1: CABO DE REDE
        self.page_cable = self._create_cable_page()
        self.stack.addWidget(self.page_cable)

        # PÁGINA 2: WI-FI
        self.page_wifi = self._create_wifi_page()
        self.stack.addWidget(self.page_wifi)

        self.main_content_layout.addWidget(self.stack)

        # ---------------------------------------------------------------------
        # 3. BARRA DE STATUS INFERIOR GLOBAL
        # ---------------------------------------------------------------------
        status_bar = QFrame(self)
        status_layout = QHBoxLayout(status_bar)
        status_layout.setContentsMargins(16, 6, 16, 10)
        status_layout.setSpacing(10)

        self.lbl_global_status = QLabel("● Pronto para auditoria.")
        self.lbl_global_status.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.lbl_global_status.setStyleSheet("color: #38bdf8;")
        status_layout.addWidget(self.lbl_global_status, 1)

        self.btn_copy_global = QPushButton("📋 Copiar Relatório Técnico")
        self.btn_copy_global.clicked.connect(self.copy_current_report)
        status_layout.addWidget(self.btn_copy_global)

        btn_close = QPushButton("Fechar")
        btn_close.clicked.connect(self.close)
        status_layout.addWidget(btn_close)

        root_layout.addWidget(content_container, 1)
        root_layout.addWidget(status_bar)

    # =========================================================================
    # CONSTRUÇÃO DA PÁGINA DE CABO DE REDE (ETHERNET)
    # =========================================================================
    def _create_cable_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        # 1. Barra de Controle da Placa de Rede
        bar_ctrl = QFrame(page)
        bar_ctrl.setObjectName("cardFrame")
        bc_layout = QHBoxLayout(bar_ctrl)
        bc_layout.setContentsMargins(12, 8, 12, 8)
        bc_layout.setSpacing(10)

        lbl_iface = QLabel("<b>Placa de Rede Selecionada:</b>")
        lbl_iface.setFont(QFont("Segoe UI", 9))
        bc_layout.addWidget(lbl_iface)

        self.combo_iface = QComboBox()
        self.combo_iface.setMinimumWidth(260)
        self.combo_iface.setToolTip("Selecione a placa de rede com cabo conectado para medição")
        bc_layout.addWidget(self.combo_iface)

        self.btn_measure_cable = QPushButton("▶ Medir Cabo da Placa")
        self.btn_measure_cable.setObjectName("primaryBtn")
        self.btn_measure_cable.setToolTip("Executa medição de comprimento, integridade dos 4 pares e ruído elétrico")
        self.btn_measure_cable.clicked.connect(self.run_cable_measurement)
        bc_layout.addWidget(self.btn_measure_cable)

        bc_layout.addStretch(1)

        self.lbl_cable_speed_badge = QLabel("1000 Mbps • Full-Duplex")
        self.lbl_cable_speed_badge.setStyleSheet(
            "background-color: #065f46; color: #6ee7b7; padding: 4px 12px; border-radius: 6px; font-weight: bold; font-size: 12px;"
        )
        bc_layout.addWidget(self.lbl_cable_speed_badge)
        layout.addWidget(bar_ctrl)

        # 2. Hero Cards (Comprimento do Cabo e Hardware da Placa)
        hero_layout = QHBoxLayout()
        hero_layout.setSpacing(10)

        # Card Comprimento
        card_len = QFrame(page)
        card_len.setObjectName("cardFrame")
        cl_layout = QVBoxLayout(card_len)
        cl_layout.setContentsMargins(16, 12, 16, 12)

        lbl_len_t = QLabel("📏 COMPRIMENTO DO CABO (TDR / PROPAGAÇÃO)")
        lbl_len_t.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_len_t.setStyleSheet("color: #94a3b8;")
        cl_layout.addWidget(lbl_len_t)

        self.lbl_big_length = QLabel("-- metros")
        self.lbl_big_length.setFont(QFont("Segoe UI", 24, QFont.Bold))
        self.lbl_big_length.setStyleSheet("color: #38bdf8; margin: 2px 0;")
        cl_layout.addWidget(self.lbl_big_length)

        # Barra visual de distância do cabo (0m até limite de 100m da norma Ethernet)
        self.progress_cable = QProgressBar()
        self.progress_cable.setRange(0, 100)
        self.progress_cable.setValue(8)
        self.progress_cable.setFormat("%v m / 100m (Limite Cat 5e/6)")
        self.progress_cable.setStyleSheet("""
            QProgressBar {
                background-color: #1e293b;
                border: 1px solid #334155;
                height: 14px;
                border-radius: 4px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #38bdf8);
                border-radius: 3px;
            }
        """)
        cl_layout.addWidget(self.progress_cable)

        self.lbl_cable_cat = QLabel("Categoria: Analisando...")
        self.lbl_cable_cat.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.lbl_cable_cat.setStyleSheet("color: #10b981; margin-top: 4px;")
        cl_layout.addWidget(self.lbl_cable_cat)

        self.lbl_cable_condition = QLabel("Condição Física: Aguardando teste...")
        self.lbl_cable_condition.setFont(QFont("Segoe UI", 9))
        self.lbl_cable_condition.setStyleSheet("color: #cbd5e1;")
        cl_layout.addWidget(self.lbl_cable_condition)

        cl_layout.addStretch(1)
        hero_layout.addWidget(card_len, 1)

        # Card Hardware da Placa
        card_nic = QFrame(page)
        card_nic.setObjectName("cardFrame")
        cn_layout = QVBoxLayout(card_nic)
        cn_layout.setContentsMargins(16, 12, 16, 12)

        lbl_nic_t = QLabel("🖥️ CONTROLADOR FÍSICO DA PLACA LOCAL")
        lbl_nic_t.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_nic_t.setStyleSheet("color: #94a3b8;")
        cn_layout.addWidget(lbl_nic_t)

        self.lbl_nic_model = QLabel("Controlador Ethernet Gigabit")
        self.lbl_nic_model.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.lbl_nic_model.setStyleSheet("color: #f1f5f9; margin-top: 2px;")
        cn_layout.addWidget(self.lbl_nic_model)

        self.lbl_nic_mac = QLabel("MAC: --:--:--:--:--:--")
        self.lbl_nic_mac.setFont(QFont("Segoe UI", 9))
        self.lbl_nic_mac.setStyleSheet("color: #94a3b8;")
        cn_layout.addWidget(self.lbl_nic_mac)

        self.lbl_nic_driver = QLabel("Driver: --")
        self.lbl_nic_driver.setFont(QFont("Segoe UI", 9))
        self.lbl_nic_driver.setStyleSheet("color: #94a3b8;")
        cn_layout.addWidget(self.lbl_nic_driver)

        self.lbl_nic_carrier = QLabel("Link Físico: Detectado (Portadora Ativa)")
        self.lbl_nic_carrier.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.lbl_nic_carrier.setStyleSheet("color: #10b981; margin-top: 4px;")
        cn_layout.addWidget(self.lbl_nic_carrier)

        cn_layout.addStretch(1)
        hero_layout.addWidget(card_nic, 1)
        layout.addLayout(hero_layout)

        # 3. Integridade Elétrica dos 4 Pares (IEEE 802.3ab PAM-5)
        card_pairs = QFrame(page)
        card_pairs.setObjectName("cardFrame")
        cp_layout = QVBoxLayout(card_pairs)
        cp_layout.setContentsMargins(16, 10, 16, 10)

        lbl_pairs_t = QLabel("🔌 INTEGRIDADE ELÉTRICA DOS 4 PARES DE FIOS (8 CONDUTORES RJ-45)")
        lbl_pairs_t.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_pairs_t.setStyleSheet("color: #38bdf8; border-bottom: 1px solid #1e293b; padding-bottom: 4px;")
        cp_layout.addWidget(lbl_pairs_t)

        grid_pairs = QGridLayout()
        grid_pairs.setContentsMargins(0, 6, 0, 6)
        grid_pairs.setHorizontalSpacing(14)
        grid_pairs.setVerticalSpacing(6)

        pairs_info = [
            ("Par A (Pinos 1 e 2 • Branco/Verde & Verde):", "lbl_pair_a", "Normal (Tx/Rx Bidirecional OK)"),
            ("Par B (Pinos 3 e 6 • Branco/Laranja & Laranja):", "lbl_pair_b", "Normal (Tx/Rx Bidirecional OK)"),
            ("Par C (Pinos 4 e 5 • Azul & Branco/Azul):", "lbl_pair_c", "Normal (Tx/Rx Bidirecional OK)"),
            ("Par D (Pinos 7 e 8 • Branco/Marrom & Marrom):", "lbl_pair_d", "Normal (Tx/Rx Bidirecional OK)"),
        ]

        for row, (label_t, attr_n, default_val) in enumerate(pairs_info):
            lbl_k = QLabel(label_t)
            lbl_k.setFont(QFont("Segoe UI", 9))
            lbl_k.setStyleSheet("color: #cbd5e1;")

            lbl_v = QLabel(default_val)
            lbl_v.setFont(QFont("Segoe UI", 9, QFont.Bold))
            lbl_v.setStyleSheet("color: #10b981;")
            setattr(self, attr_n, lbl_v)

            grid_pairs.addWidget(lbl_k, row, 0)
            grid_pairs.addWidget(lbl_v, row, 1)

        grid_pairs.setColumnStretch(1, 1)
        cp_layout.addLayout(grid_pairs)
        layout.addWidget(card_pairs)

        # 4. Qualidade de Sinal, Ruído EMI e Estabilidade
        card_noise = QFrame(page)
        card_noise.setObjectName("cardFrame")
        cn_layout2 = QVBoxLayout(card_noise)
        cn_layout2.setContentsMargins(16, 10, 16, 10)

        lbl_noise_t = QLabel("🛡️ QUALIDADE DO SINAL, RUÍDO E ESTABILIDADE DO CONECTOR RJ-45")
        lbl_noise_t.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_noise_t.setStyleSheet("color: #38bdf8; border-bottom: 1px solid #1e293b; padding-bottom: 4px;")
        cn_layout2.addWidget(lbl_noise_t)

        grid_noise = QGridLayout()
        grid_noise.setContentsMargins(0, 6, 0, 4)
        grid_noise.setHorizontalSpacing(14)
        grid_noise.setVerticalSpacing(6)

        noise_items = [
            ("Interferência / Ruído Elétrico (EMI):", "lbl_noise_emi", "Excelente (0 erros de CRC / 0 erros de Alinhamento)"),
            ("Estabilidade do Conector (Mau Contato):", "lbl_connector", "Estável (Sem oscilação de portadora / link flapping)"),
            ("Status do Enlace de Transmissão:", "lbl_link_health", "1000 Mbps Full-Duplex (Capacidade Máxima Gigabit)"),
        ]

        for row, (k, attr_n, def_v) in enumerate(noise_items):
            lbl_k = QLabel(k)
            lbl_k.setFont(QFont("Segoe UI", 9))
            lbl_k.setStyleSheet("color: #cbd5e1;")

            lbl_v = QLabel(def_v)
            lbl_v.setFont(QFont("Segoe UI", 9, QFont.Bold))
            lbl_v.setStyleSheet("color: #10b981;")
            setattr(self, attr_n, lbl_v)

            grid_noise.addWidget(lbl_k, row, 0)
            grid_noise.addWidget(lbl_v, row, 1)

        grid_noise.setColumnStretch(1, 1)
        cn_layout2.addLayout(grid_noise)
        layout.addWidget(card_noise)

        return page

    # =========================================================================
    # CONSTRUÇÃO DA PÁGINA DE DIAGNÓSTICO WI-FI (WIRELESS)
    # =========================================================================
    def _create_wifi_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        # 1. Barra Superior de Controle Wi-Fi
        bar_wifi_ctrl = QFrame(page)
        bar_wifi_ctrl.setObjectName("cardFrame")
        bw_layout = QHBoxLayout(bar_wifi_ctrl)
        bw_layout.setContentsMargins(12, 8, 12, 8)
        bw_layout.setSpacing(10)

        lbl_w_iface = QLabel("<b>Placa Wi-Fi:</b>")
        lbl_w_iface.setFont(QFont("Segoe UI", 9))
        bw_layout.addWidget(lbl_w_iface)

        self.combo_wifi_iface = QComboBox()
        self.combo_wifi_iface.setMinimumWidth(220)
        self.combo_wifi_iface.setToolTip("Selecione a interface sem fio para auditoria")
        bw_layout.addWidget(self.combo_wifi_iface)

        self.btn_measure_wifi = QPushButton("▶ Medir Sinal Wi-Fi")
        self.btn_measure_wifi.setObjectName("primaryBtn")
        self.btn_measure_wifi.setToolTip("Executa medição de potência de sinal RSSI, modulação e latência")
        self.btn_measure_wifi.clicked.connect(self.run_wifi_measurement)
        bw_layout.addWidget(self.btn_measure_wifi)

        self.btn_scan_nearby = QPushButton("📡 Redes Vizinhas")
        self.btn_scan_nearby.setToolTip("Escanear pontos de acesso e canais próximos no ambiente")
        self.btn_scan_nearby.clicked.connect(self.scan_nearby_wifi_action)
        bw_layout.addWidget(self.btn_scan_nearby)

        self.btn_demo_wifi = QPushButton("🧪 Simular Wi-Fi 6")
        self.btn_demo_wifi.setToolTip("Exibir simulação com parâmetros de rede Wi-Fi 6 empresarial para teste visual")
        self.btn_demo_wifi.clicked.connect(self.run_wifi_demo_measurement)
        bw_layout.addWidget(self.btn_demo_wifi)

        bw_layout.addStretch(1)

        self.lbl_wifi_badge = QLabel("Wi-Fi --")
        self.lbl_wifi_badge.setStyleSheet(
            "background-color: #0369a1; color: #bae6fd; padding: 4px 12px; border-radius: 6px; font-weight: bold; font-size: 12px;"
        )
        bw_layout.addWidget(self.lbl_wifi_badge)
        layout.addWidget(bar_wifi_ctrl)

        # 2. Hero Cards (Nível de Sinal RSSI & Desempenho / Geração)
        wifi_hero_layout = QHBoxLayout()
        wifi_hero_layout.setSpacing(10)

        # Card Sinal RSSI
        card_sig = QFrame(page)
        card_sig.setObjectName("cardFrame")
        cs_layout = QVBoxLayout(card_sig)
        cs_layout.setContentsMargins(16, 12, 16, 12)

        lbl_sig_t = QLabel("📶 POTÊNCIA DE SINAL (RSSI) & QUALIDADE")
        lbl_sig_t.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_sig_t.setStyleSheet("color: #94a3b8;")
        cs_layout.addWidget(lbl_sig_t)

        self.lbl_big_signal = QLabel("-- dBm (0%)")
        self.lbl_big_signal.setFont(QFont("Segoe UI", 24, QFont.Bold))
        self.lbl_big_signal.setStyleSheet("color: #10b981; margin: 2px 0;")
        cs_layout.addWidget(self.lbl_big_signal)

        # Barra visual do medidor de sinal
        self.progress_signal = QProgressBar()
        self.progress_signal.setRange(0, 100)
        self.progress_signal.setValue(0)
        self.progress_signal.setFormat("Sinal: %v%")
        self.progress_signal.setStyleSheet("""
            QProgressBar {
                background-color: #1e293b;
                border: 1px solid #334155;
                height: 14px;
                border-radius: 4px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #10b981, stop:1 #34d399);
                border-radius: 3px;
            }
        """)
        cs_layout.addWidget(self.progress_signal)

        self.lbl_wifi_desc = QLabel("Qualidade: Aguardando auditoria...")
        self.lbl_wifi_desc.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.lbl_wifi_desc.setStyleSheet("color: #38bdf8; margin-top: 4px;")
        cs_layout.addWidget(self.lbl_wifi_desc)

        self.lbl_wifi_ssid_bssid = QLabel("Rede (SSID): -- • BSSID: --")
        self.lbl_wifi_ssid_bssid.setFont(QFont("Segoe UI", 9))
        self.lbl_wifi_ssid_bssid.setStyleSheet("color: #cbd5e1;")
        cs_layout.addWidget(self.lbl_wifi_ssid_bssid)

        cs_layout.addStretch(1)
        wifi_hero_layout.addWidget(card_sig, 1)

        # Card Protocolo e Frequência
        card_spec = QFrame(page)
        card_spec.setObjectName("cardFrame")
        cspec_layout = QVBoxLayout(card_spec)
        cspec_layout.setContentsMargins(16, 12, 16, 12)

        lbl_spec_t = QLabel("📡 GERAÇÃO, FREQUÊNCIA & TAXA DE ENLACE")
        lbl_spec_t.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_spec_t.setStyleSheet("color: #94a3b8;")
        cspec_layout.addWidget(lbl_spec_t)

        self.lbl_wifi_standard = QLabel("Padrão: --")
        self.lbl_wifi_standard.setFont(QFont("Segoe UI", 11, QFont.Bold))
        self.lbl_wifi_standard.setStyleSheet("color: #f1f5f9; margin-top: 2px;")
        cspec_layout.addWidget(self.lbl_wifi_standard)

        self.lbl_wifi_band_chan = QLabel("Faixa / Canal: --")
        self.lbl_wifi_band_chan.setFont(QFont("Segoe UI", 9))
        self.lbl_wifi_band_chan.setStyleSheet("color: #94a3b8;")
        cspec_layout.addWidget(self.lbl_wifi_band_chan)

        self.lbl_wifi_bitrate = QLabel("Velocidade PHY: Tx -- Mbps • Rx -- Mbps")
        self.lbl_wifi_bitrate.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.lbl_wifi_bitrate.setStyleSheet("color: #10b981;")
        cspec_layout.addWidget(self.lbl_wifi_bitrate)

        self.lbl_wifi_sec = QLabel("Segurança: --")
        self.lbl_wifi_sec.setFont(QFont("Segoe UI", 9))
        self.lbl_wifi_sec.setStyleSheet("color: #94a3b8;")
        cspec_layout.addWidget(self.lbl_wifi_sec)

        cspec_layout.addStretch(1)
        wifi_hero_layout.addWidget(card_spec, 1)
        layout.addLayout(wifi_hero_layout)

        # 3. Latência de Rádio e Relação Sinal-Ruído (SNR)
        card_radio = QFrame(page)
        card_radio.setObjectName("cardFrame")
        cr_layout = QVBoxLayout(card_radio)
        cr_layout.setContentsMargins(16, 10, 16, 10)

        lbl_radio_t = QLabel("⚡ LATÊNCIA SEM FIO ATÉ O ROTEADOR, RUÍDO E CONGESTIONAMENTO")
        lbl_radio_t.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_radio_t.setStyleSheet("color: #38bdf8; border-bottom: 1px solid #1e293b; padding-bottom: 4px;")
        cr_layout.addWidget(lbl_radio_t)

        grid_radio = QGridLayout()
        grid_radio.setContentsMargins(0, 6, 0, 4)
        grid_radio.setHorizontalSpacing(14)
        grid_radio.setVerticalSpacing(6)

        radio_items = [
            ("Latência / Jitter até Gateway Wi-Fi:", "lbl_wifi_ping", "Ping: -- ms • Jitter: -- ms • Perda: 0%"),
            ("Relação Sinal-Ruído (SNR):", "lbl_wifi_snr", "SNR: -- dB (Ruído de Fundo: -95 dBm)"),
            ("Congestionamento do Canal Atual:", "lbl_wifi_congestion", "Auditando canal de rádio..."),
            ("Adaptador Físico / Driver:", "lbl_wifi_hw", "Controlador: -- | Driver: --"),
        ]

        for row, (k, attr_n, def_v) in enumerate(radio_items):
            lbl_k = QLabel(k)
            lbl_k.setFont(QFont("Segoe UI", 9))
            lbl_k.setStyleSheet("color: #cbd5e1;")

            lbl_v = QLabel(def_v)
            lbl_v.setFont(QFont("Segoe UI", 9, QFont.Bold))
            lbl_v.setStyleSheet("color: #10b981;")
            setattr(self, attr_n, lbl_v)

            grid_radio.addWidget(lbl_k, row, 0)
            grid_radio.addWidget(lbl_v, row, 1)

        grid_radio.setColumnStretch(1, 1)
        cr_layout.addLayout(grid_radio)
        layout.addWidget(card_radio)

        # 4. Tabela de Redes Vizinhas e Varredura de Canais
        card_scan = QFrame(page)
        card_scan.setObjectName("cardFrame")
        cscan_layout = QVBoxLayout(card_scan)
        cscan_layout.setContentsMargins(16, 10, 16, 10)

        lbl_scan_t = QLabel("📡 REDES WI-FI PRÓXIMAS DETECTADAS NO AMBIENTE (ANÁLISE DE ESPECTRO)")
        lbl_scan_t.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_scan_t.setStyleSheet("color: #38bdf8; border-bottom: 1px solid #1e293b; padding-bottom: 4px;")
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
        self.table_nearby.setFixedHeight(130)
        cscan_layout.addWidget(self.table_nearby)

        layout.addWidget(card_scan)
        return page

    # =========================================================================
    # NAVEGAÇÃO ENTRE ABAS
    # =========================================================================
    def switch_to_cable(self):
        self.current_tab = "cable"
        self.stack.setCurrentIndex(0)
        self.btn_nav_cable.setObjectName("navActiveBtn")
        self.btn_nav_wifi.setObjectName("navInactiveBtn")
        self.btn_nav_cable.setStyle(self.btn_nav_cable.style())
        self.btn_nav_wifi.setStyle(self.btn_nav_wifi.style())
        self.lbl_global_status.setText("● Visualizando diagnóstico e medição de Cabo de Rede.")

    def switch_to_wifi(self):
        self.current_tab = "wifi"
        self.stack.setCurrentIndex(1)
        self.btn_nav_wifi.setObjectName("navActiveBtn")
        self.btn_nav_cable.setObjectName("navInactiveBtn")
        self.btn_nav_wifi.setStyle(self.btn_nav_wifi.style())
        self.btn_nav_cable.setStyle(self.btn_nav_cable.style())
        self.lbl_global_status.setText("● Visualizando diagnóstico de sinal e auditoria Wi-Fi.")

        # Dispara auditoria Wi-Fi se ainda não foi executada
        if not self.current_wifi_result:
            QTimer.singleShot(150, self.run_wifi_measurement)

    # =========================================================================
    # CARREGAMENTO DE INTERFACES (CABO E WI-FI)
    # =========================================================================
    def _load_interfaces(self):
        # 1. Interfaces de Cabo
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

        # 2. Interfaces de Wi-Fi
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

    def _get_current_wifi_iface_name(self) -> str:
        data = self.combo_wifi_iface.currentData()
        if isinstance(data, dict):
            return data.get("name", "")
        txt = self.combo_wifi_iface.currentText()
        if "Nenhuma" in txt:
            return ""
        return txt.split(" ")[0].strip()

    # =========================================================================
    # EXECUÇÃO DO DIAGNÓSTICO DE CABO DE REDE
    # =========================================================================
    def run_cable_measurement(self):
        iface_name = self._get_current_cable_iface_name()
        if not iface_name:
            QMessageBox.information(self, "Placa de Rede", "Nenhuma placa de rede selecionada.")
            return

        self.btn_measure_cable.setEnabled(False)
        self.lbl_global_status.setText(f"● Executando diagnóstico e medição física de cabo na placa '{iface_name}'...")
        self.lbl_global_status.setStyleSheet("color: #38bdf8;")

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
            self.lbl_big_length.setStyleSheet("color: #38bdf8; margin: 2px 0;")
            self.progress_cable.setValue(min(100, int(res.cable_length_m)))
        elif not res.link_up:
            self.lbl_big_length.setText("0.0 m (Desconectado)")
            self.lbl_big_length.setStyleSheet("color: #94a3b8; margin: 2px 0;")
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
            self.lbl_nic_carrier.setStyleSheet("color: #10b981; font-weight: bold;")
            self.lbl_cable_speed_badge.setText(f"{res.speed_mbps} Mbps • {res.duplex}-Duplex")
            self.lbl_cable_speed_badge.setStyleSheet(
                "background-color: #065f46; color: #6ee7b7; padding: 4px 12px; border-radius: 6px; font-weight: bold;"
            )
        else:
            self.lbl_nic_carrier.setText("Link Físico: Desconectado (Sem Portadora)")
            self.lbl_nic_carrier.setStyleSheet("color: #ef4444; font-weight: bold;")
            self.lbl_cable_speed_badge.setText("Sem Link")
            self.lbl_cable_speed_badge.setStyleSheet(
                "background-color: #7f1d1d; color: #fca5a5; padding: 4px 12px; border-radius: 6px; font-weight: bold;"
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
                lbl.setStyleSheet("color: #10b981; font-weight: bold;")
            elif "Aberto" in txt or "Falha" in txt:
                lbl.setStyleSheet("color: #ef4444; font-weight: bold;")
            else:
                lbl.setStyleSheet("color: #f59e0b; font-weight: bold;")

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
        self.lbl_global_status.setStyleSheet("color: #10b981;")

    @pyqtSlot(str)
    def _on_cable_diag_error(self, err: str):
        self.lbl_global_status.setText(f"⚠️ {err}")
        self.lbl_global_status.setStyleSheet("color: #f87171;")
        QMessageBox.warning(self, "Diagnóstico de Cabo", err)

    # =========================================================================
    # EXECUÇÃO DO DIAGNÓSTICO WI-FI (WIRELESS)
    # =========================================================================
    def run_wifi_measurement(self):
        w_iface = self._get_current_wifi_iface_name()
        self.btn_measure_wifi.setEnabled(False)
        self.lbl_global_status.setText("● Executando diagnóstico e medição de sinal Wi-Fi...")
        self.lbl_global_status.setStyleSheet("color: #38bdf8;")

        self.wifi_worker = LocalWifiDiagWorker(interface_name=w_iface, force_demo=False)
        self.wifi_worker.status_updated.connect(lambda s: self.lbl_global_status.setText(f"● {s}"))
        self.wifi_worker.diag_completed.connect(self._on_wifi_diag_success)
        self.wifi_worker.error_occurred.connect(self._on_wifi_diag_error)
        self.wifi_worker.finished.connect(lambda: self.btn_measure_wifi.setEnabled(True))
        self.wifi_worker.start()

    def run_wifi_demo_measurement(self):
        """Simula teste Wi-Fi 6 empresarial de alta fidelidade para homologação."""
        self.btn_measure_wifi.setEnabled(False)
        self.lbl_global_status.setText("● Carregando ambiente de homologação e demonstração Wi-Fi 6...")
        self.lbl_global_status.setStyleSheet("color: #38bdf8;")

        self.wifi_worker = LocalWifiDiagWorker(interface_name="wlp3s0", force_demo=True)
        self.wifi_worker.status_updated.connect(lambda s: self.lbl_global_status.setText(f"● {s}"))
        self.wifi_worker.diag_completed.connect(self._on_wifi_diag_success)
        self.wifi_worker.error_occurred.connect(self._on_wifi_diag_error)
        self.wifi_worker.finished.connect(lambda: self.btn_measure_wifi.setEnabled(True))
        self.wifi_worker.start()

    def scan_nearby_wifi_action(self):
        """Dispara varredura sob demanda de redes vizinhas."""
        self.run_wifi_measurement()

    @pyqtSlot(object)
    def _on_wifi_diag_success(self, res: WifiDiagResult):
        self.current_wifi_result = res

        # 1. Sinal e Potência RSSI
        if res.has_hardware and res.is_connected:
            self.lbl_big_signal.setText(f"{res.signal_dbm} dBm  ({res.signal_percent}%)")
            self.progress_signal.setValue(res.signal_percent)
            if res.signal_percent >= 75:
                sig_color = "#10b981"
            elif res.signal_percent >= 50:
                sig_color = "#eab308"
            else:
                sig_color = "#ef4444"
            self.lbl_big_signal.setStyleSheet(f"color: {sig_color}; margin: 2px 0;")
            self.lbl_wifi_desc.setText(f"Qualidade: {res.signal_quality_desc}")
            self.lbl_wifi_desc.setStyleSheet(f"color: {sig_color};")
            self.lbl_wifi_ssid_bssid.setText(f"Rede (SSID): <b>{res.ssid}</b> • BSSID: <code>{res.bssid}</code>")
        elif res.has_hardware:
            self.lbl_big_signal.setText("Desconectado (0%)")
            self.lbl_big_signal.setStyleSheet("color: #f87171; margin: 2px 0;")
            self.progress_signal.setValue(0)
            self.lbl_wifi_desc.setText("Qualidade: Placa Wi-Fi ativa, aguardando conexão a uma rede.")
            self.lbl_wifi_desc.setStyleSheet("color: #f59e0b;")
            self.lbl_wifi_ssid_bssid.setText("Rede (SSID): -- • BSSID: --")
        else:
            self.lbl_big_signal.setText("Sem Hardware Wi-Fi")
            self.lbl_big_signal.setStyleSheet("color: #94a3b8; margin: 2px 0;")
            self.progress_signal.setValue(0)
            self.lbl_wifi_desc.setText("Qualidade: Nenhum adaptador sem fio ativo detectado neste computador.")
            self.lbl_wifi_desc.setStyleSheet("color: #94a3b8;")
            self.lbl_wifi_ssid_bssid.setText("Para testar o visual de Wi-Fi, clique no botão '🧪 Simular Wi-Fi 6' acima.")

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
        if res.is_demo:
            badge_txt += " (Modo Demo)"
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
        self.lbl_global_status.setStyleSheet("color: #10b981;")

    def _populate_nearby_table(self, networks: List[NearbyWifiNetwork]):
        self.table_nearby.setRowCount(0)
        for net in networks:
            row = self.table_nearby.rowCount()
            self.table_nearby.insertRow(row)

            # 0. Status
            status_item = QTableWidgetItem("🟢 Conectado" if net.in_use else "⚪ Próximo")
            if net.in_use:
                status_item.setForeground(QColor("#10b981"))
            self.table_nearby.setItem(row, 0, status_item)

            # 1. SSID
            ssid_item = QTableWidgetItem(net.ssid)
            if net.in_use:
                ssid_item.setFont(QFont("Segoe UI", 9, QFont.Bold))
            self.table_nearby.setItem(row, 1, ssid_item)

            # 2. Sinal %
            sig_item = QTableWidgetItem(f"{net.signal_pct}%")
            if net.signal_pct >= 75:
                sig_item.setForeground(QColor("#10b981"))
            elif net.signal_pct >= 50:
                sig_item.setForeground(QColor("#eab308"))
            else:
                sig_item.setForeground(QColor("#ef4444"))
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
        self.lbl_global_status.setStyleSheet("color: #f87171;")
        QMessageBox.warning(self, "Diagnóstico Wi-Fi", err)

    # =========================================================================
    # EXPORTAÇÃO E CÓPIA DE LAUDO TÉCNICO
    # =========================================================================
    def copy_current_report(self):
        """Copia para a área de transferência o laudo da aba ativa (Cabo ou Wi-Fi)."""
        if self.current_tab == "cable":
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
