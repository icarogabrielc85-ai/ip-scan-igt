#!/usr/bin/env python3
"""
Nmap & NSE Scripting Engine Console Dialog for IP Scan IGT.
Provides a modern, high-fidelity UI/UX (aligned with the application's design system)
integrating:
 1. Full interactive catalog of 605 official Nmap NSE scripts (https://github.com/nmap/nmap/tree/master/scripts);
 2. 1-Click NSE Presets (Vulnerabilities, Discovery, Web/HTTP, SSL/TLS Ciphers, Windows/SMB, Auth/Brute, Cameras/IoT);
 3. Real-time script search & multi-select with live command preview;
 4. Direct 1-click execution ("só selecionar e mandar rodar");
 5. Structured results viewing with colored vulnerability/security findings;
 6. Intelligent device diagnosis & ports table with quick actions (VLC RTSP, Web, SSH);
 7. Live technical terminal output.
"""

from datetime import datetime
import os
import shlex
import subprocess
import sys
from typing import Dict, List, Optional, Set

from PyQt5.QtCore import QPoint, Qt, QUrl, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QColor, QDesktopServices, QFont, QIcon, QTextCursor
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from i18n import SUPPORTED_LANGUAGES, get_current_language, set_current_language, tr
from nmap_engine import (
    NmapScannerThread,
    get_nmap_path,
    is_nmap_available,
    parse_nmap_output,
)
from nmap_scripts_db import (
    NSE_PRESETS,
    get_all_scripts,
    get_category_label,
    get_presets,
    get_script_desc,
    parse_nse_script_output,
    search_scripts,
)


def get_nmap_dialog_palette(is_dark: bool) -> dict:
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
            "accent_dark": "#0284c7",
            "btn_bg": "#1e293b",
            "btn_hover": "#334155",
            "btn_text": "#f8fafc",
            "primary_btn_bg": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #0369a1)",
            "primary_btn_hover": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0369a1, stop:1 #0284c7)",
            "run_btn_bg": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #10b981, stop:1 #059669)",
            "run_btn_hover": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #34d399, stop:1 #10b981)",
            "table_bg": "#0e141f",
            "table_alt": "#131d31",
            "table_hdr": "#162032",
            "table_hdr_text": "#94a3b8",
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
        return {
            "bg": "#f1f5f9",
            "header_bg": "#ffffff",
            "card_bg": "#ffffff",
            "card_inner": "#f8fafc",
            "border": "#cbd5e1",
            "border_focus": "#0284c7",
            "text_main": "#0f172a",
            "text_sub": "#475569",
            "text_muted": "#64748b",
            "accent": "#0284c7",
            "accent_dark": "#0369a1",
            "btn_bg": "#f1f5f9",
            "btn_hover": "#e2e8f0",
            "btn_text": "#0f172a",
            "primary_btn_bg": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #0369a1)",
            "primary_btn_hover": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0369a1, stop:1 #075985)",
            "run_btn_bg": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #059669, stop:1 #047857)",
            "run_btn_hover": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #10b981, stop:1 #059669)",
            "table_bg": "#ffffff",
            "table_alt": "#f8fafc",
            "table_hdr": "#f1f5f9",
            "table_hdr_text": "#475569",
            "success": "#059669",
            "success_bg": "#d1fae5",
            "success_text": "#065f46",
            "warning": "#d97706",
            "warning_bg": "#fef3c7",
            "warning_text": "#92400e",
            "danger": "#dc2626",
            "danger_bg": "#fee2e2",
            "danger_text": "#991b1b",
        }


class NmapDialog(QDialog):
    ports_applied = pyqtSignal(str, list, dict)  # ip, open_ports_list, services_dict

    def __init__(
        self,
        parent=None,
        target: str = "",
        hostname: str = "",
        is_dark: Optional[bool] = None,
    ):
        super().__init__(parent)
        self.target = target.strip()
        self.hostname = hostname.strip()
        if is_dark is None:
            self.is_dark = getattr(parent, "is_dark_mode", False) if parent else True
        else:
            self.is_dark = is_dark

        self.palette = get_nmap_dialog_palette(self.is_dark)
        self.scan_thread: Optional[NmapScannerThread] = None
        self.last_parsed_result: Dict = {}
        self.last_raw_text: str = ""

        # NSE Scripts State
        self.all_scripts = get_all_scripts()
        self.selected_scripts: Set[str] = {"banner", "http-title"}
        self._updating_table_check = False
        self.current_lang = get_current_language()

        self.setWindowTitle(f"{tr('nmap_window_title', 'Auditoria Nmap & Scripts NSE')} — {self.hostname or self.target or 'Host'}")
        self.setWindowFlags(self.windowFlags() | Qt.WindowMinMaxButtonsHint | Qt.WindowCloseButtonHint)

        # 90% dimension for restored geometry
        screen = QApplication.primaryScreen()
        if screen:
            geo = screen.availableGeometry()
            w = max(1000, min(1480, int(geo.width() * 0.90)))
            h = max(700, min(950, int(geo.height() * 0.90)))
            x = geo.x() + (geo.width() - w) // 2
            y = geo.y() + (geo.height() - h) // 2
            self.setGeometry(x, y, w, h)
        else:
            self.resize(1120, 780)

        self._apply_styling()
        self.init_ui()

        # Inicia maximizado por padrão para total clareza e imersão
        self.showMaximized()

    def _apply_styling(self):
        p = self.palette
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {p['bg']};
                color: {p['text_main']};
                font-family: "Segoe UI", "Noto Sans", "Ubuntu", sans-serif;
            }}
            QFrame#topNavFrame {{
                background-color: {p['header_bg']};
                border-bottom: 1px solid {p['border']};
                padding: 10px 16px;
            }}
            QFrame#cardFrame {{
                background-color: {p['card_bg']};
                border: 1px solid {p['border']};
                border-radius: 8px;
                padding: 12px;
            }}
            QFrame#cardSubFrame {{
                background-color: {p['card_inner']};
                border: 1px solid {p['border']};
                border-radius: 6px;
                padding: 8px;
            }}
            QLabel {{
                color: {p['text_main']};
            }}
            QLineEdit, QComboBox {{
                background-color: {p['card_bg']};
                color: {p['text_main']};
                border: 1px solid {p['border']};
                border-radius: 6px;
                padding: 4px 10px;
                min-height: 28px;
                font-size: 12px;
            }}
            QLineEdit:focus, QComboBox:focus {{
                border: 1.5px solid {p['border_focus']};
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
                color: #ffffff;
                font-weight: bold;
                border: 1px solid {p['border_focus']};
                border-radius: 6px;
                padding: 6px 18px;
            }}
            QPushButton#primaryBtn:hover {{
                background: {p['primary_btn_hover']};
            }}
            QPushButton#runBtn {{
                background: {p['run_btn_bg']};
                color: #ffffff;
                font-weight: bold;
                font-size: 13px;
                border: 1px solid #059669;
                border-radius: 6px;
                padding: 6px 20px;
            }}
            QPushButton#runBtn:hover {{
                background: {p['run_btn_hover']};
            }}
            QPushButton#presetBtn {{
                background-color: {p['card_inner']};
                color: {p['text_main']};
                border: 1px solid {p['border']};
                border-radius: 14px;
                padding: 4px 12px;
                font-size: 11px;
                font-weight: bold;
            }}
            QPushButton#presetBtn:hover {{
                background-color: {p['btn_hover']};
                border-color: {p['accent']};
                color: {p['accent']};
            }}
            QProgressBar {{
                background-color: {p['card_inner']};
                border: 1px solid {p['border']};
                border-radius: 3px;
                height: 6px;
                text-align: center;
            }}
            QProgressBar::chunk {{
                background: {p['primary_btn_bg']};
                border-radius: 2px;
            }}
            QTabWidget::pane {{
                border: 1px solid {p['border']};
                border-radius: 8px;
                background-color: {p['card_bg']};
            }}
            QTabBar::tab {{
                background-color: {p['header_bg']};
                color: {p['text_sub']};
                font-weight: bold;
                padding: 8px 18px;
                font-size: 12px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                border: 1px solid {p['border']};
                margin-right: 4px;
            }}
            QTabBar::tab:selected {{
                background-color: {p['card_bg']};
                color: {p['accent']};
                border-bottom: 2px solid {p['accent']};
            }}
            QTableWidget {{
                background-color: {p['table_bg']};
                alternate-background-color: {p['table_alt']};
                color: {p['text_main']};
                border: 1px solid {p['border']};
                border-radius: 6px;
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
            QScrollBar:vertical {{
                border: none;
                background: {p['bg']};
                width: 10px;
            }}
            QScrollBar::handle:vertical {{
                background: {p['border']};
                min-height: 20px;
                border-radius: 5px;
            }}
        """)

    def init_ui(self):
        p = self.palette
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ---------------------------------------------------------------------
        # 1. TOP HEADER & TARGET BAR
        # ---------------------------------------------------------------------
        top_frame = QFrame(self)
        top_frame.setObjectName("topNavFrame")
        top_layout = QVBoxLayout(top_frame)
        top_layout.setContentsMargins(16, 10, 16, 10)
        top_layout.setSpacing(8)

        row_header = QHBoxLayout()
        title_box = QVBoxLayout()
        title_box.setSpacing(1)
        self.lbl_title = QLabel(tr("nmap_title", "🔍 AUDITORIA NMAP & SCRIPTS NSE (NMAP SCRIPTING ENGINE)"))
        self.lbl_title.setFont(QFont("Segoe UI", 12, QFont.Bold))
        self.lbl_title.setStyleSheet(f"color: {p['accent']}; letter-spacing: 0.5px;")
        title_box.addWidget(self.lbl_title)

        self.lbl_sub = QLabel(tr("nmap_subtitle", "Catálogo com os 605 scripts oficiais (nmap.org/nsedoc) • Seleção e Execução Direta em 1 Clique"))
        self.lbl_sub.setFont(QFont("Segoe UI", 9))
        self.lbl_sub.setStyleSheet(f"color: {p['text_sub']};")
        title_box.addWidget(self.lbl_sub)
        row_header.addLayout(title_box)

        row_header.addStretch(1)

        # Seletor de Idioma Integrado
        self.combo_lang = QComboBox()
        self.combo_lang.setFixedHeight(28)
        self.combo_lang.setToolTip("Alterar idioma (Change application language)")
        for code, lang_info in SUPPORTED_LANGUAGES.items():
            self.combo_lang.addItem(f"{lang_info['flag']}  {lang_info['native']}", code)
        idx_lang = self.combo_lang.findData(self.current_lang)
        if idx_lang >= 0:
            self.combo_lang.setCurrentIndex(idx_lang)
        self.combo_lang.currentIndexChanged.connect(self._on_language_changed)
        row_header.addWidget(self.combo_lang)

        self.btn_toggle_fullscreen = QPushButton(tr("nmap_btn_fullscreen", "⛶ Tela Cheia"))
        self.btn_toggle_fullscreen.setToolTip("Alternar modo tela cheia / janela maximizada (F11)")
        self.btn_toggle_fullscreen.clicked.connect(self.toggle_fullscreen)
        row_header.addWidget(self.btn_toggle_fullscreen)

        self.btn_copy = QPushButton(tr("nmap_btn_copy", "📋 Copiar"))
        self.btn_copy.setToolTip("Copiar saída completa")
        self.btn_copy.clicked.connect(self.copy_output)
        row_header.addWidget(self.btn_copy)

        self.btn_save = QPushButton(tr("nmap_btn_save", "💾 Salvar"))
        self.btn_save.setToolTip("Salvar relatório em arquivo texto")
        self.btn_save.clicked.connect(self.save_output)
        row_header.addWidget(self.btn_save)

        self.btn_close = QPushButton(tr("nmap_btn_close", "✕ Fechar"))
        self.btn_close.clicked.connect(self.close)
        row_header.addWidget(self.btn_close)

        top_layout.addLayout(row_header)

        # Row Target & Port Scope Controls
        row_ctrl = QHBoxLayout()
        row_ctrl.setSpacing(10)

        self.lbl_tgt = QLabel(f"<b>{tr('nmap_target_ip', 'Alvo (IP / Host):')}</b>")
        row_ctrl.addWidget(self.lbl_tgt)

        self.txt_target = QLineEdit(self.target or "192.168.1.1")
        self.txt_target.setMinimumWidth(180)
        self.txt_target.textChanged.connect(self._update_command_preview)
        row_ctrl.addWidget(self.txt_target)

        self.lbl_port = QLabel(f"<b>{tr('nmap_port_scope', 'Escopo de Portas:')}</b>")
        row_ctrl.addWidget(self.lbl_port)

        self.combo_ports = QComboBox()
        self.combo_ports.setMinimumWidth(240)
        self.combo_ports.addItem("🚀 Top 100 Portas Rápidas (-F)", "-F")
        self.combo_ports.addItem("🌐 Serviços Web & Comuns (80,443,445,8080...)", "21,22,23,53,80,111,139,443,445,554,631,2443,3306,3389,3702,8000,8006,8080,8443,8899")
        self.combo_ports.addItem("🎥 Câmeras & CFTV (80,554,1935,2443,3702,8000,8899)", "80,554,1935,2020,2443,3702,8000,8080,8443,8899")
        self.combo_ports.addItem("🔥 Todas as 65.535 Portas (-p-)", "-p-")
        self.combo_ports.addItem("🎯 Portas Personalizadas...", "custom")
        self.combo_ports.currentIndexChanged.connect(self._on_port_scope_changed)
        row_ctrl.addWidget(self.combo_ports)

        self.txt_custom_ports = QLineEdit("80,443,445")
        self.txt_custom_ports.setMaximumWidth(120)
        self.txt_custom_ports.setVisible(False)
        self.txt_custom_ports.textChanged.connect(self._update_command_preview)
        row_ctrl.addWidget(self.txt_custom_ports)

        row_ctrl.addStretch(1)

        self.btn_run = QPushButton(tr("nmap_start_scan", "▶  Iniciar Varredura / Executar"))
        self.btn_run.setObjectName("runBtn")
        self.btn_run.setFixedHeight(32)
        self.btn_run.setToolTip("Dispara a execução do Nmap com as portas e scripts configurados (Ctrl+Enter)")
        self.btn_run.clicked.connect(self.toggle_scan)
        row_ctrl.addWidget(self.btn_run)

        top_layout.addLayout(row_ctrl)
        root_layout.addWidget(top_frame)

        # Progress bar
        self.prog_bar = QProgressBar()
        self.prog_bar.setFixedHeight(5)
        self.prog_bar.setTextVisible(False)
        self.prog_bar.setRange(0, 0)
        self.prog_bar.setVisible(False)
        root_layout.addWidget(self.prog_bar)

        # ---------------------------------------------------------------------
        # 2. MAIN TABS (Scripts NSE, Relatório & Portas, Resultados NSE/CVEs, Terminal)
        # ---------------------------------------------------------------------
        content_widget = QWidget(self)
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(16, 12, 16, 12)
        content_layout.setSpacing(10)

        self.tabs = QTabWidget()

        # ABA 0: SCRIPTS NSE (Catálogo Completo, Presets & Seleção)
        self.tab_scripts = self._create_scripts_tab()
        self.tabs.addTab(self.tab_scripts, tr("nmap_tab_scripts", "📜 Scripts NSE (Seleção & Execução)"))

        # ABA 1: RELATÓRIO ESTRUTURADO & PORTAS
        self.tab_report = self._create_report_tab()
        self.tabs.addTab(self.tab_report, tr("nmap_tab_report", "📊 Relatório & Portas"))

        # ABA 2: RESULTADOS DOS SCRIPTS & VULNERABILIDADES (CVEs)
        self.tab_cves = self._create_results_tab()
        self.tabs.addTab(self.tab_cves, tr("nmap_tab_results", "🛡️ Resultados dos Scripts & CVEs"))

        # ABA 3: TERMINAL NMAP (Log Técnico)
        self.tab_raw = self._create_terminal_tab()
        self.tabs.addTab(self.tab_raw, tr("nmap_tab_terminal", "💻 Terminal Nmap (Log Técnico)"))

        content_layout.addWidget(self.tabs)
        root_layout.addWidget(content_widget, 1)

        # Initial populate of scripts table & command preview
        self._populate_scripts_table(self.all_scripts)
        self._update_command_preview()

    # =========================================================================
    # ABA 0: SCRIPTS NSE (SELEÇÃO INTUITIVA & EXECUÇÃO EM 1 CLIQUE)
    # =========================================================================
    def _create_scripts_tab(self) -> QWidget:
        p = self.palette
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        # 1. PRESETS RÁPIDOS (1-CLIQUE)
        presets_frame = QFrame(tab)
        presets_frame.setObjectName("cardFrame")
        pf_layout = QVBoxLayout(presets_frame)
        pf_layout.setContentsMargins(12, 10, 12, 10)
        pf_layout.setSpacing(8)

        self.lbl_preset_t = QLabel(f"<b>{tr('nmap_quick_presets', '⚡ PRESETS RÁPIDOS DE SCRIPTS NSE (1-CLIQUE):')}</b>")
        self.lbl_preset_t.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.lbl_preset_t.setStyleSheet(f"color: {p['accent']};")
        pf_layout.addWidget(self.lbl_preset_t)

        presets_row = QHBoxLayout()
        presets_row.setSpacing(8)

        self.preset_buttons: Dict[str, QPushButton] = {}
        presets = get_presets(self.current_lang)
        for pid, pdata in presets.items():
            btn_p = QPushButton(pdata["name"])
            btn_p.setObjectName("presetBtn")
            btn_p.setToolTip(f"{pdata['desc']}\nArgumento NSE: --script {pdata['arg']}")
            btn_p.clicked.connect(lambda _, key=pid: self._apply_preset(key))
            self.preset_buttons[pid] = btn_p
            presets_row.addWidget(btn_p)

        self.btn_clear = QPushButton(tr("clear", "🧹 Limpar"))
        self.btn_clear.setObjectName("presetBtn")
        self.btn_clear.setToolTip("Desmarcar todos os scripts")
        self.btn_clear.clicked.connect(self._clear_all_scripts)
        presets_row.addWidget(self.btn_clear)

        presets_row.addStretch(1)
        pf_layout.addLayout(presets_row)
        layout.addWidget(presets_frame)

        # 2. BARRA DE BUSCA, CATEGORIA E FILTRO
        search_bar = QHBoxLayout()
        search_bar.setSpacing(10)

        self.txt_script_search = QLineEdit()
        self.txt_script_search.setPlaceholderText(tr("nmap_search_placeholder", "🔍 Filtrar 605 scripts por nome, categoria ou palavra-chave (ex: ssl, smb, heartbleed, cve, auth, http)..."))
        self.txt_script_search.textChanged.connect(self._filter_scripts)
        search_bar.addWidget(self.txt_script_search, 2)

        self.lbl_cat = QLabel(f"<b>{tr('nmap_col_categories', 'Categoria')}:</b>")
        search_bar.addWidget(self.lbl_cat)

        self.combo_category = QComboBox()
        self._populate_category_combo()
        self.combo_category.currentIndexChanged.connect(self._filter_scripts)
        search_bar.addWidget(self.combo_category, 1)

        self.btn_check_vis = QPushButton(tr("nmap_btn_check_vis", "☑ Marcar Visíveis"))
        self.btn_check_vis.clicked.connect(self._check_all_visible)
        search_bar.addWidget(self.btn_check_vis)

        self.btn_uncheck_vis = QPushButton(tr("nmap_btn_uncheck_vis", "☐ Desmarcar Visíveis"))
        self.btn_uncheck_vis.clicked.connect(self._uncheck_all_visible)
        search_bar.addWidget(self.btn_uncheck_vis)

        self.lbl_selected_count = QLabel("<b>2 selecionados</b>")
        self.lbl_selected_count.setStyleSheet(
            f"background-color: {p['card_inner']}; color: {p['accent']}; padding: 4px 10px; border-radius: 12px; font-weight: bold; border: 1px solid {p['border']};"
        )
        search_bar.addWidget(self.lbl_selected_count)

        layout.addLayout(search_bar)

        # 3. TABELA COMPLETA DE SCRIPTS
        self.table_scripts = QTableWidget(0, 3)
        self.table_scripts.setHorizontalHeaderLabels([
            tr("nmap_col_script", "Script NSE"),
            tr("nmap_col_categories", "Categorias"),
            tr("nmap_col_description", "Descrição Funcional & Utilidade Prática")
        ])
        self.table_scripts.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_scripts.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_scripts.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table_scripts.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_scripts.setAlternatingRowColors(True)
        self.table_scripts.verticalHeader().setVisible(False)
        self.table_scripts.itemClicked.connect(self._on_script_row_clicked)
        self.table_scripts.itemChanged.connect(self._on_script_item_changed)
        layout.addWidget(self.table_scripts, 1)

        # 4. PAINEL DE COMANDO MONTADO & EXECUÇÃO DIRETA
        cmd_box = QFrame(tab)
        cmd_box.setObjectName("cardFrame")
        cb_layout = QVBoxLayout(cmd_box)
        cb_layout.setContentsMargins(12, 10, 12, 10)
        cb_layout.setSpacing(6)

        row_args = QHBoxLayout()
        lbl_args_t = QLabel("<b>Argumentos Adicionais / Scripts Manuais:</b>")
        lbl_args_t.setFont(QFont("Segoe UI", 9))
        row_args.addWidget(lbl_args_t)

        self.txt_extra_args = QLineEdit("")
        self.txt_extra_args.setPlaceholderText("Ex: --script-args unsafe=1 ou argumentos livres...")
        self.txt_extra_args.textChanged.connect(self._update_command_preview)
        row_args.addWidget(self.txt_extra_args, 1)
        cb_layout.addLayout(row_args)

        # Prévia Visual do Comando
        preview_row = QHBoxLayout()
        self.lbl_prev_t = QLabel(f"<b>{tr('nmap_cmd_preview', 'Comando:')}</b>")
        self.lbl_prev_t.setFont(QFont("Segoe UI", 9, QFont.Bold))
        preview_row.addWidget(self.lbl_prev_t)

        self.lbl_cmd_preview = QLabel("nmap -sT ...")
        self.lbl_cmd_preview.setFont(QFont("Monospace", 9, QFont.Bold))
        self.lbl_cmd_preview.setStyleSheet(
            f"background-color: {p['table_bg']}; color: {p['accent']}; padding: 6px 12px; border-radius: 6px; border: 1px solid {p['border']};"
        )
        preview_row.addWidget(self.lbl_cmd_preview, 1)

        self.btn_run_scripts = QPushButton(tr("nmap_run_scripts", "▶ Executar Scripts Selecionados"))
        self.btn_run_scripts.setObjectName("runBtn")
        self.btn_run_scripts.setFixedHeight(34)
        self.btn_run_scripts.setToolTip("Dispara imediatamente a varredura com os scripts marcados acima")
        self.btn_run_scripts.clicked.connect(self.toggle_scan)
        preview_row.addWidget(self.btn_run_scripts)
        cb_layout.addLayout(preview_row)

        layout.addWidget(cmd_box)
        return tab

    def _populate_category_combo(self):
        lang = self.current_lang or get_current_language()
        self.combo_category.addItem(tr("nmap_cat_all", "Todas as Categorias (605)"), "todas")
        self.combo_category.addItem(f"🛡️ vuln — {get_category_label('vuln', lang)} & CVEs (105)", "vuln")
        self.combo_category.addItem(f"🔍 discovery — {get_category_label('discovery', lang)} & Banners (309)", "discovery")
        self.combo_category.addItem(f"⚡ safe — {get_category_label('safe', lang)} / Sem Risco (347)", "safe")
        self.combo_category.addItem(f"⭐ default — {get_category_label('default', lang)} (-sC) (126)", "default")
        self.combo_category.addItem(f"🔑 auth — {get_category_label('auth', lang)} (38)", "auth")
        self.combo_category.addItem(f"🔨 brute — {get_category_label('brute', lang)} (75)", "brute")
        self.combo_category.addItem(f"🦠 malware — {get_category_label('malware', lang)} (10)", "malware")
        self.combo_category.addItem(f"💥 exploit — {get_category_label('exploit', lang)} (45)", "exploit")

    # =========================================================================
    # ABA 1: RELATÓRIO ESTRUTURADO & PORTAS
    # =========================================================================
    def _create_report_tab(self) -> QWidget:
        p = self.palette
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        # Diagnostic Banner Card
        self.diag_card = QFrame(tab)
        self.diag_card.setObjectName("cardFrame")
        diag_layout = QHBoxLayout(self.diag_card)
        diag_layout.setContentsMargins(12, 10, 12, 10)

        self.lbl_diag_icon = QLabel("💡")
        self.lbl_diag_icon.setStyleSheet("font-size: 28px; border: none;")
        diag_layout.addWidget(self.lbl_diag_icon)

        diag_text_box = QVBoxLayout()
        diag_text_box.setSpacing(2)
        self.lbl_diag_title = QLabel("Aguardando varredura...")
        self.lbl_diag_title.setFont(QFont("Segoe UI", 11, QFont.Bold))
        self.lbl_diag_title.setStyleSheet(f"color: {p['accent']}; border: none;")
        self.lbl_diag_desc = QLabel("Selecione os scripts ou o escopo de portas e clique em 'Iniciar Varredura / Executar'.")
        self.lbl_diag_desc.setStyleSheet(f"color: {p['text_main']}; font-size: 12px; border: none;")
        self.lbl_diag_desc.setWordWrap(True)
        diag_text_box.addWidget(self.lbl_diag_title)
        diag_text_box.addWidget(self.lbl_diag_desc)
        diag_layout.addLayout(diag_text_box, 1)
        layout.addWidget(self.diag_card)

        # Metric Badges
        metrics_bar = QHBoxLayout()
        metrics_bar.setSpacing(8)

        self.lbl_badge_open = QLabel("🟢 0 Abertas")
        self.lbl_badge_open.setStyleSheet(f"background-color: {p['success_bg']}; color: {p['success_text']}; font-weight: bold; font-size: 11px; padding: 4px 10px; border-radius: 12px;")

        self.lbl_badge_closed = QLabel("⚪ 0 Fechadas")
        self.lbl_badge_closed.setStyleSheet(f"background-color: {p['card_inner']}; color: {p['text_muted']}; font-weight: bold; font-size: 11px; padding: 4px 10px; border-radius: 12px;")

        self.lbl_badge_latency = QLabel("⚡ Latência: --")
        self.lbl_badge_latency.setStyleSheet(f"background-color: {p['card_inner']}; color: {p['accent']}; font-weight: bold; font-size: 11px; padding: 4px 10px; border-radius: 12px;")

        self.lbl_badge_cves = QLabel("🛡️ 0 CVEs")
        self.lbl_badge_cves.setStyleSheet(f"background-color: {p['card_inner']}; color: {p['text_muted']}; font-weight: bold; font-size: 11px; padding: 4px 10px; border-radius: 12px;")

        self.lbl_badge_nse = QLabel("📜 0 Scripts")
        self.lbl_badge_nse.setStyleSheet(f"background-color: {p['card_inner']}; color: {p['accent']}; font-weight: bold; font-size: 11px; padding: 4px 10px; border-radius: 12px;")

        metrics_bar.addWidget(self.lbl_badge_open)
        metrics_bar.addWidget(self.lbl_badge_closed)
        metrics_bar.addWidget(self.lbl_badge_latency)
        metrics_bar.addWidget(self.lbl_badge_cves)
        metrics_bar.addWidget(self.lbl_badge_nse)
        metrics_bar.addStretch()

        self.chk_hide_closed = QCheckBox("Ocultar portas fechadas")
        self.chk_hide_closed.setChecked(True)
        self.chk_hide_closed.stateChanged.connect(self.refresh_ports_table)
        metrics_bar.addWidget(self.chk_hide_closed)
        layout.addLayout(metrics_bar)

        # Structured Table of Ports
        self.table_ports = QTableWidget(0, 5)
        self.table_ports.setHorizontalHeaderLabels([
            "Porta / Protocolo", "Estado", "Serviço", "Versão / Detalhes Detectados", "Ação Rápida"
        ])
        self.table_ports.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_ports.setAlternatingRowColors(True)
        self.table_ports.verticalHeader().setVisible(False)
        self.table_ports.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_ports.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_ports.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_ports.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table_ports.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        layout.addWidget(self.table_ports, 1)

        # Bottom Actions Bar
        bottom_box = QHBoxLayout()
        bottom_box.setSpacing(8)

        self.btn_apply = QPushButton("➕ Aplicar Portas ao Dispositivo")
        self.btn_apply.setFixedHeight(32)
        self.btn_apply.setEnabled(False)
        self.btn_apply.setStyleSheet(f"background-color: {p['success']}; color: #ffffff; font-weight: bold; border-radius: 5px;")
        self.btn_apply.clicked.connect(self.apply_ports_to_device)
        bottom_box.addWidget(self.btn_apply)

        self.btn_vlc = QPushButton("🎬 Assistir RTSP (VLC)")
        self.btn_vlc.setFixedHeight(32)
        self.btn_vlc.setEnabled(False)
        self.btn_vlc.clicked.connect(self.launch_vlc_rtsp)
        bottom_box.addWidget(self.btn_vlc)

        self.btn_web = QPushButton("🌐 Abrir no Navegador")
        self.btn_web.setFixedHeight(32)
        self.btn_web.setEnabled(False)
        self.btn_web.clicked.connect(self.launch_web_browser)
        bottom_box.addWidget(self.btn_web)

        bottom_box.addStretch()
        layout.addLayout(bottom_box)

        return tab

    # =========================================================================
    # ABA 2: RESULTADOS DOS SCRIPTS NSE & VULNERABILIDADES (CVEs)
    # =========================================================================
    def _create_results_tab(self) -> QWidget:
        p = self.palette
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        # Splitter entre Scripts e Tabela CVEs
        splitter = QSplitter(Qt.Vertical)

        # Top section: Script findings
        top_sec = QWidget()
        ts_layout = QVBoxLayout(top_sec)
        ts_layout.setContentsMargins(0, 0, 0, 0)
        ts_layout.setSpacing(6)

        lbl_nse_t = QLabel("<b>📜 RESULTADOS E ACHADOS DOS SCRIPTS NSE:</b>")
        lbl_nse_t.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_nse_t.setStyleSheet(f"color: {p['accent']};")
        ts_layout.addWidget(lbl_nse_t)

        self.table_nse_results = QTableWidget(0, 4)
        self.table_nse_results.setHorizontalHeaderLabels([
            "Script", "Alvo / Porta", "Status / Avaliação", "Saída Formatada do Script"
        ])
        self.table_nse_results.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_nse_results.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_nse_results.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_nse_results.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table_nse_results.setAlternatingRowColors(True)
        self.table_nse_results.verticalHeader().setVisible(False)
        ts_layout.addWidget(self.table_nse_results, 1)
        splitter.addWidget(top_sec)

        # Bottom section: CVE Correlation Table
        bot_sec = QWidget()
        bs_layout = QVBoxLayout(bot_sec)
        bs_layout.setContentsMargins(0, 0, 0, 0)
        bs_layout.setSpacing(6)

        self.lbl_cve_summary = QLabel("<b>🛡️ VULNERABILIDADES CORRELACIONADAS (BASE LOCAL SQLITE DE CVEs):</b>")
        self.lbl_cve_summary.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.lbl_cve_summary.setStyleSheet(f"color: {p['accent']};")
        bs_layout.addWidget(self.lbl_cve_summary)

        self.table_cves = QTableWidget(0, 5)
        self.table_cves.setHorizontalHeaderLabels([
            "CVE ID", "Severidade / CVSS", "Serviço / Versão", "Título / Descrição da Vulnerabilidade", "Recomendação de Mitigação"
        ])
        self.table_cves.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_cves.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_cves.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_cves.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table_cves.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table_cves.setAlternatingRowColors(True)
        self.table_cves.verticalHeader().setVisible(False)
        bs_layout.addWidget(self.table_cves, 1)
        splitter.addWidget(bot_sec)

        splitter.setSizes([350, 250])
        layout.addWidget(splitter, 1)
        return tab

    # =========================================================================
    # ABA 3: TERMINAL NMAP (LOG TÉCNICO)
    # =========================================================================
    def _create_terminal_tab(self) -> QWidget:
        p = self.palette
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(8)

        lbl_raw_info = QLabel("Saída direta de texto emitida pelo Nmap em tempo real (para auditoria técnica aprofundada):")
        lbl_raw_info.setStyleSheet(f"color: {p['text_muted']}; font-size: 11px;")
        layout.addWidget(lbl_raw_info)

        self.txt_console = QTextEdit()
        self.txt_console.setReadOnly(True)
        self.txt_console.setFont(QFont("Monospace", 9))
        self.txt_console.setStyleSheet(f"""
            QTextEdit {{
                background-color: {p['table_bg']};
                color: {p['text_main']};
                border: 1px solid {p['border']};
                border-radius: 6px;
                padding: 10px;
                line-height: 1.4;
            }}
        """)
        layout.addWidget(self.txt_console, 1)
        return tab

    # =========================================================================
    # GERENCIAMENTO DE SCRIPTS NSE, PRESETS & TABELA
    # =========================================================================
    def _populate_scripts_table(self, scripts_list: List[dict]):
        self._updating_table_check = True
        self.table_scripts.setUpdatesEnabled(False)
        try:
            p = self.palette
            lang = self.current_lang or get_current_language()
            self.table_scripts.setRowCount(len(scripts_list))

            for row, s in enumerate(scripts_list):
                sname = s["name"]
                cats = s["categories"]
                desc = get_script_desc(s, lang)

                # Col 0: Checkbox + Script Name
                it_name = QTableWidgetItem(sname)
                it_name.setFlags(Qt.ItemIsEnabled | Qt.ItemIsUserCheckable | Qt.ItemIsSelectable)
                it_name.setCheckState(Qt.Checked if sname in self.selected_scripts else Qt.Unchecked)
                it_name.setFont(QFont("Segoe UI", 9, QFont.Bold))
                if "vuln" in cats:
                    it_name.setForeground(QColor(p["danger"]))
                elif "discovery" in cats:
                    it_name.setForeground(QColor(p["accent"]))
                else:
                    it_name.setForeground(QColor(p["text_main"]))
                it_name.setData(Qt.UserRole, sname)
                self.table_scripts.setItem(row, 0, it_name)

                # Col 1: Categories (Traduzidas conforme o idioma)
                cat_translated = [get_category_label(c, lang) for c in cats]
                cat_str = " • ".join(cat_translated)
                it_cat = QTableWidgetItem(cat_str)
                it_cat.setFont(QFont("Segoe UI", 8))
                it_cat.setForeground(QColor(p["text_muted"]))
                it_cat.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                self.table_scripts.setItem(row, 1, it_cat)

                # Col 2: Description (Traduzida conforme o idioma selecionado)
                it_desc = QTableWidgetItem(desc)
                it_desc.setFont(QFont("Segoe UI", 9))
                it_desc.setForeground(QColor(p["text_main"]))
                it_desc.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                self.table_scripts.setItem(row, 2, it_desc)
        finally:
            self.table_scripts.setUpdatesEnabled(True)
            self._updating_table_check = False
        self._update_selected_count_badge()

    def _on_script_row_clicked(self, item: QTableWidgetItem):
        row = item.row()
        name_item = self.table_scripts.item(row, 0)
        if name_item and item != name_item:
            # Toggle checkbox when clicking on description or category
            new_state = Qt.Unchecked if name_item.checkState() == Qt.Checked else Qt.Checked
            name_item.setCheckState(new_state)

    def _on_script_item_changed(self, item: QTableWidgetItem):
        if self._updating_table_check or item.column() != 0:
            return
        sname = item.data(Qt.UserRole) or item.text()
        if item.checkState() == Qt.Checked:
            self.selected_scripts.add(sname)
        else:
            self.selected_scripts.discard(sname)
        self._update_selected_count_badge()
        self._update_command_preview()

    def _update_selected_count_badge(self):
        count = len(self.selected_scripts)
        self.lbl_selected_count.setText(f"<b>🏷️ {count} selecionado(s)</b>")
        if hasattr(self, "btn_run_scripts"):
            self.btn_run_scripts.setText(f"{tr('nmap_run_scripts', '▶ Executar Scripts Selecionados')} ({count})")

    def _filter_scripts(self):
        q = self.txt_script_search.text().strip()
        cat = self.combo_category.currentData() or ""
        lang = self.current_lang or get_current_language()
        filtered = search_scripts(q, cat, lang)
        self._populate_scripts_table(filtered)

    def _on_language_changed(self):
        code = self.combo_lang.currentData()
        if code and code != self.current_lang:
            self.current_lang = code
            set_current_language(code)
            self.retranslate_ui()

    def retranslate_ui(self):
        lang = self.current_lang or get_current_language()
        self.setWindowTitle(f"{tr('nmap_window_title', 'Auditoria Nmap & Scripts NSE')} — {self.hostname or self.target or 'Host'}")

        if hasattr(self, "lbl_title"):
            self.lbl_title.setText(tr("nmap_title", "🔍 AUDITORIA NMAP & SCRIPTS NSE (NMAP SCRIPTING ENGINE)"))
        if hasattr(self, "lbl_sub"):
            self.lbl_sub.setText(tr("nmap_subtitle", "Catálogo com os 605 scripts oficiais (nmap.org/nsedoc) • Seleção e Execução Direta em 1 Clique"))

        if hasattr(self, "tabs"):
            self.tabs.setTabText(0, tr("nmap_tab_scripts", "📜 Scripts NSE (Seleção & Execução)"))
            self.tabs.setTabText(1, tr("nmap_tab_report", "📊 Relatório & Portas"))
            self.tabs.setTabText(2, tr("nmap_tab_results", "🛡️ Resultados dos Scripts & CVEs"))
            self.tabs.setTabText(3, tr("nmap_tab_terminal", "💻 Terminal Nmap (Log Técnico)"))

        if hasattr(self, "lbl_preset_t"):
            self.lbl_preset_t.setText(f"<b>{tr('nmap_quick_presets', '⚡ PRESETS RÁPIDOS DE SCRIPTS NSE (1-CLIQUE):')}</b>")

        if hasattr(self, "preset_buttons"):
            presets = get_presets(lang)
            for pid, btn in self.preset_buttons.items():
                if pid in presets:
                    btn.setText(presets[pid]["name"])
                    btn.setToolTip(f"{presets[pid]['desc']}\nArgumento NSE: --script {presets[pid]['arg']}")

        if hasattr(self, "btn_clear"):
            self.btn_clear.setText(tr("clear", "🧹 Limpar"))

        if hasattr(self, "txt_script_search"):
            self.txt_script_search.setPlaceholderText(tr("nmap_search_placeholder", "🔍 Filtrar 605 scripts por nome, categoria ou utilidade..."))

        if hasattr(self, "combo_category"):
            curr_cat = self.combo_category.currentData() or "todas"
            self.combo_category.blockSignals(True)
            self.combo_category.clear()
            self._populate_category_combo()
            idx = self.combo_category.findData(curr_cat)
            if idx >= 0:
                self.combo_category.setCurrentIndex(idx)
            self.combo_category.blockSignals(False)

        if hasattr(self, "btn_check_vis"):
            self.btn_check_vis.setText(tr("nmap_btn_check_vis", "☑ Marcar Visíveis"))
        if hasattr(self, "btn_uncheck_vis"):
            self.btn_uncheck_vis.setText(tr("nmap_btn_uncheck_vis", "☐ Desmarcar Visíveis"))

        if hasattr(self, "table_scripts"):
            self.table_scripts.setHorizontalHeaderLabels([
                tr("nmap_col_script", "Script NSE"),
                tr("nmap_col_categories", "Categorias"),
                tr("nmap_col_description", "Descrição Funcional & Utilidade Prática")
            ])

        if hasattr(self, "btn_run"):
            self.btn_run.setText(tr("nmap_start_scan", "▶ Iniciar Varredura / Executar"))
        if hasattr(self, "btn_toggle_fullscreen"):
            self.btn_toggle_fullscreen.setText(tr("nmap_btn_fullscreen", "⛶ Tela Cheia"))
        if hasattr(self, "btn_copy"):
            self.btn_copy.setText(tr("nmap_btn_copy", "📋 Copiar"))
        if hasattr(self, "btn_save"):
            self.btn_save.setText(tr("nmap_btn_save", "💾 Salvar"))
        if hasattr(self, "btn_close"):
            self.btn_close.setText(tr("nmap_btn_close", "✕ Fechar"))

        self._filter_scripts()
        self._update_selected_count_badge()

    def _apply_preset(self, preset_key: str):
        presets = get_presets(self.current_lang)
        if preset_key in presets:
            pdata = presets[preset_key]
            key_scripts = pdata.get("key_scripts", [])
            arg = pdata.get("arg", "")

            # If it's a category preset like 'vuln', select the representative scripts
            if arg == "vuln":
                vuln_scripts = [s["name"] for s in self.all_scripts if "vuln" in s["categories"]]
                self.selected_scripts = set(vuln_scripts[:15])  # Top 15 CVE checks
                self.txt_extra_args.setText("--script vuln")
            elif arg == "discovery,safe":
                disc_scripts = [s["name"] for s in self.all_scripts if "discovery" in s["categories"] and "safe" in s["categories"]]
                self.selected_scripts = set(disc_scripts[:12])
                self.txt_extra_args.setText("")
            else:
                self.selected_scripts = set(key_scripts)
                self.txt_extra_args.setText("")

            self._filter_scripts()
            self._update_command_preview()

    def _clear_all_scripts(self):
        self.selected_scripts.clear()
        self.txt_extra_args.clear()
        self._filter_scripts()
        self._update_command_preview()

    def _check_all_visible(self):
        for r in range(self.table_scripts.rowCount()):
            it = self.table_scripts.item(r, 0)
            if it:
                it.setCheckState(Qt.Checked)

    def _uncheck_all_visible(self):
        for r in range(self.table_scripts.rowCount()):
            it = self.table_scripts.item(r, 0)
            if it:
                it.setCheckState(Qt.Unchecked)

    def _on_port_scope_changed(self):
        data = self.combo_ports.currentData()
        if data == "custom":
            self.txt_custom_ports.setVisible(True)
        else:
            self.txt_custom_ports.setVisible(False)
        self._update_command_preview()

    def _update_command_preview(self):
        target = self.txt_target.text().strip() or "<alvo>"
        port_data = self.combo_ports.currentData()
        if port_data == "custom":
            ports_arg = f"-p {self.txt_custom_ports.text().strip()}"
        elif port_data == "-F" or port_data == "-p-":
            ports_arg = port_data
        else:
            ports_arg = f"-p {port_data}"

        scripts_list = sorted(list(self.selected_scripts))
        extra = self.txt_extra_args.text().strip()

        cmd_parts = ["nmap", "-sT", "-sV", "--version-light"]
        if scripts_list:
            cmd_parts.append(f"--script {','.join(scripts_list[:8])}{'...' if len(scripts_list) > 8 else ''}")
        if extra:
            cmd_parts.append(extra)
        cmd_parts.extend([ports_arg, "-T4", target])

        preview_str = " ".join(cmd_parts)
        if hasattr(self, "lbl_cmd_preview"):
            self.lbl_cmd_preview.setText(preview_str)

    def get_selected_scripts(self) -> List[str]:
        """Retorna a lista ordenada dos scripts NSE atualmente selecionados."""
        return sorted(list(self.selected_scripts))

    # =========================================================================
    # EXECUÇÃO DA VARREDURA
    # =========================================================================
    def toggle_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.set_running_ui(False)
            self.txt_console.append("\n[!] Varredura cancelada pelo usuário.\n")
            return

        target = self.txt_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Alvo Obrigatório", "Por favor, especifique um endereço IP ou hostname válido.")
            return

        # Monta argumentos
        port_data = self.combo_ports.currentData()
        if port_data == "custom":
            port_arg = self.txt_custom_ports.text().strip()
            port_param = f"-p {port_arg}"
        elif port_data == "-F" or port_data == "-p-":
            port_param = port_data
        else:
            port_param = f"-p {port_data}"

        scripts_list = sorted(list(self.selected_scripts))
        extra_args = self.txt_extra_args.text().strip()

        # Build full custom arguments
        args_parts = ["-sT", "-sV", "--version-light"]
        if scripts_list:
            args_parts.append(f"--script {','.join(scripts_list)}")
        if extra_args:
            args_parts.append(extra_args)
        args_parts.extend([port_param, "-T4"])
        custom_args_str = " ".join(args_parts)

        self.txt_console.clear()
        self.table_ports.setRowCount(0)
        self.table_nse_results.setRowCount(0)
        self.lbl_diag_icon.setText("⏳")
        self.lbl_diag_title.setText(f"Varrendo host {target} com {len(scripts_list)} script(s) NSE...")
        self.lbl_diag_desc.setText("Aguarde a execução dos testes de versão, portas e scripts NSE pelo Nmap...")
        self.set_running_ui(True)
        self.btn_apply.setEnabled(False)
        self.btn_vlc.setEnabled(False)
        self.btn_web.setEnabled(False)

        self.scan_thread = NmapScannerThread(
            target=target,
            custom_args=custom_args_str,
            scripts=scripts_list,
        )
        self.scan_thread.line_output.connect(self.append_log)
        self.scan_thread.scan_finished.connect(self.on_scan_finished)
        self.scan_thread.scan_error.connect(self.on_scan_error)
        self.scan_thread.start()

    def set_running_ui(self, running: bool):
        p = self.palette
        if running:
            self.btn_run.setText("⏹  Cancelar")
            self.btn_run.setStyleSheet("background-color: #dc2626; color: #fff; font-weight: bold; border-radius: 6px;")
            if hasattr(self, "btn_run_scripts"):
                self.btn_run_scripts.setText("⏹ Cancelar")
                self.btn_run_scripts.setStyleSheet("background-color: #dc2626; color: #fff; font-weight: bold; border-radius: 6px;")
            self.prog_bar.setVisible(True)
        else:
            self.btn_run.setText("▶  Iniciar Varredura / Executar")
            self.btn_run.setStyleSheet(f"background: {p['run_btn_bg']}; color: #fff; font-weight: bold; border-radius: 6px;")
            if hasattr(self, "btn_run_scripts"):
                self.btn_run_scripts.setText(f"▶ Executar Scripts Selecionados ({len(self.selected_scripts)})")
                self.btn_run_scripts.setStyleSheet(f"background: {p['run_btn_bg']}; color: #fff; font-weight: bold; border-radius: 6px;")
            self.prog_bar.setVisible(False)

    @pyqtSlot(str)
    def append_log(self, line: str):
        self.txt_console.moveCursor(QTextCursor.End)
        self.txt_console.insertPlainText(line)
        self.txt_console.moveCursor(QTextCursor.End)

    @pyqtSlot(str, dict, str)
    def on_scan_finished(self, target: str, parsed: dict, raw_text: str):
        self.set_running_ui(False)
        self.last_parsed_result = parsed
        self.last_raw_text = raw_text

        # 1. Atualizar Cartão de Diagnóstico
        icon = parsed.get("diagnosis_icon", "💡")
        diag = parsed.get("device_diagnosis", "Varredura concluída.")
        self.lbl_diag_icon.setText(icon)
        self.lbl_diag_title.setText(f"Diagnóstico do Dispositivo: {target}")
        self.lbl_diag_desc.setText(diag)

        # 2. Atualizar Badges de Métricas
        open_count = len(parsed.get("open_ports_list", []))
        closed_count = len(parsed.get("closed_ports_list", []))
        latency = parsed.get("latency", "--")
        nse_results = parsed.get("nse_scripts", [])

        self.lbl_badge_open.setText(f"🟢 {open_count} Porta(s) Aberta(s)")
        self.lbl_badge_closed.setText(f"⚪ {closed_count} Fechada(s)")
        self.lbl_badge_latency.setText(f"⚡ Latência: {latency}")
        self.lbl_badge_nse.setText(f"📜 {len(nse_results)} Scripts Executados")

        vulns = parsed.get("vulnerabilities", []) or []
        if vulns:
            self.lbl_badge_cves.setText(f"⚠️ {len(vulns)} CVE(s) ({parsed.get('risk_level', 'HIGH')})")
            self.lbl_badge_cves.setStyleSheet("background-color: #fee2e2; color: #991b1b; font-weight: bold; font-size: 11px; padding: 4px 10px; border-radius: 12px;")
            self.tabs.setTabText(2, f"🛡️ Resultados & CVEs ({len(vulns)})")
        else:
            self.lbl_badge_cves.setText("🛡️ 0 CVEs (Seguro)")
            self.lbl_badge_cves.setStyleSheet(f"background-color: {self.palette['success_bg']}; color: {self.palette['success_text']}; font-weight: bold; font-size: 11px; padding: 4px 10px; border-radius: 12px;")
            self.tabs.setTabText(2, "🛡️ Resultados dos Scripts & CVEs")

        # 3. Habilitar Botões de Ação
        open_ports = parsed.get("open_ports_list", [])
        if open_ports:
            self.btn_apply.setEnabled(True)
            if 554 in open_ports:
                self.btn_vlc.setEnabled(True)
            if 80 in open_ports or 443 in open_ports:
                self.btn_web.setEnabled(True)

        self.refresh_ports_table()
        self.refresh_cves_table()
        self.refresh_nse_results_table(nse_results)

        # Se houver scripts executados, navega para a aba de resultados de scripts
        if nse_results:
            self.tabs.setCurrentIndex(2)
        else:
            self.tabs.setCurrentIndex(1)

    def refresh_nse_results_table(self, nse_results: List[dict]):
        self.table_nse_results.setRowCount(len(nse_results))
        for row, res in enumerate(nse_results):
            it_name = QTableWidgetItem(res["name"])
            it_name.setFont(QFont("Segoe UI", 9, QFont.Bold))

            it_port = QTableWidgetItem(str(res["port"]))
            it_port.setFont(QFont("Segoe UI", 9))

            it_st = QTableWidgetItem(res["status_label"])
            it_st.setFont(QFont("Segoe UI", 9, QFont.Bold))
            it_st.setForeground(QColor(res["color"]))

            it_out = QTableWidgetItem(res["output"])
            it_out.setFont(QFont("Monospace", 9))

            for col, it in enumerate([it_name, it_port, it_st, it_out]):
                it.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                self.table_nse_results.setItem(row, col, it)

    def refresh_cves_table(self):
        vulns = self.last_parsed_result.get("vulnerabilities", []) or []
        self.table_cves.setRowCount(len(vulns))
        if not vulns:
            self.lbl_cve_summary.setText("<b>🛡️ VULNERABILIDADES:</b> ✅ Nenhuma vulnerabilidade conhecida correlacionada.")
            return
        self.lbl_cve_summary.setText(
            f"<b>🛡️ VULNERABILIDADES:</b> ⚠️ {len(vulns)} vulnerabilidade(s) conhecida(s) correlacionada(s) (Risco: {self.last_parsed_result.get('risk_badge', '')})."
        )
        for row, v in enumerate(vulns):
            it_id = QTableWidgetItem(v.cve_id)
            it_id.setFont(QFont("Monospace", 9, QFont.Bold))
            it_sev = QTableWidgetItem(f"{v.severity} (CVSS {v.cvss:.1f})")
            it_sev.setFont(QFont("Segoe UI", 9, QFont.Bold))
            it_sev.setForeground(QColor("#dc2626") if v.severity in ("CRITICAL", "HIGH") else QColor("#d97706"))
            it_prod = QTableWidgetItem(f"{v.product} ({v.detected_version}) [:{v.port}]")
            it_desc = QTableWidgetItem(f"{v.title} — {v.description}")
            it_rem = QTableWidgetItem(v.remediation)
            for col, it in enumerate([it_id, it_sev, it_prod, it_desc, it_rem]):
                it.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                self.table_cves.setItem(row, col, it)

    def refresh_ports_table(self):
        if not self.last_parsed_result:
            return

        all_ports = self.last_parsed_result.get("all_ports", [])
        hide_closed = self.chk_hide_closed.isChecked()
        filtered_ports = [p for p in all_ports if not (hide_closed and p["state"] == "closed")]

        self.table_ports.setRowCount(len(filtered_ports))
        target_ip = self.txt_target.text().strip()

        for row, p in enumerate(filtered_ports):
            port_num = p.get("port", 0)
            proto = p.get("proto") or p.get("protocol") or "tcp"
            state = p.get("state", "open")
            service = p.get("service", "unknown")
            version = p.get("version", "")

            it_port = QTableWidgetItem(f"{port_num} / {proto}")
            it_port.setFont(QFont("Segoe UI", 10, QFont.Bold))

            it_state = QTableWidgetItem()
            if state == "open":
                it_state.setText("● Aberta")
                it_state.setForeground(QColor(self.palette["success"]))
                it_state.setFont(QFont("Segoe UI", 9, QFont.Bold))
            elif state == "closed":
                it_state.setText("○ Fechada")
                it_state.setForeground(QColor(self.palette["text_muted"]))
            else:
                it_state.setText(f"? {state}")
                it_state.setForeground(QColor(self.palette["warning"]))

            svc_icon = "🌐" if port_num in [80, 443, 8080, 8443] else ("🎬" if port_num == 554 else ("📹" if port_num in [8899, 2443, 3702] else "🔌"))
            it_svc = QTableWidgetItem(f"{svc_icon} {service}")

            ver_text = version or ("Ativo (Sem detalhes)" if state == "open" else "--")
            it_ver = QTableWidgetItem(ver_text)

            btn_act = None
            if state == "open":
                if port_num in [80, 443, 8080, 8443, 8006]:
                    protocol = "https" if port_num in [443, 8443, 8006] else "http"
                    btn_act = QPushButton("Abrir Web")
                    btn_act.setFixedHeight(24)
                    btn_act.clicked.connect(lambda _, p_num=port_num, pr=protocol, tip=target_ip: QDesktopServices.openUrl(QUrl(f"{pr}://{tip}:{p_num}/")))
                elif port_num == 554:
                    btn_act = QPushButton("Assistir RTSP")
                    btn_act.setFixedHeight(24)
                    btn_act.setStyleSheet("background-color: #0284c7; color: #fff; font-weight: bold;")
                    btn_act.clicked.connect(self.launch_vlc_rtsp)

            for col, it in enumerate([it_port, it_state, it_svc, it_ver]):
                it.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                self.table_ports.setItem(row, col, it)

            if btn_act:
                self.table_ports.setCellWidget(row, 4, btn_act)
            else:
                empty = QTableWidgetItem("--")
                empty.setFlags(Qt.ItemIsEnabled)
                self.table_ports.setItem(row, 4, empty)

    @pyqtSlot(str)
    def on_scan_error(self, err: str):
        self.set_running_ui(False)
        self.txt_console.append(f"\n[ERRO] {err}\n")
        self.lbl_diag_title.setText("Falha na varredura")
        self.lbl_diag_desc.setText(err)

    def apply_ports_to_device(self):
        target = self.txt_target.text().strip()
        open_ports = self.last_parsed_result.get("open_ports_list", [])
        services = self.last_parsed_result.get("services", {})
        if not target or not open_ports:
            return

        self.ports_applied.emit(target, open_ports, services)
        QMessageBox.information(
            self,
            "Portas Aplicadas",
            f"{len(open_ports)} porta(s) aberta(s) foram aplicadas com sucesso ao host {target} na lista principal!",
        )

    def launch_vlc_rtsp(self):
        target = self.txt_target.text().strip()
        rtsp_url = f"rtsp://{target}:554/"
        try:
            from onvif_engine import get_onvif_stream_uri
            resolved = get_onvif_stream_uri(target)
            if resolved:
                rtsp_url = resolved
        except Exception:
            pass

        from onvif_engine import launch_video_player
        title = f"Câmera IP {target} — IP Scan IGT"
        launched = launch_video_player(rtsp_url, title=title)
        if not launched:
            QMessageBox.warning(
                self,
                "Player de Vídeo",
                f"Nem FFplay nem VLC foram encontrados no sistema.\n\nInstale o VLC Media Player ou FFmpeg para reprodução direta.\n\nURL: {rtsp_url}",
            )

    def launch_web_browser(self):
        target = self.txt_target.text().strip()
        open_ports = self.last_parsed_result.get("open_ports_list", [])
        protocol = "https" if 443 in open_ports else "http"
        port = 443 if 443 in open_ports else (80 if 80 in open_ports else (open_ports[0] if open_ports else 80))
        url = f"{protocol}://{target}/" if port in [80, 443] else f"{protocol}://{target}:{port}/"
        QDesktopServices.openUrl(QUrl(url))

    def toggle_fullscreen(self):
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
        elif event.key() == Qt.Key_Return and (event.modifiers() & Qt.ControlModifier):
            self.toggle_scan()
            event.accept()
        elif event.key() == Qt.Key_Escape:
            if self.isFullScreen():
                self.showMaximized()
                self.btn_toggle_fullscreen.setText("⛶ Tela Cheia")
                event.accept()
            elif self.scan_thread and self.scan_thread.isRunning():
                self.toggle_scan()
                event.accept()
            else:
                super().keyPressEvent(event)
        else:
            super().keyPressEvent(event)

    def copy_output(self):
        QApplication.clipboard().setText(self.txt_console.toPlainText())
        QMessageBox.information(self, "Copiado", "Saída copiada para a área de transferência!")

    def save_output(self):
        path, _ = QFileDialog.getSaveFileName(self, "Salvar Relatório Nmap", os.path.expanduser("~/nmap_scan.txt"), "Texto (*.txt)")
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self.txt_console.toPlainText())
                QMessageBox.information(self, "Salvo", f"Relatório salvo com sucesso em:\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "Erro", str(e))

    def closeEvent(self, event):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
        event.accept()
