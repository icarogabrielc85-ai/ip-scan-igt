#!/usr/bin/env python3
"""
Nmap Dialog for IP Scan IGT.
Provides clean UI/UX with a structured visual report, human-friendly diagnosis,
interactive ports table, and a secondary tab for raw terminal output.
"""
import os
import subprocess
from typing import Dict, List, Optional

from PyQt5.QtCore import QPoint, Qt, QUrl, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QColor, QDesktopServices, QFont, QIcon, QTextCursor
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from nmap_engine import (
    NmapScannerThread,
    get_nmap_path,
    is_nmap_available,
    parse_nmap_output,
)

SCAN_PROFILES = [
    ("⚡ Varredura Rápida (Top 100 portas -F)", "-sT -F -T4"),
    ("🔎 Detecção de Serviços & Versões (-sV)", "-sT -sV --version-light -T4"),
    ("🎥 Câmeras & ONVIF / RTSP (Vídeo)", "-sT -sV --version-light -p 80,554,1935,2443,3702,8000,8080,8443,8899 -T4"),
    ("🌐 Todas as 65.535 Portas (-p-)", "-sT -p- -T4 --min-rate 800"),
    ("🛡️ Auditoria com Scripts Seguros (-sC -sV)", "-sT -sC -sV -T4"),
    ("⚙️ Personalizado (Argumentos Livres)", ""),
]


class NmapDialog(QDialog):
    ports_applied = pyqtSignal(str, list, dict)  # ip, open_ports_list, services_dict

    def __init__(self, parent=None, target: str = "", hostname: str = ""):
        super().__init__(parent)
        self.target = target.strip()
        self.hostname = hostname.strip()
        self.scan_thread: Optional[NmapScannerThread] = None
        self.last_parsed_result: Dict = {}
        self.last_raw_text: str = ""

        self.setWindowTitle(f"Auditoria Nmap — {self.hostname or self.target or 'Host'}")
        self.resize(960, 680)
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(14, 12, 14, 12)
        main_layout.setSpacing(10)

        is_dark = getattr(self.parent(), "is_dark_mode", False) if self.parent() else False
        card_bg = "#162032" if is_dark else "#d4d4d4"
        pane_bg = "#0e141f" if is_dark else "#e2e2e2"
        input_bg = "#1e293b" if is_dark else "#ededed"
        border_col = "#243447" if is_dark else "#a8a8a8"
        text_col = "#f1f5f9" if is_dark else "#1e242b"
        sub_col = "#94a3b8" if is_dark else "#3b424a"

        # 1. Top Configuration Frame
        cfg_frame = QFrame()
        cfg_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {card_bg};
                border: 1px solid {border_col};
                border-radius: 6px;
            }}
        """)
        cfg_layout = QVBoxLayout(cfg_frame)
        cfg_layout.setContentsMargins(12, 10, 12, 10)
        cfg_layout.setSpacing(8)

        # Row 1: Target, Profile, and Start Button
        row1 = QHBoxLayout()
        lbl_target = QLabel("Alvo (IP/Host):")
        lbl_target.setStyleSheet(f"font-weight: bold; color: {text_col}; border: none;")
        self.txt_target = QLineEdit(self.target or "192.168.111.100")
        self.txt_target.setMinimumWidth(160)
        self.txt_target.setFixedHeight(30)

        lbl_profile = QLabel("Perfil:")
        lbl_profile.setStyleSheet(f"font-weight: bold; color: {text_col}; margin-left: 10px; border: none;")
        self.combo_profile = QComboBox()
        self.combo_profile.setFixedHeight(30)
        for name, _ in SCAN_PROFILES:
            self.combo_profile.addItem(name)
        self.combo_profile.currentIndexChanged.connect(self.on_profile_changed)

        self.btn_run = QPushButton("▶  Iniciar Varredura")
        self.btn_run.setFixedHeight(30)
        self.btn_run.setMinimumWidth(160)
        self.btn_run.setStyleSheet("""
            QPushButton {
                background-color: #2b6595;
                color: #ffffff;
                font-weight: bold;
                border: none;
                border-radius: 5px;
                padding: 4px 16px;
            }
            QPushButton:hover {
                background-color: #1d4f7a;
            }
        """)
        self.btn_run.clicked.connect(self.toggle_scan)

        row1.addWidget(lbl_target)
        row1.addWidget(self.txt_target)
        row1.addWidget(lbl_profile)
        row1.addWidget(self.combo_profile, 1)
        row1.addWidget(self.btn_run)
        cfg_layout.addLayout(row1)

        # Row 2: Parameters editable
        row2 = QHBoxLayout()
        lbl_args = QLabel("Parâmetros:")
        lbl_args.setStyleSheet(f"font-size: 11px; color: {sub_col}; font-weight: 600; border: none;")
        self.txt_args = QLineEdit(SCAN_PROFILES[0][1])
        self.txt_args.setFixedHeight(28)
        self.txt_args.setStyleSheet(f"font-family: monospace; font-size: 11px; background-color: {input_bg};")
        row2.addWidget(lbl_args)
        row2.addWidget(self.txt_args, 1)
        cfg_layout.addLayout(row2)

        main_layout.addWidget(cfg_frame)

        # Progress bar
        self.prog_bar = QProgressBar()
        self.prog_bar.setFixedHeight(6)
        self.prog_bar.setTextVisible(False)
        self.prog_bar.setRange(0, 0)
        self.prog_bar.setVisible(False)
        main_layout.addWidget(self.prog_bar)

        # 2. Main Tabbed Results View (UI/UX clean)
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: 1px solid {border_col};
                border-radius: 6px;
                background-color: {pane_bg};
            }}
            QTabBar::tab {{
                font-weight: bold;
                padding: 6px 18px;
                font-size: 12px;
            }}
            QTabBar::tab:selected {{
                background-color: {pane_bg};
                border-bottom: 2px solid #2b6595;
                color: {"#38bdf8" if is_dark else "#164e78"};
            }}
        """)

        # TAB 1: Relatório Estruturado & Portas (Modern, clean, organized)
        tab_report = QWidget()
        report_layout = QVBoxLayout(tab_report)
        report_layout.setContentsMargins(12, 12, 12, 12)
        report_layout.setSpacing(10)

        # Diagnostic Banner Card
        self.diag_card = QFrame()
        diag_bg = "#162032" if is_dark else "#d0dfed"
        diag_border = "#0284c7" if is_dark else "#8eb4d9"
        self.diag_card.setStyleSheet(f"""
            QFrame {{
                background-color: {diag_bg};
                border: 1px solid {diag_border};
                border-radius: 6px;
                padding: 8px;
            }}
        """)
        diag_layout = QHBoxLayout(self.diag_card)
        diag_layout.setContentsMargins(10, 8, 10, 8)

        self.lbl_diag_icon = QLabel("💡")
        self.lbl_diag_icon.setStyleSheet("font-size: 28px; border: none;")
        diag_layout.addWidget(self.lbl_diag_icon)

        diag_text_box = QVBoxLayout()
        self.lbl_diag_title = QLabel("Aguardando varredura...")
        self.lbl_diag_title.setStyleSheet(f"font-weight: bold; font-size: 13px; color: {'#38bdf8' if is_dark else '#164e78'}; border: none;")
        self.lbl_diag_desc = QLabel("Selecione o perfil desejado e clique em 'Iniciar Varredura' para auditar o dispositivo.")
        self.lbl_diag_desc.setStyleSheet(f"color: {text_col}; font-size: 12px; border: none;")
        self.lbl_diag_desc.setWordWrap(True)
        diag_text_box.addWidget(self.lbl_diag_title)
        diag_text_box.addWidget(self.lbl_diag_desc)
        diag_layout.addLayout(diag_text_box, 1)

        report_layout.addWidget(self.diag_card)

        # Metric Badges & Filter Bar
        metrics_bar = QHBoxLayout()
        metrics_bar.setSpacing(10)

        self.lbl_badge_open = QLabel("🟢 0 Abertas")
        self.lbl_badge_open.setStyleSheet("""
            background-color: #dcfce7;
            color: #166534;
            font-weight: bold;
            font-size: 11px;
            padding: 4px 10px;
            border-radius: 12px;
            border: 1px solid #bbf7d0;
        """)

        self.lbl_badge_closed = QLabel("⚪ 0 Fechadas")
        self.lbl_badge_closed.setStyleSheet("""
            background-color: #f1f5f9;
            color: #64748b;
            font-weight: bold;
            font-size: 11px;
            padding: 4px 10px;
            border-radius: 12px;
            border: 1px solid #e2e8f0;
        """)

        self.lbl_badge_latency = QLabel("⚡ Latência: --")
        self.lbl_badge_latency.setStyleSheet("""
            background-color: #e0f2fe;
            color: #0369a1;
            font-weight: bold;
            font-size: 11px;
            padding: 4px 10px;
            border-radius: 12px;
            border: 1px solid #bae6fd;
        """)

        self.lbl_badge_cves = QLabel("🛡️ 0 CVEs")
        self.lbl_badge_cves.setStyleSheet("""
            background-color: #f1f5f9;
            color: #475569;
            font-weight: bold;
            font-size: 11px;
            padding: 4px 10px;
            border-radius: 12px;
            border: 1px solid #e2e8f0;
        """)

        metrics_bar.addWidget(self.lbl_badge_open)
        metrics_bar.addWidget(self.lbl_badge_closed)
        metrics_bar.addWidget(self.lbl_badge_latency)
        metrics_bar.addWidget(self.lbl_badge_cves)
        metrics_bar.addStretch()

        # Checkbox to hide closed ports so it never looks messy!
        self.chk_hide_closed = QCheckBox("Ocultar portas fechadas")
        self.chk_hide_closed.setChecked(True)
        self.chk_hide_closed.setStyleSheet("font-weight: 600; color: #475569;")
        self.chk_hide_closed.stateChanged.connect(self.refresh_ports_table)
        metrics_bar.addWidget(self.chk_hide_closed)

        report_layout.addLayout(metrics_bar)

        # Structured Table of Ports
        self.table_ports = QTableWidget(0, 5)
        self.table_ports.setHorizontalHeaderLabels([
            "Porta / Protocolo",
            "Estado",
            "Serviço",
            "Versão / Detalhes Detectados",
            "Ação Rápida",
        ])
        self.table_ports.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_ports.setAlternatingRowColors(True)
        self.table_ports.verticalHeader().setVisible(False)
        self.table_ports.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_ports.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_ports.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_ports.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table_ports.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        report_layout.addWidget(self.table_ports, 1)

        self.tabs.addTab(tab_report, "📊 Relatório Estruturado")

        # TAB 2: Vulnerabilidades Correlacionadas (CVEs)
        tab_cves = QWidget()
        cves_layout = QVBoxLayout(tab_cves)
        cves_layout.setContentsMargins(12, 12, 12, 12)
        cves_layout.setSpacing(8)

        self.lbl_cve_summary = QLabel("As versões e banners identificados pelo Nmap são cruzados automaticamente com a base local SQLite de CVEs.")
        self.lbl_cve_summary.setStyleSheet("color: #475569; font-size: 12px; font-weight: 600;")
        cves_layout.addWidget(self.lbl_cve_summary)

        self.table_cves = QTableWidget(0, 5)
        self.table_cves.setHorizontalHeaderLabels([
            "CVE ID",
            "Severidade / CVSS",
            "Serviço / Versão",
            "Título / Descrição da Vulnerabilidade",
            "Recomendação de Mitigação",
        ])
        self.table_cves.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_cves.setAlternatingRowColors(True)
        self.table_cves.verticalHeader().setVisible(False)
        self.table_cves.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_cves.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_cves.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_cves.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table_cves.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        cves_layout.addWidget(self.table_cves, 1)

        self.tabs.addTab(tab_cves, "🛡️ Vulnerabilidades (CVEs)")

        # TAB 3: Terminal Bruto (Log Técnico)
        tab_raw = QWidget()
        raw_layout = QVBoxLayout(tab_raw)
        raw_layout.setContentsMargins(10, 10, 10, 10)

        lbl_raw_info = QLabel("Saída direta de texto emitida pelo Nmap (para auditoria técnica detalhada):")
        lbl_raw_info.setStyleSheet("color: #64748b; font-size: 11px;")
        raw_layout.addWidget(lbl_raw_info)

        self.txt_console = QTextEdit()
        self.txt_console.setReadOnly(True)
        self.txt_console.setFont(QFont("Monospace", 9))
        self.txt_console.setStyleSheet("""
            QTextEdit {
                background-color: #0f172a;
                color: #f8fafc;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 10px;
                line-height: 1.4;
            }
        """)
        raw_layout.addWidget(self.txt_console, 1)

        self.tabs.addTab(tab_raw, "💻 Terminal Nmap (Log Técnico)")
        main_layout.addWidget(self.tabs, 1)

        # 3. Bottom Action Bar
        bottom_box = QHBoxLayout()
        bottom_box.setSpacing(8)

        self.btn_apply = QPushButton("➕ Aplicar Portas ao Dispositivo")
        self.btn_apply.setFixedHeight(34)
        self.btn_apply.setEnabled(False)
        self.btn_apply.setStyleSheet("""
            QPushButton {
                background-color: #16a34a;
                color: #ffffff;
                font-weight: bold;
                border: none;
                border-radius: 4px;
                padding: 4px 14px;
            }
            QPushButton:hover {
                background-color: #15803d;
            }
            QPushButton:disabled {
                background-color: #cbd5e1;
                color: #94a3b8;
            }
        """)
        self.btn_apply.setToolTip("Atualiza a tabela principal com as portas e serviços descobertos pelo Nmap")
        self.btn_apply.clicked.connect(self.apply_ports_to_device)
        bottom_box.addWidget(self.btn_apply)

        self.btn_vlc = QPushButton("🎬 Assistir RTSP (VLC)")
        self.btn_vlc.setFixedHeight(34)
        self.btn_vlc.setEnabled(False)
        self.btn_vlc.setToolTip("Transmitir vídeo em tempo real no VLC (Porta 554)")
        self.btn_vlc.clicked.connect(self.launch_vlc_rtsp)
        bottom_box.addWidget(self.btn_vlc)

        self.btn_web = QPushButton("🌐 Abrir no Navegador")
        self.btn_web.setFixedHeight(34)
        self.btn_web.setEnabled(False)
        self.btn_web.clicked.connect(self.launch_web_browser)
        bottom_box.addWidget(self.btn_web)

        bottom_box.addStretch()

        btn_copy = QPushButton("Copiar Saída")
        btn_copy.setFixedHeight(34)
        btn_copy.clicked.connect(self.copy_output)
        bottom_box.addWidget(btn_copy)

        btn_save = QPushButton("Salvar Relatório...")
        btn_save.setFixedHeight(34)
        btn_save.clicked.connect(self.save_output)
        bottom_box.addWidget(btn_save)

        btn_close = QPushButton("Fechar")
        btn_close.setFixedHeight(34)
        btn_close.clicked.connect(self.close)
        bottom_box.addWidget(btn_close)

        main_layout.addLayout(bottom_box)

    def on_profile_changed(self, index: int):
        if index < len(SCAN_PROFILES):
            args = SCAN_PROFILES[index][1]
            if args:
                self.txt_args.setText(args)

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

        args = self.txt_args.text().strip()

        self.txt_console.clear()
        self.table_ports.setRowCount(0)
        self.lbl_diag_icon.setText("⏳")
        self.lbl_diag_title.setText(f"Varrendo host {target}...")
        self.lbl_diag_desc.setText("Aguarde a conclusão dos testes de versão e portas pelo Nmap...")
        self.set_running_ui(True)
        self.btn_apply.setEnabled(False)
        self.btn_vlc.setEnabled(False)
        self.btn_web.setEnabled(False)

        self.scan_thread = NmapScannerThread(target=target, custom_args=args)
        self.scan_thread.line_output.connect(self.append_log)
        self.scan_thread.scan_finished.connect(self.on_scan_finished)
        self.scan_thread.scan_error.connect(self.on_scan_error)
        self.scan_thread.start()

    def set_running_ui(self, running: bool):
        if running:
            self.btn_run.setText("⏹  Cancelar")
            self.btn_run.setStyleSheet("""
                QPushButton {
                    background-color: #dc2626;
                    color: #ffffff;
                    font-weight: bold;
                    border: none;
                    border-radius: 5px;
                    padding: 4px 16px;
                }
                QPushButton:hover {
                    background-color: #b91c1c;
                }
            """)
            self.prog_bar.setVisible(True)
        else:
            self.btn_run.setText("▶  Iniciar Varredura")
            self.btn_run.setStyleSheet("""
                QPushButton {
                    background-color: #0969da;
                    color: #ffffff;
                    font-weight: bold;
                    border: none;
                    border-radius: 5px;
                    padding: 4px 16px;
                }
                QPushButton:hover {
                    background-color: #0856b3;
                }
            """)
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

        # Update Diagnosis Card
        icon = parsed.get("diagnosis_icon", "💡")
        diag = parsed.get("device_diagnosis", "Varredura concluída.")
        self.lbl_diag_icon.setText(icon)
        self.lbl_diag_title.setText(f"Diagnóstico do Dispositivo: {target}")
        self.lbl_diag_desc.setText(diag)

        # Update Badges
        open_count = len(parsed.get("open_ports_list", []))
        closed_count = len(parsed.get("closed_ports_list", []))
        latency = parsed.get("latency", "--")

        self.lbl_badge_open.setText(f"🟢 {open_count} Porta(s) Aberta(s)")
        self.lbl_badge_closed.setText(f"⚪ {closed_count} Fechada(s)")
        self.lbl_badge_latency.setText(f"⚡ Latência: {latency}")

        vulns = parsed.get("vulnerabilities", []) or []
        if vulns:
            self.lbl_badge_cves.setText(f"⚠️ {len(vulns)} CVE(s) ({parsed.get('risk_level', 'HIGH')})")
            self.lbl_badge_cves.setStyleSheet("""
                background-color: #fee2e2;
                color: #991b1b;
                font-weight: bold;
                font-size: 11px;
                padding: 4px 10px;
                border-radius: 12px;
                border: 1px solid #fecaca;
            """)
            self.tabs.setTabText(1, f"🛡️ Vulnerabilidades ({len(vulns)})")
        else:
            self.lbl_badge_cves.setText("🛡️ 0 CVEs (Seguro)")
            self.lbl_badge_cves.setStyleSheet("""
                background-color: #dcfce7;
                color: #166534;
                font-weight: bold;
                font-size: 11px;
                padding: 4px 10px;
                border-radius: 12px;
                border: 1px solid #bbf7d0;
            """)
            self.tabs.setTabText(1, "🛡️ Vulnerabilidades (0)")

        # Enable action buttons
        open_ports = parsed.get("open_ports_list", [])
        if open_ports:
            self.btn_apply.setEnabled(True)
            if 554 in open_ports:
                self.btn_vlc.setEnabled(True)
            if 80 in open_ports or 443 in open_ports:
                self.btn_web.setEnabled(True)

        self.refresh_ports_table()
        self.refresh_cves_table()
        # Always bring user to the clean structured tab first!
        self.tabs.setCurrentIndex(0)

    def refresh_cves_table(self):
        vulns = self.last_parsed_result.get("vulnerabilities", []) or []
        self.table_cves.setRowCount(len(vulns))
        if not vulns:
            self.lbl_cve_summary.setText("✅ Nenhuma vulnerabilidade conhecida (CVE) encontrada nas versões e portas analisadas.")
            return
        self.lbl_cve_summary.setText(
            f"⚠️ Atenção: {len(vulns)} vulnerabilidade(s) conhecida(s) correlacionada(s) na base SQLite (Risco: {self.last_parsed_result.get('risk_badge', '')})."
        )
        for row, v in enumerate(vulns):
            it_id = QTableWidgetItem(v.cve_id)
            it_id.setFont(QFont("Monospace", 9, QFont.Bold))
            it_sev = QTableWidgetItem(f"{v.severity} (CVSS {v.cvss:.1f})")
            it_sev.setFont(QFont("Noto Sans", 9, QFont.Bold))
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
            port_num = p["port"]
            proto = p["proto"]
            state = p["state"]
            service = p["service"]
            version = p["version"]

            # Col 0: Port
            it_port = QTableWidgetItem(f"{port_num} / {proto}")
            it_port.setFont(QFont("Noto Sans", 10, QFont.Bold))

            # Col 1: State Badge
            it_state = QTableWidgetItem()
            if state == "open":
                it_state.setText("● Aberta")
                it_state.setForeground(QColor("#16a34a"))
                it_state.setFont(QFont("Noto Sans", 10, QFont.Bold))
            elif state == "closed":
                it_state.setText("○ Fechada")
                it_state.setForeground(QColor("#94a3b8"))
            else:
                it_state.setText(f"? {state}")
                it_state.setForeground(QColor("#f59e0b"))

            # Col 2: Service
            svc_icon = "🌐" if port_num in [80, 443, 8080, 8443] else ("🎬" if port_num == 554 else ("📹" if port_num in [8899, 2443, 3702] else "🔌"))
            it_svc = QTableWidgetItem(f"{svc_icon} {service}")

            # Col 3: Version details
            ver_text = version or ("Ativo (Sem detalhes)" if state == "open" else "--")
            it_ver = QTableWidgetItem(ver_text)

            # Col 4: Action button widget
            btn_act = None
            if state == "open":
                if port_num in [80, 443, 8080, 8443, 8006]:
                    protocol = "https" if port_num in [443, 8443, 8006] else "http"
                    btn_act = QPushButton("Abrir Web")
                    btn_act.setFixedHeight(24)
                    btn_act.clicked.connect(lambda _, p=port_num, pr=protocol, tip=target_ip: QDesktopServices.openUrl(QUrl(f"{pr}://{tip}:{p}/")))
                elif port_num == 554:
                    btn_act = QPushButton("Assistir RTSP")
                    btn_act.setFixedHeight(24)
                    btn_act.setStyleSheet("background-color: #0969da; color: #fff; font-weight: bold;")
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
                f"Nem FFplay nem VLC foram encontrados no sistema.\n\nInstale o VLC Media Player ou FFmpeg para habilitar a reprodução direta.\n\nURL do Stream: {rtsp_url}",
            )

    def launch_web_browser(self):
        target = self.txt_target.text().strip()
        open_ports = self.last_parsed_result.get("open_ports_list", [])
        protocol = "https" if 443 in open_ports else "http"
        port = 443 if 443 in open_ports else (80 if 80 in open_ports else (open_ports[0] if open_ports else 80))
        url = f"{protocol}://{target}/" if port in [80, 443] else f"{protocol}://{target}:{port}/"
        QDesktopServices.openUrl(QUrl(url))

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
