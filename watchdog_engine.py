#!/usr/bin/env python3
"""
Motor de Monitoramento Contínuo (Watchdog) para o IP Scan IGT.
Monitora em segundo plano os ativos críticos salvos na aba de Favoritos utilizando
o motor de ping silencioso multiplataforma. Emite notificações nativas no desktop
(via QSystemTrayIcon e notify-send) quando um servidor ou equipamento crítico
para de responder ou quando se recupera, mantendo histórico persistente de eventos.
"""
import concurrent.futures
import json
import os
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QSystemTrayIcon,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from i18n import tr
from scanner_engine import IS_WINDOWS, _get_windows_silent_kwargs, probe_ping

WATCHDOG_CONFIG_FILE = os.path.expanduser("~/.config/linux-ipscan/watchdog_config.json")
WATCHDOG_EVENTS_FILE = os.path.expanduser("~/.config/linux-ipscan/watchdog_events.json")


@dataclass
class WatchdogEvent:
    timestamp: str
    ip: str
    hostname: str
    event_type: str   # "DOWN" | "UP"
    details: str
    rtt_ms: float = -1.0

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "ip": self.ip,
            "hostname": self.hostname,
            "event_type": self.event_type,
            "details": self.details,
            "rtt_ms": self.rtt_ms,
        }


def load_watchdog_config() -> dict:
    default_cfg = {
        "enabled": False,
        "interval_sec": 15,
        "failure_threshold": 2,
        "notify_desktop": True,
        "minimize_to_tray": False,
    }
    if os.path.exists(WATCHDOG_CONFIG_FILE):
        try:
            with open(WATCHDOG_CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    default_cfg.update(data)
        except Exception:
            pass
    return default_cfg


def save_watchdog_config(cfg: dict):
    try:
        os.makedirs(os.path.dirname(WATCHDOG_CONFIG_FILE), exist_ok=True)
        with open(WATCHDOG_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def load_watchdog_events() -> List[dict]:
    if os.path.exists(WATCHDOG_EVENTS_FILE):
        try:
            with open(WATCHDOG_EVENTS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data[:500]
        except Exception:
            pass
    return []


def append_watchdog_event(event: WatchdogEvent) -> List[dict]:
    events = load_watchdog_events()
    events.insert(0, event.to_dict())
    events = events[:500]
    try:
        os.makedirs(os.path.dirname(WATCHDOG_EVENTS_FILE), exist_ok=True)
        with open(WATCHDOG_EVENTS_FILE, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2, ensure_ascii=False)
    except Exception:
        pass
    return events


def clear_watchdog_events():
    try:
        if os.path.exists(WATCHDOG_EVENTS_FILE):
            os.remove(WATCHDOG_EVENTS_FILE)
    except Exception:
        pass


def send_desktop_notification(
    title: str,
    message: str,
    is_critical: bool = False,
    tray_icon: Optional[QSystemTrayIcon] = None,
):
    """
    Dispara notificação nativa no desktop utilizando QSystemTrayIcon (Linux & Windows)
    com suporte complementar ao notify-send no Linux.
    """
    shown_via_tray = False
    if tray_icon and tray_icon.isVisible() and QSystemTrayIcon.supportsMessages():
        try:
            icon_type = QSystemTrayIcon.Critical if is_critical else QSystemTrayIcon.Information
            tray_icon.showMessage(title, message, icon_type, 6000)
            shown_via_tray = True
        except Exception:
            pass

    if not IS_WINDOWS and not shown_via_tray:
        notify_bin = shutil.which("notify-send")
        if notify_bin:
            try:
                urgency = "critical" if is_critical else "normal"
                subprocess.Popen(
                    [notify_bin, "-u", urgency, "-a", "IP Scan IGT", title, message],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception:
                pass


class WatchdogWorker(QThread):
    """
    Thread em segundo plano que monitora continuamente os hosts favoritos com histerese
    de falha para evitar falsos positivos.
    """
    host_checked = pyqtSignal(str, bool, float, int)           # ip, alive, rtt_ms, fail_streak
    state_changed = pyqtSignal(str, str, bool, float, str)     # ip, hostname, is_online, rtt_ms, timestamp
    cycle_finished = pyqtSignal(int, int, str)                 # online_count, offline_count, timestamp

    def __init__(self, interval_sec: int = 15, failure_threshold: int = 2):
        super().__init__()
        self.interval_sec = max(3, interval_sec)
        self.failure_threshold = max(1, failure_threshold)
        self._targets: Dict[str, str] = {}   # ip -> hostname
        self._fail_counts: Dict[str, int] = {}
        self._known_state: Dict[str, bool] = {}  # ip -> True (online) / False (offline)
        self._lock = threading.Lock()
        self._is_running = False

    def set_targets(self, fav_map: Dict[str, str], initial_states: Optional[Dict[str, bool]] = None):
        with self._lock:
            self._targets = dict(fav_map)
            if initial_states:
                for ip, st in initial_states.items():
                    if ip not in self._known_state:
                        self._known_state[ip] = bool(st)

    def update_settings(self, interval_sec: int, failure_threshold: int):
        with self._lock:
            self.interval_sec = max(3, int(interval_sec))
            self.failure_threshold = max(1, int(failure_threshold))

    def stop(self):
        self._is_running = False

    def run(self):
        self._is_running = True
        while self._is_running:
            self.run_single_cycle()
            # Aguarda até o próximo ciclo em fatias curtas para parada imediata se solicitado
            with self._lock:
                wait_s = self.interval_sec
            steps = int(wait_s * 10)
            for _ in range(steps):
                if not self._is_running:
                    break
                time.sleep(0.1)

    def run_single_cycle(self):
        """Executa uma rodada de verificação imediata em todos os alvos monitorados."""
        with self._lock:
            targets_snapshot = dict(self._targets)
            threshold = self.failure_threshold

        if not targets_snapshot:
            now_str = time.strftime("%d/%m/%Y %H:%M:%S")
            self.cycle_finished.emit(0, 0, now_str)
            return

        def _probe_one(ip_addr: str):
            alive, rtt, _, _ = probe_ping(ip_addr, timeout_ms=600)
            return ip_addr, alive, (rtt if alive else -1.0)

        online_count = 0
        offline_count = 0
        now_str = time.strftime("%d/%m/%Y %H:%M:%S")

        max_w = min(16, max(1, len(targets_snapshot)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_w) as pool:
            for ip, alive, rtt in pool.map(_probe_one, targets_snapshot.keys()):
                hostname = targets_snapshot.get(ip, ip)
                with self._lock:
                    prev_state = self._known_state.get(ip, True)
                    if alive:
                        self._fail_counts[ip] = 0
                        new_state = True
                    else:
                        streak = self._fail_counts.get(ip, 0) + 1
                        self._fail_counts[ip] = streak
                        if streak >= threshold:
                            new_state = False
                        else:
                            # Mantém estado anterior durante a janela de histerese
                            new_state = prev_state

                    fail_streak = self._fail_counts.get(ip, 0)
                    state_transitioned = (ip in self._known_state) and (new_state != prev_state)
                    # Caso o host já comece falhando mais que o threshold na primeira checagem
                    if ip not in self._known_state and not new_state:
                        state_transitioned = True
                    self._known_state[ip] = new_state

                if new_state:
                    online_count += 1
                else:
                    offline_count += 1

                self.host_checked.emit(ip, alive, rtt, fail_streak)

                if state_transitioned:
                    self.state_changed.emit(ip, hostname, new_state, rtt, now_str)

        self.cycle_finished.emit(online_count, offline_count, now_str)


class WatchdogDialog(QDialog):
    """
    Janela de controle e auditoria de eventos do Watchdog (Monitoramento Contínuo de Favoritos).
    """
    config_Updated = pyqtSignal(dict)
    trigger_manual_check = pyqtSignal()

    def __init__(self, parent=None, is_dark: bool = False):
        super().__init__(parent)
        self.is_dark = is_dark
        self.cfg = load_watchdog_config()
        self.setWindowTitle(tr("watchdog_title", "🛡️ Monitoramento Contínuo (Watchdog) — Ativos Críticos"))
        self.resize(880, 580)
        self.init_ui()
        self.refresh_events_table()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(12)

        bg_card = "#1e293b" if self.is_dark else "#f8fafc"
        border_col = "#334155" if self.is_dark else "#cbd5e1"
        text_col = "#f1f5f9" if self.is_dark else "#0f172a"
        sub_col = "#94a3b8" if self.is_dark else "#475569"

        # 1. Header & Settings Card
        cfg_frame = QFrame()
        cfg_frame.setStyleSheet(
            f"QFrame {{ background-color: {bg_card}; border: 1px solid {border_col}; border-radius: 8px; }}"
        )
        cfg_vbox = QVBoxLayout(cfg_frame)
        cfg_vbox.setContentsMargins(14, 12, 14, 12)
        cfg_vbox.setSpacing(10)

        title_lbl = QLabel(
            f"<b style='font-size:14px; color:{text_col};'>🛡️ {tr('watchdog_header', 'Watchdog de Disponibilidade em Segundo Plano')}</b><br>"
            f"<span style='font-size:12px; color:{sub_col};'>"
            f"{tr('watchdog_desc', 'Monitora automaticamente todos os dispositivos listados na aba Favoritos e emite alertas nativos se um ativo crítico cair ou voltar a responder.')}"
            f"</span>"
        )
        title_lbl.setWordWrap(True)
        cfg_vbox.addWidget(title_lbl)

        controls_row = QHBoxLayout()
        controls_row.setSpacing(14)

        self.chk_enabled = QCheckBox(tr("watchdog_enable_chk", "Ativar Monitoramento Contínuo (Watchdog)"))
        self.chk_enabled.setChecked(bool(self.cfg.get("enabled", False)))
        self.chk_enabled.setStyleSheet(f"font-weight: bold; color: {text_col};")
        controls_row.addWidget(self.chk_enabled)

        lbl_int = QLabel(tr("watchdog_interval_lbl", "Intervalo (s):"))
        lbl_int.setStyleSheet(f"color: {text_col}; font-weight: 600;")
        self.spin_interval = QSpinBox()
        self.spin_interval.setRange(5, 300)
        self.spin_interval.setSuffix(" s")
        self.spin_interval.setValue(int(self.cfg.get("interval_sec", 15)))
        self.spin_interval.setFixedHeight(28)
        controls_row.addWidget(lbl_int)
        controls_row.addWidget(self.spin_interval)

        lbl_fail = QLabel(tr("watchdog_threshold_lbl", "Tolerância de Falhas:"))
        lbl_fail.setStyleSheet(f"color: {text_col}; font-weight: 600;")
        self.spin_threshold = QSpinBox()
        self.spin_threshold.setRange(1, 10)
        self.spin_threshold.setValue(int(self.cfg.get("failure_threshold", 2)))
        self.spin_threshold.setToolTip("Número de pings consecutivos perdidos antes de disparar alerta de queda (evita falsos positivos).")
        self.spin_threshold.setFixedHeight(28)
        controls_row.addWidget(lbl_fail)
        controls_row.addWidget(self.spin_threshold)

        controls_row.addStretch()

        self.btn_check_now = QPushButton(f"⚡ {tr('watchdog_check_now', 'Verificar Agora')}")
        self.btn_check_now.setFixedHeight(30)
        self.btn_check_now.setStyleSheet(
            "QPushButton { background-color: #0969da; color: #ffffff; font-weight: bold; border-radius: 5px; padding: 4px 12px; }"
        )
        self.btn_check_now.clicked.connect(self.on_check_now_clicked)
        controls_row.addWidget(self.btn_check_now)

        cfg_vbox.addLayout(controls_row)

        opts_row = QHBoxLayout()
        self.chk_notify = QCheckBox(tr("watchdog_notify_chk", "Emitir notificações nativas na área de trabalho ao detectar queda ou retorno"))
        self.chk_notify.setChecked(bool(self.cfg.get("notify_desktop", True)))
        self.chk_notify.setStyleSheet(f"color: {sub_col};")

        self.chk_tray = QCheckBox(tr("watchdog_tray_chk", "Manter rodando na Bandeja do Sistema (System Tray) ao fechar a janela"))
        self.chk_tray.setChecked(bool(self.cfg.get("minimize_to_tray", False)))
        self.chk_tray.setStyleSheet(f"color: {sub_col};")

        opts_row.addWidget(self.chk_notify)
        opts_row.addSpacing(16)
        opts_row.addWidget(self.chk_tray)
        opts_row.addStretch()
        cfg_vbox.addLayout(opts_row)

        layout.addWidget(cfg_frame)

        # 2. Events Log Table
        hdr_row = QHBoxLayout()
        lbl_log = QLabel(f"<b>📋 {tr('watchdog_log_title', 'Histórico de Incidentes & Recuperações (Quedas / Retornos)')}</b>")
        hdr_row.addWidget(lbl_log)
        hdr_row.addStretch()

        btn_export = QPushButton(f"💾 {tr('watchdog_export_log', 'Exportar Log CSV')}")
        btn_export.setFixedHeight(28)
        btn_export.clicked.connect(self.export_events_csv)
        hdr_row.addWidget(btn_export)

        btn_clear = QPushButton(f"🗑️ {tr('watchdog_clear_log', 'Limpar Histórico')}")
        btn_clear.setFixedHeight(28)
        btn_clear.clicked.connect(self.on_clear_events)
        hdr_row.addWidget(btn_clear)

        layout.addLayout(hdr_row)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels([
            tr("watchdog_col_time", "Data / Hora"),
            tr("watchdog_col_event", "Evento"),
            tr("col_hostname", "Nome / Host"),
            tr("col_ip", "Endereço IP"),
            tr("watchdog_col_details", "Detalhes do Evento"),
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.table, 1)

        # 3. Bottom Bar
        bottom = QHBoxLayout()
        bottom.addStretch()

        btn_save = QPushButton(f"✔  {tr('btn_save_apply', 'Salvar e Aplicar')}")
        btn_save.setFixedHeight(34)
        btn_save.setMinimumWidth(140)
        btn_save.setStyleSheet(
            "QPushButton { background-color: #16a34a; color: #ffffff; font-weight: bold; border-radius: 5px; padding: 4px 16px; }"
        )
        btn_save.clicked.connect(self.save_and_close)

        btn_close = QPushButton(tr("btn_close", "Fechar"))
        btn_close.setFixedHeight(34)
        btn_close.setMinimumWidth(100)
        btn_close.clicked.connect(self.reject)

        bottom.addWidget(btn_save)
        bottom.addWidget(btn_close)
        layout.addLayout(bottom)

    def refresh_events_table(self):
        events = load_watchdog_events()
        self.table.setRowCount(len(events))
        for row, ev in enumerate(events):
            ts = ev.get("timestamp", "")
            etype = ev.get("event_type", "DOWN")
            host = ev.get("hostname", "") or "--"
            ip = ev.get("ip", "")
            details = ev.get("details", "")

            it_ts = QTableWidgetItem(ts)
            it_ev = QTableWidgetItem("🔴 QUEDA (OFFLINE)" if etype == "DOWN" else "🟢 RECUPERADO (ONLINE)")
            it_ev.setFont(QFont("Segoe UI", 9, QFont.Bold))
            it_ev.setForeground(QColor("#dc2626") if etype == "DOWN" else QColor("#16a34a"))

            it_host = QTableWidgetItem(host)
            it_ip = QTableWidgetItem(ip)
            it_det = QTableWidgetItem(details)

            for col, item in enumerate([it_ts, it_ev, it_host, it_ip, it_det]):
                item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                self.table.setItem(row, col, item)

    def on_check_now_clicked(self):
        self.save_current_config()
        self.trigger_manual_check.emit()
        self.refresh_events_table()

    def on_clear_events(self):
        clear_watchdog_events()
        self.refresh_events_table()

    def export_events_csv(self):
        events = load_watchdog_events()
        if not events:
            QMessageBox.information(self, "Watchdog", "Nenhum evento registrado para exportar.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Exportar Histórico do Watchdog", os.path.expanduser("~/watchdog_eventos.csv"), "CSV (*.csv)"
        )
        if not path:
            return
        try:
            import csv
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Data/Hora", "Evento", "Host", "IP", "Detalhes"])
                for ev in events:
                    w.writerow([
                        ev.get("timestamp", ""),
                        ev.get("event_type", ""),
                        ev.get("hostname", ""),
                        ev.get("ip", ""),
                        ev.get("details", ""),
                    ])
            QMessageBox.information(self, "Sucesso", f"Histórico exportado com sucesso em:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Erro", str(e))

    def save_current_config(self) -> dict:
        self.cfg = {
            "enabled": self.chk_enabled.isChecked(),
            "interval_sec": self.spin_interval.value(),
            "failure_threshold": self.spin_threshold.value(),
            "notify_desktop": self.chk_notify.isChecked(),
            "minimize_to_tray": self.chk_tray.isChecked(),
        }
        save_watchdog_config(self.cfg)
        self.config_Updated.emit(self.cfg)
        return self.cfg

    def save_and_close(self):
        self.save_current_config()
        self.accept()
