import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QCheckBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from config_paths import get_config_file
from i18n import tr

NETWORK_GUARD_FILE = get_config_file("network_guard.json")


def normalize_mac(mac: str) -> str:
    if not mac:
        return ""
    clean = mac.strip().upper().replace("-", ":")
    if clean in ("N/D", "N/A", "UNKNOWN", "DESCONHECIDO", "00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
        return ""
    parts = clean.split(":")
    if len(parts) == 6 and all(len(p) == 2 for p in parts):
        return clean
    return clean


@dataclass
class GuardAlert:
    timestamp: str
    alert_type: str  # "ARP_SPOOFING" | "IP_CONFLICT" | "INTRUDER_NEW_MAC"
    severity: str    # "CRITICAL" | "HIGH" | "WARNING"
    ip: str
    mac: str
    previous_mac: str = ""
    hostname: str = ""
    vendor: str = ""
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "ip": self.ip,
            "mac": self.mac,
            "previous_mac": self.previous_mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "details": self.details,
        }

    def badge_text(self) -> str:
        if self.alert_type == "ARP_SPOOFING":
            return "[🚨 ARP SPOOFING]"
        if self.alert_type == "IP_CONFLICT":
            return "[⚠️ CONFLITO IP]"
        if self.alert_type == "INTRUDER_NEW_MAC":
            return "[🆕 NOVO MAC]"
        return f"[{self.alert_type}]"


class NetworkGuardEngine:
    """
    Motor de Detecção de Intrusos (Novos MACs), Conflito de IP (MAC Flip)
    e Ataques de ARP Spoofing (Sequestro de MAC do Gateway).
    """

    def __init__(self, storage_path: str = NETWORK_GUARD_FILE):
        self.storage_path = storage_path
        self.alert_new_devices: bool = True
        self.auto_trust_first_scan: bool = False
        self.known_macs: Dict[str, Dict[str, Any]] = {}
        self.ip_mac_map: Dict[str, str] = {}
        self.gateway_bindings: Dict[str, str] = {}  # gateway_ip -> gateway_mac
        self.events: List[Dict[str, Any]] = []
        self.load()

    def load(self):
        if not os.path.exists(self.storage_path):
            return
        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self.alert_new_devices = bool(data.get("alert_new_devices", True))
                self.auto_trust_first_scan = bool(data.get("auto_trust_first_scan", False))
                self.known_macs = data.get("known_macs", {}) or {}
                self.ip_mac_map = data.get("ip_mac_map", {}) or {}
                self.gateway_bindings = data.get("gateway_bindings", {}) or {}
                self.events = data.get("events", []) or []
        except Exception:
            pass

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
            data = {
                "alert_new_devices": self.alert_new_devices,
                "auto_trust_first_scan": self.auto_trust_first_scan,
                "known_macs": self.known_macs,
                "ip_mac_map": self.ip_mac_map,
                "gateway_bindings": self.gateway_bindings,
                "events": self.events[:300],
            }
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def _record_event(self, alert: GuardAlert):
        # Avoid duplicate consecutive identical alerts in the top 5 entries
        for recent in self.events[:5]:
            if (
                recent.get("alert_type") == alert.alert_type
                and recent.get("ip") == alert.ip
                and recent.get("mac") == alert.mac
                and recent.get("previous_mac") == alert.previous_mac
            ):
                return
        self.events.insert(0, alert.to_dict())
        self.events = self.events[:300]

    def inspect_host(
        self,
        ip: str,
        mac: str,
        hostname: str = "",
        vendor: str = "",
        gateway_ip: str = "",
    ) -> List[GuardAlert]:
        """
        Analisa o par (IP, MAC) contra a base histórica para detectar:
        1. ARP Spoofing (mudança de MAC do Gateway ou clonagem do MAC do Gateway por outro IP)
        2. Conflito de IP (mudança abrupta de MAC para o mesmo IP)
        3. Dispositivo Intruso / Desconhecido (MAC não marcado como Confiável)
        """
        norm_mac = normalize_mac(mac)
        if not norm_mac or not ip:
            return []

        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        alerts: List[GuardAlert] = []

        # 1. Gateway ARP Spoofing Inspection
        if gateway_ip:
            if ip == gateway_ip:
                prev_gw_mac = self.gateway_bindings.get(gateway_ip, "")
                if prev_gw_mac and prev_gw_mac != norm_mac:
                    alert = GuardAlert(
                        timestamp=now_str,
                        alert_type="ARP_SPOOFING",
                        severity="CRITICAL",
                        ip=ip,
                        mac=norm_mac,
                        previous_mac=prev_gw_mac,
                        hostname=hostname or "Gateway",
                        vendor=vendor,
                        details=(
                            f"Possível ataque ARP Spoofing (Man-in-the-Middle)! "
                            f"O Gateway {gateway_ip} mudou de MAC ({prev_gw_mac} -> {norm_mac})."
                        ),
                    )
                    alerts.append(alert)
                    self._record_event(alert)
                else:
                    self.gateway_bindings[gateway_ip] = norm_mac
            else:
                gw_mac = self.gateway_bindings.get(gateway_ip, "")
                if gw_mac and norm_mac == gw_mac:
                    alert = GuardAlert(
                        timestamp=now_str,
                        alert_type="ARP_SPOOFING",
                        severity="CRITICAL",
                        ip=ip,
                        mac=norm_mac,
                        previous_mac=gw_mac,
                        hostname=hostname,
                        vendor=vendor,
                        details=(
                            f"Alerta de ARP Spoofing! O host {ip} está anunciando o mesmo endereço MAC "
                            f"({norm_mac}) do Gateway principal ({gateway_ip})."
                        ),
                    )
                    alerts.append(alert)
                    self._record_event(alert)

        # 2. IP Conflict / MAC Flip Detection
        prev_mac_for_ip = self.ip_mac_map.get(ip, "")
        if prev_mac_for_ip and prev_mac_for_ip != norm_mac:
            # Only add IP_CONFLICT if not already flagged as ARP_SPOOFING for the exact same transition
            if not any(a.alert_type == "ARP_SPOOFING" for a in alerts):
                alert = GuardAlert(
                    timestamp=now_str,
                    alert_type="IP_CONFLICT",
                    severity="HIGH",
                    ip=ip,
                    mac=norm_mac,
                    previous_mac=prev_mac_for_ip,
                    hostname=hostname,
                    vendor=vendor,
                    details=(
                        f"Conflito de IP ou troca de hardware no endereço {ip}: "
                        f"respondia com MAC {prev_mac_for_ip} e agora responde com {norm_mac}."
                    ),
                )
                alerts.append(alert)
                self._record_event(alert)

        self.ip_mac_map[ip] = norm_mac

        # 3. Unknown / Intruder MAC Detection
        if norm_mac not in self.known_macs:
            is_trusted = bool(self.auto_trust_first_scan and len(self.known_macs) == 0)
            self.known_macs[norm_mac] = {
                "mac": norm_mac,
                "ip": ip,
                "hostname": hostname or "",
                "vendor": vendor or "",
                "first_seen": now_str,
                "last_seen": now_str,
                "trusted": is_trusted,
            }
            if not is_trusted and self.alert_new_devices:
                alert = GuardAlert(
                    timestamp=now_str,
                    alert_type="INTRUDER_NEW_MAC",
                    severity="WARNING",
                    ip=ip,
                    mac=norm_mac,
                    hostname=hostname,
                    vendor=vendor,
                    details=(
                        f"Novo dispositivo (MAC não autorizado) detectado na rede: "
                        f"{norm_mac} ({vendor or 'Fabricante desconhecido'}) no IP {ip}."
                    ),
                )
                alerts.append(alert)
                self._record_event(alert)
        else:
            entry = self.known_macs[norm_mac]
            entry["ip"] = ip
            if hostname:
                entry["hostname"] = hostname
            if vendor:
                entry["vendor"] = vendor
            entry["last_seen"] = now_str
            if not entry.get("trusted", False) and self.alert_new_devices:
                alert = GuardAlert(
                    timestamp=now_str,
                    alert_type="INTRUDER_NEW_MAC",
                    severity="WARNING",
                    ip=ip,
                    mac=norm_mac,
                    hostname=hostname,
                    vendor=vendor,
                    details=(
                        f"Dispositivo não autorizado ativo na rede: "
                        f"{norm_mac} ({vendor or 'Desconhecido'}) em {ip}."
                    ),
                )
                alerts.append(alert)

        self.save()
        return alerts

    def trust_mac(self, mac: str, trusted: bool = True, ip: str = "", hostname: str = "", vendor: str = ""):
        norm = normalize_mac(mac)
        if not norm:
            return
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        if norm not in self.known_macs:
            self.known_macs[norm] = {
                "mac": norm,
                "ip": ip,
                "hostname": hostname,
                "vendor": vendor,
                "first_seen": now_str,
                "last_seen": now_str,
                "trusted": trusted,
            }
        else:
            self.known_macs[norm]["trusted"] = trusted
            if ip:
                self.known_macs[norm]["ip"] = ip
            if hostname:
                self.known_macs[norm]["hostname"] = hostname
            if vendor:
                self.known_macs[norm]["vendor"] = vendor
        # Bind current gateway MAC cleanly if trusting
        if ip and trusted:
            self.ip_mac_map[ip] = norm
        self.save()

    def trust_all_records(self, records: Dict[str, Any], gateway_ip: str = ""):
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        for ip, rec in records.items():
            norm = normalize_mac(getattr(rec, "mac", ""))
            if not norm:
                continue
            if norm not in self.known_macs:
                self.known_macs[norm] = {
                    "mac": norm,
                    "ip": ip,
                    "hostname": getattr(rec, "hostname", "") or "",
                    "vendor": getattr(rec, "vendor", "") or "",
                    "first_seen": now_str,
                    "last_seen": now_str,
                    "trusted": True,
                }
            else:
                self.known_macs[norm]["trusted"] = True
                self.known_macs[norm]["ip"] = ip
                self.known_macs[norm]["last_seen"] = now_str
            self.ip_mac_map[ip] = norm
            if gateway_ip and ip == gateway_ip:
                self.gateway_bindings[gateway_ip] = norm
            # Clear active guard alerts on the record
            rec.guard_alerts = []
            rec.guard_badge = ""
        self.save()

    def clear_events(self):
        self.events.clear()
        self.save()

    def reset_bindings(self):
        self.ip_mac_map.clear()
        self.gateway_bindings.clear()
        self.events.clear()
        self.save()


# Global Singleton
NETWORK_GUARD = NetworkGuardEngine()


class NetworkGuardDialog(QDialog):
    """
    Painel de Controle do Network Guard:
    - Visualização de incidentes de ARP Spoofing, Conflitos de IP e Novos Dispositivos (Intrusos)
    - Gerenciamento de inventário de endereços MAC confiáveis (Whitelist L2)
    """

    guard_updated = pyqtSignal()

    def __init__(self, parent=None, records: Optional[Dict[str, Any]] = None, gateway_ip: str = "", is_dark: bool = False):
        super().__init__(parent)
        self.records = records or {}
        self.gateway_ip = gateway_ip
        self.is_dark = is_dark
        self.setWindowTitle(
            tr(
                "guard_dialog_title",
                "🛡️ Network Guard — Detecção de Intrusos, Conflito de IP e ARP Spoofing",
            )
        )
        self.resize(920, 600)
        self._setup_ui()
        self.refresh_tables()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        hdr = QLabel(
            "<h3>🛡️ Network Guard — Proteção em Camada 2 (ARP & Controle de Admissão MAC)</h3>"
            "<p style='color:#64748b; font-size:12px; margin-top:2px;'>"
            "Detecta automaticamente sequestro de Gateway (<b>ARP Spoofing / MitM</b>), "
            "<b>Conflitos de IP</b> (troca abrupta de MAC) e <b>Dispositivos Intrusos</b> não autorizados na sub-rede."
            "</p>"
        )
        hdr.setWordWrap(True)
        layout.addWidget(hdr)

        # Top control bar
        ctrl_frame = QFrame()
        ctrl_frame.setFrameShape(QFrame.StyledPanel)
        ctrl_layout = QHBoxLayout(ctrl_frame)
        ctrl_layout.setContentsMargins(12, 8, 12, 8)

        self.chk_alert_new = QCheckBox(
            tr("guard_chk_new_mac", "Alertar quando um novo endereço MAC desconhecido entrar na rede")
        )
        self.chk_alert_new.setChecked(NETWORK_GUARD.alert_new_devices)
        self.chk_alert_new.toggled.connect(self._on_toggle_alert_new)
        ctrl_layout.addWidget(self.chk_alert_new)

        ctrl_layout.addStretch()

        self.btn_trust_all = QPushButton(
            tr("guard_btn_trust_all", "✅ Aprovar Todos os Dispositivos Atuais como Confiáveis")
        )
        self.btn_trust_all.setFixedHeight(30)
        self.btn_trust_all.setStyleSheet(
            "QPushButton { background-color: #059669; color: #ffffff; font-weight: bold; padding: 4px 12px; border-radius: 5px; }"
        )
        self.btn_trust_all.clicked.connect(self._trust_all_current)
        ctrl_layout.addWidget(self.btn_trust_all)

        layout.addWidget(ctrl_frame)

        # Tabs: 1. Alertas de Anomalias | 2. Inventário de MACs Conhecidos
        self.tabs = QTabWidget()

        # Tab 1: Alertas
        tab_alerts = QWidget()
        al_layout = QVBoxLayout(tab_alerts)
        al_layout.setContentsMargins(8, 8, 8, 8)

        self.tbl_alerts = QTableWidget(0, 6)
        self.tbl_alerts.setHorizontalHeaderLabels([
            "Data / Hora",
            "Severidade",
            "Tipo de Anomalia",
            "IP Afetado",
            "Endereço MAC",
            "Descrição Técnica do Incidente",
        ])
        self.tbl_alerts.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tbl_alerts.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tbl_alerts.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.tbl_alerts.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.tbl_alerts.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.tbl_alerts.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.tbl_alerts.verticalHeader().setVisible(False)
        self.tbl_alerts.setAlternatingRowColors(True)
        al_layout.addWidget(self.tbl_alerts)

        al_btns = QHBoxLayout()
        btn_clear_events = QPushButton("🗑️ Limpar Histórico de Alertas")
        btn_clear_events.clicked.connect(self._clear_events)
        btn_reset_arp = QPushButton("🔄 Redefinir Vínculos IP-MAC e Gateway")
        btn_reset_arp.clicked.connect(self._reset_bindings)
        al_btns.addWidget(btn_clear_events)
        al_btns.addWidget(btn_reset_arp)
        al_btns.addStretch()
        al_layout.addLayout(al_btns)

        self.tabs.addTab(tab_alerts, "🚨 Incidentes & Anomalias Detectadas")

        # Tab 2: Known MACs Whitelist
        tab_macs = QWidget()
        mac_layout = QVBoxLayout(tab_macs)
        mac_layout.setContentsMargins(8, 8, 8, 8)

        self.tbl_macs = QTableWidget(0, 6)
        self.tbl_macs.setHorizontalHeaderLabels([
            "Status de Confiança",
            "Endereço MAC",
            "Último IP",
            "Nome do Host",
            "Fabricante (OUI)",
            "Última Aparição",
        ])
        self.tbl_macs.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tbl_macs.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tbl_macs.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.tbl_macs.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.tbl_macs.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.tbl_macs.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.tbl_macs.verticalHeader().setVisible(False)
        self.tbl_macs.setAlternatingRowColors(True)
        mac_layout.addWidget(self.tbl_macs)

        mac_btns = QHBoxLayout()
        btn_toggle_trust = QPushButton("🛡️ Alternar Confiável / Não Autorizado para o MAC Selecionado")
        btn_toggle_trust.clicked.connect(self._toggle_selected_mac_trust)
        mac_btns.addWidget(btn_toggle_trust)
        mac_btns.addStretch()
        mac_layout.addLayout(mac_btns)

        self.tabs.addTab(tab_macs, "🏷️ Inventário de Endereços MAC (Whitelist)")

        layout.addWidget(self.tabs)

        # Footer
        footer = QHBoxLayout()
        self.lbl_summary = QLabel("")
        footer.addWidget(self.lbl_summary)
        footer.addStretch()
        btn_close = QPushButton(tr("btn_close", "Fechar"))
        btn_close.setFixedWidth(110)
        btn_close.clicked.connect(self.accept)
        footer.addWidget(btn_close)
        layout.addLayout(footer)

    def _on_toggle_alert_new(self, checked: bool):
        NETWORK_GUARD.alert_new_devices = bool(checked)
        NETWORK_GUARD.save()
        self.guard_updated.emit()

    def _trust_all_current(self):
        NETWORK_GUARD.trust_all_records(self.records, gateway_ip=self.gateway_ip)
        for mac_entry in NETWORK_GUARD.known_macs.values():
            mac_entry["trusted"] = True
        NETWORK_GUARD.save()
        self.refresh_tables()
        self.guard_updated.emit()
        QMessageBox.information(
            self,
            "Network Guard",
            "Todos os dispositivos atuais foram marcados como Confiáveis na Whitelist L2!",
        )

    def _toggle_selected_mac_trust(self):
        row = self.tbl_macs.currentRow()
        if row < 0:
            return
        mac_item = self.tbl_macs.item(row, 1)
        if not mac_item:
            return
        mac = mac_item.text().strip()
        if mac in NETWORK_GUARD.known_macs:
            cur = bool(NETWORK_GUARD.known_macs[mac].get("trusted", False))
            NETWORK_GUARD.known_macs[mac]["trusted"] = not cur
            NETWORK_GUARD.save()
            self.refresh_tables()
            self.guard_updated.emit()

    def _clear_events(self):
        NETWORK_GUARD.clear_events()
        self.refresh_tables()
        self.guard_updated.emit()

    def _reset_bindings(self):
        NETWORK_GUARD.reset_bindings()
        self.refresh_tables()
        self.guard_updated.emit()

    def refresh_tables(self):
        # Populate Alerts Table
        events = NETWORK_GUARD.events
        self.tbl_alerts.setRowCount(len(events))
        for r, ev in enumerate(events):
            sev = ev.get("severity", "WARNING")
            atype = ev.get("alert_type", "")
            it_ts = QTableWidgetItem(ev.get("timestamp", ""))
            it_sev = QTableWidgetItem(sev)
            it_type = QTableWidgetItem(atype)
            it_ip = QTableWidgetItem(ev.get("ip", ""))
            it_mac = QTableWidgetItem(ev.get("mac", ""))
            it_det = QTableWidgetItem(ev.get("details", ""))

            col = QColor("#dc2626") if sev == "CRITICAL" else (QColor("#d97706") if sev == "HIGH" else QColor("#0284c7"))
            it_sev.setForeground(col)
            f_bold = QFont("Segoe UI", 9, QFont.Bold)
            it_sev.setFont(f_bold)
            it_type.setFont(f_bold)

            for c, it in enumerate([it_ts, it_sev, it_type, it_ip, it_mac, it_det]):
                it.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                self.tbl_alerts.setItem(r, c, it)

        # Populate MACs Table
        mac_list = sorted(NETWORK_GUARD.known_macs.values(), key=lambda x: (x.get("trusted", False), x.get("ip", "")))
        self.tbl_macs.setRowCount(len(mac_list))
        trusted_count = 0
        untrusted_count = 0
        for r, m in enumerate(mac_list):
            is_trusted = bool(m.get("trusted", False))
            if is_trusted:
                trusted_count += 1
                status_txt = "✅ Confiável (Autorizado)"
                status_col = QColor("#059669")
            else:
                untrusted_count += 1
                status_txt = "⚠️ Não Autorizado (Novo)"
                status_col = QColor("#d97706")

            it_st = QTableWidgetItem(status_txt)
            it_st.setForeground(status_col)
            it_st.setFont(QFont("Segoe UI", 9, QFont.Bold))
            it_mac = QTableWidgetItem(m.get("mac", ""))
            it_ip = QTableWidgetItem(m.get("ip", ""))
            it_host = QTableWidgetItem(m.get("hostname", ""))
            it_ven = QTableWidgetItem(m.get("vendor", ""))
            it_seen = QTableWidgetItem(m.get("last_seen", ""))

            for c, it in enumerate([it_st, it_mac, it_ip, it_host, it_ven, it_seen]):
                it.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                self.tbl_macs.setItem(r, c, it)

        self.lbl_summary.setText(
            f"<b>Resumo Network Guard:</b> {len(events)} incidente(s) registrado(s)  •  "
            f"{trusted_count} MAC(s) confiáveis  •  {untrusted_count} MAC(s) não autorizados"
        )
