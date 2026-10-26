import ipaddress
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from i18n import tr

SNAPSHOTS_FILE = os.path.expanduser("~/.config/linux-ipscan/snapshots.json")


def serialize_host_for_snapshot(rec: Any) -> Dict[str, Any]:
    """Converte um HostRecord ou dict em um dicionário serializável enxuto para Snapshot."""
    if isinstance(rec, dict):
        cves = rec.get("cves", [])
        if not cves and "vulnerabilities" in rec:
            cves = [
                v.get("cve_id", str(v)) if isinstance(v, dict) else getattr(v, "cve_id", str(v))
                for v in rec.get("vulnerabilities", [])
            ]
        return {
            "ip": rec.get("ip", ""),
            "alive": bool(rec.get("alive", True)),
            "hostname": rec.get("hostname", "") or "",
            "mac": (rec.get("mac", "") or "").upper(),
            "vendor": rec.get("vendor", "") or "",
            "device_type": rec.get("device_type", "") or "",
            "os_family": rec.get("os_family", "") or "",
            "open_ports": sorted(int(p) for p in (rec.get("open_ports") or [])),
            "http_info": rec.get("http_info", "") or "",
            "ssl_info": rec.get("ssl_info", "") or "",
            "ssh_banner": rec.get("ssh_banner", "") or "",
            "snmp_info": rec.get("snmp_info", "") or "",
            "upnp_info": rec.get("upnp_info", "") or "",
            "cves": sorted(set(str(c) for c in cves if c)),
            "risk_level": rec.get("risk_level", "NONE") or "NONE",
        }

    vulns = getattr(rec, "vulnerabilities", []) or []
    cve_ids = sorted(set(getattr(v, "cve_id", str(v)) for v in vulns if v))
    return {
        "ip": getattr(rec, "ip", ""),
        "alive": bool(getattr(rec, "alive", True)),
        "hostname": getattr(rec, "hostname", "") or "",
        "mac": (getattr(rec, "mac", "") or "").upper(),
        "vendor": getattr(rec, "vendor", "") or "",
        "device_type": getattr(rec, "device_type", "") or "",
        "os_family": getattr(rec, "os_family", "") or "",
        "open_ports": sorted(int(p) for p in (getattr(rec, "open_ports", []) or [])),
        "http_info": getattr(rec, "http_info", "") or "",
        "ssl_info": getattr(rec, "ssl_info", "") or "",
        "ssh_banner": getattr(rec, "ssh_banner", "") or "",
        "snmp_info": getattr(rec, "snmp_info", "") or "",
        "upnp_info": getattr(rec, "upnp_info", "") or "",
        "cves": cve_ids,
        "risk_level": getattr(rec, "risk_level", "NONE") or "NONE",
    }


@dataclass
class HostDiffEntry:
    ip: str
    status: str  # "ADDED" | "REMOVED" | "MODIFIED" | "UNCHANGED"
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    changes: List[str] = field(default_factory=list)
    added_ports: List[int] = field(default_factory=list)
    removed_ports: List[int] = field(default_factory=list)
    added_cves: List[str] = field(default_factory=list)
    resolved_cves: List[str] = field(default_factory=list)
    mac_changed: Optional[Tuple[str, str]] = None

    def format_summary(self) -> str:
        if self.status == "ADDED":
            return "🟢 Novo dispositivo detectado na rede" + (
                f" ({', '.join(map(str, self.added_ports))})" if self.added_ports else ""
            )
        if self.status == "REMOVED":
            return "🔴 Dispositivo ausente / offline em relação ao Snapshot Base"
        if self.status == "MODIFIED":
            return " • ".join(self.changes)
        return "⚪ Sem alterações"


@dataclass
class SnapshotDiffResult:
    baseline_name: str
    target_name: str
    added_hosts: List[HostDiffEntry] = field(default_factory=list)
    removed_hosts: List[HostDiffEntry] = field(default_factory=list)
    modified_hosts: List[HostDiffEntry] = field(default_factory=list)
    unchanged_hosts: List[HostDiffEntry] = field(default_factory=list)

    @property
    def total_changes(self) -> int:
        return len(self.added_hosts) + len(self.removed_hosts) + len(self.modified_hosts)


def _ip_key(ip_str: str) -> Tuple[int, ...]:
    try:
        return tuple(int(x) for x in ip_str.split("."))
    except Exception:
        return (999, 999, 999, 999)


def compare_host_maps(
    baseline_hosts: Dict[str, Any],
    current_hosts: Dict[str, Any],
    baseline_name: str = "Snapshot Base",
    target_name: str = "Varredura Atual",
) -> SnapshotDiffResult:
    """
    Compara dois mapas de hosts (IP -> HostRecord ou dict) e retorna as diferenças detalhadas:
    - Novos hosts (ADDED)
    - Hosts ausentes/removidos (REMOVED)
    - Hosts com mudanças de portas, CVEs, MAC ou hostname (MODIFIED)
    - Hosts idênticos (UNCHANGED)
    """
    base_norm = {
        ip: serialize_host_for_snapshot(h)
        for ip, h in baseline_hosts.items()
        if (isinstance(h, dict) and h.get("alive", True)) or getattr(h, "alive", True)
    }
    curr_norm = {
        ip: serialize_host_for_snapshot(h)
        for ip, h in current_hosts.items()
        if (isinstance(h, dict) and h.get("alive", True)) or getattr(h, "alive", True)
    }

    res = SnapshotDiffResult(baseline_name=baseline_name, target_name=target_name)
    all_ips = sorted(set(base_norm.keys()) | set(curr_norm.keys()), key=_ip_key)

    for ip in all_ips:
        in_base = ip in base_norm
        in_curr = ip in curr_norm

        if not in_base and in_curr:
            c = curr_norm[ip]
            changes = ["Novo host online"]
            if c["open_ports"]:
                changes.append(f"Portas abertas: {', '.join(map(str, c['open_ports']))}")
            if c["cves"]:
                changes.append(f"CVEs detectadas: {', '.join(c['cves'])}")
            res.added_hosts.append(
                HostDiffEntry(
                    ip=ip,
                    status="ADDED",
                    hostname=c["hostname"],
                    mac=c["mac"],
                    vendor=c["vendor"],
                    changes=changes,
                    added_ports=list(c["open_ports"]),
                    added_cves=list(c["cves"]),
                )
            )
        elif in_base and not in_curr:
            b = base_norm[ip]
            res.removed_hosts.append(
                HostDiffEntry(
                    ip=ip,
                    status="REMOVED",
                    hostname=b["hostname"],
                    mac=b["mac"],
                    vendor=b["vendor"],
                    changes=["Host ficou offline ou saiu da sub-rede"],
                    removed_ports=list(b["open_ports"]),
                )
            )
        else:
            b = base_norm[ip]
            c = curr_norm[ip]
            changes: List[str] = []

            b_ports = set(b["open_ports"])
            c_ports = set(c["open_ports"])
            added_ports = sorted(c_ports - b_ports)
            removed_ports = sorted(b_ports - c_ports)

            if added_ports:
                changes.append(f"+Portas Abertas: {', '.join(map(str, added_ports))}")
            if removed_ports:
                changes.append(f"-Portas Fechadas: {', '.join(map(str, removed_ports))}")

            b_cves = set(b["cves"])
            c_cves = set(c["cves"])
            added_cves = sorted(c_cves - b_cves)
            resolved_cves = sorted(b_cves - c_cves)

            if added_cves:
                changes.append(f"⚠️ +Novas CVEs: {', '.join(added_cves)}")
            if resolved_cves:
                changes.append(f"✅ -CVEs Corrigidas: {', '.join(resolved_cves)}")

            mac_changed = None
            if b["mac"] and c["mac"] and b["mac"] != c["mac"]:
                mac_changed = (b["mac"], c["mac"])
                changes.append(f"🏷️ MAC alterado: {b['mac']} → {c['mac']}")

            if b["hostname"] and c["hostname"] and b["hostname"] != c["hostname"]:
                changes.append(f"Nome alterado: {b['hostname']} → {c['hostname']}")

            entry = HostDiffEntry(
                ip=ip,
                status="MODIFIED" if changes else "UNCHANGED",
                hostname=c["hostname"] or b["hostname"],
                mac=c["mac"] or b["mac"],
                vendor=c["vendor"] or b["vendor"],
                changes=changes,
                added_ports=added_ports,
                removed_ports=removed_ports,
                added_cves=added_cves,
                resolved_cves=resolved_cves,
                mac_changed=mac_changed,
            )
            if changes:
                res.modified_hosts.append(entry)
            else:
                res.unchanged_hosts.append(entry)

    return res


class SnapshotManager:
    """Gerencia o armazenamento local de Snapshots de Auditoria em JSON."""

    def __init__(self, storage_path: str = SNAPSHOTS_FILE):
        self.storage_path = storage_path
        self.snapshots: List[Dict[str, Any]] = []
        self.load()

    def load(self):
        if not os.path.exists(self.storage_path):
            self.snapshots = []
            return
        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                self.snapshots = data
        except Exception:
            self.snapshots = []

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(self.snapshots[:50], f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def create_snapshot(
        self,
        records: Dict[str, Any],
        name: str = "",
        interface_str: str = "",
    ) -> Dict[str, Any]:
        now_ts = int(time.time())
        now_str = time.strftime("%d/%m/%Y %H:%M:%S")
        if not name:
            name = f"Snapshot Base — {now_str}"
        hosts_serialized = {
            ip: serialize_host_for_snapshot(rec)
            for ip, rec in records.items()
            if (isinstance(rec, dict) and rec.get("alive", True)) or getattr(rec, "alive", True)
        }
        snap = {
            "id": f"snap_{now_ts}_{len(self.snapshots) + 1}",
            "name": name,
            "created_at": now_str,
            "interface": interface_str,
            "host_count": len(hosts_serialized),
            "hosts": hosts_serialized,
        }
        self.snapshots.insert(0, snap)
        self.save()
        return snap

    def delete_snapshot(self, snap_id: str):
        self.snapshots = [s for s in self.snapshots if s.get("id") != snap_id]
        self.save()

    def get_snapshot(self, snap_id: str) -> Optional[Dict[str, Any]]:
        for s in self.snapshots:
            if s.get("id") == snap_id:
                return s
        return None


SNAPSHOT_MANAGER = SnapshotManager()


class SnapshotDiffDialog(QDialog):
    """
    Janela Interativa de Snapshots de Auditoria & Comparador de Mudanças (Baseline Diff).
    """

    def __init__(
        self,
        parent=None,
        current_records: Optional[Dict[str, Any]] = None,
        interface_str: str = "",
        is_dark: bool = False,
    ):
        super().__init__(parent)
        self.current_records = current_records or {}
        self.interface_str = interface_str
        self.is_dark = is_dark
        self.last_diff: Optional[SnapshotDiffResult] = None

        self.setWindowTitle(
            tr("snapshot_dialog_title", "📸 Snapshots de Auditoria & Comparador de Mudanças (Baseline Diff)")
        )
        self.resize(980, 620)
        self._setup_ui()
        self._populate_combos()
        self.run_comparison()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        hdr = QLabel(
            "<h3>📸 Snapshots de Auditoria & Comparador de Mudanças (Baseline Diff)</h3>"
            "<p style='color:#64748b; font-size:12px; margin-top:2px;'>"
            "Salve uma fotografia (Baseline) da rede e compare com varreduras futuras para identificar instantaneamente "
            "<b>🟢 Novos Dispositivos</b>, <b>🔴 Servidores Ausentes</b> e <b>🟠 Novas Portas ou CVEs</b>."
            "</p>"
        )
        hdr.setWordWrap(True)
        layout.addWidget(hdr)

        # Control Bar
        bar = QFrame()
        bar.setFrameShape(QFrame.StyledPanel)
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(12, 8, 12, 8)
        bar_layout.setSpacing(10)

        btn_save_snap = QPushButton("📸 Salvar Varredura Atual como Snapshot")
        btn_save_snap.setFixedHeight(32)
        btn_save_snap.setStyleSheet(
            "QPushButton { background-color: #0969da; color: #ffffff; font-weight: bold; padding: 4px 12px; border-radius: 5px; }"
        )
        btn_save_snap.clicked.connect(self._save_current_snapshot)
        bar_layout.addWidget(btn_save_snap)

        bar_layout.addWidget(QLabel("<b>Base (Antes):</b>"))
        self.combo_base = QComboBox()
        self.combo_base.setMinimumWidth(240)
        self.combo_base.currentIndexChanged.connect(self.run_comparison)
        bar_layout.addWidget(self.combo_base)

        bar_layout.addWidget(QLabel("<b>Comparar com (Depois):</b>"))
        self.combo_target = QComboBox()
        self.combo_target.setMinimumWidth(240)
        self.combo_target.currentIndexChanged.connect(self.run_comparison)
        bar_layout.addWidget(self.combo_target)

        btn_del = QPushButton("🗑️ Excluir Base")
        btn_del.setToolTip("Excluir o Snapshot selecionado no campo Base")
        btn_del.clicked.connect(self._delete_selected_base)
        bar_layout.addWidget(btn_del)

        bar_layout.addStretch()
        layout.addWidget(bar)

        # KPI Summary Row
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(12)

        self.lbl_kpi_added = QLabel("🟢 +0 Novos Hosts")
        self.lbl_kpi_added.setAlignment(Qt.AlignCenter)
        self.lbl_kpi_added.setStyleSheet(
            "background:#dcfce7; color:#166534; font-weight:bold; padding:8px; border-radius:6px; border:1px solid #bbf7d0;"
        )

        self.lbl_kpi_removed = QLabel("🔴 -0 Hosts Ausentes")
        self.lbl_kpi_removed.setAlignment(Qt.AlignCenter)
        self.lbl_kpi_removed.setStyleSheet(
            "background:#fee2e2; color:#991b1b; font-weight:bold; padding:8px; border-radius:6px; border:1px solid #fecaca;"
        )

        self.lbl_kpi_modified = QLabel("🟠 ~0 Hosts Alterados")
        self.lbl_kpi_modified.setAlignment(Qt.AlignCenter)
        self.lbl_kpi_modified.setStyleSheet(
            "background:#fef3c7; color:#92400e; font-weight:bold; padding:8px; border-radius:6px; border:1px solid #fde68a;"
        )

        self.lbl_kpi_unchanged = QLabel("⚪ =0 Inalterados")
        self.lbl_kpi_unchanged.setAlignment(Qt.AlignCenter)
        self.lbl_kpi_unchanged.setStyleSheet(
            "background:#f1f5f9; color:#475569; font-weight:bold; padding:8px; border-radius:6px; border:1px solid #cbd5e1;"
        )

        kpi_row.addWidget(self.lbl_kpi_added)
        kpi_row.addWidget(self.lbl_kpi_removed)
        kpi_row.addWidget(self.lbl_kpi_modified)
        kpi_row.addWidget(self.lbl_kpi_unchanged)

        # Filter combo
        kpi_row.addWidget(QLabel("Filtrar:"))
        self.combo_filter = QComboBox()
        self.combo_filter.addItem("🔍 Todas as Alterações (Novos, Ausentes e Modificados)", "CHANGES")
        self.combo_filter.addItem("🟢 Apenas Novos Hosts (+)", "ADDED")
        self.combo_filter.addItem("🔴 Apenas Hosts Ausentes (-)", "REMOVED")
        self.combo_filter.addItem("🟠 Apenas Hosts Modificados (~)", "MODIFIED")
        self.combo_filter.addItem("📋 Todos os Hosts (Incluindo Inalterados)", "ALL")
        self.combo_filter.currentIndexChanged.connect(self._render_diff_table)
        kpi_row.addWidget(self.combo_filter)

        layout.addLayout(kpi_row)

        # Diff Table
        self.tbl_diff = QTableWidget(0, 5)
        self.tbl_diff.setHorizontalHeaderLabels([
            "Status da Mudança",
            "Endereço IP",
            "Nome do Host",
            "MAC / Fabricante",
            "Detalhes das Alterações (Portas, Serviços, CVEs e Hardware)",
        ])
        self.tbl_diff.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tbl_diff.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tbl_diff.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.tbl_diff.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.tbl_diff.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.tbl_diff.verticalHeader().setVisible(False)
        self.tbl_diff.setAlternatingRowColors(True)
        layout.addWidget(self.tbl_diff)

        # Footer
        footer = QHBoxLayout()
        self.lbl_status = QLabel("")
        footer.addWidget(self.lbl_status)
        footer.addStretch()

        btn_close = QPushButton(tr("btn_close", "Fechar"))
        btn_close.setFixedWidth(110)
        btn_close.clicked.connect(self.accept)
        footer.addWidget(btn_close)
        layout.addLayout(footer)

    def _populate_combos(self):
        SNAPSHOT_MANAGER.load()
        self.combo_base.blockSignals(True)
        self.combo_target.blockSignals(True)
        self.combo_base.clear()
        self.combo_target.clear()

        live_label = f"⚡ Varredura Atual Ao Vivo ({len(self.current_records)} hosts)"
        self.combo_target.addItem(live_label, "__LIVE__")

        for snap in SNAPSHOT_MANAGER.snapshots:
            label = f"📸 {snap.get('name')} ({snap.get('host_count', 0)} hosts)"
            sid = snap.get("id")
            self.combo_base.addItem(label, sid)
            self.combo_target.addItem(label, sid)

        self.combo_base.blockSignals(False)
        self.combo_target.blockSignals(False)

    def _save_current_snapshot(self):
        if not self.current_records:
            QMessageBox.warning(
                self,
                "Varredura Vazia",
                "Execute uma varredura de rede primeiro para salvar os dispositivos ativos em um Snapshot.",
            )
            return

        default_name = f"Auditoria {time.strftime('%d/%m/%Y %H:%M')}"
        name, ok = QInputDialog.getText(
            self,
            "Salvar Snapshot de Auditoria",
            "Nome de identificação para este Snapshot Base:",
            QLineEdit.Normal,
            default_name,
        )
        if not ok:
            return
        snap = SNAPSHOT_MANAGER.create_snapshot(
            self.current_records,
            name=name.strip() or default_name,
            interface_str=self.interface_str,
        )
        self._populate_combos()
        # Select the newly created snapshot as Base
        idx = self.combo_base.findData(snap["id"])
        if idx >= 0:
            self.combo_base.setCurrentIndex(idx)
        self.run_comparison()
        QMessageBox.information(
            self,
            "Snapshot Salvo",
            f"Snapshot '{snap['name']}' salvo com sucesso ({snap['host_count']} dispositivos registrados)!",
        )

    def _delete_selected_base(self):
        sid = self.combo_base.currentData()
        if not sid:
            return
        SNAPSHOT_MANAGER.delete_snapshot(sid)
        self._populate_combos()
        self.run_comparison()

    def run_comparison(self):
        base_id = self.combo_base.currentData()
        target_id = self.combo_target.currentData()

        if not base_id:
            self.last_diff = None
            self.tbl_diff.setRowCount(0)
            self.lbl_status.setText("Nenhum Snapshot Base salvo ainda. Clique em '📸 Salvar Varredura Atual como Snapshot'.")
            return

        base_snap = SNAPSHOT_MANAGER.get_snapshot(base_id)
        if not base_snap:
            return

        base_hosts = base_snap.get("hosts", {})
        base_name = base_snap.get("name", "Snapshot Base")

        if target_id == "__LIVE__":
            target_hosts = self.current_records
            target_name = "Varredura Atual (Ao Vivo)"
        else:
            t_snap = SNAPSHOT_MANAGER.get_snapshot(target_id)
            target_hosts = t_snap.get("hosts", {}) if t_snap else {}
            target_name = t_snap.get("name", "Snapshot Alvo") if t_snap else "Alvo"

        self.last_diff = compare_host_maps(base_hosts, target_hosts, baseline_name=base_name, target_name=target_name)
        self.lbl_kpi_added.setText(f"🟢 +{len(self.last_diff.added_hosts)} Novos Hosts")
        self.lbl_kpi_removed.setText(f"🔴 -{len(self.last_diff.removed_hosts)} Hosts Ausentes")
        self.lbl_kpi_modified.setText(f"🟠 ~{len(self.last_diff.modified_hosts)} Hosts Alterados")
        self.lbl_kpi_unchanged.setText(f"⚪ ={len(self.last_diff.unchanged_hosts)} Inalterados")
        self._render_diff_table()

    def _render_diff_table(self):
        if not self.last_diff:
            self.tbl_diff.setRowCount(0)
            return

        flt = self.combo_filter.currentData()
        entries: List[HostDiffEntry] = []
        if flt == "ADDED":
            entries = list(self.last_diff.added_hosts)
        elif flt == "REMOVED":
            entries = list(self.last_diff.removed_hosts)
        elif flt == "MODIFIED":
            entries = list(self.last_diff.modified_hosts)
        elif flt == "ALL":
            entries = (
                list(self.last_diff.added_hosts)
                + list(self.last_diff.removed_hosts)
                + list(self.last_diff.modified_hosts)
                + list(self.last_diff.unchanged_hosts)
            )
        else:
            entries = (
                list(self.last_diff.added_hosts)
                + list(self.last_diff.removed_hosts)
                + list(self.last_diff.modified_hosts)
            )

        self.tbl_diff.setRowCount(len(entries))
        f_bold = QFont("Segoe UI", 9, QFont.Bold)

        for r, e in enumerate(entries):
            if e.status == "ADDED":
                st_txt = "🟢 +NOVO HOST"
                st_col = QColor("#059669")
            elif e.status == "REMOVED":
                st_txt = "🔴 -AUSENTE"
                st_col = QColor("#dc2626")
            elif e.status == "MODIFIED":
                st_txt = "🟠 ~MODIFICADO"
                st_col = QColor("#d97706")
            else:
                st_txt = "⚪ =INALTERADO"
                st_col = QColor("#64748b")

            it_st = QTableWidgetItem(st_txt)
            it_st.setForeground(st_col)
            it_st.setFont(f_bold)

            it_ip = QTableWidgetItem(e.ip)
            it_ip.setFont(f_bold)

            it_host = QTableWidgetItem(e.hostname or "--")
            mac_ven = f"{e.mac or 'N/D'} ({e.vendor or 'Desconhecido'})"
            it_mv = QTableWidgetItem(mac_ven)
            it_det = QTableWidgetItem(e.format_summary())

            for c, it in enumerate([it_st, it_ip, it_host, it_mv, it_det]):
                it.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                self.tbl_diff.setItem(r, c, it)

        self.lbl_status.setText(
            f"Comparando <b>{self.last_diff.baseline_name}</b> vs <b>{self.last_diff.target_name}</b>: "
            f"{self.last_diff.total_changes} alteração(ões) encontrada(s)."
        )
