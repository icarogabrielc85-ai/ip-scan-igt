#!/usr/bin/env python3
"""
Network Interface Selection Dialog for IP Scan IGT.
Allows selecting between multiple network cards (Ethernet, Wi-Fi, VPN, Virtual Bridges).
"""
import os
from typing import Dict, List, Optional

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from scanner_engine import get_all_network_interfaces


class NetworkInterfaceDialog(QDialog):
    interface_selected = pyqtSignal(dict)

    def __init__(self, parent=None, current_interface: str = ""):
        super().__init__(parent)
        self.current_interface = current_interface
        self.interfaces: List[Dict] = []
        self.selected_info: Optional[Dict] = None

        self.setWindowTitle("Seleção de Placa de Rede & Sub-rede")
        self.resize(1020, 430)
        self.init_ui()
        self.load_interfaces()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        is_dark = getattr(self.parent(), "is_dark_mode", False) if self.parent() else False
        hdr_bg = "#162032" if is_dark else "#d2d2d2"
        hdr_border = "#243447" if is_dark else "#a8a8a8"
        title_col = "#f8fafc" if is_dark else "#1e242b"
        sub_col = "#94a3b8" if is_dark else "#3b424a"

        # Header Info Card
        hdr_frame = QFrame()
        hdr_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {hdr_bg};
                border: 1px solid {hdr_border};
                border-radius: 6px;
                padding: 6px;
            }}
        """)
        hdr_layout = QHBoxLayout(hdr_frame)
        hdr_layout.setContentsMargins(10, 6, 10, 6)

        lbl_icon = QLabel("🖧")
        lbl_icon.setStyleSheet("font-size: 26px; border: none;")
        hdr_layout.addWidget(lbl_icon)

        hdr_info = QVBoxLayout()
        lbl_title = QLabel("Escolha de Placa de Rede / Interface")
        lbl_title.setStyleSheet(f"font-weight: bold; font-size: 14px; color: {title_col}; border: none;")
        lbl_sub = QLabel("Selecione a placa de rede desejada para preencher a faixa de IPs correspondente e executar a varredura.")
        lbl_sub.setStyleSheet(f"color: {sub_col}; font-size: 11px; border: none;")
        hdr_info.addWidget(lbl_title)
        hdr_info.addWidget(lbl_sub)
        hdr_layout.addLayout(hdr_info)
        hdr_layout.addStretch()

        btn_refresh = QPushButton("🔄 Atualizar")
        btn_refresh.setFixedHeight(30)
        btn_refresh.setToolTip("Recarregar lista de interfaces de rede")
        btn_refresh.clicked.connect(self.load_interfaces)
        hdr_layout.addWidget(btn_refresh)

        layout.addWidget(hdr_frame)

        # Table of interfaces
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels([
            "Placa / Nome",
            "Tipo",
            "Endereço IPv4",
            "Máscara / CIDR",
            "Faixa da Sub-rede",
            "Endereço MAC",
            "Gateway Padrão",
        ])
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)

        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        self.table.itemDoubleClicked.connect(self.on_item_double_clicked)
        layout.addWidget(self.table, 1)

        # Bottom Bar with Actions
        bottom_box = QHBoxLayout()
        bottom_box.setSpacing(8)

        self.lbl_selected_hint = QLabel("Nenhuma placa selecionada.")
        self.lbl_selected_hint.setStyleSheet("font-weight: 500; color: #475569;")
        bottom_box.addWidget(self.lbl_selected_hint)
        bottom_box.addStretch()

        self.btn_select = QPushButton("✔  Usar Placa Selecionada")
        self.btn_select.setFixedHeight(34)
        self.btn_select.setEnabled(False)
        self.btn_select.setStyleSheet("""
            QPushButton {
                background-color: #0969da;
                color: #ffffff;
                font-weight: bold;
                border: none;
                border-radius: 4px;
                padding: 4px 16px;
            }
            QPushButton:hover {
                background-color: #0856b3;
            }
            QPushButton:disabled {
                background-color: #94a3b8;
            }
        """)
        self.btn_select.clicked.connect(self.accept_selection)
        bottom_box.addWidget(self.btn_select)

        btn_cancel = QPushButton("Cancelar")
        btn_cancel.setFixedHeight(34)
        btn_cancel.clicked.connect(self.reject)
        bottom_box.addWidget(btn_cancel)

        layout.addLayout(bottom_box)

    def load_interfaces(self):
        self.interfaces = get_all_network_interfaces()
        self.table.setRowCount(len(self.interfaces))

        selected_row = -1
        for row, iface in enumerate(self.interfaces):
            is_active = iface["name"] == self.current_interface or (not self.current_interface and iface.get("is_default"))

            name_text = f"{iface['icon']}  {iface['name']}"
            if iface.get("is_default"):
                name_text += "  [Padrão]"

            item_name = QTableWidgetItem(name_text)
            item_name.setFont(QFont("Noto Sans", 10, QFont.Bold))

            item_type = QTableWidgetItem(iface.get("type", "Rede"))
            item_ip = QTableWidgetItem(iface.get("ip", ""))
            item_cidr = QTableWidgetItem(f"/{iface.get('cidr', '24')} ({iface.get('netmask', '')})")
            item_range = QTableWidgetItem(f"{iface.get('start_ip', '')}  —  {iface.get('end_ip', '')}  ({iface.get('total_hosts', 0)} IPs)")
            item_range.setForeground(QColor("#0969da"))
            item_mac = QTableWidgetItem(iface.get("mac", "N/D"))
            gw_text = iface.get("gateway", "")
            if iface.get("speed"):
                gw_text += f" ({iface['speed']})" if gw_text else iface['speed']
            item_gw = QTableWidgetItem(gw_text or "--")

            for col, item in enumerate([item_name, item_type, item_ip, item_cidr, item_range, item_mac, item_gw]):
                item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                self.table.setItem(row, col, item)

            if is_active and selected_row == -1:
                selected_row = row

        if selected_row >= 0:
            self.table.selectRow(selected_row)

    def on_selection_changed(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if selected_rows:
            row = selected_rows[0].row()
            if 0 <= row < len(self.interfaces):
                self.selected_info = self.interfaces[row]
                self.lbl_selected_hint.setText(
                    f"Selecionada: <b>{self.selected_info['name']}</b> ({self.selected_info['ip']}) "
                    f"— Faixa: {self.selected_info['start_ip']} até {self.selected_info['end_ip']}"
                )
                self.btn_select.setEnabled(True)
                return
        self.btn_select.setEnabled(False)
        self.selected_info = None
        self.lbl_selected_hint.setText("Nenhuma placa selecionada.")

    def on_item_double_clicked(self, item):
        self.accept_selection()

    def accept_selection(self):
        if self.selected_info:
            self.interface_selected.emit(self.selected_info)
            self.accept()
        else:
            QMessageBox.warning(self, "Aviso", "Por favor, selecione uma placa de rede da lista.")
